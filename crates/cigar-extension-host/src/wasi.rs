//! Fuel, epoch, memory, and capability-limited Preview 2 component backend.

use crate::broker::CapabilityBroker;
use crate::digest::raw_content_digest;
use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use crate::frame::FrameCodec;
use crate::host::{ExtensionBackend, InvocationCancellation, RuntimeResponse};
use crate::manifest::ActivatedExtension;
use cigar_canon::MAX_CANONICAL_INPUT_BYTES;
use cigar_protocol::{
    ExtensionComputeBudget, ExtensionHostCallKind, ExtensionInvocationV1, ExtensionResponseV1,
    ExtensionRuntimeKind,
};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use wasmtime::component::{Component, Linker};
use wasmtime::{
    Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, UpdateDeadline,
};

const HOST_FAILURE: u32 = u32::MAX;
const WATCHDOG_INTERVAL: Duration = Duration::from_millis(1);

struct AggregateStoreLimits {
    per_memory: StoreLimits,
    maximum_memory_bytes: usize,
    allocated_memory_bytes: usize,
    pending_growth_bytes: Option<usize>,
    memory_limit_exceeded: bool,
}

impl AggregateStoreLimits {
    const fn new(per_memory: StoreLimits, maximum_memory_bytes: usize) -> Self {
        Self {
            per_memory,
            maximum_memory_bytes,
            allocated_memory_bytes: 0,
            pending_growth_bytes: None,
            memory_limit_exceeded: false,
        }
    }

    const fn memory_limit_exceeded(&self) -> bool {
        self.memory_limit_exceeded
    }
}

impl ResourceLimiter for AggregateStoreLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.pending_growth_bytes = None;
        let allowed = match self.per_memory.memory_growing(current, desired, maximum) {
            Ok(allowed) => allowed,
            Err(failure) => {
                self.memory_limit_exceeded = true;
                return Err(failure);
            }
        };
        if !allowed {
            self.memory_limit_exceeded = true;
            return Ok(false);
        }
        let growth = desired.checked_sub(current).ok_or_else(|| {
            self.memory_limit_exceeded = true;
            wasmtime::Error::msg("linear memory shrank during a growth request")
        })?;
        let aggregate = self
            .allocated_memory_bytes
            .checked_add(growth)
            .ok_or_else(|| {
                self.memory_limit_exceeded = true;
                wasmtime::Error::msg("aggregate linear memory accounting overflowed")
            })?;
        if aggregate > self.maximum_memory_bytes {
            self.memory_limit_exceeded = true;
            return Err(wasmtime::Error::msg(
                "aggregate linear memory limit exceeded",
            ));
        }
        self.allocated_memory_bytes = aggregate;
        self.pending_growth_bytes = Some(growth);
        Ok(true)
    }

    fn memory_grow_failed(&mut self, failure: wasmtime::Error) -> wasmtime::Result<()> {
        if let Some(growth) = self.pending_growth_bytes.take() {
            self.allocated_memory_bytes = self
                .allocated_memory_bytes
                .checked_sub(growth)
                .ok_or_else(|| {
                    wasmtime::Error::msg("aggregate linear memory accounting underflowed")
                })?;
        }
        self.memory_limit_exceeded = true;
        self.per_memory.memory_grow_failed(failure)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.per_memory.table_growing(current, desired, maximum)
    }

    fn table_grow_failed(&mut self, failure: wasmtime::Error) -> wasmtime::Result<()> {
        self.per_memory.table_grow_failed(failure)
    }

    fn instances(&self) -> usize {
        self.per_memory.instances()
    }

    fn tables(&self) -> usize {
        self.per_memory.tables()
    }

    fn memories(&self) -> usize {
        self.per_memory.memories()
    }
}

struct ComponentState {
    limits: AggregateStoreLimits,
    input: Vec<u8>,
    output: Vec<u8>,
    scratch: Vec<u8>,
    host_response: Vec<u8>,
    maximum_input_bytes: usize,
    maximum_output_bytes: usize,
    handles: Vec<cigar_protocol::ExtensionHandle>,
    broker: Option<Arc<CapabilityBroker>>,
    cancellation: InvocationCancellation,
    denied_host_calls: u32,
    resource_exhausted_host_calls: u32,
}

/// Wasmtime Preview 2 Component Model backend for the versioned CIGAR scalar capability world.
///
/// This is intentionally not a general-purpose `wasi:cli/command` host. No `wasi:*` imports are
/// linked. Consequently components begin with no environment, filesystem, network, clock, random,
/// process, or credential authority. The only available imports expose a bounded byte view of the
/// canonical invocation/result frames and dispatch broker-authorized host calls. A component
/// importing a standard WASI interface fails instantiation.
pub struct WasiPreview2Backend {
    activated: ActivatedExtension,
    engine: Engine,
    component: Component,
    component_bytes: usize,
    codec: FrameCodec,
    #[cfg(test)]
    compilation_count: std::sync::atomic::AtomicUsize,
}

impl fmt::Debug for WasiPreview2Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasiPreview2Backend")
            .field("extension_id", &self.activated.manifest().extension_id)
            .field("manifest_digest", self.activated.manifest_digest())
            .field("component_bytes", &self.component_bytes)
            .finish_non_exhaustive()
    }
}

impl WasiPreview2Backend {
    /// Compiles and verifies one exact signed component before it can be registered.
    pub fn new(
        activated: ActivatedExtension,
        component_bytes: Vec<u8>,
    ) -> Result<Self, ExtensionHostError> {
        if activated.manifest().runtime != ExtensionRuntimeKind::WasiPreview2
            || raw_content_digest(&component_bytes)? != activated.manifest().implementation_digest
        {
            return Err(error(ExtensionHostErrorCode::DigestMismatch));
        }
        let engine = component_engine(&activated)?;
        let component = Component::new(&engine, &component_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
        let component_bytes = component_bytes.len();
        Ok(Self {
            activated,
            engine,
            component,
            component_bytes,
            codec: FrameCodec::new(MAX_CANONICAL_INPUT_BYTES)?,
            #[cfg(test)]
            compilation_count: std::sync::atomic::AtomicUsize::new(1),
        })
    }

    #[cfg(test)]
    pub(crate) fn compilation_count(&self) -> usize {
        self.compilation_count.load(Ordering::SeqCst)
    }
}

impl ExtensionBackend for WasiPreview2Backend {
    fn runtime_kind(&self) -> ExtensionRuntimeKind {
        ExtensionRuntimeKind::WasiPreview2
    }

    fn invoke(
        &self,
        invocation: &ExtensionInvocationV1,
        deadline: Instant,
        cancellation: InvocationCancellation,
        broker: Option<Arc<CapabilityBroker>>,
    ) -> Result<RuntimeResponse, ExtensionHostError> {
        if cancellation.is_cancelled() {
            return Err(error(ExtensionHostErrorCode::Cancelled));
        }
        if !invocation.authorized_capabilities.is_empty() && broker.is_none() {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let input = self.codec.encode(invocation)?;
        let engine = &self.engine;
        let component = &self.component;
        let maximum_input_bytes = usize::try_from(invocation.effective_limits.max_input_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?;
        let maximum_output_bytes = usize::try_from(invocation.effective_limits.max_output_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?;
        let memory_limit = usize::try_from(invocation.effective_limits.max_memory_bytes)
            .map_err(|_error| error(ExtensionHostErrorCode::ResourceExhausted))?;
        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_limit)
            .table_elements(1_024)
            .instances(32)
            .tables(16)
            .memories(16)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            engine,
            ComponentState {
                limits: AggregateStoreLimits::new(limits, memory_limit),
                input,
                output: Vec::new(),
                scratch: Vec::new(),
                host_response: Vec::new(),
                maximum_input_bytes,
                maximum_output_bytes,
                handles: invocation.handles.clone(),
                broker,
                cancellation: cancellation.clone(),
                denied_host_calls: 0,
                resource_exhausted_host_calls: 0,
            },
        );
        store.limiter(|state| &mut state.limits);
        let fuel = match invocation.effective_limits.compute {
            ExtensionComputeBudget::Fuel { units } => units,
            ExtensionComputeBudget::CpuTime { .. } => {
                return Err(error(ExtensionHostErrorCode::InvalidInput));
            }
        };
        store
            .set_fuel(fuel)
            .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(move |context| {
            if context.data().cancellation.is_cancelled() || Instant::now() >= deadline {
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        let mut linker = Linker::new(engine);
        add_scalar_capability_world(&mut linker)?;
        let instance = match linker.instantiate(&mut store, component) {
            Ok(instance) => instance,
            Err(_failure) if store.data().limits.memory_limit_exceeded() => {
                return Err(error(ExtensionHostErrorCode::ResourceExhausted));
            }
            Err(_failure) => return Err(error(ExtensionHostErrorCode::CapabilityDenied)),
        };
        let invoke = instance
            .get_typed_func::<(), (u32,)>(&mut store, "invoke")
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;

        let finished = Arc::new(AtomicBool::new(false));
        let watchdog_finished = finished.clone();
        let watchdog_engine = engine.clone();
        let watchdog_cancel = cancellation.clone();
        let watchdog = thread::spawn(move || {
            while !watchdog_finished.load(Ordering::SeqCst)
                && !watchdog_cancel.is_cancelled()
                && Instant::now() < deadline
            {
                thread::sleep(WATCHDOG_INTERVAL);
            }
            if !watchdog_finished.load(Ordering::SeqCst) {
                watchdog_engine.increment_epoch();
            }
        });
        let call_result = invoke.call(&mut store, ());
        finished.store(true, Ordering::SeqCst);
        watchdog
            .join()
            .map_err(|_panic| error(ExtensionHostErrorCode::BackendUnavailable))?;
        let (declared_length,) = match call_result {
            Ok(result) => result,
            Err(_failure) if cancellation.is_cancelled() => {
                return Err(error(ExtensionHostErrorCode::Cancelled));
            }
            Err(_failure) if Instant::now() >= deadline => {
                return Err(error(ExtensionHostErrorCode::DeadlineExceeded));
            }
            Err(_failure) => return Err(error(ExtensionHostErrorCode::ResourceExhausted)),
        };
        if store.data().resource_exhausted_host_calls != 0 {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        if store.data().denied_host_calls != 0 {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let declared_length = usize::try_from(declared_length)
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
        if declared_length != store.data().output.len()
            || declared_length > maximum_output_bytes
            || declared_length > self.codec.maximum_payload_bytes() + 4
        {
            return Err(error(ExtensionHostErrorCode::ResourceExhausted));
        }
        let response: ExtensionResponseV1 = self.codec.decode(&store.data().output)?;
        Ok(RuntimeResponse::completed(response))
    }
}

fn component_engine(activated: &ActivatedExtension) -> Result<Engine, ExtensionHostError> {
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .wasm_features(wasmtime::WasmFeatures::THREADS, false)
        .wasm_features(wasmtime::WasmFeatures::SHARED_EVERYTHING_THREADS, false)
        .consume_fuel(true)
        .epoch_interruption(true);
    let recursion_stack = usize::from(activated.manifest().limits.max_recursion_depth)
        .checked_mul(4_096)
        .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?
        .clamp(64 * 1_024, 8 * 1_024 * 1_024);
    config.max_wasm_stack(recursion_stack);
    Engine::new(&config).map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))
}

fn add_scalar_capability_world(
    linker: &mut Linker<ComponentState>,
) -> Result<(), ExtensionHostError> {
    linker
        .root()
        .func_wrap("input-len", |store, (): ()| {
            Ok((u32::try_from(store.data().input.len()).unwrap_or(HOST_FAILURE),))
        })
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    linker
        .root()
        .func_wrap("input-byte", |store, (index,): (u32,)| {
            let value = usize::try_from(index)
                .ok()
                .and_then(|index| store.data().input.get(index).copied())
                .map_or(HOST_FAILURE, u32::from);
            Ok((value,))
        })
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    linker
        .root()
        .func_wrap("output-byte", |mut store, (index, value): (u32, u32)| {
            let expected = u32::try_from(store.data().output.len()).unwrap_or(HOST_FAILURE);
            let accepted = index == expected
                && value <= u32::from(u8::MAX)
                && store.data().output.len() < store.data().maximum_output_bytes;
            if accepted {
                store.data_mut().output.push(value as u8);
                Ok((0_u32,))
            } else {
                Ok((HOST_FAILURE,))
            }
        })
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    linker
        .root()
        .func_wrap("scratch-clear", |mut store, (): ()| {
            store.data_mut().scratch.clear();
            Ok(())
        })
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    linker
        .root()
        .func_wrap("scratch-byte", |mut store, (index, value): (u32, u32)| {
            let expected = u32::try_from(store.data().scratch.len()).unwrap_or(HOST_FAILURE);
            let accepted = index == expected
                && value <= u32::from(u8::MAX)
                && store.data().scratch.len() < store.data().maximum_input_bytes;
            if accepted {
                store.data_mut().scratch.push(value as u8);
                Ok((0_u32,))
            } else {
                Ok((HOST_FAILURE,))
            }
        })
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    linker
        .root()
        .func_wrap(
            "host-call",
            |mut store, (kind, handle_index): (u32, u32)| {
                let call_kind = decode_host_call_kind(kind);
                let handle = if handle_index == HOST_FAILURE {
                    Some(None)
                } else {
                    usize::try_from(handle_index)
                        .ok()
                        .and_then(|index| store.data().handles.get(index).cloned())
                        .map(Some)
                };
                let broker = store.data().broker.clone();
                let request = store.data().scratch.clone();
                let result = call_kind
                    .ok_or_else(|| error(ExtensionHostErrorCode::InvalidInput))
                    .and_then(|kind| {
                        broker
                            .ok_or_else(|| error(ExtensionHostErrorCode::CapabilityDenied))?
                            .dispatch_host_call(kind, handle.flatten().as_ref(), &request)
                    });
                match result {
                    Ok(response) if response.len() <= store.data().maximum_output_bytes => {
                        let length = u32::try_from(response.len()).unwrap_or(HOST_FAILURE);
                        store.data_mut().host_response = response;
                        Ok((length,))
                    }
                    Ok(_) => {
                        store.data_mut().resource_exhausted_host_calls =
                            store.data().resource_exhausted_host_calls.saturating_add(1);
                        store.data_mut().denied_host_calls =
                            store.data().denied_host_calls.saturating_add(1);
                        store.data_mut().host_response.clear();
                        Ok((HOST_FAILURE,))
                    }
                    Err(failure) => {
                        if failure.code() == ExtensionHostErrorCode::ResourceExhausted {
                            store.data_mut().resource_exhausted_host_calls =
                                store.data().resource_exhausted_host_calls.saturating_add(1);
                        }
                        store.data_mut().denied_host_calls =
                            store.data().denied_host_calls.saturating_add(1);
                        store.data_mut().host_response.clear();
                        Ok((HOST_FAILURE,))
                    }
                }
            },
        )
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    linker
        .root()
        .func_wrap("host-response-byte", |store, (index,): (u32,)| {
            let value = usize::try_from(index)
                .ok()
                .and_then(|index| store.data().host_response.get(index).copied())
                .map_or(HOST_FAILURE, u32::from);
            Ok((value,))
        })
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    linker
        .root()
        .func_wrap("cancelled", |store, (): ()| {
            Ok((u32::from(store.data().cancellation.is_cancelled()),))
        })
        .map_err(|_error| error(ExtensionHostErrorCode::BackendUnavailable))?;
    Ok(())
}

fn decode_host_call_kind(value: u32) -> Option<ExtensionHostCallKind> {
    match value {
        1 => Some(ExtensionHostCallKind::ReadSource),
        2 => Some(ExtensionHostCallKind::ReadBlob),
        3 => Some(ExtensionHostCallKind::IteratorNext),
        4 => Some(ExtensionHostCallKind::ClockNow),
        5 => Some(ExtensionHostCallKind::RandomFill),
        6 => Some(ExtensionHostCallKind::Trace),
        7 => Some(ExtensionHostCallKind::CheckCancelled),
        8 => Some(ExtensionHostCallKind::NetworkRequest),
        9 => Some(ExtensionHostCallKind::FileRead),
        10 => Some(ExtensionHostCallKind::FileWrite),
        11 => Some(ExtensionHostCallKind::ResolveSecret),
        _ => None,
    }
}
