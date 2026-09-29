//! Explicit opt-in broker process. Host stdio never shares an agent command decoder.
use cigar_context::broker::authentication::{ClientHello, ClientProof, MAX_HANDSHAKE_FRAME};
use cigar_context::broker::protocol::{
    AgentCommand, AgentRequest, BROKER_PROTOCOL, ErrorCode, HostCommand, HostRequest,
    MAX_AGENT_FRAME, MAX_AGENT_RESPONSE, MAX_HOST_FRAME, MAX_HOST_RESPONSE, Outcome, Reply, Timing,
    TransportLimits, decode_agent, decode_host, encode, read_frame, write_frame,
};
use cigar_context::broker::scheduler::{BrokerScheduler, Cancellation, DispatchStatus, Scheduled};
use cigar_context::broker::{BrokerCredential, BrokerError, ContextBroker};
use cigar_context::{O200kTokenizer, TokenCounter};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

mod persistence;
use persistence::Persistence;

struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Reservation> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .ok()?;
        Some(Reservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

struct Reservation {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct Packet {
    bytes: Vec<u8>,
    // Account for queued, writing and slow-reader replies until the last byte is sent/dropped.
    _reservation: Option<Reservation>,
}

enum Work {
    Host(HostRequest),
    Agent {
        credential: BrokerCredential,
        request: AgentRequest,
    },
}

struct Job {
    work: Work,
    port: ReplyPort,
}

struct ReplyPort {
    id: u32,
    host: bool,
    channel: mpsc::SyncSender<Packet>,
}

struct Shared {
    queue: Mutex<BrokerScheduler<Job>>,
    ready: Condvar,
    closed: AtomicBool,
    incoming: Arc<Budget>,
    outgoing: Arc<Budget>,
    connections: Arc<Budget>,
    agent_connections: Mutex<BTreeMap<String, Weak<Budget>>>,
    limits: TransportLimits,
    host_wait_ms: u64,
}

impl Shared {
    fn reserve_agent(&self, grant_id: &str) -> std::io::Result<Reservation> {
        let mut agents = self.agent_connections.lock().map_err(|_| unavailable())?;
        // Only active connections retain a budget. Grant turnover cannot accumulate registry
        // entries; its size is bounded by the global active-connection limit.
        agents.retain(|_, budget| budget.strong_count() > 0);
        let budget = agents
            .get(grant_id)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let budget = Budget::new(self.limits.max_connections_per_agent);
                agents.insert(grant_id.into(), Arc::downgrade(&budget));
                budget
            });
        budget.reserve(1).ok_or_else(unavailable)
    }

    fn stop(&self) {
        // Pair the stop predicate with the same mutex as Condvar::wait. An atomic flag alone
        // can notify between the owner's predicate check and wait registration, losing wakeup.
        let _queue = match self.queue.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }

    fn emit(&self, port: ReplyPort, outcome: Outcome<Value>, timing: Timing) {
        let host = port.host;
        let limit = if host {
            MAX_HOST_RESPONSE - 1
        } else {
            MAX_AGENT_RESPONSE
        };
        let reply = Reply {
            protocol: BROKER_PROTOCOL.into(),
            id: port.id,
            outcome,
            timing,
        };
        let Ok(bytes) = encode(&reply, limit) else {
            // No trustworthy result can be delivered. The caller observes a transport failure,
            // not a false assertion that a dispatched mutation failed. Never retry here.
            return;
        };
        let reservation = if host {
            None
        } else {
            let Some(reservation) = self.outgoing.reserve(bytes.len()) else {
                return;
            };
            Some(reservation)
        };
        let _ = port.channel.try_send(Packet {
            bytes,
            _reservation: reservation,
        });
    }

    fn reject_scheduled(&self, mut scheduled: Scheduled<Job>, error: ErrorCode) {
        let timing = Timing {
            queue_us: micros(scheduled.queue_delay()),
            service_us: 0,
        };
        if let Some(job) = scheduled.take() {
            self.emit(
                job.port,
                Outcome::Error {
                    error,
                    dispatched: false,
                },
                timing,
            );
        }
    }
}

struct Runtime {
    shared: Arc<Shared>,
    address: SocketAddr,
    actor: Option<JoinHandle<()>>,
    listener: Option<JoinHandle<()>>,
}

impl Runtime {
    fn start(command: HostCommand) -> Result<(Self, Value), ErrorCode> {
        let HostCommand::Init {
            domain,
            graph,
            retention,
            queues,
            transport,
            storage,
        } = command
        else {
            return Err(ErrorCode::InvalidInput);
        };
        transport.validate().map_err(ErrorCode::from)?;
        if retention.max_agents != queues.max_agents {
            return Err(ErrorCode::InvalidInput);
        }
        let (broker, persistence, restored) =
            Persistence::open(domain, graph.graph_limits(), retention, storage)
                .map_err(ErrorCode::from)?;
        let tokenizer = O200kTokenizer::with_cache_limits(graph.cache_limits())
            .map_err(|error| ErrorCode::from(BrokerError::from(error)))?;
        let scheduler = BrokerScheduler::new(broker.epoch(), queues).map_err(ErrorCode::from)?;
        // Never resolve a name or accept a caller-provided bind address.
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ErrorCode::Unavailable)?;
        let address = listener.local_addr().map_err(|_| ErrorCode::Unavailable)?;
        let hello = json!({
            "protocol": BROKER_PROTOCOL, "core_version": env!("CARGO_PKG_VERSION"),
            "epoch": broker.epoch(), "host": "127.0.0.1", "port": address.port(),
            "tokenizer": tokenizer.identity(), "max_frame_bytes": MAX_AGENT_FRAME,
            "max_response_bytes": MAX_AGENT_RESPONSE,
            "host_max_frame_bytes": MAX_HOST_FRAME, "host_max_response_bytes": MAX_HOST_RESPONSE,
            "execution": "single-owner-fair-dispatch", "requires_hol_services": false,
            "capabilities": ["broker_scopes.v1", "source_cas.v1", "proposal_admission.v1",
                "provenance_freshness.v1", "exact_answer_review.v1", "fair_admission.v1",
                "mutual_grant_proof.v1", "execution_handoff.v1", "selection_explanation.v1", "document_boundaries.v1",
                "source_batches.v1"],
            "transport_limits": transport,
            "storage": {"mode": if persistence.active() { "sqlite-checkpoint.v1" } else { "memory" },
                "restored": restored},
        });
        let shared = Arc::new(Shared {
            queue: Mutex::new(scheduler),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
            incoming: Budget::new(transport.max_inbound_bytes),
            outgoing: Budget::new(transport.max_outbound_bytes),
            connections: Budget::new(transport.max_connections),
            agent_connections: Mutex::new(BTreeMap::new()),
            limits: transport,
            host_wait_ms: queues.max_wait_ms,
        });
        let owner = Arc::clone(&shared);
        let actor = std::thread::Builder::new()
            .name("cigar-broker-owner".into())
            .spawn(move || own(broker, persistence, tokenizer, &owner))
            .map_err(|_| ErrorCode::Unavailable)?;
        let incoming = Arc::clone(&shared);
        let listener = match std::thread::Builder::new()
            .name("cigar-broker-listener".into())
            .spawn(move || accept(listener, &incoming))
        {
            Ok(listener) => listener,
            Err(_) => {
                shared.stop();
                let _ = actor.join();
                return Err(ErrorCode::Unavailable);
            }
        };
        Ok((
            Self {
                shared,
                address,
                actor: Some(actor),
                listener: Some(listener),
            },
            hello,
        ))
    }

    fn call(&self, request: HostRequest, bytes: usize) -> std::io::Result<Packet> {
        let (tx, rx) = mpsc::sync_channel(1);
        let id = request.id;
        let mut queue = self.shared.queue.lock().map_err(|_| unavailable())?;
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        if let Err(error) = queue.enqueue_host(
            Job {
                work: Work::Host(request),
                port: ReplyPort {
                    id,
                    host: true,
                    channel: tx,
                },
            },
            bytes,
            self.shared.host_wait_ms,
        ) {
            return packet_error(id, error.into(), false);
        }
        drop(queue);
        self.shared.ready.notify_one();
        rx.recv().map_err(|_| unavailable())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shared.stop();
        // Wake blocking accept on the exact local listener. No polling, DNS or external traffic.
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        if let Some(actor) = self.actor.take() {
            let _ = actor.join();
        }
    }
}

pub(super) fn run() -> std::io::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let Some(first) = host_frame(&mut input)? else {
        return Ok(());
    };
    let request = decode_host(&first).map_err(|_| unavailable())?;
    let id = request.id;
    let (runtime, hello) = match Runtime::start(request.command) {
        Ok(runtime) => runtime,
        Err(error) => {
            write_host(&mut output, packet_error(id, error, false)?)?;
            return Ok(());
        }
    };
    let encoded = encode(
        &Reply {
            protocol: BROKER_PROTOCOL.into(),
            id,
            outcome: Outcome::Ok { result: hello },
            timing: Timing::default(),
        },
        MAX_HOST_RESPONSE - 1,
    )
    .map_err(|_| unavailable())?;
    write_host(
        &mut output,
        Packet {
            bytes: encoded,
            _reservation: None,
        },
    )?;
    while let Some(frame) = host_frame(&mut input)? {
        let request = decode_host(&frame).map_err(|_| unavailable())?;
        let close = matches!(request.command, HostCommand::Close {});
        write_host(&mut output, runtime.call(request, frame.len())?)?;
        if close {
            break;
        }
    }
    Ok(())
}

fn host_frame(input: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    let length = input
        .take((MAX_HOST_FRAME + 1) as u64)
        .read_until(b'\n', &mut frame)?;
    if length == 0 {
        return Ok(None);
    }
    if length > MAX_HOST_FRAME || frame.last() != Some(&b'\n') {
        return Err(unavailable());
    }
    Ok(Some(frame))
}

fn write_host(output: &mut impl Write, packet: Packet) -> std::io::Result<()> {
    output.write_all(&packet.bytes)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn packet_error(id: u32, error: ErrorCode, dispatched: bool) -> std::io::Result<Packet> {
    let bytes = encode(
        &Reply::<Value> {
            protocol: BROKER_PROTOCOL.into(),
            id,
            outcome: Outcome::Error { error, dispatched },
            timing: Timing::default(),
        },
        MAX_AGENT_RESPONSE,
    )
    .map_err(|_| unavailable())?;
    Ok(Packet {
        bytes,
        _reservation: None,
    })
}

fn micros(duration: Duration) -> u64 {
    // Timing is telemetry, not authority. Keep values exactly representable by every SDK.
    duration.as_micros().min(9_007_199_254_740_991) as u64
}

fn unavailable() -> std::io::Error {
    std::io::Error::other("broker transport unavailable")
}

fn next_job(shared: &Shared) -> Option<Scheduled<Job>> {
    let mut queue = shared.queue.lock().ok()?;
    while queue.is_empty() && !shared.closed.load(Ordering::Acquire) {
        queue = shared.ready.wait(queue).ok()?;
    }
    if shared.closed.load(Ordering::Acquire) {
        None
    } else {
        queue.pop()
    }
}

fn own(
    mut broker: ContextBroker,
    mut persistence: Persistence,
    tokenizer: O200kTokenizer,
    shared: &Shared,
) {
    while let Some(mut scheduled) = next_job(shared) {
        match scheduled.status() {
            DispatchStatus::Expired => {
                shared.reject_scheduled(scheduled, ErrorCode::Expired);
                continue;
            }
            DispatchStatus::Cancelled => {
                shared.reject_scheduled(scheduled, ErrorCode::Cancelled);
                continue;
            }
            DispatchStatus::Ready => {}
        }
        let Some(job) = scheduled.take() else {
            continue;
        };
        let queue_us = micros(scheduled.queue_delay());
        let start = Instant::now();
        let close = matches!(
            &job.work,
            Work::Host(HostRequest {
                command: HostCommand::Close {},
                ..
            })
        );
        let pending = match &job.work {
            Work::Host(request) => persistence.prepare(&broker, &request.command),
            Work::Agent { .. } => Ok(None),
        };
        let result = match pending {
            Err(error) => Err(error),
            Ok(event) => {
                let result = match job.work {
                    Work::Host(request) => {
                        execute_host(&mut broker, &tokenizer, shared, request.command)
                    }
                    Work::Agent {
                        credential,
                        request,
                    } => execute_agent(&mut broker, &tokenizer, &credential, request),
                };
                if result.is_ok()
                    && let Some(event) = event
                    && persistence.commit(&broker, event).is_err()
                {
                    // Mutation outcome is uncertain. Drop this reply and stop all authority;
                    // a dispatched storage failure cannot be reported as a safe-to-retry error.
                    break;
                }
                result
            }
        };
        let outcome = match result {
            Ok(result) => Outcome::Ok { result },
            Err(error) => Outcome::Error {
                error: error.into(),
                dispatched: true,
            },
        };
        if close {
            shared.stop();
        }
        shared.emit(
            job.port,
            outcome,
            Timing {
                queue_us,
                service_us: micros(start.elapsed()),
            },
        );
    }
    shared.stop();
    // A poisoned queue is never resumed. Only cancel and release its waiting jobs.
    let waiting = match shared.queue.lock() {
        Ok(mut queue) => queue.host_drain(),
        Err(poisoned) => poisoned.into_inner().host_drain(),
    };
    for job in waiting {
        shared.reject_scheduled(job, ErrorCode::Closed);
    }
}

fn execute_host(
    broker: &mut ContextBroker,
    tokenizer: &O200kTokenizer,
    shared: &Shared,
    command: HostCommand,
) -> Result<Value, BrokerError> {
    match command {
        HostCommand::Init { .. } => Err(BrokerError::InvalidInput),
        HostCommand::Grant {
            spec,
            queue: limits,
        } => {
            let agent = spec.view.id.clone();
            let lease = spec.lease_ms;
            let mut queue = shared.queue.lock().map_err(|_| BrokerError::Unavailable)?;
            queue.validate_lane_limits(limits)?;
            for job in queue.host_prune() {
                shared.reject_scheduled(job, ErrorCode::Cancelled);
            }
            let credential = broker.host_grant(spec)?;
            let cancelled = match queue.host_register(&agent, &credential, limits, lease) {
                Ok(replaced) => replaced,
                Err(error) => {
                    // Do not expose a graph grant that the admission registry could not install.
                    broker.host_revoke(&agent);
                    let cancelled = queue.host_revoke(&agent);
                    drop(queue);
                    for job in cancelled {
                        shared.reject_scheduled(job, ErrorCode::Cancelled);
                    }
                    return Err(error);
                }
            };
            drop(queue);
            for job in cancelled {
                shared.reject_scheduled(job, ErrorCode::Cancelled);
            }
            Ok(json!(credential))
        }
        HostCommand::Revoke { agent } => {
            let cancelled = shared
                .queue
                .lock()
                .map_err(|_| BrokerError::Unavailable)?
                .host_revoke(&agent);
            let revoked = broker.host_revoke(&agent);
            for job in cancelled {
                shared.reject_scheduled(job, ErrorCode::Cancelled);
            }
            Ok(json!(revoked))
        }
        HostCommand::SourceRevision { source } => Ok(json!(broker.host_source_revision(&source)?)),
        HostCommand::ReplaceSource {
            source,
            expected,
            documents,
            provenance,
        } => Ok(json!(broker.host_replace_source(
            &source, &expected, documents, provenance
        )?)),
        HostCommand::BeginSourceReplace {
            source,
            expected,
            provenance,
            lease_ms,
        } => Ok(json!(broker.host_begin_source_replace(
            &source, &expected, provenance, lease_ms
        )?)),
        HostCommand::AppendSourceDocuments {
            transaction,
            documents,
        } => Ok(json!(
            broker.host_append_source_documents(&transaction, documents)?
        )),
        HostCommand::CommitSourceReplace { transaction } => {
            Ok(json!(broker.host_commit_source_replace(&transaction)?))
        }
        HostCommand::AbortSourceReplace { transaction } => {
            Ok(json!(broker.host_abort_source_replace(&transaction)))
        }
        HostCommand::ChunksAtLines { document, starts } => {
            Ok(json!(document.chunks_at_lines(&starts)?))
        }
        HostCommand::Provenance { source } => Ok(json!(broker.host_provenance(&source))),
        HostCommand::SetEdge {
            from,
            to,
            kind,
            present,
            expected,
        } => Ok(json!(
            broker.host_set_edge(&from, &to, kind, present, &expected)?
        )),
        HostCommand::Proposal { proposal_id } => {
            let (source, expected, documents) = broker.host_proposal(&proposal_id)?;
            Ok(json!({"source":source,"expected":expected,"documents":documents}))
        }
        HostCommand::AdmitProposal {
            proposal_id,
            provenance,
        } => Ok(json!(broker.host_admit_proposal(&proposal_id, provenance)?)),
        HostCommand::RejectProposal { proposal_id } => {
            broker.host_reject_proposal(&proposal_id)?;
            Ok(Value::Null)
        }
        HostCommand::Submission { ticket } => {
            let submission = broker.host_submission(&ticket, tokenizer)?;
            Ok(json!({"submission_id":submission.submission_id,
                "draft":submission.draft,"review_keys":submission.draft.review_keys()?}))
        }
        HostCommand::CheckAnswer {
            ticket,
            submission_id,
            reviews,
            policy,
        } => Ok(json!(broker.host_check_answer(
            &ticket,
            &submission_id,
            &reviews,
            &policy,
            tokenizer
        )?)),
        HostCommand::BindExecution {
            ticket,
            submission_id,
            effect_id,
            intent_digest,
            review,
        } => Ok(json!(broker.host_bind_execution(
            &ticket,
            &submission_id,
            &effect_id,
            &intent_digest,
            &review,
            tokenizer
        )?)),
        HostCommand::TakeExecutionHandoff { binding, review } => Ok(json!(
            broker.host_take_execution_handoff(&binding, &review, tokenizer)?
        )),
        HostCommand::Close {} => Ok(Value::Null),
    }
}

fn execute_agent(
    broker: &mut ContextBroker,
    tokenizer: &O200kTokenizer,
    credential: &BrokerCredential,
    request: AgentRequest,
) -> Result<Value, BrokerError> {
    match request.command {
        AgentCommand::Compile { request } => {
            Ok(json!(broker.compile(credential, &request, tokenizer)?))
        }
        AgentCommand::Revalidate { ticket } => {
            broker.revalidate(credential, &ticket, tokenizer)?;
            Ok(Value::Null)
        }
        AgentCommand::Explain { ticket } => {
            Ok(json!(broker.explain(credential, &ticket, tokenizer)?))
        }
        AgentCommand::Citations { ticket, node_id } => Ok(json!(
            broker.citations(credential, &ticket, &node_id, tokenizer)?
        )),
        AgentCommand::SourceRevision { source } => {
            Ok(json!(broker.source_revision(credential, &source)?))
        }
        AgentCommand::ProposeSource {
            request_key,
            source,
            expected,
            documents,
        } => Ok(json!(broker.propose_source(
            credential,
            &request_key,
            &source,
            &expected,
            documents
        )?)),
        AgentCommand::ProposalStatus { request_key } => {
            Ok(json!(broker.proposal_status(credential, &request_key)?))
        }
        AgentCommand::ForgetProposal { request_key } => {
            broker.forget_proposal(credential, &request_key)?;
            Ok(Value::Null)
        }
        AgentCommand::ForgetTicket { ticket } => {
            broker.forget_ticket(credential, &ticket)?;
            Ok(Value::Null)
        }
        AgentCommand::SubmitAnswer { ticket, draft } => Ok(
            json!({"submission_id":broker.submit_answer(credential, &ticket, draft, tokenizer)?}),
        ),
    }
}

fn accept(listener: TcpListener, shared: &Arc<Shared>) {
    loop {
        match listener.accept() {
            Ok((stream, address)) => {
                if shared.closed.load(Ordering::Acquire) {
                    break;
                }
                if !address.ip().is_loopback() {
                    continue;
                }
                let Some(active) = shared.connections.reserve(1) else {
                    continue;
                };
                let owner = Arc::clone(shared);
                let accepted = Instant::now();
                // Both the socket and reservation are dropped if thread creation fails.
                let _ = std::thread::Builder::new()
                    .name("cigar-broker-client".into())
                    .spawn(move || {
                        let _ = serve(stream, &owner, accepted, active);
                    });
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                shared.stop();
                break;
            }
        }
    }
}

struct DeadlineSocket<'a> {
    stream: &'a mut TcpStream,
    until: Instant,
}

impl DeadlineSocket<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))
    }
}

impl Read for DeadlineSocket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineSocket<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

struct CancelOnDrop(Cancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let _ = self.0.cancel();
    }
}

fn serve(
    mut stream: TcpStream,
    shared: &Shared,
    accepted: Instant,
    // Last parameter drops first, releasing capacity before the socket signals EOF.
    _active: Reservation,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let until = accepted
        .checked_add(Duration::from_millis(shared.limits.frame_timeout_ms))
        .ok_or_else(unavailable)?;
    let mut reader = DeadlineSocket {
        stream: &mut stream,
        until,
    };
    let frame = read_frame(&mut reader, MAX_HANDSHAKE_FRAME).map_err(|_| unavailable())?;
    let hello: ClientHello = serde_json::from_slice(&frame).map_err(|_| unavailable())?;
    let proof = {
        let queue = shared.queue.lock().map_err(|_| unavailable())?;
        if shared.closed.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        queue.server_proof(&hello).map_err(|_| unavailable())?
    };
    write_frame(&mut reader, &proof, MAX_HANDSHAKE_FRAME).map_err(|_| unavailable())?;
    let frame = read_frame(&mut reader, MAX_HANDSHAKE_FRAME).map_err(|_| unavailable())?;
    let client: ClientProof = serde_json::from_slice(&frame).map_err(|_| unavailable())?;
    let credential = shared
        .queue
        .lock()
        .map_err(|_| unavailable())?
        .authenticate_client(&hello, &proof, &client)
        .map_err(|_| unavailable())?;
    let _agent_active = shared.reserve_agent(&hello.grant_id)?;
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_AGENT_FRAME {
        return Err(unavailable());
    }
    let incoming = shared.incoming.reserve(length).ok_or_else(unavailable)?;
    let mut frame = vec![0_u8; length];
    reader.read_exact(&mut frame)?;
    let request = decode_agent(&frame).map_err(|_| unavailable())?;
    drop(frame);
    let id = request.id;
    let wait = request.wait_ms;
    let (tx, rx) = mpsc::sync_channel(1);
    let mut queue = shared.queue.lock().map_err(|_| unavailable())?;
    if shared.closed.load(Ordering::Acquire) {
        return Err(unavailable());
    }
    let admitted = queue.enqueue_agent(
        &credential,
        Job {
            work: Work::Agent {
                credential: credential.clone(),
                request,
            },
            port: ReplyPort {
                id,
                host: false,
                channel: tx,
            },
        },
        length,
        wait,
    );
    drop(queue);
    drop(incoming);
    let cancellation = match admitted {
        Ok(cancellation) => CancelOnDrop(cancellation),
        Err(error) => {
            let mut packet = packet_error(id, error.into(), false)?;
            packet._reservation = Some(
                shared
                    .outgoing
                    .reserve(packet.bytes.len())
                    .ok_or_else(unavailable)?,
            );
            return send_packet(&mut stream, shared, packet);
        }
    };
    shared.ready.notify_one();
    let until = Instant::now()
        .checked_add(Duration::from_millis(shared.limits.response_timeout_ms))
        .ok_or_else(unavailable)?;
    loop {
        let remaining = until
            .checked_duration_since(Instant::now())
            .ok_or_else(unavailable)?;
        match rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(packet) => return send_packet(&mut stream, shared, packet),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(unavailable()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // One request per connection. Keep the duplex socket open until its reply;
                // FIN, reset or extra request bytes cancels only this connection's queued work.
                if shared.closed.load(Ordering::Acquire) || !peer_waiting(&stream)? {
                    drop(cancellation);
                    return Err(unavailable());
                }
            }
        }
    }
}

fn peer_waiting(stream: &TcpStream) -> std::io::Result<bool> {
    stream.set_nonblocking(true)?;
    let mut byte = [0_u8; 1];
    let result = stream.peek(&mut byte);
    stream.set_nonblocking(false)?;
    match result {
        Ok(_) => Ok(false), // FIN or unrequested pipelined bytes.
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(true),
        Err(_) => Ok(false),
    }
}

fn send_packet(stream: &mut TcpStream, shared: &Shared, packet: Packet) -> std::io::Result<()> {
    let until = Instant::now()
        .checked_add(Duration::from_millis(shared.limits.write_timeout_ms))
        .ok_or_else(unavailable)?;
    let length = u32::try_from(packet.bytes.len()).map_err(|_| unavailable())?;
    let mut writer = DeadlineSocket { stream, until };
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&packet.bytes)?;
    writer.flush()
}
