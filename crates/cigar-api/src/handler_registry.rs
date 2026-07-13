//! Complete generated-operation handler registry for embedded and network execution.
//!
//! The registry deliberately leaves opaque page and resume cursors untouched. The concrete
//! domain handler that issued a cursor remains the only authority allowed to authenticate,
//! scope, and interpret it.

use crate::generated::{OPERATION_COUNT, OPERATIONS, StreamKind, operation_by_id};
use crate::{
    ApiError, FacadeEventStream, RequestContext, RequestEnvelope, ResponseEnvelope, ServiceFacade,
    ServiceFuture,
};
use cigar_canon::from_deterministic_cbor;
use cigar_protocol::ErrorCode;
use futures_core::Stream;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Creates content-safe errors for fail-closed registry dispatch.
pub trait FacadeErrorFactory: Send + Sync {
    /// Creates a public error without including request or handler data.
    fn public_error(&self, code: ErrorCode) -> ApiError;
}

/// Object-safe implementation boundary for one generated unary operation.
pub trait UnaryOperationHandler: Send + Sync {
    /// Exact generated operation implemented by this handler.
    fn operation_id(&self) -> &'static str;

    /// Executes the operation after registry-level contract validation.
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>>;
}

/// Object-safe implementation boundary for one generated server-streaming operation.
pub trait StreamOperationHandler: Send + Sync {
    /// Exact generated operation implemented by this handler.
    fn operation_id(&self) -> &'static str;

    /// Opens a bounded resumable stream after registry-level contract validation.
    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>>;
}

/// Stable, content-free complete-registry construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerRegistryError {
    /// The handler identity is not present in the frozen generated contract.
    UnknownOperation,
    /// A unary handler was supplied for a stream operation or conversely.
    WrongHandlerKind,
    /// More than one handler claimed the same generated operation.
    DuplicateHandler,
    /// At least one generated operation has no concrete handler.
    MissingHandler,
}

impl fmt::Display for HandlerRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownOperation => "handler operation is not in the frozen registry",
            Self::WrongHandlerKind => "handler kind disagrees with the frozen registry",
            Self::DuplicateHandler => "generated operation has duplicate handlers",
            Self::MissingHandler => "generated operation is missing a concrete handler",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HandlerRegistryError {}

/// Builder requiring exactly one correctly typed handler for every frozen operation.
pub struct CompleteServiceFacadeBuilder {
    unary: BTreeMap<&'static str, Arc<dyn UnaryOperationHandler>>,
    streams: BTreeMap<&'static str, Arc<dyn StreamOperationHandler>>,
    errors: Arc<dyn FacadeErrorFactory>,
}

impl CompleteServiceFacadeBuilder {
    /// Starts an empty fail-closed registry with an injected public-error authority.
    #[must_use]
    pub fn new(errors: Arc<dyn FacadeErrorFactory>) -> Self {
        Self {
            unary: BTreeMap::new(),
            streams: BTreeMap::new(),
            errors,
        }
    }

    /// Registers one unary handler, rejecting unknown, duplicate, or stream identities.
    pub fn register_unary(
        &mut self,
        handler: Arc<dyn UnaryOperationHandler>,
    ) -> Result<&mut Self, HandlerRegistryError> {
        let operation_id = handler.operation_id();
        let contract =
            operation_by_id(operation_id).ok_or(HandlerRegistryError::UnknownOperation)?;
        if contract.stream_kind != StreamKind::Unary {
            return Err(HandlerRegistryError::WrongHandlerKind);
        }
        if self.streams.contains_key(operation_id) || self.unary.contains_key(operation_id) {
            return Err(HandlerRegistryError::DuplicateHandler);
        }
        self.unary.insert(operation_id, handler);
        Ok(self)
    }

    /// Registers one stream handler, rejecting unknown, duplicate, or unary identities.
    pub fn register_stream(
        &mut self,
        handler: Arc<dyn StreamOperationHandler>,
    ) -> Result<&mut Self, HandlerRegistryError> {
        let operation_id = handler.operation_id();
        let contract =
            operation_by_id(operation_id).ok_or(HandlerRegistryError::UnknownOperation)?;
        if contract.stream_kind != StreamKind::ServerStream {
            return Err(HandlerRegistryError::WrongHandlerKind);
        }
        if self.unary.contains_key(operation_id) || self.streams.contains_key(operation_id) {
            return Err(HandlerRegistryError::DuplicateHandler);
        }
        self.streams.insert(operation_id, handler);
        Ok(self)
    }

    /// Seals the registry only when every generated operation has one concrete handler.
    pub fn build(self) -> Result<CompleteServiceFacade, HandlerRegistryError> {
        let configured: BTreeSet<_> = self
            .unary
            .keys()
            .chain(self.streams.keys())
            .copied()
            .collect();
        let required: BTreeSet<_> = OPERATIONS
            .iter()
            .map(|operation| operation.operation_id)
            .collect();
        if configured.len() != OPERATION_COUNT || configured != required {
            return Err(HandlerRegistryError::MissingHandler);
        }
        Ok(CompleteServiceFacade {
            unary: self.unary,
            streams: self.streams,
            errors: self.errors,
        })
    }
}

impl fmt::Debug for CompleteServiceFacadeBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompleteServiceFacadeBuilder")
            .field("unary_handler_count", &self.unary.len())
            .field("stream_handler_count", &self.streams.len())
            .field("errors", &"[INJECTED]")
            .finish()
    }
}

/// Immutable embedded facade proven complete against the generated operation registry.
pub struct CompleteServiceFacade {
    unary: BTreeMap<&'static str, Arc<dyn UnaryOperationHandler>>,
    streams: BTreeMap<&'static str, Arc<dyn StreamOperationHandler>>,
    errors: Arc<dyn FacadeErrorFactory>,
}

impl CompleteServiceFacade {
    /// Returns all registered operation identities in stable lexical order.
    #[must_use]
    pub fn registered_operation_ids(&self) -> Vec<&'static str> {
        let mut operations: Vec<_> = self
            .unary
            .keys()
            .chain(self.streams.keys())
            .copied()
            .collect();
        operations.sort_unstable();
        operations
    }

    fn validate(
        &self,
        context: &RequestContext,
        request: &RequestEnvelope,
        kind: StreamKind,
    ) -> Result<&'static crate::generated::OperationContract, ApiError> {
        let contract = operation_by_id(request.operation_id().as_str())
            .ok_or_else(|| self.errors.public_error(ErrorCode::InvalidArgument))?;
        if context.operation() != request.operation_id() || contract.stream_kind != kind {
            return Err(self.errors.public_error(ErrorCode::InvalidArgument));
        }
        request
            .validate_contract(contract)
            .map_err(|failure| self.errors.public_error(failure.error_code()))?;
        if !request.payload_cbor().is_empty()
            && from_deterministic_cbor(request.payload_cbor()).is_err()
        {
            return Err(self.errors.public_error(ErrorCode::InvalidArgument));
        }
        Ok(contract)
    }
}

impl ServiceFacade for CompleteServiceFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        Box::pin(async move {
            let contract = self.validate(&context, &request, StreamKind::Unary)?;
            let handler = self
                .unary
                .get(contract.operation_id)
                .ok_or_else(|| self.errors.public_error(ErrorCode::Internal))?;
            let response = handler.call(context, request).await?;
            if response.operation_id().as_str() != contract.operation_id {
                return Err(self.errors.public_error(ErrorCode::Internal));
            }
            if !response.payload_cbor().is_empty()
                && from_deterministic_cbor(response.payload_cbor()).is_err()
            {
                return Err(self.errors.public_error(ErrorCode::Internal));
            }
            Ok(response)
        })
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        Box::pin(async move {
            let contract = self.validate(&context, &request, StreamKind::ServerStream)?;
            let handler = self
                .streams
                .get(contract.operation_id)
                .ok_or_else(|| self.errors.public_error(ErrorCode::Internal))?;
            let stream = handler.subscribe(context, request).await?;
            Ok(Box::pin(RegistryEventStream {
                inner: stream,
                expected_operation: contract.operation_id,
                errors: Arc::clone(&self.errors),
                ended: false,
            }) as FacadeEventStream)
        })
    }
}

struct RegistryEventStream {
    inner: FacadeEventStream,
    expected_operation: &'static str,
    errors: Arc<dyn FacadeErrorFactory>,
    ended: bool,
}

impl Stream for RegistryEventStream {
    type Item = <FacadeEventStream as Stream>::Item;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(event)))
                if event.operation_id().as_str() != self.expected_operation
                    || (!event.payload_cbor().is_empty()
                        && from_deterministic_cbor(event.payload_cbor()).is_err()) =>
            {
                self.ended = true;
                Poll::Ready(Some(Err(self.errors.public_error(ErrorCode::Internal))))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            result => result,
        }
    }
}

impl fmt::Debug for CompleteServiceFacade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompleteServiceFacade")
            .field("operation_count", &self.registered_operation_ids().len())
            .field("handlers", &"[INJECTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompleteServiceFacadeBuilder, FacadeErrorFactory, HandlerRegistryError,
        StreamOperationHandler, UnaryOperationHandler,
    };
    use crate::generated::{OPERATION_COUNT, OPERATIONS, StreamKind};
    use crate::{
        ApiError, FacadeEventStream, RequestContext, RequestEnvelope, ResponseEnvelope,
        ServiceFuture,
    };
    use cigar_protocol::{ErrorCode, RecordId};
    use futures_core::Stream;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    struct Errors(RecordId);

    impl FacadeErrorFactory for Errors {
        fn public_error(&self, code: ErrorCode) -> ApiError {
            ApiError::new(code, self.0.clone())
        }
    }

    struct Unary {
        operation_id: &'static str,
        correlation: RecordId,
    }

    impl Unary {
        fn new(operation_id: &'static str) -> Result<Self, cigar_protocol::ValidationErrors> {
            Ok(Self {
                operation_id,
                correlation: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            })
        }
    }

    impl UnaryOperationHandler for Unary {
        fn operation_id(&self) -> &'static str {
            self.operation_id
        }

        fn call<'a>(
            &'a self,
            _context: RequestContext,
            request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
            let operation = request.operation_id().as_str().to_owned();
            let correlation = self.correlation.clone();
            Box::pin(async move {
                ResponseEnvelope::new(operation, vec![0xf6], None, None)
                    .map_err(|_error| ApiError::new(ErrorCode::Internal, correlation))
            })
        }
    }

    struct Streaming(&'static str);

    struct EmptyStream;

    impl Stream for EmptyStream {
        type Item = Result<crate::EventEnvelope, ApiError>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    impl StreamOperationHandler for Streaming {
        fn operation_id(&self) -> &'static str {
            self.0
        }

        fn subscribe<'a>(
            &'a self,
            _context: RequestContext,
            _request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
            Box::pin(async move { Ok(Box::pin(EmptyStream) as FacadeEventStream) })
        }
    }

    fn builder() -> Result<CompleteServiceFacadeBuilder, Box<dyn std::error::Error>> {
        Ok(CompleteServiceFacadeBuilder::new(Arc::new(Errors(
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        ))))
    }

    #[test]
    fn exact_generated_registry_seals_and_enumerates_all_operations()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = builder()?;
        for operation in OPERATIONS {
            match operation.stream_kind {
                StreamKind::Unary => {
                    builder.register_unary(Arc::new(Unary::new(operation.operation_id)?))?;
                }
                StreamKind::ServerStream => {
                    builder.register_stream(Arc::new(Streaming(operation.operation_id)))?;
                }
            }
        }
        let facade = builder.build()?;
        let mut expected: Vec<_> = OPERATIONS
            .iter()
            .map(|operation| operation.operation_id)
            .collect();
        expected.sort_unstable();
        assert_eq!(facade.registered_operation_ids(), expected);
        assert_eq!(facade.registered_operation_ids().len(), OPERATION_COUNT);
        Ok(())
    }

    #[test]
    fn missing_duplicate_unknown_and_wrong_kind_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            builder()?.build().err(),
            Some(HandlerRegistryError::MissingHandler)
        );

        let mut duplicate = builder()?;
        duplicate.register_unary(Arc::new(Unary::new("getVersion")?))?;
        assert_eq!(
            duplicate
                .register_unary(Arc::new(Unary::new("getVersion")?))
                .err(),
            Some(HandlerRegistryError::DuplicateHandler)
        );

        let mut unknown = builder()?;
        assert_eq!(
            unknown
                .register_unary(Arc::new(Unary::new("notGenerated")?))
                .err(),
            Some(HandlerRegistryError::UnknownOperation)
        );

        let mut wrong = builder()?;
        assert_eq!(
            wrong
                .register_unary(Arc::new(Unary::new("subscribeSpaceEvents")?))
                .err(),
            Some(HandlerRegistryError::WrongHandlerKind)
        );
        assert_eq!(
            wrong
                .register_stream(Arc::new(Streaming("getVersion")))
                .err(),
            Some(HandlerRegistryError::WrongHandlerKind)
        );
        Ok(())
    }
}
