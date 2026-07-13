//! Bounded content-safe event retention and resumable live delivery.

use futures_core::Stream;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

const MAX_HISTORY_EVENTS: usize = 10_000;
const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 1024 * 1024;
const MAX_SUBSCRIBERS: usize = 128;
const MAX_LIVE_CAPACITY: usize = 256;
const MAX_ATTRIBUTES: usize = 32;
const MAX_ATTRIBUTE_TEXT_BYTES: usize = 256;

/// Stable content-free safe-event failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventError {
    /// Event broker bounds were invalid or a serialized event exceeded its byte bound.
    LimitExceeded,
    /// A code, run ID, attribute key, or attribute value was outside the safe profile.
    InvalidEvent,
    /// A resume sequence was zero or ahead of the broker.
    InvalidResume,
    /// The configured concurrent subscriber capacity was exhausted.
    SubscriberLimit,
    /// Secure randomness or UTC timestamp generation was unavailable.
    IdentityUnavailable,
    /// The event sequence space was exhausted.
    SequenceExhausted,
    /// Bounded broker state was unavailable.
    StoreUnavailable,
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "dashboard event limit was exceeded",
            Self::InvalidEvent => "dashboard safe event is invalid",
            Self::InvalidResume => "dashboard event resume sequence is invalid",
            Self::SubscriberLimit => "dashboard event subscriber limit was reached",
            Self::IdentityUnavailable => "dashboard event identity is unavailable",
            Self::SequenceExhausted => "dashboard event sequence was exhausted",
            Self::StoreUnavailable => "dashboard event store is unavailable",
        })
    }
}

impl std::error::Error for EventError {}

/// Closed safe-event source category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeEventKind {
    /// Aggregate sidecar or daemon status transition.
    Status,
    /// Verified content-safe protocol observation.
    Protocol,
    /// Reviewed dashboard-controlled run transition.
    Run,
    /// Evidence verification transition.
    Evidence,
    /// Browser session lifecycle transition.
    Session,
}

impl SafeEventKind {
    /// Returns the stable SSE event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Protocol => "protocol",
            Self::Run => "run",
            Self::Evidence => "evidence",
            Self::Session => "session",
        }
    }
}

/// Closed scalar value accepted in a browser-safe event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SafeEventAttribute {
    /// Boolean state.
    Boolean(bool),
    /// Nonnegative bounded JSON integer.
    Unsigned(u64),
    /// Short printable ASCII status code or opaque value.
    Text(String),
}

/// Deterministically ordered content-safe event attributes.
pub type SafeEventAttributes = BTreeMap<String, SafeEventAttribute>;

/// One strict content-safe event retained and delivered by the sidecar.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeEvent {
    schema_version: String,
    event_id: String,
    sequence: u64,
    observed_at: String,
    kind: SafeEventKind,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    attributes: SafeEventAttributes,
}

impl SafeEvent {
    /// Returns the monotonic broker sequence used as the SSE ID.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the closed SSE event category.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        self.kind.as_str()
    }

    /// Serializes the already validated event for SSE delivery.
    pub fn to_json(&self) -> Result<String, EventError> {
        serde_json::to_string(self).map_err(|_error| EventError::InvalidEvent)
    }

    /// Parses and revalidates one retained event from dashboard-owned storage.
    pub fn from_json(source: &str) -> Result<Self, EventError> {
        let event: Self =
            serde_json::from_str(source).map_err(|_error| EventError::InvalidEvent)?;
        event.validate()?;
        Ok(event)
    }

    /// Returns the strict UTC observation timestamp used for retention.
    #[must_use]
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }

    /// Returns the opaque run identity when this event belongs to one dashboard run.
    #[must_use]
    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    fn validate(&self) -> Result<(), EventError> {
        if self.schema_version != "cigar.dashboard-safe-event.v1"
            || self.sequence == 0
            || !uuid_v7_is_valid(&self.event_id)
            || OffsetDateTime::parse(&self.observed_at, &Rfc3339).is_err()
            || !bounded_identifier(&self.code)
            || self
                .run_id
                .as_deref()
                .is_some_and(|value| !uuid_v7_is_valid(value))
            || !attributes_are_valid(&self.attributes)
        {
            return Err(EventError::InvalidEvent);
        }
        Ok(())
    }

    fn new(
        sequence: u64,
        kind: SafeEventKind,
        code: &str,
        run_id: Option<&str>,
        attributes: SafeEventAttributes,
    ) -> Result<Self, EventError> {
        if sequence == 0
            || !bounded_identifier(code)
            || run_id.is_some_and(|value| !uuid_v7_is_valid(value))
            || !attributes_are_valid(&attributes)
        {
            return Err(EventError::InvalidEvent);
        }
        Ok(Self {
            schema_version: "cigar.dashboard-safe-event.v1".to_owned(),
            event_id: uuid_v7()?,
            sequence,
            observed_at: now_rfc3339()?,
            kind,
            code: code.to_owned(),
            run_id: run_id.map(str::to_owned),
            attributes,
        })
    }
}

struct RetainedEvent {
    event: SafeEvent,
    encoded_bytes: usize,
}

struct BrokerState {
    next_sequence: u64,
    retained_bytes: usize,
    history: VecDeque<RetainedEvent>,
}

struct BrokerInner {
    state: Mutex<BrokerState>,
    live: broadcast::Sender<SafeEvent>,
    subscriber_permits: Arc<Semaphore>,
    max_history_events: usize,
    max_history_bytes: usize,
    max_event_bytes: usize,
    sink: Mutex<Option<Arc<dyn SafeEventSink>>>,
}

/// Synchronous persistence boundary used to commit an event before live publication.
pub trait SafeEventSink: Send + Sync {
    /// Commits one already validated event or fails the publication.
    fn record(&self, event: &SafeEvent) -> Result<(), EventError>;
}

/// Cloneable bounded in-memory safe-event broker.
#[derive(Clone)]
pub struct SafeEventBroker {
    inner: Arc<BrokerInner>,
}

impl SafeEventBroker {
    /// Creates a broker with hard count, byte, event-size, and subscriber limits.
    pub fn new(
        max_history_events: usize,
        configured_history_bytes: u64,
        max_event_bytes: usize,
        max_subscribers: usize,
    ) -> Result<Self, EventError> {
        Self::new_seeded(
            max_history_events,
            configured_history_bytes,
            max_event_bytes,
            max_subscribers,
            Vec::new(),
        )
    }

    /// Creates a broker seeded from strictly validated dashboard-owned retained events.
    pub fn new_seeded(
        max_history_events: usize,
        configured_history_bytes: u64,
        max_event_bytes: usize,
        max_subscribers: usize,
        retained_events: Vec<SafeEvent>,
    ) -> Result<Self, EventError> {
        let max_history_bytes = usize::try_from(
            configured_history_bytes.min(u64::try_from(MAX_HISTORY_BYTES).unwrap_or(u64::MAX)),
        )
        .map_err(|_error| EventError::LimitExceeded)?;
        if !(1..=MAX_HISTORY_EVENTS).contains(&max_history_events)
            || !(256..=MAX_EVENT_BYTES).contains(&max_event_bytes)
            || !(1..=MAX_SUBSCRIBERS).contains(&max_subscribers)
            || max_history_bytes < 256
        {
            return Err(EventError::LimitExceeded);
        }
        let live_capacity = max_history_events.min(MAX_LIVE_CAPACITY);
        let (live, _receiver) = broadcast::channel(live_capacity);
        let mut history = VecDeque::new();
        let mut retained_bytes = 0_usize;
        let mut previous_sequence = None;
        for event in retained_events {
            event.validate()?;
            if previous_sequence.is_some_and(|previous| previous >= event.sequence) {
                return Err(EventError::InvalidEvent);
            }
            let encoded_bytes = serde_json::to_vec(&event)
                .map_err(|_error| EventError::InvalidEvent)?
                .len();
            if encoded_bytes > max_event_bytes || encoded_bytes > max_history_bytes {
                return Err(EventError::LimitExceeded);
            }
            while history.len() >= max_history_events
                || retained_bytes
                    .checked_add(encoded_bytes)
                    .is_none_or(|bytes| bytes > max_history_bytes)
            {
                let removed: RetainedEvent =
                    history.pop_front().ok_or(EventError::LimitExceeded)?;
                retained_bytes = retained_bytes
                    .checked_sub(removed.encoded_bytes)
                    .ok_or(EventError::StoreUnavailable)?;
            }
            previous_sequence = Some(event.sequence);
            retained_bytes = retained_bytes
                .checked_add(encoded_bytes)
                .ok_or(EventError::LimitExceeded)?;
            history.push_back(RetainedEvent {
                event,
                encoded_bytes,
            });
        }
        let next_sequence = previous_sequence.map_or(Ok(1), |sequence| {
            sequence.checked_add(1).ok_or(EventError::SequenceExhausted)
        })?;
        Ok(Self {
            inner: Arc::new(BrokerInner {
                state: Mutex::new(BrokerState {
                    next_sequence,
                    retained_bytes,
                    history,
                }),
                live,
                subscriber_permits: Arc::new(Semaphore::new(max_subscribers)),
                max_history_events,
                max_history_bytes,
                max_event_bytes,
                sink: Mutex::new(None),
            }),
        })
    }

    /// Attaches exactly one persistence sink before the first new event is published.
    pub fn attach_sink(&self, sink: Arc<dyn SafeEventSink>) -> Result<(), EventError> {
        let mut current = self
            .inner
            .sink
            .lock()
            .map_err(|_poisoned| EventError::StoreUnavailable)?;
        if current.is_some() {
            return Err(EventError::StoreUnavailable);
        }
        *current = Some(sink);
        Ok(())
    }

    /// Validates, sequences, retains, and publishes one content-safe event.
    pub fn publish(
        &self,
        kind: SafeEventKind,
        code: &str,
        run_id: Option<&str>,
        attributes: SafeEventAttributes,
    ) -> Result<SafeEvent, EventError> {
        let mut state = self.lock_state()?;
        let sequence = state.next_sequence;
        let event = SafeEvent::new(sequence, kind, code, run_id, attributes)?;
        let encoded_bytes = serde_json::to_vec(&event)
            .map_err(|_error| EventError::InvalidEvent)?
            .len();
        if encoded_bytes > self.inner.max_event_bytes
            || encoded_bytes > self.inner.max_history_bytes
        {
            return Err(EventError::LimitExceeded);
        }
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(EventError::SequenceExhausted)?;
        let sink = self
            .inner
            .sink
            .lock()
            .map_err(|_poisoned| EventError::StoreUnavailable)?
            .clone();
        if let Some(sink) = sink {
            sink.record(&event)?;
        }
        state.next_sequence = next_sequence;
        while state.history.len() >= self.inner.max_history_events
            || state
                .retained_bytes
                .checked_add(encoded_bytes)
                .is_none_or(|bytes| bytes > self.inner.max_history_bytes)
        {
            let removed = state.history.pop_front().ok_or(EventError::LimitExceeded)?;
            state.retained_bytes = state
                .retained_bytes
                .checked_sub(removed.encoded_bytes)
                .ok_or(EventError::StoreUnavailable)?;
        }
        state.retained_bytes = state
            .retained_bytes
            .checked_add(encoded_bytes)
            .ok_or(EventError::LimitExceeded)?;
        state.history.push_back(RetainedEvent {
            event: event.clone(),
            encoded_bytes,
        });
        drop(state);
        let _ignored = self.inner.live.send(event.clone());
        Ok(event)
    }

    /// Creates a bounded replay plus live stream after an optional SSE sequence.
    pub fn subscribe(
        &self,
        last_event_sequence: Option<u64>,
    ) -> Result<SafeEventStream, EventError> {
        if last_event_sequence == Some(0) {
            return Err(EventError::InvalidResume);
        }
        let permit = self
            .inner
            .subscriber_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_error| EventError::SubscriberLimit)?;
        let receiver = self.inner.live.subscribe();
        let state = self.lock_state()?;
        let latest = state.next_sequence.saturating_sub(1);
        if last_event_sequence.is_some_and(|sequence| sequence > latest) {
            return Err(EventError::InvalidResume);
        }
        let oldest = state
            .history
            .front()
            .map_or(state.next_sequence, |retained| retained.event.sequence);
        let mut replay = VecDeque::new();
        let gap = last_event_sequence
            .is_some_and(|sequence| sequence.checked_add(1).is_none_or(|next| next < oldest));
        if gap {
            replay.push_back(resync_event(oldest, latest)?);
        } else {
            replay.extend(
                state
                    .history
                    .iter()
                    .filter(|retained| {
                        last_event_sequence
                            .is_none_or(|sequence| retained.event.sequence > sequence)
                    })
                    .map(|retained| retained.event.clone()),
            );
        }
        drop(state);
        Ok(SafeEventStream {
            broker: self.clone(),
            replay,
            live: BroadcastStream::new(receiver),
            watermark: latest,
            terminated: false,
            _permit: permit,
        })
    }

    fn resync_current(&self) -> Result<SafeEvent, EventError> {
        let state = self.lock_state()?;
        let latest = state.next_sequence.saturating_sub(1);
        let oldest = state
            .history
            .front()
            .map_or(state.next_sequence, |retained| retained.event.sequence);
        resync_event(oldest, latest)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, BrokerState>, EventError> {
        self.inner
            .state
            .lock()
            .map_err(|_poisoned| EventError::StoreUnavailable)
    }
}

impl fmt::Debug for SafeEventBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeEventBroker")
            .field("max_history_events", &self.inner.max_history_events)
            .field("max_history_bytes", &self.inner.max_history_bytes)
            .field("max_event_bytes", &self.inner.max_event_bytes)
            .finish_non_exhaustive()
    }
}

/// One replay-then-live subscription that terminates after an explicit lag resync event.
pub struct SafeEventStream {
    broker: SafeEventBroker,
    replay: VecDeque<SafeEvent>,
    live: BroadcastStream<SafeEvent>,
    watermark: u64,
    terminated: bool,
    _permit: OwnedSemaphorePermit,
}

impl Stream for SafeEventStream {
    type Item = Result<SafeEvent, EventError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(event) = self.replay.pop_front() {
            return Poll::Ready(Some(Ok(event)));
        }
        if self.terminated {
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut self.live).poll_next(context) {
                Poll::Ready(Some(Ok(event))) if event.sequence > self.watermark => {
                    self.watermark = event.sequence;
                    return Poll::Ready(Some(Ok(event)));
                }
                Poll::Ready(Some(Ok(_duplicate))) => continue,
                Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(_skipped)))) => {
                    self.terminated = true;
                    return Poll::Ready(Some(self.broker.resync_current()));
                }
                Poll::Ready(None) => {
                    self.terminated = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl fmt::Debug for SafeEventStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeEventStream")
            .field("replay_count", &self.replay.len())
            .field("watermark", &self.watermark)
            .field("terminated", &self.terminated)
            .finish_non_exhaustive()
    }
}

fn resync_event(oldest: u64, latest: u64) -> Result<SafeEvent, EventError> {
    if latest == 0 || oldest == 0 || oldest > latest.saturating_add(1) {
        return Err(EventError::InvalidResume);
    }
    let mut attributes = SafeEventAttributes::new();
    attributes.insert(
        "oldest_available".to_owned(),
        SafeEventAttribute::Unsigned(oldest),
    );
    attributes.insert(
        "latest_available".to_owned(),
        SafeEventAttribute::Unsigned(latest),
    );
    SafeEvent::new(
        latest,
        SafeEventKind::Status,
        "stream.resync_required",
        None,
        attributes,
    )
}

fn attributes_are_valid(attributes: &SafeEventAttributes) -> bool {
    attributes.len() <= MAX_ATTRIBUTES
        && attributes.iter().all(|(key, value)| {
            bounded_identifier(key)
                && match value {
                    SafeEventAttribute::Boolean(_) | SafeEventAttribute::Unsigned(_) => true,
                    SafeEventAttribute::Text(text) => {
                        !text.is_empty()
                            && text.len() <= MAX_ATTRIBUTE_TEXT_BYTES
                            && text
                                .bytes()
                                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
                    }
                }
        })
}

pub(crate) fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !value.ends_with(['.', '_', '-'])
        && !value.contains("..")
        && !value.contains("__")
        && !value.contains("--")
}

pub(crate) fn uuid_v7_is_valid(value: &str) -> bool {
    let mut parts = value.split('-');
    let valid = matches!(parts.next(), Some(part) if part.len() == 8 && is_lower_hex(part))
        && matches!(parts.next(), Some(part) if part.len() == 4 && is_lower_hex(part))
        && matches!(parts.next(), Some(part) if part.len() == 4 && part.starts_with('7') && is_lower_hex(part))
        && matches!(parts.next(), Some(part) if part.len() == 4 && part.starts_with(['8', '9', 'a', 'b']) && is_lower_hex(part))
        && matches!(parts.next(), Some(part) if part.len() == 12 && is_lower_hex(part));
    valid && parts.next().is_none()
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn uuid_v7() -> Result<String, EventError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| EventError::IdentityUnavailable)?
        .as_millis()
        & ((1_u128 << 48) - 1);
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_error| EventError::IdentityUnavailable)?;
    let entropy = u128::from_be_bytes(random);
    let mut value = (timestamp << 80) | (entropy & ((1_u128 << 76) - 1));
    value = (value & !(0xf_u128 << 76)) | (0x7_u128 << 76);
    value = (value & !(0x3_u128 << 62)) | (0x2_u128 << 62);
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) & 0xffff_ffff,
        (value >> 80) & 0xffff,
        (value >> 64) & 0xffff,
        (value >> 48) & 0xffff,
        value & 0xffff_ffff_ffff
    ))
}

pub(crate) fn now_rfc3339() -> Result<String, EventError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_error| EventError::IdentityUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        EventError, SafeEventAttribute, SafeEventAttributes, SafeEventBroker, SafeEventKind,
    };
    use tokio_stream::StreamExt as _;

    fn broker(
        events: usize,
        bytes: u64,
        subscribers: usize,
    ) -> Result<SafeEventBroker, EventError> {
        SafeEventBroker::new(events, bytes, 4096, subscribers)
    }

    fn publish(broker: &SafeEventBroker, value: u64) -> Result<u64, EventError> {
        let mut attributes = SafeEventAttributes::new();
        attributes.insert("value".to_owned(), SafeEventAttribute::Unsigned(value));
        broker
            .publish(SafeEventKind::Status, "status.observed", None, attributes)
            .map(|event| event.sequence())
    }

    #[tokio::test]
    async fn replay_is_ordered_and_retention_gap_requires_resync()
    -> Result<(), Box<dyn std::error::Error>> {
        let broker = broker(2, 4096, 2)?;
        assert_eq!(publish(&broker, 1)?, 1);
        assert_eq!(publish(&broker, 2)?, 2);
        assert_eq!(publish(&broker, 3)?, 3);

        let mut replay = broker.subscribe(Some(1))?;
        assert_eq!(
            replay
                .next()
                .await
                .transpose()?
                .map(|event| event.sequence()),
            Some(2)
        );
        assert_eq!(
            replay
                .next()
                .await
                .transpose()?
                .map(|event| event.sequence()),
            Some(3)
        );
        drop(replay);

        assert_eq!(publish(&broker, 4)?, 4);
        let mut gap = broker.subscribe(Some(1))?;
        let resync = gap.next().await.transpose()?.ok_or("resync missing")?;
        assert_eq!(resync.sequence(), 4);
        assert!(resync.to_json()?.contains("stream.resync_required"));
        Ok(())
    }

    #[tokio::test]
    async fn lag_emits_one_resync_then_closes() -> Result<(), Box<dyn std::error::Error>> {
        let broker = broker(2, 4096, 1)?;
        let mut stream = broker.subscribe(None)?;
        publish(&broker, 1)?;
        publish(&broker, 2)?;
        publish(&broker, 3)?;
        let resync = stream.next().await.transpose()?.ok_or("resync missing")?;
        assert!(resync.to_json()?.contains("stream.resync_required"));
        assert!(stream.next().await.is_none());
        Ok(())
    }

    #[test]
    fn subscribers_attributes_and_resume_are_strictly_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let broker = broker(4, 4096, 1)?;
        let subscription = broker.subscribe(None)?;
        assert_eq!(
            broker.subscribe(None).err(),
            Some(EventError::SubscriberLimit)
        );
        drop(subscription);
        assert!(broker.subscribe(None).is_ok());
        assert_eq!(
            broker.subscribe(Some(1)).err(),
            Some(EventError::InvalidResume)
        );

        let mut invalid = SafeEventAttributes::new();
        invalid.insert(
            "tenant".to_owned(),
            SafeEventAttribute::Text("line\nsecret".to_owned()),
        );
        assert_eq!(
            broker
                .publish(SafeEventKind::Protocol, "protocol.observed", None, invalid)
                .err(),
            Some(EventError::InvalidEvent)
        );
        Ok(())
    }
}
