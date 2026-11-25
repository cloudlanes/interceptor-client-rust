//! The reconnect, retry and redirect policy shared by every `interceptor-client`
//! (`interceptor-docs/client-api/retry-policy.md`, E13-T007).
//!
//! [`RetryPolicy::decide`] says what to do with an operation when an error, a `Close` or a lost
//! connection hits it. It is pure: the connection code applies the decision. Every reconnect
//! resumes the TLS session when a ticket for that server name is cached.
//! `conformance/retry-policy-v1.json` holds the shared vectors, which `tests/retry_policy.rs`
//! runs.

use std::fmt;
use std::time::Duration;

/// The backoff ceiling stops doubling after this many retries.
const MAX_BACKOFF_EXPONENT: u32 = 20;
/// The largest `max_retry_delay` accepted: `2^31 - 1` ms.
const MAX_RETRY_DELAY_LIMIT_MS: u64 = (1 << 31) - 1;

/// Whether an operation may be sent again when its outcome is unknown (the `Retry` column of
/// `client-api/v1.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Repeating it changes nothing more.
    Idempotent,
    /// A send: repeated, with duplicates dropped by the entity's duplicate detection.
    ByMessageId,
    /// Repeating it may fail or act twice.
    Once,
}

/// Where one operation stands when an event hits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attempt {
    /// Retries already made, redirects included.
    pub retries: u32,
    /// Redirects already followed since the last answer that was not a redirect.
    pub redirects: u32,
    /// A uniform random `u32` for the backoff's jitter.
    pub jitter: u32,
}

/// What happened to an in-flight operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// An `Error`, `RESET` or `Redirect` answered the operation on its stream.
    Error {
        /// The ion error code.
        code: &'a str,
        /// A redirect's endpoint.
        endpoint: Option<&'a str>,
    },
    /// An `Error` on the control stream: the server closes the connection.
    ConnectionError {
        /// The ion error code.
        code: &'a str,
        /// Where to reconnect, for a redirect.
        endpoint: Option<&'a str>,
    },
    /// A `Close` (drain): in-flight streams finish, then the connection closes.
    Close {
        /// The reconnect hint.
        endpoint: Option<&'a str>,
    },
    /// The connection ended with no `Error` while the operation was in flight.
    ConnectionLost {
        /// Whether a `Close` came first.
        draining: bool,
        /// That `Close`'s endpoint.
        endpoint: Option<&'a str>,
    },
}

/// What happens to the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send it again after the delay.
    Retry,
    /// Return the error to the application.
    Surface,
    /// Keep waiting for its answer on the draining connection.
    Continue,
}

/// What happens to the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connection<'a> {
    /// Keep using it.
    Keep,
    /// Connect to this endpoint after the delay.
    ConnectEndpoint(&'a str),
    /// Connect through the configured Service address after the delay.
    ConnectService,
    /// Drop it; the next call connects through the Service.
    Close,
}

/// The policy's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision<'a> {
    /// The operation's fate.
    pub action: Action,
    /// How long to wait before connecting and retrying.
    pub delay: Duration,
    /// The connection's fate.
    pub connection: Connection<'a>,
}

/// Retry settings out of range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRetryPolicy;

impl fmt::Display for InvalidRetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("retry delays need 1 ms <= initial <= max <= 2^31 - 1 ms")
    }
}

impl std::error::Error for InvalidRetryPolicy {}

/// The retry settings and the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    initial_retry_delay_ms: u64,
    max_retry_delay_ms: u64,
    max_retries_send: Option<u32>,
    max_retries_other: Option<u32>,
}

impl Default for RetryPolicy {
    /// `initialRetryDelay` 100 ms, `maxRetryDelay` 5 s, `maxRetries` unlimited for sends and 10
    /// for every other call.
    fn default() -> Self {
        Self {
            initial_retry_delay_ms: 100,
            max_retry_delay_ms: 5_000,
            max_retries_send: None,
            max_retries_other: Some(10),
        }
    }
}

impl RetryPolicy {
    /// A policy with these settings; `None` retries without limit.
    ///
    /// # Errors
    ///
    /// Unless `1 ms <= initial_retry_delay <= max_retry_delay <= 2^31 - 1 ms`.
    pub fn new(
        initial_retry_delay: Duration,
        max_retry_delay: Duration,
        max_retries_send: Option<u32>,
        max_retries_other: Option<u32>,
    ) -> Result<Self, InvalidRetryPolicy> {
        let initial = u64::try_from(initial_retry_delay.as_millis()).unwrap_or(u64::MAX);
        let max = u64::try_from(max_retry_delay.as_millis()).unwrap_or(u64::MAX);
        if initial == 0 || initial > max || max > MAX_RETRY_DELAY_LIMIT_MS {
            return Err(InvalidRetryPolicy);
        }
        Ok(Self {
            initial_retry_delay_ms: initial,
            max_retry_delay_ms: max,
            max_retries_send,
            max_retries_other,
        })
    }

    /// `maxRetries` for an operation of this class.
    #[must_use]
    pub const fn max_retries(&self, class: RetryClass) -> Option<u32> {
        match class {
            RetryClass::ByMessageId => self.max_retries_send,
            RetryClass::Idempotent | RetryClass::Once => self.max_retries_other,
        }
    }

    /// The delay before retry number `retries` (0 for the first): uniform in
    /// `[ceiling / 2, ceiling)`, `ceiling = min(max, initial * 2^min(retries, 20))`, picked by
    /// `jitter`.
    #[must_use]
    pub fn backoff(&self, retries: u32, jitter: u32) -> Duration {
        let ceiling = (self.initial_retry_delay_ms << retries.min(MAX_BACKOFF_EXPONENT))
            .min(self.max_retry_delay_ms);
        let half = ceiling / 2;
        Duration::from_millis(half + (((ceiling - half) * u64::from(jitter)) >> 32))
    }

    /// What to do with an operation of class `class` at `attempt` when `event` hits it.
    #[must_use]
    pub fn decide<'a>(
        &self,
        class: RetryClass,
        attempt: Attempt,
        event: Event<'a>,
    ) -> Decision<'a> {
        let exhausted = self
            .max_retries(class)
            .is_some_and(|max| attempt.retries >= max);
        let may_resend = class != RetryClass::Once;
        let backoff = || self.backoff(attempt.retries, attempt.jitter);
        let retry = |delay, connection| Decision {
            action: Action::Retry,
            delay,
            connection,
        };
        let surface = |connection| Decision {
            action: Action::Surface,
            delay: Duration::ZERO,
            connection,
        };
        let redirect = |endpoint| {
            let delay = if attempt.redirects == 0 {
                Duration::ZERO
            } else {
                backoff()
            };
            retry(delay, Connection::ConnectEndpoint(endpoint))
        };
        match event {
            Event::Error { code, endpoint } => match Class::of(code) {
                Class::Transient if exhausted => surface(Connection::Keep),
                Class::Transient => {
                    endpoint.map_or_else(|| retry(backoff(), Connection::Keep), redirect)
                }
                Class::Permanent => surface(Connection::Keep),
                Class::Protocol => surface(Connection::Close),
            },
            Event::ConnectionError { code, endpoint } => match Class::of(code) {
                Class::Transient if may_resend && !exhausted => {
                    endpoint.map_or_else(|| retry(backoff(), Connection::ConnectService), redirect)
                }
                _ => surface(Connection::Close),
            },
            Event::Close { endpoint } => Decision {
                action: Action::Continue,
                delay: Duration::ZERO,
                connection: endpoint
                    .map_or(Connection::ConnectService, Connection::ConnectEndpoint),
            },
            Event::ConnectionLost { draining, endpoint } => {
                if !may_resend || exhausted {
                    surface(Connection::Close)
                } else if draining {
                    retry(
                        Duration::ZERO,
                        endpoint.map_or(Connection::ConnectService, Connection::ConnectEndpoint),
                    )
                } else {
                    retry(backoff(), Connection::ConnectService)
                }
            }
        }
    }
}

/// An error code's class, from its prefix; a code with no known prefix is a protocol error.
enum Class {
    Transient,
    Permanent,
    Protocol,
}

impl Class {
    fn of(code: &str) -> Self {
        match code.split_once('.').map(|(prefix, _)| prefix) {
            Some("transient") => Self::Transient,
            Some("permanent") => Self::Permanent,
            _ => Self::Protocol,
        }
    }
}
