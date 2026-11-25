//! Rust client for `interceptor-server`, speaking the ion protocol (TCP + TLS 1.3, ALPN
//! `interceptor-ion/1`).
//!
//! The API follows the shared client specification (`interceptor-docs/client-api/v1.md`) in four
//! modules: core messaging, management, pipelines and ad-hoc SQL. They land with E13-T011; this
//! crate is the repository scaffold (E13-T002).

/// The ion ALPN token this client major speaks: `interceptor-client` 0.x and 1.x pin ion major 1.
pub const ION_ALPN: &str = "interceptor-ion/1";

pub mod retry;
