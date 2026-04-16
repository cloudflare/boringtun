//! TCP tunnel handling for explicit CONNECT and transparent proxy flows.
//!
//! This module owns the TCP-side proxy paths, including TLS fingerprint peeking,
//! upstream dialing, traffic classification, tarpitting, and optional Oracle
//! session bookkeeping. It does not handle plain HTTP proxying; that remains in
//! `proxy.rs`.

mod classify;
mod connect;
mod db_helpers;
mod dial;
mod tarpit;
mod tls;
mod transparent;

pub use connect::handle;
pub(crate) use dial::parse_host_port;
pub use tarpit::tarpit_semaphore;
pub use transparent::handle_transparent;
