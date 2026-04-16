//! Shared event emission helpers for broadcast and Oracle persistence.
//!
//! This module centralizes the common event envelope used across proxy, tunnel,
//! and QUIC paths. It does not decide when events should be emitted.

use serde::Serialize;
use tracing::error;

use crate::state::SharedState;

/// Payload fields stored alongside an emitted event.
///
/// The typed fields are stored in the Oracle row metadata, while `extra` is
/// flattened into the broadcast JSON payload.
pub struct EmitPayload {
    pub peer_ip: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub status_code: Option<u16>,
    pub blocked: bool,
    pub obfuscation_profile: Option<String>,
    pub extra: serde_json::Value,
}

#[derive(Serialize)]
struct EventEnvelope<'a, T>
where
    T: Serialize,
{
    #[serde(rename = "type")]
    event: &'a str,
    host: &'a str,
    time: String,
    #[serde(flatten)]
    extra: T,
}

/// Emit an event using a generic JSON value for the extra payload.
pub fn emit(state: &SharedState, event: &str, host: &str, payload: EmitPayload) {
    emit_serializable(
        state,
        event,
        host,
        payload.peer_ip,
        payload.bytes_up,
        payload.bytes_down,
        payload.status_code,
        payload.blocked,
        payload.obfuscation_profile,
        payload.extra,
    );
}

/// Emit an event using any serializable extra payload.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_serializable<T>(
    state: &SharedState,
    event: &str,
    host: &str,
    peer_ip: Option<String>,
    bytes_up: u64,
    bytes_down: u64,
    status_code: Option<u16>,
    blocked: bool,
    obfuscation_profile: Option<String>,
    extra: T,
) where
    T: Serialize,
{
    #[cfg(not(feature = "oracle-db"))]
    let _ = (
        &peer_ip,
        bytes_up,
        bytes_down,
        status_code,
        blocked,
        &obfuscation_profile,
    );

    let raw = match serde_json::to_string(&EventEnvelope {
        event,
        host,
        time: chrono::Utc::now().to_rfc3339(),
        extra,
    }) {
        Ok(raw) => raw,
        Err(e) => {
            error!(%e, event_name = event, %host, "failed to serialize event envelope");
            return;
        }
    };

    let _ = state.events_tx.send(raw.clone());

    #[cfg(feature = "oracle-db")]
    crate::db::insert_proxy_event(
        state.db.clone(),
        crate::db::ProxyEvent {
            obfuscation_profile,
            event_type: event.to_string(),
            host: host.to_string(),
            peer_ip,
            bytes_up,
            bytes_down,
            status_code,
            blocked,
            correlation_id: None,
            parent_event_id: None,
            event_sequence: None,
            duration_ms: None,
            raw_json: raw,
        },
    );
}

#[cfg(test)]
mod tests {
    use hickory_resolver::TokioAsyncResolver;
    use serde::ser::{Error as _, Serializer};
    use tokio::sync::broadcast;

    use super::*;

    struct FailingExtra;

    impl Serialize for FailingExtra {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("intentional serialization failure"))
        }
    }

    async fn create_test_state() -> SharedState {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .expect("system resolver should initialize");

        crate::state::AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            crate::config::Config::for_tests(),
            #[cfg(feature = "oracle-db")]
            tokio_util::sync::CancellationToken::new(),
        )
    }

    #[tokio::test]
    async fn emit_serializable_skips_broadcast_when_serialization_fails() {
        let state = create_test_state().await;
        let mut rx = state.events_tx.subscribe();

        emit_serializable(
            &state,
            "test_event",
            "example.com",
            None,
            0,
            0,
            None,
            false,
            None,
            FailingExtra,
        );

        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }
}
