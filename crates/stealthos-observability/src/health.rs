//! Health-check and metrics HTTP endpoints.
//!
//! Provides a lightweight [`axum::Router`] serving:
//! - `GET /health` -- JSON health status for load balancers and Docker `HEALTHCHECK`
//! - `GET /metrics` -- Prometheus text exposition format

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::metrics::ServerMetrics;

/// Shared state for the health endpoint.
///
/// Active connection and pool counts are read directly from
/// [`ServerMetrics`] to guarantee a single source of truth.
pub struct HealthState {
    /// Monotonic instant the server started -- used to compute uptime.
    pub start_time: Instant,
    /// Compile-time version string (typically from `env!("CARGO_PKG_VERSION")`).
    pub version: &'static str,
    /// Configured maximum connections.
    pub max_connections: usize,
    /// Configured maximum pools.
    pub max_pools: usize,
    /// Reference to server metrics -- the single source of truth for
    /// active connection/pool gauges and all counters.
    pub metrics: Arc<ServerMetrics>,
}

/// JSON response body for `GET /health`.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_seconds: u64,
    version: &'static str,
    connections: ResourceUsage,
    pools: ResourceUsage,
}

#[derive(Serialize)]
struct ResourceUsage {
    active: usize,
    max: usize,
}

/// Build the health + metrics [`Router`].
///
/// Mount this on the internal metrics bind address (e.g., `127.0.0.1:9091`)
/// so it is not exposed to the public internet.
pub fn health_router(state: Arc<HealthState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// SECURITY: S7 - The health endpoint is intended for load balancers and
/// Docker HEALTHCHECK probes on an internal-only port. It deliberately
/// returns exact resource usage so operators can monitor capacity. If this
/// port is accidentally exposed to the public internet, an attacker could
/// use connection/pool counts to fingerprint the server or determine if
/// targets are online.
///
/// Mitigation: The default `metrics_bind` is `127.0.0.1:9091` and the
/// docker-compose restricts the host-side port to localhost. Operators MUST
/// NOT expose this port publicly.
async fn health_handler(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    // Saturating conversion from u64 to usize. On 32-bit targets the value
    // clamps to usize::MAX, which is acceptable for a display-only gauge.
    let active_conns = usize::try_from(state.metrics.connections_active.load(Ordering::Relaxed))
        .unwrap_or(usize::MAX);
    let active_pools =
        usize::try_from(state.metrics.pools_active.load(Ordering::Relaxed)).unwrap_or(usize::MAX);
    let uptime = state.start_time.elapsed().as_secs();

    let status = if active_conns <= state.max_connections {
        "healthy"
    } else {
        "degraded"
    };

    let body = HealthResponse {
        status,
        uptime_seconds: uptime,
        version: state.version,
        connections: ResourceUsage {
            active: active_conns,
            max: state.max_connections,
        },
        pools: ResourceUsage {
            active: active_pools,
            max: state.max_pools,
        },
    };

    (StatusCode::OK, axum::Json(body))
}

async fn metrics_handler(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let body = state.metrics.to_prometheus();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<HealthState> {
        let metrics = Arc::new(ServerMetrics::new());
        metrics
            .connections_active
            .store(5, std::sync::atomic::Ordering::Relaxed);
        metrics
            .pools_active
            .store(2, std::sync::atomic::Ordering::Relaxed);
        Arc::new(HealthState {
            start_time: Instant::now(),
            version: "0.1.0-test",
            max_connections: 500,
            max_pools: 100,
            metrics,
        })
    }

    #[tokio::test]
    async fn health_response_is_healthy() {
        let state = test_state();
        let app = health_router(state);

        let req = axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["version"], "0.1.0-test");
        assert_eq!(json["connections"]["active"], 5);
        assert_eq!(json["pools"]["max"], 100);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus() {
        let state = test_state();
        state
            .metrics
            .connections_total
            .store(99, std::sync::atomic::Ordering::Relaxed);
        let app = health_router(state);

        let req = axum::http::Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("stealth_relay_connections_total 99"));
    }
}
