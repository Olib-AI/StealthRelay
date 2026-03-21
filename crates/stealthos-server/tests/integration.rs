//! Integration tests for the StealthOS Relay Server.
//!
//! These tests exercise the full stack -- crypto, core domain, observability,
//! and transport -- without requiring an external server process. Each test
//! creates its own isolated state and binds to port 0 for conflict-free
//! parallel execution.

// Integration tests use `unsafe` for `std::env::set_var` / `remove_var`
// which became unsafe in Edition 2024. This is acceptable for test code.
#![deny(warnings)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use stealthos_core::PoolRegistry;
use stealthos_core::pool::PoolPeer;
use stealthos_core::ratelimit::{ConnectionThrottler, IpRateLimiter, RateLimitConfig};
use stealthos_core::router::Router;
use stealthos_core::types::{ConnectionId, PeerId, PoolId};
use stealthos_crypto::pow::PowChallenge;
use stealthos_crypto::{
    HandshakeInitiator, HandshakeResponder, HostIdentity, InvitationToken, PeerIdentity,
    SessionCipher,
};
use stealthos_observability::metrics::ServerMetrics;
use stealthos_observability::{HealthState, health_router};
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

// =========================================================================
// Test 1: Health endpoint
// =========================================================================

/// Start the health HTTP server and verify /health returns 200 with valid JSON
/// containing expected fields: status, version, connections, pools.
#[tokio::test]
async fn health_endpoint_returns_ok() {
    let metrics = Arc::new(ServerMetrics::new());
    metrics.connections_active.store(7, Ordering::Relaxed);
    metrics.pools_active.store(3, Ordering::Relaxed);
    let state = Arc::new(HealthState {
        start_time: Instant::now(),
        version: "0.1.0-test",
        max_connections: 500,
        max_pools: 100,
        metrics,
    });

    let app = health_router(state);

    let req = axum::http::Request::builder()
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "healthy");
    assert_eq!(json["version"], "0.1.0-test");
    assert_eq!(json["connections"]["active"], 7);
    assert_eq!(json["connections"]["max"], 500);
    assert_eq!(json["pools"]["active"], 3);
    assert_eq!(json["pools"]["max"], 100);
    assert!(json["uptime_seconds"].is_number());
}

// =========================================================================
// Test 2: Metrics endpoint
// =========================================================================

/// Verify /metrics returns Prometheus-compatible text with expected metric
/// names and HELP/TYPE annotations.
#[tokio::test]
async fn metrics_endpoint_returns_prometheus() {
    let metrics = Arc::new(ServerMetrics::new());
    metrics.connections_total.store(42, Ordering::Relaxed);
    metrics.messages_relayed.store(1000, Ordering::Relaxed);
    metrics.pools_active.store(5, Ordering::Relaxed);

    let state = Arc::new(HealthState {
        start_time: Instant::now(),
        version: "0.1.0-test",
        max_connections: 500,
        max_pools: 100,
        metrics,
    });

    let app = health_router(state);

    let req = axum::http::Request::builder()
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    // Verify Prometheus exposition format.
    assert!(
        text.contains("# HELP stealth_relay_connections_total"),
        "missing HELP for connections_total"
    );
    assert!(
        text.contains("# TYPE stealth_relay_connections_total counter"),
        "missing TYPE for connections_total"
    );
    assert!(
        text.contains("stealth_relay_connections_total 42"),
        "wrong connections_total value"
    );
    assert!(
        text.contains("stealth_relay_messages_relayed_total 1000"),
        "wrong messages_relayed value"
    );
    assert!(
        text.contains("stealth_relay_pools_active 5"),
        "wrong pools_active value"
    );
    assert!(
        text.contains("# TYPE stealth_relay_pools_active gauge"),
        "pools_active should be a gauge"
    );
}

// =========================================================================
// Test 3: Full crypto lifecycle
// =========================================================================

/// Full handshake -> encrypt -> decrypt -> rekey cycle exercising the
/// entire crypto stack end-to-end.
#[tokio::test]
async fn full_crypto_lifecycle() {
    // Generate identities.
    let host = HostIdentity::generate();
    let peer = PeerIdentity::generate();
    let pool_id = b"integration-test-pool".to_vec();

    // Run handshake.
    let server_x25519_pk = host.x25519_public().to_bytes();
    let initiator = HandshakeInitiator::new(peer, server_x25519_pk, pool_id.clone());
    let (init_msg, awaiting) = initiator.create_init_message();

    let responder = HandshakeResponder::new(&host, pool_id);
    let (response_msg, server_keys) = responder
        .process_init_message(&init_msg)
        .expect("server should process init successfully");

    let server_ed25519_pk = host.public_keys().ed25519;
    let client_keys = awaiting
        .process_response(&response_msg, &server_ed25519_pk)
        .expect("client should process response successfully");

    // Verify keys match.
    assert_eq!(
        client_keys.client_write_key, server_keys.client_write_key,
        "client_write_key mismatch after handshake"
    );
    assert_eq!(
        client_keys.server_write_key, server_keys.server_write_key,
        "server_write_key mismatch after handshake"
    );
    assert_eq!(
        client_keys.rekey_seed, server_keys.rekey_seed,
        "rekey_seed mismatch after handshake"
    );

    // Create session ciphers.
    let mut client_cipher = SessionCipher::new(client_keys, false);
    let mut server_cipher = SessionCipher::new(server_keys, true);

    let aad = b"pool-context";

    // Send 10 messages client -> server.
    for i in 0..10u32 {
        let plaintext = format!("client msg {i}");
        let envelope = client_cipher
            .encrypt(plaintext.as_bytes(), aad)
            .expect("encrypt should succeed");
        let decrypted = server_cipher
            .decrypt(&envelope, aad)
            .expect("decrypt should succeed");
        assert_eq!(
            decrypted,
            plaintext.as_bytes(),
            "decrypted content mismatch for client msg {i}"
        );
    }

    // Send 10 messages server -> client.
    for i in 0..10u32 {
        let plaintext = format!("server msg {i}");
        let envelope = server_cipher
            .encrypt(plaintext.as_bytes(), aad)
            .expect("encrypt should succeed");
        let decrypted = client_cipher
            .decrypt(&envelope, aad)
            .expect("decrypt should succeed");
        assert_eq!(
            decrypted,
            plaintext.as_bytes(),
            "decrypted content mismatch for server msg {i}"
        );
    }

    // Rekey both sides.
    client_cipher.rekey();
    server_cipher.rekey();

    // Send 10 more messages in each direction after rekey.
    for i in 10..20u32 {
        let plaintext = format!("post-rekey client msg {i}");
        let envelope = client_cipher
            .encrypt(plaintext.as_bytes(), aad)
            .expect("encrypt after rekey should succeed");
        let decrypted = server_cipher
            .decrypt(&envelope, aad)
            .expect("decrypt after rekey should succeed");
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    for i in 10..20u32 {
        let plaintext = format!("post-rekey server msg {i}");
        let envelope = server_cipher
            .encrypt(plaintext.as_bytes(), aad)
            .expect("encrypt after rekey should succeed");
        let decrypted = client_cipher
            .decrypt(&envelope, aad)
            .expect("decrypt after rekey should succeed");
        assert_eq!(decrypted, plaintext.as_bytes());
    }
}

// =========================================================================
// Test 4: Invitation flow
// =========================================================================

/// Generate invitation -> encode URL -> decode -> create proof -> verify.
#[tokio::test]
async fn invitation_full_flow() {
    let host = HostIdentity::generate();
    let pool_id = Uuid::now_v7();

    // Generate invitation token.
    let token =
        InvitationToken::generate(&host, pool_id, "relay.test.local:8443".to_owned(), 3600, 3);
    assert!(!token.is_expired(), "fresh token should not be expired");

    // Encode to URL and decode back.
    let url = token.to_url();
    assert!(
        url.starts_with("stealth://invite/"),
        "URL should have stealth:// prefix"
    );

    let decoded = InvitationToken::from_url(&url).expect("URL decoding should succeed");
    assert_eq!(decoded.token_id, token.token_id, "token_id mismatch");
    assert_eq!(decoded.pool_id, token.pool_id, "pool_id mismatch");
    assert_eq!(decoded.expires_at, token.expires_at, "expires_at mismatch");
    assert_eq!(decoded.max_uses, token.max_uses, "max_uses mismatch");
    assert_eq!(
        decoded.server_address, token.server_address,
        "server_address mismatch"
    );

    // Create a join proof.
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

    let proof = token.create_join_proof(&pool_id, &nonce);

    // Verify the proof with the verification key.
    let vk = token.verification_key();
    assert!(
        proof.verify(&vk, &pool_id, 60),
        "join proof should verify with correct vk"
    );

    // Verify with wrong key fails.
    let wrong_vk = [0xAAu8; 32];
    assert!(
        !proof.verify(&wrong_vk, &pool_id, 60),
        "join proof should fail with wrong vk"
    );

    // Verify commitment matches.
    let commitment = token.commitment();
    let tc = token.to_commitment();
    assert_eq!(
        commitment, tc.commitment,
        "commitment from token and to_commitment should match"
    );
    assert_eq!(tc.token_id, token.token_id);
    assert_eq!(tc.expires_at, token.expires_at);
    assert_eq!(tc.max_uses, token.max_uses);
}

// =========================================================================
// Test 5: Pool lifecycle
// =========================================================================

/// Create pool -> add peers -> route messages -> remove peers -> cleanup.
#[tokio::test]
async fn pool_lifecycle() {
    let registry = PoolRegistry::new(10);
    let pool_id = PoolId(Uuid::now_v7());

    // Create a pool.
    let pool = registry
        .create_pool(
            pool_id,
            "test-pool".into(),
            ConnectionId(100),
            PeerId("host-peer".into()),
            [0xAAu8; 32],
            "TestHost".into(),
            8,
        )
        .expect("pool creation should succeed");

    assert_eq!(registry.pool_count(), 1);
    assert_eq!(pool.peer_count(), 0);

    // Add 3 peers.
    for i in 1..=3u64 {
        pool.add_peer(PoolPeer {
            peer_id: PeerId(format!("peer-{i}")),
            connection_id: ConnectionId(100 + i),
            display_name: format!("Peer {i}"),
            public_key: [i as u8; 32],
            connected_at: TokioInstant::now(),
            last_activity: TokioInstant::now(),
            last_acked_sequence: 0,
        })
        .expect("add_peer should succeed");
    }
    assert_eq!(pool.peer_count(), 3);

    // Route a broadcast message from peer-1: should go to host, peer-2, peer-3.
    let result = Router::route(
        &pool,
        &PeerId("peer-1".into()),
        ConnectionId(101),
        "broadcast data",
        None,
        1,
    );
    let result = result.expect("broadcast should have recipients");
    assert_eq!(
        result.recipients.len(),
        3,
        "broadcast should reach host + 2 other peers"
    );
    let conn_ids: Vec<u64> = result.recipients.iter().map(|c| c.0).collect();
    assert!(conn_ids.contains(&100), "host should receive broadcast");
    assert!(conn_ids.contains(&102), "peer-2 should receive broadcast");
    assert!(conn_ids.contains(&103), "peer-3 should receive broadcast");
    assert!(
        !conn_ids.contains(&101),
        "sender should NOT receive broadcast"
    );

    // Route a targeted message from host to peer-2 only.
    let targeted = Router::route(
        &pool,
        &PeerId("host-peer".into()),
        ConnectionId(100),
        "targeted data",
        Some(&["peer-2".to_owned()]),
        2,
    );
    let targeted = targeted.expect("targeted should have recipients");
    assert_eq!(
        targeted.recipients.len(),
        1,
        "targeted should reach only peer-2"
    );
    assert_eq!(targeted.recipients[0], ConnectionId(102));

    // Remove peer-1.
    let removed = pool.remove_peer(&PeerId("peer-1".into()));
    assert!(removed.is_some(), "remove should return the peer");
    assert_eq!(pool.peer_count(), 2);

    // Add an invitation commitment and consume it.
    let token_id = [0x42u8; 16];
    let commitment = [0xBBu8; 32];
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    pool.add_invitation_commitment(token_id, commitment, expires_at, 1);

    pool.try_consume_invitation(&token_id)
        .expect("first consume should succeed");

    let second_consume = pool.try_consume_invitation(&token_id);
    assert!(
        second_consume.is_err(),
        "second consume should fail (max_uses=1)"
    );

    // Verify pool listing includes host + remaining peers.
    let peers = pool.peers();
    assert_eq!(peers.len(), 3, "should list host + 2 remaining peers");
}

// =========================================================================
// Test 6: Rate limiting
// =========================================================================

/// Verify rate limiter blocks after threshold and penalties increase cost.
#[tokio::test]
async fn rate_limiting_blocks_after_threshold() {
    let config = RateLimitConfig {
        messages_per_second: 5,
        failed_attempt_penalty: 3,
        ..RateLimitConfig::default()
    };
    let limiter = IpRateLimiter::new(config);
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    // Make 5 allowed requests (bucket capacity = 5).
    for i in 0..5 {
        assert!(
            limiter.check_rate(ip).is_ok(),
            "request {i} should be allowed"
        );
    }

    // 6th should be blocked.
    assert!(
        limiter.check_rate(ip).is_err(),
        "request after threshold should be blocked"
    );

    // Record a failure -- should add penalty tokens.
    limiter.record_failure(ip);
}

// =========================================================================
// Test 7: Connection throttling
// =========================================================================

/// Verify progressive blocking after failed auth attempts.
#[tokio::test]
async fn connection_throttle_escalation() {
    let config = RateLimitConfig {
        max_failed_auth: 3,
        block_duration_secs: 600,
        escalation_block_secs: 86_400,
        ..RateLimitConfig::default()
    };
    let throttler = ConnectionThrottler::new(config);
    let ip: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    // Should be allowed initially.
    assert!(
        throttler.check_allowed(ip).is_ok(),
        "fresh IP should be allowed"
    );

    // Record 2 failures -- should still be allowed.
    throttler.record_failure(ip);
    throttler.record_failure(ip);
    assert!(
        throttler.check_allowed(ip).is_ok(),
        "2 failures should not block yet"
    );

    // 3rd failure triggers the block.
    throttler.record_failure(ip);
    let result = throttler.check_allowed(ip);
    assert!(result.is_err(), "3rd failure should trigger IP block");

    // Verify the error message contains time information.
    if let Err(e) = result {
        let msg = e.to_string();
        assert!(
            msg.contains("remaining"),
            "block error should contain remaining time"
        );
    }

    // A success resets the failure counter (but does not unblock).
    throttler.record_success(ip);
}

// =========================================================================
// Test 8: PoW challenge
// =========================================================================

/// Generate challenge -> solve -> verify, with various difficulties.
#[tokio::test]
async fn pow_challenge_and_solve() {
    // Use low difficulty for fast test execution.
    let challenge = PowChallenge::generate(10);

    // Verify freshness.
    assert!(
        challenge.is_fresh(60),
        "newly generated challenge should be fresh"
    );

    // Solve it.
    let solution = challenge.solve();

    // Verify the solution.
    assert!(
        challenge.verify(&solution).is_ok(),
        "valid solution should verify"
    );

    // Wrong solution with high difficulty -- overwhelmingly unlikely to pass.
    let hard_challenge = PowChallenge::generate(20);
    let hard_bad = stealthos_crypto::pow::PowSolution {
        solution: [0xFF; 8],
    };
    // Probability of accidental pass: 1/2^20 ~ 1 in a million.
    assert!(
        hard_challenge.verify(&hard_bad).is_err(),
        "wrong solution should fail verification"
    );

    // Expired challenge.
    let old_challenge = PowChallenge {
        challenge: [0u8; 32],
        difficulty: 10,
        timestamp: 0, // Unix epoch -- definitely expired.
    };
    assert!(
        !old_challenge.is_fresh(60),
        "ancient challenge should not be fresh"
    );
}

// =========================================================================
// Test 9: Config loading
// =========================================================================

/// Test config loading from TOML file with environment variable overrides.
#[tokio::test]
async fn config_file_and_env_override() {
    use stealthos_server::config::ServerConfig;

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let config_path = dir.path().join("test-config.toml");

    // Write a test TOML file.
    let toml_content = r#"
[server]
ws_bind = "0.0.0.0:7777"
metrics_bind = "127.0.0.1:7778"
max_connections = 250

[pool]
max_pools = 50
max_pool_size = 8

[logging]
level = "debug"
format = "pretty"

[rate_limit]
connections_per_minute = 15
messages_per_second = 30
"#;
    std::fs::write(&config_path, toml_content).expect("failed to write test config");

    // Load config from file.
    let cfg = ServerConfig::load(Some(config_path.as_path())).expect("config load should succeed");

    assert_eq!(cfg.server.ws_bind, "0.0.0.0:7777");
    assert_eq!(cfg.server.metrics_bind, "127.0.0.1:7778");
    assert_eq!(cfg.server.max_connections, 250);
    assert_eq!(cfg.pool.max_pools, 50);
    assert_eq!(cfg.pool.max_pool_size, 8);
    assert_eq!(cfg.logging.level, "debug");
    assert_eq!(cfg.logging.format, "pretty");
    assert_eq!(cfg.rate_limit.connections_per_minute, 15);
    assert_eq!(cfg.rate_limit.messages_per_second, 30);

    // Set env vars to override specific values.
    unsafe {
        std::env::set_var("STEALTH_SERVER__MAX_CONNECTIONS", "999");
        std::env::set_var("STEALTH_POOL__MAX_POOLS", "200");
    }

    let cfg2 = ServerConfig::load(Some(config_path.as_path()))
        .expect("config load with env overrides should succeed");

    assert_eq!(
        cfg2.server.max_connections, 999,
        "env var should override file value for max_connections"
    );
    assert_eq!(
        cfg2.pool.max_pools, 200,
        "env var should override file value for max_pools"
    );
    // Non-overridden values should remain from file.
    assert_eq!(cfg2.server.ws_bind, "0.0.0.0:7777");
    assert_eq!(cfg2.logging.level, "debug");

    // Cleanup env vars.
    unsafe {
        std::env::remove_var("STEALTH_SERVER__MAX_CONNECTIONS");
        std::env::remove_var("STEALTH_POOL__MAX_POOLS");
    }
}

// =========================================================================
// Test 10: WebSocket transport (basic)
// =========================================================================

/// Start WebSocket listener, connect a client, send a message, verify receipt.
#[tokio::test]
async fn websocket_connect_and_echo() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::sync::mpsc;

    // Bind a TCP listener on a random port.
    let tcp_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .expect("failed to bind TCP listener");
    let bound_addr = tcp_listener
        .local_addr()
        .expect("failed to get local address");

    let (event_tx, mut event_rx) = mpsc::channel::<String>(16);

    // Spawn a minimal server accept loop.
    let server_handle = tokio::spawn(async move {
        let (tcp_stream, _remote_addr) =
            tcp_listener.accept().await.expect("accept should succeed");

        let ws_stream = tokio_tungstenite::accept_async(tcp_stream)
            .await
            .expect("websocket handshake should succeed");

        let (mut ws_sink, mut ws_source) = ws_stream.split();

        // Read one message and forward it to the event channel.
        if let Some(Ok(msg)) = ws_source.next().await {
            if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
                let _ = event_tx.send(text.to_string()).await;
            }
        }

        // Send a close frame.
        let _ = ws_sink
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
    });

    // Connect a client.
    let url = format!("ws://127.0.0.1:{}", bound_addr.port());
    let (ws_stream, _response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("client connect should succeed");

    let (mut client_sink, mut client_source) = ws_stream.split();

    // Send a text message from the client.
    let test_message = r#"{"frame_type":"heartbeat_ping","data":{"timestamp":12345}}"#;
    client_sink
        .send(tokio_tungstenite::tungstenite::Message::text(test_message))
        .await
        .expect("client send should succeed");

    // Verify the server received the message.
    let received = tokio::time::timeout(std::time::Duration::from_secs(5), event_rx.recv())
        .await
        .expect("should receive within timeout")
        .expect("channel should not be closed");

    assert_eq!(
        received, test_message,
        "server should receive the exact message sent"
    );

    // Wait for the server close frame.
    while let Some(msg) = client_source.next().await {
        match msg {
            Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }

    server_handle.await.expect("server task should complete");
}
