//! Server configuration with TOML file loading, environment variable overlay,
//! and sensible defaults.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use stealthos_core::ratelimit::RateLimitConfig;

/// Top-level server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub pool: PoolSection,
    #[serde(default)]
    pub transport: TransportSection,
    #[serde(default)]
    pub crypto: CryptoSection,
    #[serde(default)]
    pub logging: LogSection,
    #[serde(default)]
    pub rate_limit: RateLimitSection,
}

// ---------------------------------------------------------------------------
// Section structs with defaults
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSection {
    /// WebSocket listener bind address.
    #[serde(default = "default_ws_bind")]
    pub ws_bind: String,
    /// Health/metrics HTTP bind address (should be internal-only).
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: String,
    /// Maximum concurrent WebSocket connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Maximum size of a single WebSocket message in bytes.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    /// Seconds of inactivity before a connection is closed.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    /// Seconds allowed for the WebSocket handshake to complete.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSection {
    /// Maximum number of active pools.
    #[serde(default = "default_max_pools")]
    pub max_pools: usize,
    /// Maximum peers per pool.
    #[serde(default = "default_max_pool_size")]
    pub max_pool_size: usize,
    /// Seconds of pool inactivity before automatic cleanup.
    #[serde(default = "default_pool_idle_timeout")]
    pub pool_idle_timeout: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportSection {
    /// Optional path to a PEM-encoded TLS certificate chain.
    /// When both `tls_cert_path` and `tls_key_path` are set, the server
    /// terminates TLS directly on the WebSocket listener.
    pub tls_cert_path: Option<String>,
    /// Optional path to a PEM-encoded TLS private key.
    pub tls_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSection {
    /// Directory for host identity key files.
    #[serde(default = "default_key_dir")]
    pub key_dir: String,
    /// Whether to auto-generate a host keypair on first start.
    #[serde(default = "default_auto_generate")]
    pub auto_generate_keys: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSection {
    /// Tracing filter directive (e.g., `"info"`, `"stealthos_server=debug"`).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: `"json"` or `"pretty"`.
    #[serde(default = "default_log_format")]
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSection {
    /// Maximum new connections per IP per minute.
    #[serde(default = "default_connections_per_minute")]
    pub connections_per_minute: u32,
    /// Maximum messages per connection per second.
    #[serde(default = "default_messages_per_second")]
    pub messages_per_second: u32,
    /// Maximum failed auth attempts before IP block.
    #[serde(default = "default_max_failed_auth")]
    pub max_failed_auth: u32,
    /// Duration in seconds an IP stays blocked after exceeding limits.
    #[serde(default = "default_block_duration")]
    pub block_duration_secs: u64,
}

// ---------------------------------------------------------------------------
// Default value functions
// ---------------------------------------------------------------------------

fn default_ws_bind() -> String {
    "0.0.0.0:9090".to_owned()
}
fn default_metrics_bind() -> String {
    "127.0.0.1:9091".to_owned()
}
fn default_max_connections() -> usize {
    500
}
fn default_max_message_size() -> usize {
    65_536
}
fn default_idle_timeout() -> u64 {
    600
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_max_pools() -> usize {
    100
}
fn default_max_pool_size() -> usize {
    16
}
fn default_pool_idle_timeout() -> u64 {
    300
}
fn default_key_dir() -> String {
    "/var/stealth-relay/keys".to_owned()
}
fn default_auto_generate() -> bool {
    true
}
fn default_log_level() -> String {
    "info".to_owned()
}
fn default_log_format() -> String {
    "json".to_owned()
}
fn default_connections_per_minute() -> u32 {
    30
}
fn default_messages_per_second() -> u32 {
    60
}
fn default_max_failed_auth() -> u32 {
    5
}
fn default_block_duration() -> u64 {
    600
}

// ---------------------------------------------------------------------------
// Default impls
// ---------------------------------------------------------------------------

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSection::default(),
            pool: PoolSection::default(),
            transport: TransportSection::default(),
            crypto: CryptoSection::default(),
            logging: LogSection::default(),
            rate_limit: RateLimitSection::default(),
        }
    }
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            ws_bind: default_ws_bind(),
            metrics_bind: default_metrics_bind(),
            max_connections: default_max_connections(),
            max_message_size: default_max_message_size(),
            idle_timeout: default_idle_timeout(),
            handshake_timeout: default_handshake_timeout(),
        }
    }
}

impl Default for PoolSection {
    fn default() -> Self {
        Self {
            max_pools: default_max_pools(),
            max_pool_size: default_max_pool_size(),
            pool_idle_timeout: default_pool_idle_timeout(),
        }
    }
}

impl Default for CryptoSection {
    fn default() -> Self {
        Self {
            key_dir: default_key_dir(),
            auto_generate_keys: default_auto_generate(),
        }
    }
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            connections_per_minute: default_connections_per_minute(),
            messages_per_second: default_messages_per_second(),
            max_failed_auth: default_max_failed_auth(),
            block_duration_secs: default_block_duration(),
        }
    }
}

impl RateLimitSection {
    /// Build a [`RateLimitConfig`] from the configuration section.
    ///
    /// Derived fields (`escalation_block_secs`, `failed_attempt_penalty`,
    /// `global_max_per_minute`) are computed from the base values so there
    /// is exactly one source of truth for these formulas.
    pub fn to_rate_limit_config(&self) -> RateLimitConfig {
        RateLimitConfig {
            connections_per_minute: self.connections_per_minute,
            messages_per_second: self.messages_per_second,
            max_failed_auth: self.max_failed_auth,
            block_duration_secs: self.block_duration_secs,
            escalation_block_secs: self.block_duration_secs * 2,
            failed_attempt_penalty: 3,
            global_max_per_minute: self.connections_per_minute * 10,
        }
    }
}

impl TransportSection {
    /// Convert to a pair of optional [`PathBuf`] values for the transport layer.
    pub fn tls_paths(&self) -> (Option<PathBuf>, Option<PathBuf>) {
        (
            self.tls_cert_path.as_ref().map(PathBuf::from),
            self.tls_key_path.as_ref().map(PathBuf::from),
        )
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl ServerConfig {
    /// Load configuration from an optional TOML file, with environment
    /// variable overlay and built-in defaults.
    ///
    /// Precedence (highest to lowest):
    /// 1. Environment variables with `STEALTH_` prefix (double-underscore for nesting,
    ///    e.g., `STEALTH_SERVER__WS_BIND=0.0.0.0:443`)
    /// 2. TOML file at `path`
    /// 3. Compiled-in defaults
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut config = if let Some(p) = path {
            let content = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", p.display()))?;
            toml::from_str::<Self>(&content)
                .map_err(|e| anyhow::anyhow!("failed to parse config file {}: {e}", p.display()))?
        } else {
            Self::default()
        };

        // Environment variable overlay with STEALTH_ prefix.
        config.apply_env_overrides();
        Ok(config)
    }

    /// Apply environment variable overrides.
    ///
    /// Uses the convention `STEALTH_<SECTION>__<FIELD>` (double underscore
    /// separates section from field, matching serde's nested structure).
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("STEALTH_SERVER__WS_BIND") {
            self.server.ws_bind = v;
        }
        if let Ok(v) = std::env::var("STEALTH_SERVER__METRICS_BIND") {
            self.server.metrics_bind = v;
        }
        if let Ok(v) = std::env::var("STEALTH_SERVER__MAX_CONNECTIONS") {
            if let Ok(n) = v.parse() {
                self.server.max_connections = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_SERVER__MAX_MESSAGE_SIZE") {
            if let Ok(n) = v.parse() {
                self.server.max_message_size = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_SERVER__IDLE_TIMEOUT") {
            if let Ok(n) = v.parse() {
                self.server.idle_timeout = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_SERVER__HANDSHAKE_TIMEOUT") {
            if let Ok(n) = v.parse() {
                self.server.handshake_timeout = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_POOL__MAX_POOLS") {
            if let Ok(n) = v.parse() {
                self.pool.max_pools = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_POOL__MAX_POOL_SIZE") {
            if let Ok(n) = v.parse() {
                self.pool.max_pool_size = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_POOL__POOL_IDLE_TIMEOUT") {
            if let Ok(n) = v.parse() {
                self.pool.pool_idle_timeout = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_TRANSPORT__TLS_CERT_PATH") {
            self.transport.tls_cert_path = Some(v);
        }
        if let Ok(v) = std::env::var("STEALTH_TRANSPORT__TLS_KEY_PATH") {
            self.transport.tls_key_path = Some(v);
        }
        if let Ok(v) = std::env::var("STEALTH_CRYPTO__KEY_DIR") {
            self.crypto.key_dir = v;
        }
        if let Ok(v) = std::env::var("STEALTH_CRYPTO__AUTO_GENERATE_KEYS") {
            if let Ok(b) = v.parse() {
                self.crypto.auto_generate_keys = b;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_LOGGING__LEVEL") {
            self.logging.level = v;
        }
        if let Ok(v) = std::env::var("STEALTH_LOGGING__FORMAT") {
            self.logging.format = v;
        }
        if let Ok(v) = std::env::var("STEALTH_RATE_LIMIT__CONNECTIONS_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                self.rate_limit.connections_per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_RATE_LIMIT__MESSAGES_PER_SECOND") {
            if let Ok(n) = v.parse() {
                self.rate_limit.messages_per_second = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_RATE_LIMIT__MAX_FAILED_AUTH") {
            if let Ok(n) = v.parse() {
                self.rate_limit.max_failed_auth = n;
            }
        }
        if let Ok(v) = std::env::var("STEALTH_RATE_LIMIT__BLOCK_DURATION_SECS") {
            if let Ok(n) = v.parse() {
                self.rate_limit.block_duration_secs = n;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.server.ws_bind, "0.0.0.0:9090");
        assert_eq!(cfg.server.metrics_bind, "127.0.0.1:9091");
        assert_eq!(cfg.server.max_connections, 500);
        assert_eq!(cfg.pool.max_pools, 100);
        assert_eq!(cfg.pool.max_pool_size, 16);
        assert!(cfg.crypto.auto_generate_keys);
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, "json");
        assert_eq!(cfg.rate_limit.connections_per_minute, 30);
    }

    #[test]
    fn load_defaults_without_file() {
        let cfg = ServerConfig::load(None).unwrap();
        assert_eq!(cfg.server.max_connections, 500);
    }

    #[test]
    fn toml_round_trip() {
        let cfg = ServerConfig::default();
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let deserialized: ServerConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.server.ws_bind, cfg.server.ws_bind);
        assert_eq!(deserialized.pool.max_pools, cfg.pool.max_pools);
    }

    #[test]
    fn rate_limit_config_derived_fields() {
        let section = RateLimitSection::default();
        let rlc = section.to_rate_limit_config();
        assert_eq!(rlc.connections_per_minute, 30);
        assert_eq!(rlc.block_duration_secs, 600);
        assert_eq!(rlc.escalation_block_secs, 1200);
        assert_eq!(rlc.failed_attempt_penalty, 3);
        assert_eq!(rlc.global_max_per_minute, 300);
    }

    #[test]
    fn transport_tls_defaults_to_none() {
        let cfg = ServerConfig::default();
        assert!(cfg.transport.tls_cert_path.is_none());
        assert!(cfg.transport.tls_key_path.is_none());
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
            [server]
            ws_bind = "0.0.0.0:443"
        "#;
        let cfg: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.server.ws_bind, "0.0.0.0:443");
        // Other fields should be defaults.
        assert_eq!(cfg.server.max_connections, 500);
        assert_eq!(cfg.pool.max_pools, 100);
    }

    #[test]
    fn parse_full_toml_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(
            &path,
            r#"
            [server]
            ws_bind = "127.0.0.1:8080"
            max_connections = 100

            [pool]
            max_pools = 10
            max_pool_size = 8

            [transport]
            tls_cert_path = "/etc/cert.pem"
            tls_key_path = "/etc/key.pem"

            [crypto]
            key_dir = "/tmp/keys"
            auto_generate_keys = false

            [logging]
            level = "debug"
            format = "pretty"

            [rate_limit]
            connections_per_minute = 10
            messages_per_second = 20
            max_failed_auth = 3
            block_duration_secs = 300
            "#,
        )
        .unwrap();

        let cfg = ServerConfig::load(Some(&path)).unwrap();
        assert_eq!(cfg.server.ws_bind, "127.0.0.1:8080");
        assert_eq!(cfg.server.max_connections, 100);
        assert_eq!(cfg.pool.max_pools, 10);
        assert_eq!(cfg.pool.max_pool_size, 8);
        assert_eq!(
            cfg.transport.tls_cert_path,
            Some("/etc/cert.pem".to_owned())
        );
        assert_eq!(cfg.crypto.key_dir, "/tmp/keys");
        assert!(!cfg.crypto.auto_generate_keys);
        assert_eq!(cfg.logging.level, "debug");
        assert_eq!(cfg.rate_limit.connections_per_minute, 10);
    }

    #[test]
    fn tls_paths_conversion() {
        let section = TransportSection {
            tls_cert_path: Some("/etc/cert.pem".into()),
            tls_key_path: Some("/etc/key.pem".into()),
        };
        let (cert, key) = section.tls_paths();
        assert_eq!(cert, Some(PathBuf::from("/etc/cert.pem")));
        assert_eq!(key, Some(PathBuf::from("/etc/key.pem")));

        let empty = TransportSection::default();
        let (cert, key) = empty.tls_paths();
        assert!(cert.is_none());
        assert!(key.is_none());
    }

    #[test]
    fn rate_limit_config_custom_values() {
        let section = RateLimitSection {
            connections_per_minute: 10,
            messages_per_second: 20,
            max_failed_auth: 3,
            block_duration_secs: 300,
        };
        let rlc = section.to_rate_limit_config();
        assert_eq!(rlc.connections_per_minute, 10);
        assert_eq!(rlc.messages_per_second, 20);
        assert_eq!(rlc.max_failed_auth, 3);
        assert_eq!(rlc.block_duration_secs, 300);
        assert_eq!(rlc.escalation_block_secs, 600); // 2x base
        assert_eq!(rlc.failed_attempt_penalty, 3);
        assert_eq!(rlc.global_max_per_minute, 100); // 10x connections
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = ServerConfig::load(Some(Path::new("/nonexistent/config.toml")));
        assert!(result.is_err());
    }
}
