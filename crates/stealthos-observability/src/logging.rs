//! Structured logging setup using `tracing` + `tracing-subscriber`.
//!
//! Supports JSON (for production / log aggregators) and human-readable
//! pretty format (for local development).

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Tracing directive string: `"trace"`, `"debug"`, `"info"`, `"warn"`, or `"error"`.
    /// Also accepts per-module directives like `"stealthos_server=debug,tower=warn"`.
    pub level: String,
    /// Output format.
    pub format: LogFormat,
}

/// Output format for structured logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Newline-delimited JSON -- one JSON object per log event.
    Json,
    /// Human-readable, coloured output for terminal use.
    Pretty,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Json,
        }
    }
}

/// Initialise the global `tracing` subscriber.
///
/// Must be called exactly once, early in `main`. Subsequent calls will panic.
///
/// The `RUST_LOG` environment variable takes precedence over `config.level`
/// when set, allowing runtime override without config changes.
pub fn init_logging(config: &LogConfig) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    match config.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_span_list(true)
                        .flatten_event(true),
                )
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .pretty()
                        .with_target(true)
                        .with_thread_ids(true),
                )
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_config_defaults() {
        let cfg = LogConfig::default();
        assert_eq!(cfg.level, "info");
        assert_eq!(cfg.format, LogFormat::Json);
    }
}
