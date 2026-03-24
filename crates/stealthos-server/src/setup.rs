//! Secure setup page -- serves a token-protected HTML page with the claim QR code.
//!
//! When the server is unclaimed, the `/setup?token=<TOKEN>` endpoint renders
//! an HTML page with an inline SVG QR code and manual claim code. The setup
//! token is a separate secret (8 bytes, printed to stderr at startup) that
//! prevents unauthorized access to the claim secret even if the metrics port
//! is reachable.
//!
//! After the server is claimed, the endpoint returns a "Server Claimed" page
//! and never reveals the claim secret again.

use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::{Router, routing::get};
use rand::RngCore;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::claim::{self, ClaimState};

/// Shared state for the setup page handler.
pub struct SetupState {
    /// One-time setup token (8 bytes). Printed to stderr at startup.
    /// Required in the `?token=` query parameter to access the setup page.
    setup_token: [u8; 8],
    /// Reference to the shared claim state.
    claim_state: Arc<Mutex<ClaimState>>,
}

impl SetupState {
    /// Create a new setup state with a random token.
    pub fn new(claim_state: Arc<Mutex<ClaimState>>) -> Self {
        let mut setup_token = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut setup_token);
        Self {
            setup_token,
            claim_state,
        }
    }

    /// Return the setup token as a lowercase hex string (16 chars).
    pub fn token_hex(&self) -> String {
        claim::hex_encode(&self.setup_token)
    }

    /// Validate a provided token string against the stored token.
    /// Uses constant-time comparison to prevent timing side-channels.
    fn validate_token(&self, provided: &str) -> bool {
        let expected = self.token_hex();
        if provided.len() != expected.len() {
            return false;
        }
        bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// Returns the 32-byte claim secret if the server is unclaimed.
    fn claim_secret(&self) -> Option<[u8; 32]> {
        let cs = self
            .claim_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cs.claim_secret().copied()
    }

    /// Check if the server has been claimed.
    fn is_claimed(&self) -> bool {
        self.claim_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_claimed()
    }
}

/// Query parameters for the setup endpoint.
#[derive(Deserialize)]
struct SetupQuery {
    token: Option<String>,
}

/// Build the setup page [`Router`].
///
/// After calling `.with_state()`, this returns a `Router<()>` which can be
/// merged with the health router via `Router::merge`.
pub fn setup_router(state: Arc<SetupState>) -> Router {
    Router::new()
        .route("/setup", get(setup_handler))
        .with_state(state)
}

/// GET /setup?token=<TOKEN>
///
/// Security layers:
/// 1. The setup token must match (constant-time comparison)
/// 2. The claim secret is only served while the server is unclaimed
/// 3. After claiming, the page returns a benign "Server Claimed" message
async fn setup_handler(
    State(state): State<Arc<SetupState>>,
    Query(params): Query<SetupQuery>,
) -> impl IntoResponse {
    // Always return the claimed page if already claimed -- regardless of token.
    if state.is_claimed() {
        return (StatusCode::OK, Html(claimed_page()));
    }

    // Require and validate the setup token.
    let Some(token) = params.token.as_deref() else {
        return (StatusCode::FORBIDDEN, Html(forbidden_page()));
    };

    if !state.validate_token(token) {
        return (StatusCode::FORBIDDEN, Html(forbidden_page()));
    }

    // Serve the setup page with the claim QR code.
    let Some(secret) = state.claim_secret() else {
        // Race: server was claimed between the check above and here.
        return (StatusCode::OK, Html(claimed_page()));
    };

    (StatusCode::OK, Html(render_setup_page(&secret)))
}

// ── HTML page rendering ──────────────────────────────────────────────────

/// Render the setup page with inline SVG QR code and manual code.
fn render_setup_page(claim_secret: &[u8; 32]) -> String {
    let full_hex = claim::hex_encode(claim_secret);
    let url = format!("stealth://claim/{full_hex}");

    // Format as XXXX-XXXX-... for manual entry.
    let formatted: String = full_hex
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("????"))
        .collect::<Vec<_>>()
        .join("-");

    let svg = render_qr_to_svg(&url);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StealthOS Relay - Claim Server</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: #0f0f1a;
    color: #e0e0e6;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
  }}
  .container {{
    max-width: 480px;
    width: 100%;
    padding: 32px 24px;
    text-align: center;
  }}
  .logo {{
    font-size: 1.1em;
    letter-spacing: 0.05em;
    color: #8888aa;
    margin-bottom: 8px;
  }}
  h1 {{
    font-size: 1.6em;
    font-weight: 600;
    margin: 0 0 8px 0;
    color: #fff;
  }}
  .subtitle {{
    color: #9999bb;
    font-size: 0.95em;
    margin-bottom: 28px;
    line-height: 1.5;
  }}
  .qr-container {{
    background: #ffffff;
    padding: 20px;
    border-radius: 12px;
    display: inline-block;
    margin-bottom: 24px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.3);
  }}
  .qr-container svg {{
    display: block;
    width: 240px;
    height: 240px;
  }}
  .manual-section {{
    background: #1a1a2e;
    border: 1px solid #2a2a44;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 20px;
  }}
  .manual-label {{
    font-size: 0.8em;
    color: #7777aa;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 8px;
  }}
  .manual-code {{
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.85em;
    color: #ccccee;
    word-break: break-all;
    line-height: 1.7;
    user-select: all;
  }}
  .copy-btn {{
    display: inline-block;
    margin-top: 12px;
    padding: 8px 20px;
    background: #2a2a44;
    color: #ccccee;
    border: 1px solid #3a3a55;
    border-radius: 6px;
    font-size: 0.85em;
    cursor: pointer;
    transition: background 0.15s;
  }}
  .copy-btn:hover {{
    background: #3a3a55;
  }}
  .copy-btn:active {{
    background: #4a4a66;
  }}
  .warning {{
    margin-top: 24px;
    padding: 12px 16px;
    background: rgba(255, 180, 50, 0.08);
    border: 1px solid rgba(255, 180, 50, 0.2);
    border-radius: 8px;
    color: #ddaa44;
    font-size: 0.85em;
    line-height: 1.5;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="logo">STEALTHOS RELAY</div>
  <h1>Claim Your Server</h1>
  <p class="subtitle">
    Scan the QR code with the StealthOS app to claim ownership of this server,
    or copy the manual code below.
  </p>

  <div class="qr-container">
    {svg}
  </div>

  <div class="manual-section">
    <div class="manual-label">Manual Code</div>
    <div class="manual-code" id="claim-code">{formatted}</div>
    <button class="copy-btn" onclick="copyCode()" id="copy-btn">Copy Code</button>
  </div>

  <div class="warning">
    This code is <strong>one-time use</strong> and will be destroyed after claiming.
    Only the server operator should see this page.
  </div>
</div>
<script>
function copyCode() {{
  var code = '{full_hex}';
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(code).then(function() {{
      document.getElementById('copy-btn').textContent = 'Copied!';
      setTimeout(function() {{
        document.getElementById('copy-btn').textContent = 'Copy Code';
      }}, 2000);
    }});
  }} else {{
    var ta = document.createElement('textarea');
    ta.value = code;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    document.getElementById('copy-btn').textContent = 'Copied!';
    setTimeout(function() {{
      document.getElementById('copy-btn').textContent = 'Copy Code';
    }}, 2000);
  }}
}}
// Auto-refresh to detect when server is claimed.
setInterval(function() {{
  fetch(window.location.href).then(function(r) {{
    return r.text();
  }}).then(function(html) {{
    if (html.indexOf('Server Claimed') !== -1) {{
      document.body.innerHTML = html;
      // Swap to the claimed page body content.
      var parser = new DOMParser();
      var doc = parser.parseFromString(html, 'text/html');
      document.body.innerHTML = doc.body.innerHTML;
    }}
  }}).catch(function() {{}});
}}, 3000);
</script>
</body>
</html>"#
    )
}

/// Render a QR code as inline SVG from the module grid.
///
/// Avoids the `svg` feature flag on the `qrcode` crate by building
/// the SVG manually from the boolean module matrix.
#[allow(clippy::cast_possible_wrap)]
fn render_qr_to_svg(data: &str) -> String {
    use std::fmt::Write;

    use qrcode::{EcLevel, QrCode};

    let Ok(code) = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L) else {
        return String::from("<p>QR generation failed</p>");
    };

    let width = code.width();
    let margin: usize = 2;
    let total = width + margin * 2;

    let mut svg =
        format!(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}">"#,);
    // White background.
    let _ = write!(
        svg,
        "<rect width=\"{total}\" height=\"{total}\" fill=\"#fff\"/>"
    );
    // Dark modules.
    for y in 0..width {
        for x in 0..width {
            if code[(x, y)] == qrcode::Color::Dark {
                let px = x + margin;
                let py = y + margin;
                let _ = write!(
                    svg,
                    "<rect x=\"{px}\" y=\"{py}\" width=\"1\" height=\"1\" fill=\"#000\"/>"
                );
            }
        }
    }
    svg.push_str("</svg>");
    svg
}

/// HTML page shown after the server has been claimed.
fn claimed_page() -> String {
    String::from(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StealthOS Relay - Server Claimed</title>
<style>
  body {
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f0f1a;
    color: #e0e0e6;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
  }
  .container { max-width: 400px; padding: 32px 24px; }
  .check { font-size: 3em; margin-bottom: 16px; }
  h1 { font-size: 1.4em; color: #fff; margin: 0 0 12px 0; }
  p { color: #9999bb; line-height: 1.6; }
</style>
</head>
<body>
<div class="container">
  <div class="check">&#x2705;</div>
  <h1>Server Claimed</h1>
  <p>
    This server has been claimed and is ready to accept connections.
    You can close this page.
  </p>
</div>
</body>
</html>"#,
    )
}

/// HTML page shown when the token is missing or invalid.
fn forbidden_page() -> String {
    String::from(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StealthOS Relay - Access Denied</title>
<style>
  body {
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f0f1a;
    color: #e0e0e6;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
  }
  .container { max-width: 420px; padding: 32px 24px; }
  .lock { font-size: 3em; margin-bottom: 16px; }
  h1 { font-size: 1.4em; color: #fff; margin: 0 0 12px 0; }
  p { color: #9999bb; line-height: 1.6; }
  code {
    background: #1a1a2e;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.9em;
  }
</style>
</head>
<body>
<div class="container">
  <div class="lock">&#x1F512;</div>
  <h1>Access Denied</h1>
  <p>
    A valid setup token is required to access this page.
    Check the server logs for the setup URL with the token.
  </p>
</div>
</body>
</html>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_unclaimed_state() -> (Arc<SetupState>, Arc<Mutex<ClaimState>>) {
        let dir = tempfile::tempdir().unwrap();
        let claim = ClaimState::load_or_create(dir.path());
        assert!(!claim.is_claimed());
        let shared = Arc::new(Mutex::new(claim));
        let setup = Arc::new(SetupState::new(Arc::clone(&shared)));
        (setup, shared)
    }

    fn make_claimed_state() -> Arc<SetupState> {
        let dir = tempfile::tempdir().unwrap();
        let mut claim = ClaimState::load_or_create(dir.path());
        let secret = *claim.claim_secret().unwrap();
        claim
            .try_claim(&secret, &[42u8; 32], dir.path(), "fp")
            .unwrap();
        let shared = Arc::new(Mutex::new(claim));
        Arc::new(SetupState::new(shared))
    }

    #[test]
    fn token_validation_correct() {
        let (setup, _) = make_unclaimed_state();
        let token = setup.token_hex();
        assert!(setup.validate_token(&token));
    }

    #[test]
    fn token_validation_wrong() {
        let (setup, _) = make_unclaimed_state();
        assert!(!setup.validate_token("0000000000000000"));
        assert!(!setup.validate_token("short"));
        assert!(!setup.validate_token(""));
    }

    #[test]
    fn claim_secret_available_when_unclaimed() {
        let (setup, _) = make_unclaimed_state();
        assert!(setup.claim_secret().is_some());
        assert!(!setup.is_claimed());
    }

    #[test]
    fn claim_secret_none_when_claimed() {
        let setup = make_claimed_state();
        assert!(setup.claim_secret().is_none());
        assert!(setup.is_claimed());
    }

    #[test]
    fn render_setup_page_contains_svg_and_code() {
        let secret = [0xab; 32];
        let html = render_setup_page(&secret);
        assert!(html.contains("<svg"));
        assert!(html.contains("</svg>"));
        assert!(html.contains("abab-abab")); // partial formatted code
        assert!(html.contains("Claim Your Server"));
    }

    #[test]
    fn render_qr_to_svg_produces_valid_svg() {
        let svg = render_qr_to_svg("stealth://claim/test");
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("fill=\"#000\"")); // dark modules
    }

    #[tokio::test]
    async fn setup_handler_requires_token() {
        let (setup, _) = make_unclaimed_state();
        let app = setup_router(setup);

        // No token -> 403
        let req = axum::http::Request::builder()
            .uri("/setup")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn setup_handler_wrong_token() {
        let (setup, _) = make_unclaimed_state();
        let app = setup_router(setup);

        let req = axum::http::Request::builder()
            .uri("/setup?token=0000000000000000")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn setup_handler_correct_token() {
        let (setup, _) = make_unclaimed_state();
        let token = setup.token_hex();
        let app = setup_router(setup);

        let req = axum::http::Request::builder()
            .uri(&format!("/setup?token={token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Claim Your Server"));
        assert!(html.contains("<svg"));
    }

    #[tokio::test]
    async fn setup_handler_claimed_returns_claimed_page() {
        let setup = make_claimed_state();
        let token = setup.token_hex();
        let app = setup_router(setup);

        let req = axum::http::Request::builder()
            .uri(&format!("/setup?token={token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Server Claimed"));
        assert!(!html.contains("Claim Your Server"));
    }

    #[tokio::test]
    async fn setup_handler_claimed_no_token_still_ok() {
        // Even without a token, claimed state returns the claimed page (200, not 403).
        let setup = make_claimed_state();
        let app = setup_router(setup);

        let req = axum::http::Request::builder()
            .uri("/setup")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Server Claimed"));
    }
}
