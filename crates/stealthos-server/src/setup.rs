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
    /// Server version string (from `CARGO_PKG_VERSION`).
    version: &'static str,
}

impl SetupState {
    /// Create a new setup state with a random token.
    pub fn new(claim_state: Arc<Mutex<ClaimState>>, version: &'static str) -> Self {
        let mut setup_token = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut setup_token);
        Self {
            setup_token,
            claim_state,
            version,
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
        .route("/", get(root_handler))
        .route("/setup", get(setup_handler))
        .with_state(state)
}

/// GET / — shows guide when claimed, info page when unclaimed.
async fn root_handler(State(state): State<Arc<SetupState>>) -> impl IntoResponse {
    if state.is_claimed() {
        (StatusCode::OK, Html(claimed_page(state.version)))
    } else {
        (StatusCode::OK, Html(unclaimed_root_page()))
    }
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
        return (StatusCode::OK, Html(claimed_page(state.version)));
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
        return (StatusCode::OK, Html(claimed_page(state.version)));
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

/// HTML page shown when visiting `/` before claiming.
fn unclaimed_root_page() -> String {
    String::from(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StealthOS Relay</title>
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
  h1 { font-size: 1.4em; color: #fff; margin: 0 0 12px 0; }
  p { color: #9999bb; line-height: 1.6; }
  code { background: #1a1a2e; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
</style>
</head>
<body>
<div class="container">
  <h1>StealthOS Relay</h1>
  <p>
    This server is waiting to be claimed.<br>
    Check the server logs for the setup URL with the security token.
  </p>
</div>
</body>
</html>"#,
    )
}

/// HTML page shown after the server has been claimed.
/// Includes step-by-step guides for setting up free HTTPS tunnels
/// and a client-side update check (browser fetches GitHub API, not the server).
fn claimed_page(version: &str) -> String {
    // Use string replacement instead of format! to avoid escaping all CSS/JS braces.
    CLAIMED_PAGE_TEMPLATE.replace("{{VERSION}}", version)
}

const CLAIMED_PAGE_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StealthOS Relay - Server Ready</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: #0f0f1a;
    color: #e0e0e6;
    line-height: 1.6;
  }
  .page { max-width: 720px; margin: 0 auto; padding: 32px 24px 64px; }
  .hero {
    text-align: center;
    padding: 40px 0 32px;
    border-bottom: 1px solid #1e1e36;
    margin-bottom: 32px;
  }
  .hero .icon { font-size: 3em; margin-bottom: 12px; }
  .hero h1 { font-size: 1.6em; color: #fff; margin: 0 0 8px; }
  .hero p { color: #9999bb; margin: 0; font-size: 0.95em; }
  .status-bar {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    justify-content: center;
    margin-top: 16px;
  }
  .status-item {
    background: #1a1a2e;
    border: 1px solid #2a2a44;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 0.85em;
  }
  .status-item .label { color: #7777aa; }
  .status-item .value { color: #88cc88; font-family: monospace; }
  .update-banner {
    display: none;
    background: rgba(100, 200, 100, 0.08);
    border: 1px solid rgba(100, 200, 100, 0.25);
    border-radius: 10px;
    padding: 16px 20px;
    margin: 20px 0;
    text-align: center;
  }
  .update-banner.visible { display: block; }
  .update-banner .new-ver { color: #88cc88; font-weight: 600; }
  .update-banner code { font-size: 0.85em; }
  h2 {
    font-size: 1.25em;
    color: #fff;
    margin: 36px 0 8px;
    padding-bottom: 8px;
    border-bottom: 1px solid #1e1e36;
  }
  h3 { font-size: 1.05em; color: #ccccee; margin: 24px 0 8px; }
  p, li { color: #b0b0cc; font-size: 0.92em; }
  a { color: #6699ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .next-step {
    background: #1a1a2e;
    border: 1px solid #2a2a44;
    border-radius: 10px;
    padding: 20px 24px;
    margin: 20px 0;
  }
  .next-step h3 { margin-top: 0; color: #fff; }
  .tunnel-option {
    background: #12121f;
    border: 1px solid #22223a;
    border-radius: 10px;
    padding: 20px 24px;
    margin: 16px 0;
  }
  .tunnel-option h3 {
    margin: 0 0 4px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .tunnel-option .badge {
    font-size: 0.7em;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: normal;
  }
  .badge-easy { background: #1a3a2a; color: #66cc88; }
  .badge-rec  { background: #1a2a3a; color: #66aaff; }
  .tunnel-option .tagline {
    color: #7777aa;
    font-size: 0.85em;
    margin: 0 0 12px;
  }
  .steps { margin: 0; padding: 0; list-style: none; counter-reset: step; }
  .steps li {
    counter-increment: step;
    position: relative;
    padding-left: 32px;
    margin-bottom: 10px;
  }
  .steps li::before {
    content: counter(step);
    position: absolute;
    left: 0;
    width: 22px; height: 22px;
    background: #2a2a44;
    border-radius: 50%;
    text-align: center;
    line-height: 22px;
    font-size: 0.75em;
    color: #8888bb;
  }
  code {
    background: #1a1a2e;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.88em;
    font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
    color: #ccccee;
  }
  pre {
    background: #0d0d18;
    border: 1px solid #22223a;
    border-radius: 8px;
    padding: 14px 18px;
    overflow-x: auto;
    font-size: 0.85em;
    line-height: 1.5;
    margin: 10px 0;
  }
  pre code { background: none; padding: 0; color: #ccddee; }
  .copy-wrap { position: relative; }
  .copy-wrap button {
    position: absolute;
    top: 8px; right: 8px;
    background: #2a2a44;
    border: 1px solid #3a3a55;
    color: #aaaacc;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.75em;
    cursor: pointer;
  }
  .copy-wrap button:hover { background: #3a3a55; }
  .note {
    background: rgba(100, 150, 255, 0.06);
    border: 1px solid rgba(100, 150, 255, 0.15);
    border-radius: 8px;
    padding: 12px 16px;
    font-size: 0.85em;
    color: #99aacc;
    margin: 12px 0;
  }
  .warn {
    background: rgba(255, 180, 50, 0.06);
    border: 1px solid rgba(255, 180, 50, 0.15);
    border-radius: 8px;
    padding: 12px 16px;
    font-size: 0.85em;
    color: #ccaa66;
    margin: 12px 0;
  }
  .footer {
    text-align: center;
    margin-top: 48px;
    padding-top: 24px;
    border-top: 1px solid #1e1e36;
    color: #555577;
    font-size: 0.8em;
  }
  .footer a { color: #6677aa; }
</style>
</head>
<body>
<div class="page">

  <div class="hero">
    <div class="icon">&#x2705;</div>
    <h1>Server Claimed &amp; Running</h1>
    <p>Your StealthOS Relay is ready. Now let's make it reachable from the internet.</p>
    <div class="status-bar">
      <div class="status-item">
        <span class="label">WebSocket</span>
        <span class="value">ws://localhost:9090</span>
      </div>
      <div class="status-item">
        <span class="label">Status</span>
        <span class="value">Online</span>
      </div>
      <div class="status-item">
        <span class="label">Version</span>
        <span class="value" id="current-version">{{VERSION}}</span>
      </div>
    </div>
  </div>

  <div class="update-banner" id="update-banner">
    <p>
      A new version is available: <span class="new-ver" id="new-version"></span>
    </p>
    <p>Update with: <code>curl -fsSL https://raw.githubusercontent.com/Olib-AI/StealthRelay/main/scripts/install.sh | bash -s -- --update</code></p>
    <p style="font-size:0.8em; color:#7777aa; margin-top:8px;">
      <a href="https://github.com/Olib-AI/StealthRelay/releases" target="_blank" rel="noopener">View release notes</a>
    </p>
  </div>

  <div class="next-step">
    <h3>What's next?</h3>
    <p>
      Your relay is running on your local network, but your friends can't reach it from the
      internet yet. You need a <strong>secure tunnel</strong> that gives your server a public
      HTTPS address &mdash; no port forwarding, no domain purchase, completely free.
    </p>
    <p>Pick one of the options below. We recommend starting with <strong>ngrok</strong> if
    you want the fastest setup, or <strong>Cloudflare Tunnel</strong> for a permanent solution.</p>
  </div>

  <!-- ── Option 1: ngrok ────────────────────────────────────── -->
  <div class="tunnel-option">
    <h3>
      ngrok
      <span class="badge badge-easy">Easiest</span>
    </h3>
    <p class="tagline">One command, instant HTTPS. Free tier includes 1 static domain.</p>

    <ol class="steps">
      <li>
        Create a free account at
        <a href="https://ngrok.com/signup" target="_blank" rel="noopener">ngrok.com/signup</a>
      </li>
      <li>
        Install ngrok:
        <div class="copy-wrap">
          <pre><code># macOS
brew install ngrok

# Linux (snap)
sudo snap install ngrok

# Or download from https://ngrok.com/download</code></pre>
        </div>
      </li>
      <li>
        Add your auth token (from the ngrok dashboard):
        <div class="copy-wrap">
          <pre><code>ngrok config add-authtoken YOUR_TOKEN</code></pre>
        </div>
      </li>
      <li>
        Start the tunnel:
        <div class="copy-wrap">
          <pre><code>ngrok tcp 9090</code></pre>
        </div>
        <div class="note">
          ngrok will display a forwarding address like <code>tcp://0.tcp.ngrok.io:12345</code>.
          Use this as your server URL in the StealthOS app.
        </div>
      </li>
      <li>
        <strong>For a permanent address</strong>, claim your free static domain in the
        <a href="https://dashboard.ngrok.com/domains" target="_blank" rel="noopener">ngrok dashboard</a>, then:
        <div class="copy-wrap">
          <pre><code>ngrok tcp --domain=your-name.ngrok-free.app 9090</code></pre>
        </div>
      </li>
    </ol>
    <div class="note">
      <strong>Free tier:</strong> 1 static domain, 1 online ngrok process, 20,000 connections/month.
      Plenty for personal use.
    </div>
  </div>

  <!-- ── Option 2: Cloudflare Tunnel ────────────────────────── -->
  <div class="tunnel-option">
    <h3>
      Cloudflare Tunnel
      <span class="badge badge-rec">Recommended for permanent setup</span>
    </h3>
    <p class="tagline">Unlimited bandwidth, no port forwarding, keeps your IP hidden. Requires a free Cloudflare account.</p>

    <ol class="steps">
      <li>
        Create a free account at
        <a href="https://dash.cloudflare.com/sign-up" target="_blank" rel="noopener">dash.cloudflare.com</a>
      </li>
      <li>
        Install cloudflared:
        <div class="copy-wrap">
          <pre><code># macOS
brew install cloudflared

# Ubuntu / Debian
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared

# Or download from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/</code></pre>
        </div>
      </li>
      <li>
        Log in to Cloudflare:
        <div class="copy-wrap">
          <pre><code>cloudflared tunnel login</code></pre>
        </div>
        <p>This opens a browser window to authorize your account.</p>
      </li>
      <li>
        Create a tunnel:
        <div class="copy-wrap">
          <pre><code>cloudflared tunnel create stealth-relay</code></pre>
        </div>
      </li>
      <li>
        Route traffic to your relay:
        <div class="copy-wrap">
          <pre><code>cloudflared tunnel route dns stealth-relay relay.yourdomain.com</code></pre>
        </div>
      </li>
      <li>
        Start the tunnel:
        <div class="copy-wrap">
          <pre><code>cloudflared tunnel --url ws://localhost:9090 run stealth-relay</code></pre>
        </div>
      </li>
      <li>
        Use <code>wss://relay.yourdomain.com</code> as your server URL in the StealthOS app.
      </li>
    </ol>
    <div class="note">
      <strong>Free tier:</strong> Unlimited bandwidth, unlimited tunnels.
      You need a domain on Cloudflare (can transfer an existing one, or buy one from ~$10/year).
    </div>
    <div class="note">
      <strong>Don't have a domain?</strong> Use the quick tunnel instead &mdash; no domain needed:
      <pre><code>cloudflared tunnel --url ws://localhost:9090</code></pre>
      This gives you a temporary <code>https://xxxx-xxxx.trycloudflare.com</code> address.
      It changes every time you restart, but it's great for testing.
    </div>
  </div>

  <!-- ── Option 3: Tailscale Funnel ─────────────────────────── -->
  <div class="tunnel-option">
    <h3>
      Tailscale Funnel
      <span class="badge badge-easy">No domain needed</span>
    </h3>
    <p class="tagline">Expose your relay over HTTPS using your Tailscale network. Free for personal use.</p>

    <ol class="steps">
      <li>
        Create a free account at
        <a href="https://tailscale.com/signup" target="_blank" rel="noopener">tailscale.com</a>
        and install Tailscale on this machine.
        <div class="copy-wrap">
          <pre><code># macOS
brew install tailscale

# Ubuntu / Debian
curl -fsSL https://tailscale.com/install.sh | sh

# Or see https://tailscale.com/download</code></pre>
        </div>
      </li>
      <li>
        Connect to your Tailscale network:
        <div class="copy-wrap">
          <pre><code>sudo tailscale up</code></pre>
        </div>
      </li>
      <li>
        Enable Funnel for port 9090:
        <div class="copy-wrap">
          <pre><code>sudo tailscale funnel 9090</code></pre>
        </div>
      </li>
      <li>
        Tailscale will show you your public URL, something like:
        <code>https://your-machine.tailnet-name.ts.net</code>
        <p>Use this as your server URL in the StealthOS app (it supports WebSocket over HTTPS).</p>
      </li>
    </ol>
    <div class="note">
      <strong>Free tier:</strong> Up to 3 users, HTTPS included, no domain needed.
      Your URL is based on your machine name and Tailscale account.
    </div>
  </div>

  <!-- ── Comparison ──────────────────────────────────────────── -->
  <h2>Which one should I pick?</h2>
  <table style="width:100%; border-collapse:collapse; font-size:0.88em; margin-top:12px;">
    <thead>
      <tr style="border-bottom:1px solid #2a2a44; text-align:left;">
        <th style="padding:8px; color:#9999bb;"></th>
        <th style="padding:8px; color:#9999bb;">ngrok</th>
        <th style="padding:8px; color:#9999bb;">Cloudflare</th>
        <th style="padding:8px; color:#9999bb;">Tailscale</th>
      </tr>
    </thead>
    <tbody>
      <tr style="border-bottom:1px solid #1e1e36;">
        <td style="padding:8px; color:#8888bb;">Setup time</td>
        <td style="padding:8px;">~2 min</td>
        <td style="padding:8px;">~10 min</td>
        <td style="padding:8px;">~5 min</td>
      </tr>
      <tr style="border-bottom:1px solid #1e1e36;">
        <td style="padding:8px; color:#8888bb;">Needs domain?</td>
        <td style="padding:8px;">No</td>
        <td style="padding:8px;">Yes (or use quick tunnel)</td>
        <td style="padding:8px;">No</td>
      </tr>
      <tr style="border-bottom:1px solid #1e1e36;">
        <td style="padding:8px; color:#8888bb;">Permanent URL</td>
        <td style="padding:8px;">1 free static domain</td>
        <td style="padding:8px;">Yes (your domain)</td>
        <td style="padding:8px;">Yes (*.ts.net)</td>
      </tr>
      <tr style="border-bottom:1px solid #1e1e36;">
        <td style="padding:8px; color:#8888bb;">Bandwidth</td>
        <td style="padding:8px;">1 GB/mo free</td>
        <td style="padding:8px;">Unlimited</td>
        <td style="padding:8px;">Unlimited</td>
      </tr>
      <tr>
        <td style="padding:8px; color:#8888bb;">Best for</td>
        <td style="padding:8px;">Quick testing</td>
        <td style="padding:8px;">Permanent setup</td>
        <td style="padding:8px;">Personal use</td>
      </tr>
    </tbody>
  </table>

  <div class="warn">
    <strong>Important:</strong> After setting up your tunnel, update the server URL in the
    StealthOS app to the new <code>wss://</code> address. Your friends will use this address
    in their invitation links.
  </div>

  <h2>Verify it works</h2>
  <p>Once your tunnel is running, test from any device:</p>
  <div class="copy-wrap">
    <pre><code># Replace with your tunnel URL
curl -i --http1.1 \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGVzdA==" \
  https://your-tunnel-url/</code></pre>
  </div>
  <p>You should see a <code>101 Switching Protocols</code> response. That means your relay
  is live and reachable from the internet.</p>

  <div class="footer">
    <p>
      <a href="https://github.com/Olib-AI/StealthRelay" target="_blank" rel="noopener">StealthRelay</a>
      by <a href="https://www.olib.ai" target="_blank" rel="noopener">Olib AI</a>
      &mdash;
      <a href="https://www.stealthos.app" target="_blank" rel="noopener">StealthOS</a>
    </p>
  </div>

</div>
<script>
// Client-side update check — the BROWSER fetches the GitHub API, not the server.
// Zero privacy impact on the relay. No outbound connections from your server.
(function() {
  var current = document.getElementById('current-version').textContent.replace(/^v/, '');
  fetch('https://api.github.com/repos/Olib-AI/StealthRelay/releases/latest')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.tag_name) return;
      var latest = data.tag_name.replace(/^v/, '');
      if (latest !== current && compareSemver(latest, current) > 0) {
        document.getElementById('new-version').textContent = data.tag_name;
        document.getElementById('update-banner').classList.add('visible');
      }
    })
    .catch(function() { /* silently ignore — no connectivity or rate limited */ });

  function compareSemver(a, b) {
    var pa = a.split('.').map(Number);
    var pb = b.split('.').map(Number);
    for (var i = 0; i < 3; i++) {
      if ((pa[i] || 0) > (pb[i] || 0)) return 1;
      if ((pa[i] || 0) < (pb[i] || 0)) return -1;
    }
    return 0;
  }
})();
</script>
</body>
</html>"#;

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
        let setup = Arc::new(SetupState::new(Arc::clone(&shared), "0.0.0-test"));
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
        Arc::new(SetupState::new(shared, "0.0.0-test"))
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
