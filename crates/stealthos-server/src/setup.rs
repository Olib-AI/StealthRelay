//! Secure setup page -- serves a token-protected HTML page with the claim QR code.
//!
//! While the server is unclaimed, `/setup?token=<TOKEN>` renders an HTML page
//! with an inline SVG QR code and the manual claim code. Anyone who reads that
//! page owns the server, so the surface is defended on four axes:
//!
//! * **Reachability.** The routes live on their own listener
//!   (`server.setup_bind`, loopback by default) instead of riding along with
//!   health and metrics, which operators routinely publish.
//! * **Secrecy of the token.** 32 bytes of `OsRng`, compared in constant time.
//!   A valid token is exchanged once for an `HttpOnly` session cookie and the
//!   caller is redirected to a token-free URL, so the secret-bearing link stops
//!   travelling in browser history, `Referer` headers and proxy logs.
//! * **Guessing.** Failed token presentations lock the source address out.
//! * **Lifetime.** The claim secret is only served inside
//!   `server.setup_window_secs` of startup. After that the page is inert until
//!   the server is restarted, so a setup URL scraped out of a log archive
//!   hours later is worth nothing.
//!
//! After the server is claimed, the endpoint returns a "Server Claimed" page
//! and never reveals the claim secret again.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Router, routing::get};
use rand::RngCore;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::claim::{self, ClaimState};

/// Length of the setup token, in bytes.
///
/// Matches the claim secret it guards: a token shorter than the secret would
/// just move the attack to the cheaper half of the pair.
const SETUP_TOKEN_LEN: usize = 32;

/// Name of the cookie carrying a setup session.
const SESSION_COOKIE: &str = "stealth_setup";

/// Failed token presentations from one address before it is locked out.
const MAX_TOKEN_ATTEMPTS: u32 = 5;

/// How long a locked-out address stays locked out.
const TOKEN_LOCKOUT: Duration = Duration::from_secs(300);

/// Cap on addresses tracked by the throttle, so a spray from many sources
/// cannot grow the map without bound.
const MAX_TRACKED_CLIENTS: usize = 1024;

/// Response headers for every setup page.
///
/// A setup page can contain the claim secret: it must not be cached by a
/// browser or an intermediary, must not leak its own URL through a `Referer`,
/// and must not be framed by another origin.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; \
script-src 'unsafe-inline'; img-src data:; \
connect-src 'self' https://api.github.com; form-action 'none'; \
frame-ancestors 'none'; base-uri 'none'";

/// Per-address record of failed token presentations.
#[derive(Clone, Copy)]
struct ClientAttempts {
    failures: u32,
    /// When the most recent failure was recorded.
    last: Instant,
}

/// Lockout for repeated bad setup tokens.
///
/// Keyed by peer address, which over TCP cannot be spoofed. The setup
/// listener is loopback-bound by default, so this mostly matters for
/// operators who deliberately expose it on a LAN.
#[derive(Default)]
struct TokenThrottle {
    clients: Mutex<HashMap<IpAddr, ClientAttempts>>,
}

impl TokenThrottle {
    fn is_locked(&self, client: IpAddr) -> bool {
        let clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clients
            .get(&client)
            .is_some_and(|a| a.failures >= MAX_TOKEN_ATTEMPTS && a.last.elapsed() < TOKEN_LOCKOUT)
    }

    fn record_failure(&self, client: IpAddr) {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = clients.get_mut(&client) {
            // A failure after the lockout expired starts a fresh count.
            if entry.last.elapsed() >= TOKEN_LOCKOUT {
                entry.failures = 0;
            }
            entry.failures = entry.failures.saturating_add(1);
            entry.last = Instant::now();
            return;
        }
        if clients.len() >= MAX_TRACKED_CLIENTS {
            clients.retain(|_, a| a.last.elapsed() < TOKEN_LOCKOUT);
            // Still full: evict the least recently seen address to make room,
            // so a new client is always tracked.
            if clients.len() >= MAX_TRACKED_CLIENTS
                && let Some(oldest) = clients
                    .iter()
                    .min_by_key(|(_, a)| a.last)
                    .map(|(ip, _)| *ip)
            {
                clients.remove(&oldest);
            }
        }
        clients.insert(
            client,
            ClientAttempts {
                failures: 1,
                last: Instant::now(),
            },
        );
    }

    fn reset(&self, client: IpAddr) {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clients.remove(&client);
    }
}

/// Outcome of authorizing a request for the setup surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// The request carried a valid session cookie.
    Session,
    /// The request carried the valid setup token and should be handed a
    /// session cookie.
    Token,
    /// No valid credential.
    Denied,
    /// Too many failed token presentations from this address.
    LockedOut,
}

/// Shared state for the setup page handler.
pub struct SetupState {
    /// One-time setup token. Printed to stderr at startup and required, once,
    /// to open a setup session.
    setup_token: [u8; SETUP_TOKEN_LEN],
    /// Value of the session cookie handed out in exchange for the token.
    session_token: [u8; SETUP_TOKEN_LEN],
    /// Reference to the shared claim state.
    claim_state: Arc<Mutex<ClaimState>>,
    /// Server version string (from `CARGO_PKG_VERSION`).
    version: &'static str,
    /// Recovery key (hex string), set once at claim time, cleared after first read.
    /// This allows the setup page to show the recovery key one time after claiming.
    recovery_key: Mutex<Option<String>>,
    /// When this state was created, i.e. server startup.
    opened_at: Instant,
    /// How long after `opened_at` the claim secret stays available.
    /// `None` disables the expiry.
    window: Option<Duration>,
    /// Lockout for repeated bad tokens.
    throttle: TokenThrottle,
}

impl SetupState {
    /// Create a new setup state with a random token.
    ///
    /// `window_secs` bounds how long the claim secret remains available;
    /// `0` disables the expiry.
    pub fn new(
        claim_state: Arc<Mutex<ClaimState>>,
        version: &'static str,
        window_secs: u64,
    ) -> Self {
        let mut setup_token = [0u8; SETUP_TOKEN_LEN];
        rand::rngs::OsRng.fill_bytes(&mut setup_token);
        let mut session_token = [0u8; SETUP_TOKEN_LEN];
        rand::rngs::OsRng.fill_bytes(&mut session_token);
        Self {
            setup_token,
            session_token,
            claim_state,
            version,
            recovery_key: Mutex::new(None),
            opened_at: Instant::now(),
            window: (window_secs > 0).then(|| Duration::from_secs(window_secs)),
            throttle: TokenThrottle::default(),
        }
    }

    /// Return the setup token as a lowercase hex string.
    pub fn token_hex(&self) -> String {
        claim::hex_encode(&self.setup_token)
    }

    /// Validate a provided token string against the stored token.
    /// Uses constant-time comparison to prevent timing side-channels.
    fn validate_token(&self, provided: &str) -> bool {
        constant_time_eq_str(provided, &claim::hex_encode(&self.setup_token))
    }

    /// `true` when the setup window has closed.
    ///
    /// Only gates the *claim secret*: the status endpoint and the claimed
    /// page keep working, so an operator who claimed just before expiry can
    /// still collect their recovery key.
    pub fn window_expired(&self) -> bool {
        self.window
            .is_some_and(|window| self.opened_at.elapsed() >= window)
    }

    /// Decide whether a request may see the setup surface.
    fn authorize(&self, client: IpAddr, headers: &HeaderMap, token: Option<&str>) -> Access {
        if self.has_session_cookie(headers) {
            return Access::Session;
        }
        // Check the lockout before looking at the token, so a locked-out
        // address gains nothing by continuing to guess.
        if self.throttle.is_locked(client) {
            return Access::LockedOut;
        }
        match token {
            Some(t) if self.validate_token(t) => {
                self.throttle.reset(client);
                Access::Token
            }
            Some(_) => {
                self.throttle.record_failure(client);
                Access::Denied
            }
            None => Access::Denied,
        }
    }

    /// `true` when the request carries this process's session cookie.
    fn has_session_cookie(&self, headers: &HeaderMap) -> bool {
        let expected = claim::hex_encode(&self.session_token);
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|raw| raw.split(';'))
            .filter_map(|pair| pair.split_once('='))
            .any(|(name, value)| {
                name.trim() == SESSION_COOKIE && constant_time_eq_str(value.trim(), &expected)
            })
    }

    /// `Set-Cookie` value that opens a setup session.
    fn session_cookie_header(&self) -> String {
        // Session-scoped: no Max-Age, so it dies with the browser session.
        // `Secure` is deliberately omitted -- the page is served over plain
        // HTTP on loopback or through an operator's own tunnel.
        format!(
            "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict",
            claim::hex_encode(&self.session_token)
        )
    }

    /// Returns the 32-byte claim secret if the server is unclaimed.
    fn claim_secret(&self) -> Option<[u8; 32]> {
        let cs = self
            .claim_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cs.claim_secret().copied()
    }

    /// Store the recovery key after a successful claim. Called by the handler.
    pub fn set_recovery_key(&self, key_hex: String) {
        let mut rk = self
            .recovery_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *rk = Some(key_hex);
    }

    /// Take the recovery key (returns it once, then clears it).
    fn take_recovery_key(&self) -> Option<String> {
        let mut rk = self
            .recovery_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        rk.take()
    }

    /// Check if the server has been claimed.
    fn is_claimed(&self) -> bool {
        self.claim_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_claimed()
    }
}

/// Length-checked constant-time string comparison.
///
/// The length check leaks only the length, which for both the token and the
/// cookie is a compile-time constant.
fn constant_time_eq_str(provided: &str, expected: &str) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

/// Peer address of the request, if the listener attached connection info.
///
/// Its own extractor rather than a bare `ConnectInfo` so a router driven
/// without connection info -- which is how the tests exercise it -- degrades
/// to "unknown client" instead of rejecting the request.
struct PeerAddr(Option<SocketAddr>);

impl PeerAddr {
    /// Address to key the lockout on. Requests with no connection info share
    /// one bucket, which is the conservative choice: they throttle together.
    const fn ip(&self) -> IpAddr {
        match self.0 {
            Some(addr) => addr.ip(),
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;

    // Written as a plain fn returning a ready future: nothing here awaits.
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        std::future::ready(Ok(Self(peer)))
    }
}

/// Wrap a rendered page in the headers every setup response needs.
fn page(status: StatusCode, html: String) -> Response {
    let mut response = (status, Html(html)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if let Ok(csp) = HeaderValue::from_str(CSP) {
        headers.insert(header::CONTENT_SECURITY_POLICY, csp);
    }
    response
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
        .route("/setup/status", get(status_handler))
        .with_state(state)
}

/// GET / — shows guide when claimed, info page when unclaimed.
async fn root_handler(State(state): State<Arc<SetupState>>) -> Response {
    if state.is_claimed() {
        page(StatusCode::OK, claimed_page(state.version))
    } else {
        page(StatusCode::OK, unclaimed_root_page())
    }
}

/// GET /setup?token=<TOKEN>
///
/// Security layers:
/// 1. A valid setup token (constant-time compare) or an established session
///    cookie is required; repeated bad tokens lock the source address out.
/// 2. A token presented in the query string is swapped for a session cookie
///    and the caller is redirected to a token-free URL.
/// 3. The claim secret is only served while the server is unclaimed and
///    inside the setup window.
/// 4. After claiming, the page returns a benign "Server Claimed" message.
async fn setup_handler(
    State(state): State<Arc<SetupState>>,
    peer: PeerAddr,
    headers: HeaderMap,
    Query(params): Query<SetupQuery>,
) -> Response {
    // Always return the claimed page if already claimed -- regardless of token.
    if state.is_claimed() {
        return page(StatusCode::OK, claimed_page(state.version));
    }

    let client = peer.ip();
    match state.authorize(client, &headers, params.token.as_deref()) {
        Access::Session => {}
        Access::Token => return redirect_to_session(&state),
        Access::LockedOut => return page(StatusCode::TOO_MANY_REQUESTS, locked_out_page()),
        Access::Denied => return page(StatusCode::FORBIDDEN, forbidden_page()),
    }

    // The window closes on the claim secret only; everything above still
    // answers so a claim in flight can finish.
    if state.window_expired() {
        return page(StatusCode::GONE, expired_page());
    }

    // Serve the setup page with the claim QR code.
    let Some(secret) = state.claim_secret() else {
        // Race: server was claimed between the check above and here.
        return page(StatusCode::OK, claimed_page(state.version));
    };

    page(StatusCode::OK, render_setup_page(&secret))
}

/// Swap a valid token for a session cookie and bounce to a token-free URL.
///
/// Keeps the claim-secret-equivalent token out of browser history, out of
/// `Referer` headers on any link the page carries, and out of the access logs
/// of anything between the operator and the server.
fn redirect_to_session(state: &SetupState) -> Response {
    let mut response = (StatusCode::SEE_OTHER, ()).into_response();
    let headers = response.headers_mut();
    headers.insert(header::LOCATION, HeaderValue::from_static("/setup"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Ok(cookie) = HeaderValue::from_str(&state.session_cookie_header()) {
        headers.insert(header::SET_COOKIE, cookie);
    }
    response
}

/// GET /setup/status — JSON endpoint polled by the setup page JS.
///
/// Returns claim status and, once after claiming, the recovery key.
/// The recovery key is cleared after the first read (one-time).
/// Protected by the same session or token as `/setup`.
async fn status_handler(
    State(state): State<Arc<SetupState>>,
    peer: PeerAddr,
    headers: HeaderMap,
    Query(params): Query<SetupQuery>,
) -> Response {
    let client = peer.ip();
    let access = state.authorize(client, &headers, params.token.as_deref());
    let status = match access {
        Access::Session | Access::Token => StatusCode::OK,
        Access::LockedOut => StatusCode::TOO_MANY_REQUESTS,
        Access::Denied => StatusCode::FORBIDDEN,
    };
    if status != StatusCode::OK {
        let mut response = (
            status,
            axum::Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }

    let claimed = state.is_claimed();
    let recovery_key = if claimed {
        state.take_recovery_key()
    } else {
        None
    };

    let mut response = (
        status,
        axum::Json(serde_json::json!({
            "claimed": claimed,
            "recovery_key": recovery_key,
        })),
    )
        .into_response();
    let out = response.headers_mut();
    out.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    // A poll that arrived with the token still in the query gets a cookie too,
    // so subsequent polls need not carry it.
    if access == Access::Token
        && let Ok(cookie) = HeaderValue::from_str(&state.session_cookie_header())
    {
        out.insert(header::SET_COOKIE, cookie);
    }
    response
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
    <button class="copy-btn" id="copy-btn">Copy Code</button>
  </div>

  <div class="warning">
    This code is <strong>one-time use</strong> and will be destroyed after claiming.
    Only the server operator should see this page.
  </div>
</div>

<!-- Hidden recovery key page — shown by JS after successful claim -->
<div id="recovery-page" style="display:none;">
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#0f0f1a;color:#e0e0e6;min-height:100vh;display:flex;justify-content:center;
align-items:center;text-align:center;">
<div style="max-width:520px;padding:32px 24px;">
  <div style="font-size:3em;margin-bottom:16px;">&#x2705;</div>
  <h1 style="font-size:1.5em;color:#fff;margin:0 0 12px;">Server Claimed Successfully</h1>
  <p style="color:#9999bb;line-height:1.6;margin-bottom:24px;">
    Save your <strong style="color:#fff;">recovery key</strong> below. It is the
    <strong style="color:#ffaa44;">only way</strong> to reclaim your server if you lose your device.
    This key is shown <strong style="color:#ffaa44;">once</strong> and never stored on the server.
  </p>
  <div style="background:#1a1a2e;border:1px solid #2a2a44;border-radius:10px;
  padding:20px;margin-bottom:16px;">
    <div style="font-size:0.75em;color:#7777aa;text-transform:uppercase;
    letter-spacing:0.08em;margin-bottom:10px;">Recovery Key</div>
    <div id="rk-display" style="font-family:'SF Mono','Fira Code',Consolas,monospace;
    font-size:0.9em;color:#88cc88;word-break:break-all;line-height:1.8;
    user-select:all;"></div>
    <button id="rk-copy" style="margin-top:12px;padding:8px 20px;
    background:#2a2a44;color:#ccccee;border:1px solid #3a3a55;border-radius:6px;
    font-size:0.85em;cursor:pointer;">Copy Recovery Key</button>
  </div>
  <div style="background:rgba(255,180,50,0.08);border:1px solid rgba(255,180,50,0.2);
  border-radius:8px;padding:12px 16px;font-size:0.85em;color:#ddaa44;margin-bottom:20px;">
    <strong>Write this down or save it in a password manager.</strong><br>
    If you lose your device AND this key, you must redeploy with a fresh key volume.
  </div>
  <button id="rk-continue" style="padding:10px 28px;background:#2a4a2a;
  color:#88cc88;border:1px solid #3a6a3a;border-radius:6px;font-size:0.95em;
  cursor:pointer;">I've Saved It — Continue to Setup</button>
</div>
</div>
</div>

<script>
(function() {{
  var claimCode = '{full_hex}';

  // Copy claim code button
  document.getElementById('copy-btn').addEventListener('click', function() {{
    copyToClipboard(claimCode, 'copy-btn', 'Copy Code');
  }});

  // Copy recovery key button
  document.getElementById('rk-copy').addEventListener('click', function() {{
    copyToClipboard(window._rkRaw || '', 'rk-copy', 'Copy Recovery Key');
  }});

  // Continue button on recovery key page
  document.getElementById('rk-continue').addEventListener('click', function() {{
    window.location.href = '/';
  }});

  function copyToClipboard(text, btnId, resetLabel) {{
    var btn = document.getElementById(btnId);
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text).then(function() {{
        btn.textContent = 'Copied!';
        setTimeout(function() {{ btn.textContent = resetLabel; }}, 2000);
      }});
    }} else {{
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      btn.textContent = 'Copied!';
      setTimeout(function() {{ btn.textContent = resetLabel; }}, 2000);
    }}
  }}

  // Poll for claim status. The session cookie set when this page was opened
  // authenticates the poll, so the token never has to appear in a URL again.
  var pollInterval = setInterval(function() {{
    fetch('/setup/status', {{ credentials: 'same-origin' }})
      .then(function(r) {{
        if (!r.ok) return null;
        return r.json();
      }})
      .then(function(data) {{
        if (!data) return;
        if (data.claimed) {{
          clearInterval(pollInterval);
          if (data.recovery_key) {{
            showRecoveryKey(data.recovery_key);
          }} else {{
            window.location.href = '/';
          }}
        }}
      }})
      .catch(function() {{}});
  }}, 2000);

  function showRecoveryKey(key) {{
    window._rkRaw = key;
    var formatted = key.match(/.{{1,4}}/g).join('-');
    document.getElementById('rk-display').textContent = formatted;
    document.querySelector('.container').style.display = 'none';
    document.getElementById('recovery-page').style.display = 'block';
  }}
}})();
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
        format!(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}">"#);
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
          <pre><code>cloudflared tunnel --url http://localhost:9090 run stealth-relay</code></pre>
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
      <pre><code>cloudflared tunnel --url http://localhost:9090</code></pre>
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

/// Minimal styled page for the non-secret outcomes: denied, locked out,
/// window closed. Kept to one template so the three read alike.
fn notice_page(icon: &str, title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StealthOS Relay - {title}</title>
<style>
  body {{
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f0f1a;
    color: #e0e0e6;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
  }}
  .container {{ max-width: 420px; padding: 32px 24px; }}
  .icon {{ font-size: 3em; margin-bottom: 16px; }}
  h1 {{ font-size: 1.4em; color: #fff; margin: 0 0 12px 0; }}
  p {{ color: #9999bb; line-height: 1.6; }}
  code {{
    background: #1a1a2e;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.9em;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="icon">{icon}</div>
  <h1>{title}</h1>
  <p>{body}</p>
</div>
</body>
</html>"#
    )
}

/// HTML page shown when the token is missing or invalid.
fn forbidden_page() -> String {
    notice_page(
        "&#x1F512;",
        "Access Denied",
        "A valid setup token is required to access this page. \
         The setup URL, with its token, is printed to the server console \
         at startup.",
    )
}

/// HTML page shown after too many bad tokens from one address.
fn locked_out_page() -> String {
    notice_page(
        "&#x23F3;",
        "Too Many Attempts",
        "Too many invalid setup tokens came from this address. \
         Try again in a few minutes.",
    )
}

/// HTML page shown once the setup window has closed.
fn expired_page() -> String {
    notice_page(
        "&#x23F0;",
        "Setup Window Closed",
        "This server stopped handing out its claim code a while after \
         starting up, so that a setup link cannot be used long after it was \
         issued. Restart the relay to open a new setup window, or claim the \
         server with the code from the startup console.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cookie header value a browser would send back after a redirect.
    fn session_cookie_of(setup: &SetupState) -> String {
        format!(
            "{SESSION_COOKIE}={}",
            claim::hex_encode(&setup.session_token)
        )
    }

    fn make_unclaimed_state() -> (Arc<SetupState>, Arc<Mutex<ClaimState>>) {
        make_unclaimed_state_with_window(0)
    }

    fn make_unclaimed_state_with_window(
        window_secs: u64,
    ) -> (Arc<SetupState>, Arc<Mutex<ClaimState>>) {
        let dir = tempfile::tempdir().unwrap();
        let claim = ClaimState::load_or_create(dir.path());
        assert!(!claim.is_claimed());
        let shared = Arc::new(Mutex::new(claim));
        let setup = Arc::new(SetupState::new(
            Arc::clone(&shared),
            "0.0.0-test",
            window_secs,
        ));
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
        Arc::new(SetupState::new(shared, "0.0.0-test", 0))
    }

    /// Issue a GET against a fresh router built over `setup`.
    async fn get(
        setup: &Arc<SetupState>,
        uri: &str,
        cookie: Option<&str>,
    ) -> axum::http::Response<axum::body::Body> {
        let mut builder = axum::http::Request::builder().uri(uri);
        if let Some(c) = cookie {
            builder = builder.header(axum::http::header::COOKIE, c);
        }
        let req = builder.body(axum::body::Body::empty()).unwrap();
        tower::ServiceExt::oneshot(setup_router(Arc::clone(setup)), req)
            .await
            .unwrap()
    }

    async fn body_string(resp: axum::http::Response<axum::body::Body>) -> String {
        let body = axum::body::to_bytes(resp.into_body(), 262_144)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[test]
    fn token_validation_correct() {
        let (setup, _) = make_unclaimed_state();
        let token = setup.token_hex();
        assert!(setup.validate_token(&token));
    }

    #[test]
    fn token_is_256_bits() {
        let (setup, _) = make_unclaimed_state();
        assert_eq!(SETUP_TOKEN_LEN, 32);
        assert_eq!(setup.token_hex().len(), 64);
        // Two states must not share a token.
        let (other, _) = make_unclaimed_state();
        assert_ne!(setup.token_hex(), other.token_hex());
    }

    #[test]
    fn token_validation_wrong() {
        let (setup, _) = make_unclaimed_state();
        assert!(!setup.validate_token(&"0".repeat(64)));
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
        let resp = get(&setup, "/setup", None).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(!body_string(resp).await.contains("Claim Your Server"));
    }

    #[tokio::test]
    async fn setup_handler_wrong_token() {
        let (setup, _) = make_unclaimed_state();
        let resp = get(&setup, &format!("/setup?token={}", "0".repeat(64)), None).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A valid token buys a session cookie and a redirect; the claim secret
    /// is served to the follow-up request, not to the URL that carried the
    /// token. That keeps the token out of history, `Referer` and proxy logs.
    #[tokio::test]
    async fn valid_token_redirects_and_sets_session_cookie() {
        let (setup, _) = make_unclaimed_state();
        let token = setup.token_hex();

        let resp = get(&setup, &format!("/setup?token={token}"), None).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(axum::http::header::LOCATION).unwrap(),
            "/setup"
        );
        let cookie = resp
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie.starts_with(SESSION_COOKIE));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        // The redirect body carries no secret.
        assert!(!body_string(resp).await.contains("Claim Your Server"));

        // Following the redirect with the cookie yields the page.
        let jar = cookie.split(';').next().unwrap().to_owned();
        let resp = get(&setup, "/setup", Some(&jar)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("Claim Your Server"));
    }

    #[tokio::test]
    async fn wrong_session_cookie_is_rejected() {
        let (setup, _) = make_unclaimed_state();
        let forged = format!("{SESSION_COOKIE}={}", "0".repeat(64));
        let resp = get(&setup, "/setup", Some(&forged)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Repeated bad tokens lock the source address out, and the lockout
    /// applies even once a correct token is presented.
    #[tokio::test]
    async fn repeated_bad_tokens_lock_the_client_out() {
        let (setup, _) = make_unclaimed_state();
        let bad = format!("/setup?token={}", "0".repeat(64));
        for _ in 0..MAX_TOKEN_ATTEMPTS {
            let resp = get(&setup, &bad, None).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        let resp = get(&setup, &bad, None).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // Even the real token is refused while the lockout stands.
        let resp = get(&setup, &format!("/setup?token={}", setup.token_hex()), None).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // An established session is unaffected -- the lockout targets guessing.
        let resp = get(&setup, "/setup", Some(&session_cookie_of(&setup))).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Once the setup window closes the claim secret is gone until restart,
    /// so a setup URL scraped out of a log archive later is inert.
    #[tokio::test]
    async fn expired_window_withholds_the_claim_secret() {
        let (setup, _) = make_unclaimed_state_with_window(1);
        assert!(!setup.window_expired());

        // Reach into the state rather than sleeping: the window is a
        // wall-clock offset from startup.
        let expired = Arc::new(SetupState {
            opened_at: Instant::now()
                .checked_sub(Duration::from_secs(10))
                .expect("test clock is far enough from the epoch"),
            window: Some(Duration::from_secs(1)),
            ..SetupState::new(Arc::clone(&setup.claim_state), "0.0.0-test", 1)
        });
        assert!(expired.window_expired());

        let resp = get(&expired, "/setup", Some(&session_cookie_of(&expired))).await;
        assert_eq!(resp.status(), StatusCode::GONE);
        let html = body_string(resp).await;
        assert!(html.contains("Setup Window Closed"));
        assert!(!html.contains("Claim Your Server"));
    }

    #[tokio::test]
    async fn window_of_zero_never_expires() {
        let (setup, _) = make_unclaimed_state_with_window(0);
        assert!(setup.window.is_none());
        assert!(!setup.window_expired());
    }

    #[tokio::test]
    async fn setup_handler_claimed_returns_claimed_page() {
        let setup = make_claimed_state();
        let token = setup.token_hex();
        let resp = get(&setup, &format!("/setup?token={token}"), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Server Claimed"));
        assert!(!html.contains("Claim Your Server"));
    }

    #[tokio::test]
    async fn setup_handler_claimed_no_token_still_ok() {
        // Even without a token, claimed state returns the claimed page (200, not 403).
        let setup = make_claimed_state();
        let resp = get(&setup, "/setup", None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("Server Claimed"));
    }

    #[tokio::test]
    async fn status_requires_credentials() {
        let (setup, _) = make_unclaimed_state();
        let resp = get(&setup, "/setup/status", None).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = get(&setup, "/setup/status", Some(&session_cookie_of(&setup))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"claimed\":false"));
    }

    /// Pages that can carry the claim secret must not be cached, framed, or
    /// leak their own URL through a `Referer`.
    #[tokio::test]
    async fn setup_pages_carry_hardening_headers() {
        let (setup, _) = make_unclaimed_state();
        let resp = get(&setup, "/setup", Some(&session_cookie_of(&setup))).await;
        let headers = resp.headers();
        assert!(
            headers
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        assert_eq!(
            headers.get(axum::http::header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert_eq!(
            headers.get(axum::http::header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert!(
            headers
                .get(axum::http::header::CONTENT_SECURITY_POLICY)
                .is_some()
        );
    }

    #[test]
    fn throttle_evicts_when_full() {
        let throttle = TokenThrottle::default();
        for i in 0..(MAX_TRACKED_CLIENTS + 16) {
            let ip = IpAddr::V4(Ipv4Addr::from(u32::try_from(i).unwrap()));
            throttle.record_failure(ip);
        }
        let clients = throttle.clients.lock().unwrap();
        assert!(clients.len() <= MAX_TRACKED_CLIENTS);
    }
}
