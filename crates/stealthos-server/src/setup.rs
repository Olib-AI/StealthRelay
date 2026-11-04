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
use rand_core::Rng;
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
        rand::rng().fill_bytes(&mut setup_token);
        let mut session_token = [0u8; SETUP_TOKEN_LEN];
        rand::rng().fill_bytes(&mut session_token);
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

/// Stylesheet shared by every setup page.
///
/// System fonts only: the CSP allows no font source and these pages make no
/// outside request for their looks. The plate (`.plate`) keeps its white
/// background in dark mode too, because a QR code has to stay dark on light
/// to scan, and it reads as one object wherever it appears.
const PAGE_CSS: &str = r#"
:root {
  color-scheme: light dark;
  --page: #edf0f0;
  --ink: #172124;
  --soft: #46555a;
  --rule: #c2cccd;
  --well: #dde3e3;
  --accent: #1b6b62;
  --accent-hover: #14544d;
  --on-accent: #ffffff;
  --warn: #7a4a00;
  --mark-body: #2d3436;
  --sans: "Avenir Next", Avenir, "Segoe UI Variable Text", "Segoe UI", Ubuntu, Cantarell, "Noto Sans", system-ui, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, "Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --page: #11171a;
    --ink: #e8eeee;
    --soft: #a7b4b8;
    --rule: #303c40;
    --well: #1c2528;
    --accent: #7fd0c7;
    --accent-hover: #a3e0d9;
    --on-accent: #0c1f1d;
    --warn: #f0b66b;
    --mark-body: #e8eeee;
  }
}
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
html { -webkit-text-size-adjust: 100%; scroll-padding-top: 1.5rem; }
body {
  margin: 0;
  background: var(--page);
  color: var(--ink);
  font: 400 1.0625rem/1.55 var(--sans);
  overflow-wrap: break-word;
}
.shell {
  max-width: 70rem;
  margin: 0 auto;
  padding: clamp(1.25rem, 4vw, 3rem) clamp(1.25rem, 4vw, 3rem) 4rem;
}
.brand {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  margin-bottom: clamp(2.25rem, 7vw, 4.5rem);
  font-weight: 600;
}
.brand svg { display: block; width: 2.125rem; height: 2.125rem; flex: none; }
.mark-body { fill: var(--mark-body); }
h1 {
  margin: 0 0 0.9rem;
  font-size: clamp(2.25rem, 6.5vw, 3.5rem);
  font-weight: 600;
  line-height: 1.04;
  letter-spacing: -0.02em;
}
h1:focus { outline: none; }
h2 {
  margin: 3.25rem 0 0.6rem;
  font-size: 1.625rem;
  font-weight: 600;
  line-height: 1.2;
  letter-spacing: -0.01em;
}
h3 { margin: 0 0 0.4rem; font-size: 1.3125rem; font-weight: 600; line-height: 1.25; }
p { margin: 0 0 0.8rem; }
.prose { max-width: 38rem; }
.lede { font-size: 1.1875rem; line-height: 1.45; color: var(--soft); max-width: 34rem; }
.small { font-size: 0.9375rem; color: var(--soft); }
.warn { color: var(--warn); }
a { color: var(--accent); text-decoration-thickness: 1px; text-underline-offset: 0.16em; }
a:hover { color: var(--accent-hover); text-decoration-thickness: 2px; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 2px; }
code { font-family: var(--mono); font-size: 0.875em; font-variant-ligatures: none; overflow-wrap: anywhere; }
button { font: inherit; font-family: var(--sans); cursor: pointer; }

/* Numbered instructions: the numbers hang in their own column. */
.steps { list-style: none; margin: 1.25rem 0 0; padding: 0; counter-reset: step; }
.steps > li { counter-increment: step; position: relative; padding-left: 2rem; margin-top: 1.15rem; }
.steps > li::before {
  content: counter(step);
  position: absolute;
  left: 0;
  font-weight: 600;
  color: var(--accent);
  font-variant-numeric: lining-nums tabular-nums;
}
.steps p { margin: 0.35rem 0 0.6rem; }
@media (max-width: 30rem) {
  .steps > li { padding-left: 1.4rem; }
}
.steps .small { margin-top: 0.5rem; }

/* A command: wraps instead of scrolling, so all of it can be read before it is run. */
.cmd {
  display: flow-root;
  margin: 0.5rem 0 0.75rem;
  padding: 0.6rem 0.75rem;
  background: var(--well);
  border-radius: 6px;
}
.cmd pre {
  margin: 0;
  font: 0.875rem/1.55 var(--mono);
  font-variant-ligatures: none;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.cmd code { font-size: inherit; }
.cmd button {
  float: right;
  margin: -0.15rem -0.25rem 0.15rem 0.75rem;
  padding: 0.1rem 0.5rem;
  min-height: 1.75rem;
  color: var(--accent);
  background: transparent;
  border: 1px solid currentColor;
  border-radius: 5px;
  font-size: 0.8125rem;
  font-weight: 500;
}
.cmd button:hover { color: var(--accent-hover); }
.os { margin: 0.75rem 0 0; font-size: 0.9375rem; font-weight: 600; }
.os + .cmd { margin-top: 0.25rem; }
.subhead { margin: 1.75rem 0 0.25rem; font-weight: 600; }
.claim-window { margin-top: 1.5rem; }
@media (pointer: coarse) {
  .cmd button { min-height: 2.5rem; padding-inline: 0.75rem; }
}

/* The plate: the one object on these pages, a printed label with the code on it. */
.plate {
  width: max-content;
  max-width: 100%;
  padding: 1.5rem;
  color: #11191c;
  background: #ffffff;
  border: 1.5px solid #11191c;
  border-radius: 14px;
  font-size: 1.25rem;
}
@media (max-width: 22rem) {
  .plate { padding: 1rem; }
}
.plate :focus-visible { outline-color: #1b6b62; }
.plate-qr { width: 20.2ch; max-width: 100%; margin: -0.35rem -0.1rem 1rem; font-family: var(--mono); }
.plate-qr svg { display: block; width: 100%; height: auto; shape-rendering: crispEdges; }
.plate-label { margin: 0 0 0.3rem; font-size: 0.9375rem; font-weight: 600; line-height: 1.3; }
/* 20 characters to a line is exactly four groups, so the code sets as a 4 by 4 block. */
.plate-code {
  width: 20.2ch;
  max-width: 100%;
  margin: 0;
  font-family: var(--mono);
  font-variant-ligatures: none;
  font-variant-numeric: tabular-nums;
  line-height: 1.5;
  word-break: break-all;
  -webkit-user-select: all;
  user-select: all;
}
.plate-note {
  width: 0;
  min-width: 100%;
  margin: 0.9rem 0 0;
  font-size: 0.875rem;
  line-height: 1.4;
  color: #3d4b50;
}
.plate-copy {
  display: block;
  width: 100%;
  min-height: 2.75rem;
  margin-top: 1rem;
  padding: 0.45rem 1rem;
  color: #ffffff;
  background: #1b6b62;
  border: 0;
  border-radius: 7px;
  font-size: 1rem;
  font-weight: 600;
}
.plate-copy:hover { background: #14544d; }
.action {
  min-height: 2.75rem;
  margin-top: 0.75rem;
  padding: 0.5rem 1.15rem;
  color: var(--on-accent);
  background: var(--accent);
  border: 0;
  border-radius: 7px;
  font-weight: 600;
}
.action:hover { background: var(--accent-hover); }

/* Claim page: words on the left, plate on the right; on a phone the plate comes second. */
.claim {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  grid-template-areas: "intro" "plate" "rest";
  gap: 1.75rem;
}
.claim-intro { grid-area: intro; }
.claim-plate { grid-area: plate; }
.claim-rest { grid-area: rest; min-width: 0; }
.claim-intro > :last-child, .claim-rest > :last-child { margin-bottom: 0; }
.claim-rest .steps { margin-top: 0; }
.claim-rest .steps > li:first-child { margin-top: 0; }
@media (min-width: 60rem) {
  .claim {
    grid-template-columns: minmax(0, 1fr) max-content;
    grid-template-rows: auto 1fr;
    grid-template-areas: "intro plate" "rest plate";
    column-gap: clamp(3rem, 7vw, 6rem);
    row-gap: 2rem;
  }
  .claim-plate { position: sticky; top: 1.5rem; align-self: start; }
}
.status {
  width: 0;
  min-width: 100%;
  margin: 0.9rem 0 0;
  font-size: 0.9375rem;
  line-height: 1.4;
  color: var(--soft);
}
.status::before {
  content: "";
  display: inline-block;
  width: 0.5rem;
  height: 0.5rem;
  margin-right: 0.5rem;
  border-radius: 50%;
  background: var(--accent);
  vertical-align: 0.08em;
}
.status.is-stuck { color: var(--warn); }
.status.is-stuck::before { background: var(--warn); }
@media (prefers-reduced-motion: no-preference) {
  .status:not(.is-stuck)::before { animation: waiting 2s ease-in-out infinite; }
  @keyframes waiting { 50% { opacity: 0.25; } }
}
details.guide { margin-top: 0.75rem; }
details.guide > summary {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  min-height: 2.75rem;
  color: var(--accent);
  font-weight: 600;
  cursor: pointer;
  list-style: none;
}
details.guide > summary:hover { color: var(--accent-hover); }
details.guide > summary::-webkit-details-marker { display: none; }
/* A drawn chevron that turns when the guide opens. */
details.guide > summary::before {
  content: "";
  width: 0.5rem;
  height: 0.5rem;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
  transform: rotate(-45deg);
}
details.guide[open] > summary::before { transform: translateY(-0.1rem) rotate(45deg); }
details.guide[open] { margin-bottom: 2rem; }
.guide-body { margin-top: 1rem; padding-top: 1.25rem; border-top: 1px solid var(--rule); }

/* Ready page: a contents column on wide screens, then one reading column. */
.manual { display: grid; grid-template-columns: minmax(0, 1fr); }
.manual-main { min-width: 0; max-width: 44rem; }
.contents { display: none; }
@media (min-width: 60rem) {
  .manual { grid-template-columns: 11rem minmax(0, 1fr); column-gap: clamp(2.5rem, 6vw, 5rem); }
  .contents { display: block; position: sticky; top: 1.5rem; align-self: start; padding-top: 0.75rem; }
}
.contents p { margin: 0 0 0.4rem; font-size: 0.9375rem; color: var(--soft); }
.contents ul { margin: 0; padding: 0; list-style: none; font-size: 0.9375rem; line-height: 1.35; }
.contents li { margin-bottom: 0.55rem; }

/* The route a connection takes: three stops, read left to right or top to bottom. */
.route {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  margin: 1.5rem 0 1.75rem;
  padding: 0;
  list-style: none;
}
.stop { padding: 0.7rem 0.9rem; border: 1px solid var(--rule); border-radius: 8px; line-height: 1.3; }
.stop strong { display: block; font-weight: 600; }
.stop span { font-size: 0.875rem; color: var(--soft); }
.stop.is-relay { color: #11191c; background: #ffffff; border: 1.5px solid #11191c; }
.stop.is-relay span { color: #3d4b50; }
.hop {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  min-height: 2.25rem;
  margin-left: 1.25rem;
  padding-left: 0.75rem;
  border-left: 1.5px solid var(--soft);
  font: 0.8125rem/1.3 var(--mono);
  color: var(--soft);
}
@media (min-width: 40rem) {
  .route { grid-template-columns: minmax(0, 1fr) 6rem minmax(0, 1fr) 6rem minmax(0, 1fr); align-items: center; }
  .hop {
    display: block;
    min-height: 0;
    margin: 0;
    padding: 0 0.25rem 0.2rem;
    border-left: 0;
    border-bottom: 1.5px solid var(--soft);
    text-align: center;
  }
}

/* Options under the guide are separated by a heavy rule, not boxed. */
.option { margin-top: 2.5rem; padding-top: 1.25rem; border-top: 2px solid var(--ink); }
.update { margin: 1.5rem 0 0; display: none; }
.update.visible { display: block; }
.update-title { margin-bottom: 0.25rem; font-weight: 600; }

.compare { width: 100%; margin: 1.25rem 0 0.75rem; border-collapse: collapse; font-size: 0.9375rem; line-height: 1.35; }
.compare th, .compare td { padding: 0.55rem 0.75rem 0.55rem 0; text-align: left; vertical-align: top; }
.compare thead th { font-weight: 600; border-bottom: 2px solid var(--ink); }
.compare tbody th { font-weight: 400; color: var(--soft); }
.compare tbody tr { border-bottom: 1px solid var(--rule); }
.compare th:last-child, .compare td:last-child { padding-right: 0; }
@media (max-width: 39.99rem) {
  .compare thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
  .compare tbody tr { display: block; padding: 0.75rem 0; }
  .compare tbody th, .compare tbody td { display: block; padding: 0.1rem 0; }
  .compare tbody th { margin-bottom: 0.15rem; font-weight: 600; color: var(--ink); }
  .compare tbody td::before { content: attr(data-label) ": "; color: var(--soft); }
}

.foot { margin-top: 4rem; padding-top: 1rem; border-top: 1px solid var(--rule); font-size: 0.9375rem; color: var(--soft); }
.foot p:last-child { margin-bottom: 0; }

/* Notice pages. */
.notice { max-width: 38rem; }
.notice h1 { font-size: clamp(2rem, 5.5vw, 2.75rem); }
.notice ul { margin: 0 0 0.8rem; padding-left: 1.15rem; }
.notice li { margin-bottom: 0.5rem; }
"#;

/// Name and mark at the top of every page, drawn from the `StealthOS` logo.
const BRAND: &str = r##"<header class="brand"><svg viewBox="0 0 100 100" aria-hidden="true" focusable="false"><path class="mark-body" fill-rule="evenodd" d="{{MARK_BODY}}"/><path fill="#8fa894" fill-rule="evenodd" d="{{MARK_SAGE}}"/><circle cx="42.5" cy="29" r="3" fill="#4db6ac"/><circle cx="58" cy="29" r="3" fill="#4db6ac"/></svg><span>StealthOS Relay</span></header>"##;

/// Copy helper shared by every page, and the Copy button on each command.
///
/// Presentation only. `navigator.clipboard` needs a secure context, which
/// loopback is and a LAN address is not, so the older path stays as a fallback.
const COPY_SCRIPT: &str = r"
function copyText(text, btn, label) {
  function done(ok) {
    btn.textContent = ok ? 'Copied' : 'Could not copy';
    setTimeout(function() { btn.textContent = label; }, 2000);
  }
  function fallback() {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    btn.focus();
    done(ok);
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() { done(true); }, fallback);
  } else {
    fallback();
  }
}
document.querySelectorAll('.cmd').forEach(function(block) {
  var code = block.querySelector('code');
  var btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = 'Copy';
  btn.setAttribute('aria-label', 'Copy command');
  btn.addEventListener('click', function() { copyText(code.textContent, btn, 'Copy'); });
  block.insertBefore(btn, block.firstChild);
});
";

/// Wrap a page body in the document every setup page shares.
fn html_document(title: &str, body: &str, script: &str) -> String {
    let brand = BRAND
        .replace("{{MARK_BODY}}", MARK_BODY)
        .replace("{{MARK_SAGE}}", MARK_SAGE);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title}</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<div class="shell">
{brand}
{body}
</div>
<script>{COPY_SCRIPT}{script}</script>
</body>
</html>"#
    )
}

/// Outline of the logo's body.
const MARK_BODY: &str = "M64 62L63 62L56 70L56 78L57 78L58 74L63 66ZM67 7L66 8L56 16L52 15L45 16L35 8L34 8L39 19L33 24L30 34L42 42L42 43L38 42L35 56L22 65L18 77L18 78L19 83L23 87L23 88L9 90L7 90L7 91L11 92L21 93L45 94L78 93L90 92L94 91L94 90L90 89L82 88L80 89L77 86L73 85L66 84L65 83L67 82L67 81L36 79L36 78L42 78L42 75L41 71L39 68L35 65L36 64L40 66L43 69L45 73L46 78L54 78L54 69L60 62L62 55L63 42L58 43L58 42L71 34L68 24L62 19ZM58 27L59 27L61 29L60 31L59 32L57 32L56 30L56 28ZM42 27L44 27L45 29L45 31L43 32L41 32L40 30L40 28Z";
/// Outline of the logo's lighter shading.
const MARK_SAGE: &str = "M64 39L60 42L60 42L63 42L62 56L60 62L54 69L54 78L46 78L45 75L43 69L40 66L36 65L36 66L40 70L42 75L42 78L40 78L40 79L68 81L68 82L66 83L66 84L73 84L80 87L78 84L73 80L68 78L61 78L62 68L62 69L58 74L57 78L56 78L56 70L64 60L67 56L64 39ZM42 42L37 39L34 46L27 51L22 56L19 64L18 70L18 75L18 75L22 65L35 55L38 42L39 42L42 43ZM67 8L62 19L67 23L68 23L68 8ZM33 7L33 23L34 23L39 19L39 18L34 7Z";

/// How to get an address the app can use. Shown before claiming, because the
/// app needs that address to reach the relay at all, and again after it.
const TUNNEL_GUIDE: &str = r##"
<table class="compare">
  <thead>
    <tr><td></td><th scope="col"><a href="#ngrok">ngrok</a></th><th scope="col"><a href="#cloudflare">Cloudflare Tunnel</a></th><th scope="col"><a href="#tailscale">Tailscale Funnel</a></th></tr>
  </thead>
  <tbody>
    <tr><th scope="row">Setup time</th><td data-label="ngrok">About 2 minutes</td><td data-label="Cloudflare Tunnel">About 10 minutes</td><td data-label="Tailscale Funnel">About 5 minutes</td></tr>
    <tr><th scope="row">Needs a domain</th><td data-label="ngrok">No</td><td data-label="Cloudflare Tunnel">Yes, or use a quick tunnel for testing</td><td data-label="Tailscale Funnel">No</td></tr>
    <tr><th scope="row">Address</th><td data-label="ngrok">Assigned by ngrok, stays the same</td><td data-label="Cloudflare Tunnel">Your own domain</td><td data-label="Tailscale Funnel">A ts.net name, stays the same</td></tr>
    <tr><th scope="row">Data on the free plan</th><td data-label="ngrok">1 GB a month</td><td data-label="Cloudflare Tunnel">No published limit</td><td data-label="Tailscale Funnel">Limited, no published figure</td></tr>
    <tr><th scope="row">Good for</th><td data-label="ngrok">Trying it out</td><td data-label="Cloudflare Tunnel">A relay you keep running</td><td data-label="Tailscale Funnel">Personal use</td></tr>
  </tbody>
</table>
<p class="small">Free-plan limits were last checked in November 2026 and can change. Voice and video calls go through the relay, so they use data quickly.</p>
<p class="small">The commands use the relay's default port, 9090. If you changed <code>server.ws_bind</code>, use your port instead.</p>

<section class="option" id="ngrok">
  <h3>ngrok</h3>
  <p>The quickest way to get an address, and it stays the same when you restart the tunnel. Needs a free ngrok account.</p>
  <ol class="steps" role="list">
    <li>Create an account at <a href="https://ngrok.com/signup" target="_blank" rel="noopener">ngrok.com/signup</a>.</li>
    <li>Install ngrok.
      <p class="os">macOS</p>
      <div class="cmd"><pre><code>brew install ngrok</code></pre></div>
      <p class="os">Linux, with snap</p>
      <div class="cmd"><pre><code>sudo snap install ngrok</code></pre></div>
      <p class="small">Anything else: <a href="https://ngrok.com/download" target="_blank" rel="noopener">ngrok.com/download</a>.</p>
    </li>
    <li>Add your auth token, which is on the ngrok dashboard.
      <div class="cmd"><pre><code>ngrok config add-authtoken YOUR_TOKEN</code></pre></div>
    </li>
    <li>Start the tunnel and leave it running.
      <div class="cmd"><pre><code>ngrok http 9090</code></pre></div>
      <p>ngrok prints a forwarding address like <code>https://your-assigned-name.ngrok-free.app</code>. In StealthOS, use it with <code>wss://</code>: <code>wss://your-assigned-name.ngrok-free.app</code>.</p>
    </li>
  </ol>
</section>

<section class="option" id="cloudflare">
  <h3>Cloudflare Tunnel</h3>
  <p>A lasting address on your own domain. Needs a free Cloudflare account and a domain on Cloudflare. You can move a domain you already own or buy one, from about $10 a year.</p>
  <ol class="steps" role="list">
    <li>Create an account at <a href="https://dash.cloudflare.com/sign-up" target="_blank" rel="noopener">dash.cloudflare.com</a>.</li>
    <li>Install cloudflared.
      <p class="os">macOS</p>
      <div class="cmd"><pre><code>brew install cloudflared</code></pre></div>
      <p class="os">Ubuntu or Debian</p>
      <div class="cmd"><pre><code>curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg &gt; /dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update &amp;&amp; sudo apt install cloudflared</code></pre></div>
      <p class="small">Anything else: <a href="https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/" target="_blank" rel="noopener">Cloudflare's downloads page</a>.</p>
    </li>
    <li>Log in to Cloudflare. This opens a browser window where you authorize your account.
      <div class="cmd"><pre><code>cloudflared tunnel login</code></pre></div>
    </li>
    <li>Create the tunnel.
      <div class="cmd"><pre><code>cloudflared tunnel create stealth-relay</code></pre></div>
    </li>
    <li>Point a name on your domain at it.
      <div class="cmd"><pre><code>cloudflared tunnel route dns stealth-relay relay.yourdomain.com</code></pre></div>
    </li>
    <li>Start the tunnel and leave it running.
      <div class="cmd"><pre><code>cloudflared tunnel --url http://localhost:9090 run stealth-relay</code></pre></div>
    </li>
    <li>In StealthOS, use <code>wss://relay.yourdomain.com</code>.</li>
  </ol>
  <p class="subhead">No domain, or just testing?</p>
  <p>A quick tunnel needs no domain and no account:</p>
  <div class="cmd"><pre><code>cloudflared tunnel --url http://localhost:9090</code></pre></div>
  <p>It prints a temporary address like <code>https://xxxx-xxxx.trycloudflare.com</code>, which you use with <code>wss://</code>. The address changes every time the tunnel restarts, so it is for testing only.</p>
</section>

<section class="option" id="tailscale">
  <h3>Tailscale Funnel</h3>
  <p>A lasting address on a ts.net name, with no domain to buy. Needs a free Tailscale account. Funnel is in beta, and Tailscale limits its bandwidth without publishing a figure.</p>
  <ol class="steps" role="list">
    <li>Create an account at <a href="https://login.tailscale.com/start" target="_blank" rel="noopener">login.tailscale.com</a> and install Tailscale on this machine.
      <p class="os">macOS</p>
      <div class="cmd"><pre><code>brew install tailscale
sudo brew services start tailscale</code></pre></div>
      <p class="small">Not every Tailscale app for macOS can share a port with Funnel. <a href="https://tailscale.com/kb/1223/funnel" target="_blank" rel="noopener">Tailscale's Funnel guide</a> lists which can.</p>
      <p class="os">Ubuntu or Debian</p>
      <div class="cmd"><pre><code>curl -fsSL https://tailscale.com/install.sh | sh</code></pre></div>
      <p class="small">Anything else: <a href="https://tailscale.com/download" target="_blank" rel="noopener">tailscale.com/download</a>.</p>
    </li>
    <li>Connect to your Tailscale network.
      <div class="cmd"><pre><code>sudo tailscale up</code></pre></div>
    </li>
    <li>Turn on Funnel for port 9090 and leave it running. The first time, Tailscale gives you a page where you approve Funnel for your network.
      <div class="cmd"><pre><code>sudo tailscale funnel 9090</code></pre></div>
    </li>
    <li>Tailscale prints your public address, something like <code>https://your-machine.tailnet-name.ts.net</code>. In StealthOS, use it with <code>wss://</code>: <code>wss://your-machine.tailnet-name.ts.net</code>.</li>
  </ol>
</section>

<section class="option">
  <h3>What a tunnel provider can see</h3>
  <p>A tunnel ends TLS on the provider's servers. The provider can see which addresses connect to your relay, when, how much they send, and relay details such as pool IDs. StealthOS encrypts chats and calls between pool members before they leave the device.</p>
  <p>To leave the provider out, give the relay its own certificate with <code>tls_cert_path</code> and <code>tls_key_path</code> under <code>[transport]</code> in its config, and open its port to the internet.</p>
</section>
"##;

/// Body of the claim page. `{{QR}}`, `{{CODE}}` and `{{GUIDE}}` are filled in
/// by [`render_setup_page`].
const CLAIM_BODY: &str = r#"
<main class="claim" id="claim-view">
  <div class="claim-intro">
    <h1>Claim Your Server</h1>
    <p class="lede">The device that claims this relay becomes its owner. After that, only that device can host pools here.</p>
  </div>

  <div class="claim-plate">
    <div class="plate">
      <div class="plate-qr" role="img" aria-label="QR code that claims this server in the StealthOS app">{{QR}}</div>
      <p class="plate-label" id="claim-label">Claim code</p>
      <p class="plate-code" id="claim-code" aria-labelledby="claim-label">{{CODE}}</p>
      <button class="plate-copy" id="copy-btn" type="button">Copy code</button>
      <p class="plate-note">Anyone who has this code can claim this server, so keep this page to yourself. The code stops working once the server is claimed.</p>
    </div>
    <p class="status" id="claim-status" role="status">Waiting for the app. This page updates by itself.</p>
  </div>

  <div class="claim-rest">
    <ol class="steps" role="list">
      <li><strong>Give the relay a <code>wss://</code> address.</strong>
        <p>StealthOS connects to relays only over TLS, so it cannot use <code>ws://localhost:9090</code>. A tunnel gives the relay an HTTPS address, which the app uses as <code>wss://</code>.</p>
        <p>If you deployed to Fly.io, Railway, Render or DigitalOcean, the provider has already given you an HTTPS address. Use that.</p>
        <details class="guide">
          <summary>How to set up a tunnel</summary>
          <div class="guide-body">{{GUIDE}}</div>
        </details>
      </li>
      <li><strong>Connect from the app.</strong>
        <p>In StealthOS, open Connection Pool and choose Host Remote Pool. Enter the address as the Server URL, then choose Create Remote Pool.</p>
      </li>
      <li><strong>Claim the server.</strong>
        <p>When the app asks you to claim the server, choose Scan QR Code and point the camera at this page, or enter the code by hand.</p>
      </li>
      <li><strong>Save your recovery key.</strong>
        <p>The app shows it after the claim. Keep this page open and it appears here too.</p>
      </li>
    </ol>
    <p class="small claim-window">By default the relay stops showing this code one hour after it starts. Restarting it starts the hour again and prints a new setup link.</p>
  </div>
</main>

<main class="claim" id="recovery-page" hidden>
  <div class="claim-intro">
    <p class="small">Server claimed.</p>
    <h1 id="recovery-title" tabindex="-1">Save Your Recovery Key</h1>
    <p class="lede">This key is the only way to claim the relay again if you lose the device that owns it.</p>
  </div>

  <div class="claim-plate">
    <div class="plate">
      <p class="plate-label" id="rk-label">Recovery key</p>
      <p class="plate-code" id="rk-display" aria-labelledby="rk-label"></p>
      <button class="plate-copy" id="rk-copy" type="button">Copy recovery key</button>
    </div>
  </div>

  <div class="claim-rest">
    <div class="prose">
      <p>The relay stores only a hash of this key, so it cannot show the key to you again after you leave this page.</p>
      <p>Save it in a password manager or write it down. If you lose both the device and this key, you have to redeploy the relay with a fresh key volume.</p>
      <button class="action" id="rk-continue" type="button">I've saved it, continue</button>
    </div>
  </div>
</main>
"#;

/// Script for the claim page. `{{CLAIM_HEX}}` is filled in by
/// [`render_setup_page`].
const CLAIM_SCRIPT: &str = r"
(function() {
  var claimCode = '{{CLAIM_HEX}}';
  var recoveryKey = '';
  var status = document.getElementById('claim-status');
  var waitingText = status.textContent;

  document.getElementById('copy-btn').addEventListener('click', function() {
    copyText(claimCode, this, 'Copy code');
  });
  document.getElementById('rk-copy').addEventListener('click', function() {
    copyText(recoveryKey, this, 'Copy recovery key');
  });
  document.getElementById('rk-continue').addEventListener('click', function() {
    window.location.href = '/';
  });

  function showStuck(stuck) {
    status.classList.toggle('is-stuck', stuck);
    var text = stuck ? 'No answer from the relay. If it restarted, open the new setup link from its console.' : waitingText;
    if (status.textContent !== text) status.textContent = text;
  }

  // Poll for claim status. The session cookie set when this page was opened
  // authenticates the poll, so the token never has to appear in a URL again.
  var pollInterval = setInterval(function() {
    fetch('/setup/status', { credentials: 'same-origin' })
      .then(function(r) {
        showStuck(!r.ok);
        if (!r.ok) return null;
        return r.json();
      })
      .then(function(data) {
        if (!data) return;
        if (data.claimed) {
          clearInterval(pollInterval);
          if (data.recovery_key) {
            showRecoveryKey(data.recovery_key);
          } else {
            window.location.href = '/';
          }
        }
      })
      .catch(function() { showStuck(true); });
  }, 2000);

  function showRecoveryKey(key) {
    recoveryKey = key;
    document.getElementById('rk-display').textContent = key.match(/.{1,4}/g).join('-');
    document.getElementById('claim-view').hidden = true;
    document.getElementById('recovery-page').hidden = false;
    document.title = 'StealthOS Relay: Save Your Recovery Key';
    window.scrollTo(0, 0);
    document.getElementById('recovery-title').focus();
  }
})();
";

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

    let body = CLAIM_BODY
        .replace("{{GUIDE}}", TUNNEL_GUIDE)
        .replace("{{QR}}", &svg)
        .replace("{{CODE}}", &formatted);
    let script = CLAIM_SCRIPT.replace("{{CLAIM_HEX}}", &full_hex);
    html_document("StealthOS Relay: Claim Server", &body, &script)
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
        return String::from(
            "<p>The QR code could not be drawn. Enter the code below by hand.</p>",
        );
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

/// Where to find the setup link, used on the pages that ask for it.
const FIND_SETUP_LINK: &str = r#"
<p>If the console has scrolled away, search the relay's logs for the link.</p>
<p class="os">Installed as a service on Linux</p>
<div class="cmd"><pre><code>sudo journalctl -u stealth-relay | grep setup</code></pre></div>
<p class="os">Docker</p>
<div class="cmd"><pre><code>docker logs stealth-relay 2&gt;&amp;1 | grep setup</code></pre></div>
"#;

/// HTML page shown when visiting `/` before claiming.
fn unclaimed_root_page() -> String {
    let body = format!(
        r#"<main class="notice">
<h1>Waiting to Be Claimed</h1>
<p class="lede">To claim this relay, open its setup link.</p>
<p>The relay printed the link to its console when it started. The link carries a token that protects the setup page.</p>
{FIND_SETUP_LINK}
</main>"#
    );
    html_document("StealthOS Relay", &body, "")
}

/// HTML page shown after the server has been claimed.
/// Includes step-by-step guides for setting up free HTTPS tunnels
/// and a client-side update check (browser fetches GitHub API, not the server).
fn claimed_page(version: &str) -> String {
    // Use string replacement instead of format! to avoid escaping all CSS/JS braces.
    let body = READY_BODY
        .replace("{{GUIDE}}", TUNNEL_GUIDE)
        .replace("{{VERSION}}", version);
    html_document("StealthOS Relay: Server Ready", &body, READY_SCRIPT)
}

/// Body of the page shown once the server is claimed.
const READY_BODY: &str = r##"
<div class="manual">
  <nav class="contents" aria-label="On this page">
    <p>On this page</p>
    <ul>
      <li><a href="#address">Public address</a></li>
      <li><a href="#ngrok">ngrok</a></li>
      <li><a href="#cloudflare">Cloudflare Tunnel</a></li>
      <li><a href="#tailscale">Tailscale Funnel</a></li>
      <li><a href="#check">Check it works</a></li>
      <li><a href="#in-app">Use it in StealthOS</a></li>
    </ul>
  </nav>

  <main class="manual-main">
    <h1>Server Claimed</h1>
    <p class="lede">This relay is running and belongs to the device that claimed it. Only that device can host pools here.</p>
    <p class="small">Relay version <span id="current-version">{{VERSION}}</span></p>

    <div class="update" id="update-banner">
      <p class="update-title">A new version is available: <span id="new-version"></span></p>
      <p>To update a native install, run this on the server. Your keys and config are kept.</p>
      <div class="cmd"><pre><code>curl -fsSL https://raw.githubusercontent.com/Olib-AI/StealthRelay/main/scripts/install.sh | bash -s -- --update</code></pre></div>
      <p class="small"><a href="https://github.com/Olib-AI/StealthRelay/releases" target="_blank" rel="noopener">Read the release notes</a></p>
    </div>

    <h2 id="address">Give it a public address</h2>
    <div class="prose">
      <p>People you invite connect through the address in their invitation. StealthOS accepts only <code>wss://</code> addresses, so that address has to be HTTPS. A tunnel gives the relay one without opening a port or managing a certificate.</p>
    </div>

    <ol class="route" aria-label="How a connection reaches this relay">
      <li class="stop"><strong>StealthOS</strong><span>on each device</span></li>
      <li class="hop" aria-label="over">wss://</li>
      <li class="stop"><strong>Tunnel</strong><span>TLS ends here</span></li>
      <li class="hop" aria-label="over">http://</li>
      <li class="stop is-relay"><strong>This relay</strong><span>port 9090</span></li>
    </ol>

    <div class="prose">
      <p>If you claimed over an address that lasts, you already have what you need: go to <a href="#check">Check it works</a>. If you deployed to Fly.io, Railway, Render or DigitalOcean, the provider's HTTPS address is yours to use.</p>
    </div>

    {{GUIDE}}

    <h2 id="check">Check it works</h2>
    <p>From any device, with your own address in place of <code>your-tunnel-url</code>:</p>
    <div class="cmd"><pre><code>curl -i --http1.1 \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://your-tunnel-url/</code></pre></div>
    <p>You should see <code>101 Switching Protocols</code>, which means the relay answers from the internet. curl then keeps the connection open, so press Ctrl+C to end it.</p>

    <h2 id="in-app">Use it in StealthOS</h2>
    <p>If the app still has a different address for this relay, open Connection Pool, edit the saved server's URL and enter the new <code>wss://</code> address. Invitations you create after that carry the new address.</p>

    <footer class="foot">
      <p><a href="https://github.com/Olib-AI/StealthRelay" target="_blank" rel="noopener">StealthRelay</a> is made by <a href="https://www.olib.ai" target="_blank" rel="noopener">Olib AI</a> for <a href="https://www.stealthos.app" target="_blank" rel="noopener">StealthOS</a>.</p>
      <p>This page checks for a new version by asking GitHub from your browser, not from the relay.</p>
    </footer>
  </main>
</div>
"##;

/// Update check for the page shown once the server is claimed.
const READY_SCRIPT: &str = r"
// Client-side update check: the BROWSER fetches the GitHub API, not the server.
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
    .catch(function() { /* silently ignore: no connectivity or rate limited */ });

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
";

/// Minimal page for the non-secret outcomes: denied, locked out, window
/// closed. Kept to one template so the three read alike.
fn notice_page(title: &str, body: &str) -> String {
    let main = format!(r#"<main class="notice"><h1>{title}</h1>{body}</main>"#);
    html_document(&format!("StealthOS Relay: {title}"), &main, "")
}

/// HTML page shown when the token is missing or invalid.
fn forbidden_page() -> String {
    notice_page(
        "Access Denied",
        &format!(
            r#"<p class="lede">This page needs the relay's setup link, with its token.</p>
<p>The relay printed the link to its console when it started. Each restart prints a new link, and the old one stops working.</p>
{FIND_SETUP_LINK}"#
        ),
    )
}

/// HTML page shown after too many bad tokens from one address.
fn locked_out_page() -> String {
    let minutes = TOKEN_LOCKOUT.as_secs() / 60;
    notice_page(
        "Too Many Attempts",
        &format!(
            r#"<p class="lede">The relay received {MAX_TOKEN_ATTEMPTS} wrong setup tokens from this address, so it is refusing this address for {minutes} minutes.</p>
<p>After that, open the setup link exactly as the relay printed it.</p>"#
        ),
    )
}

/// HTML page shown once the setup window has closed.
fn expired_page() -> String {
    notice_page(
        "Setup Window Closed",
        r#"<p class="lede">This relay has stopped showing its claim code, so that an old setup link cannot be used.</p>
<p>The code is shown for a limited time after the relay starts: one hour by default. The server is still unclaimed, and there are two ways to claim it:</p>
<ul>
<li>Restart the relay. It prints a new setup link and shows the code again for the same time.</li>
<li>Enter the code by hand in the StealthOS app. The code is in the relay's startup console. If its output goes to a log instead, run <code>stealth-relay claim-code</code> on the server.</li>
</ul>"#,
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

    /// Every page in its every form, for the checks that apply to all of them.
    fn all_pages() -> Vec<String> {
        vec![
            render_setup_page(&[0xab; 32]),
            unclaimed_root_page(),
            claimed_page("0.0.0-test"),
            forbidden_page(),
            locked_out_page(),
            expired_page(),
        ]
    }

    /// ASCII only rules out em and en dashes and emoji in one check; the
    /// entity forms have to be ruled out by name.
    #[test]
    fn pages_have_no_dashes_or_emoji() {
        for html in all_pages() {
            assert!(html.is_ascii(), "non-ASCII text in a page");
            for entity in ["&mdash;", "&ndash;", "&#x1F", "&#x23", "&#x27"] {
                assert!(!html.contains(entity), "{entity} in a page");
            }
        }
    }

    /// The CSP allows no outside fonts, images or stylesheets, so the pages
    /// must not depend on any.
    #[test]
    fn pages_load_nothing_from_outside() {
        for html in all_pages() {
            for reference in ["<link", "<img", "@import", "@font-face", "url(", "src="] {
                assert!(!html.contains(reference), "{reference} in a page");
            }
        }
    }

    /// The claim page script and markup have to agree on what the code is,
    /// and the poll has to keep hitting the status route.
    #[test]
    fn claim_page_keeps_code_and_poll() {
        let html = render_setup_page(&[0xab; 32]);
        assert!(html.contains(&format!("var claimCode = '{}'", "ab".repeat(32))));
        assert!(html.contains("fetch('/setup/status'"));
        assert!(!html.contains("{{"));
        for id in [
            "claim-code",
            "copy-btn",
            "rk-display",
            "rk-copy",
            "rk-continue",
        ] {
            assert!(html.contains(&format!("id=\"{id}\"")), "missing {id}");
        }
    }

    #[test]
    fn claimed_page_shows_version_and_no_claim_material() {
        let html = claimed_page("1.2.3");
        assert!(html.contains(">1.2.3<"));
        assert!(!html.contains("{{"));
        assert!(!html.contains("claim-code\""));
    }

    #[test]
    fn locked_out_page_states_the_real_limits() {
        let html = locked_out_page();
        assert!(html.contains(&format!("{MAX_TOKEN_ATTEMPTS} wrong setup tokens")));
        assert!(html.contains(&format!("{} minutes", TOKEN_LOCKOUT.as_secs() / 60)));
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
