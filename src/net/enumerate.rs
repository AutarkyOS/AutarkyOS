//! HTTP path enumeration: the T2 recon tier.
//!
//! The fingerprint module says *what* is running. This one asks *what has it
//! left exposed* -- paths that a web server freely serves and that reveal
//! configuration, tooling, or attack surface a human with a browser and a list
//! would find in the same amount of time.
//!
//! Each path in the table is one TCP connection: connect, send a GET, read the
//! response, close. That is the only shape the single-TCB stack supports, and
//! it is the shape that matters -- a pipelined bulk fetch over one connection
//! would be faster and would be a different tool. The table is short on
//! purpose: a hundred paths at 600 ms each is a minute per host, and one step
//! of the arena cannot spend that.
//!
//! ### What it records
//!
//! Each exposure is stored under the recon index as a sibling of the port
//! entry, so the oracle's service count rises by one per finding without
//! anything in the oracle having to change. The path is
//! `/ai/recon/<ip>/<port>-<path-slug>`, where the slug is the path with
//! slashes replaced by underscores.
//!
//! ### What it does not do
//!
//! No credential is submitted, no payload is crafted, no form is filled. A
//! GET to a path the server freely answers is reconnaissance in the exact same
//! sense a banner grab is.

use super::Ipv4;
use super::recon;
use alloc::string::String;
use alloc::vec::Vec;

/// One path in the enumeration table.
struct PathEntry {
    path: &'static str,
    kind: ExposureKind,
}

/// What finding the path represents.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExposureKind {
    Config,
    SourceControl,
    AdminPanel,
    ServerInfo,
    ApiDoc,
    SecurityPolicy,
}

impl ExposureKind {
    pub fn tag(self) -> &'static str {
        match self {
            ExposureKind::Config => "config",
            ExposureKind::SourceControl => "scm",
            ExposureKind::AdminPanel => "admin",
            ExposureKind::ServerInfo => "serverinfo",
            ExposureKind::ApiDoc => "apidoc",
            ExposureKind::SecurityPolicy => "security",
        }
    }
}

/// What one path enumeration found.
#[derive(Clone)]
pub struct Exposure {
    pub path: &'static str,
    pub kind: ExposureKind,
    pub status: u16,
    pub interesting_headers: Vec<(String, String)>,
    pub body_preview: String,
}

impl Exposure {
    pub fn render(&self) -> String {
        let mut s = String::from(self.kind.tag());
        s.push(' ');
        s.push_str(self.path);
        s.push_str(" [");
        push_u16(&mut s, self.status);
        s.push(']');
        for (k, v) in &self.interesting_headers {
            s.push(' ');
            s.push_str(k);
            s.push(':');
            s.push_str(v);
        }
        if !self.body_preview.is_empty() {
            s.push(' ');
            s.push_str(&self.body_preview);
        }
        s
    }
}

fn push_u16(s: &mut String, v: u16) {
    recon::push_u16(s, v);
}

/// The paths to probe. Small on purpose: each is a TCP connection, and the
/// arena step has a budget.
const HTTP_PATHS: &[PathEntry] = &[
    PathEntry { path: "/robots.txt", kind: ExposureKind::Config },
    PathEntry { path: "/.env", kind: ExposureKind::Config },
    PathEntry { path: "/.git/HEAD", kind: ExposureKind::SourceControl },
    PathEntry { path: "/server-status", kind: ExposureKind::ServerInfo },
    PathEntry { path: "/server-info", kind: ExposureKind::ServerInfo },
    PathEntry { path: "/.well-known/security.txt", kind: ExposureKind::SecurityPolicy },
    PathEntry { path: "/wp-login.php", kind: ExposureKind::AdminPanel },
    PathEntry { path: "/admin", kind: ExposureKind::AdminPanel },
    PathEntry { path: "/swagger.json", kind: ExposureKind::ApiDoc },
    PathEntry { path: "/api", kind: ExposureKind::ApiDoc },
    PathEntry { path: "/phpinfo.php", kind: ExposureKind::ServerInfo },
    PathEntry { path: "/sitemap.xml", kind: ExposureKind::Config },
];

/// Headers that leak server internals. Checked case-insensitively.
const INTERESTING_HEADERS: &[&str] = &[
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "server",
    "x-runtime",
    "x-debug",
    "x-request-id",
];

/// The most interesting headers recorded from one response. A hostile server
/// can send an unbounded stream of them, and this kernel's heap is bounded and
/// unswappable; a handful is all a "leaked internals" finding ever needs, and
/// bounding the count bounds the stored exposure record.
const MAX_HEADERS: usize = 16;

/// The most characters kept from one header value. Attacker-controlled, so it
/// is clipped -- and clipped by *characters*, never `&val[..80]`, which panics
/// (a halt, in a kernel with no fault recovery) when byte 80 lands inside a
/// multibyte UTF-8 sequence. Columns, not bytes: the tree's standing rule.
const HEADER_VALUE_CHARS: usize = 80;

/// Whether the response indicates something worth recording. A 200 on most
/// paths is interesting; a 200 on /robots.txt is interesting only if the body
/// contains Disallow (every server can serve an empty one). 404 and 403 are
/// the normal "nothing here" answers.
fn is_interesting(path: &str, status: u16, body: &[u8]) -> bool {
    if status == 404 || status == 403 || status == 0 {
        return false;
    }
    if path == "/robots.txt" && status == 200 {
        return body.windows(8).any(|w| w.eq_ignore_ascii_case(b"disallow"));
    }
    if path == "/.git/HEAD" && status == 200 {
        return body.starts_with(b"ref: ");
    }
    status == 200 || status == 301 || status == 302 || status == 401
}

/// Parse the status code from the first line of an HTTP response.
/// Returns 0 if unparseable.
fn parse_status(response: &[u8]) -> u16 {
    // "HTTP/1.x NNN ..."
    let line_end = response.iter().position(|&b| b == b'\n').unwrap_or(response.len());
    let first_line = &response[..line_end];
    let mut parts = first_line.split(|&b| b == b' ');
    parts.next(); // HTTP/1.x
    if let Some(code) = parts.next() {
        if code.len() >= 3 {
            let h = (code[0] as u16).wrapping_sub(b'0' as u16);
            let t = (code[1] as u16).wrapping_sub(b'0' as u16);
            let u = (code[2] as u16).wrapping_sub(b'0' as u16);
            if h < 10 && t < 10 && u < 10 {
                return h * 100 + t * 10 + u;
            }
        }
    }
    0
}

/// Extract interesting header values from a raw HTTP response.
fn extract_headers(response: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(response.len().min(4096));
    let headers = &response[..header_end];

    for line in headers.split(|&b| b == b'\n') {
        // A hostile server can send headers without limit; a bounded heap cannot
        // absorb them, so stop after a handful. Checked before matching so the
        // loop over a flood terminates cheaply.
        if out.len() >= MAX_HEADERS {
            break;
        }
        let line = if line.last() == Some(&b'\r') { &line[..line.len() - 1] } else { line };
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = &line[..colon];
            let value = &line[colon + 1..];
            let name_lower = ascii_lower(name);
            for &interesting in INTERESTING_HEADERS {
                if name_lower == interesting {
                    let val = core::str::from_utf8(value)
                        .unwrap_or("")
                        .trim();
                    if !val.is_empty() {
                        // Clip by characters, never `&val[..n]`: the value is
                        // attacker-controlled UTF-8 and a byte cut inside a
                        // multibyte char panics the kernel.
                        let clipped: String = val.chars().take(HEADER_VALUE_CHARS).collect();
                        out.push((String::from(interesting), clipped));
                    }
                }
            }
        }
    }
    out
}

fn ascii_lower(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        s.push(if b.is_ascii_uppercase() { (b + 32) as char } else { b as char });
    }
    s
}

/// A short preview of the body, for recording.
fn body_preview(response: &[u8], max: usize) -> String {
    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(response.len());
    let body = &response[body_start..];
    let mut s = String::new();
    for &c in body.iter().take(max) {
        if (0x20..0x7f).contains(&c) {
            s.push(c as char);
        } else if c == b'\n' || c == b'\r' || c == b'\t' {
            s.push(' ');
        }
    }
    s
}

/// Enumerate HTTP paths on one host/port. Each path is a fresh TCP connection
/// (the single-TCB constraint). Returns the exposures found.
pub fn enumerate_http(host: Ipv4, port: u16, per_path_ms: u64) -> Vec<Exposure> {
    let host_str = recon::ip_dotted(host);
    let mut out = Vec::new();
    for entry in HTTP_PATHS {
        let resp = match super::tcp::http_get(host, &host_str, port, entry.path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = parse_status(&resp);
        if !is_interesting(entry.path, status, &resp) {
            continue;
        }
        let headers = extract_headers(&resp);
        let preview = body_preview(&resp, 120);
        out.push(Exposure {
            path: entry.path,
            kind: entry.kind,
            status,
            interesting_headers: headers,
            body_preview: preview,
        });
        let _ = per_path_ms;
    }
    out
}

/// Store one exposure in the recon index. The path is
/// `/ai/recon/<ip>/<port>-<slug>`, a sibling of the port entry so the oracle
/// counts it automatically.
pub fn record_exposure(ip: Ipv4, port: u16, exp: &Exposure) {
    let mut path = String::from(recon::ROOT);
    path.push('/');
    path.push_str(&recon::ip_seg(ip));
    path.push('/');
    recon::push_u16(&mut path, port);
    path.push('-');
    path.push_str(&slug(exp.path));

    crate::sysbox::write_text(&path, &exp.render());
}

/// Turn a URL path into a single path segment: drop the leading `/`, replace
/// the rest with underscores.
fn slug(path: &str) -> String {
    let p = if path.starts_with('/') { &path[1..] } else { path };
    let mut s = String::new();
    for c in p.chars() {
        if c == '/' || c == '.' {
            s.push('_');
        } else if c.is_ascii_alphanumeric() || c == '-' {
            s.push(c);
        }
    }
    if s.is_empty() {
        s.push_str("index");
    }
    s
}

// --- selftest ---------------------------------------------------------------

pub fn selftest() -> bool {
    let mut ok = true;
    let mut claim = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   enumerate {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    // Status parsing.
    claim(parse_status(b"HTTP/1.1 200 OK\r\n") == 200, "parse 200");
    claim(parse_status(b"HTTP/1.0 404 Not Found\r\n") == 404, "parse 404");
    claim(parse_status(b"HTTP/1.1 301 Moved\r\n") == 301, "parse 301");
    claim(parse_status(b"garbage") == 0, "garbage yields 0");
    claim(parse_status(b"") == 0, "empty yields 0");

    // Interesting-path logic.
    claim(
        !is_interesting("/robots.txt", 200, b"User-agent: *\nAllow: /"),
        "robots.txt without Disallow is not interesting",
    );
    claim(
        is_interesting("/robots.txt", 200, b"User-agent: *\nDisallow: /admin"),
        "robots.txt with Disallow is interesting",
    );
    claim(
        is_interesting("/.git/HEAD", 200, b"ref: refs/heads/main\n"),
        ".git/HEAD with ref: is interesting",
    );
    claim(
        !is_interesting("/.git/HEAD", 200, b"<!DOCTYPE html>"),
        ".git/HEAD serving HTML is not interesting",
    );
    claim(is_interesting("/.env", 200, b"DB_HOST=..."), ".env 200 is interesting");
    claim(!is_interesting("/.env", 404, b""), ".env 404 is not interesting");
    claim(!is_interesting("/.env", 403, b""), ".env 403 is not interesting");
    claim(is_interesting("/admin", 401, b""), "admin 401 is interesting (auth required)");

    // Header extraction.
    let resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/7.4\r\n\r\nbody";
    let hdrs = extract_headers(resp);
    claim(hdrs.len() == 2, "two interesting headers extracted");
    claim(
        hdrs.iter().any(|(k, v)| k == "server" && v.contains("nginx")),
        "server header found",
    );
    claim(
        hdrs.iter().any(|(k, v)| k == "x-powered-by" && v.contains("PHP")),
        "x-powered-by found",
    );

    // No interesting headers.
    let resp2 = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>";
    let hdrs2 = extract_headers(resp2);
    claim(hdrs2.is_empty(), "no interesting headers in plain response");

    // A hostile header value with a multibyte UTF-8 char straddling the clip
    // boundary must not panic (a halt, here) and must clip on a char boundary.
    // 'é' is two bytes; placed as char 80 it spans bytes 79-80, so the old
    // `&val[..80]` cut through it. Reaching this claim at boot *is* the proof.
    let mut long: Vec<u8> = Vec::new();
    long.extend_from_slice(b"HTTP/1.1 200 OK\r\nServer: ");
    for _ in 0..(HEADER_VALUE_CHARS - 1) {
        long.push(b'a');
    }
    long.extend_from_slice("\u{00e9}xtra".as_bytes());
    long.extend_from_slice(b"\r\n\r\n");
    let hl = extract_headers(&long);
    claim(hl.len() == 1, "a boundary-straddling header extracts without a panic");
    claim(
        hl[0].1.chars().count() == HEADER_VALUE_CHARS,
        "the value is clipped to the char budget, on a char boundary",
    );

    // A flood of interesting headers is capped, so a hostile server cannot grow
    // the record without bound.
    let mut many: Vec<u8> = Vec::new();
    many.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    for _ in 0..64 {
        many.extend_from_slice(b"X-Powered-By: x\r\n");
    }
    many.extend_from_slice(b"\r\n");
    let hm = extract_headers(&many);
    claim(hm.len() <= MAX_HEADERS, "interesting headers capped against a flood");

    // Slug generation.
    claim(slug("/robots.txt") == "robots_txt", "robots.txt slug");
    claim(slug("/.git/HEAD") == "_git_HEAD", ".git/HEAD slug");
    claim(slug("/.well-known/security.txt") == "_well-known_security_txt", "nested slug");
    claim(slug("/admin") == "admin", "plain path slug");
    claim(slug("/") == "index", "root path slug");

    // Body preview.
    let resp3 = b"HTTP/1.1 200 OK\r\n\r\nHello World!\x00\xff";
    let preview = body_preview(resp3, 50);
    claim(preview == "Hello World!", "body preview extracts printable text");

    // Exposure render round-trip.
    let exp = Exposure {
        path: "/.env",
        kind: ExposureKind::Config,
        status: 200,
        interesting_headers: alloc::vec![(String::from("server"), String::from("nginx"))],
        body_preview: String::from("DB_HOST=localhost"),
    };
    let rendered = exp.render();
    claim(rendered.contains("config"), "render contains kind");
    claim(rendered.contains("/.env"), "render contains path");
    claim(rendered.contains("[200]"), "render contains status");
    claim(rendered.contains("server:nginx"), "render contains header");
    claim(rendered.contains("DB_HOST"), "render contains body preview");

    ok
}
