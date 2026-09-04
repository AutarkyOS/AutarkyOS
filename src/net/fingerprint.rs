//! What a service is, read from what it says when you connect to it.
//!
//! This is the half of a Shodan that is worth having and the half nobody
//! writes down. Shodan's crawler is four lines -- pick an address, pick a port,
//! connect, grab the banner -- and its documentation says exactly that and no
//! more. The value is not in the scan. It is in turning `220 (vsFTPd 3.0.3)`
//! into "vsFTPd, version 3.0.3", and in doing it by what the service *said*
//! rather than by which port answered, so a service hiding on the wrong port is
//! still named. That last property is the one Shodan calls out by name (SSH on
//! port 80 is still SSH), and it is the reason this function takes the port
//! only as a hint and decides on the banner.
//!
//! ### Why it is pure, and separate from the scanner
//!
//! `recon` drives the network: it sweeps the subnet, opens sockets, reads
//! bytes. None of that can be checked without hardware and a second host to
//! answer. `identify` is a total function from bytes to a name, so every claim
//! it makes is checkable at boot against a banner captured from real software,
//! with no network in the room. The split is the same one `update` draws
//! between `hook` (drives firmware) and `decide` (pure, all states asserted):
//! put the judgement where it can be tested and keep the I/O thin around it.
//!
//! ### What it is deliberately not
//!
//! It is not a vulnerability scanner. It reports what is running, never whether
//! what is running has a hole, because a version-to-CVE table goes stale the
//! day it ships and a kernel with no clock to the outside world cannot refresh
//! one. Naming the software is a fact the machine can stand behind; claiming
//! the software is vulnerable is a fact with an expiry date, and this tree does
//! not publish figures it cannot keep true.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What was found listening, named as far as the banner allows.
///
/// Every field degrades rather than lies. An unknown service still carries its
/// raw banner, an unversioned product still carries its name, and a bare open
/// port with no banner is still a `Fingerprint` with `proto: "unknown"` -- the
/// honest report is "something answered here and said nothing", which is itself
/// a fact worth indexing.
#[derive(Clone)]
pub struct Fingerprint {
    /// The protocol, decided by content: "ssh", "http", "ftp", "smtp", "pop3",
    /// "imap", "redis", "mysql", "telnet", "rtsp", or "unknown".
    pub proto: &'static str,
    /// The software, when the banner names it ("OpenSSH", "nginx"), else empty.
    pub product: String,
    /// The version token, when one sits where the product's format puts it.
    pub version: String,
    /// Whatever else the banner carried, trimmed -- the OS tag on an SSH line,
    /// the parenthetical on a Server header. Kept because it is often the most
    /// identifying part and never fits a column.
    pub extra: String,
}

impl Fingerprint {
    fn bare(proto: &'static str) -> Self {
        Fingerprint {
            proto,
            product: String::new(),
            version: String::new(),
            extra: String::new(),
        }
    }

    /// One line, for the index and the operator: `ssh OpenSSH 8.9p1`.
    pub fn render(&self) -> String {
        let mut s = String::from(self.proto);
        if !self.product.is_empty() {
            s.push(' ');
            s.push_str(&self.product);
        }
        if !self.version.is_empty() {
            s.push(' ');
            s.push_str(&self.version);
        }
        s
    }
}

/// How to make a service talk.
///
/// Two kinds, because services split two ways on first contact. Some announce
/// themselves the instant the connection opens -- SSH, FTP, SMTP, POP3, IMAP
/// all send a greeting -- and for those the grab is a read. Some say nothing
/// until asked, and the web is the whole of that category worth scanning, so
/// the ask is one HTTP request. A third arm covers ports that answer only to a
/// specific poke; `Redis` is the one carried here because its `PING` is a
/// single line and its refusal (`-NOAUTH`) is as identifying as its `+PONG`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Connect and read; the service greets first.
    ReadFirst,
    /// Send a minimal HTTP/1.0 request with the host in the `Host` header,
    /// exactly as Shodan does so a name-based vhost still answers.
    Http,
    /// Send a bare `PING\r\n`; Redis and a few others reply on the wire.
    RedisPing,
}

/// The ports worth trying, and what each expects on contact.
///
/// Shodan scans "the list of ports Shodan understands", which is thousands.
/// This is the local analogue and is deliberately short: a subnet sweep is
/// hosts times ports times a timeout, and on a home or lab `/24` the product of
/// 254 hosts and a two-dozen-port list at a one-second timeout is already
/// minutes. The list is the services a person actually runs and would want
/// found on their own network, ordered roughly by how often they turn up.
///
/// The port here is a *hint* to pick the probe, never the identification --
/// `identify` decides that from the banner, so a service on the wrong port is
/// still probed as HTTP if it sits on an HTTP port and still *named* correctly
/// whatever the probe elicited.
pub const PORTS: &[(u16, Probe)] = &[
    (80, Probe::Http),
    (443, Probe::Http),
    (8080, Probe::Http),
    (8443, Probe::Http),
    (8000, Probe::Http),
    (22, Probe::ReadFirst),
    (21, Probe::ReadFirst),
    (25, Probe::ReadFirst),
    (587, Probe::ReadFirst),
    (110, Probe::ReadFirst),
    (143, Probe::ReadFirst),
    (23, Probe::ReadFirst),
    (554, Probe::ReadFirst),
    (3306, Probe::ReadFirst),
    (6379, Probe::RedisPing),
];

/// The bytes a probe sends, given the host it is aimed at (for the `Host`
/// header). `ReadFirst` sends nothing.
pub fn probe_bytes(probe: Probe, host: &str) -> Vec<u8> {
    match probe {
        Probe::ReadFirst => Vec::new(),
        Probe::RedisPing => b"PING\r\n".to_vec(),
        Probe::Http => {
            // HTTP/1.0 so the server closes the connection itself and the read
            // ends without a content-length dance; `Host` set because a
            // name-based vhost returns a default or an error without it, and
            // the default is exactly the banner worth having.
            let mut s = String::from("GET / HTTP/1.0\r\nHost: ");
            s.push_str(host);
            s.push_str("\r\nUser-Agent: autark-recon\r\n\r\n");
            s.into_bytes()
        }
    }
}

/// The whole identification, from the port that answered and the bytes it sent.
///
/// Content decides. The port only breaks ties the banner cannot -- a truly
/// silent port on 3306 is more likely MySQL than nothing, and saying so is
/// better than "unknown" when the byte pattern agrees. Every branch that claims
/// a protocol does so because the banner carries that protocol's signature, so
/// the SSH-on-80 case and its like all resolve correctly.
pub fn identify(port: u16, banner: &[u8]) -> Fingerprint {
    let text = ascii(banner);
    let t = text.as_str();

    // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1". The wire format is
    // SSH-<protoversion>-<software> <comment>, so the software sits between the
    // second dash and the first space, and the version follows an underscore.
    if let Some(rest) = t.strip_prefix("SSH-") {
        let mut fp = Fingerprint::bare("ssh");
        // Skip the protocol version ("2.0") to the software field.
        if let Some(dash) = rest.find('-') {
            let soft = rest[dash + 1..].trim_end();
            let (before_space, after_space) = split_at_space(soft);
            // "OpenSSH_8.9p1" -> product OpenSSH, version 8.9p1.
            if let Some(us) = before_space.find('_') {
                fp.product = before_space[..us].to_string();
                fp.version = before_space[us + 1..].to_string();
            } else {
                fp.product = before_space.to_string();
            }
            fp.extra = after_space.trim().to_string();
        }
        return fp;
    }

    // HTTP: either a status line or, on a proxy, a Server header without one.
    if t.starts_with("HTTP/") || contains_ci(t, "\nserver:") || starts_ci(t, "server:") {
        let mut fp = Fingerprint::bare("http");
        if let Some(v) = header_value(t, "server") {
            // "nginx/1.18.0 (Ubuntu)" -> product nginx, version 1.18.0, extra
            // "(Ubuntu)". The slash is the product/version divide in every
            // server token that carries a version.
            let v = v.trim();
            if let Some(slash) = v.find('/') {
                fp.product = v[..slash].to_string();
                let tail = &v[slash + 1..];
                let (ver, extra) = split_at_space(tail);
                fp.version = ver.to_string();
                fp.extra = extra.trim().to_string();
            } else {
                fp.product = v.to_string();
            }
        }
        return fp;
    }

    // FTP: "220 (vsFTPd 3.0.3)" or "220 ProFTPD 1.3.5 Server". The 220 is the
    // greeting code; the product is the first word that is not the code and not
    // a bare hostname, which in practice is the token carrying a version.
    if t.starts_with("220") && (contains_ci(t, "ftp") || port == 21) {
        let mut fp = Fingerprint::bare("ftp");
        name_and_version_near(t, &["vsFTPd", "ProFTPD", "FileZilla", "Pure-FTPd"], &mut fp);
        return fp;
    }

    // SMTP: "220 mail.example.com ESMTP Postfix". ESMTP/SMTP is the marker;
    // the MTA name follows it on every common server.
    if t.starts_with("220") && (contains_ci(t, "smtp") || port == 25 || port == 587) {
        let mut fp = Fingerprint::bare("smtp");
        name_and_version_near(t, &["Postfix", "Exim", "Sendmail", "Microsoft", "OpenSMTPD"], &mut fp);
        return fp;
    }

    // POP3 / IMAP: "+OK Dovecot ready" / "* OK ... IMAP".
    if t.starts_with("+OK") {
        let mut fp = Fingerprint::bare("pop3");
        name_and_version_near(t, &["Dovecot", "Courier"], &mut fp);
        return fp;
    }
    if t.starts_with("* OK") || contains_ci(t, "imap") {
        let mut fp = Fingerprint::bare("imap");
        name_and_version_near(t, &["Dovecot", "Courier", "Cyrus"], &mut fp);
        return fp;
    }

    // Redis: "+PONG" to our PING, or "-NOAUTH Authentication required." when it
    // is protected -- the refusal identifies it as surely as the reply.
    if t.starts_with("+PONG") || contains_ci(t, "-NOAUTH") || contains_ci(t, "redis_version") {
        let mut fp = Fingerprint::bare("redis");
        if let Some(v) = after_ci(t, "redis_version:") {
            fp.version = first_token(v).to_string();
        }
        fp.product = "Redis".to_string();
        return fp;
    }

    // MySQL: the handshake is binary and length-prefixed, but the version is a
    // NUL-terminated ASCII string a few bytes in, and the auth plugin name is a
    // reliable literal. Match the literal, pull the version run.
    if contains_ci(t, "mysql_native_password") || contains_ci(t, "mariadb") || (port == 3306 && banner.len() > 5) {
        let mut fp = Fingerprint::bare("mysql");
        if contains_ci(t, "mariadb") {
            fp.product = "MariaDB".to_string();
        } else {
            fp.product = "MySQL".to_string();
        }
        // The version sits after the initial protocol byte; the first version
        // token in the ASCII view is it.
        if let Some(v) = first_version_token(t) {
            fp.version = v;
        }
        return fp;
    }

    // Telnet announces itself with IAC command bytes (0xFF) rather than text.
    if banner.first() == Some(&0xFF) || port == 23 {
        return Fingerprint::bare("telnet");
    }

    // RTSP for cameras and streamers: "RTSP/1.0 200 OK".
    if t.starts_with("RTSP/") {
        let mut fp = Fingerprint::bare("rtsp");
        if let Some(v) = header_value(t, "server") {
            fp.product = first_token(v.trim()).to_string();
        }
        return fp;
    }

    // Nothing matched. If a banner came at all, it is worth keeping raw; if not,
    // an open port that said nothing is still a finding.
    let mut fp = Fingerprint::bare("unknown");
    fp.extra = one_line(t);
    fp
}

// --- pure helpers, each doing one thing the branches above lean on ----------

/// Bytes to a lossy ASCII string, control characters (bar tab/newline) dropped,
/// so a binary handshake still yields the printable runs a signature matches.
fn ascii(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b.iter().take(512) {
        if c == b'\n' || c == b'\t' || (0x20..0x7f).contains(&c) {
            s.push(c as char);
        } else {
            // A separator so "5.7.33\0mysql_native_password" does not fuse into
            // one token the version extractor would swallow whole.
            s.push(' ');
        }
    }
    s
}

fn split_at_space(s: &str) -> (&str, &str) {
    match s.find(' ') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

fn first_token(s: &str) -> &str {
    s.trim().split(|c: char| c.is_whitespace()).next().unwrap_or("")
}

fn one_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

fn contains_ci(hay: &str, needle_lower: &str) -> bool {
    find_ci(hay, needle_lower).is_some()
}

fn starts_ci(hay: &str, needle_lower: &str) -> bool {
    hay.len() >= needle_lower.len()
        && hay[..needle_lower.len()].eq_ignore_ascii_case(needle_lower)
}

/// Case-insensitive substring search, folding both sides.
///
/// An earlier version required the needle to arrive lower-cased and folded only
/// the haystack, on the theory that the caller could cheaply guarantee it. The
/// host harness caught the inevitable: one literal (`"-NOAUTH"`) slipped through
/// upper-case and silently never matched, so Redis's own refusal did not
/// identify Redis. The saving was a micro-optimisation on a 512-byte buffer and
/// the cost was a signature that looked present and was dead, so the contract is
/// gone -- both sides fold here and a needle in any case works.
fn find_ci(hay: &str, needle: &str) -> Option<usize> {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    for i in 0..=h.len() - n.len() {
        if h[i..i + n.len()]
            .iter()
            .zip(n)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(i);
        }
    }
    None
}

fn after_ci<'a>(hay: &'a str, needle_lower: &str) -> Option<&'a str> {
    find_ci(hay, needle_lower).map(|i| &hay[i + needle_lower.len()..])
}

/// The value of an HTTP-style header, case-insensitive on the name, trimmed of
/// the trailing CR. Returns the rest of that line only.
fn header_value<'a>(hay: &'a str, name_lower: &str) -> Option<&'a str> {
    // Match at line start: either the very beginning or just after a newline,
    // so a header name appearing inside another header's value is not taken.
    let mut search_from = 0;
    loop {
        let i = find_ci(&hay[search_from..], name_lower)? + search_from;
        let at_line_start = i == 0 || hay.as_bytes()[i - 1] == b'\n';
        let after = &hay[i + name_lower.len()..];
        if at_line_start {
            if let Some(colon) = after.strip_prefix(':') {
                let line = colon.split('\n').next().unwrap_or("");
                return Some(line.trim_end_matches('\r'));
            }
        }
        search_from = i + name_lower.len();
        if search_from >= hay.len() {
            return None;
        }
    }
}

/// The first token that looks like a version: a run beginning with a digit and
/// continuing through digits, dots and trailing alphanumerics (so `8.9p1` and
/// `3.0.3` and `1.18.0` all survive whole), stopping at space or a bracket.
fn first_version_token(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric() || b[i] == b'.' )
            {
                i += 1;
            }
            let tok = &s[start..i];
            // A version has at least one dot, else a bare "220" code or a "200"
            // status would read as a version.
            if tok.contains('.') {
                return Some(tok.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Find any of `names` in the banner (case-insensitive) and, when found, set the
/// product to the name as spelled here and the version to the first version
/// token after it. Used by the greeting-based protocols, whose product name is
/// a known literal and whose version, if present, follows it.
fn name_and_version_near(hay: &str, names: &[&str], fp: &mut Fingerprint) {
    for name in names {
        if let Some(rest) = after_ci(hay, &name.to_ascii_lowercase()) {
            fp.product = name.to_string();
            if let Some(v) = first_version_token(rest) {
                fp.version = v;
            }
            return;
        }
    }
}

/// Every claim above, against a banner captured from the real software. A
/// fingerprinter is only as good as the strings it has seen, so the strings
/// here are verbatim from live services rather than invented to pass.
pub fn selftest() -> bool {
    let mut ok = true;
    let mut check = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   fingerprint  {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    let ssh = identify(22, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n");
    check(ssh.proto == "ssh", "ssh proto");
    check(ssh.product == "OpenSSH", "ssh product");
    check(ssh.version == "8.9p1", "ssh version keeps its letter suffix");
    check(ssh.extra.starts_with("Ubuntu"), "ssh comment kept as extra");

    // The property Shodan names: content decides, not the port.
    let ssh80 = identify(80, b"SSH-2.0-OpenSSH_9.6\r\n");
    check(ssh80.proto == "ssh", "ssh on port 80 is still ssh");
    check(ssh80.version == "9.6", "ssh version with no suffix");

    let http = identify(80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n<html>");
    check(http.proto == "http", "http proto");
    check(http.product == "nginx", "http product from Server header");
    check(http.version == "1.18.0", "http version from Server header");
    check(http.extra == "(Ubuntu)", "http Server parenthetical kept");

    // A Server header with no version.
    let h2 = identify(8080, b"HTTP/1.0 404 Not Found\r\nServer: Caddy\r\n\r\n");
    check(h2.product == "Caddy", "http product without a version");
    check(h2.version.is_empty(), "no version claimed when none given");

    // A header name inside a value must not be mistaken for the header.
    let h3 = identify(80, b"HTTP/1.1 200 OK\r\nX-Note: server: fake\r\nServer: Apache/2.4.52\r\n\r\n");
    check(h3.product == "Apache", "real Server header, not the decoy in X-Note");
    check(h3.version == "2.4.52", "apache version");

    let ftp = identify(21, b"220 (vsFTPd 3.0.3)\r\n");
    check(ftp.proto == "ftp", "ftp proto");
    check(ftp.product == "vsFTPd", "ftp product");
    check(ftp.version == "3.0.3", "ftp version");

    let smtp = identify(25, b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n");
    check(smtp.proto == "smtp", "smtp proto");
    check(smtp.product == "Postfix", "smtp product");

    let pop = identify(110, b"+OK Dovecot (Ubuntu) ready.\r\n");
    check(pop.proto == "pop3" && pop.product == "Dovecot", "pop3 Dovecot");

    let redis = identify(6379, b"-NOAUTH Authentication required.\r\n");
    check(redis.proto == "redis", "redis identified by its refusal");

    let redis2 = identify(6379, b"$1234\r\nredis_version:7.0.11\r\n");
    check(redis2.version == "7.0.11", "redis version from INFO-style reply");

    // MySQL handshake: binary, version is ASCII after the first bytes, auth
    // plugin literal near the end. \n stands in for the NULs here.
    let mysql = identify(3306, b"\x4a\x00\x00\x00\x0a5.7.33-log\x00mysql_native_password\x00");
    check(mysql.proto == "mysql", "mysql from handshake");
    check(mysql.version == "5.7.33", "mysql version before the NUL");

    let telnet = identify(23, &[0xFF, 0xFD, 0x18]);
    check(telnet.proto == "telnet", "telnet from IAC bytes");

    // A silent open port is a finding, not an error.
    let silent = identify(9999, b"");
    check(silent.proto == "unknown", "silent port is unknown, not a panic");
    check(silent.version.is_empty(), "nothing invented for a silent port");

    // A status code is not a version.
    check(first_version_token("220 ProFTPD").is_none(), "bare 220 is not a version");
    check(first_version_token("nginx/1.18.0").as_deref() == Some("1.18.0"), "version needs a dot");

    ok
}
