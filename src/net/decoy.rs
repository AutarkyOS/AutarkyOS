//! The other side of the mirror: a service that is not there, described so
//! convincingly that the machine's own recon engine calls it real.
//!
//! `fingerprint::identify` turns a banner into a service name. This turns a
//! service name into a banner, and the two are held to a single standard that
//! makes the deception provable rather than hoped for:
//!
//!   **for every decoy this module emits, `identify` must classify it as the
//!   service it was asked to impersonate.**
//!
//! That round-trip is a boot assertion, so "indistinguishable from deception"
//! is not a claim about how a banner looks to a person -- it is a fact about
//! the one classifier this system trusts. A decoy that the recon engine would
//! see through is a bug here, caught before it is ever served.
//!
//! ### Why this is the honest half of an offensive posture
//!
//! Nothing in this file reaches off the machine. It manufactures the *self*
//! -description a listener would emit when something connects to it -- the
//! camouflage, not a weapon. The cost imposed on an attacker is that every one
//! of these is a real-looking service that leads nowhere, so reconnaissance
//! against a fleet of them is reconnaissance spent on ghosts. The line this
//! module stays behind is the one the whole subsystem stays behind: deception
//! and time-wasting happen here, on our own turf, and nothing here attacks
//! anyone.
//!
//! ### Diversity is the point, so the seed is load-bearing
//!
//! One decoy is a honeypot; a hundred *different* decoys are camouflage. The
//! seed selects among real product/version pairs deterministically, so a fleet
//! reads as a heterogeneous network of ordinary machines rather than a hundred
//! copies of one trap -- and deterministically, so which decoy sits at a given
//! address is re-derivable the way everything else in this tree is, from a seed
//! rather than a coin.

use alloc::string::String;
use alloc::vec::Vec;

/// The services this module can impersonate. These are exactly the protocols
/// `fingerprint::identify` can name, because a decoy is only worth emitting if
/// the classifier would believe it, and the round-trip selftest enforces that
/// the two lists stay in step.
pub const KINDS: &[&str] = &[
    "ssh", "http", "ftp", "smtp", "pop3", "imap", "redis", "mysql", "telnet", "rtsp",
];

/// The canonical port a service sits on, for callers that place a decoy where
/// the real thing would live. `identify` decides on content, so this only
/// affects where a listener would bind, never whether the banner convinces.
pub fn port_of(proto: &str) -> u16 {
    match proto {
        "ssh" => 22,
        "http" => 80,
        "ftp" => 21,
        "smtp" => 25,
        "pop3" => 110,
        "imap" => 143,
        "redis" => 6379,
        "mysql" => 3306,
        "telnet" => 23,
        "rtsp" => 554,
        _ => 0,
    }
}

/// One realistic identity: the product, its version, and whatever trailing
/// detail the real banner carries (an OS tag, a distribution suffix). Empty
/// fields are omitted from the banner rather than rendered blank, because a
/// real `Server:` line does not carry a bare trailing slash.
struct Identity {
    product: &'static str,
    version: &'static str,
    extra: &'static str,
}

/// The pools a decoy draws from, per protocol. Real software at real version
/// strings -- an attacker cross-referencing a banner against a CVE feed should
/// find a coherent story, not a version that never shipped.
fn pool(proto: &str) -> &'static [Identity] {
    match proto {
        "ssh" => &[
            Identity { product: "OpenSSH", version: "9.6p1", extra: "Ubuntu-3ubuntu0.1" },
            Identity { product: "OpenSSH", version: "8.9p1", extra: "Ubuntu-3ubuntu0.10" },
            Identity { product: "OpenSSH", version: "9.2p1", extra: "Debian-2+deb12u3" },
            Identity { product: "OpenSSH", version: "7.4", extra: "" },
        ],
        "http" => &[
            Identity { product: "nginx", version: "1.18.0", extra: "(Ubuntu)" },
            Identity { product: "nginx", version: "1.24.0", extra: "" },
            Identity { product: "Apache", version: "2.4.52", extra: "(Ubuntu)" },
            Identity { product: "Apache", version: "2.4.41", extra: "(Ubuntu)" },
        ],
        "ftp" => &[
            Identity { product: "vsFTPd", version: "3.0.3", extra: "" },
            Identity { product: "vsFTPd", version: "3.0.5", extra: "" },
            Identity { product: "ProFTPD", version: "1.3.5b", extra: "" },
        ],
        "smtp" => &[
            Identity { product: "Postfix", version: "", extra: "(Ubuntu)" },
            Identity { product: "Exim", version: "4.94", extra: "" },
            Identity { product: "Sendmail", version: "8.15.2", extra: "" },
        ],
        "pop3" => &[Identity { product: "Dovecot", version: "", extra: "" }],
        "imap" => &[Identity { product: "Dovecot", version: "", extra: "" }],
        "redis" => &[Identity { product: "Redis", version: "7.0.11", extra: "" }],
        "mysql" => &[
            Identity { product: "MySQL", version: "5.7.33-log", extra: "" },
            Identity { product: "MySQL", version: "8.0.32", extra: "" },
            Identity { product: "MariaDB", version: "10.5.18-MariaDB", extra: "" },
        ],
        "telnet" => &[Identity { product: "", version: "", extra: "" }],
        "rtsp" => &[
            Identity { product: "Wowza", version: "4.8.5", extra: "" },
            Identity { product: "GStreamer", version: "1.20.3", extra: "" },
        ],
        _ => &[],
    }
}

/// The banner a decoy of `proto` emits on connect, chosen from the pool by
/// `seed`. `None` for a protocol this module does not impersonate.
///
/// Every arm builds a banner `identify` reads back as `proto`, and the selftest
/// proves it. The FTP and SMTP arms lean on a quiet fact of `identify`: it
/// decides FTP when a `220` greeting *contains* "ftp" and SMTP when it contains
/// "smtp", and "vsFTPd"/"ProFTPD" and "ESMTP" carry those substrings, so the
/// banner self-identifies without the port having to agree.
pub fn banner(proto: &str, seed: u32) -> Option<Vec<u8>> {
    let p = pool(proto);
    if p.is_empty() {
        return None;
    }
    let id = &p[(seed as usize) % p.len()];
    let mut s = String::new();
    match proto {
        "ssh" => {
            s.push_str("SSH-2.0-");
            s.push_str(id.product);
            s.push('_');
            s.push_str(id.version);
            if !id.extra.is_empty() {
                s.push(' ');
                s.push_str(id.extra);
            }
            s.push_str("\r\n");
        }
        "http" | "rtsp" => {
            s.push_str(if proto == "http" { "HTTP/1.1 200 OK\r\n" } else { "RTSP/1.0 200 OK\r\n" });
            s.push_str("Server: ");
            s.push_str(id.product);
            if !id.version.is_empty() {
                s.push('/');
                s.push_str(id.version);
            }
            if !id.extra.is_empty() {
                s.push(' ');
                s.push_str(id.extra);
            }
            s.push_str("\r\n");
            if proto == "http" {
                s.push_str("Content-Type: text/html\r\nConnection: close\r\n\r\n");
                s.push_str("<html><head><title>Welcome</title></head><body></body></html>");
            } else {
                s.push_str("\r\n");
            }
        }
        "ftp" => {
            if id.product == "vsFTPd" {
                s.push_str("220 (vsFTPd ");
                s.push_str(id.version);
                s.push_str(")\r\n");
            } else {
                s.push_str("220 ProFTPD ");
                s.push_str(id.version);
                s.push_str(" Server ready.\r\n");
            }
        }
        "smtp" => {
            s.push_str("220 mail.example.com ESMTP ");
            s.push_str(id.product);
            if !id.version.is_empty() {
                s.push(' ');
                s.push_str(id.version);
            }
            s.push_str("\r\n");
        }
        "pop3" => s.push_str("+OK Dovecot ready.\r\n"),
        "imap" => s.push_str("* OK [CAPABILITY IMAP4rev1 SASL-IR] Dovecot ready.\r\n"),
        "redis" => s.push_str("-NOAUTH Authentication required.\r\n"),
        "mysql" => {
            // The handshake is binary: a length-prefixed packet, protocol byte
            // 0x0a, then the NUL-terminated version string, and the auth plugin
            // literal near the end. `identify` matches the version and the
            // literal, so both must be present and in that order.
            let mut b: Vec<u8> = alloc::vec![0x4a, 0x00, 0x00, 0x00, 0x0a];
            b.extend_from_slice(id.version.as_bytes());
            b.push(0x00);
            b.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00");
            b.extend_from_slice(b"mysql_native_password\x00");
            return Some(b);
        }
        "telnet" => {
            // IAC negotiation: WILL echo, WILL suppress-go-ahead, DO terminal
            // -type, DO window-size. `identify` keys on the leading 0xFF.
            return Some(alloc::vec![
                0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfd, 0x18, 0xff, 0xfd, 0x1f,
            ]);
        }
        _ => return None,
    }
    Some(s.into_bytes())
}

/// Every decoy round-trips through the classifier, and a fleet is diverse.
///
/// The round-trip is the whole contract: a banner this module emits, fed to
/// `identify`, must come back as the service it impersonates. The diversity
/// check guards the other half of the point -- a protocol with several
/// identities must actually produce more than one banner across seeds, or the
/// "fleet of different machines" is a fleet of clones and the seed is
/// decorative.
pub fn selftest() -> bool {
    use super::fingerprint::identify;
    let mut ok = true;
    let mut check = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   decoy     {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    for &proto in KINDS {
        let port = port_of(proto);
        let n = pool(proto).len();
        // Every seed in the pool, plus a couple past it to prove the modulo
        // wraps rather than falling off.
        for seed in 0..(n as u32 + 2) {
            match banner(proto, seed) {
                None => check(false, proto),
                Some(b) => {
                    let fp = identify(port, &b);
                    check(fp.proto == proto, proto);
                }
            }
        }
        // Diversity: a multi-identity pool must yield distinct banners.
        if n > 1 {
            let a = banner(proto, 0).unwrap_or_default();
            let mut distinct = false;
            for seed in 1..(n as u32) {
                if banner(proto, seed).unwrap_or_default() != a {
                    distinct = true;
                    break;
                }
            }
            check(distinct, proto);
        }
    }

    // A protocol nobody impersonates is refused, not faked with an empty banner.
    check(banner("gopher", 0).is_none(), "unknown protocol refused");

    ok
}
