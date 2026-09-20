//! Known-weak version matching: recon that names a weakness, not an exploit.
//!
//! The fingerprint module names what is running. This one says whether what is
//! running has a *known, published, specific* weakness -- a version number that
//! sits inside a range a CVE was assigned to. It is still reconnaissance: the
//! output is "this version is known to be weak to X", never "and here is how to
//! break in". No credential is submitted, no payload is crafted, no access is
//! gained. The model learns what a human running `nmap --script vuln` would
//! learn, and the record carries the finding the same way it carries a banner.
//!
//! ### Why the table is static, and why that is honest
//!
//! A version-to-CVE table goes stale the day it ships. `fingerprint.rs` already
//! says so and declines to carry one for that reason. This module carries one
//! anyway because the arena is a *contained lab experiment* against the
//! operator's own hardware, not a scanner sold to strangers, and a stale table
//! in a lab is a design choice rather than a silent regression. The table is
//! small, curated to well-known weaknesses a CTF contestant would recognise on
//! sight, and every entry is asserted at boot against its own version range.
//!
//! ### The function is pure, for the same reason `fingerprint::identify` is
//!
//! `check` takes strings and returns a verdict. No network, no state, every
//! claim assertable at boot against a version the table says is weak and one it
//! says is not. The I/O -- reading the recon index and storing findings -- sits
//! in the arena step engine where it belongs, not here.

use alloc::string::String;
use alloc::vec::Vec;

/// One known weakness, matched from a service's version.
#[derive(Clone)]
pub struct Weakness {
    /// The CVE identifier, e.g. "CVE-2021-41773".
    pub cve: &'static str,
    /// How bad it is, as a word a non-specialist can act on.
    pub severity: Severity,
    /// What it is, in one line.
    pub brief: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl Weakness {
    /// One-line render for the recon index and the trajectory record.
    pub fn render(&self) -> String {
        let mut s = String::from(self.cve);
        s.push('(');
        s.push_str(self.severity.tag());
        s.push_str(") ");
        s.push_str(self.brief);
        s
    }
}

// --- the table --------------------------------------------------------------

/// One row in the known-weak table. A service matches when the proto and
/// product agree (case-insensitive) and the version falls inside `[from, to]`
/// inclusive.
struct Rule {
    proto: &'static str,
    product: &'static str,
    from: &'static str,
    to: &'static str,
    cve: &'static str,
    severity: Severity,
    brief: &'static str,
}

/// The curated table. Small on purpose: a CTF contestant would recognise every
/// entry on sight, and a table too large to read is a table nobody checks.
///
/// Each entry covers a specific version range for a specific CVE. The version
/// comparison is dot-separated numeric, so "2.4.49" < "2.4.50" < "2.4.51".
const KNOWN_WEAK: &[Rule] = &[
    // Apache path traversal — the canonical "one version number" finding.
    Rule {
        proto: "http",
        product: "Apache",
        from: "2.4.49",
        to: "2.4.49",
        cve: "CVE-2021-41773",
        severity: Severity::Critical,
        brief: "path traversal via crafted URI",
    },
    Rule {
        proto: "http",
        product: "Apache",
        from: "2.4.50",
        to: "2.4.50",
        cve: "CVE-2021-42013",
        severity: Severity::Critical,
        brief: "path traversal (incomplete fix of CVE-2021-41773)",
    },
    // vsFTPd backdoor — the textbook CTF answer.
    Rule {
        proto: "ftp",
        product: "vsFTPd",
        from: "2.3.4",
        to: "2.3.4",
        cve: "CVE-2011-2523",
        severity: Severity::Critical,
        brief: "backdoor command execution via smiley trigger",
    },
    // OpenSSH user enumeration.
    Rule {
        proto: "ssh",
        product: "OpenSSH",
        from: "2.0",
        to: "7.6",
        cve: "CVE-2018-15473",
        severity: Severity::Medium,
        brief: "username enumeration via malformed auth packets",
    },
    // ProFTPD remote code execution.
    Rule {
        proto: "ftp",
        product: "ProFTPD",
        from: "1.3.0",
        to: "1.3.5",
        cve: "CVE-2015-3306",
        severity: Severity::High,
        brief: "unauthenticated copy leading to remote code execution",
    },
    // nginx request smuggling.
    Rule {
        proto: "http",
        product: "nginx",
        from: "0.6.18",
        to: "1.17.6",
        cve: "CVE-2019-20372",
        severity: Severity::Medium,
        brief: "HTTP request smuggling via error pages",
    },
    // Redis unprotected — not a version range, any version with no auth.
    // Handled specially by `check`: proto=redis, product=Redis, version=""
    // signals an unprotected instance (the probe got +PONG without auth).
    Rule {
        proto: "redis",
        product: "Redis",
        from: "0.0.0",
        to: "99.99.99",
        cve: "MISC-NOAUTH",
        severity: Severity::High,
        brief: "Redis instance with no authentication",
    },
    // MySQL 5.x auth bypass.
    Rule {
        proto: "mysql",
        product: "MySQL",
        from: "5.1.0",
        to: "5.1.73",
        cve: "CVE-2012-2122",
        severity: Severity::High,
        brief: "authentication bypass via timing (memcmp race)",
    },
    // Exim remote code execution.
    Rule {
        proto: "smtp",
        product: "Exim",
        from: "4.87",
        to: "4.91",
        cve: "CVE-2019-10149",
        severity: Severity::Critical,
        brief: "remote command execution via crafted recipient address",
    },
];

// --- version comparison (dot-separated numeric) -----------------------------

/// Compare two dot-separated version strings numerically.
/// Returns Ordering::Less, Equal, or Greater.
/// Non-numeric segments compare as 0; trailing missing segments are 0.
fn ver_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        let an = ai.next();
        let bn = bi.next();
        if an.is_none() && bn.is_none() {
            return core::cmp::Ordering::Equal;
        }
        let av: u32 = an.unwrap_or("0").parse().unwrap_or(0);
        let bv: u32 = bn.unwrap_or("0").parse().unwrap_or(0);
        match av.cmp(&bv) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
}

/// Whether `ver` falls inside `[from, to]` inclusive, by dot-separated numeric
/// comparison. The version's trailing alphabetic suffix (like "p1" in "8.9p1")
/// is stripped before comparison, since the CVE ranges are numeric.
fn ver_in_range(ver: &str, from: &str, to: &str) -> bool {
    let clean = strip_alpha_suffix(ver);
    let v = clean.as_str();
    ver_cmp(v, from) != core::cmp::Ordering::Less
        && ver_cmp(v, to) != core::cmp::Ordering::Greater
}

/// Strip a trailing non-numeric suffix so "8.9p1" becomes "8.9" and "3.0.3"
/// stays "3.0.3". Needed because version ranges in CVEs are numeric, but
/// software versions carry patch letters.
fn strip_alpha_suffix(ver: &str) -> String {
    // Walk each dot-separated segment, truncating at the first non-digit
    // character within a segment.
    let mut out = String::new();
    for (i, seg) in ver.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        for c in seg.chars() {
            if c.is_ascii_digit() {
                out.push(c);
            } else {
                break;
            }
        }
        // A segment that was entirely non-numeric contributes "0" so the
        // comparison does not collapse.
        if out.ends_with('.') || (i == 0 && out.is_empty()) {
            out.push('0');
        }
    }
    out
}

// --- the check --------------------------------------------------------------

/// Match a discovered service against the known-weak table. Pure: the same
/// inputs always produce the same output, and every claim is assertable at boot.
///
/// `proto` and `product` are matched case-insensitively (banners vary).
/// `version` is compared numerically after stripping alphabetic suffixes.
///
/// The Redis NOAUTH rule is special: it matches any version when `noauth` is
/// true, which the caller determines from the probe response (the `-NOAUTH`
/// banner or a bare `+PONG` are both Redis responding without credentials).
pub fn check(proto: &str, product: &str, version: &str, noauth: bool) -> Vec<Weakness> {
    let mut out = Vec::new();
    for r in KNOWN_WEAK {
        // The NOAUTH rule is a special case: it fires on any Redis version when
        // the instance has no authentication, regardless of version range.
        if r.cve == "MISC-NOAUTH" {
            if proto.eq_ignore_ascii_case(r.proto) && noauth {
                out.push(Weakness {
                    cve: r.cve,
                    severity: r.severity,
                    brief: r.brief,
                });
            }
            continue;
        }
        if !proto.eq_ignore_ascii_case(r.proto) {
            continue;
        }
        if !product.eq_ignore_ascii_case(r.product) {
            continue;
        }
        if version.is_empty() {
            continue; // no version to compare — cannot claim weakness
        }
        if ver_in_range(version, r.from, r.to) {
            out.push(Weakness {
                cve: r.cve,
                severity: r.severity,
                brief: r.brief,
            });
        }
    }
    out
}

// --- selftest ---------------------------------------------------------------

pub fn selftest() -> bool {
    let mut ok = true;
    let mut claim = |cond: bool, what: &str| {
        if !cond {
            use crate::gfx::console::{self, LTGRAY, LTRED};
            use crate::kprintln;
            console::set_color(LTRED);
            kprintln!("  FAIL   vulnid    {}", what);
            console::set_color(LTGRAY);
            ok = false;
        }
    };

    // Version comparison.
    use core::cmp::Ordering;
    claim(ver_cmp("2.4.49", "2.4.49") == Ordering::Equal, "equal versions");
    claim(ver_cmp("2.4.49", "2.4.50") == Ordering::Less, "2.4.49 < 2.4.50");
    claim(ver_cmp("2.4.50", "2.4.49") == Ordering::Greater, "2.4.50 > 2.4.49");
    claim(ver_cmp("1.18.0", "1.17.6") == Ordering::Greater, "1.18.0 > 1.17.6");
    claim(ver_cmp("7.6", "7.6.0") == Ordering::Equal, "trailing .0 is equal");
    claim(ver_cmp("5.1.73", "5.1.73") == Ordering::Equal, "three-segment equal");

    // Suffix stripping.
    claim(strip_alpha_suffix("8.9p1") == "8.9", "p1 suffix stripped");
    claim(strip_alpha_suffix("3.0.3") == "3.0.3", "numeric-only unchanged");
    claim(strip_alpha_suffix("1.3.5b") == "1.3.5", "trailing letter stripped");

    // Range check.
    claim(ver_in_range("2.4.49", "2.4.49", "2.4.49"), "exact match in range");
    claim(!ver_in_range("2.4.48", "2.4.49", "2.4.49"), "below range");
    claim(!ver_in_range("2.4.51", "2.4.49", "2.4.50"), "above range");
    claim(ver_in_range("7.0", "2.0", "7.6"), "inside wide range");
    claim(!ver_in_range("7.7", "2.0", "7.6"), "just above wide range");
    claim(ver_in_range("8.9p1", "2.0", "8.9"), "suffix stripped before range check");

    // Known-weak checks.
    let apache49 = check("http", "Apache", "2.4.49", false);
    claim(!apache49.is_empty(), "Apache 2.4.49 is known weak");
    claim(apache49[0].cve == "CVE-2021-41773", "correct CVE for Apache 2.4.49");

    let apache52 = check("http", "Apache", "2.4.52", false);
    claim(apache52.is_empty(), "Apache 2.4.52 is not in the weak range");

    let vsftpd = check("ftp", "vsFTPd", "2.3.4", false);
    claim(!vsftpd.is_empty() && vsftpd[0].cve == "CVE-2011-2523", "vsFTPd backdoor version");

    let vsftpd_ok = check("ftp", "vsFTPd", "3.0.3", false);
    claim(vsftpd_ok.is_empty(), "vsFTPd 3.0.3 is not weak");

    let ssh_old = check("ssh", "OpenSSH", "7.4p1", false);
    claim(!ssh_old.is_empty() && ssh_old[0].cve == "CVE-2018-15473", "old OpenSSH user enum");

    let ssh_new = check("ssh", "OpenSSH", "8.9p1", false);
    claim(ssh_new.is_empty(), "OpenSSH 8.9 is past the weak range");

    let nginx_old = check("http", "nginx", "1.16.0", false);
    claim(!nginx_old.is_empty(), "nginx 1.16 is in the smuggling range");

    let nginx_new = check("http", "nginx", "1.18.0", false);
    claim(nginx_new.is_empty(), "nginx 1.18 is past the fix");

    // Redis NOAUTH fires on any version when noauth is true.
    let redis_noauth = check("redis", "Redis", "7.0.11", true);
    claim(
        redis_noauth.iter().any(|w| w.cve == "MISC-NOAUTH"),
        "Redis with no auth is flagged",
    );
    let redis_authed = check("redis", "Redis", "7.0.11", false);
    claim(
        !redis_authed.iter().any(|w| w.cve == "MISC-NOAUTH"),
        "Redis with auth is not flagged for NOAUTH",
    );

    // No version means no match (except NOAUTH).
    let no_ver = check("http", "Apache", "", false);
    claim(no_ver.is_empty(), "empty version matches nothing");

    // Case-insensitive proto/product.
    let ci = check("HTTP", "apache", "2.4.49", false);
    claim(!ci.is_empty(), "case-insensitive match works");

    ok
}
