//! AES-CCM: counter mode with CBC-MAC, RFC 3610.
//!
//! One authenticated cipher, and the reason it exists here is that WPA2 leaves
//! no choice: CCMP is AES-CCM and a supplicant does not get to negotiate
//! something else. `aes.rs` says the same thing about why a table-driven AES is
//! in a tree that otherwise prefers ChaCha20.
//!
//! **Generic in the parameters, because the callers are not one caller.** CCMP
//! uses a 13-byte nonce and an 8-byte tag; RFC 3610's own vectors use tags from
//! 4 to 16 bytes; and a future 802.11 cipher suite may want 16. So `L` is
//! derived from the nonce length rather than fixed, and the tag length is an
//! argument -- which is also what lets the published vectors be run against
//! exactly the code the radio will use, rather than against a special case of
//! it.
//!
//! ### The two halves, and why they are computed in this order
//!
//! CCM is CBC-MAC for authenticity and CTR for confidentiality, over the same
//! key. The MAC is taken over the **plaintext**, so sealing computes it first
//! and opening must decrypt before it can check -- which means `open` has to
//! produce a candidate plaintext it does not yet trust. It is only returned
//! after the tag matches, and the comparison is constant time: a byte-at-a-time
//! `==` that returns early leaks which byte differed, and that is enough to
//! forge a tag one byte at a time.

use alloc::vec::Vec;

use super::aes::Aes;

/// Build the flags-and-nonce prefix shared by `B_0` and every counter block.
fn block(first: u8, nonce: &[u8], l: usize, counter: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = first;
    b[1..1 + nonce.len()].copy_from_slice(nonce);
    // Big-endian in the trailing `l` bytes, written from the end so the width
    // is the loop bound rather than an offset somebody has to get right twice.
    for k in 0..l {
        b[15 - k] = (counter >> (8 * k)) as u8;
    }
    b
}

fn cbc_mac(aes: &Aes, nonce: &[u8], l: usize, aad: &[u8], data: &[u8], tag_len: usize) -> [u8; 16] {
    let flags = (if aad.is_empty() { 0 } else { 0x40 })
        | ((((tag_len as u8) - 2) / 2) << 3)
        | (l as u8 - 1);
    let mut mac = block(flags, nonce, l, data.len());
    aes.encrypt_block(&mut mac);

    if !aad.is_empty() {
        // The length prefix is two bytes below 0xFF00 and six above it. The
        // second form is unreachable from 802.11, where the header is at most a
        // few dozen bytes, and is here because a reader checking this against
        // RFC 3610 should find the whole rule rather than the half that was
        // needed.
        let mut blk: Vec<u8> = Vec::with_capacity(aad.len() + 22);
        if aad.len() < 0xFF00 {
            blk.push((aad.len() >> 8) as u8);
            blk.push(aad.len() as u8);
        } else {
            blk.extend_from_slice(&[0xFF, 0xFE]);
            blk.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        }
        blk.extend_from_slice(aad);
        while blk.len() % 16 != 0 {
            blk.push(0);
        }
        for chunk in blk.chunks(16) {
            for i in 0..16 {
                mac[i] ^= chunk[i];
            }
            aes.encrypt_block(&mut mac);
        }
    }

    for chunk in data.chunks(16) {
        for (i, v) in chunk.iter().enumerate() {
            mac[i] ^= *v;
        }
        // A short final chunk is zero-padded, which is what *not* xoring the
        // rest amounts to. Written this way so the padding is an absence rather
        // than a buffer somebody has to remember to clear.
        aes.encrypt_block(&mut mac);
    }
    mac
}

/// The counter-mode keystream applied in place, starting at block 1.
fn ctr_xor(aes: &Aes, nonce: &[u8], l: usize, data: &mut [u8]) {
    for (j, chunk) in data.chunks_mut(16).enumerate() {
        let mut s = block(l as u8 - 1, nonce, l, j + 1);
        aes.encrypt_block(&mut s);
        for (k, v) in chunk.iter_mut().enumerate() {
            *v ^= s[k];
        }
    }
}

fn params(key: &[u8], nonce: &[u8], tag_len: usize) -> Option<(Aes, usize)> {
    let l = 15usize.checked_sub(nonce.len())?;
    // RFC 3610 admits L in 2..=8, which is nonces of 13 down to 7 bytes.
    if !(2..=8).contains(&l) {
        return None;
    }
    // Even, and at least 4. An odd or tiny tag is not a weaker CCM, it is a
    // different construction that the flags byte cannot encode.
    if tag_len < 4 || tag_len > 16 || tag_len % 2 != 0 {
        return None;
    }
    Some((Aes::new(key)?, l))
}

/// Encrypt and authenticate. Returns ciphertext followed by the tag.
pub fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plain: &[u8], tag_len: usize) -> Option<Vec<u8>> {
    let (aes, l) = params(key, nonce, tag_len)?;
    // The length field is `l` bytes, so a message that cannot be described in
    // it cannot be authenticated -- refused rather than truncated into a tag
    // that verifies against the wrong length.
    if l < 8 && plain.len() >= (1usize << (8 * l)) {
        return None;
    }

    let mac = cbc_mac(&aes, nonce, l, aad, plain, tag_len);
    let mut out = plain.to_vec();
    ctr_xor(&aes, nonce, l, &mut out);

    // The tag is masked with block zero, which is the one counter block the
    // message never uses.
    let mut s0 = block(l as u8 - 1, nonce, l, 0);
    aes.encrypt_block(&mut s0);
    for k in 0..tag_len {
        out.push(mac[k] ^ s0[k]);
    }
    Some(out)
}

/// Verify and decrypt. `None` if the tag does not match.
pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8], tag_len: usize) -> Option<Vec<u8>> {
    let (aes, l) = params(key, nonce, tag_len)?;
    if data.len() < tag_len {
        return None;
    }
    let (body, tag) = data.split_at(data.len() - tag_len);

    let mut plain = body.to_vec();
    ctr_xor(&aes, nonce, l, &mut plain);
    let mac = cbc_mac(&aes, nonce, l, aad, &plain, tag_len);
    let mut s0 = block(l as u8 - 1, nonce, l, 0);
    aes.encrypt_block(&mut s0);

    // Constant time. An `==` that returns at the first difference says which
    // byte differed, and a forger who can ask often enough builds a tag one
    // byte at a time from exactly that.
    let mut diff = 0u8;
    for k in 0..tag_len {
        diff |= (mac[k] ^ s0[k]) ^ tag[k];
    }
    if diff != 0 {
        return None;
    }
    Some(plain)
}

pub fn selftest() -> bool {
    use crate::gfx::console::{self, LTGRAY, LTGREEN, LTRED};
    let mut ok = true;
    let mut check = |what: &str, pass: bool| {
        console::set_color(if pass { LTGREEN } else { LTRED });
        crate::kprintln!("  {}  {}", if pass { "ok  " } else { "FAIL" }, what);
        console::set_color(LTGRAY);
        ok &= pass;
    };

    // RFC 3610, Packet Vector #1. Eight octets of cleartext header are the
    // additional data, the remaining twenty-three are the payload, the tag is
    // eight, and the nonce is thirteen -- which is exactly CCMP's shape, so
    // this vector exercises the parameters the radio will use rather than a
    // convenient special case.
    let key: [u8; 16] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF,
    ];
    let nonce: [u8; 13] = [
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
    ];
    let aad: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let plain: [u8; 23] = [
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    ];
    let want: [u8; 31] = [
        0x58, 0x8C, 0x97, 0x9A, 0x61, 0xC6, 0x63, 0xD2, 0xF0, 0x66, 0xD0, 0xC2, 0xC0, 0xF9, 0x89,
        0x80, 0x6D, 0x5F, 0x6B, 0x61, 0xDA, 0xC3, 0x84, 0x17, 0xE8, 0xD1, 0x2C, 0xFD, 0xF9, 0x26,
        0xE0,
    ];

    let sealed = seal(&key, &nonce, &aad, &plain, 8);
    check(
        "RFC 3610 packet vector 1, ciphertext and tag both",
        sealed.as_deref() == Some(&want[..]),
    );

    let sealed = sealed.unwrap_or_default();
    check(
        "and it opens back to the plaintext it came from",
        open(&key, &nonce, &aad, &sealed, 8).as_deref() == Some(&plain[..]),
    );

    // Three ways to be wrong, and every one of them must fail. A cipher that
    // authenticates the payload and not the header is the classic mistake, and
    // it is invisible in a round trip that never alters the header.
    let mut bad = sealed.clone();
    bad[0] ^= 1;
    check(
        "a flipped ciphertext bit is refused",
        open(&key, &nonce, &aad, &bad, 8).is_none(),
    );
    let mut badtag = sealed.clone();
    let last = badtag.len() - 1;
    badtag[last] ^= 1;
    check(
        "a flipped tag bit is refused",
        open(&key, &nonce, &aad, &badtag, 8).is_none(),
    );
    let mut badaad = aad;
    badaad[0] ^= 1;
    check(
        "and so is an altered header, which the payload alone would not notice",
        open(&key, &nonce, &badaad, &sealed, 8).is_none(),
    );
    check(
        "a different nonce does not open it either",
        {
            let mut n2 = nonce;
            n2[0] ^= 1;
            open(&key, &n2, &aad, &sealed, 8).is_none()
        },
    );

    // Empty in both directions, because 802.11 has zero-length data frames and
    // CCM's own length encoding is where an empty message goes wrong.
    let e = seal(&key, &nonce, &[], &[], 8);
    check(
        "an empty message with no header still authenticates",
        match &e {
            Some(v) => v.len() == 8 && open(&key, &nonce, &[], v, 8).as_deref() == Some(&[][..]),
            None => false,
        },
    );

    // The parameters that are not CCM, refused rather than approximated.
    check(
        "a nonce outside 7..13 bytes is refused",
        seal(&key, &[0u8; 14], &aad, &plain, 8).is_none()
            && seal(&key, &[0u8; 6], &aad, &plain, 8).is_none(),
    );
    check(
        "an odd or out-of-range tag length is refused",
        seal(&key, &nonce, &aad, &plain, 7).is_none()
            && seal(&key, &nonce, &aad, &plain, 2).is_none()
            && seal(&key, &nonce, &aad, &plain, 18).is_none(),
    );
    check(
        "a key that is not 128 or 256 bits is refused",
        seal(&[0u8; 24], &nonce, &aad, &plain, 8).is_none(),
    );
    check(
        "and data shorter than its own tag is refused rather than indexed",
        open(&key, &nonce, &aad, &[0u8; 4], 8).is_none(),
    );

    // A tag length other than eight, so the flags byte is exercised at more
    // than one value -- it encodes `(tag_len - 2) / 2` and a constant would
    // hide an error there.
    let t16 = seal(&key, &nonce, &aad, &plain, 16);
    check(
        "a sixteen-byte tag round-trips, so the flags byte is not a constant",
        match &t16 {
            Some(v) => {
                v.len() == plain.len() + 16
                    && open(&key, &nonce, &aad, v, 16).as_deref() == Some(&plain[..])
            }
            None => false,
        },
    );

    ok
}
