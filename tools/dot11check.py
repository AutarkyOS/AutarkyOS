#!/usr/bin/env python3
"""Check GLaDOS's 802.11 frames against scapy, which is not GLaDOS.

Every wireless suite in the kernel builds a frame with `net/ieee80211.rs` and
reads it back with the parsers in the same file.  A field written in the wrong
order is therefore read back in the wrong order, the claim passes, and no
access point in the world will answer -- which is a bug that costs a bare-metal
boot to find and tells you nothing when you find it.

So the kernel prints its frames (`wifi frames`) and this puts them through
scapy: an independent implementation of these formats, written by other people,
used to read real captures.  Where scapy can build the same frame the check is
byte for byte; where it cannot, the fields are compared one at a time.

    python tools\\drive.py --qemu-extra "-accel whpx -cpu max" \\
        "initiative off" "agent stop" "wifi frames" > out\\frames.log
    python tools\\dot11check.py out\\frames.log

Reads a drive.py log (or stdin) and looks for lines shaped `frame <name> <hex>`.
Exit code is the number of checks that failed, so it is usable from a script.

What this does NOT establish, said plainly: scapy agrees about *layout*, not
about whether a real access point accepts what we send.  Association depends on
the capability bits and the RSN suites being ones the network offers, and only
a real network answers that.  It also says nothing about the CCMP cryptography
-- only the header framing -- because scapy does not carry the Annex J vectors
either, and those are still owed.
"""

import binascii
import sys

try:
    from scapy.layers.dot11 import (
        Dot11,
        Dot11Auth,
        Dot11AssoReq,
        Dot11AssoResp,
        Dot11Beacon,
        Dot11CCMP,
        Dot11Deauth,
        Dot11Disas,
        Dot11Elt,
        Dot11EltRates,
        Dot11EltRSN,
        Dot11ProbeReq,
        Dot11ProbeResp,
    )
    from scapy.layers.eap import EAPOL, EAPOL_KEY
    from scapy.layers.l2 import LLC, SNAP
except ImportError:
    sys.stderr.write(
        "scapy is missing: .\\tools\\venv\\Scripts\\python.exe -m pip install scapy\n"
    )
    raise SystemExit(2)

ME = "02:00:00:00:00:11"
AP = "02:00:00:00:00:aa"
SSID = b"glados"
SEQ = 7
# What net/ieee80211.rs::BASIC_RATES holds, in the element's own encoding.
RATES = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])

FAILED = 0
PASSED = 0


def check(what, ok, detail=""):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print("  ok    %s" % what)
    else:
        FAILED += 1
        print("  FAIL  %s%s" % (what, ("  -- " + detail) if detail else ""))


def same_bytes(what, got, want):
    if got == want:
        check(what, True)
        return
    at = next(
        (i for i in range(min(len(got), len(want))) if got[i] != want[i]),
        min(len(got), len(want)),
    )
    check(
        what,
        False,
        "%d bytes vs %d, first difference at %d: %02x vs %02x"
        % (
            len(got),
            len(want),
            at,
            got[at] if at < len(got) else 0,
            want[at] if at < len(want) else 0,
        ),
    )


def seq_of(pkt):
    """The sequence control field's top twelve bits, however scapy spells it."""
    sc = pkt[Dot11].SC
    if sc is None:
        return None
    return sc >> 4


def check_auth_req(raw):
    p = Dot11(raw)
    check("auth request is a management authentication frame", p.type == 0 and p.subtype == 11)
    check(
        "  addressed to the access point, from us, on its BSSID",
        p.addr1 == AP and p.addr2 == ME and p.addr3 == AP,
    )
    check("  neither ToDS nor FromDS, as management frames are not", p.FCfield.to_DS == 0 and p.FCfield.from_DS == 0)
    check("  the frame's own sequence control is the one we asked for", seq_of(p) == SEQ)
    a = p[Dot11Auth]
    check(
        "  Open System, transaction 1, status 0 -- and scapy reads the three "
        "in that order",
        a.algo == 0 and a.seqnum == 1 and a.status == 0,
    )
    # And byte for byte against scapy's own builder, which is the stronger form.
    want = bytes(
        Dot11(type=0, subtype=11, addr1=AP, addr2=ME, addr3=AP, SC=SEQ << 4)
        / Dot11Auth(algo=0, seqnum=1, status=0)
    )
    same_bytes("  and the whole frame is byte for byte what scapy builds", raw, want)


def check_auth_resp(raw):
    p = Dot11(raw)
    a = p[Dot11Auth]
    check(
        "auth response is transaction 2, the other way round",
        p.subtype == 11 and a.seqnum == 2 and p.addr1 == ME and p.addr2 == AP,
    )


def check_assoc_req(raw, rsn):
    name = "association request" + (" with RSN" if rsn else ", open")
    p = Dot11(raw)
    check("%s is a management association request" % name, p.type == 0 and p.subtype == 0)
    a = p[Dot11AssoReq]
    check("  listen interval is 10 beacon periods", a.listen_interval == 10)
    # ESS is bit 0 and Privacy is bit 4. Scapy names them.
    cap = a.cap
    check("  ESS is set, so this is infrastructure and not ad-hoc", "ESS" in str(cap))
    if rsn:
        check("  privacy is set, agreeing with the RSN element", "privacy" in str(cap))
    else:
        check("  privacy is clear on an open network", "privacy" not in str(cap))

    elts = {}
    e = p.getlayer(Dot11Elt)
    while e is not None:
        elts.setdefault(e.ID, e)
        e = e.payload.getlayer(Dot11Elt)
    check("  carries the SSID", 0 in elts and bytes(elts[0].info) == SSID)
    check("  carries the supported rates, in the element's own encoding",
          1 in elts and bytes(elts[1].info) == RATES)
    if not rsn:
        check("  and no RSN element at all", 48 not in elts)
        return
    check("  carries an RSN element", 48 in elts)
    if 48 not in elts:
        return
    # Re-parse the RSN element as scapy's typed version, which is where the
    # suite selectors actually get read.
    r = Dot11EltRSN(bytes(elts[48]))
    check("  RSN version 1", r.version == 1)
    check(
        "  group cipher is CCMP (00-0f-ac-4), which scapy names",
        r.group_cipher_suite.cipher == 4 and bytes(r.group_cipher_suite.oui.to_bytes(3, "big")) == b"\x00\x0f\xac",
    )
    check(
        "  exactly one pairwise cipher and it is CCMP",
        r.nb_pairwise_cipher_suites == 1
        and len(r.pairwise_cipher_suites) == 1
        and r.pairwise_cipher_suites[0].cipher == 4,
    )
    check(
        "  exactly one AKM and it is PSK (suite type 2)",
        r.nb_akm_suites == 1 and len(r.akm_suites) == 1 and r.akm_suites[0].suite == 2,
    )
    check("  and no TKIP is offered anywhere in it",
          all(c.cipher != 2 for c in r.pairwise_cipher_suites) and r.group_cipher_suite.cipher != 2)


def check_assoc_resp(raw):
    p = Dot11(raw)
    a = p[Dot11AssoResp]
    check("association response is subtype 1", p.subtype == 1)
    check("  status 0", a.status == 0)
    # The AID's top two bits are set by convention and are not part of the
    # number. Scapy's `AID` field is the raw sixteen bits.
    check("  AID is 7 once the two convention bits are masked off",
          (a.AID & 0x3FFF) == 7, "raw AID = 0x%04x" % a.AID)
    check("  and those two bits really are set on the wire", (a.AID & 0xC000) == 0xC000)


def check_deauth(raw):
    p = Dot11(raw)
    check("deauthentication is subtype 12 and carries reason 3",
          p.subtype == 12 and p[Dot11Deauth].reason == 3)


def check_disassoc(raw):
    p = Dot11(raw)
    check("disassociation is subtype 10 and carries reason 8",
          p.subtype == 10 and p[Dot11Disas].reason == 8)


def check_beacon(raw, probe_resp=False):
    name = "probe response" if probe_resp else "beacon"
    p = Dot11(raw)
    want_sub = 5 if probe_resp else 8
    check("%s is subtype %d" % (name, want_sub), p.subtype == want_sub)
    check(
        "  addressed %s" % ("to the station that asked" if probe_resp else "to everybody"),
        p.addr1 == (ME if probe_resp else "ff:ff:ff:ff:ff:ff"),
    )
    b = p[Dot11ProbeResp] if probe_resp else p[Dot11Beacon]
    check("  beacon interval 100", b.beacon_interval == 100)
    elts = {}
    e = p.getlayer(Dot11Elt)
    while e is not None:
        elts.setdefault(e.ID, e)
        e = e.payload.getlayer(Dot11Elt)
    check("  names the network", 0 in elts and bytes(elts[0].info) == SSID)
    check("  and the channel, in the DS Parameter Set", 3 in elts and elts[3].info == b"\x06")
    check("  and says it is RSN", 48 in elts)


def check_probe_req(raw):
    p = Dot11(raw)
    check("probe request is subtype 4, broadcast both ways",
          p.subtype == 4 and p.addr1 == "ff:ff:ff:ff:ff:ff" and p.addr3 == "ff:ff:ff:ff:ff:ff")
    check("  from us", p.addr2 == ME)
    e = p.getlayer(Dot11Elt)
    check("  first element is the SSID", e is not None and e.ID == 0 and bytes(e.info) == SSID)


def check_rsn_element(raw):
    r = Dot11EltRSN(raw)
    check("the RSN element stands alone and parses as one", r.ID == 48)
    check("  its declared length matches what follows", r.len == len(raw) - 2)
    check("  version 1, group CCMP, pairwise CCMP, AKM PSK",
          r.version == 1
          and r.group_cipher_suite.cipher == 4
          and r.pairwise_cipher_suites[0].cipher == 4
          and r.akm_suites[0].suite == 2)


def check_snap(raw):
    s = LLC(raw)
    check("SNAP is AA AA 03 then a zero OUI",
          s.dsap == 0xAA and s.ssap == 0xAA and s.ctrl == 3)
    sn = s[SNAP]
    check("  the OUI is zero and the EtherType is IPv4", sn.OUI == 0 and sn.code == 0x0800)
    check("  and the payload follows at byte eight", raw[8:] == b"payload")
    same_bytes("  byte for byte against scapy's own",
               raw, bytes(LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x0800) / b"payload"))


def check_data(raw, to_ds):
    name = "data to the AP" if to_ds else "data from the AP"
    p = Dot11(raw)
    check("%s is a data frame" % name, p.type == 2 and p.subtype == 0)
    check("  the direction bits say so",
          p.FCfield.to_DS == (1 if to_ds else 0) and p.FCfield.from_DS == (0 if to_ds else 1))
    if to_ds:
        # ToDS: addr1 BSSID, addr2 source, addr3 destination.
        check("  BSSID first, source second, destination third",
              p.addr1 == AP and p.addr2 == ME and p.addr3 == AP)
    else:
        # FromDS: addr1 destination, addr2 BSSID, addr3 source.
        check("  destination first, BSSID second, source third",
              p.addr1 == ME and p.addr2 == AP and p.addr3 == AP)
    check("  header is 24 bytes and the body is SNAP", raw[24:26] == b"\xaa\xaa")


def check_ccmp(raw):
    p = Dot11(raw)
    check("a protected frame still parses as a data frame", p.type == 2 and p.subtype == 0)
    check("  and the Protected bit is set", p.FCfield.protected == 1)
    c = p[Dot11CCMP]
    # The packet number is split across the header in an order that is not the
    # order it is counted in: PN0 and PN1, a reserved byte, the key-id byte,
    # then PN2..PN5.
    pn = (
        c.PN0
        | (c.PN1 << 8)
        | (c.PN2 << 16)
        | (c.PN3 << 24)
        | (c.PN4 << 32)
        | (c.PN5 << 40)
    )
    check("  scapy reassembles the packet number we sent", pn == 0x060504030201,
          "got 0x%012x" % pn)
    check("  ExtIV is set, which is what says this is CCMP and not WEP", c.ext_iv == 1)
    check("  and the key id is the one that was asked for", c.key_id == 2)
    check("  the header is eight bytes and a MIC of eight is on the end",
          len(raw) == 24 + 8 + (len(raw) - 40) + 8)


def check_eapol(name, raw, expect):
    p = EAPOL(raw)
    check("%s is an EAPOL-Key frame" % name, p.type == 3)
    check("  its declared length matches the body that follows", p.len == len(raw) - 4)
    k = p[EAPOL_KEY]
    check("  key descriptor type 2, which is RSN", k.key_descriptor_type == 2)
    # `has_key_mic` is the flag; `key_mic` is the sixteen bytes themselves.
    # Two fields one letter apart, and the first version of this checker read
    # the wrong one -- which is the same class of mistake it exists to catch,
    # arriving in the checker instead of the kernel.
    got = {
        "pairwise": int(k.key_type),
        "ack": int(k.key_ack),
        "mic": int(k.has_key_mic),
        "secure": int(k.secure),
        "install": int(k.install),
        "encrypted": int(k.encrypted_key_data),
    }
    bad = [f for f in expect if got[f] != expect[f]]
    check(
        "  key information bits: %s"
        % ", ".join("%s=%d" % (f, expect[f]) for f in sorted(expect)),
        not bad,
        "differs on " + ", ".join("%s=%d" % (f, got[f]) for f in bad),
    )
    check(
        "  the AKM descriptor version is 2, meaning HMAC-SHA1",
        k.key_descriptor_type_version == 2,
    )
    check("  key length is 16, the size of a CCMP temporal key", k.key_length == 16)
    check(
        "  and the nonce is where the standard puts it, 32 bytes of it",
        len(bytes(k.key_nonce)) == 32,
    )
    zeros = b"\x00" * 16
    if name == "eapol_m1":
        check("  message 1 carries the ANonce we set", bytes(k.key_nonce) == b"\x11" * 32)
        check(
            "  with a MIC of all zeros, there being no key yet to sign it",
            bytes(k.key_mic) == zeros,
        )
        check("  and no key data", k.key_data_length == 0)
    if name == "eapol_m2":
        check("  message 2 carries the SNonce we set", bytes(k.key_nonce) == b"\x22" * 32)
        check("  with a MIC that is not zero", bytes(k.key_mic) != zeros)
    if name == "eapol_m3":
        # The GTK travels wrapped under the KEK, and RFC 3394 makes the result
        # eight bytes longer than the encapsulation that went in: 24 -> 32.
        check(
            "  message 3 carries 32 bytes of wrapped key data, the group key",
            k.key_data_length == 32 and len(bytes(k.key_data)) == 32,
        )
        check(
            "  and echoes the ANonce, which is what binds it to message 1",
            bytes(k.key_nonce) == b"\x11" * 32,
        )
    if name == "eapol_m4":
        check(
            "  message 4 is an acknowledgement: a MIC and nothing else",
            k.key_data_length == 0 and bytes(k.key_mic) != zeros,
        )

HANDLERS = {
    "auth_req": check_auth_req,
    "auth_resp": check_auth_resp,
    "assoc_req_rsn": lambda r: check_assoc_req(r, True),
    "assoc_req_open": lambda r: check_assoc_req(r, False),
    "assoc_resp": check_assoc_resp,
    "deauth": check_deauth,
    "disassoc": check_disassoc,
    "beacon": lambda r: check_beacon(r, False),
    "probe_resp": lambda r: check_beacon(r, True),
    "probe_req": check_probe_req,
    "rsn_element": check_rsn_element,
    "snap": check_snap,
    "data_to_ds": lambda r: check_data(r, True),
    "data_from_ds": lambda r: check_data(r, False),
    "ccmp": check_ccmp,
    "eapol_m1": lambda r: check_eapol(
        "eapol_m1", r, {"pairwise": 1, "ack": 1, "mic": 0, "secure": 0}
    ),
    "eapol_m2": lambda r: check_eapol(
        "eapol_m2", r, {"pairwise": 1, "ack": 0, "mic": 1, "secure": 0}
    ),
    "eapol_m3": lambda r: check_eapol(
        "eapol_m3",
        r,
        {"pairwise": 1, "ack": 1, "mic": 1, "secure": 1, "install": 1, "encrypted": 1},
    ),
    "eapol_m4": lambda r: check_eapol(
        "eapol_m4", r, {"pairwise": 1, "ack": 0, "mic": 1, "secure": 1}
    ),
}


def main():
    src = open(sys.argv[1], "r", errors="replace") if len(sys.argv) > 1 else sys.stdin
    frames = {}
    for line in src:
        # drive.py echoes the guest's serial, so the line may carry a prompt.
        at = line.find("frame ")
        if at < 0:
            continue
        parts = line[at:].split()
        if len(parts) != 3:
            continue
        name, hexs = parts[1], parts[2]
        if name not in HANDLERS:
            continue
        try:
            frames[name] = binascii.unhexlify(hexs)
        except binascii.Error:
            pass

    if not frames:
        print("no frames in that log. Did 'wifi frames' run?")
        return 2

    print("checking %d frame(s) against scapy %s\n" % (len(frames), __import__("scapy").__version__))
    for name in HANDLERS:
        if name not in frames:
            check("%s -- missing from the dump" % name, False)
            continue
        try:
            HANDLERS[name](frames[name])
        except Exception as e:  # a parse that throws is a failure, not a crash
            check("%s -- scapy could not read it" % name, False, repr(e))

    print("\n  %d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
