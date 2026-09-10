# The published share log

One HTML file that reads `ledger.json` and **recomputes its digest in the
browser**. Intended for GitHub Pages at `pool.aperture.institute`.

`design/pool.md` calls publishing "the only thing standing in for trust", and
means it literally: Layer 1 never holds a miner's coins, so there is no wallet
to audit. What a miner has instead is this record and whatever can be checked
against it.

## Why it recomputes rather than displays

A page showing the digest the pool wrote beside the rows the pool wrote proves
nothing -- both halves come from one program, and a program whose
canonicalisation was wrong would agree with itself. So the canonical form is
rebuilt here from the rows and hashed with the browser's own SHA-256.

That makes three implementations of the format: the Rust writer
(`Pool::ledger_json`), the Rust reader (`Pool::load_ledger`), and this. The
bargain `tokenizer.py --verify` makes, for the same reason.

Verified both ways rather than assumed. Against a real ledger the page reports
`DIGEST VERIFIED`; with **one unit of work moved from one worker to another and
the digest left untouched** -- the exact edit somebody would make to steal a
slice of a payout -- it reports `DIGEST MISMATCH` and prints both hashes.

## What the digest is not

**Not a signature.** Anybody who can edit the file can recompute it, and
`ledger_json` says so in its own comment. It fixes the record to a value so two
copies can be compared, and so a later Merkle distributor has something to be
checked against. The page says this in its footer rather than letting a green
tick imply more than it means.

## Deploying

    cp pool/site/index.html  <pages-repo>/
    cp <state>/ledger.json   <pages-repo>/

The pool writes `ledger.json` through a temporary and renames, so a publisher
copying it never sees half a document.

**`crypto.subtle` needs a secure context**, so verification works over `https`
and on `localhost` and not from a `file://` URL. GitHub Pages is https. Opened
from a file the page says `NOT CHECKED` rather than failing quietly -- "this
page cannot tell" and "this record is wrong" are different answers.

Locally:

    cd pool/site && python3 -m http.server 8731 --bind 127.0.0.1

## No build step

One file, no framework. A build step is a thing that can produce a site which
does not match its source, and the entire product here is that the published
thing can be checked -- so the source you can read is the thing that runs.
