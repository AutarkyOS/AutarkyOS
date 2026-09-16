#!/usr/bin/env python3
"""The dense forward pass again, batched -- and proven against `reference.py`.

`reference.py` is this project's numeric oracle and it is deliberately written
one position at a time: a Python loop over tokens, and inside it a Python loop
over layers doing matrix-vector products. That shape is why it is readable and
why it is trusted, and it is also why a 726-token prompt takes minutes. It is
an oracle, not a runner.

So this is the runner: the same arithmetic with the position loop turned into a
matrix dimension, which hands the work to BLAS instead of to CPython.

### A second implementation is a liability unless it is checked

`model.rs` makes the objection twice and this file has already paid for it
once: `lm_eval.py` used to carry its own dense pass, written for llama2, and it
could not run Qwen3 at all -- derived head width, interleaved RoPE, no QK-Norm.
Nobody noticed because nothing ever compared it to anything.

    python tools/fastdense.py out/dense-check.bin --check

runs both implementations over the same ids and prints the largest disagreement
in the logits together with whether the argmax matches. That check is the only
reason this file is allowed to exist, so it is the first thing in it and it is
not optional: a run that has not been checked is `reference.py`'s to make.

### What has to match, and where each one hides when it does not

**QK-Norm before RoPE, per head.** Applied after, the rotation is rescaled and
position stops meaning what it means.

**`rotate_half`, pairing `i` with `i + head_dim/2`.** The interleaved
convention rotates by the same angles, so the model stays fluent and attends by
a scrambled notion of distance.

**The head width the file states**, not `dim // heads`. Qwen3 states 128 where
the derivation gives 64.

**The KV cache round-trip, when the checkpoint asks for one.** It is what the
kernel's int8 cache costs, applied where the kernel applies it -- after QK-Norm
for keys, on the raw projection for values, before RoPE for both.

None of the four fails loudly. All four are in the check.
"""

import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference as R  # noqa: E402


def dequantise(mat, block=4096):
    """One int8 matrix to f32, a band of rows at a time.

    `reference.mv` scales by row, so row `i` of the real matrix is
    `data[i] * scales[i]`. Banded because the whole classifier at once is a
    622 MB temporary on top of the 622 MB result, and the peak is what decides
    whether this fits.
    """
    data, scales = mat
    rows, cols = data.shape
    out = np.empty((rows, cols), dtype=np.float32)
    for i in range(0, rows, block):
        j = min(i + block, rows)
        np.multiply(data[i:j], scales[i:j, None], out=out[i:j], dtype=np.float32)
    return out


def rms(x, weight, eps):
    """RMSNorm over the last axis, whatever leads it."""
    scale = np.sqrt((x * x).mean(axis=-1, keepdims=True) + eps)
    return (x / scale) * weight


def kv8_roundtrip(a, block=R.KV_BLOCK):
    """`reference.q8_roundtrip` over a whole batch at once.

    Same blocks, same peak-over-127 scale, same round-to-nearest and clip --
    the point of the cache round-trip is that the error here is the error the
    kernel has, so an approximation of it would be worth nothing.
    """
    shape = a.shape
    flat = a.reshape(-1, block)
    peak = np.abs(flat).max(axis=1, keepdims=True)
    scale = np.where(peak == 0, 1.0, peak / 127.0).astype(np.float32)
    out = np.rint(flat / scale).clip(-127, 127) * scale
    return out.reshape(shape).astype(np.float32)


class Dense:
    """A dense checkpoint, ready to answer `feed(ids) -> logits`."""

    def __init__(self, path, max_len, verbose=False):
        t0 = time.time()
        cfg, w = R.load(str(path))
        self.cfg = cfg
        self.max_len = max_len
        L = cfg["layers"]

        # Dequantised once. Every forward after this is BLAS on f32, which is
        # the whole of the speedup -- `mv` pays `astype` per call per layer per
        # token, and that cost is most of the oracle's runtime.
        self.embed = dequantise(w["embed"])
        # Tied embeddings are one array under two names. Sharing it rather than
        # dequantising twice saves 622 MB on this checkpoint.
        tied = w["wcls"][0] is w["embed"][0]
        self.wcls = self.embed if tied else dequantise(w["wcls"])

        self.wq = [dequantise(w["wq"][i]) for i in range(L)]
        self.wk = [dequantise(w["wk"][i]) for i in range(L)]
        self.wv = [dequantise(w["wv"][i]) for i in range(L)]
        self.wo = [dequantise(w["wo"][i]) for i in range(L)]
        self.w1 = [dequantise(w["w1"][i]) for i in range(L)]
        self.w2 = [dequantise(w["w2"][i]) for i in range(L)]
        self.w3 = [dequantise(w["w3"][i]) for i in range(L)]

        f32 = lambda v: np.asarray(v, dtype=np.float32)
        self.rms_att = [f32(w["rms_att"][i]) for i in range(L)]
        self.rms_ffn = [f32(w["rms_ffn"][i]) for i in range(L)]
        self.rms_final = f32(w["rms_final"])
        if cfg["qk_norm"]:
            self.q_norm = [f32(w["q_norm"][i]) for i in range(L)]
            self.k_norm = [f32(w["k_norm"][i]) for i in range(L)]

        hs = cfg["head_dim"]
        half = hs // 2
        idx = np.arange(half, dtype=np.float32)
        self.inv = (1.0 / (cfg["theta"] ** (2.0 * idx / hs))).astype(np.float32)

        self.kc = np.zeros((L, max_len, cfg["kv_dim"]), dtype=np.float32)
        self.vc = np.zeros((L, max_len, cfg["kv_dim"]), dtype=np.float32)
        self.pos = 0
        if verbose:
            gb = sum(
                a.nbytes
                for a in [self.embed, self.kc, self.vc]
                + self.wq + self.wk + self.wv + self.wo + self.w1 + self.w2 + self.w3
            ) / 1e9
            print(f"  loaded in {time.time() - t0:.1f}s, {gb:.2f} GB resident"
                  f"{', tied' if tied else ''}")

    def reset(self):
        self.pos = 0
        # Not cleared: the causal mask never looks past `pos`, so stale rows
        # cannot be read. Zeroing 470 MB per question would cost more than the
        # question.

    def _rope(self, x, positions):
        """`rotate_half` over `(T, heads, head_dim)`, in place."""
        hs = self.cfg["head_dim"]
        half = hs // 2
        ang = positions[:, None] * self.inv[None, :]
        cos = np.cos(ang).astype(np.float32)[:, None, :]
        sin = np.sin(ang).astype(np.float32)[:, None, :]
        a = x[..., :half].copy()
        b = x[..., half:].copy()
        x[..., :half] = a * cos - b * sin
        x[..., half:] = b * cos + a * sin
        return x

    def feed(self, ids):
        cfg = self.cfg
        ids = list(ids)
        T = len(ids)
        start, n = self.pos, self.pos + len(ids)
        if n > self.max_len:
            raise ValueError(f"{n} tokens into a {self.max_len} context")

        heads, kvh = cfg["heads"], cfg["kv_heads"]
        hs, eps = cfg["head_dim"], cfg["eps"]
        kv_mul = heads // kvh
        scale = np.float32(1.0 / np.sqrt(hs))
        positions = np.arange(start, n, dtype=np.float32)

        # The causal mask, once. Query `t` sits at absolute `start + t` and may
        # see every key up to and including itself -- which during a decode
        # step is the whole prefix, and during a prefill is a triangle.
        keys = np.arange(n)[None, :]
        allowed = keys <= (start + np.arange(T))[:, None]
        bias = np.where(allowed, np.float32(0.0), np.float32(-np.inf))

        x = self.embed[ids].astype(np.float32, copy=True)
        for li in range(cfg["layers"]):
            xb = rms(x, self.rms_att[li], eps)
            q = (xb @ self.wq[li].T).reshape(T, heads, hs)
            k = (xb @ self.wk[li].T).reshape(T, kvh, hs)
            v = xb @ self.wv[li].T

            if cfg["qk_norm"]:
                q = rms(q, self.q_norm[li], eps)
                k = rms(k, self.k_norm[li], eps)

            # Where the kernel's cache rounds, if it does: keys normed and
            # unrotated, values raw, both before RoPE.
            if cfg.get("kv8"):
                k = kv8_roundtrip(k)
                v = kv8_roundtrip(v)

            q = self._rope(q, positions)
            k = self._rope(k, positions)

            self.kc[li, start:n] = k.reshape(T, -1)
            self.vc[li, start:n] = v

            kc = self.kc[li, :n].reshape(n, kvh, hs)
            vc = self.vc[li, :n].reshape(n, kvh, hs)
            att = np.empty((T, heads, hs), dtype=np.float32)
            for h in range(heads):
                kh = h // kv_mul
                s = (q[:, h, :] @ kc[:, kh, :].T) * scale + bias
                s -= s.max(axis=-1, keepdims=True)
                np.exp(s, out=s)
                s /= s.sum(axis=-1, keepdims=True)
                att[:, h, :] = s @ vc[:, kh, :]

            x = x + att.reshape(T, -1) @ self.wo[li].T

            xb = rms(x, self.rms_ffn[li], eps)
            hb = xb @ self.w1[li].T
            hb2 = xb @ self.w3[li].T
            hb = hb / (1.0 + np.exp(-hb, dtype=np.float32)) * hb2  # SwiGLU
            x = x + hb @ self.w2[li].T

        self.pos = n
        # Only the last position's logits, which is all any caller here wants
        # and is 151,936 rows of classifier not run T times.
        return rms(x[-1], self.rms_final, eps) @ self.wcls.T


def check(path, tokens, chunk):
    """Both implementations, same ids, and the largest disagreement."""
    print(f"[fastdense] {Path(path).name}: {tokens} token(s), "
          f"prefill in one call of {chunk if chunk else tokens}")
    cfg, w = R.load(str(path))
    vocab = w["embed"][0].shape[0]
    rng = np.random.default_rng(20260916)
    ids = [int(v) for v in rng.integers(0, min(vocab, 30000), size=tokens)]

    t0 = time.time()
    slow = R.forward(cfg, w, ids, R.new_cache(cfg, tokens), 0)
    t_slow = time.time() - t0
    del w

    fast = Dense(path, max_len=tokens + 8, verbose=True)
    t0 = time.time()
    if chunk:
        # Fed in pieces, so the cache and the mask are exercised across calls
        # the way a prefill-then-decode actually uses them. A runner that is
        # only right in one call is right for no benchmark.
        out = None
        for i in range(0, tokens, chunk):
            out = fast.feed(ids[i:i + chunk])
    else:
        out = fast.feed(ids)
    t_fast = time.time() - t0

    d = np.abs(out - slow)
    print(f"  oracle {t_slow:8.2f}s      batched {t_fast:8.2f}s      "
          f"{t_slow / max(t_fast, 1e-9):.0f}x")
    print(f"  max |dlogit| {d.max():.3e}   mean {d.mean():.3e}")
    print(f"  argmax  oracle {int(np.argmax(slow))}  batched {int(np.argmax(out))}"
          f"   {'same' if np.argmax(slow) == np.argmax(out) else 'DIFFERENT'}")
    top = 5
    a = np.argsort(slow)[::-1][:top]
    b = np.argsort(out)[::-1][:top]
    print(f"  top-{top} order {'preserved' if list(a) == list(b) else 'CHANGED'}")

    # f32 accumulation in a different order gives a different last bit; what
    # must not move is which token wins, and a tolerance says so in a number
    # rather than in a hope.
    ok = np.argmax(slow) == np.argmax(out) and d.max() < 2e-2 and list(a) == list(b)
    print("  " + ("agrees with the oracle" if ok else "DOES NOT AGREE -- do not use"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--tokens", type=int, default=48)
    ap.add_argument("--chunk", type=int, default=0,
                    help="feed the prefill in pieces of this size, to exercise "
                         "the cache across calls")
    args = ap.parse_args()
    if not args.check:
        ap.error("nothing to do but --check; this module is imported to be used")
    raise SystemExit(check(args.model, args.tokens, args.chunk))


if __name__ == "__main__":
    main()
