//! Weight matrices that may be f32 or int8, read in place.
//!
//! The checkpoint is already in RAM when this runs -- `uefi::read_file` put it
//! in a LoaderData pool allocation before ExitBootServices, which the identity
//! map covers write-back. So nothing is copied: a `Mat` is a view into those
//! bytes. For a 135 MB model that saves both the copy and the 135 MB of heap
//! it would have needed.
//!
//! int8 data needs no alignment (`i8` is align 1), so the hot path casts
//! straight from the blob. The f32 side -- per-row scales, and the norm
//! weights -- is read with `from_le_bytes` instead of being cast, because a
//! misaligned `&[f32]` is undefined behaviour and the alignment of any
//! particular tensor is an accident of the shapes above it. Scales are read
//! once per output row rather than once per weight, so the cost is noise.
//!
//! Dequantisation is `sum(w[j] * x[j]) * scale[row]`, not
//! `sum(w[j] * scale * x[j])`: the scale is constant across the row, so it
//! belongs outside the loop. One multiply per output element instead of one
//! per weight.

use super::adapter::Dora;
use super::tensor;

#[derive(Clone)]
pub enum Mat<'a> {
    /// Row-major f32, `rows * cols` values.
    F32 { data: &'a [f32], rows: usize, cols: usize },
    /// Row-major int8 with one f32 scale per row.
    Q8 { data: &'a [i8], scales: &'a [u8], rows: usize, cols: usize },
    /// Row-major int4: two signed nibbles per byte (even column low, odd high),
    /// one f32 scale per 32-wide block. `data` is `rows*cols/2` bytes, `scales`
    /// is `rows*(cols/32)` little-endian f32. Serving only -- the training and
    /// adjoint paths refuse it, because a frozen base is all int4 is for.
    Q4 { data: &'a [u8], scales: &'a [u8], rows: usize, cols: usize },
}

/// Weights sharing one block scale. Named in three files; see model.rs.
pub const Q4_BLOCK: usize = 32;

/// Dequantise one int4 row into `out` (length `cols`).
///
/// Low nibble is the even column, high the odd, each two's-complement in
/// [-8, 7], times its block's f32 scale. The one function both kernels and the
/// row-dequant share, so a sign-extension bug -- the int4 version of "an
/// unsigned widen turns every negative weight into a large positive one" --
/// can only exist in one place.
#[inline]
pub fn q4_row(out: &mut [f32], packed: &[u8], scales: &[u8], cols: usize) {
    for c in 0..cols {
        let byte = packed[c >> 1];
        let nib = if c & 1 == 0 { byte & 0x0F } else { byte >> 4 };
        let signed = if nib >= 8 { nib as i32 - 16 } else { nib as i32 };
        let s = f32_at(scales, c / Q4_BLOCK);
        out[c] = signed as f32 * s;
    }
}

/// One matvec, described by pointers so a core that owns none of it can run
/// part of it.
///
/// Raw pointers rather than slices because this crosses to a core that has no
/// borrow of anything. It is sound because `parallel_rows` does not return
/// until every chunk has finished, so this struct -- which lives on the
/// caller's stack -- outlives every read of it.
/// 0 = f32, 1 = int8, 2 = int4. A byte rather than an enum only because it
/// crosses to a core with no borrow of the type; the values are the file's
/// quant tags so there is one numbering to remember.
#[derive(Clone, Copy)]
struct RowJob {
    kind: u8,
    data: *const u8,
    scales: *const u8,
    x: *const f32,
    out: *mut f32,
    cols: usize,
    avx: bool,
}

/// Rows `[lo, hi)` of the job at `ctx`.
///
/// # Safety
/// `ctx` must point at a live `RowJob` whose buffers cover `[lo, hi)`, and no
/// other core may hold the same range. `parallel_rows` guarantees both.
unsafe fn matvec_rows(ctx: usize, lo: usize, hi: usize) {
    let job = unsafe { *(ctx as *const RowJob) };
    let n = hi - lo;
    let out = unsafe { core::slice::from_raw_parts_mut(job.out.add(lo), n) };
    let x = unsafe { core::slice::from_raw_parts(job.x, job.cols) };
    match job.kind {
        1 => {
            let data = unsafe {
                core::slice::from_raw_parts((job.data as *const i8).add(lo * job.cols), n * job.cols)
            };
            // Four bytes of little-endian f32 per row, so the scale offset is a
            // row count times four and not times `cols`. Getting that wrong
            // reads a scale from the middle of another row and is silent.
            let scales = unsafe { core::slice::from_raw_parts(job.scales.add(lo * 4), n * 4) };
            if job.avx {
                unsafe { q8_matvec_avx2(out, x, data, scales, n, job.cols) }
            } else {
                q8_matvec_scalar(out, x, data, scales, n, job.cols)
            }
        }
        2 => {
            // int4: half a byte per weight, and one f32 scale per 32-block --
            // so the row offset is `lo * cols/2` and the scale offset is
            // `lo * (cols/32) * 4`, the two places the int8 arithmetic above
            // does not carry over unchanged.
            let nb = job.cols / Q4_BLOCK;
            let data = unsafe {
                core::slice::from_raw_parts(job.data.add(lo * job.cols / 2), n * job.cols / 2)
            };
            let scales = unsafe {
                core::slice::from_raw_parts(job.scales.add(lo * nb * 4), n * nb * 4)
            };
            if job.avx {
                unsafe { q4_matvec_avx2(out, x, data, scales, n, job.cols) }
            } else {
                q4_matvec_scalar(out, x, data, scales, n, job.cols)
            }
        }
        _ => {
            let data = unsafe {
                core::slice::from_raw_parts((job.data as *const f32).add(lo * job.cols), n * job.cols)
            };
            tensor::matmul(out, x, data, job.cols, n);
        }
    }
}

/// The batch (prefill) equivalent of `RowJob`.
///
/// Prefill is weight-stationary: a row of weights is read once and multiplied
/// against every token's activations in the same pass. That is what makes the
/// batch kernel worth having, and it is preserved under the split -- a core
/// handed rows `[lo, hi)` reads *its* slice of the weights once, for all
/// tokens, and no weight byte is read by two cores. So the split distributes
/// the compute without multiplying the memory traffic, which is the trap
/// CLAUDE.md warns a *per-token* split would fall into. Row-parallel avoids it
/// because output row `r` for every token depends only on weight row `r`.
///
/// `total_rows` is the output stride the workers must all agree on: the layout
/// is `out[t*total_rows + r]` for the whole matrix, so a worker owning a row
/// slice still writes at the full stride.
#[derive(Clone, Copy)]
struct BatchJob {
    kind: u8,
    data: *const u8,
    scales: *const u8,
    xs: *const f32,
    out: *mut f32,
    cols: usize,
    tc: usize,
    total_rows: usize,
    avx: bool,
}

/// Output rows `[lo, hi)` of a batch job, for every token.
///
/// # Safety
/// `ctx` must point at a live `BatchJob`; `parallel_split` guarantees it
/// outlives every call and that no two cores share a row range.
unsafe fn matvec_batch_rows(ctx: usize, lo: usize, hi: usize) {
    let job = unsafe { *(ctx as *const BatchJob) };
    let n = hi - lo;
    // The whole output is addressed, because a worker writes scattered slots
    // `out[t*total_rows + r]` across the token dimension. `parallel_split`
    // keeps the row ranges disjoint, so no two workers touch the same slot.
    let out = unsafe {
        core::slice::from_raw_parts_mut(job.out, job.tc * job.total_rows)
    };
    let xs = unsafe { core::slice::from_raw_parts(job.xs, job.tc * job.cols) };
    // Offset the weights and scales to this worker's first row, exactly as
    // `matvec_rows` does -- the same "scales are four bytes, not `cols`"
    // arithmetic, and the same way to get it silently wrong.
    if job.kind == 2 {
        let nb = job.cols / Q4_BLOCK;
        let data = unsafe {
            core::slice::from_raw_parts(job.data.add(lo * job.cols / 2), n * job.cols / 2)
        };
        let scales = unsafe {
            core::slice::from_raw_parts(job.scales.add(lo * nb * 4), n * nb * 4)
        };
        if job.avx {
            unsafe {
                q4_matvec_batch_avx2(out, xs, data, scales, n, job.cols, job.tc, job.total_rows, lo)
            }
        } else {
            q4_matvec_batch_scalar(out, xs, data, scales, n, job.cols, job.tc, job.total_rows, lo);
        }
        return;
    }
    let data = unsafe {
        core::slice::from_raw_parts((job.data as *const i8).add(lo * job.cols), n * job.cols)
    };
    let scales = unsafe { core::slice::from_raw_parts(job.scales.add(lo * 4), n * 4) };
    if job.avx {
        unsafe {
            q8_matvec_batch_avx2(out, xs, data, scales, n, job.cols, job.tc, job.total_rows, lo)
        }
    } else {
        q8_matvec_batch_scalar(out, xs, data, scales, n, job.cols, job.tc, job.total_rows, lo);
    }
}

#[inline]
pub fn f32_at(bytes: &[u8], i: usize) -> f32 {
    let o = i * 4;
    f32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
}

impl Mat<'_> {
    /// Frozen matvec followed by the site's QDoRA wrapper. Kept beside
    /// `matvec` so an adapted projection reads as one operation at every
    /// call site, and so the two halves cannot drift apart silently.
    pub fn wrap_matvec(&self, d: &Dora, x: &[f32], ax: &mut [f32], out: &mut [f32]) {
        self.matvec(out, x);
        d.apply(out, x, ax);
    }

    /// `out = self * x`. `out` must have `rows` entries, `x` must have `cols`.
    ///
    /// Split across every core when there is enough of it to be worth the
    /// handshake. This one function is where a token's gigabyte of weights
    /// actually gets read, so it is the whole of what the other cores are for:
    /// every projection in every layer, plus the classifier, arrives here.
    ///
    /// Row-parallel, which needs no new arithmetic. `out[o]` depends on row
    /// `o` of the weights and on all of `x`, and on nothing else -- so a core
    /// handed rows `[lo, hi)` runs the *same* kernel over `data[lo*cols..]`
    /// and `scales[lo*4..]` and writes `out[lo..hi]`. There is no reduction
    /// and no shared accumulator, which is why this is worth doing and why it
    /// needs no locking.
    pub fn matvec(&self, out: &mut [f32], x: &[f32]) {
        let (rows, cols) = match self {
            Mat::F32 { rows, cols, .. } => (*rows, *cols),
            Mat::Q8 { rows, cols, .. } => (*rows, *cols),
            Mat::Q4 { rows, cols, .. } => (*rows, *cols),
        };
        let job = RowJob {
            kind: match self {
                Mat::F32 { .. } => 0,
                Mat::Q8 { .. } => 1,
                Mat::Q4 { .. } => 2,
            },
            data: match self {
                Mat::F32 { data, .. } => data.as_ptr() as *const u8,
                Mat::Q8 { data, .. } => data.as_ptr() as *const u8,
                Mat::Q4 { data, .. } => data.as_ptr(),
            },
            scales: match self {
                Mat::F32 { .. } => core::ptr::null(),
                Mat::Q8 { scales, .. } => scales.as_ptr(),
                Mat::Q4 { scales, .. } => scales.as_ptr(),
            },
            x: x.as_ptr(),
            out: out.as_mut_ptr(),
            cols,
            // Decided here and carried, rather than read per chunk: an
            // application processor reads no kernel state, and `detected()`
            // is kernel state.
            avx: {
                let f = crate::cpu::detected();
                f.avx_enabled && f.avx2 && f.fma
            },
        };
        if crate::smp::parallel_split(
            &job as *const RowJob as usize,
            matvec_rows,
            rows,
            cols,
        ) {
            return;
        }
        match self {
            Mat::F32 { data, rows, cols } => {
                tensor::matmul(&mut out[..*rows], &x[..*cols], data, *cols, *rows)
            }
            Mat::Q8 { data, scales, rows, cols } => {
                let f = crate::cpu::detected();
                // All three, and `avx2` is not optional: the kernel below is
                // `target_feature(avx2,fma)` and uses `_mm256_cvtepi8_epi32`,
                // which is an AVX2 instruction. Gating on AVX alone would take
                // a #UD on any part with AVX and FMA but no AVX2 -- AMD's
                // Piledriver, for one. `avx_enabled` is separate again and
                // means the OS has actually set CR4.OSXSAVE and XCR0, without
                // which every one of these faults regardless of what CPUID
                // advertises.
                if f.avx_enabled && f.avx2 && f.fma {
                    unsafe { q8_matvec_avx2(out, x, data, scales, *rows, *cols) }
                } else {
                    q8_matvec_scalar(out, x, data, scales, *rows, *cols)
                }
            }
            Mat::Q4 { data, scales, rows, cols } => {
                let f = crate::cpu::detected();
                if f.avx_enabled && f.avx2 && f.fma {
                    unsafe { q4_matvec_avx2(out, x, data, scales, *rows, *cols) }
                } else {
                    q4_matvec_scalar(out, x, data, scales, *rows, *cols)
                }
            }
        }
    }

    /// Copy row `r` out as f32. Used for the embedding lookup, which is a row
    /// fetch rather than a matrix-vector product.
    pub fn row_into(&self, r: usize, out: &mut [f32]) {
        match self {
            Mat::F32 { data, cols, .. } => {
                out[..*cols].copy_from_slice(&data[r * cols..(r + 1) * cols]);
            }
            Mat::Q8 { data, scales, cols, .. } => {
                let s = f32_at(scales, r);
                let row = &data[r * cols..(r + 1) * cols];
                for (o, v) in out[..*cols].iter_mut().zip(row.iter()) {
                    *o = *v as f32 * s;
                }
            }
            Mat::Q4 { data, scales, cols, .. } => {
                let rb = cols / 2;
                let nb = cols / Q4_BLOCK;
                q4_row(
                    &mut out[..*cols],
                    &data[r * rb..(r + 1) * rb],
                    &scales[r * nb * 4..(r + 1) * nb * 4],
                    *cols,
                );
            }
        }
    }

    /// `out[t*rows + r] = row r . xs[t*cols ..]` for `tc` input rows.
    ///
    /// The whole point of this shape is what crosses the memory bus once:
    /// prefilled as `tc` separate matvecs, a prompt of N tokens streams every
    /// weight byte N times, which under TCG means re-translating the same
    /// 132 MiB of working set N times and on hardware means paying DRAM
    /// bandwidth N times for weights that were already in cache the second
    /// time around. Row-major outer order streams each weight row once and
    /// reuses it against every input row while it is hot; per output element
    /// the additions still run over `j` ascending into one accumulator, so
    /// results are bit-identical to calling `matvec` per position.
    pub fn matvec_batch(&self, out: &mut [f32], xs: &[f32], tc: usize) {
        match self {
            Mat::F32 { data, rows, cols } => {
                // Flat checkpoints are the tiny llama2.c test models; their
                // f32 path never got a weight-stationary kernel because there
                // was nothing for it to save. Per-position reuse keeps one
                // code path for the arithmetic.
                for t in 0..tc {
                    let x = &xs[t * *cols..(t + 1) * *cols];
                    let o = &mut out[t * *rows..(t + 1) * *rows];
                    tensor::matmul(o, x, data, *cols, *rows);
                }
            }
            Mat::Q8 { data, scales, rows, cols } => {
                let f = crate::cpu::detected();
                // Same gate as `matvec`: AVX2 is not optional (see above), and
                // `avx_enabled` means the OS actually enabled the state.
                let avx = f.avx_enabled && f.avx2 && f.fma;
                // Prefill was the one heavy path left on a single core, which is
                // why the first token of a conversation cost the whole system
                // turn at one core's pace. It splits like `matvec` does, by
                // output row, and the same threshold decides whether the
                // handshake is worth it -- here the per-row work is `cols * tc`,
                // since each row is dotted against every token.
                let job = BatchJob {
                    kind: 1,
                    data: data.as_ptr() as *const u8,
                    scales: scales.as_ptr(),
                    xs: xs.as_ptr(),
                    out: out.as_mut_ptr(),
                    cols: *cols,
                    tc,
                    total_rows: *rows,
                    avx,
                };
                if crate::smp::parallel_split(
                    &job as *const BatchJob as usize,
                    matvec_batch_rows,
                    *rows,
                    cols.saturating_mul(tc),
                ) {
                    return;
                }
                if avx {
                    unsafe { q8_matvec_batch_avx2(out, xs, data, scales, *rows, *cols, tc, *rows, 0) }
                } else {
                    q8_matvec_batch_scalar(out, xs, data, scales, *rows, *cols, tc, *rows, 0)
                }
            }
            Mat::Q4 { data, scales, rows, cols } => {
                let f = crate::cpu::detected();
                let avx = f.avx_enabled && f.avx2 && f.fma;
                let job = BatchJob {
                    kind: 2,
                    data: data.as_ptr(),
                    scales: scales.as_ptr(),
                    xs: xs.as_ptr(),
                    out: out.as_mut_ptr(),
                    cols: *cols,
                    tc,
                    total_rows: *rows,
                    avx,
                };
                if crate::smp::parallel_split(
                    &job as *const BatchJob as usize,
                    matvec_batch_rows,
                    *rows,
                    cols.saturating_mul(tc),
                ) {
                    return;
                }
                if avx {
                    unsafe { q4_matvec_batch_avx2(out, xs, data, scales, *rows, *cols, tc, *rows, 0) }
                } else {
                    q4_matvec_batch_scalar(out, xs, data, scales, *rows, *cols, tc, *rows, 0)
                }
            }
        }
    }
}

pub fn q8_matvec_scalar(
    out: &mut [f32],
    x: &[f32],
    data: &[i8],
    scales: &[u8],
    rows: usize,
    cols: usize,
) {
    for r in 0..rows {
        let row = &data[r * cols..(r + 1) * cols];
        let mut acc = 0.0f32;
        for j in 0..cols {
            acc += row[j] as f32 * x[j];
        }
        out[r] = acc * f32_at(scales, r);
    }
}

/// AVX2 int8 matrix-vector.
///
/// Sixteen weights per iteration: a 128-bit load of int8, widened to i32 in
/// two 256-bit registers, converted to f32, then two FMAs against x. The
/// widening is the expensive part and is why this is nowhere near sixteen
/// times the scalar version -- but the memory traffic is a quarter of f32's,
/// and that is what actually bounds generation.
///
/// # Safety
/// Requires AVX2 and FMA. Callers check `cpu::detected()`.
#[target_feature(enable = "avx2,fma")]
pub unsafe fn q8_matvec_avx2(
    out: &mut [f32],
    x: &[f32],
    data: &[i8],
    scales: &[u8],
    rows: usize,
    cols: usize,
) {
    use core::arch::x86_64::*;

    for r in 0..rows {
        let row = &data[r * cols..(r + 1) * cols];
        let mut acc0 = _mm256_setzero_ps();
        let mut acc1 = _mm256_setzero_ps();

        let chunks = cols / 16;
        for c in 0..chunks {
            let base = c * 16;
            let packed = _mm_loadu_si128(row.as_ptr().add(base) as *const __m128i);
            // Sign-extend: cvtepi8_epi32 takes the low 8 bytes, so the high
            // half is shifted down first. Using an unsigned widen here would
            // turn every negative weight into a large positive one, which
            // looks like a plausible model that generates nonsense.
            let lo = _mm256_cvtepi8_epi32(packed);
            let hi = _mm256_cvtepi8_epi32(_mm_srli_si128(packed, 8));
            let lof = _mm256_cvtepi32_ps(lo);
            let hif = _mm256_cvtepi32_ps(hi);
            let x0 = _mm256_loadu_ps(x.as_ptr().add(base));
            let x1 = _mm256_loadu_ps(x.as_ptr().add(base + 8));
            acc0 = _mm256_fmadd_ps(lof, x0, acc0);
            acc1 = _mm256_fmadd_ps(hif, x1, acc1);
        }

        let sum = _mm256_add_ps(acc0, acc1);
        let mut lanes = [0.0f32; 8];
        _mm256_storeu_ps(lanes.as_mut_ptr(), sum);
        let mut total = lanes.iter().sum::<f32>();

        // Ragged tail. Every dimension in the models here is a multiple of 16,
        // so this is usually dead -- which is exactly why it has to be correct
        // rather than merely present.
        for j in chunks * 16..cols {
            total += row[j] as f32 * x[j];
        }

        out[r] = total * f32_at(scales, r);
    }
}

/// int4 matvec, scalar -- the oracle the AVX2 version is checked against.
///
/// One row is `cols/2` packed bytes and `cols/32` block scales. The dequant is
/// `q4_row`'s, kept in one place so a sign bug lives in one place.
pub fn q4_matvec_scalar(
    out: &mut [f32],
    x: &[f32],
    data: &[u8],
    scales: &[u8],
    rows: usize,
    cols: usize,
) {
    let row_bytes = cols / 2;
    let nb = cols / Q4_BLOCK;
    for r in 0..rows {
        let packed = &data[r * row_bytes..(r + 1) * row_bytes];
        let rsc = &scales[r * nb * 4..(r + 1) * nb * 4];
        let mut acc = 0.0f32;
        for c in 0..cols {
            let byte = packed[c >> 1];
            let nib = if c & 1 == 0 { byte & 0x0F } else { byte >> 4 };
            let signed = if nib >= 8 { nib as i32 - 16 } else { nib as i32 };
            acc += signed as f32 * f32_at(rsc, c / Q4_BLOCK) * x[c];
        }
        out[r] = acc;
    }
}

/// int4 matvec, AVX2.
///
/// Sixteen columns per iteration, which is half a 32-block, so the block scale
/// is constant across a chunk and loaded once. Eight packed bytes hold the
/// sixteen nibbles as (low, high) pairs by column; `unpacklo` interleaves them
/// back into column order, and the sign extension is `(n ^ 8) - 8`, which maps
/// 0..15 to -8..7 in one xor and one subtract -- the SIMD form of the scalar
/// `if nib >= 8 { nib - 16 }`.
///
/// # Safety
/// Requires AVX2 and FMA. Callers check `cpu::detected()`.
#[target_feature(enable = "avx2,fma")]
pub unsafe fn q4_matvec_avx2(
    out: &mut [f32],
    x: &[f32],
    data: &[u8],
    scales: &[u8],
    rows: usize,
    cols: usize,
) {
    use core::arch::x86_64::*;
    let row_bytes = cols / 2;
    let nb = cols / Q4_BLOCK;
    let mask = _mm_set1_epi8(0x0F);
    let eight = _mm_set1_epi8(8);
    let chunks = cols / 16;

    for r in 0..rows {
        let packed = data.as_ptr().add(r * row_bytes);
        let rsc = &scales[r * nb * 4..(r + 1) * nb * 4];
        let mut acc0 = _mm256_setzero_ps();
        let mut acc1 = _mm256_setzero_ps();

        for ch in 0..chunks {
            // Eight bytes -> sixteen nibbles. Low nibble is the even column,
            // high the odd, so unpacklo(lo,hi) restores column order.
            let bytes = _mm_loadl_epi64(packed.add(ch * 8) as *const __m128i);
            let lo = _mm_and_si128(bytes, mask);
            let hi = _mm_and_si128(_mm_srli_epi16(bytes, 4), mask);
            let inter = _mm_unpacklo_epi8(lo, hi);
            // (n ^ 8) - 8: 0..15 -> -8..7.
            let signed = _mm_sub_epi8(_mm_xor_si128(inter, eight), eight);
            // Widen the sixteen int8 to two lanes of f32, as the int8 kernel does.
            let w0 = _mm256_cvtepi32_ps(_mm256_cvtepi8_epi32(signed));
            let w1 = _mm256_cvtepi32_ps(_mm256_cvtepi8_epi32(_mm_srli_si128(signed, 8)));
            // One block scale for the whole chunk (16 cols, block is 32).
            let s = _mm256_set1_ps(f32_at(rsc, (ch * 16) / Q4_BLOCK));
            let w0 = _mm256_mul_ps(w0, s);
            let w1 = _mm256_mul_ps(w1, s);
            let x0 = _mm256_loadu_ps(x.as_ptr().add(ch * 16));
            let x1 = _mm256_loadu_ps(x.as_ptr().add(ch * 16 + 8));
            acc0 = _mm256_fmadd_ps(w0, x0, acc0);
            acc1 = _mm256_fmadd_ps(w1, x1, acc1);
        }

        let sum = _mm256_add_ps(acc0, acc1);
        let mut lanes = [0.0f32; 8];
        _mm256_storeu_ps(lanes.as_mut_ptr(), sum);
        let mut total = lanes.iter().sum::<f32>();
        // Ragged tail; cols are multiples of 32 in every model here, so dead.
        for c in chunks * 16..cols {
            let byte = *packed.add(c >> 1);
            let nib = if c & 1 == 0 { byte & 0x0F } else { byte >> 4 };
            let signed = if nib >= 8 { nib as i32 - 16 } else { nib as i32 };
            total += signed as f32 * f32_at(rsc, c / Q4_BLOCK) * x[c];
        }
        out[r] = total;
    }
}

/// int4 weight-stationary batch, scalar. One block of nibbles read once, dotted
/// against every token. Writes `out[t*out_stride + row_base + r]`, the split's
/// scattered layout; single-core passes `(rows, 0)`.
pub fn q4_matvec_batch_scalar(
    out: &mut [f32],
    xs: &[f32],
    data: &[u8],
    scales: &[u8],
    rows: usize,
    cols: usize,
    tc: usize,
    out_stride: usize,
    row_base: usize,
) {
    let row_bytes = cols / 2;
    let nb = cols / Q4_BLOCK;
    let mut w = alloc::vec![0.0f32; cols];
    for r in 0..rows {
        let packed = &data[r * row_bytes..(r + 1) * row_bytes];
        let rsc = &scales[r * nb * 4..(r + 1) * nb * 4];
        q4_row(&mut w, packed, rsc, cols);
        for tk in 0..tc {
            let x = &xs[tk * cols..(tk + 1) * cols];
            let mut acc = 0.0f32;
            for c in 0..cols {
                acc += w[c] * x[c];
            }
            out[tk * out_stride + row_base + r] = acc;
        }
    }
}

/// int4 weight-stationary batch, AVX2. Dequantises a row once into a reused
/// scratch, then a plain f32 dot per token -- the dequant, not the dot, is what
/// the batch saves by hoisting, and unpacking sixteen nibbles per token would
/// throw that saving away.
///
/// # Safety
/// Requires AVX2 and FMA. Callers check `cpu::detected()`.
#[target_feature(enable = "avx2,fma")]
pub unsafe fn q4_matvec_batch_avx2(
    out: &mut [f32],
    xs: &[f32],
    data: &[u8],
    scales: &[u8],
    rows: usize,
    cols: usize,
    tc: usize,
    out_stride: usize,
    row_base: usize,
) {
    use core::arch::x86_64::*;
    let row_bytes = cols / 2;
    let nb = cols / Q4_BLOCK;
    let mut w = alloc::vec![0.0f32; cols];
    let chunks = cols / 16;
    for r in 0..rows {
        let packed = &data[r * row_bytes..(r + 1) * row_bytes];
        let rsc = &scales[r * nb * 4..(r + 1) * nb * 4];
        q4_row(&mut w, packed, rsc, cols);
        for tk in 0..tc {
            let x = xs.as_ptr().add(tk * cols);
            let mut a0 = _mm256_setzero_ps();
            let mut a1 = _mm256_setzero_ps();
            for ch in 0..chunks {
                let base = ch * 16;
                a0 = _mm256_fmadd_ps(
                    _mm256_loadu_ps(w.as_ptr().add(base)),
                    _mm256_loadu_ps(x.add(base)),
                    a0,
                );
                a1 = _mm256_fmadd_ps(
                    _mm256_loadu_ps(w.as_ptr().add(base + 8)),
                    _mm256_loadu_ps(x.add(base + 8)),
                    a1,
                );
            }
            let sum = _mm256_add_ps(a0, a1);
            let mut lanes = [0.0f32; 8];
            _mm256_storeu_ps(lanes.as_mut_ptr(), sum);
            let mut total = lanes.iter().sum::<f32>();
            for c in chunks * 16..cols {
                total += w[c] * xs[tk * cols + c];
            }
            out[tk * out_stride + row_base + r] = total;
        }
    }
}

/// Weight-stationary batch of [`q8_matvec_scalar`]: row-major outer loop, one
/// accumulator per input position, additions over `j` ascending -- the same
/// order, so the same bits, as the per-position kernel.
pub fn q8_matvec_batch_scalar(
    out: &mut [f32],
    xs: &[f32],
    data: &[i8],
    scales: &[u8],
    rows: usize,
    cols: usize,
    tc: usize,
    out_stride: usize,
    row_base: usize,
) {
    for r in 0..rows {
        let row = &data[r * cols..(r + 1) * cols];
        let scale = f32_at(scales, r);
        for t in 0..tc {
            let x = &xs[t * cols..(t + 1) * cols];
            let mut acc = 0.0f32;
            for j in 0..cols {
                acc += row[j] as f32 * x[j];
            }
            out[t * out_stride + row_base + r] = acc * scale;
        }
    }
}

/// Weight-stationary batch of [`q8_matvec_avx2`].
///
/// The lane structure per (row, position) is exactly the single-position
/// kernel's -- two accumulators over 16-wide chunks, horizontal add, ragged
/// tail -- so results match it bit for bit. What is hoisted is nothing that
/// changes that order: the weight bytes are walked once per row instead of
/// once per row per position.
///
/// # Safety
/// Requires AVX2 and FMA. Callers check `cpu::detected()`.
/// `out_stride` and `row_base` exist for the row-split: a core handed rows
/// `[lo, hi)` is given `data`/`scales` already offset to `lo`, so it counts its
/// own rows from zero, but the output layout is `out[t*total_rows + r]` for the
/// *whole* matrix -- so it must write at `t*out_stride + row_base + r`. The
/// single-core caller passes `out_stride = rows, row_base = 0` and the
/// arithmetic collapses to what it was.
#[target_feature(enable = "avx2,fma")]
pub unsafe fn q8_matvec_batch_avx2(
    out: &mut [f32],
    xs: &[f32],
    data: &[i8],
    scales: &[u8],
    rows: usize,
    cols: usize,
    tc: usize,
    out_stride: usize,
    row_base: usize,
) {
    use core::arch::x86_64::*;

    for r in 0..rows {
        let row = &data[r * cols..(r + 1) * cols];
        let scale = f32_at(scales, r);
        let chunks = cols / 16;
        for t in 0..tc {
            let x = &xs[t * cols..(t + 1) * cols];
            let mut acc0 = _mm256_setzero_ps();
            let mut acc1 = _mm256_setzero_ps();

            for c in 0..chunks {
                let base = c * 16;
                let packed = _mm_loadu_si128(row.as_ptr().add(base) as *const __m128i);
                let lo = _mm256_cvtepi8_epi32(packed);
                let hi = _mm256_cvtepi8_epi32(_mm_srli_si128(packed, 8));
                let lof = _mm256_cvtepi32_ps(lo);
                let hif = _mm256_cvtepi32_ps(hi);
                let x0 = _mm256_loadu_ps(x.as_ptr().add(base));
                let x1 = _mm256_loadu_ps(x.as_ptr().add(base + 8));
                acc0 = _mm256_fmadd_ps(lof, x0, acc0);
                acc1 = _mm256_fmadd_ps(hif, x1, acc1);
            }

            let sum = _mm256_add_ps(acc0, acc1);
            let mut lanes = [0.0f32; 8];
            _mm256_storeu_ps(lanes.as_mut_ptr(), sum);
            let mut total = lanes.iter().sum::<f32>();

            for j in chunks * 16..cols {
                total += row[j] as f32 * x[j];
            }

            out[t * out_stride + row_base + r] = total * scale;
        }
    }
}
