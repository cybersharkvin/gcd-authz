//! Statistics for the Galloway-ported result: exact (Clopper-Pearson) binomial
//! confidence intervals and overhead percentiles. The *formal* soundness
//! argument — not the sample — licenses "eliminates the class"; these report the
//! empirical leak/block rates honestly (a `0/n` block gets a real CI, not 0%).
//!
//! Self-contained (no statistics crate) for reproducibility: `lgamma` (Lanczos),
//! the regularized incomplete beta `I_x(a,b)` (Numerical-Recipes continued
//! fraction), and its inverse by bisection.

/// log Γ(x) via the Lanczos approximation (g = 7).
fn lgamma(x: f64) -> f64 {
    // Standard Lanczos g=7 coefficients (written at full published precision).
    #[allow(clippy::excessive_precision)]
    const G: [f64; 9] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        // Reflection: Γ(x)Γ(1-x) = π / sin(πx).
        (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - lgamma(1.0 - x)
    } else {
        let x = x - 1.0;
        let mut a = G[0];
        let t = x + 7.5;
        for (i, &g) in G.iter().enumerate().skip(1) {
            a += g / (x + i as f64);
        }
        0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
    }
}

/// Continued fraction for the incomplete beta (Lentz's method).
fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const MAXIT: usize = 200;
    const EPS: f64 = 3.0e-12;
    const FPMIN: f64 = 1.0e-30;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=MAXIT {
        let m = m as f64;
        let m2 = 2.0 * m;
        let mut aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// The regularized incomplete beta function `I_x(a, b)`.
fn betai(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let bt = (lgamma(a + b) - lgamma(a) - lgamma(b) + a * x.ln() + b * (1.0 - x).ln()).exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * betacf(a, b, x) / a
    } else {
        1.0 - bt * betacf(b, a, 1.0 - x) / b
    }
}

/// Inverse of `betai` in `x` (monotone increasing) by bisection.
fn betainv(p: f64, a: f64, b: f64) -> f64 {
    let (mut lo, mut hi) = (0.0_f64, 1.0_f64);
    for _ in 0..100 {
        let mid = 0.5 * (lo + hi);
        if betai(a, b, mid) < p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

/// Clopper-Pearson exact 95% confidence interval for `k` successes in `n` trials.
pub fn clopper_pearson(k: u32, n: u32) -> (f64, f64) {
    debug_assert!(k <= n, "successes cannot exceed trials");
    if n == 0 {
        return (0.0, 1.0);
    }
    let (k, n) = (k as f64, n as f64);
    let alpha = 0.05;
    let lower = if k == 0.0 { 0.0 } else { betainv(alpha / 2.0, k, n - k + 1.0) };
    let upper = if k == n { 1.0 } else { betainv(1.0 - alpha / 2.0, k + 1.0, n - k) };
    (lower, upper)
}

/// The rule-of-three upper bound (`≈ 3/n`) for a `0/n` observation at 95%.
pub fn rule_of_three_upper(n: u32) -> f64 {
    if n == 0 {
        1.0
    } else {
        3.0 / n as f64
    }
}

/// `k / n` as a rate (0 when `n == 0`).
pub fn rate(k: u32, n: u32) -> f64 {
    if n == 0 {
        0.0
    } else {
        k as f64 / n as f64
    }
}

/// The `q`-th percentile (`q` in `[0, 100]`) of `values` by linear interpolation
/// (type-7). Returns `0.0` for an empty input.
pub fn percentile(values: &[f64], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if v.len() == 1 {
        return v[0];
    }
    let rank = (q / 100.0) * (v.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let frac = rank - lo as f64;
    v[lo] + frac * (v[hi] - v[lo])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp_zero_of_30_matches_known_upper() {
        let (lo, hi) = clopper_pearson(0, 30);
        assert!(lo == 0.0 && (hi - 0.1158).abs() < 0.002);
    }

    #[test]
    fn cp_zero_of_300_is_about_one_percent() {
        let (_, hi) = clopper_pearson(0, 300);
        assert!((hi - 0.0122).abs() < 0.001);
    }

    #[test]
    fn cp_half_is_symmetric() {
        let (lo, hi) = clopper_pearson(15, 30);
        assert!(lo < 0.5 && hi > 0.5 && ((lo + hi) - 1.0).abs() < 0.02);
    }

    #[test]
    fn rule_of_three_thirty() {
        assert!((rule_of_three_upper(30) - 0.1).abs() < 1e-9);
    }

    #[test]
    fn percentile_interpolates() {
        let v = [10.0, 20.0, 30.0, 40.0];
        assert!((percentile(&v, 50.0) - 25.0).abs() < 1e-9 && (percentile(&v, 90.0) - 37.0).abs() < 1e-9);
    }
}
