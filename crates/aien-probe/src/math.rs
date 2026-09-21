//! Calibration primitives for the probe engine.
//!
//! These functions mirror the semantics of the Mojo SIMD helpers on the Grace Blackwell GB10
//! path (temperature scaling, entropy, projection) in plain Rust, so the engine stays
//! deterministic and testable without a device.

/// Scales a logit by a temperature.
///
/// A non positive or non finite temperature leaves the logit unchanged, matching the Mojo
/// `temperature_scale` contract. A non finite logit collapses to zero.
pub fn temperature_scale(logit: f64, temperature: f64) -> f64 {
    if !logit.is_finite() {
        return 0.0;
    }
    if !temperature.is_finite() || temperature <= 1.0e-4 {
        return logit;
    }
    let scaled = logit / temperature;
    if scaled.is_finite() {
        scaled
    } else {
        logit
    }
}

/// Numerically stable logistic function.
pub fn sigmoid(z: f64) -> f64 {
    if z.is_nan() {
        return 0.0;
    }
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

/// Numerically stable softmax over a slice of logits.
///
/// An empty slice yields an empty vector. A degenerate sum yields a uniform distribution.
pub fn softmax(logits: &[f64]) -> Vec<f64> {
    if logits.is_empty() {
        return Vec::new();
    }
    let max = logits.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let exps: Vec<f64> = logits.iter().map(|l| (l - max).exp()).collect();
    let sum: f64 = exps.iter().sum();
    if !sum.is_finite() || sum <= 0.0 {
        let uniform = 1.0 / logits.len() as f64;
        return vec![uniform; logits.len()];
    }
    exps.iter().map(|e| e / sum).collect()
}

/// Probability weighted mean of the level indices, a position on the ordered scale.
pub fn expected_value(probabilities: &[f64]) -> f64 {
    probabilities
        .iter()
        .enumerate()
        .map(|(level, p)| level as f64 * p)
        .sum()
}

/// Shannon entropy of a probability distribution in nats.
pub fn entropy(probabilities: &[f64]) -> f64 {
    probabilities
        .iter()
        .filter(|p| **p > 1.0e-12)
        .map(|p| -p * p.ln())
        .sum()
}

/// Confidence in a distribution: one minus entropy normalized by the uniform maximum.
pub fn confidence(probabilities: &[f64]) -> f64 {
    let n = probabilities.len();
    if n <= 1 {
        return 1.0;
    }
    let max_entropy = (n as f64).ln();
    if max_entropy <= 0.0 {
        return 1.0;
    }
    (1.0 - entropy(probabilities) / max_entropy).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temperature_scale_edges() {
        assert_eq!(temperature_scale(2.0, 0.5), 4.0);
        assert_eq!(temperature_scale(5.0, 0.0), 5.0);
        assert_eq!(temperature_scale(5.0, 0.00005), 5.0);
        assert_eq!(temperature_scale(f64::NAN, 1.0), 0.0);
        assert_eq!(temperature_scale(2.0, f64::INFINITY), 2.0);
    }

    #[test]
    fn test_sigmoid_symmetry() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1.0e-12);
        assert!((sigmoid(1.0) + sigmoid(-1.0) - 1.0).abs() < 1.0e-12);
        assert!(sigmoid(50.0) > 0.999);
        assert!(sigmoid(-50.0) < 0.001);
    }

    #[test]
    fn test_softmax_sums_to_one() {
        let probs = softmax(&[1.0, 2.0, 3.0, 4.0]);
        let sum: f64 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1.0e-12);
        assert!(softmax(&[]).is_empty());
        let uniform = softmax(&[0.0, 0.0, 0.0, 0.0]);
        for p in uniform {
            assert!((p - 0.25).abs() < 1.0e-12);
        }
    }

    #[test]
    fn test_expected_value_and_confidence() {
        let probs = vec![0.0, 0.0, 0.0, 1.0];
        assert!((expected_value(&probs) - 3.0).abs() < 1.0e-12);
        assert!((confidence(&probs) - 1.0).abs() < 1.0e-12);
        let flat = vec![0.25, 0.25, 0.25, 0.25];
        assert!((confidence(&flat)).abs() < 1.0e-12);
    }
}
