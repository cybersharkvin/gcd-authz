use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InferenceCost {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(default)]
    pub cache_read_tokens: u32,
    #[serde(default)]
    pub cache_write_tokens: u32,
}

/// Wall-clock timing for an inference call, parsed from llama.cpp's `timings` block.
/// NOT `Eq` — holds `f64`. Accumulated across multi-turn agent loops.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct InferenceTimings {
    pub prompt_ms: f64,
    pub predicted_ms: f64,
    pub prompt_n: u32,
    pub predicted_n: u32,
}

impl InferenceTimings {
    /// Generation throughput (tokens/sec), derived from accumulated totals.
    /// Summing this field across turns would be wrong, so it is always derived.
    pub fn predicted_per_second(&self) -> f64 {
        if self.predicted_ms > 0.0 {
            self.predicted_n as f64 / (self.predicted_ms / 1000.0)
        } else {
            0.0
        }
    }

    /// Fold another turn's timings into this running total.
    pub fn accumulate(&mut self, o: &InferenceTimings) {
        self.prompt_ms += o.prompt_ms;
        self.predicted_ms += o.predicted_ms;
        self.prompt_n += o.prompt_n;
        self.predicted_n += o.predicted_n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_serde_round_trip() {
        let c = InferenceCost { input_tokens: 100, output_tokens: 50, cache_read_tokens: 10, cache_write_tokens: 5 };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<InferenceCost>(&json).unwrap(), c);
    }

    #[test]
    fn cost_default_cache_zero() {
        let c = InferenceCost::default();
        assert_eq!(c.cache_read_tokens, 0);
        assert_eq!(c.cache_write_tokens, 0);
    }

    #[test]
    fn cost_deserialize_without_cache_fields() {
        let json = r#"{"input_tokens":100,"output_tokens":50}"#;
        let c: InferenceCost = serde_json::from_str(json).unwrap();
        assert_eq!(c.cache_read_tokens, 0);
        assert_eq!(c.cache_write_tokens, 0);
    }

    #[test]
    fn timings_per_second_derived() {
        let t = InferenceTimings { prompt_ms: 0.0, predicted_ms: 1000.0, prompt_n: 0, predicted_n: 80 };
        assert_eq!(t.predicted_per_second(), 80.0);
    }

    #[test]
    fn timings_accumulate_sums() {
        let mut a = InferenceTimings { prompt_ms: 10.0, predicted_ms: 20.0, prompt_n: 1, predicted_n: 2 };
        a.accumulate(&InferenceTimings { prompt_ms: 5.0, predicted_ms: 5.0, prompt_n: 1, predicted_n: 3 });
        assert_eq!((a.prompt_ms, a.predicted_n), (15.0, 5));
    }

    #[test]
    fn timings_zero_predicted_ms_is_zero_rate() {
        assert_eq!(InferenceTimings::default().predicted_per_second(), 0.0);
    }
}
