//! A2 — embedding input classifier.
//!
//! Cosine-similarity denylist over a pre-embedded corpus of injection phrases,
//! scored against the Qwen3-Embedding service. A user message is blocked when its
//! max similarity to any denylist phrase exceeds the threshold (default 0.85).
//!
//! This is the server-side home of what used to be the Python harness's
//! `InputFilter`. The threshold and corpus are unchanged so results are comparable.

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ClassifierError {
    #[error("failed to read denylist vectors `{path}`: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("failed to parse denylist vectors: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("denylist is empty")]
    Empty,
    #[error("inconsistent embedding dimensions in denylist")]
    RaggedDims,
}

#[derive(Debug, Deserialize)]
struct DenyVec {
    #[allow(dead_code)]
    phrase: String,
    embedding: Vec<f32>,
}

/// L2-normalized denylist matrix + the embedding endpoint to score against.
/// Private fields — built only via `load`, which rejects an empty/ragged corpus.
pub struct EmbeddingClassifier {
    /// Each row is L2-normalized so a dot product with a normalized query == cosine.
    normalized: Vec<Vec<f32>>,
    dim: usize,
    threshold: f32,
    endpoint: String,
    model: String,
    http: reqwest::Client,
}

impl EmbeddingClassifier {
    /// Load `denylist_vectors.json` (`[{phrase, embedding:[f32]}]`) and pre-normalize.
    ///
    /// # Contract
    /// - denylist non-empty
    /// - every embedding has the same non-zero dimension
    pub fn load(path: &str, endpoint: String, model: String, threshold: f32) -> Result<Self, ClassifierError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ClassifierError::Io { path: path.into(), source })?;
        let vecs: Vec<DenyVec> = serde_json::from_str(&raw)?;
        if vecs.is_empty() {
            return Err(ClassifierError::Empty);
        }
        let dim = vecs[0].embedding.len();
        if dim == 0 || vecs.iter().any(|v| v.embedding.len() != dim) {
            return Err(ClassifierError::RaggedDims);
        }
        let normalized = vecs.into_iter().map(|v| normalize(v.embedding)).collect();
        Ok(Self { normalized, dim, threshold, endpoint, model, http: reqwest::Client::new() })
    }

    pub fn denylist_len(&self) -> usize {
        self.normalized.len()
    }

    /// Returns `true` if `text` should be BLOCKED (max cosine similarity > threshold).
    /// On any embedding-service error, fails OPEN (returns `false`) — matching the
    /// original harness behaviour so a flaky embedder can't silently inflate blocks.
    pub async fn is_blocked(&self, text: &str) -> bool {
        match self.max_similarity(text).await {
            Some(sim) => sim > self.threshold,
            None => false,
        }
    }

    async fn max_similarity(&self, text: &str) -> Option<f32> {
        let body = serde_json::json!({ "input": [text], "model": self.model });
        let resp = self.http.post(&self.endpoint).json(&body).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let json: serde_json::Value = resp.json().await.ok()?;
        let arr = json["data"][0]["embedding"].as_array()?;
        if arr.len() != self.dim {
            return None;
        }
        let query = normalize(arr.iter().map(|v| v.as_f64().unwrap_or(0.0) as f32).collect());
        let mut max = f32::MIN;
        for row in &self.normalized {
            let dot: f32 = row.iter().zip(&query).map(|(a, b)| a * b).sum();
            if dot > max {
                max = dot;
            }
        }
        Some(max)
    }
}

/// L2-normalize a vector (zero vector maps to itself).
fn normalize(mut v: Vec<f32>) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut v {
            *x /= norm;
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_unit_length() {
        let n = normalize(vec![3.0, 4.0]);
        assert!(((n[0] * n[0] + n[1] * n[1]) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn normalize_zero_vector_stays_zero() {
        assert_eq!(normalize(vec![0.0, 0.0]), vec![0.0, 0.0]);
    }
}
