/// Constitutional hash computation.
///
/// Produces the same SHA-256 hash as `Constitution.model_post_init()` in Python:
///   canonical = "|".join(f"{r.id}:{r.text}:{r.severity}:{kw1,kw2,...}" for r in sorted(rules))
///   hash = sha256(canonical.encode()).hexdigest()[:16]
///
/// Constitutional Hash: 608508a9bd224290
use sha2::{Digest, Sha256};

/// Compute the constitutional hash from rule data.
///
/// `rules` is a list of `(rule_id, rule_text, severity_value, sorted_keywords)`.
/// Rules are sorted by rule_id before hashing (matching Python behavior).
/// Streams directly into the SHA-256 hasher without cloning rules or
/// allocating an intermediate canonical string.
pub fn compute_constitutional_hash(rules: &[(String, String, String, Vec<String>)]) -> String {
    let mut order: Vec<usize> = (0..rules.len()).collect();
    order.sort_by(|&a, &b| rules[a].0.cmp(&rules[b].0));

    let mut hasher = Sha256::new();
    let mut kw_refs: Vec<&str> = Vec::new();
    for (pos, &idx) in order.iter().enumerate() {
        if pos > 0 {
            hasher.update(b"|");
        }
        let (id, text, severity, keywords) = &rules[idx];
        hasher.update(id.as_bytes());
        hasher.update(b":");
        hasher.update(text.as_bytes());
        hasher.update(b":");
        hasher.update(severity.as_bytes());
        hasher.update(b":");

        kw_refs.clear();
        kw_refs.extend(keywords.iter().map(String::as_str));
        kw_refs.sort_unstable();
        for (ki, kw) in kw_refs.iter().enumerate() {
            if ki > 0 {
                hasher.update(b",");
            }
            hasher.update(kw.as_bytes());
        }
    }

    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_rules() {
        let rules: Vec<(String, String, String, Vec<String>)> = vec![];
        let hash = compute_constitutional_hash(&rules);
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_deterministic() {
        let rules = vec![(
            "R1".into(),
            "Test rule".into(),
            "high".into(),
            vec!["keyword".to_string()],
        )];
        assert_eq!(
            compute_constitutional_hash(&rules),
            compute_constitutional_hash(&rules),
        );
    }

    #[test]
    fn test_sort_order_invariant() {
        let rules_a = vec![
            ("B".into(), "rule b".into(), "high".into(), vec![]),
            ("A".into(), "rule a".into(), "low".into(), vec![]),
        ];
        let rules_b = vec![
            ("A".into(), "rule a".into(), "low".into(), vec![]),
            ("B".into(), "rule b".into(), "high".into(), vec![]),
        ];
        assert_eq!(
            compute_constitutional_hash(&rules_a),
            compute_constitutional_hash(&rules_b),
        );
    }

    #[test]
    fn test_matches_canonical_sha256_prefix() {
        let rules = vec![
            (
                "R2".into(),
                "Second".into(),
                "critical".into(),
                vec!["zeta".into(), "alpha".into()],
            ),
            (
                "R1".into(),
                "First".into(),
                "high".into(),
                vec!["beta".into()],
            ),
        ];
        let canonical = "R1:First:high:beta|R2:Second:critical:alpha,zeta";
        let expected = hex::encode(Sha256::digest(canonical.as_bytes()))[..16].to_string();
        assert_eq!(compute_constitutional_hash(&rules), expected);
    }
}
