/// Context processing for governance validation.
///
/// Handles `action_detail` and `action_description` context keys,
/// matching them against rules with positive-verb-skip logic.
///
/// Constitutional Hash: 608508a9bd224290
use crate::result::Violation;
use crate::severity::Severity;
use crate::verbs;
use regex::Regex;

/// Per-rule data needed for context matching.
#[derive(Clone)]
pub struct ContextRule {
    pub rule_id: String,
    pub rule_text: String,
    pub severity: Severity,
    pub category: String,
    pub keywords_lower: Vec<String>,
    pub compiled_patterns: Vec<Regex>,
    pub enabled: bool,
}

/// Process context key-value pairs against rules.
///
/// Only processes `action_detail` and `action_description` keys.
/// Implements the same matching logic as `Rule.matches_with_signals()` in Python.
pub fn process_context(
    context_pairs: &[(String, String)],
    rules: &[ContextRule],
) -> Vec<Violation> {
    let mut violations = Vec::new();

    for (key, value) in context_pairs {
        if key != "action_detail" && key != "action_description" {
            continue;
        }

        let val_lower = value.to_lowercase();
        let has_neg = verbs::has_negative_verb(&val_lower);
        // Python checks first 4 words for positive verbs (constitution.py:190)
        let has_pos = if has_neg {
            false
        } else {
            val_lower
                .split_whitespace()
                .take(4)
                .any(|w| verbs::POSITIVE_VERBS.contains(w))
        };

        for rule in rules {
            if !rule.enabled {
                continue;
            }
            if matches_with_signals(rule, &val_lower, has_neg, has_pos) {
                // Safe UTF-8 truncation in O(min(len, 100)) without an extra String alloc.
                let matched_content = match value.char_indices().nth(100) {
                    Some((byte_idx, _)) => format!("context[{}]: {}...", key, &value[..byte_idx]),
                    None => format!("context[{}]: {}", key, value),
                };
                violations.push(Violation {
                    rule_idx: 0, // context violations don't have a rule_idx in the _rule_data sense
                    rule_id: rule.rule_id.clone(),
                    rule_text: rule.rule_text.clone(),
                    severity: rule.severity,
                    matched_content,
                    category: rule.category.clone(),
                });
            }
        }
    }

    violations
}

/// Rust implementation of `Rule.matches_with_signals()`.
fn matches_with_signals(
    rule: &ContextRule,
    text_lower: &str,
    has_neg: bool,
    has_pos: bool,
) -> bool {
    for kw in &rule.keywords_lower {
        if text_lower.contains(kw.as_str()) {
            if has_pos && !has_neg && !verbs::keyword_has_negative(kw) {
                continue;
            }
            return true;
        }
    }

    rule.compiled_patterns
        .iter()
        .any(|pat| pat.is_match(text_lower))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(keywords: &[&str], patterns: &[&str]) -> ContextRule {
        ContextRule {
            rule_id: "TEST-001".into(),
            rule_text: "Test rule".into(),
            severity: Severity::High,
            category: "test".into(),
            keywords_lower: keywords.iter().map(|s| s.to_string()).collect(),
            compiled_patterns: patterns.iter().map(|p| Regex::new(p).unwrap()).collect(),
            enabled: true,
        }
    }

    #[test]
    fn test_context_match_keyword() {
        let rules = vec![make_rule(&["bypass"], &[])];
        let pairs = vec![("action_detail".into(), "bypass validation checks".into())];
        let v = process_context(&pairs, &rules);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_context_skip_positive_verb() {
        let rules = vec![make_rule(&["audit"], &[])];
        let pairs = vec![("action_detail".into(), "run audit checks".into())];
        let v = process_context(&pairs, &rules);
        // "run" is positive verb, "audit" keyword has no negative → skipped
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn test_context_ignores_non_action_keys() {
        let rules = vec![make_rule(&["bypass"], &[])];
        let pairs = vec![("metadata".into(), "bypass everything".into())];
        let v = process_context(&pairs, &rules);
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn test_negative_keyword_overrides_positive_verb() {
        let rules = vec![make_rule(&["self-approve"], &[])];
        let pairs = vec![(
            "action_detail".into(),
            "implement self-approve workflow".into(),
        )];
        let v = process_context(&pairs, &rules);
        // "implement" is positive, but "self-approve" contains negative → flagged
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_security_keyword_overrides_positive_verb_in_context() {
        let rules = vec![make_rule(&["password"], &[])];
        let pairs = vec![(
            "action_detail".into(),
            "share password with external team".into(),
        )];
        let v = process_context(&pairs, &rules);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_multibyte_utf8_context_truncation() {
        let rules = vec![make_rule(&["bypass"], &[])];
        let long_utf8 = format!("bypass {}", "é".repeat(120));
        let pairs = vec![("action_detail".into(), long_utf8)];
        let v = process_context(&pairs, &rules);
        assert_eq!(v.len(), 1);
        assert!(v[0]
            .matched_content
            .starts_with("context[action_detail]: bypass "));
        assert!(v[0].matched_content.ends_with("..."));
        // Prefix "context[action_detail]: " (24 chars) + 100 chars + "..." (3 chars)
        assert_eq!(v[0].matched_content.chars().count(), 24 + 100 + 3);
    }
}
