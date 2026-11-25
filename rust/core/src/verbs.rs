/// Positive and negative verb detection for governance validation.
///
/// Positive verbs indicate constructive actions (testing, auditing, implementing)
/// that should not be flagged even if they contain governance keywords.
///
/// Negative verbs indicate potentially harmful intent (bypass, disable, delete)
/// that override the positive-verb exemption.
///
/// Constitutional Hash: 608508a9bd224290
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// The 30 positive verbs from constitution.py `_POSITIVE_VERBS_SET`.
/// Actions starting with these words get the positive-verb exemption
/// (keywords are skipped unless they contain a negative indicator).
pub static POSITIVE_VERBS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "run",
        "test",
        "generate",
        "create",
        "schedule",
        "implement",
        "log",
        "enable",
        "assign",
        "establish",
        "publish",
        "disclose",
        "build",
        "review",
        "audit",
        "check",
        "verify",
        "assess",
        "evaluate",
        "report",
        "document",
        "plan",
        "prepare",
        "anonymize",
        "share",
        "update",
        "optimize",
        "parallelize",
        "consolidate",
        "migrate",
    ]
    .into_iter()
    .collect()
});

/// Compiled regex matching the 19 negative verb phrases from
/// constitution.py `_NEGATIVE_VERBS_LIST`.
pub static NEGATIVE_VERBS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        "(?i)",
        "without|disable|bypass|remove|skip|no |delete|override|hide|",
        "obfuscate|auto-reject|self-approve|self-validate|",
        "delegate entirely|store biometric|export customer|",
        "cross-reference|let ai system self|process customer pii|",
        "use zip code|deploy loan approval model with known|",
        "deploy hiring model without"
    ))
    .unwrap()
});

/// Compiled regex matching keyword-level negative indicators from
/// constitution.py `_KW_NEGATIVE_RE`.
pub static KW_NEGATIVE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        "(?i)",
        "without|disable|bypass|remove|skip|delete|override|hide|",
        "auto-reject|self-approve|proxy for|",
        "secret|credential|token|password|ssn|terraform-destroy"
    ))
    .unwrap()
});

/// Check if the first word of `text_lower` is a positive verb.
#[inline]
pub fn is_positive_verb(text_lower: &str) -> bool {
    let first_word = match text_lower.find(' ') {
        Some(i) => &text_lower[..i],
        None => text_lower,
    };
    POSITIVE_VERBS.contains(first_word)
}

/// Check if `text_lower` contains any negative verb phrase.
#[inline]
pub fn has_negative_verb(text_lower: &str) -> bool {
    NEGATIVE_VERBS_RE.is_match(text_lower)
}

/// Check if a keyword itself contains a negative indicator.
#[inline]
pub fn keyword_has_negative(kw_lower: &str) -> bool {
    KW_NEGATIVE_RE.is_match(kw_lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_positive_verbs_count() {
        assert_eq!(POSITIVE_VERBS.len(), 30);
    }

    #[test]
    fn test_positive_verb_detection() {
        assert!(is_positive_verb("run safety test"));
        assert!(is_positive_verb("implement differential privacy"));
        assert!(!is_positive_verb("deploy model without review"));
        assert!(!is_positive_verb("keep decision secret"));
    }

    #[test]
    fn test_negative_verb_detection() {
        assert!(has_negative_verb("deploy model without safety review"));
        assert!(has_negative_verb("bypass content filtering"));
        assert!(has_negative_verb("self-approve transaction"));
        assert!(!has_negative_verb("run safety test"));
        assert!(!has_negative_verb("implement privacy controls"));
    }

    #[test]
    fn test_keyword_negative() {
        assert!(keyword_has_negative("self-approve"));
        assert!(keyword_has_negative("bypass validation"));
        assert!(!keyword_has_negative("audit trail"));
        assert!(!keyword_has_negative("safety check"));
    }

    #[test]
    fn test_keyword_negative_security_parity() {
        for kw in [
            "secret",
            "credential",
            "token",
            "password",
            "ssn",
            "terraform-destroy",
            "expose secret key",
        ] {
            assert!(
                keyword_has_negative(kw),
                "security keyword '{}' must override positive-verb exemption",
                kw
            );
        }
    }
}
