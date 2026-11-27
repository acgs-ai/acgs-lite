/// Validation result types for the governance engine.
///
/// Pure Rust types — no FFI dependencies.
///
/// Constitutional Hash: 608508a9bd224290
use serde::{Deserialize, Serialize};

use crate::severity::{self, Severity};

pub type ViolationTuple = (String, String, String, String, String);

/// A single rule violation detected during validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub rule_idx: usize,
    pub rule_id: String,
    pub rule_text: String,
    pub severity: Severity,
    pub matched_content: String,
    pub category: String,
}

/// The decision made by the validator.
#[derive(Debug)]
pub enum Decision {
    /// No violations found — action is allowed.
    Allow,
    /// A CRITICAL violation found in strict mode — must raise immediately.
    DenyCritical { rule_idx: usize },
    /// Non-critical violations found — action may be escalated or denied.
    Deny {
        violations: Vec<Violation>,
        has_blocking: bool,
    },
}

impl Decision {
    /// Convert to the legacy (decision_code, data) tuple format for backward compat.
    pub fn to_legacy_tuple(&self) -> (i32, i64) {
        match self {
            Decision::Allow => (severity::ALLOW, 0),
            Decision::DenyCritical { rule_idx } => (severity::DENY_CRITICAL, *rule_idx as i64),
            Decision::Deny { violations, .. } => {
                let mut bitmask: u128 = 0;
                for v in violations {
                    if v.rule_idx < 128 {
                        bitmask |= 1u128 << v.rule_idx;
                    }
                }
                // The PyO3 legacy tuple still exposes an i64 here for backward
                // compatibility. Bits above 63 truncate at this boundary, while
                // Python's fallback path still handles large constitutions.
                (severity::DENY, bitmask as i64)
            }
        }
    }
}

/// Structured result of a full validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub decision: i32,
    pub violations: Vec<ViolationRecord>,
    pub blocking: bool,
    pub constitutional_hash: String,
    pub rules_checked: usize,
}

/// Serializable violation record for external consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationRecord {
    pub rule_id: String,
    pub rule_text: String,
    pub severity: String,
    pub matched_content: String,
    pub category: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_legacy() {
        let d = Decision::Allow;
        assert_eq!(d.to_legacy_tuple(), (severity::ALLOW, 0));
    }

    #[test]
    fn test_deny_critical_legacy() {
        let d = Decision::DenyCritical { rule_idx: 3 };
        assert_eq!(d.to_legacy_tuple(), (severity::DENY_CRITICAL, 3));
    }

    #[test]
    fn test_deny_bitmask() {
        let d = Decision::Deny {
            violations: vec![
                Violation {
                    rule_idx: 0,
                    rule_id: "R1".into(),
                    rule_text: "test".into(),
                    severity: Severity::Medium,
                    matched_content: "x".into(),
                    category: "c".into(),
                },
                Violation {
                    rule_idx: 2,
                    rule_id: "R3".into(),
                    rule_text: "test".into(),
                    severity: Severity::High,
                    matched_content: "y".into(),
                    category: "c".into(),
                },
            ],
            has_blocking: true,
        };
        let (code, mask) = d.to_legacy_tuple();
        assert_eq!(code, severity::DENY);
        assert_eq!(mask, 0b101); // bits 0 and 2
    }
}
