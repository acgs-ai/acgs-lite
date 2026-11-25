/// Core hot-path governance validator.
///
/// Implements keyword-scan + anchor-dispatch + regex validation using
/// Aho-Corasick automaton for O(N) multi-pattern matching.
///
/// Pure Rust — no FFI dependencies.
///
/// Constitutional Hash: 608508a9bd224290
use aho_corasick::{AhoCorasick, MatchKind};
use regex::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};

use crate::context::{self, ContextRule};
use crate::result::{Decision, ValidationResult, Violation, ViolationRecord, ViolationTuple};
use crate::severity::{self, Severity};
use crate::verbs;

/// Payload carried by each Aho-Corasick pattern.
#[derive(Clone)]
enum AcPayload {
    Keyword(Vec<(usize, bool)>),
    Anchor(usize),
    Both {
        kw_data: Vec<(usize, bool)>,
        anchor_idx: usize,
    },
}

struct AnchorEntry {
    patterns: Vec<(usize, Regex)>,
}

#[derive(Clone)]
struct RuleData {
    rule_id: String,
    rule_text: String,
    severity: String,
    severity_enum: Severity,
    category: String,
    is_critical: bool,
}

/// Error returned when building a GovernanceValidator fails.
#[derive(Debug)]
pub enum BuildError {
    BadRegex { pattern: String, message: String },
    TooManyRules { count: usize },
    TooManyAnchors { count: usize },
    RuleIndexOutOfBounds { rule_idx: usize, rule_count: usize },
    AhoCorasickBuild(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::BadRegex { pattern, message } => {
                write!(f, "Bad regex '{}': {}", pattern, message)
            }
            BuildError::TooManyRules { count } => {
                write!(f, "Rule count {} exceeds 127 (u128 bitmask limit)", count)
            }
            BuildError::TooManyAnchors { count } => {
                write!(f, "Anchor count {} exceeds 127 (u128 bitmask limit)", count)
            }
            BuildError::RuleIndexOutOfBounds {
                rule_idx,
                rule_count,
            } => {
                write!(
                    f,
                    "Rule index {} out of bounds for {} rules",
                    rule_idx, rule_count
                )
            }
            BuildError::AhoCorasickBuild(msg) => {
                write!(f, "AC build error: {}", msg)
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Input for constructing a GovernanceValidator from plain Rust types.
pub struct ValidatorConfig {
    /// Map of keyword → [(rule_idx, keyword_has_negative)]
    pub kw_to_idxs: HashMap<String, Vec<(usize, bool)>>,
    /// [(anchor_string, [(rule_idx, pattern_string)])]
    pub anchor_dispatch: Vec<(String, Vec<(usize, String)>)>,
    /// [(rule_idx, pattern_string)]
    pub no_anchor_pats: Vec<(usize, String)>,
    /// [(rule_id, rule_text, severity_str, category, is_critical)]
    pub rule_data: Vec<(String, String, String, String, bool)>,
    /// Positive verb set
    pub positive_verbs: HashSet<String>,
    /// Strict mode
    pub strict: bool,
    /// Optional context rules
    pub context_rules: Vec<ContextRule>,
    /// Constitutional hash
    pub const_hash: String,
}

/// Compile a rule pattern case-insensitively.
///
/// Callers pass the bare pattern string (Python compiles it with
/// `re.IGNORECASE` but hands over only `pattern.pattern`), and every scan runs
/// on lowercased text. A case-sensitive compile would let an uppercase literal
/// such as `AKIA[0-9A-Z]{16}` never fire, so the Rust path would allow what the
/// Python path denies.
fn compile_rule_pattern(pat_str: &str) -> Result<Regex, BuildError> {
    RegexBuilder::new(pat_str)
        .case_insensitive(true)
        .build()
        .map_err(|e| BuildError::BadRegex {
            pattern: pat_str.to_string(),
            message: e.to_string(),
        })
}

/// The core hot-path validator — pure Rust, no FFI.
pub struct GovernanceValidator {
    automaton: AhoCorasick,
    payloads: Vec<AcPayload>,
    anchor_dispatch: Vec<AnchorEntry>,
    no_anchor_pats: Vec<(usize, Regex)>,
    rule_data: Vec<RuleData>,
    positive_verbs: HashSet<String>,
    strict: bool,
    context_rules: Vec<ContextRule>,
    const_hash: String,
}

impl GovernanceValidator {
    /// Build a new validator from plain Rust config.
    pub fn new(config: ValidatorConfig) -> Result<Self, BuildError> {
        let rule_count = config.rule_data.len();
        // Fail fast before compiling regexes or building the Aho-Corasick automaton:
        // bitmask deduplication uses u128 — max 127 rules/anchors.
        if rule_count > 127 {
            return Err(BuildError::TooManyRules { count: rule_count });
        }
        if config.anchor_dispatch.len() > 127 {
            return Err(BuildError::TooManyAnchors {
                count: config.anchor_dispatch.len(),
            });
        }

        // Build anchor_to_idx and anchor_dispatch (moving owned strings from config)
        let mut anchor_to_idx: HashMap<String, usize> =
            HashMap::with_capacity(config.anchor_dispatch.len());
        let mut anchor_dispatch: Vec<AnchorEntry> =
            Vec::with_capacity(config.anchor_dispatch.len());
        for (ai, (anchor, pats)) in config.anchor_dispatch.into_iter().enumerate() {
            let mut patterns: Vec<(usize, Regex)> = Vec::with_capacity(pats.len());
            for (rule_idx, pat_str) in pats {
                if rule_idx >= rule_count {
                    return Err(BuildError::RuleIndexOutOfBounds {
                        rule_idx,
                        rule_count,
                    });
                }
                patterns.push((rule_idx, compile_rule_pattern(&pat_str)?));
            }
            anchor_to_idx.insert(anchor, ai);
            anchor_dispatch.push(AnchorEntry { patterns });
        }

        // Collect all words and build payloads (moving owned strings from config)
        let capacity = config.kw_to_idxs.len() + anchor_to_idx.len();
        let mut all_words: Vec<String> = Vec::with_capacity(capacity);
        let mut payloads: Vec<AcPayload> = Vec::with_capacity(capacity);
        for (kw, idxs) in config.kw_to_idxs {
            for &(rule_idx, _) in &idxs {
                if rule_idx >= rule_count {
                    return Err(BuildError::RuleIndexOutOfBounds {
                        rule_idx,
                        rule_count,
                    });
                }
            }
            if let Some(ai) = anchor_to_idx.remove(&kw) {
                all_words.push(kw);
                payloads.push(AcPayload::Both {
                    kw_data: idxs,
                    anchor_idx: ai,
                });
            } else {
                all_words.push(kw);
                payloads.push(AcPayload::Keyword(idxs));
            }
        }
        for (anchor, ai) in anchor_to_idx {
            all_words.push(anchor);
            payloads.push(AcPayload::Anchor(ai));
        }

        // No-anchor patterns
        let mut no_anchor_pats: Vec<(usize, Regex)> =
            Vec::with_capacity(config.no_anchor_pats.len());
        for (rule_idx, pat_str) in config.no_anchor_pats {
            if rule_idx >= rule_count {
                return Err(BuildError::RuleIndexOutOfBounds {
                    rule_idx,
                    rule_count,
                });
            }
            no_anchor_pats.push((rule_idx, compile_rule_pattern(&pat_str)?));
        }

        // Rule data (move owned strings without cloning)
        let rule_data: Vec<RuleData> = config
            .rule_data
            .into_iter()
            .map(
                |(rule_id, rule_text, severity, category, is_critical)| RuleData {
                    severity_enum: Severity::from_label(&severity),
                    rule_id,
                    rule_text,
                    severity,
                    category,
                    is_critical,
                },
            )
            .collect();

        // Build Aho-Corasick automaton
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(&all_words)
            .map_err(|e| BuildError::AhoCorasickBuild(e.to_string()))?;

        Ok(GovernanceValidator {
            automaton,
            payloads,
            anchor_dispatch,
            no_anchor_pats,
            rule_data,
            positive_verbs: config.positive_verbs,
            strict: config.strict,
            context_rules: config.context_rules,
            const_hash: config.const_hash,
        })
    }

    /// Full-width hot-path validation returning the untruncated 128-bit fired mask.
    ///
    /// Returns: `(decision_code, data)`
    /// - `(ALLOW=0, 0)`                 — no violations
    /// - `(DENY_CRITICAL=1, rule_idx)`  — critical violation in strict mode
    /// - `(DENY=2, fired_bitmask)`      — bitmask across up to 127 rules
    pub fn validate_hot_u128(&self, text_lower: &str) -> (i32, u128) {
        let mut fired: u128 = 0;
        if let Some(crit_idx) = self.scan_rules(text_lower, |rule_idx| {
            fired |= 1u128 << rule_idx;
        }) {
            return (severity::DENY_CRITICAL, crit_idx as u128);
        }
        if fired == 0 {
            (severity::ALLOW, 0)
        } else {
            (severity::DENY, fired)
        }
    }

    /// Legacy hot-path validation — minimal allocation.
    ///
    /// Returns: `(decision_code, data)`
    /// - `(ALLOW=0, 0)`                — no violations
    /// - `(DENY_CRITICAL=1, rule_idx)` — critical violation
    /// - `(DENY=2, fired_bitmask)`     — non-critical violations (i64 legacy ABI)
    pub fn validate_hot(&self, text_lower: &str) -> (i32, i64) {
        let (code, data) = self.validate_hot_u128(text_lower);
        (code, data as i64)
    }

    /// Full validation with structured violation data.
    ///
    /// Returns: (decision, violations_tuples, blocking)
    pub fn validate_full(
        &self,
        text_lower: &str,
        context_pairs: Option<&[(String, String)]>,
    ) -> (i32, Vec<ViolationTuple>, bool) {
        let decision = self.scan(text_lower);

        match decision {
            Decision::Allow => {
                if let Some(pairs) = context_pairs {
                    if !pairs.is_empty() && !self.context_rules.is_empty() {
                        let ctx_violations = context::process_context(pairs, &self.context_rules);
                        if !ctx_violations.is_empty() {
                            let has_blocking = ctx_violations.iter().any(|v| v.severity.blocks());
                            let tuples: Vec<_> = ctx_violations
                                .into_iter()
                                .map(|v| {
                                    (
                                        v.rule_id,
                                        v.rule_text,
                                        v.severity.as_str().to_string(),
                                        v.matched_content,
                                        v.category,
                                    )
                                })
                                .collect();
                            return (severity::DENY, tuples, has_blocking);
                        }
                    }
                }
                (severity::ALLOW, Vec::new(), false)
            }
            Decision::DenyCritical { rule_idx } => {
                let rd = &self.rule_data[rule_idx];
                let tuples = vec![(
                    rd.rule_id.clone(),
                    rd.rule_text.clone(),
                    rd.severity.clone(),
                    String::new(),
                    rd.category.clone(),
                )];
                (severity::DENY_CRITICAL, tuples, true)
            }
            Decision::Deny {
                mut violations,
                has_blocking,
            } => {
                if let Some(pairs) = context_pairs {
                    if !pairs.is_empty() && !self.context_rules.is_empty() {
                        let ctx_violations = context::process_context(pairs, &self.context_rules);
                        violations.extend(ctx_violations);
                    }
                }
                let blocking = has_blocking || violations.iter().any(|v| v.severity.blocks());
                let tuples: Vec<_> = violations
                    .into_iter()
                    .map(|v| {
                        (
                            v.rule_id,
                            v.rule_text,
                            v.severity.as_str().to_string(),
                            v.matched_content,
                            v.category,
                        )
                    })
                    .collect();
                (severity::DENY, tuples, blocking)
            }
        }
    }

    /// Structured validation result for external consumers (WASM, HTTP).
    pub fn validate(
        &self,
        text: &str,
        context_pairs: Option<&[(String, String)]>,
    ) -> ValidationResult {
        let text_lower = text.to_lowercase();
        let (decision, violations, blocking) = self.validate_full(&text_lower, context_pairs);
        let records: Vec<ViolationRecord> = violations
            .into_iter()
            .map(|(rule_id, rule_text, sev, matched, cat)| ViolationRecord {
                rule_id,
                rule_text,
                severity: sev,
                matched_content: matched,
                category: cat,
            })
            .collect();
        ValidationResult {
            decision,
            violations: records,
            blocking,
            constitutional_hash: self.const_hash.clone(),
            rules_checked: self.rule_data.len(),
        }
    }

    /// Get the constitutional hash.
    pub fn const_hash(&self) -> &str {
        &self.const_hash
    }

    /// Unified zero-overhead scan shared between `validate_hot*` and `validate_full`.
    ///
    /// Invokes `on_fire(rule_idx)` once per newly fired non-short-circuited rule.
    /// Returns `Some(rule_idx)` immediately when a critical rule fires under strict mode.
    #[inline]
    fn scan_rules<F>(&self, text_lower: &str, mut on_fire: F) -> Option<usize>
    where
        F: FnMut(usize),
    {
        let first_word = match text_lower.find(' ') {
            Some(i) => &text_lower[..i],
            None => text_lower,
        };
        // Parity with Python engine/core.py: a leading positive verb only exempts
        // non-negative keywords when the text contains NO negative verb phrase.
        let is_pos_verb =
            self.positive_verbs.contains(first_word) && !verbs::has_negative_verb(text_lower);

        let mut fired: u128 = 0;
        let mut hit_anchors: u128 = 0;

        // AC scan — single overlapping pass tracks both keywords and anchors
        for mat in self.automaton.find_overlapping_iter(text_lower) {
            let kw_slice = match &self.payloads[mat.pattern().as_usize()] {
                AcPayload::Keyword(kw_data) => kw_data.as_slice(),
                AcPayload::Anchor(ai) => {
                    hit_anchors |= 1u128 << ai;
                    continue;
                }
                AcPayload::Both {
                    kw_data,
                    anchor_idx,
                } => {
                    hit_anchors |= 1u128 << anchor_idx;
                    kw_data.as_slice()
                }
            };
            for &(rule_idx, kw_has_neg) in kw_slice {
                if is_pos_verb && !kw_has_neg {
                    continue;
                }
                let bit = 1u128 << rule_idx;
                if fired & bit != 0 {
                    continue;
                }
                fired |= bit;
                if self.strict && self.rule_data[rule_idx].is_critical {
                    return Some(rule_idx);
                }
                on_fire(rule_idx);
            }
        }

        // Anchor dispatch (regex patterns)
        if hit_anchors != 0 {
            let mut tmp = hit_anchors;
            while tmp != 0 {
                let lsb = tmp & tmp.wrapping_neg();
                let ai = lsb.trailing_zeros() as usize;
                tmp ^= lsb;
                if ai < self.anchor_dispatch.len() {
                    for &(rule_idx, ref re) in &self.anchor_dispatch[ai].patterns {
                        let bit = 1u128 << rule_idx;
                        if fired & bit == 0 && re.is_match(text_lower) {
                            fired |= bit;
                            if self.strict && self.rule_data[rule_idx].is_critical {
                                return Some(rule_idx);
                            }
                            on_fire(rule_idx);
                        }
                    }
                }
            }
        }

        for &(rule_idx, ref re) in &self.no_anchor_pats {
            let bit = 1u128 << rule_idx;
            if fired & bit == 0 && re.is_match(text_lower) {
                fired |= bit;
                if self.strict && self.rule_data[rule_idx].is_critical {
                    return Some(rule_idx);
                }
                on_fire(rule_idx);
            }
        }

        None
    }

    fn scan(&self, text_lower: &str) -> Decision {
        let mut violations: Vec<Violation> = Vec::new();
        if let Some(rule_idx) = self.scan_rules(text_lower, |rule_idx| {
            let rd = &self.rule_data[rule_idx];
            violations.push(Violation {
                rule_idx,
                rule_id: rd.rule_id.clone(),
                rule_text: rd.rule_text.clone(),
                severity: rd.severity_enum,
                matched_content: String::new(),
                category: rd.category.clone(),
            });
        }) {
            return Decision::DenyCritical { rule_idx };
        }

        if violations.is_empty() {
            Decision::Allow
        } else {
            let has_blocking = violations.iter().any(|v| v.severity.blocks());
            Decision::Deny {
                violations,
                has_blocking,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator(anchor: Option<&str>, pattern: &str) -> GovernanceValidator {
        let (anchor_dispatch, no_anchor_pats) = match anchor {
            Some(a) => (
                vec![(a.to_string(), vec![(0, pattern.to_string())])],
                vec![],
            ),
            None => (vec![], vec![(0, pattern.to_string())]),
        };
        GovernanceValidator::new(ValidatorConfig {
            kw_to_idxs: HashMap::new(),
            anchor_dispatch,
            no_anchor_pats,
            rule_data: vec![(
                "SEC-001".into(),
                "No AWS keys".into(),
                "high".into(),
                "security".into(),
                false,
            )],
            positive_verbs: HashSet::new(),
            strict: false,
            context_rules: vec![],
            const_hash: String::new(),
        })
        .unwrap()
    }

    // Python compiles rule patterns with re.IGNORECASE and passes only
    // `pattern.pattern` here, while the scan runs on lowercased text, so an
    // uppercase literal must still match (parity with the Python path).
    #[test]
    fn anchored_uppercase_pattern_matches_lowercased_text() {
        let v = validator(Some("akia"), "AKIA[0-9A-Z]{16}");
        let r = v.validate("deploy with AKIAABCDEFGHIJKLMNOP", None);
        assert_eq!(r.decision, severity::DENY);
        assert_eq!(
            v.validate_hot("deploy with akiaabcdefghijklmnop").0,
            severity::DENY
        );
    }

    #[test]
    fn no_anchor_uppercase_pattern_matches_lowercased_text() {
        let v = validator(None, "[A-Z]{2}[0-9]{6}");
        let r = v.validate("passport AB123456", None);
        assert_eq!(r.decision, severity::DENY);
    }

    #[test]
    fn non_matching_text_still_allows() {
        let v = validator(Some("akia"), "AKIA[0-9A-Z]{16}");
        assert_eq!(v.validate("akia is a word", None).decision, severity::ALLOW);
    }

    #[test]
    fn positive_verb_does_not_exempt_when_negative_verb_present() {
        let mut kw_to_idxs = HashMap::new();
        kw_to_idxs.insert("production access".to_string(), vec![(0, false)]);
        let mut positive_verbs = HashSet::new();
        positive_verbs.insert("enable".to_string());
        let v = GovernanceValidator::new(ValidatorConfig {
            kw_to_idxs,
            anchor_dispatch: vec![],
            no_anchor_pats: vec![],
            rule_data: vec![(
                "SEC-002".into(),
                "Require approval for production access".into(),
                "high".into(),
                "security".into(),
                false,
            )],
            positive_verbs,
            strict: false,
            context_rules: vec![],
            const_hash: String::new(),
        })
        .unwrap();

        // Constructive action with no negative verb is exempted.
        assert_eq!(
            v.validate("enable production access audit", None).decision,
            severity::ALLOW
        );
        assert_eq!(
            v.validate_hot("enable production access audit"),
            (severity::ALLOW, 0)
        );

        // Negative verb ("without", "bypass") overrides positive-verb exemption (Python parity).
        assert_eq!(
            v.validate("enable production access without approval", None)
                .decision,
            severity::DENY
        );
        assert_eq!(
            v.validate_hot("enable production access without approval"),
            (severity::DENY, 1)
        );
        assert_eq!(
            v.validate_hot("enable production access bypass"),
            (severity::DENY, 1)
        );
    }

    #[test]
    fn rejects_out_of_bounds_rule_index_at_build_time() {
        let mut kw_to_idxs = HashMap::new();
        kw_to_idxs.insert("boom".to_string(), vec![(5, false)]);
        let err = GovernanceValidator::new(ValidatorConfig {
            kw_to_idxs,
            anchor_dispatch: vec![],
            no_anchor_pats: vec![],
            rule_data: vec![(
                "R-0".into(),
                "Only rule".into(),
                "high".into(),
                "sec".into(),
                false,
            )],
            positive_verbs: HashSet::new(),
            strict: false,
            context_rules: vec![],
            const_hash: String::new(),
        })
        .err()
        .expect("out-of-bounds rule_idx must fail build");
        assert!(matches!(
            err,
            BuildError::RuleIndexOutOfBounds {
                rule_idx: 5,
                rule_count: 1
            }
        ));

        // Anchor and no-anchor out-of-bounds indices must also fail build.
        let err_anchor = GovernanceValidator::new(ValidatorConfig {
            kw_to_idxs: HashMap::new(),
            anchor_dispatch: vec![("akia".into(), vec![(1, "akia[a-z]+".into())])],
            no_anchor_pats: vec![],
            rule_data: vec![(
                "R-0".into(),
                "Only".into(),
                "high".into(),
                "s".into(),
                false,
            )],
            positive_verbs: HashSet::new(),
            strict: false,
            context_rules: vec![],
            const_hash: String::new(),
        })
        .err()
        .expect("anchor rule_idx OOB must fail build");
        assert!(matches!(
            err_anchor,
            BuildError::RuleIndexOutOfBounds {
                rule_idx: 1,
                rule_count: 1
            }
        ));

        let err_no_anchor = GovernanceValidator::new(ValidatorConfig {
            kw_to_idxs: HashMap::new(),
            anchor_dispatch: vec![],
            no_anchor_pats: vec![(2, "[0-9]{4}".into())],
            rule_data: vec![(
                "R-0".into(),
                "Only".into(),
                "high".into(),
                "s".into(),
                false,
            )],
            positive_verbs: HashSet::new(),
            strict: false,
            context_rules: vec![],
            const_hash: String::new(),
        })
        .err()
        .expect("no-anchor rule_idx OOB must fail build");
        assert!(matches!(
            err_no_anchor,
            BuildError::RuleIndexOutOfBounds {
                rule_idx: 2,
                rule_count: 1
            }
        ));

        // >127 rules or >127 anchors must fail fast before building automaton.
        let too_many_rules: Vec<_> = (0..128)
            .map(|i| {
                (
                    format!("R-{i}"),
                    "t".into(),
                    "low".into(),
                    "c".into(),
                    false,
                )
            })
            .collect();
        assert!(matches!(
            GovernanceValidator::new(ValidatorConfig {
                kw_to_idxs: HashMap::new(),
                anchor_dispatch: vec![],
                no_anchor_pats: vec![],
                rule_data: too_many_rules,
                positive_verbs: HashSet::new(),
                strict: false,
                context_rules: vec![],
                const_hash: String::new(),
            }),
            Err(BuildError::TooManyRules { count: 128 })
        ));

        let too_many_anchors: Vec<_> = (0..128).map(|i| (format!("a{i}"), vec![])).collect();
        assert!(matches!(
            GovernanceValidator::new(ValidatorConfig {
                kw_to_idxs: HashMap::new(),
                anchor_dispatch: too_many_anchors,
                no_anchor_pats: vec![],
                rule_data: vec![],
                positive_verbs: HashSet::new(),
                strict: false,
                context_rules: vec![],
                const_hash: String::new(),
            }),
            Err(BuildError::TooManyAnchors { count: 128 })
        ));
    }

    #[test]
    fn validate_hot_u128_preserves_high_rule_bits() {
        let mut kw_to_idxs = HashMap::new();
        let mut rule_data = Vec::new();
        for i in 0..75 {
            kw_to_idxs.insert(format!("kw{:03}", i), vec![(i, false)]);
            rule_data.push((
                format!("R-{:03}", i),
                format!("Rule {}", i),
                "high".into(),
                "sec".into(),
                false,
            ));
        }
        let v = GovernanceValidator::new(ValidatorConfig {
            kw_to_idxs,
            anchor_dispatch: vec![],
            no_anchor_pats: vec![],
            rule_data,
            positive_verbs: HashSet::new(),
            strict: false,
            context_rules: vec![],
            const_hash: String::new(),
        })
        .unwrap();

        let (code, mask) = v.validate_hot_u128("trigger kw000 and kw070");
        assert_eq!(code, severity::DENY);
        assert_eq!(mask, (1u128 << 0) | (1u128 << 70));
    }
}
