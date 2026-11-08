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
        // Build anchor_to_idx and anchor_dispatch
        let mut anchor_to_idx: HashMap<String, usize> = HashMap::new();
        let mut anchor_dispatch: Vec<AnchorEntry> = Vec::new();
        for (ai, (anchor, pats)) in config.anchor_dispatch.iter().enumerate() {
            let mut patterns: Vec<(usize, Regex)> = Vec::with_capacity(pats.len());
            for (rule_idx, pat_str) in pats {
                patterns.push((*rule_idx, compile_rule_pattern(pat_str)?));
            }
            anchor_to_idx.insert(anchor.clone(), ai);
            anchor_dispatch.push(AnchorEntry { patterns });
        }

        // Collect all words and build payloads
        let mut all_words: Vec<String> = Vec::new();
        let mut payloads: Vec<AcPayload> = Vec::new();
        for (kw, idxs) in &config.kw_to_idxs {
            if let Some(&ai) = anchor_to_idx.get(kw) {
                all_words.push(kw.clone());
                payloads.push(AcPayload::Both {
                    kw_data: idxs.clone(),
                    anchor_idx: ai,
                });
            } else {
                all_words.push(kw.clone());
                payloads.push(AcPayload::Keyword(idxs.clone()));
            }
        }
        for (anchor, &ai) in &anchor_to_idx {
            if !config.kw_to_idxs.contains_key(anchor) {
                all_words.push(anchor.clone());
                payloads.push(AcPayload::Anchor(ai));
            }
        }

        // No-anchor patterns
        let mut no_anchor_pats: Vec<(usize, Regex)> = Vec::new();
        for (rule_idx, pat_str) in &config.no_anchor_pats {
            no_anchor_pats.push((*rule_idx, compile_rule_pattern(pat_str)?));
        }

        // Rule data
        let rule_data: Vec<RuleData> = config
            .rule_data
            .iter()
            .map(|(rid, rtxt, sev_str, cat, is_crit)| RuleData {
                rule_id: rid.clone(),
                rule_text: rtxt.clone(),
                severity_enum: Severity::from_label(sev_str),
                severity: sev_str.clone(),
                category: cat.clone(),
                is_critical: *is_crit,
            })
            .collect();

        // Build Aho-Corasick automaton
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(&all_words)
            .map_err(|e| BuildError::AhoCorasickBuild(e.to_string()))?;

        // Guard: bitmask deduplication uses u128 — max 127 rules/anchors
        if rule_data.len() > 127 {
            return Err(BuildError::TooManyRules {
                count: rule_data.len(),
            });
        }
        if anchor_dispatch.len() > 127 {
            return Err(BuildError::TooManyAnchors {
                count: anchor_dispatch.len(),
            });
        }

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

    /// Legacy hot-path validation — minimal allocation.
    ///
    /// Returns: (decision_code, data)
    ///   (ALLOW=0, 0)              — no violations
    ///   (DENY_CRITICAL=1, rule_idx) — critical violation
    ///   (DENY=2, fired_bitmask)   — non-critical violations
    pub fn validate_hot(&self, text_lower: &str) -> (i32, i64) {
        // exp265: scan_hot() — bitmask-only path, skips Violation struct allocation
        // and String cloning. For allow paths, this eliminates Vec<Violation> alloc.
        // For deny paths, returns only the fired bitmask (Python reconstructs violations).
        self.scan_hot(text_lower)
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

    /// Core scan logic — shared between validate_hot and validate_full.
    /// Hot-path scan — returns (decision_code, data) directly as a tuple.
    /// Unlike `scan()`, this never allocates Violation structs or clones Strings.
    /// For Allow: returns (ALLOW, 0).
    /// For DenyCritical: returns (DENY_CRITICAL, rule_idx).
    /// For Deny: returns (DENY, fired_bitmask) — caller reconstructs violations from bitmask.
    fn scan_hot(&self, text_lower: &str) -> (i32, i64) {
        let first_word = match text_lower.find(' ') {
            Some(i) => &text_lower[..i],
            None => text_lower,
        };
        let is_pos_verb = self.positive_verbs.contains(first_word);

        let mut fired: u128 = 0;
        let mut hit_anchors: u128 = 0;

        // AC scan — single pass, tracks both keywords and anchors
        for mat in self.automaton.find_overlapping_iter(text_lower) {
            match &self.payloads[mat.pattern().as_usize()] {
                AcPayload::Keyword(kw_data) => {
                    for &(rule_idx, kw_has_neg) in kw_data {
                        if is_pos_verb && !kw_has_neg {
                            continue;
                        }
                        let bit = 1u128 << rule_idx;
                        if fired & bit != 0 {
                            continue;
                        }
                        fired |= bit;
                        let rd = &self.rule_data[rule_idx];
                        if self.strict && rd.is_critical {
                            return (severity::DENY_CRITICAL, rule_idx as i64);
                        }
                    }
                }
                AcPayload::Anchor(ai) => {
                    hit_anchors |= 1u128 << ai;
                }
                AcPayload::Both {
                    kw_data,
                    anchor_idx,
                } => {
                    hit_anchors |= 1u128 << anchor_idx;
                    for &(rule_idx, kw_has_neg) in kw_data {
                        if is_pos_verb && !kw_has_neg {
                            continue;
                        }
                        let bit = 1u128 << rule_idx;
                        if fired & bit != 0 {
                            continue;
                        }
                        fired |= bit;
                        let rd = &self.rule_data[rule_idx];
                        if self.strict && rd.is_critical {
                            return (severity::DENY_CRITICAL, rule_idx as i64);
                        }
                    }
                }
            }
        }

        // Anchor dispatch (regex patterns)
        if hit_anchors != 0 || !self.no_anchor_pats.is_empty() {
            if hit_anchors != 0 {
                let mut tmp = hit_anchors;
                while tmp != 0 {
                    let lsb = tmp & tmp.wrapping_neg();
                    let ai = lsb.trailing_zeros() as usize;
                    tmp ^= lsb;
                    if ai < self.anchor_dispatch.len() {
                        for (rule_idx, re) in &self.anchor_dispatch[ai].patterns {
                            let bit = 1u128 << rule_idx;
                            if fired & bit == 0 && re.is_match(text_lower) {
                                fired |= bit;
                                let rd = &self.rule_data[*rule_idx];
                                if self.strict && rd.is_critical {
                                    return (severity::DENY_CRITICAL, *rule_idx as i64);
                                }
                            }
                        }
                    }
                }
            }
            for (rule_idx, re) in &self.no_anchor_pats {
                let bit = 1u128 << rule_idx;
                if fired & bit == 0 && re.is_match(text_lower) {
                    fired |= bit;
                    let rd = &self.rule_data[*rule_idx];
                    if self.strict && rd.is_critical {
                        return (severity::DENY_CRITICAL, *rule_idx as i64);
                    }
                }
            }
        }

        if fired == 0 {
            (severity::ALLOW, 0)
        } else {
            (severity::DENY, fired as i64)
        }
    }

    fn scan(&self, text_lower: &str) -> Decision {
        let first_word = match text_lower.find(' ') {
            Some(i) => &text_lower[..i],
            None => text_lower,
        };
        let is_pos_verb = self.positive_verbs.contains(first_word);

        let mut fired: u128 = 0;
        let mut hit_anchors: u128 = 0;
        let mut violations: Vec<Violation> = Vec::new();

        // AC scan — overlapping mode finds all matches
        for mat in self.automaton.find_overlapping_iter(text_lower) {
            match &self.payloads[mat.pattern().as_usize()] {
                AcPayload::Keyword(kw_data) => {
                    for &(rule_idx, kw_has_neg) in kw_data {
                        if is_pos_verb && !kw_has_neg {
                            continue;
                        }
                        let bit = 1u128 << rule_idx;
                        if fired & bit != 0 {
                            continue;
                        }
                        fired |= bit;
                        let rd = &self.rule_data[rule_idx];
                        if self.strict && rd.is_critical {
                            return Decision::DenyCritical { rule_idx };
                        }
                        violations.push(Violation {
                            rule_idx,
                            rule_id: rd.rule_id.clone(),
                            rule_text: rd.rule_text.clone(),
                            severity: rd.severity_enum,
                            matched_content: String::new(),
                            category: rd.category.clone(),
                        });
                    }
                }
                AcPayload::Anchor(ai) => {
                    hit_anchors |= 1u128 << ai;
                }
                AcPayload::Both {
                    kw_data,
                    anchor_idx,
                } => {
                    hit_anchors |= 1u128 << anchor_idx;
                    for &(rule_idx, kw_has_neg) in kw_data {
                        if is_pos_verb && !kw_has_neg {
                            continue;
                        }
                        let bit = 1u128 << rule_idx;
                        if fired & bit != 0 {
                            continue;
                        }
                        fired |= bit;
                        let rd = &self.rule_data[rule_idx];
                        if self.strict && rd.is_critical {
                            return Decision::DenyCritical { rule_idx };
                        }
                        violations.push(Violation {
                            rule_idx,
                            rule_id: rd.rule_id.clone(),
                            rule_text: rd.rule_text.clone(),
                            severity: rd.severity_enum,
                            matched_content: String::new(),
                            category: rd.category.clone(),
                        });
                    }
                }
            }
        }

        // Anchor dispatch (regex patterns)
        if hit_anchors != 0 || !self.no_anchor_pats.is_empty() {
            if hit_anchors != 0 {
                let mut tmp = hit_anchors;
                while tmp != 0 {
                    let lsb = tmp & tmp.wrapping_neg();
                    let ai = lsb.trailing_zeros() as usize;
                    tmp ^= lsb;
                    if ai < self.anchor_dispatch.len() {
                        for (rule_idx, re) in &self.anchor_dispatch[ai].patterns {
                            let bit = 1u128 << rule_idx;
                            if fired & bit == 0 && re.is_match(text_lower) {
                                fired |= bit;
                                let rd = &self.rule_data[*rule_idx];
                                if self.strict && rd.is_critical {
                                    return Decision::DenyCritical {
                                        rule_idx: *rule_idx,
                                    };
                                }
                                violations.push(Violation {
                                    rule_idx: *rule_idx,
                                    rule_id: rd.rule_id.clone(),
                                    rule_text: rd.rule_text.clone(),
                                    severity: rd.severity_enum,
                                    matched_content: String::new(),
                                    category: rd.category.clone(),
                                });
                            }
                        }
                    }
                }
            }
            for (rule_idx, re) in &self.no_anchor_pats {
                let bit = 1u128 << rule_idx;
                if fired & bit == 0 && re.is_match(text_lower) {
                    fired |= bit;
                    let rd = &self.rule_data[*rule_idx];
                    if self.strict && rd.is_critical {
                        return Decision::DenyCritical {
                            rule_idx: *rule_idx,
                        };
                    }
                    violations.push(Violation {
                        rule_idx: *rule_idx,
                        rule_id: rd.rule_id.clone(),
                        rule_text: rd.rule_text.clone(),
                        severity: rd.severity_enum,
                        matched_content: String::new(),
                        category: rd.category.clone(),
                    });
                }
            }
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
}
