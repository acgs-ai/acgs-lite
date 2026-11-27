/// acgs-validator-wasm — WASM binding for the ACGS governance validator.
///
/// Exposes `WasmValidator` to JavaScript via wasm-bindgen.
/// Designed for Cloudflare Workers: load constitution from JSON,
/// validate actions, return structured results.
///
/// Constitutional Hash: 608508a9bd224290
use std::collections::{HashMap, HashSet};

use acgs_validator_core::{
    context::ContextRule, severity::Severity, GovernanceValidator, ValidatorConfig,
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// JSON schema for constructing a validator from a constitution.
#[derive(Deserialize)]
struct ConstitutionConfig {
    /// Map of keyword → [(rule_idx, keyword_has_negative)]
    kw_to_idxs: HashMap<String, Vec<(usize, bool)>>,
    /// [(anchor_string, [(rule_idx, pattern_string)])]
    anchor_dispatch: Vec<(String, Vec<(usize, String)>)>,
    /// [(rule_idx, pattern_string)]
    no_anchor_pats: Vec<(usize, String)>,
    /// [(rule_id, rule_text, severity_str, category, is_critical)]
    rule_data: Vec<(String, String, String, String, bool)>,
    /// Positive verb set
    positive_verbs: Vec<String>,
    /// Strict mode
    strict: bool,
    /// Optional context rules
    #[serde(default)]
    context_rules: Vec<ContextRuleConfig>,
    /// Constitutional hash
    #[serde(default)]
    const_hash: String,
}

#[derive(Deserialize)]
struct ContextRuleConfig {
    rule_id: String,
    rule_text: String,
    severity: String,
    category: String,
    keywords_lower: Vec<String>,
    patterns: Vec<String>,
    enabled: bool,
}

/// JSON schema for validation input context.
#[derive(Deserialize)]
struct ValidateInput {
    /// The action text to validate
    text: String,
    /// Optional context key-value pairs
    #[serde(default)]
    context: Vec<(String, String)>,
}

/// JSON schema for validation output.
#[derive(Serialize)]
struct ValidateOutput {
    decision: i32,
    valid: bool,
    violations: Vec<ViolationOutput>,
    blocking: bool,
    constitutional_hash: String,
    rules_checked: usize,
}

#[derive(Serialize)]
struct ViolationOutput {
    rule_id: String,
    rule_text: String,
    severity: String,
    matched_content: String,
    category: String,
}

/// WASM-exported governance validator.
#[wasm_bindgen]
pub struct WasmValidator {
    inner: GovernanceValidator,
}

#[wasm_bindgen]
impl WasmValidator {
    /// Create a new validator from a JSON constitution config.
    ///
    /// Throws on invalid config (bad regex, too many rules, etc.).
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str) -> Result<WasmValidator, JsError> {
        let config: ConstitutionConfig =
            serde_json::from_str(config_json).map_err(|e| JsError::new(&e.to_string()))?;

        // Convert context rules
        let context_rules: Vec<ContextRule> = config
            .context_rules
            .into_iter()
            .map(|cr| {
                let compiled_patterns: Vec<Regex> = cr
                    .patterns
                    .iter()
                    .map(|p| RegexBuilder::new(p).case_insensitive(true).build())
                    .collect::<Result<_, _>>()
                    .map_err(|e| JsError::new(&format!("Bad context regex: {}", e)))?;
                Ok(ContextRule {
                    rule_id: cr.rule_id,
                    rule_text: cr.rule_text,
                    severity: Severity::from_label(&cr.severity),
                    category: cr.category,
                    keywords_lower: cr.keywords_lower,
                    compiled_patterns,
                    enabled: cr.enabled,
                })
            })
            .collect::<Result<_, JsError>>()?;

        let validator_config = ValidatorConfig {
            kw_to_idxs: config.kw_to_idxs,
            anchor_dispatch: config.anchor_dispatch,
            no_anchor_pats: config.no_anchor_pats,
            rule_data: config.rule_data,
            positive_verbs: config.positive_verbs.into_iter().collect::<HashSet<_>>(),
            strict: config.strict,
            context_rules,
            const_hash: config.const_hash,
        };

        let inner =
            GovernanceValidator::new(validator_config).map_err(|e| JsError::new(&e.to_string()))?;

        Ok(WasmValidator { inner })
    }

    /// Validate an action against the constitution.
    ///
    /// Input: JSON string with `{ "text": "...", "context": [["key", "value"], ...] }`
    /// Output: JSON string with decision, violations, blocking flag, hash.
    pub fn validate(&self, input_json: &str) -> Result<String, JsError> {
        let input: ValidateInput =
            serde_json::from_str(input_json).map_err(|e| JsError::new(&e.to_string()))?;

        let context_pairs = if input.context.is_empty() {
            None
        } else {
            Some(input.context.as_slice())
        };

        let result = self.inner.validate(&input.text, context_pairs);

        let output = ValidateOutput {
            decision: result.decision,
            valid: result.violations.is_empty(),
            violations: result
                .violations
                .into_iter()
                .map(|v| ViolationOutput {
                    rule_id: v.rule_id,
                    rule_text: v.rule_text,
                    severity: v.severity,
                    matched_content: v.matched_content,
                    category: v.category,
                })
                .collect(),
            blocking: result.blocking,
            constitutional_hash: result.constitutional_hash,
            rules_checked: result.rules_checked,
        };

        serde_json::to_string(&output).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Get the constitutional hash.
    pub fn const_hash(&self) -> String {
        self.inner.const_hash().to_string()
    }

    /// Quick hot-path validation (returns decision code and bitmask).
    ///
    /// Returns: `[decision_code, data]` as a JSON array.
    /// Note: JavaScript `JSON.parse()` loses integer precision above `2^53 - 1`
    /// (rule index >= 53); use `validate_hot_hex` when >53 rules are compiled.
    pub fn validate_hot(&self, text_lower: &str) -> String {
        let (decision, data) = self.inner.validate_hot_u128(text_lower);
        format!("[{},{}]", decision, data)
    }

    /// Lossless hot-path validation for >53 rules: returns `[decision_code,"<hex>"]`
    /// so JavaScript callers can decode the full 128-bit mask with `BigInt("0x" + hex)`.
    pub fn validate_hot_hex(&self, text_lower: &str) -> String {
        let (decision, data) = self.inner.validate_hot_u128(text_lower);
        format!("[{},\"{:x}\"]", decision, data)
    }
}
