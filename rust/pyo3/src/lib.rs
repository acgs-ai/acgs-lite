/// acgs_lite_rust — PyO3 thin wrapper over acgs-validator-core.
///
/// Converts Python types to Rust types and delegates to the core validator.
///
/// Constitutional Hash: 608508a9bd224290
use std::collections::{HashMap, HashSet};

use acgs_validator_core::{
    context::ContextRule, result::ViolationTuple, severity::Severity, BuildError,
    GovernanceValidator, ValidatorConfig, ALLOW, DENY, DENY_CRITICAL,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use regex::Regex;

/// PyO3 wrapper around the core GovernanceValidator.
#[pyclass(name = "GovernanceValidator")]
struct PyGovernanceValidator {
    inner: GovernanceValidator,
}

#[pymethods]
impl PyGovernanceValidator {
    /// Constructor — accepts Python types, converts to Rust, delegates to core.
    #[new]
    #[pyo3(signature = (kw_to_idxs, anchor_dispatch_py, no_anchor_pats_py, rule_data_py, positive_verbs_py, strict, context_rules_py=None, const_hash=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        kw_to_idxs: &Bound<'_, PyDict>,
        anchor_dispatch_py: &Bound<'_, PyList>,
        no_anchor_pats_py: &Bound<'_, PyList>,
        rule_data_py: &Bound<'_, PyList>,
        positive_verbs_py: &Bound<'_, PyList>,
        strict: bool,
        context_rules_py: Option<&Bound<'_, PyList>>,
        const_hash: Option<String>,
    ) -> PyResult<Self> {
        // Extract anchor_dispatch
        let mut anchor_dispatch: Vec<(String, Vec<(usize, String)>)> = Vec::new();
        for item in anchor_dispatch_py.iter() {
            let tuple = item.cast::<PyTuple>()?;
            let anchor: String = tuple.get_item(0)?.extract()?;
            let pats_py = tuple.get_item(1)?.cast_into::<PyList>()?;
            let mut patterns: Vec<(usize, String)> = Vec::with_capacity(pats_py.len());
            for pat_item in pats_py.iter() {
                let pt = pat_item.cast::<PyTuple>()?;
                let rule_idx: usize = pt.get_item(0)?.extract()?;
                let pat_str: String = pt.get_item(1)?.extract()?;
                patterns.push((rule_idx, pat_str));
            }
            anchor_dispatch.push((anchor, patterns));
        }

        // Extract kw_to_idxs
        let mut kw_map: HashMap<String, Vec<(usize, bool)>> = HashMap::new();
        for (key, val) in kw_to_idxs.iter() {
            let kw: String = key.extract()?;
            let idxs_py = val.cast::<PyList>()?;
            let mut idxs: Vec<(usize, bool)> = Vec::with_capacity(idxs_py.len());
            for item in idxs_py.iter() {
                let t = item.cast::<PyTuple>()?;
                let rule_idx: usize = t.get_item(0)?.extract()?;
                let has_neg: bool = t.get_item(1)?.extract()?;
                idxs.push((rule_idx, has_neg));
            }
            kw_map.insert(kw, idxs);
        }

        // Extract no-anchor patterns
        let mut no_anchor_pats: Vec<(usize, String)> = Vec::new();
        for item in no_anchor_pats_py.iter() {
            let t = item.cast::<PyTuple>()?;
            let rule_idx: usize = t.get_item(0)?.extract()?;
            let pat_str: String = t.get_item(1)?.extract()?;
            no_anchor_pats.push((rule_idx, pat_str));
        }

        // Extract rule data
        let mut rule_data: Vec<(String, String, String, String, bool)> =
            Vec::with_capacity(rule_data_py.len());
        for item in rule_data_py.iter() {
            let t = item.cast::<PyTuple>()?;
            rule_data.push((
                t.get_item(0)?.extract()?,
                t.get_item(1)?.extract()?,
                t.get_item(2)?.extract()?,
                t.get_item(3)?.extract()?,
                t.get_item(4)?.extract()?,
            ));
        }

        // Extract positive verbs
        let mut positive_verbs: HashSet<String> = HashSet::new();
        for item in positive_verbs_py.iter() {
            positive_verbs.insert(item.extract()?);
        }

        // Extract context rules
        let context_rules = if let Some(cr_py) = context_rules_py {
            let mut rules = Vec::with_capacity(cr_py.len());
            for item in cr_py.iter() {
                let t = item.cast::<PyTuple>()?;
                let rule_id: String = t.get_item(0)?.extract()?;
                let rule_text: String = t.get_item(1)?.extract()?;
                let sev_str: String = t.get_item(2)?.extract()?;
                let category: String = t.get_item(3)?.extract()?;
                let kws_py = t.get_item(4)?.cast_into::<PyList>()?;
                let pats_py = t.get_item(5)?.cast_into::<PyList>()?;
                let enabled: bool = t.get_item(6)?.extract()?;

                let keywords_lower: Vec<String> = kws_py
                    .iter()
                    .map(|k| k.extract::<String>())
                    .collect::<PyResult<_>>()?;

                let compiled_patterns: Vec<Regex> = pats_py
                    .iter()
                    .map(|p| {
                        let s: String = p.extract()?;
                        Regex::new(&format!("(?i){}", s)).map_err(|e| {
                            PyValueError::new_err(format!("Bad context regex '{}': {}", s, e))
                        })
                    })
                    .collect::<PyResult<_>>()?;

                rules.push(ContextRule {
                    rule_id,
                    rule_text,
                    severity: Severity::from_label(&sev_str),
                    category,
                    keywords_lower,
                    compiled_patterns,
                    enabled,
                });
            }
            rules
        } else {
            Vec::new()
        };

        let config = ValidatorConfig {
            kw_to_idxs: kw_map,
            anchor_dispatch,
            no_anchor_pats,
            rule_data,
            positive_verbs,
            strict,
            context_rules,
            const_hash: const_hash.unwrap_or_default(),
        };

        let inner = GovernanceValidator::new(config).map_err(|e| match e {
            BuildError::BadRegex { pattern, message } => {
                PyValueError::new_err(format!("Bad regex '{}': {}", pattern, message))
            }
            BuildError::TooManyRules { count } => PyValueError::new_err(format!(
                "GovernanceValidator: rule count {} exceeds 63 (u64 bitmask limit)",
                count
            )),
            BuildError::TooManyAnchors { count } => PyValueError::new_err(format!(
                "GovernanceValidator: anchor count {} exceeds 63 (u64 bitmask limit)",
                count
            )),
            BuildError::AhoCorasickBuild(msg) => {
                PyValueError::new_err(format!("AC build error: {}", msg))
            }
        })?;

        Ok(PyGovernanceValidator { inner })
    }

    /// Legacy hot-path validation.
    /// Hot-path validation. Accepts any-case text, lowercases internally.
    /// exp271: Moving lowercase into Rust saves ~54ns Python str.lower() + avoids
    /// allocating a Python string object. Rust's to_ascii_lowercase() is SIMD-optimized.
    fn validate_hot(&self, text: &str) -> PyResult<(i32, i64)> {
        // exp272: Use stack buffer for short strings (≤256 bytes, covers 99%+ of
        // governance actions). Avoids heap allocation for to_ascii_lowercase().
        // Non-ASCII input needs full Unicode lowercasing (parity with Python
        // str.lower()); ASCII-only folding would leave e.g. "Ñ" uppercase and a
        // keyword such as "contraseña" would never match.
        if !text.is_ascii() {
            return Ok(self.inner.validate_hot(&text.to_lowercase()));
        }
        let len = text.len();
        if len <= 256 {
            let mut buf = [0u8; 256];
            buf[..len].copy_from_slice(text.as_bytes());
            buf[..len].make_ascii_lowercase();
            // SAFETY: input was valid UTF-8, ASCII lowercase preserves validity
            let lowered = unsafe { std::str::from_utf8_unchecked(&buf[..len]) };
            Ok(self.inner.validate_hot(lowered))
        } else {
            let lowered = text.to_ascii_lowercase();
            Ok(self.inner.validate_hot(&lowered))
        }
    }

    /// Full validation with structured violation data.
    #[pyo3(signature = (text, context_pairs=None))]
    /// exp271: accepts any-case text, lowercases internally.
    fn validate_full(
        &self,
        text: &str,
        context_pairs: Option<Vec<(String, String)>>,
    ) -> PyResult<(i32, Vec<ViolationTuple>, bool)> {
        let lowered = if text.is_ascii() {
            text.to_ascii_lowercase()
        } else {
            text.to_lowercase()
        };
        Ok(self.inner.validate_full(&lowered, context_pairs.as_deref()))
    }

    /// Get the constitutional hash.
    #[getter]
    fn const_hash(&self) -> &str {
        self.inner.const_hash()
    }
}

#[pymodule]
fn acgs_lite_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Python expects `GovernanceValidator` — use #[pyclass(name = ...)] or rename
    m.add_class::<PyGovernanceValidator>()?;
    m.add("ALLOW", ALLOW)?;
    m.add("DENY_CRITICAL", DENY_CRITICAL)?;
    m.add("DENY", DENY)?;
    Ok(())
}
