# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs bundle — export, verify, and demo deterministic compliance receipt bundles."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

# Keep compliance/legitimacy imports lazy inside handlers so importing acgs_lite.cli
# never expands the Trusted Computing Base closure (TestHigh2TrustedComputingBase).
_BUNDLE_DEMO_SEED = b"acgs-bundle-demo-seed-2026-11-!!"[:32]
_BUNDLE_DEMO_KEY_ID = "acgs-bundle-demo-k1"
_PROFILE_CA_ADMT = "ca-admt-2027"
_PROFILE_EU_AI_ACT = "eu-ai-act-art12-26"
_PROFILE_CHOICES = (_PROFILE_CA_ADMT, _PROFILE_EU_AI_ACT)
_SCITT_KIND_CHOICES = ("auto", "bundle", "decision", "outcome", "json")
_ASCII_HEX_RE = re.compile(r"[0-9a-fA-F]+")


class _BundleCliError(ValueError):
    """Fail-closed CLI input/IO validation error."""


def _demo_action(operation: str, *, scope: str, subject: str) -> dict[str, str]:
    return {"operation": operation, "scope": scope, "subject": subject}


def _load_json_value(path: Path, *, label: str) -> Any:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _BundleCliError(f"Failed to read {label} file {path}: {exc}") from exc
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise _BundleCliError(f"Invalid JSON in {label} file {path}: {exc}") from exc


def _load_json_records(path: Path, *, label: str) -> list[dict[str, Any]]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _BundleCliError(f"Failed to read {label} file {path}: {exc}") from exc

    stripped = raw_text.strip()
    if not stripped:
        return []

    if stripped[0] == "[":
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise _BundleCliError(f"Invalid JSON array in {label} file {path}: {exc}") from exc
        if not isinstance(loaded, list):
            raise _BundleCliError(f"{label} file {path} must contain a JSON array or JSONL")
        out: list[dict[str, Any]] = []
        for idx, item in enumerate(loaded):
            if not isinstance(item, dict):
                raise _BundleCliError(f"{label}[{idx}] in {path} must be a JSON object")
            out.append(item)
        return out

    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(raw_text.splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise _BundleCliError(f"Invalid JSONL at {path}:{line_no} in {label}: {exc}") from exc
        if not isinstance(obj, dict):
            raise _BundleCliError(f"Line {line_no} in {label} file {path} must be a JSON object")
        records.append(obj)
    return records


def _load_trusted_verifiers(path: Path) -> dict[str, str]:
    loaded = _load_json_value(path, label="keys")
    if not isinstance(loaded, dict) or not loaded:
        raise _BundleCliError(f"Keys file {path} must contain a non-empty JSON object")
    verifiers: dict[str, str] = {}
    for key_id, hex_val in loaded.items():
        if not isinstance(key_id, str) or not key_id.strip():
            raise _BundleCliError(f"Keys file {path} contains an empty or non-string key_id")
        if not isinstance(hex_val, str) or not hex_val.strip():
            raise _BundleCliError(
                f"Keys file {path} entry {key_id!r} must be a non-empty hex string"
            )
        verifiers[key_id] = hex_val
    return verifiers


def _write_json_file(path: Path, payload: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise _BundleCliError(f"Failed to write output file {path}: {exc}") from exc


def _cmd_export(args: argparse.Namespace) -> int:
    from acgs_lite.compliance.receipt_bundle import BundleExportError, export_receipt_bundle
    from acgs_lite.legitimacy import (
        ReceiptSigningUnavailable,
        SignedOutcomeReceipt,
        SignedReceipt,
    )

    try:
        trusted_verifiers = _load_trusted_verifiers(Path(args.keys))
        receipt_dicts = _load_json_records(Path(args.receipts), label="receipts")
        receipts: list[SignedReceipt] = []
        for idx, item in enumerate(receipt_dicts):
            try:
                receipts.append(SignedReceipt.from_dict(item))
            except (TypeError, ValueError) as exc:
                raise _BundleCliError(f"Invalid SignedReceipt at receipts[{idx}]: {exc}") from exc

        outcomes: list[SignedOutcomeReceipt] = []
        if args.outcomes is not None:
            outcome_dicts = _load_json_records(Path(args.outcomes), label="outcomes")
            for idx, item in enumerate(outcome_dicts):
                try:
                    outcomes.append(SignedOutcomeReceipt.from_dict(item))
                except (TypeError, ValueError) as exc:
                    raise _BundleCliError(
                        f"Invalid SignedOutcomeReceipt at outcomes[{idx}]: {exc}"
                    ) from exc

        escalations = (
            _load_json_records(Path(args.escalations), label="escalations")
            if args.escalations is not None
            else []
        )
        halt_events = (
            _load_json_records(Path(args.halts), label="halts") if args.halts is not None else []
        )

        bundle = export_receipt_bundle(
            receipts,
            profile=args.profile,
            trusted_public_keys=trusted_verifiers,
            system_id=args.system_id,
            outcome_receipts=outcomes,
            retention_days=args.retention_days,
            escalations=escalations,
            halt_events=halt_events,
            generated_at=args.generated_at,
        )
        if args.out is not None:
            out_path = Path(args.out)
            _write_json_file(out_path, bundle.to_dict())
            summary = {
                "bundle_digest": bundle.bundle_digest,
                "profile": bundle.profile,
                "system_id": bundle.system_id,
                "decision_count": len(bundle.decisions),
                "adverse_decision_count": len(bundle.adverse_decisions),
                "outcome_count": len(bundle.outcomes),
                "output_path": str(out_path),
            }
            if getattr(args, "json_out", False):
                print(json.dumps(summary, indent=2, sort_keys=True))
            else:
                print(
                    f"Exported {bundle.profile} bundle ({bundle.bundle_digest}) -> {out_path} "
                    f"[{len(bundle.decisions)} decisions, {len(bundle.outcomes)} outcomes]"
                )
        else:
            print(bundle.to_json(indent=2))
        return 0
    except ReceiptSigningUnavailable as exc:
        print(
            f"Error: {exc}. Install cryptography via: pip install 'acgs-lite[crypto]'",
            file=sys.stderr,
        )
        return 1
    except (_BundleCliError, BundleExportError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_verify(args: argparse.Namespace) -> int:
    from acgs_lite.compliance.receipt_bundle import verify_receipt_bundle

    try:
        trusted_verifiers = _load_trusted_verifiers(Path(args.keys))
        bundle_obj = _load_json_value(Path(args.bundle), label="bundle")
        ver = verify_receipt_bundle(bundle_obj, trusted_public_keys=trusted_verifiers)
    except (_BundleCliError, TypeError, ValueError) as exc:
        if getattr(args, "json_out", False):
            print(
                json.dumps(
                    {
                        "valid": False,
                        "profile": None,
                        "bundle_digest": None,
                        "verified_decision_count": 0,
                        "verified_outcome_count": 0,
                        "reasons": [str(exc)],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    payload = {
        "valid": ver.valid,
        "profile": ver.profile,
        "bundle_digest": ver.bundle_digest,
        "verified_decision_count": ver.verified_decision_count,
        "verified_outcome_count": ver.verified_outcome_count,
        "reasons": list(ver.reasons),
    }
    if getattr(args, "json_out", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif ver.valid:
        print(
            f"VALID {ver.profile} bundle ({ver.bundle_digest}) — "
            f"{ver.verified_decision_count} decisions, {ver.verified_outcome_count} outcomes verified."
        )
    else:
        print(f"INVALID {ver.profile or 'unknown'} bundle:", file=sys.stderr)
        for reason in ver.reasons:
            print(f"  - {reason}", file=sys.stderr)
    return 0 if ver.valid else 1


def _mint_adverse_receipt(
    signer: Any,
    *,
    request_id: str,
    goal: str,
    decision_type: Any,
    rule_id: str,
    rationale: str,
) -> Any:
    from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary, sign_receipt

    boundary = ExecutionBoundary(
        allowed_method="_demo_action",
        allowed_scope="prod-demo",
        allowed_subjects=("acct-1042",),
        expires_at="2027-12-31T00:00:00Z",
        single_use=True,
    )
    receipt = DecisionReceipt.create(
        request_id=request_id,
        goal=goal,
        proposed_method="_demo_action",
        decision_type=decision_type,
        authority_basis="constitution:bundle-demo",
        matched_constraints=(rule_id,),
        policy_version="2026.11",
        denial_or_review_rationale=rationale,
        execution_boundary=boundary,
    )
    return sign_receipt(receipt, signer)


def _build_demo_provider() -> Any:
    from acgs_lite.legitimacy import (
        EffectOutcome,
        EffectRequest,
        ProviderContract,
        ProviderContractClass,
        ProviderResult,
    )

    class _DemoFencedLedgerProvider:
        contract = ProviderContract(
            provider_id="demo-ledger",
            contract_class=ProviderContractClass.FENCEABLE,
            version="2026-11",
            dedup_by_key=True,
            atomic_query_fence=True,
        )

        @property
        def provider_id(self) -> str:
            return self.contract.provider_id

        def send(self, request: EffectRequest) -> ProviderResult:
            return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)

        def query_and_fence(self, request: EffectRequest) -> ProviderResult:
            return ProviderResult(
                request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True
            )

    return _DemoFencedLedgerProvider()


def _cmd_demo(args: argparse.Namespace) -> int:
    from acgs_lite.compliance.receipt_bundle import (
        BundleExportError,
        export_receipt_bundle,
        verify_receipt_bundle,
    )
    from acgs_lite.constitution import Constitution, Rule, Severity
    from acgs_lite.engine.core import GovernanceEngine
    from acgs_lite.legitimacy import (
        ContractedEffectStore,
        Ed25519ReceiptSigner,
        EffectStore,
        ExecutionAuthority,
        ProviderContractRegistry,
        ReceiptSigningUnavailable,
        bind_invocation,
        bind_policy,
        local_grant_identity,
        outcome_from_record,
        sign_execution_authorization,
        sign_outcome,
    )
    from acgs_lite.legitimacy.authorization import (
        authorization_envelope_json,
        build_issue_receipt,
        engine_decision_from_results,
    )

    try:
        signer = Ed25519ReceiptSigner.from_seed(_BUNDLE_DEMO_SEED, key_id=_BUNDLE_DEMO_KEY_ID)
        trusted = {signer.key_id: signer.public_key_hex()}

        constitution = Constitution(
            name="acgs-bundle-demo",
            version="2026.11",
            rules=[
                Rule(
                    id="no-raw-ssn",
                    text="Block raw PII before side effects",
                    severity=Severity.CRITICAL,
                    keywords=["raw_ssn"],
                )
            ],
        )
        engine = GovernanceEngine(constitution, strict=False)
        authority = ExecutionAuthority()
        provider = _build_demo_provider()
        registry = ProviderContractRegistry()
        registry.register(provider.contract)

        op = "refund invoice inv-2048"
        val_result = engine.validate(op, agent_id="bundle-demo-agent")
        invocation = bind_invocation(
            _demo_action, (op,), {"scope": "prod-demo", "subject": "acct-1042"}
        )
        policy = bind_policy(constitution)
        decision = engine_decision_from_results([val_result])
        grant_id = authority.allocate_grant_id()
        try:
            allow_receipt = build_issue_receipt(
                func=_demo_action,
                invocation=invocation,
                policy=policy,
                decision=decision,
                grant_id=grant_id,
            )
            signed_allow = sign_execution_authorization(
                allow_receipt,
                signer,
                authorization_json=authorization_envelope_json(
                    invocation, policy, grant_id=grant_id
                ),
            )
            grant = authority.issue(
                receipt=allow_receipt,
                invocation=invocation,
                policy=policy,
                grant_id=grant_id,
                signed_receipt=signed_allow,
            )
        finally:
            authority.release_grant_id(grant_id)

        with tempfile.TemporaryDirectory(prefix="acgs-bundle-demo-") as tmp_dir:
            store = EffectStore(Path(tmp_dir) / "bundle_demo.sqlite")
            store.create_budget("bundle-demo", 100)
            contracted = ContractedEffectStore(store, registry)
            eff = store.reserve(
                provider_id=provider.provider_id,
                grant_identity=local_grant_identity(grant),
                action={"op": "refund", "invoice": "inv-2048", "amount_cents": 2500},
                budget_id="bundle-demo",
                amount=1,
            )
            rec = contracted.send(eff.key, provider, grant=grant)
            signed_outcome = sign_outcome(
                outcome_from_record(
                    rec,
                    store=contracted,
                    provider=provider,
                    grant=grant,
                    provider_reference="ch_demo_2048",
                ),
                signer,
            )

        signed_deny = _mint_adverse_receipt(
            signer,
            request_id="req-demo-deny-1",
            goal="export raw_ssn field",
            decision_type="DENY_GOAL",
            rule_id="no-raw-ssn",
            rationale="Blocked raw PII before side effect",
        )
        signed_review = _mint_adverse_receipt(
            signer,
            request_id="req-demo-review-1",
            goal="high-value wire override",
            decision_type="STRUCTURED_REVIEW_REQUIRED",
            rule_id="dual-control-threshold",
            rationale="Escalated for independent human approval",
        )

        bundle = export_receipt_bundle(
            [signed_allow, signed_deny, signed_review],
            profile=args.profile,
            trusted_public_keys=trusted,
            system_id="acgs-demo-system",
            outcome_receipts=[signed_outcome],
            retention_days=180,
            escalations=[
                {
                    "escalation_id": "esc-demo-1",
                    "request_id": "req-demo-review-1",
                    "proposer_id": "agent-refund-1",
                    "approver_id": "alice.reviewer@acgs.ai",
                    "decision": "approve",
                    "decided_at": "2026-11-27T12:00:00Z",
                    "rationale": "Verified dual-control invoice",
                }
            ],
            halt_events=[
                {
                    "event": "circuit_breaker_drill",
                    "system_id": "acgs-demo-system",
                    "recorded_at": "2026-11-27T12:05:00Z",
                }
            ],
        )

        ver_ok = verify_receipt_bundle(bundle.to_dict(), trusted_public_keys=trusted)
        tampered = copy.deepcopy(bundle.to_dict())
        tampered["decisions"][1]["decision_type"] = "ALLOW"
        ver_tampered = verify_receipt_bundle(tampered, trusted_public_keys=trusted)

        out_path: str | None = None
        if args.out is not None:
            _write_json_file(Path(args.out), bundle.to_dict())
            out_path = str(args.out)

        keys_out_path: str | None = None
        if args.keys_out is not None:
            # Extract public verification anchors from the verified bundle envelope
            # rather than from the signer object directly.
            verifier_anchors = {
                str(entry["signed_receipt"]["key_id"]): str(entry["signed_receipt"]["public_key"])
                for entry in bundle.decisions[:1]
            }
            _write_json_file(Path(args.keys_out), verifier_anchors)
            keys_out_path = str(args.keys_out)

        all_passed = ver_ok.valid and not ver_tampered.valid
        summary = {
            "all_passed": all_passed,
            "profile": bundle.profile,
            "bundle_digest": bundle.bundle_digest,
            "verified_valid": ver_ok.valid,
            "tampered_rejected": not ver_tampered.valid,
            "verified_decision_count": ver_ok.verified_decision_count,
            "verified_outcome_count": ver_ok.verified_outcome_count,
            "adverse_decision_count": len(bundle.adverse_decisions),
            "output_path": out_path,
            "keys_output_path": keys_out_path,
            "bundle_verification": {
                "valid": ver_ok.valid,
                "reasons": list(ver_ok.reasons),
            },
            "tampered_verification": {
                "valid": ver_tampered.valid,
                "reasons": list(ver_tampered.reasons),
            },
        }
        if getattr(args, "json_out", False):
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(f"Profile: {bundle.profile} | Digest: {bundle.bundle_digest}")
            print(
                f"Verified bundle: valid={ver_ok.valid} "
                f"({ver_ok.verified_decision_count} decisions, {ver_ok.verified_outcome_count} outcomes)"
            )
            print(f"Tamper check:    rejected={not ver_tampered.valid}")
            if out_path is not None:
                print(f"Bundle written:  {out_path}")
            if keys_out_path is not None:
                print(f"Keys written:    {keys_out_path}")
        return 0 if all_passed else 1
    except ReceiptSigningUnavailable as exc:
        print(
            f"Error: {exc}. Install cryptography via: pip install 'acgs-lite[crypto]'",
            file=sys.stderr,
        )
        return 1
    except (_BundleCliError, BundleExportError, OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _parse_hex_bytes(raw: str | None, *, label: str) -> bytes:
    if raw is None:
        return b""
    if not isinstance(raw, str):
        raise _BundleCliError(f"{label} must be a hexadecimal string")
    cleaned = raw.strip()
    if not cleaned or len(cleaned) % 2 != 0 or _ASCII_HEX_RE.fullmatch(cleaned) is None:
        raise _BundleCliError(f"{label} must be non-empty even-length hexadecimal")
    return bytes.fromhex(cleaned)


def _detect_scitt_kind(payload_obj: dict[str, Any]) -> str:
    if payload_obj.get("schema_version") == "acgs-compliance-bundle-v1":
        return "bundle"
    inner = payload_obj.get("receipt")
    if isinstance(inner, dict):
        if "effect_key" in inner:
            return "outcome"
        if "receipt_hash" in inner:
            return "decision"
    return "json"


def _load_scitt_signer(args: argparse.Namespace) -> Any:
    from acgs_lite.legitimacy import Ed25519ReceiptSigner

    raw_key_id = getattr(args, "key_id", None)
    key_id: str | None = None
    if raw_key_id is not None:
        if not isinstance(raw_key_id, str) or not raw_key_id.strip():
            raise _BundleCliError("--key-id must be a non-empty string")
        key_id = raw_key_id.strip()

    if getattr(args, "demo_key", False):
        return Ed25519ReceiptSigner.from_seed(
            _BUNDLE_DEMO_SEED,
            key_id=key_id or _BUNDLE_DEMO_KEY_ID,
        )

    env_name = getattr(args, "signing_key_env", None)
    if not isinstance(env_name, str) or not env_name.strip():
        raise _BundleCliError("Specify either --demo-key or --signing-key-env")
    env_var = env_name.strip()
    seed_hex = os.environ.get(env_var, "").strip()
    if len(seed_hex) != 64 or _ASCII_HEX_RE.fullmatch(seed_hex) is None:
        raise _BundleCliError(
            f"Environment variable {env_var!r} must contain a 64-character hex Ed25519 seed"
        )
    return Ed25519ReceiptSigner.from_seed(bytes.fromhex(seed_hex), key_id=key_id)


def _cmd_scitt_export(args: argparse.Namespace) -> int:
    from acgs_lite.compliance.receipt_bundle import verify_receipt_bundle
    from acgs_lite.compliance.scitt import (
        MEDIA_TYPE_COMPLIANCE_BUNDLE,
        SCITTExportError,
        export_scitt_cose_sign1,
    )
    from acgs_lite.legitimacy import (
        ReceiptSigningUnavailable,
        SignedOutcomeReceipt,
        SignedReceipt,
    )

    try:
        payload_raw = _load_json_value(Path(args.input), label="input")
        if not isinstance(payload_raw, dict):
            raise _BundleCliError("SCITT export input JSON must be an object")

        kind = _detect_scitt_kind(payload_raw) if args.kind == "auto" else args.kind
        trusted_keys = _load_trusted_verifiers(Path(args.keys)) if args.keys is not None else None

        scitt_payload: Any
        resolved_content_type = args.content_type
        if kind == "decision":
            signed_dec = SignedReceipt.from_dict(payload_raw)
            if trusted_keys is not None:
                trusted_pk = trusted_keys.get(signed_dec.key_id)
                if not isinstance(trusted_pk, str) or not signed_dec.verify(trusted_pk):
                    raise _BundleCliError(
                        f"Input SignedReceipt failed pinned verification for key_id {signed_dec.key_id!r}"
                    )
            scitt_payload = signed_dec
        elif kind == "outcome":
            signed_out = SignedOutcomeReceipt.from_dict(payload_raw)
            if trusted_keys is not None:
                trusted_pk = trusted_keys.get(signed_out.key_id)
                if not isinstance(trusted_pk, str) or not signed_out.verify(trusted_pk):
                    raise _BundleCliError(
                        "Input SignedOutcomeReceipt failed pinned verification for "
                        f"key_id {signed_out.key_id!r}"
                    )
            scitt_payload = signed_out
        elif kind == "bundle":
            if trusted_keys is not None:
                bundle_ver = verify_receipt_bundle(
                    payload_raw,
                    trusted_public_keys=trusted_keys,
                )
                if not bundle_ver.valid:
                    raise _BundleCliError(
                        "Input compliance bundle failed pre-export verification: "
                        + "; ".join(bundle_ver.reasons)
                    )
            scitt_payload = payload_raw
            if resolved_content_type is None:
                resolved_content_type = MEDIA_TYPE_COMPLIANCE_BUNDLE
        else:
            scitt_payload = payload_raw

        external_aad = _parse_hex_bytes(args.external_aad_hex, label="external-aad-hex")
        signer = _load_scitt_signer(args)
        envelope = export_scitt_cose_sign1(
            scitt_payload,
            signer,
            content_type=resolved_content_type,
            issuer=args.issuer,
            subject=args.subject,
            issued_at=args.issued_at,
            external_aad=external_aad,
        )

        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(envelope.cose_bytes)

        output_meta = {
            **envelope.to_metadata_dict(),
            "output_path": str(out_path),
            "kind": kind,
            "demo_key_used": bool(args.demo_key),
        }
        if getattr(args, "json_out", False):
            print(json.dumps(output_meta, indent=2, sort_keys=True))
        else:
            print(
                f"Exported SCITT COSE_Sign1 ({envelope.content_type}, key_id={envelope.key_id}) "
                f"-> {out_path} [{len(envelope.cose_bytes)} bytes]"
            )
        return 0
    except ReceiptSigningUnavailable as exc:
        print(
            f"Error: {exc}. Install cryptography via: pip install 'acgs-lite[crypto]'",
            file=sys.stderr,
        )
        return 1
    except (_BundleCliError, SCITTExportError, OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_scitt_verify(args: argparse.Namespace) -> int:
    from acgs_lite.compliance.scitt import verify_scitt_cose_sign1
    from acgs_lite.legitimacy import ReceiptSigningUnavailable

    try:
        cose_path = Path(args.cose)
        try:
            raw_bytes = cose_path.read_bytes()
        except OSError as exc:
            raise _BundleCliError(f"Failed to read COSE file {cose_path}: {exc}") from exc
        if not raw_bytes:
            raise _BundleCliError(f"COSE file {cose_path} is empty")

        trusted_keys = _load_trusted_verifiers(Path(args.keys))
        external_aad = _parse_hex_bytes(args.external_aad_hex, label="external-aad-hex")
        result = verify_scitt_cose_sign1(
            raw_bytes,
            trusted_keys,
            expected_content_type=args.expected_content_type,
            expected_issuer=args.expected_issuer,
            external_aad=external_aad,
        )
    except ReceiptSigningUnavailable as exc:
        print(
            f"Error: {exc}. Install cryptography via: pip install 'acgs-lite[crypto]'",
            file=sys.stderr,
        )
        return 1
    except (_BundleCliError, TypeError, ValueError) as exc:
        if getattr(args, "json_out", False):
            print(
                json.dumps(
                    {
                        "valid": False,
                        "key_id": None,
                        "content_type": None,
                        "payload_sha256": None,
                        "issuer": None,
                        "subject": None,
                        "issued_at": None,
                        "errors": [str(exc)],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1

    output = {
        "valid": result.valid,
        "key_id": result.key_id,
        "content_type": result.content_type,
        "payload_sha256": result.payload_sha256,
        "issuer": result.issuer,
        "subject": result.subject,
        "issued_at": result.issued_at,
        "errors": list(result.errors),
    }
    if getattr(args, "json_out", False):
        print(json.dumps(output, indent=2, sort_keys=True))
    elif result.valid:
        print(
            f"VALID SCITT COSE_Sign1 ({result.content_type}, key_id={result.key_id}, "
            f"sha256={result.payload_sha256})"
        )
    else:
        print("INVALID SCITT COSE_Sign1:", file=sys.stderr)
        for err in result.errors:
            print(f"  - {err}", file=sys.stderr)
    return 0 if result.valid else 1


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``acgs bundle`` subcommands (export, verify, demo, scitt-export, scitt-verify)."""
    p = sub.add_parser(
        "bundle",
        help="Export, verify, and demo deterministic compliance and SCITT receipt bundles",
    )
    bundle_sub = p.add_subparsers(dest="bundle_action", required=True)

    p_export = bundle_sub.add_parser(
        "export",
        help="Export a SHA-256-manifested compliance receipt bundle",
    )
    p_export.add_argument(
        "--receipts", required=True, help="JSON array or JSONL file of SignedReceipt objects"
    )
    p_export.add_argument(
        "--keys", required=True, help="JSON object mapping trusted key_id -> hex public key"
    )
    p_export.add_argument(
        "--profile", required=True, choices=_PROFILE_CHOICES, help="Regulatory profile"
    )
    p_export.add_argument("--system-id", required=True, help="Governed system identifier")
    p_export.add_argument(
        "--outcomes", default=None, help="Optional JSON/JSONL of SignedOutcomeReceipt objects"
    )
    p_export.add_argument(
        "--escalations", default=None, help="Optional JSON/JSONL of escalation records"
    )
    p_export.add_argument(
        "--halts", default=None, help="Optional JSON/JSONL of halt/resume records"
    )
    p_export.add_argument(
        "--retention-days", type=int, default=None, help="Configured log retention window in days"
    )
    p_export.add_argument("--generated-at", default=None, help="Optional ISO 8601 timestamp")
    p_export.add_argument("--out", default=None, help="Write bundle JSON to this path")
    p_export.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON output")

    p_verify = bundle_sub.add_parser(
        "verify",
        help="Verify a serialized compliance receipt bundle offline",
    )
    p_verify.add_argument("bundle", help="Path to compliance receipt bundle JSON file")
    p_verify.add_argument(
        "--keys", required=True, help="JSON object mapping trusted key_id -> hex public key"
    )
    p_verify.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON output")

    p_demo = bundle_sub.add_parser(
        "demo",
        help="Generate, verify, and tamper-test a sample compliance receipt bundle offline",
    )
    p_demo.add_argument(
        "--profile",
        default=_PROFILE_CA_ADMT,
        choices=_PROFILE_CHOICES,
        help="Regulatory profile (default: ca-admt-2027)",
    )
    p_demo.add_argument("--out", default=None, help="Optional path to write sample bundle JSON")
    p_demo.add_argument(
        "--keys-out", default=None, help="Optional path to write public verifier JSON"
    )
    p_demo.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON output")

    p_scitt_export = bundle_sub.add_parser(
        "scitt-export",
        help="Wrap a receipt, compliance bundle, or JSON artifact in RFC 9052 COSE_Sign1",
    )
    p_scitt_export.add_argument("input", help="Path to input JSON artifact")
    p_scitt_export.add_argument("--out", required=True, help="Write COSE_Sign1 binary to this path")
    key_group = p_scitt_export.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--demo-key",
        action="store_true",
        help="Sign with the offline demo seed matching `acgs bundle demo --keys-out`",
    )
    key_group.add_argument(
        "--signing-key-env",
        default=None,
        help="Environment variable containing a 64-char hex Ed25519 signing seed",
    )
    p_scitt_export.add_argument("--key-id", default=None, help="Optional override for COSE kid")
    p_scitt_export.add_argument(
        "--kind",
        default="auto",
        choices=_SCITT_KIND_CHOICES,
        help="Payload type override (default: auto)",
    )
    p_scitt_export.add_argument(
        "--keys",
        default=None,
        help="Optional JSON object of pinned public keys for pre-export verification",
    )
    p_scitt_export.add_argument("--issuer", default=None, help="Optional SCITT CWT iss claim")
    p_scitt_export.add_argument("--subject", default=None, help="Optional SCITT CWT sub claim")
    p_scitt_export.add_argument(
        "--issued-at", type=int, default=None, help="Optional SCITT CWT iat epoch seconds"
    )
    p_scitt_export.add_argument(
        "--content-type", default=None, help="Optional COSE protected header content_type override"
    )
    p_scitt_export.add_argument(
        "--external-aad-hex", default=None, help="Optional hex-encoded COSE external_aad bytes"
    )
    p_scitt_export.add_argument(
        "--json", dest="json_out", action="store_true", help="Emit JSON output"
    )

    p_scitt_verify = bundle_sub.add_parser(
        "scitt-verify",
        help="Verify an RFC 9052 COSE_Sign1 SCITT envelope offline",
    )
    p_scitt_verify.add_argument("cose", help="Path to COSE_Sign1 binary file")
    p_scitt_verify.add_argument(
        "--keys", required=True, help="JSON object mapping trusted key_id -> hex public key"
    )
    p_scitt_verify.add_argument(
        "--expected-content-type",
        default=None,
        help="Require exact COSE content_type protected header value",
    )
    p_scitt_verify.add_argument(
        "--expected-issuer",
        default=None,
        help="Require exact SCITT CWT iss claim value",
    )
    p_scitt_verify.add_argument(
        "--external-aad-hex", default=None, help="Optional hex-encoded COSE external_aad bytes"
    )
    p_scitt_verify.add_argument(
        "--json", dest="json_out", action="store_true", help="Emit JSON output"
    )


def handler(args: argparse.Namespace) -> int:
    """Dispatch ``acgs bundle`` subcommands."""
    action = getattr(args, "bundle_action", None)
    if action == "export":
        return _cmd_export(args)
    if action == "verify":
        return _cmd_verify(args)
    if action == "demo":
        return _cmd_demo(args)
    if action == "scitt-export":
        return _cmd_scitt_export(args)
    if action == "scitt-verify":
        return _cmd_scitt_verify(args)
    print(f"Error: unsupported bundle action: {action!r}", file=sys.stderr)
    return 1
