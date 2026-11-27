"""Telegram webhook router for governance-aware message intake."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from acgs_lite._compat import constant_time_compare
from acgs_lite.engine import GovernanceEngine

try:
    from fastapi import APIRouter, Body, HTTPException, Request
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "Telegram webhook integration requires FastAPI. Install with: pip install acgs-lite[server]"
    ) from exc

_TELEGRAM_SECRET_HEADER = "X-Telegram-Bot-Api-Secret-Token"


def _validate_path_secret(path_secret: str) -> str:
    candidate = path_secret.strip()
    if not candidate:
        raise ValueError("webhook_path_secret must be a non-empty string")
    if "/" in candidate:
        raise ValueError("webhook_path_secret must not contain '/'")
    return candidate


def _validate_secret_token(secret_token: str | None) -> str | None:
    if secret_token is None:
        return None
    candidate = secret_token.strip()
    if not candidate:
        raise ValueError("secret_token must be a non-empty string when provided")
    return candidate


def _telegram_reply(chat_id: int, text: str) -> dict[str, Any]:
    return {
        "method": "sendMessage",
        "chat_id": chat_id,
        "text": text,
    }


def create_telegram_webhook_router(
    *,
    engine_getter: Callable[[], GovernanceEngine],
    webhook_path_secret: str,
    secret_token: str | None = None,
) -> APIRouter:
    """Create a Telegram webhook router with path-secret and optional header verification.

    Args:
        engine_getter: Callable that returns the current GovernanceEngine. Called at
            request time so the handler always uses the latest engine (e.g. after
            a rule change triggers a rebuild).
        webhook_path_secret: Secret path component for the webhook URL.
        secret_token: Optional Telegram Bot API secret token for header verification.
    """
    resolved_path_secret = _validate_path_secret(webhook_path_secret)
    resolved_secret_token = _validate_secret_token(secret_token)
    router = APIRouter(prefix=f"/telegram/webhook/{resolved_path_secret}", tags=["telegram"])

    @router.post("")
    def telegram_webhook(
        request: Request,
        payload: Annotated[dict[str, Any], Body(...)],
    ) -> dict[str, Any]:
        if resolved_secret_token is not None:
            provided = request.headers.get(_TELEGRAM_SECRET_HEADER, "")
            if not constant_time_compare(provided, resolved_secret_token):
                raise HTTPException(status_code=401, detail="Invalid Telegram secret token")

        message = payload.get("message")
        if not isinstance(message, dict):
            return {"ok": True}

        chat = message.get("chat")
        text = message.get("text")
        raw_chat_id = chat.get("id") if isinstance(chat, dict) else None
        if (
            isinstance(raw_chat_id, bool)
            or not isinstance(raw_chat_id, int)
            or not isinstance(text, str)
        ):
            return {"ok": True}

        chat_id = raw_chat_id
        result = engine_getter().validate(
            text,
            agent_id=f"telegram:{chat_id}",
            context={
                "channel": "telegram",
                "telegram_chat_id": chat_id,
                "telegram_message_id": message.get("message_id"),
                "telegram_update_id": payload.get("update_id"),
            },
        )
        if result.valid:
            return _telegram_reply(
                chat_id,
                "ACGS Agent: governance cleared your message. Send the next step when ready.",
            )

        return _telegram_reply(
            chat_id,
            "ACGS Agent: your message was blocked by constitutional governance and was not processed.",
        )

    return router


__all__ = ["create_telegram_webhook_router"]
