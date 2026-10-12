"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if not PRINCIPALS_PATH.exists():
        return {}
    return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Kiểm tra data_classification hợp lệ
    valid_classifications = ("public", "internal", "restricted")
    if context.data_classification not in valid_classifications:
        return False, f"invalid data_classification: {context.data_classification}"

    # 2. Rule tối thiểu: restricted + egress_enabled=True -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "egress denied: restricted data egress is forbidden"

    # 3. Kiểm tra danh tính principal
    if not context.principal_id:
        return False, "principal_id is required"

    principals = _load_principals()
    principal = principals.get(context.principal_id)
    if principal is None:
        return False, f"unknown principal_id: {context.principal_id}"

    # 4. Kiểm tra thời hạn (expires_at)
    if context.expires_at:
        try:
            exp_dt = datetime.fromisoformat(context.expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            if exp_dt < now_dt:
                return False, f"credential expired at {context.expires_at}"
        except Exception:
            return False, f"invalid expires_at format: {context.expires_at}"

    # 5. Kiểm tra mục đích (request_purpose)
    allowed_purposes = principal.get("purposes", [])
    if context.request_purpose and context.request_purpose not in allowed_purposes:
        return False, f"purpose '{context.request_purpose}' not allowed for principal '{context.principal_id}'"

    # 6. Kiểm tra quyền của tool được yêu cầu
    tool = context.requested_tool
    if tool:
        allowed_tools = principal.get("allowed_tools", [])
        if tool not in allowed_tools:
            return False, f"principal '{context.principal_id}' is not authorized for tool '{tool}'"

        if context.agent_scopes and tool not in context.agent_scopes:
            return False, f"tool '{tool}' exceeds agent_scopes {context.agent_scopes}"

        if context.delegation_depth > 0:
            if not context.parent_scopes or tool not in context.parent_scopes:
                return False, f"tool '{tool}' exceeds parent_scopes {context.parent_scopes} in delegation depth {context.delegation_depth}"

    return True, f"access granted: {tool or 'action'} authorized for principal '{context.principal_id}'"
