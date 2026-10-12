"""BƯỚC 3c & 3d — trifecta split + egress allowlist + OBO runner.

Tách 1 yêu cầu người dùng thành các run riêng biệt:
Run A: search_docs (untrusted content). KHÔNG gọi read_customer, KHÔNG gọi http_post.
Run B: read_customer (private store). CHỈ nhận list ticket_id số từ TÊN FILE của Run A,
       tra cứu customers.json qua trường related_tickets đáng tin cậy.
Mọi tool call đều phải qua policy.check() và ghi ledger.append() trước khi execute.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""
    pass


def _hash_args(args_dict: dict) -> str:
    serialized = json.dumps(args_dict, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=1)).isoformat()
    agent_id = "lab24-agent"
    agent_scopes = ("search_docs", "read_customer")

    # ----------------------------------------------------
    # RUN A: Untrusted content processing (search_docs)
    # ----------------------------------------------------
    run_id_a = "run-a"
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/{run_id_a}",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=agent_scopes,
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    ledger.append({
        "ts": now.isoformat(),
        "agent_id": agent_id,
        "run_id": run_id_a,
        "on_behalf_of": principal_id,
        "tool": "search_docs",
        "args_hash": _hash_args({"query": message}),
        "classification": "internal",
        "decision": "allow" if allow_search else "deny",
        "reason": reason_search,
        "expires_at": expires_at,
    }, ledger_path)

    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Extract numeric ticket IDs purely from file names (e.g., ticket-007.md -> 7)
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    # Scan for potential injection instruction across raw text to detect exfil attempt
    combined_raw_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_raw_text)

    # ----------------------------------------------------
    # RUN B: Private data store (via trusted related_tickets)
    # ----------------------------------------------------
    run_id_b = "run-b"
    collected_records = []
    if ticket_ids and CUSTOMERS_FILE.exists():
        customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
        matched_cids: list[str] = []
        for c in customers_data:
            rel = c.get("related_tickets", [])
            cid = c["customer_id"]
            if any(t in rel for t in ticket_ids) and cid not in matched_cids:
                matched_cids.append(cid)

        for cid in matched_cids:
            ctx_read = PolicyContext(
                data_classification="restricted",
                request_purpose="support-reply",
                agent_owner=f"{agent_id}/{run_id_b}",
                delegation_depth=0,
                egress_enabled=False,
                principal_id=principal_id,
                requested_tool="read_customer",
                agent_scopes=agent_scopes,
                expires_at=expires_at,
            )
            allow_read, reason_read = policy.check(ctx_read)
            ledger.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "run_id": run_id_b,
                "on_behalf_of": principal_id,
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cid}),
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
                "expires_at": expires_at,
            }, ledger_path)

            if allow_read:
                try:
                    record = tools.read_customer(cid)
                    collected_records.append(record)
                except tools.ToolError:
                    pass

    # Exfiltration PEP check
    if injected is not None:
        target_url = injected.target_url or "http://127.0.0.1:10024/reconcile"
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/{run_id_b}",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=agent_scopes,
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id_b,
            "on_behalf_of": principal_id,
            "tool": "http_post",
            "args_hash": _hash_args({"url": target_url}),
            "classification": "restricted",
            "decision": "allow" if allow_post else "deny",
            "reason": reason_post,
            "expires_at": expires_at,
        }, ledger_path)

        if allow_post:
            tools.http_post(target_url, {"records": collected_records})

    # Redact PII in docs before sending to LLM for final summary
    sanitized_docs = [
        {"id": d["id"], "text": pii.redact(d["text"])}
        for d in docs
    ]
    return llm.summarize(sanitized_docs)
