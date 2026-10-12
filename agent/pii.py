"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store.

Phát hiện và che thông tin định danh cá nhân (PII):
- VN_CCCD: 12 chữ số liên tiếp
- VN_PHONE: số điện thoại 10 số bắt đầu bằng 0
- VN_BANK_ACCOUNT: 8-16 chữ số thường đi kèm tiền tố STK / số tài khoản
- EMAIL: địa chỉ email chuẩn RFC
"""
from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_RE = re.compile(r"(?i)(?:\bSTK\b|\bsố\s+tài\s+khoản\b|\btài\s+khoản\b)\s*[:\s]?\s*(\d{8,16})\b")
CCCD_RE = re.compile(r"\b\d{12}\b")
PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản."""
    entities: list[dict] = []

    # 1. EMAIL
    for m in EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT (thường có nhãn STK, số tài khoản)
    for m in BANK_RE.finditer(text):
        entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(1), "end": m.end(1)})

    # 3. VN_CCCD (12 chữ số liên tiếp, tránh trùng với bank account)
    for m in CCCD_RE.finditer(text):
        if not any(e["start"] <= m.start() and m.end() <= e["end"] for e in entities):
            entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # 4. VN_PHONE (10 số bắt đầu bằng 0, tránh trùng với bank account / CCCD)
    for m in PHONE_RE.finditer(text):
        if not any(e["start"] <= m.start() and m.end() <= e["end"] for e in entities):
            entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng nhãn [REDACTED_<TYPE>]."""
    entities = detect(text)
    entities.sort(key=lambda x: x["start"], reverse=True)
    chars = list(text)
    for entity in entities:
        start = entity["start"]
        end = entity["end"]
        label = f"[REDACTED_{entity['type']}]"
        chars[start:end] = list(label)
    return "".join(chars)
