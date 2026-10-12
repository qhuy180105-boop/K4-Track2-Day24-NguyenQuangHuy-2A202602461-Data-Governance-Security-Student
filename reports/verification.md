# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - Hệ điều hành: Windows 11 (AMD64)
  - Python: Python 3.11.9
  - Gitleaks: v8.30.1

- `python -m pytest tests/ -q`:
  - Kết quả kiểm thử: `33 passed in 6.76s` (100% test cases đạt).
  - Chi tiết các bộ test:
    * `tests/test_check_lure_cli.py`: 3/3 passed (kiểm tra CLI nhận diện lure hợp lệ và báo lỗi định dạng).
    * `tests/test_pii.py`: 2/2 passed (đạt 100% Precision và 100% Recall trên 118 nhãn PII tiếng Việt; redact xóa sạch các thực thể).
    * `tests/test_policy.py`: 4/4 passed (chặn egress với data restricted, kiểm soát quyền theo phân loại).
    * `tests/test_obo.py`: 5/5 passed (chặn support_l1 gọi read_customer, cho phép dpo; kiểm tra delegation depth, TTL hết hạn, unknown principal).
    * `tests/test_split.py`: 1/1 passed (Trifecta Split ngăn chặn đọc khách hàng do attacker chỉ định trong prompt free-text, bảo toàn đọc khách hàng hợp lệ).
    * `tests/test_scaffold_dispatch.py`: 4/4 passed (bảo toàn tính tương thích của runner).
    * `tests/test_injection.py`: 8/8 passed (replay 4 biến thể tấn công prompt injection với cả 2 vai trò support_l1 và dpo; toàn bộ đều bị containment chặn đứng exfiltration).
    * `tests/test_ledger.py`: 3/3 passed (kiểm tra hash chaining, phát hiện giả mạo dòng cũ, bắt buộc có lý do non-empty).
    * `tests/test_supply_chain.py`: 3/3 passed (hook Gitleaks pinned v8.30.1, requirements.lock có sha256 hash, báo cáo sự cố bí mật ghi nhận đúng commit 1bdd849).

- `pre-commit run --all-files`:
  - Lệnh: `.venv\Scripts\pre-commit.exe run --all-files`
  - Kết quả:
    ```
    [INFO] Initializing environment for https://github.com/gitleaks/gitleaks.
    Detect hardcoded secrets.................................................Passed
    ```

- Ledger verify:
  - Lệnh: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (chuỗi hàm băm SHA-256 toàn vẹn, hợp lệ từ genesis hash đến dòng cuối cùng).

- Các lỗi còn lại:
  - Không có lỗi kỹ thuật hoặc bảo mật tồn đọng. Toàn bộ các yêu cầu từ Checkpoint 1 đến Checkpoint 5 đã hoàn thành đầy đủ, đáp ứng mọi tiêu chí bắt buộc và không vi phạm điều kiện trượt trong `RUBRIC.md`.

- Commit SHA cuối cùng:
  - Commit SHA: `6dd19f2`
