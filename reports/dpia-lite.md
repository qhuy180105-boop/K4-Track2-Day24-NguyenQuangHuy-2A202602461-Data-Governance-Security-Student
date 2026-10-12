# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
   - **Dữ liệu PII khách hàng (Dữ liệu cá nhân theo Luật BV dữ liệu cá nhân Việt Nam):**
     * Dữ liệu cá nhân cơ bản: Họ và tên (`full_name`), Số điện thoại (`phone`), Địa chỉ thư điện tử (`email`), Địa chỉ nơi ở/liên hệ (`address`).
     * Dữ liệu cá nhân nhạy cảm / định danh tài chính: Số thẻ Căn cước công dân (`id_number` / CCCD), Số tài khoản ngân hàng (`bank_account`).
   - **Phân loại cấp độ bảo mật (Data Classification):**
     * `public`: Dữ liệu và chính sách mở, thông tin dịch vụ chung.
     * `internal`: Nội dung ticket hỗ trợ kỹ thuật (`corpus/*.md`), danh sách mã định danh ticket.
     * `restricted`: Cơ sở dữ liệu hồ sơ khách hàng (`data/customers.json`) chứa thông tin PII nhạy cảm và định danh.

2. Mục đích xử lý và principal:
   - **Mục đích xử lý:**
     * `support-reply`: Hỗ trợ khách hàng, giải quyết khiếu nại dịch vụ và tổng hợp trạng thái các sự cố mở được phân công.
   - **Danh tính và vai trò thực hiện (Principal & OBO Delegation):**
     * `support_l1` (Nhân viên CSKH cấp 1): Chỉ được cấp quyền tra cứu tài liệu nghiệp vụ (`search_docs`). Bị cấm truy xuất trực tiếp cơ sở dữ liệu hồ sơ cá nhân (`read_customer`).
     * `dpo` (Cán bộ phụ trách bảo vệ dữ liệu): Được cấp quyền tra cứu tài liệu (`search_docs`) và đọc dữ liệu khách hàng (`read_customer`) khi gắn với mục đích `support-reply`.
     * Nguyên tắc giới hạn tối thiểu: Mọi principal đều bị cấm chuyển tiếp dữ liệu nhạy cảm ra kênh truyền ngoài (`restricted` + egress).

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - **Run A (Môi trường không tin cậy - Untrusted Environment):**
     * Input: Câu truy vấn người dùng (`message`).
     * Tool: `search_docs` tìm kiếm trong thư mục ticket `corpus/`.
     * Bộ lọc PII Gate: Hàm `agent.pii.redact()` loại bỏ và làm mờ toàn bộ thông tin CCCD, điện thoại, ngân hàng, email trước khi chuyển văn bản qua ranh giới (boundary).
     * Cơ chế Boundary Handoff: Chỉ truyền mảng các số nguyên ticket ID (`int`) được trích xuất từ **tên file** (dạng `ticket-<ID>.md`). Toàn bộ nội dung văn bản tự do do attacker kiểm soát bị cô lập tại Run A.
   - **Run B (Môi trường tin cậy - Trusted Environment):**
     * Tool: `read_customer` đọc thông tin từ `data/customers.json`.
     * Nguyên tắc truy xuất: Chỉ truy vấn những khách hàng có trường `related_tickets` chứa ticket ID hợp lệ được xác thực từ Run A. Tuyệt đối không nhận customer ID trực tiếp từ prompt của attacker.
     * Điểm kiểm soát chính sách (PEP): Thực hiện kiểm tra quyền On-Behalf-Of (OBO) và hiệu lực của token (`expires_at`, purpose) trước khi gọi hàm đọc.
   - **Kênh truyền ngoài (Egress Channel & Endpoint):**
     * Tool: `http_post` gửi yêu cầu HTTP POST tới đích `http://127.0.0.1:10024/exfil` (Local HTTP exfil sink).
     * Cơ chế phòng vệ: PEP xác định dữ liệu mang nhãn `restricted` khi kết hợp với cờ `egress_enabled=True` sẽ từ chối gọi tool ngay lập tức (`egress denied`).
     * Kết quả: Endpoint sink nhận 0 byte dữ liệu (`reports/attack-after.log` hoàn toàn rỗng).

4. Bằng chứng deny/allow và giới hạn của mock:
   - **Bằng chứng Allow:**
     * `search_docs` cho `dpo` và `support_l1`: Ghi nhận `decision: "allow"` kèm lý do phân quyền hợp lệ tại `reports/ledger.jsonl:1`.
     * `read_customer` cho `dpo` trên các khách hàng gắn với ticket mở hợp lệ: Ghi nhận 21 lượt gọi `decision: "allow"` tại `reports/ledger.jsonl:2-22`.
   - **Bằng chứng Deny:**
     * Từ chối nhân viên không đủ thẩm quyền: `support_l1` bị chặn khi cố gọi `read_customer` (kiểm chứng tại `tests/test_obo.py`).
     * Từ chối đối tượng do attacker chỉ định: Kẻ tấn công yêu cầu đọc `KH-000777` trong nội dung lure nhưng Run B từ chối truy xuất vì không nằm trong `related_tickets` của ticket hợp lệ (kiểm chứng tại `tests/test_split.py`).
     * Từ chối xuất dữ liệu ra ngoài: Gọi `http_post` bị từ chối với lý do `egress denied: restricted data egress is forbidden`, ghi nhận tại `reports/ledger.jsonl:23`.
     * Đối chiếu before/after: `reports/attack-before.log` (1,196 bytes dữ liệu PII lộ lọt) so với `reports/attack-after.log` (0 bytes).
   - **Giới hạn của môi trường Mock:**
     * Dữ liệu mô phỏng: Toàn bộ dữ liệu khách hàng và ticket là dữ liệu tổng hợp (synthetic), không chứa PII của người dùng thật.
     * Phương pháp nhận diện PII: Sử dụng biểu thức chính quy (Regex) tối ưu cho định dạng Việt Nam, chưa thể phát hiện các trường hợp cố tình ngụy trang ký tự nâng cao mà các mô hình NLP/NER hiện đại xử lý được.
     * Cơ chế danh tính: Sử dụng file JSON tĩnh giả lập IdP (`principals.json`), trong môi trường sản xuất thực tế cần thay thế bằng OAuth 2.0 Token Exchange (RFC 8693) và xác thực mTLS có chứng chỉ số.
