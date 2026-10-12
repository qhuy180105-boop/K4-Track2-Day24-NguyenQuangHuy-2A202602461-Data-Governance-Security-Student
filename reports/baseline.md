# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa. Trong baseline `_naive_loop()` tại `agent/loop.py:27`, hàm chỉ nhận `message` và `llm`, hoàn toàn không có `agent_id`, `run_id` hay danh tính người dùng (principal) để kiểm tra quyền hạn. Tại `agent/loop.py:39` và `agent/loop.py:44`, các lời gọi đọc dữ liệu khách hàng và gửi qua HTTP đều được thực hiện trực tiếp mà không gắn với bất kỳ danh tính hay phiên làm việc nào.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có policy hay cơ chế PEP nào kiểm tra mục đích, quyền hay phân loại dữ liệu trước khi gửi. Người thực sự quyết định việc gửi là kẻ tấn công đã cài prompt injection trong ticket (untrusted content); baseline xử lý chỉ thị bên trong như lệnh tại `agent/loop.py:34-35` (`injected = llm.find_injection(...)`) rồi tự động gọi `tools.http_post()` tại `agent/loop.py:44`. Bản thân `tools.http_post` tại `agent/tools.py:68-85` chỉ kiểm tra URL thuộc localhost chứ không kiểm tra quyền hay nội dung dữ liệu.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Dòng tạo body POST chứa dữ liệu hồ sơ khách hàng là `agent/loop.py:44` (`tools.http_post(injected.target_url, {"records": collected})`), lấy từ kết quả `tools.read_customer(customer_id)` tại `agent/loop.py:39`. Bằng chứng sink nhận body đó được ghi lại trong file `reports/sink.log` bởi hàm `do_POST()` tại `sink/sink.py:46-47`.
