# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks phiên bản v8.30.1 (chạy qua CLI `gitleaks` và hook `gitleaks-system`).
- Commit chứa token giả: `1bdd849` (full SHA: `1bdd849922156c868a5ee9293d68f5b72e242d2c`), commit author `VinUni AI20k Lab <lab@users.noreply.github.com>`, ngày 2026-10-09T16:22:06Z.
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt` (dòng 1).
  - Rule: `lab24-synthetic-token` (định nghĩa trong `.gitleaks.toml`, regex `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`).
  - Lệnh quét lịch sử: `gitleaks git --config .gitleaks.toml --redact --verbose .`
  - Kết quả quét lịch sử: Tìm thấy 1 leak (finding) tại commit `1bdd849`, exit code 1 đúng như dự kiến. Bằng chứng log:
    ```
    Finding:     REDACTED
    Secret:      REDACTED
    RuleID:      lab24-synthetic-token
    Entropy:     4.600922
    File:        lab-fake-secret.txt
    Line:        1
    Commit:      1bdd849922156c868a5ee9293d68f5b72e242d2c
    Author:      VinUni AI20k Lab
    Date:        2026-10-09T16:22:06Z
    ```
- Kết quả quét file hiện tại:
  - Lệnh quét file hiện tại: `gitleaks dir --config .gitleaks.toml --redact .` (bỏ qua virtualenv trong `.gitleaksignore`).
  - Kết quả: Không tìm thấy leak nào trong mã nguồn hiện tại (`no leaks found`, exit code 0). File `lab-fake-secret.txt` đã bị xoá ở commit tiếp theo.
- Nếu đây là credential thật, cần xử lý thế nào:
  1. Coi credential đó đã bị lộ hoàn toàn (compromised).
  2. Ngay lập tức thực hiện thu hồi (revoke) và rotate secret tại nhà cung cấp / dịch vụ quản lý danh tính (IAM / API Provider).
  3. Kiểm tra nhật ký truy cập (access audit logs) của dịch vụ liên quan để xác định xem credential đã bị kẻ xấu lợi dụng để truy cập trái phép hay chưa trong khoảng thời gian lộ lọt.
  4. Cập nhật secret mới an toàn thông qua Secret Manager hoặc biến môi trường bảo mật (không lưu trữ trong git).
  5. Viết báo cáo sự cố (incident report) và thông báo cho các bên liên quan theo quy trình bảo mật thông tin.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file khỏi HEAD chỉ xoá file ở commit hiện tại, nhưng toàn bộ lịch sử Git (git history/git reflog/packfiles) vẫn lưu commit `1bdd849` và nội dung file `lab-fake-secret.txt`. Bất kỳ ai clone hoặc truy cập repo (kể cả clone nông nếu ref còn tồn tại) đều có thể checkout commit cũ hoặc dùng `git show 1bdd849` để lấy secret.
  - Kể cả khi có rewrite git history (dùng `git filter-repo` hay BFG), nếu secret đã từng bị push ra bên ngoài thì secret đó có thể đã bị bot crawler thu thập. Do đó, chỉ có hành động rotate / thu hồi (revoke) secret tại server cấp quyền mới vô hiệu hóa được giá trị xác thực của credential.
  - Pin dependency (`requirements.lock` kèm sha256) và pre-commit hook chỉ bảo vệ chuỗi cung ứng phần mềm và ngăn chặn commit secret mới trong tương lai; chúng hoàn toàn không thể thu hồi hoặc vô hiệu hóa một credential đã từng bị phơi bày trong lịch sử.
