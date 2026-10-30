# Work Vault

Kho lưu password, API key, key file theo dự án / danh mục / service. Chạy trên Cloudflare Workers + D1 + R2.
Mã hoá đầu-cuối: trình duyệt mã hoá trước khi gửi, server chỉ giữ ciphertext.

## Deploy

```bash
npm install
npx wrangler login
npx wrangler d1 create work-vault          # chép database_id vào wrangler.jsonc
npx wrangler r2 bucket create work-vault-files
npx wrangler d1 migrations apply work-vault --remote
npx wrangler secret put SERVER_SECRET      # chuỗi ngẫu nhiên dài, giữ nguyên sau khi tạo admin
npx wrangler deploy
```

Sau khi deploy:

1. Mở URL, nhập `SERVER_SECRET` làm setup token, tạo admin đầu tiên.
2. Mời thêm ít nhất 1 admin dự phòng.
3. Bật **Cloudflare Access** (Zero Trust → Access → Applications) cho domain, chỉ cho email công ty + OTP/SSO.
4. Nếu dùng custom domain, tắt route `*.workers.dev` để không có đường vào bỏ qua Access.
5. Để người ngoài công ty mở được link chia sẻ, tạo Access policy **Bypass** cho đúng các đường dẫn: `/s`, `/api/public/*`, `/app.js`, `/crypto.js`, `/styles.css`. Mọi đường dẫn khác giữ nguyên chặn.

## Chạy local

```bash
printf 'SERVER_SECRET=%s\n' "$(openssl rand -hex 24)" > .dev.vars
npm run db:local
npm run dev                # http://localhost:8787
npm test                   # test mã hoá
SECRET=$(cut -d= -f2 .dev.vars) node --test test/api.e2e.mjs   # test phân quyền, cần server chạy với DB trống
```

## Vai trò

| Vai trò | Quyền |
|---|---|
| Chỉ xem | Đọc mục, tải tệp trong dự án |
| Chỉnh sửa | Thêm/sửa/xoá mục và tệp |
| Quản lý | Thêm cấp quyền, gỡ người, xoay khoá, đổi tên, xoá dự án |
| Admin | Mời, khoá, cấp lại tài khoản, xem nhật ký. Không tự đọc được dự án mình không thuộc |

## Link chia sẻ

Nút **Chia sẻ** trên từng mục (vai trò Chỉnh sửa trở lên). Quản lý ở **Link chia sẻ** trong sidebar.

| Kiểu | Hành vi | Hết hạn |
|---|---|---|
| Một lần | Chết ngay sau lần mở đầu. Nội dung bị xoá khỏi R2 trước khi trả về người nhận | 1 giờ, 24 giờ, 7 ngày |
| Public | Xem nhiều lần, đếm lượt xem, thu hồi được | 1 giờ, 24 giờ, 7 ngày, 30 ngày |

- Khoá nằm trong phần `#` của link, không gửi lên server. Server chỉ giữ ciphertext và hash của bằng chứng khoá.
- Mở link cần bấm nút (POST kèm bằng chứng), nên bot xem trước link trong chat không làm mất link một lần. Biết id mà không có khoá cũng không mở hay đốt được link.
- Nhiều request mở cùng lúc: đúng một request thắng.
- Link là bản chụp lúc tạo. Tệp chia sẻ tối đa 10 MB.
- Thu hồi được bởi: người tạo, người quản lý dự án, admin.
- Tự chết khi: xoá mục, xoá dự án, người tạo bị gỡ khỏi dự án hoặc bị khoá tài khoản.
- Cron mỗi giờ xoá nội dung link hết hạn. Dòng metadata giữ 90 ngày.

## Mô hình bảo mật

| Thành phần | Cách làm |
|---|---|
| Đăng nhập | Master password → PBKDF2-SHA256 1.000.000 vòng → HKDF tách auth key (gửi server) và KEK (không rời trình duyệt) |
| Khoá người dùng | Cặp khoá ECDH P-256. Private key được KEK bọc, public key nằm trên server |
| Khoá dự án | AES-256 ngẫu nhiên, bọc riêng cho từng thành viên bằng public key của họ |
| Dữ liệu | AES-256-GCM. Tên dự án, danh mục, service, tên tệp đều mã hoá. AAD gắn ciphertext với dự án và id |
| Tệp | Mỗi tệp một khoá riêng, lưu trong mục đã mã hoá |
| Gỡ thành viên | Tạo khoá dự án mới, mã hoá lại mọi mục, bọc lại cho người còn lại, trong một transaction |
| Server | Lưu hash của auth key, public key, ciphertext. Không log request. Email không tồn tại vẫn nhận salt giả, nên không dò được tài khoản |
| Phiên | Cookie `__Host-`, HttpOnly, Secure, SameSite=Strict, 8 giờ. Kiểm tra Origin cho mọi request ghi |
| Brute force | 5 lần sai / 15 phút theo IP và theo tài khoản |
| Trình duyệt | CSP `default-src 'none'`, không script ngoài, không `innerHTML` với dữ liệu, tự khoá sau 10 phút, clipboard tự xoá sau 30 giây |
| Nhật ký | Đăng nhập, sửa/xoá, tải tệp, đổi quyền. Việc xem secret diễn ra trong trình duyệt nên không ghi được |

### Giới hạn cần biết

- Ai kiểm soát tài khoản Cloudflare hoặc pipeline deploy có thể sửa JS để lấy mật khẩu ở lần đăng nhập sau. Bật 2FA cho Cloudflare, giới hạn người được deploy.
- Server độc hại có thể đưa public key giả khi cấp quyền. So vân tay ngoài luồng (gọi điện, gặp trực tiếp) trước khi cấp quyền dự án quan trọng.
- Ai có bản sao D1 có thể dò master password offline. Password yếu = tài khoản đó yếu.
- Gỡ người không xoá được những gì họ đã đọc. Luôn đổi credential thật sau khi có người rời team.
- Khoá tệp không đổi khi xoay khoá. Người đã gỡ bị server chặn tải tệp, nhưng ai có cả bản sao R2 và khoá tệp cũ vẫn giải mã được tệp cũ.
- Khoá hoặc cấp lại tài khoản: admin không tự xoay khoá được. Người quản lý dự án sẽ thấy cảnh báo và phải bấm **Xoay khoá**.
- Dự án chỉ có một thành viên mà người đó mất cả mật khẩu lẫn recovery key thì dữ liệu mất vĩnh viễn. Mỗi dự án nên có 2 người quản lý.
- Link chia sẻ nằm ngoài kiểm soát vault: ai có link là đọc được, không cần đăng nhập,. Thu hồi không lấy lại được thứ đã xem.
- Link gửi qua kênh có lưu lịch sử (email, chat) tồn tại ở đó tới khi hết hạn. Link một lần cho biết có người mở trước: người nhận thấy link đã chết thì đổi credential.
- Nếu response của link một lần bị mất giữa đường, link vẫn chết. Người gửi phải tạo link mới.
- Chưa có export/backup. D1 có Time Travel 30 ngày; R2 không có bản sao tự động.
- Code chưa được audit độc lập.
