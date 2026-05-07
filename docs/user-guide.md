# SecAudit — Hướng dẫn sử dụng đầy đủ

> Tài liệu này mô tả mọi giao diện của SecAudit Desktop (WPF) và SecAudit.Cli
> (headless / WinPE). Nếu bạn cần tình huống audit offline ổ đĩa đã tháo ra, xem
> riêng [`winpe-usage.md`](winpe-usage.md).

Mục lục

1. [Khởi chạy lần đầu](#1-khởi-chạy-lần-đầu)
2. [Bố cục shell](#2-bố-cục-shell)
3. [Dashboard — Full Audit](#3-dashboard--full-audit)
4. [Trang Log Forensics](#4-trang-log-forensics)
   - 4.1 [Tab "Thư mục / tệp local"](#41-tab-thư-mục--tệp-local)
   - 4.2 [Tab "Windows Event Log"](#42-tab-windows-event-log)
   - 4.3 [Tab "SSH / SFTP remote"](#43-tab-ssh--sftp-remote)
   - 4.4 [Baseline & Internal CIDRs](#44-baseline--internal-cidrs)
   - 4.5 [Bảng kết quả & Chain-of-custody](#45-bảng-kết-quả--chain-of-custody)
5. [Settings](#5-settings)
6. [CLI & WinPE offline](#6-cli--winpe-offline)
7. [Báo cáo xuất ra](#7-báo-cáo-xuất-ra)
8. [Cách chụp lại các ảnh trong tài liệu](#8-cách-chụp-lại-các-ảnh-trong-tài-liệu)

---

## 1. Khởi chạy lần đầu

SecAudit là file portable **`SecAudit.exe`** (self-contained .NET 8, không cần
cài runtime). Đặt file ở nơi bạn muốn (USB, `C:\Tools`, v.v.) và chạy.

- **UAC**: Khi bấm đúp, Windows sẽ hỏi quyền admin. Bấm **Có / Yes**. SecAudit
  bắt buộc chạy elevated vì phải đọc `HKLM\SYSTEM`, `winevt\Logs`, TPM state…
- **EULA gate**: Lần chạy đầu tiên (và mỗi lần thao tác nhạy cảm) sẽ có modal
  yêu cầu bạn tích 2 checkbox và gõ `I AM AUTHORIZED`. Ghi nhận vào signed
  audit log `%PROGRAMDATA%\SecAudit\audit\audit-YYYYMMDD.log`.
- **Không có mạng**: SecAudit hoạt động **offline-first**. Database CVE đã
  được nhúng sẵn; chỉ nút "Update CVE DB" mới cần mạng.

![Dialog UAC elevation](images/00-uac-prompt.png)

> _Ảnh: hộp thoại User Account Control "Bạn có muốn cho phép ứng dụng này thực
> hiện thay đổi trên thiết bị của mình?" — nguồn được ký bởi "SecAudit Team"._

![EULA gate lần đầu](images/01-eula-gate.png)

> _Ảnh: modal EULA (vi/en) với 2 checkbox "Tôi có quyền quản trị thiết bị này"
> + "Tôi đã đọc EULA", ô nhập `I AM AUTHORIZED`, nút **Chấp nhận** khoá cho
> đến khi cả 3 điều kiện hợp lệ._

---

## 2. Bố cục shell

Cửa sổ chính dùng Fluent / Mica backdrop, NavigationView bên trái và vùng nội
dung bên phải. Footer hiển thị cảnh báo "AUTHORIZED USE ONLY".

```
┌─ SecAudit — Authorized Use Only ───────────────────────────────────[_][□][×]┐
│┌──────────────┐┌─────────────────────────────────────────────────────────┐ │
││ 🏠 Dashboard ││                                                         │ │
││ 🔍 Log Forens││                  (Nội dung trang được chọn)             │ │
││              ││                                                         │ │
││              ││                                                         │ │
││              ││                                                         │ │
│├──────────────┤│                                                         │ │
││ ⚙  Settings  ││                                                         │ │
│└──────────────┘└─────────────────────────────────────────────────────────┘ │
│ AUTHORIZED USE ONLY · SecAudit v0.1 · © 2026                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **Dashboard** (biểu tượng Home): chỉ số rủi ro tổng + bảng finding từ full-audit.
- **Log Forensics** (biểu tượng kính lúp trên document): phân tích log riêng.
- **Settings** (ở footer): phiên bản, ngôn ngữ, theme, trạng thái elevated.

![Shell chính](images/02-shell-layout.png)

> _Ảnh: cửa sổ SecAudit kích thước 1280×800 với NavigationView bên trái mở sẵn,
> Dashboard đang active._

---

## 3. Dashboard — Full Audit

Đây là điểm bắt đầu "quick audit toàn hệ thống": bấm 1 nút, chạy tất cả 6 module
tuần tự, đổ kết quả vào DataGrid, cho phép xuất báo cáo.

![Dashboard overview](images/10-dashboard-idle.png)

**Các thành phần:**

| Thành phần | Mô tả |
|---|---|
| **Overall risk score** | Số 0-100 do `RiskScoreCalculator` tính từ các finding (Critical ×10, High ×5, Medium ×2, Low ×1). Nhãn dải: *An toàn / Chú ý / Rủi ro / Nghiêm trọng*. |
| **Status** | Mô tả text trạng thái hiện tại ("Idle", "Running module 3/6: Patch & CVE", "Done"). |
| **ProgressBar** | % tiến độ 0-100 theo module đang chạy. |
| **Run Full Audit** | Kích hoạt pipeline 6 module. Bị disable khi `IsRunning=true`. |
| **Export Reports** | Mở dialog chọn format (HTML/PDF/JSON/DOCX) và ghi vào `%LOCALAPPDATA%\SecAudit\reports\`. |
| **Bảng findings** | Severity, Category, Title, Evidence, Asset, **Hành động**. |

**Cột "Hành động"** là đặc biệt: với các finding có remediation tự động
(UAC off, SMBv1 on, RDP không NLA…), nút **Vá ngay** xuất hiện; bấm vào sẽ áp
dụng `IRemediationAction` tương ứng, ghi audit log, và re-scan mục đó.

**Luồng làm việc điển hình:**

1. Bấm **Run Full Audit**.
2. Theo dõi progress bar. Tổng thời gian ~30s–2 phút tuỳ máy (LAN scan chiếm lâu nhất).
3. Xem finding, sắp xếp theo cột **Severity** (bấm tiêu đề cột).
4. Với các dòng có **Vá ngay**, nếu tin tưởng remediation, bấm từng dòng (hoặc
   "Apply All" — chưa có trong v0.1, vá từng mục).
5. Bấm **Export Reports** để lưu HTML + PDF gửi cho sếp / kiểm toán.

![Dashboard đang chạy](images/11-dashboard-running.png)

> _Ảnh: Progress bar ~40%, Status="Running module 3/6: Patch & CVE",
> DataGrid đã có vài dòng finding từ SystemInfo + Hardening._

![Dashboard sau khi audit xong](images/12-dashboard-done.png)

> _Ảnh: 37 finding, risk score 62 (band "Rủi ro"). Các dòng Critical/High đỏ/cam,
> cột Hành động có nút "Vá ngay" cho 3 dòng Hardening._

---

## 4. Trang Log Forensics

Đây là trang trọng tâm của tài liệu — nơi bạn "truy vết" dấu hiệu tấn công
trong nhật ký. Trang chia làm 4 block dọc:

1. **Nguồn log** — chọn giữa 3 tab: thư mục local / Windows Event Log / SSH remote.
2. **Baseline & phạm vi mạng nội bộ** — tham số cho UnknownLogon / RemoteAccess.
3. **Nút điều khiển** — Bắt đầu / Huỷ / Mở thư mục bằng chứng.
4. **Progress + bảng Findings + Manifest**.

![Trang Log Forensics toàn cảnh](images/20-logforensics-overview.png)

### 4.1 Tab "Thư mục / tệp local"

Dùng khi bạn đã thu thập log sẵn (ví dụ copy từ máy bị nghi nhiễm, trích evtx
bằng `wevtutil epl`, hoặc rsync từ server Linux về).

```
┌─ Nguồn log ─────────────────────────────────────────────────────────────┐
│ [Thư mục / tệp local] [Windows Event Log] [SSH / SFTP remote]           │
│ ──────────────────────                                                  │
│                                                                         │
│ ┌─ Đường dẫn thư mục hoặc tệp log ─────────────────┐ ┌───────────┐      │
│ │ D:\Evidence\case-2026-04-20\logs                 │ │ Duyệt…    │      │
│ └──────────────────────────────────────────────────┘ └───────────┘      │
│                                                                         │
│ ☑ Quét đệ quy sâu trong thư mục con                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

| Trường | Bắt buộc? | Giá trị hợp lệ | Ví dụ |
|---|---|---|---|
| **Đường dẫn** | ✔ | Thư mục **hoặc** 1 file duy nhất (absolute path khuyến nghị) | `D:\Evidence\case\logs` hoặc `C:\inetpub\logs\LogFiles\W3SVC1\u_ex260420.log` |
| **Quét đệ quy** | ✖ (mặc định `true`) | ☑ để quét mọi thư mục con | Bỏ tick nếu chỉ muốn scan đúng 1 thư mục không đi sâu |

**Định dạng file được nhận:** `.evtx`, `.log`, `.txt`, `.out`, `.syslog`,
`.access`, `.error`, `.history`, `.csv`, và tên file `bash_history` /
`.bash_history`. Parser tự detect theo tên file:

| Parser | Nhận diện nếu tên file … |
|---|---|
| WindowsEvtx | đuôi `.evtx` |
| LinuxAuthLog | bắt đầu bằng `auth` hoặc `secure` |
| LinuxSyslog | chứa `syslog` hoặc `messages` |
| NginxCombined | chứa `access` (không bắt đầu `u_`) |
| IisW3c | bắt đầu `u_` với đuôi `.log` |
| ApacheError | chứa `error` (không phải `u_` / `w3svc`) |
| BashHistory | kết thúc `bash_history` / `zsh_history` / `_history` |

> **Mẹo**: Nếu bạn có bộ log hỗn hợp (Windows + Linux cùng vụ), cứ đưa tất cả
> vào 1 folder, bật đệ quy. SecAudit sẽ dispatch từng file cho parser phù hợp
> và **toàn bộ rule** sẽ quan sát record bất kể nguồn (BruteForce phát hiện
> cả Event 4625 lẫn sshd "Failed password" thông qua cùng `logon.failed` kind).

![Tab Local folder đã điền](images/21-logforensics-tab-local.png)

### 4.2 Tab "Windows Event Log"

Dùng khi bạn đang đứng trên máy cần audit **trực tiếp** (không qua export file).

```
┌─ Nguồn log ─────────────────────────────────────────────────────────────┐
│ [Thư mục / tệp local] [Windows Event Log] [SSH / SFTP remote]           │
│                       ─────────────────                                 │
│                                                                         │
│ Snapshot một channel đang chạy (Security / System / Application…):      │
│ ┌────────────────────────────────────────────────────┐                  │
│ │ Security                                           │                  │
│ └────────────────────────────────────────────────────┘                  │
│                                                                         │
│ Hoặc tải một tệp .evtx đã thu thập:                                     │
│ ┌────────────────────────────────────────────────────┐ ┌─────────┐      │
│ │                                                    │ │ Duyệt…  │      │
│ └────────────────────────────────────────────────────┘ └─────────┘      │
└─────────────────────────────────────────────────────────────────────────┘
```

| Trường | Bắt buộc? | Giá trị hợp lệ | Ví dụ |
|---|---|---|---|
| **Channel** | ✔ (nếu không dùng file) | Tên channel y như trong Event Viewer | `Security`, `System`, `Application`, `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational` |
| **Tệp .evtx** | ✔ (nếu không dùng channel) | File `.evtx` trên đĩa | `C:\ForensicCase\Security.evtx` |

**Ưu tiên**: nếu điền cả hai, **tệp .evtx thắng** (SecAudit đọc file, bỏ qua channel).

**Channel phổ biến nên chạy:**

| Channel | Giá trị để detect |
|---|---|
| `Security` | 4624/4625 (logon), 4672 (privilege), 4697/7045 (service install), 1102 (log cleared) |
| `System` | 7045 (service install), 104 (log cleared) |
| `Microsoft-Windows-Sysmon/Operational` | Sysmon 1 (process.create), 11 (filecreate), 13 (regset) — bắt buộc cho Keylogger / Ransomware burst rule |
| `Microsoft-Windows-PowerShell/Operational` | 4104 (script block) — base64 / IEX |

![Tab Windows Event Log](images/22-logforensics-tab-eventlog.png)

### 4.3 Tab "SSH / SFTP remote"

Dùng khi server Linux/Unix **đang chạy** và bạn chỉ có SSH access.

```
┌─ Nguồn log ─────────────────────────────────────────────────────────────┐
│ [Thư mục / tệp local] [Windows Event Log] [SSH / SFTP remote]           │
│                                             ──────────────────          │
│                                                                         │
│ Host     [ web01.corp.vn              ]  Port [ 22    ]                 │
│ Username [ soc-readonly               ]                                 │
│ Password [ •••••••••••                ]                                 │
│ Private  [ C:\Keys\soc-readonly.pem   ] [ Duyệt… ]                      │
│ key                                                                     │
│ Remote   [ /var/log/                  ]  ☑ Recursive                    │
│ path                                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

> ⚠️ **Về bảo mật tài khoản SSH**: Luôn dùng tài khoản **read-only** có quyền
> chỉ đọc `/var/log/`. SecAudit không cần sudo. Nếu có thể, dùng **private key
> + passphrase** thay vì password.

| Trường | Bắt buộc? | Định dạng | Ví dụ / Mẹo |
|---|---|---|---|
| **Host** | ✔ | Hostname hoặc IP | `web01.corp.vn` hoặc `10.0.8.12` |
| **Port** | ✔ (mặc định 22) | 1-65535 | `22`, `2222` |
| **Username** | ✔ | User trên remote | `soc-readonly` (nên có nhóm `adm` hoặc ACL đọc `/var/log/`) |
| **Password** | Một trong 2 bắt buộc | plaintext, **không lưu đĩa** — chỉ giữ RAM trong session | Nhập trực tiếp vào PasswordBox (được mask) |
| **Private key** | Một trong 2 bắt buộc | Path tới file OpenSSH PEM / PPK | `C:\Keys\soc-readonly.pem`. Nếu key có passphrase, SecAudit sẽ hỏi riêng trong session. |
| **Remote path** | ✔ (mặc định `/var/log/`) | Thư mục hoặc glob pattern trên remote | `/var/log/`, `/var/log/nginx/`, `/var/log/auth.log` |
| **Recursive** | ✖ (mặc định `false`) | ☑ đi vào thư mục con | Bật khi Remote path là `/var/log/` và bạn muốn bao gồm `nginx/`, `apache2/`, v.v. |
| **Giới hạn kích thước/file** | ✖ (cấu hình, mặc định 50MB) | byte cap mỗi file | Bảo vệ bandwidth — các file lớn hơn sẽ bị cắt `head -c 50MB` khi tải về. |

Khi nhấn "Bắt đầu phân tích", SecAudit:
1. Mở SSH connection, xác thực.
2. Dùng SFTP để liệt kê thư mục, với mỗi file: tải về `%LOCALAPPDATA%\SecAudit\forensics\<session>\evidence\` (giữ đường dẫn gốc).
3. SHA-256 mỗi file ngay sau khi tải → ghi vào manifest.
4. Chạy parser + rule như Local folder.
5. Không upload ngược — chỉ đọc.

![Tab SSH remote](images/23-logforensics-tab-ssh.png)

### 4.4 Baseline & Internal CIDRs

Block này điều khiển **hai rule quan trọng** và cần được điền cẩn thận:

```
┌─ Baseline & phạm vi mạng nội bộ ────────────────────────────────────────┐
│ User whitelist (phân cách dấu phẩy) — tài khoản hợp lệ; đăng nhập bởi   │
│ tài khoản khác sẽ bị flag là 'logon lạ'.                                │
│ ┌────────────────────────────────────────────────────────────────────┐  │
│ │ Administrator, admin, root, svc-backup, jsmith, lnguyen            │  │
│ └────────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│ Internal CIDRs (phân cách dấu phẩy) — dải IP được coi là nội bộ.        │
│ ┌────────────────────────────────────────────────────────────────────┐  │
│ │ 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10           │  │
│ └────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

#### User whitelist

- **Định dạng**: tên account phân cách bằng **dấu phẩy** (`,`). Khoảng trắng
  xung quanh được tự động trim. Không phân biệt hoa/thường.
- **Hành vi**:
  - Nếu **rỗng** → `UnknownLogonRule` **tắt hoàn toàn** (không có baseline thì
    mọi login thành công đều là "lạ" → ồn nhiễu).
  - Nếu có giá trị → mọi `logon.success` / `logon.explicit` với
    `TargetUserName` **không** nằm trong whitelist sẽ tạo **High/Critical finding**:
    - **High** nếu IP nguồn thuộc Internal CIDRs.
    - **Critical** nếu IP nguồn **ngoài** Internal CIDRs (VD public internet).
- **Tài khoản hệ thống luôn được bỏ qua**: `SYSTEM`, `LOCAL SERVICE`,
  `NETWORK SERVICE`, `ANONYMOUS LOGON`, `DWM-*`, `UMFD-*`, và mọi tên kết thúc `$`
  (machine account). Bạn **không cần** liệt kê chúng.
- **Ví dụ điền cho văn phòng 20 người**: `admin, helpdesk, lnguyen, ptran, jsmith, htran, svc-backup, svc-monitor`

> **Lưu ý**: Whitelist áp dụng theo `TargetUserName` (tức tài khoản đích của
> phiên login), không phải `SubjectUserName` (ai khởi tạo). Với Windows
> Event 4624 thông thường đây cũng chính là user đăng nhập.

#### Internal CIDRs

- **Định dạng**: danh sách CIDR `X.X.X.X/NN` phân cách dấu phẩy. Cho phép cả
  IPv4 và IPv6; mỗi entry có thể ghi thuần IP (`10.1.2.3`) → mặc định `/32`.
- **Hành vi**: Dùng để phân biệt "bên trong vs bên ngoài" cho:
  - `UnknownLogonRule` → severity High vs Critical.
  - Rule tương lai (remote-access từ non-internal IP) — hiện tại chỉ tác động
    UnknownLogon.
- **Mặc định**: `192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12` (RFC 1918 đầy đủ).
  Bạn **không cần sửa** trừ khi có VPN CGNAT (`100.64.0.0/10`) hoặc range public
  tĩnh thuộc sở hữu doanh nghiệp.
- **Ví dụ cho doanh nghiệp có VPN + chi nhánh nước ngoài**:
  `192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 203.162.45.0/24`

![Baseline fields](images/24-logforensics-baseline.png)

### 4.5 Bảng kết quả & Chain-of-custody

Sau khi nhấn **Bắt đầu phân tích**, 4 thành phần bên dưới sẽ cập nhật:

```
┌─ Controls ──────────────────────────────────────────────────────────────┐
│ [Bắt đầu phân tích]  [Huỷ]  [Mở thư mục bằng chứng]                     │
└─────────────────────────────────────────────────────────────────────────┘

┌─ Progress ──────────────────────────────────────────────────────────────┐
│ parsing auth.log (421 KB)                                               │
│ [████████░░░░░░░░░░░░░░░] Files: 3   Records: 14,502                    │
│ Evidence: C:\Users\admin\AppData\Local\SecAudit\forensics\20260420-...  │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│ [Phát hiện] [Chain-of-custody]                                           │
│ ──────────                                                               │
│ ┌─Severity─┬─Category──────────────┬─Title──────────┬─Asset─┬─Evidence─┐ │
│ │ Critical │ log-forensics.brute-  │ Dò mật khẩu —  │ user: │ Phát hiệ │ │
│ │          │ force                 │ tài khoản ...  │ root  │ n 15 ... │ │
│ │ ...                                                                  │ │
│ └──────────┴───────────────────────┴────────────────┴───────┴──────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

- **Tab "Phát hiện"**: danh sách Finding kiểu `Severity / Category / Title /
  Asset / Evidence`. Sort bằng click tiêu đề cột. Để copy chi tiết, right-click
  → Copy (nếu bạn đã bật theo ứng dụng — v0.1 hiện hỗ trợ Ctrl+C theo hàng).
- **Tab "Chain-of-custody"**: danh sách file đã được snapshot + kích thước + SHA-256.
  Cùng với `manifest.json` trong Evidence folder, đây là bằng chứng bạn dùng để
  đối chất khi gửi case lên C05 / CERT.
- **Mở thư mục bằng chứng**: bấm vào sẽ `explorer /select,manifest.json` đưa
  bạn đến ngay session folder.

![Log Forensics sau khi chạy](images/25-logforensics-finished.png)

---

## 4.6 Trang "Ứng cứu sự cố website" (WebIncident)

Trang riêng, tách khỏi Log Forensics. Mặc định **chỉ phân tích evidence/log/webroot
offline** — không tự kết nối website (giảm rủi ro bị antivirus chặn). Live URL
probe (DNS/TLS/HTTP) là tùy chọn nâng cao.

**Các trường nhập:**
| Trường | Ý nghĩa |
|---|---|
| **Target** | Domain/URL — bắt buộc khi bật Live URL probe; tùy chọn khi chỉ phân tích offline |
| **Server evidence** | Thư mục hoặc file `.zip` chứa log + webroot từ máy chủ bị tấn công |
| **WebRoot path** | Thư mục webroot riêng (nếu khác `ServerEvidencePath/htdocs`) |
| **Baseline manifest** | File `webroot-manifest.csv` của lần audit sạch trước đó để diff |
| **Live URL probe** | Bật để thu DNS, TLS cert, HTTP redirect chain, body SHA256 |
| **Capture HTTP body** | Lưu body HTML để hậu kỳ phân tích (mặc định tắt) |

**Các tín hiệu phát hiện được (v0.1.0):**

1. **Defacement** — match các chuỗi *"hacked by"*, *"bị hack"*, *"đã bị tấn công"*…
2. **Ransom note** — *"your files are encrypted"*, BTC/Monero address, *"bị mã hóa"*…
3. **Phishing form** — credential/payment field (`cvv`, `seed phrase`, `card number`)
4. **Hidden iframe / skimmer** — Magecart-style, payment-form trong iframe ẩn
5. **Obfuscated JS** — `eval/atob/fromCharCode/unescape`, long base64
6. **Cryptominer** — coinhive, cryptonight, webminer, BeEF hook
7. **Webshell signatures (mới)** — phát hiện theo họ trên file PHP/ASP/JSP trong
   webroot evidence. Kết quả hiện ở cột "Phân loại" với prefix
   `Webshell signature: <Family>`. Các họ hỗ trợ:
   - **China-Chopper** — one-liner `eval($_POST/$_REQUEST)` của APT
   - **b374k** — PHP web manager shell
   - **Weevely** — cookie-encrypted command transport (yêu cầu ≥2 marker)
   - **c99 / r57** — classic mass-scanner drop
   - **ASPXSpy** — ASP.NET shell có file/process/registry browser
   - **GenericObfuscatedShell** — chuỗi `eval + base64_decode/gzinflate/str_rot13`
8. **Scanner UA** trong access log — sqlmap, nikto, nuclei, ffuf, burp, wpscan…
9. **Webroot diff** — so với baseline manifest → file `.php/.aspx/.jsp` mới
10. **Suspicious extension** trong webroot — `.phar .htaccess .env .bak .sql .zip`

**Trình phân tích log (mới — v0.1.0):**
- Mỗi file log được sniff 64 KB đầu để nhận format
- Nếu là **ModSecurity audit log** (định dạng serial `--id-A--/B/F/H/Z--`) →
  parse riêng: trích xuất `[id "942100"]` + `[msg "..."]` từ section H, đẩy vào
  cột **Rule** dưới dạng `ModSecurity:942100`
- Nếu không, fallback sang Apache Combined / Nginx / IIS W3C parser cũ
- Cả hai cùng đẩy vào timeline JSON + CSV trong session folder

**Đầu ra session folder:**
```
%LOCALAPPDATA%\SecAudit\reports\web-<timestamp>-<host>\
├── manifest.json                       — chain-of-custody (SHA256 mọi file)
├── web-attack-timeline.json + .csv    — timeline đã enrich với rule id
├── webroot-manifest.csv               — full inventory webroot
├── server-evidence-summary.json       — tóm tắt phân tích
└── server-evidence-skipped-risky-files.csv  — file bị bỏ qua khi unzip evidence
```

**So sánh ngắn với Burp Suite:** Burp là pentest (chủ động tìm lỗ hổng); WebIncident
là forensics (phân tích sau khi đã bị tấn công). Hai công cụ ở hai pha khác nhau
trong vòng đời an ninh, không cạnh tranh.

---

## 5. Settings

Trang đơn giản, hiển thị metadata runtime:

- **Phiên bản** — ví dụ `0.1.0`.
- **Ngôn ngữ** — `vi-VN` / `en-US` (đọc từ `CultureInfo.CurrentUICulture`).
- **Theme** — Light / Dark (theo hệ thống, chưa cho chọn tay trong v0.1).
- **Quyền Admin** — `True` / `False` (phải là True để audit đầy đủ).

Ngoài ra có 2 card thông tin:
- **Về biên bản kiểm tra** — nhắc rằng report PDF có phần đầu/cuối để điền tay.
- **Sử dụng có ủy quyền** — nhắc EULA + luật ANM 2018.

![Settings page](images/30-settings.png)

---

## 6. CLI & WinPE offline

Ngoài WPF shell, bạn có **`SecAudit.Cli.exe`** headless cho kịch bản Incident
Response (boot USB WinPE, audit ổ đĩa đã ngắt):

```cmd
SecAudit.Cli.exe --offline D:\ --output F:\reports --formats html,pdf,json
```

Chi tiết đầy đủ xem [`winpe-usage.md`](winpe-usage.md). Tóm tắt flags:

| Flag | Ý nghĩa |
|---|---|
| `--offline <drive>` | Audit ổ Windows đã mount offline (ví dụ `D:\`). Chỉ 3 module chạy có nghĩa: PatchCve, RemoteAccess, LogForensics. |
| `--output <dir>` | Nơi ghi HTML/PDF/JSON/DOCX. |
| `--asset <name>` | Đặt tên asset trong report. Mặc định `%COMPUTERNAME%` hoặc `<drive>-OFFLINE`. |
| `--formats <list>` | Lọc format. VD `html,pdf`. |
| `--quiet` | Bỏ log tiến độ, chỉ in error. |
| `-h`, `--help` | In help. |

Khi ở `--offline`, CLI tự seed `ForensicsSettings.LocalPath = <drive>\Windows\System32\winevt\Logs`
cho LogForensics — tức bạn không cần config trang Log Forensics riêng; report
sẽ có sẵn dấu hiệu brute-force, log cleared, service install lạ trên volume.

![CLI running](images/40-cli-offline.png)

---

## 7. Báo cáo xuất ra

Mỗi lần audit, SecAudit ghi:

```
%LOCALAPPDATA%\SecAudit\reports\
└── report-20260420-093544\
    ├── report.html      (dễ đọc, mở bằng trình duyệt mặc định)
    ├── report.pdf       (QuestPDF — dùng để in, ký & đóng dấu)
    ├── report.json      (machine-readable, import vào SIEM)
    └── report.docx      (biên bản — phần đầu/cuối điền tay)
```

Cùng thư mục:

```
%LOCALAPPDATA%\SecAudit\forensics\<session-id>\
├── evidence\              (log files đã snapshot)
└── manifest.json          (SHA-256 mỗi file, session metadata)

%PROGRAMDATA%\SecAudit\audit\
└── audit-20260420.log     (JSONL hash-chain, signed ECDSA-P256)
```

**Biên bản DOCX** có layout theo mẫu "BIÊN BẢN GHI NHẬN":

- Phần I — Thông tin chung (đơn vị, ngày, căn cứ, thành phần) — **để trống, điền tay**
- Phần II — Kết quả kiểm tra — **tự động điền** từ audit
- Phần III — Kiến nghị — kết hợp từ các `Remediation` của finding Critical/High
- Phần ký — **để trống**

![Report HTML mẫu](images/50-report-html.png)
![Report PDF mẫu](images/51-report-pdf.png)
![Report DOCX mẫu](images/52-report-docx.png)

---

## 8. Cách chụp lại các ảnh trong tài liệu

Các file PNG được tham chiếu trong tài liệu này **chưa có sẵn** trong repo — bạn
chụp lại khi chạy thực tế. Dưới đây là script PowerShell giúp chụp nhanh từng
bước (cần cài Windows 10/11, không cần phần mềm ngoài):

```powershell
# save as build\capture-screenshots.ps1
$target = "C:\Users\Admin\AI\docs\images"
New-Item -ItemType Directory -Force -Path $target | Out-Null

function Snap([string]$name, [string]$hint) {
    Write-Host ""
    Write-Host ">>> Bước kế tiếp: $hint" -Foreground Yellow
    Read-Host "    Chuẩn bị xong, Enter để chụp cửa sổ SecAudit đang focus"
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $w = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $w.Width, $w.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($w.Location, [System.Drawing.Point]::Empty, $bmp.Size)
    $path = Join-Path $target $name
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "    Đã lưu: $path" -Foreground Green
}

Snap "00-uac-prompt.png"         "Bấm đúp SecAudit.exe, đợi UAC prompt hiện ra"
Snap "01-eula-gate.png"          "Chấp nhận UAC, đợi modal EULA gate"
Snap "02-shell-layout.png"       "Qua EULA, vào Dashboard"
Snap "10-dashboard-idle.png"     "Trang Dashboard, chưa chạy audit"
Snap "11-dashboard-running.png"  "Bấm Run Full Audit, chờ ~30% tiến độ"
Snap "12-dashboard-done.png"     "Đợi audit xong"
Snap "20-logforensics-overview.png" "Chuyển sang tab Log Forensics (chưa điền)"
Snap "21-logforensics-tab-local.png" "Chọn tab Local, paste path D:\Evidence"
Snap "22-logforensics-tab-eventlog.png" "Chuyển tab Windows Event Log, gõ Security"
Snap "23-logforensics-tab-ssh.png"  "Chuyển tab SSH, điền host giả"
Snap "24-logforensics-baseline.png" "Focus khu baseline, đã điền whitelist"
Snap "25-logforensics-finished.png" "Sau khi bấm Bắt đầu phân tích, scan xong"
Snap "30-settings.png"           "Điều hướng xuống Settings"
Snap "40-cli-offline.png"        "Mở cửa sổ cmd, chạy SecAudit.Cli --help rồi --offline"
Snap "50-report-html.png"        "Mở report.html trong browser"
Snap "51-report-pdf.png"         "Mở report.pdf trong viewer"
Snap "52-report-docx.png"        "Mở report.docx trong Word"
```

Cách dùng:

1. Build app: `dotnet build SecAudit.sln -c Release`
2. Chạy `powershell -ExecutionPolicy Bypass -File build\capture-screenshots.ps1`
3. Mỗi lần script dừng, setup UI đúng như hint rồi Enter để chụp.
4. Check `docs\images\*.png`, commit.

> Script chụp **toàn màn hình** (PrimaryScreen). Nếu bạn dùng 2 màn hình và
> SecAudit mở ở màn phụ, sửa `PrimaryScreen` thành `AllScreens[1]` hoặc dùng
> `GetWindowRect` qua P/Invoke để chụp đúng cửa sổ.

---

## Phụ lục — Bảng tham chiếu nhanh các rule

| Rule | EventKind phát hiện | Nguồn log tối thiểu | Trường cần điền trên UI |
|---|---|---|---|
| BruteForce | `logon.failed` ≥10/600s cùng user hoặc IP | Security evtx / auth.log | (không cần baseline) |
| UnknownLogon | `logon.success` user ∉ whitelist | Security evtx / auth.log | **User whitelist** (bắt buộc) + **Internal CIDRs** (để phân High/Critical) |
| LogCleared | Event 1102/104 hoặc rsyslog restart | Security / System evtx, auth.log | (không cần baseline) |
| BackdoorService | Event 4697/7045 image path đáng ngờ | Security / System evtx | (không cần baseline) |
| VulnScan | UA scanner hoặc 50+ URI/IP trong 300s | nginx/apache access.log, IIS u_ex | (không cần baseline) |
| PrivEsc | Event 4672, sudo COMMAND=, sudo -i | Security evtx, auth.log, bash_history | (không cần baseline) |
| Keylogger | Sysmon 13 UpperFilters lạ, apt install logkeys, tên process chứa "keylogger" | Sysmon channel, auth.log, bash_history | (không cần baseline) |
| Ransomware | 100+ file/phút với extension ransom, vssadmin delete shadows | Sysmon 11, bash/process log | (không cần baseline) |
| DataDestruction | rm -rf /, dd if=/dev/zero, wevtutil cl, format /q | bash_history, Security evtx | (không cần baseline) |

---

**Tài liệu liên quan**: [`winpe-usage.md`](winpe-usage.md), [EULA](../EULA.md),
[`README.md`](../README.md).
