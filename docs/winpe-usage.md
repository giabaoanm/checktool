# SecAudit — WinPE / Offline Volume Audit

Iteration 7 cho phép chạy SecAudit từ một USB boot WinPE / Mini-Windows để audit một
volume Windows đang bị tắt / nghi nhiễm rootkit / RAT mà không cần khởi động hệ điều
hành đó. Đây là kịch bản Incident Response kinh điển: nếu máy đã bị xâm nhập, boot
vào Windows thật sẽ để malware có cơ hội chống forensics (ẩn file, xoá event log,
kill audit tool). Boot vào WinPE và mount ổ C: thành D: để quét tĩnh.

## Module nào chạy được trong offline mode?

| Module | Offline? | Ghi chú |
|---|---|---|
| SystemInfo | KHÔNG | Cần WMI để đọc BIOS/CPU/license — không có nghĩa trên volume tĩnh. |
| Hardening | KHÔNG | Phần lớn check cần Defender/Firewall runtime state. |
| Patch & CVE | **CÓ** | Đọc Component Based Servicing packages từ SOFTWARE hive để tìm KB còn thiếu. |
| LAN Scanner | KHÔNG | Cần adapter mạng live. |
| Remote Access | **CÓ (một phần)** | Run keys + Services hive + Scheduled Tasks XML. WMI event-subscription bỏ qua (chỉ live). |
| Log Forensics | **CÓ** | Snapshot `<volume>\Windows\System32\winevt\Logs\*.evtx` + các parser sẵn có. |

3 module offline-capable = 3 câu hỏi IR kinh điển:
1. Máy có bản vá nào thiếu (attacker dùng CVE để vào)?
2. Có backdoor/persistence nào được cài?
3. Log ghi nhận gì bất thường?

## Chuẩn bị USB WinPE

### A. Build `SecAudit.Cli.exe` self-contained (bước này làm trên máy dev)

```powershell
# Từ repo root
./build/publish-cli.ps1
```

Script sẽ:
1. Clean `out\cli\`
2. `dotnet publish` với đầy đủ flag WinPE-compatible:
   `SelfContained`, `PublishSingleFile`, `InvariantGlobalization`, `PublishTrimmed=false`,
   `PublishReadyToRun=false`, `IncludeAllContentForSelfExtract`, compression
3. Verify đúng single-file (chỉ `.exe` + optional `.pdb`)
4. In SHA-256 để lưu provenance (đối chiếu sau khi copy sang USB)
5. Smoke test `--help` trên host (bắt các regression kiểu "globalization missing on startup")

Output: `out\cli\SecAudit.Cli.exe` (khoảng 45-50 MB). Đây là **file duy nhất** cần copy lên USB.

Để publish và copy sang USB trong 1 bước:
```powershell
$env:WINPE_USB = 'E:\SecAudit\'   # hoặc truyền -WinPeUsb
./build/publish-cli.ps1
```

### B. Tạo WinPE boot USB

1. Tải ADK + WinPE add-on từ Microsoft: <https://learn.microsoft.com/windows-hardware/get-started/adk-install>
2. Mở **Deployment and Imaging Tools Environment** (với quyền Administrator).
3. Tạo workspace và boot USB:
   ```cmd
   copype amd64 C:\WinPE_amd64
   MakeWinPEMedia /UFD C:\WinPE_amd64 F:
   ```
   (thay `F:` bằng ký tự ổ USB của bạn)
4. Copy `out\cli\SecAudit.Cli.exe` vào USB (ví dụ `F:\Tools\SecAudit.Cli.exe`).

> **Không cần** nhúng .NET runtime vào boot.wim. Publish script ở bước A đã bundle
> CoreCLR + all dependencies vào exe — đó là ý nghĩa của `SelfContained=true`.
> Khởi chạy lần đầu, exe tự extract vào `%TEMP%\.net\SecAudit.Cli\<hash>\` (trên WinPE
> là `X:\Windows\Temp\...` trong RAM disk) rồi boot CoreCLR từ đó.

### C. Alternative: Hiren's BootCD / Gandalf's Win10 PE

Nếu bạn đã có sẵn một Mini-Windows USB dạng Hiren's hoặc Gandalf's:
- Copy thẳng `SecAudit.Cli.exe` vào bất kỳ thư mục nào trên USB (ví dụ `F:\Tools\`).
- Không cần bước ADK/MakeWinPEMedia.
- SecAudit vẫn detect đúng môi trường qua key `HKLM\SYSTEM\ControlSet001\Control\MiniNT`.

## Chạy audit offline

1. Boot máy nghi nhiễm bằng USB WinPE.
2. Xác định ký tự ổ chứa Windows của máy (thường là `D:` trong WinPE vì `X:` là WinPE
   RAM disk). Kiểm tra bằng `dir D:\Windows`.
3. Chạy audit:
   ```cmd
   X:\> D:
   D:\> X:\SecAudit.Cli.exe --offline D:\ --output D:\Users\Public\secaudit-report --formats html,pdf,json
   ```
   Hoặc chạy trực tiếp từ USB:
   ```cmd
   F:\> SecAudit.Cli.exe --offline D:\ --output F:\reports
   ```

Output:
- Console hiển thị `[offline] LogForensics will scan: D:\Windows\System32\winevt\Logs`
  và danh sách module bị bỏ qua (`-- skipping system-info (not supported in --offline mode)`).
- Report HTML/PDF/JSON sinh ra trong thư mục `--output`.
- Chain-of-custody evidence của LogForensics nằm trong `%LOCALAPPDATA%\SecAudit\forensics\<session>\`
  (trên WinPE RAM disk — nhớ copy về trước khi reboot!).

## Giới hạn của offline mode

- **HKCU** không đọc được: NTUSER.DAT của mỗi user nằm ở `D:\Users\<name>\NTUSER.DAT` và
  không được load mặc định. Các autostart dưới `HKCU\...\Run` sẽ không được liệt kê.
  Workaround: dùng `reg load HKLM\OfflineUser D:\Users\<name>\NTUSER.DAT` thủ công trước
  khi chạy, hoặc tin vào HKLM-only (đủ cho 90% backdoor commodity).
- **WMI event subscriptions** (MITRE T1546.003) bỏ qua — WMI repository là binary proprietary.
  Phát hiện này chỉ có khi chạy live.
- **File-version CVE checks** (MS17-010 v.v.) hiện chỉ dựa trên KB; deep file-version match
  trên `D:\Windows\System32\*.sys` chưa được triển khai trong iteration này.
- **TPM / Secure Boot / BitLocker status** mất hoàn toàn — đó là runtime state.

## Detect đang chạy trong WinPE

SecAudit tự check key `HKLM\SYSTEM\ControlSet001\Control\MiniNT`. Nếu phát hiện WinPE
mà user không truyền `--offline`, CLI in cảnh báo:

```
[hint] Running inside WinPE but --offline was not supplied. The audit will target
the live WinPE environment, which is rarely what you want. Re-run with
--offline <drive-letter> to audit a mounted Windows volume.
```

## Yêu cầu quyền

- **Administrator** bắt buộc (WinPE boot mặc định chạy dưới SYSTEM — đủ).
- SecAudit enable `SeBackupPrivilege` + `SeRestorePrivilege` trong constructor của
  `MountedVolumeOfflineTarget` trước khi gọi `RegLoadKey`.

## Troubleshooting

| Triệu chứng | Nguyên nhân thường gặp |
|---|---|
| `RegLoadKey(SOFTWARE) failed: Win32 5` | Chưa chạy elevated. WinPE mặc định OK; máy dev phải "Run as admin". |
| `RegLoadKey(SOFTWARE) failed: Win32 32` | Hive file đang bị process khác hold. Đóng Regedit nếu đang mở. |
| `SOFTWARE hive missing at ...` | Volume root không đúng. Thử `dir D:\Windows\System32\config` để xác nhận. |
| `Windows folder not found at D:\Windows` | Volume không phải Windows OS disk — có thể là data partition. |
| `SeBackupPrivilege not held` | Process chưa elevated. |
| `CultureNotFoundException: vi-VN` trên WinPE | `InvariantGlobalization` bị tắt; rebuild bằng `publish-cli.ps1`. |
| `FileNotFoundException: System.Management.dll` | Trimming bị bật; `publish-cli.ps1` đã set `PublishTrimmed=false`. |
| Exe > 150 MB | `PublishReadyToRun=true` làm phình exe; check publish flags. |
| AV (Defender) flag "generic.trojan" trên exe | Compression + reflection trigger heuristic. Tạm thử build lại với `-p:EnableCompressionInSingleFile=false` hoặc sign bằng OV cert. |

## Roadmap tương lai (không thuộc iteration 7)

- Load NTUSER.DAT per-user để cover HKCU Run keys.
- File-version CVE check: đọc VS_VERSION_INFO từ `D:\Windows\System32\*.sys` bằng PeNet.
- Hỗ trợ BitLocker-protected volumes (unlock trước khi audit).
- Offline WMI repository parser (rất phức tạp — cân nhắc ROI).
