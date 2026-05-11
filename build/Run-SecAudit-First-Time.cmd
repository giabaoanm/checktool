@echo off
:: =====================================================================
::  SecAudit — First-time launcher
:: =====================================================================
::  WHY THIS SCRIPT EXISTS:
::  SecAudit chứa hàng nghìn signature mã độc (YARA rule, cracker pattern,
::  credential-dumper detection). Windows Defender / Kaspersky / ESET nhìn
::  những chuỗi này bên trong SecAudit.exe và NHẦM tool là payload, dẫn tới
::  quarantine ngay khi user chạy lần đầu. Đây là vấn đề chung của MỌI security
::  tool có embedded signature (PE-bear, oletools, YARA-scanner...). Không có
::  cách triệt để ngoài: (a) ký Authenticode + submit Microsoft whitelist, hoặc
::  (b) Defender exclusion thủ công.
::
::  Script này:
::    1) Yêu cầu quyền Admin (UAC prompt).
::    2) Thêm Defender exclusion cho thư mục chứa SecAudit.exe.
::    3) Thêm Defender exclusion cho %LOCALAPPDATA%\SecAudit\ (nơi tool xuất báo cáo).
::    4) Khởi chạy SecAudit.exe.
::
::  Sau khi chạy lần đầu, user có thể double-click SecAudit.exe trực tiếp.
:: =====================================================================

setlocal EnableExtensions EnableDelayedExpansion

:: --- Elevate to Admin if needed ---
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [SecAudit] Yêu cầu quyền Administrator để thêm Defender exclusion...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

set "SECAUDIT_DIR=%~dp0"
set "SECAUDIT_EXE=%SECAUDIT_DIR%SecAudit.exe"
set "REPORTS_DIR=%LOCALAPPDATA%\SecAudit"

if not exist "%SECAUDIT_EXE%" (
    echo [LỖI] Khong tim thay SecAudit.exe cung thu muc voi launcher.
    echo Vui long dat Run-SecAudit-First-Time.cmd CUNG thu muc voi SecAudit.exe.
    pause
    exit /b 1
)

echo.
echo ======================================================
echo  SecAudit - First-time setup
echo ======================================================
echo.
echo  - SecAudit folder:  %SECAUDIT_DIR%
echo  - SecAudit binary:  %SECAUDIT_EXE%
echo  - Reports folder:   %REPORTS_DIR%
echo.
echo Dang them Defender exclusion (an toan voi enterprise policy)...
echo.

:: Microsoft Defender exclusions — folder + path + process
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Add-MpPreference -ExclusionPath '%SECAUDIT_DIR%' -ErrorAction Stop; Write-Host '  [OK] ExclusionPath: %SECAUDIT_DIR%' -ForegroundColor Green } catch { Write-Host ('  [BO QUA] ExclusionPath thu muc: ' + $_.Exception.Message) -ForegroundColor Yellow }"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Add-MpPreference -ExclusionPath '%REPORTS_DIR%' -ErrorAction Stop; Write-Host '  [OK] ExclusionPath: %REPORTS_DIR%' -ForegroundColor Green } catch { Write-Host ('  [BO QUA] ExclusionPath reports: ' + $_.Exception.Message) -ForegroundColor Yellow }"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Add-MpPreference -ExclusionProcess 'SecAudit.exe' -ErrorAction Stop; Write-Host '  [OK] ExclusionProcess: SecAudit.exe' -ForegroundColor Green } catch { Write-Host ('  [BO QUA] ExclusionProcess: ' + $_.Exception.Message) -ForegroundColor Yellow }"

:: Create reports folder so the exclusion-path applies even before first scan.
if not exist "%REPORTS_DIR%" mkdir "%REPORTS_DIR%" >nul 2>&1

echo.
echo ======================================================
echo Defender exclusion da duoc them. Dang khoi chay SecAudit...
echo ======================================================
echo.
echo LUU Y:
echo   - Sau lan dau, ban co the double-click SecAudit.exe truc tiep.
echo   - Neu dung AV ben thu 3 (Kaspersky/ESET): can vao GUI cua AV de them
echo     '%SECAUDIT_DIR%' vao Trusted folder thu cong.
echo   - Go bo exclusion sau khi xong: Remove-MpPreference -ExclusionPath '%SECAUDIT_DIR%'
echo.

start "" "%SECAUDIT_EXE%"

exit /b 0
