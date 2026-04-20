namespace SecAudit.Modules.LogForensics.Rules.Sysmon;

/// <summary>
/// Shared string marker lists and small utilities used by the 10 Sysmon-oriented
/// detection rules. Kept internal so the public rule API stays focused on
/// <see cref="Rules.IDetectionRule"/>.
///
/// Một điểm cần nhớ: Sysmon paths rendered bằng backslash Windows; so sánh luôn
/// dùng <see cref="StringComparison.OrdinalIgnoreCase"/>.
/// </summary>
internal static class SysmonHelpers
{
    /// <summary>
    /// Thư mục "ghi được bởi user" — nơi malware post-exploitation hay drop payload.
    /// Bất kỳ binary nào chạy từ đây đều đáng ngờ trong ngữ cảnh hệ thống doanh nghiệp.
    /// </summary>
    public static readonly string[] UserWritableMarkers =
    {
        @"\Users\Public\", @"\Windows\Temp\", @"\Temp\",
        @"\AppData\Local\Temp", @"\AppData\Roaming\",
        @"\ProgramData\", @"\$Recycle.Bin\", @"\PerfLogs\",
        @"\Downloads\"
    };

    /// <summary>
    /// LOLBAS (Living-Off-The-Land Binaries) thường bị lạm dụng — bản thân không
    /// phải malware nhưng attacker dùng để thực thi / download mà không drop EXE lạ.
    /// Nguồn: lolbas-project.github.io.
    /// </summary>
    public static readonly string[] LolBinNames =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "regasm.exe", "regsvcs.exe",
        "installutil.exe", "msbuild.exe", "bitsadmin.exe", "certutil.exe",
        "curl.exe", "wmic.exe", "forfiles.exe", "hh.exe"
    };

    /// <summary>
    /// Parent binaries that spawning a shell/script child is almost always malicious.
    /// Office macro → PowerShell là cổ điển; services.exe → powershell là persistence.
    /// </summary>
    public static readonly string[] SuspiciousParents =
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "visio.exe", "mspub.exe", "onenote.exe",
        "acrord32.exe", "foxitreader.exe",
        "wordpad.exe"
    };

    /// <summary>
    /// Shell children — attacker's landing pad after macro/exploit. Kết hợp với
    /// <see cref="SuspiciousParents"/> tạo thành chain cờ đỏ chuẩn Sigma.
    /// </summary>
    public static readonly string[] ShellChildren =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
        "certutil.exe", "curl.exe"
    };

    /// <summary>
    /// Cobalt Strike default named-pipe patterns — BEACON dùng pipe để inter-process
    /// comm giữa beacon DLL và its loader. Tên mặc định cực kỳ ổn định qua các bản
    /// CS; nếu thấy là gần như 100% positive.
    /// Ref: https://www.cobaltstrike.com/ + RiskIQ/Talos reports.
    /// </summary>
    public static readonly string[] CobaltStrikePipePatterns =
    {
        @"\msagent_",      // CS default
        @"\MSSE-",         // CS default
        @"\postex_",       // CS post-exploitation
        @"\status_",       // CS
        @"\mojo.5688",     // CS (collides w/ Chrome mojo — cần check process)
        @"\gh_",           // Meterpreter-style
        @"\wkssvc",        // masquerade as legitimate
        @"\spoolss"        // masquerade
    };

    /// <summary>
    /// Kiểm tra image path có nằm trong vùng "user-writable" hay không — một trong
    /// các heuristic mạnh nhất cho malware drop (Sigma rule pattern).
    /// </summary>
    public static bool IsInUserWritableLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) { return false; }
        foreach (var m in UserWritableMarkers)
        {
            if (path.Contains(m, StringComparison.OrdinalIgnoreCase)) { return true; }
        }
        return false;
    }

    /// <summary>
    /// Tách filename từ full image path, bỏ qua quotes. `C:\\Windows\\System32\\cmd.exe` → `cmd.exe`.
    /// </summary>
    private static readonly char[] PathSeparators = { '\\', '/' };

    public static string GetFileName(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) { return string.Empty; }
        var trimmed = imagePath.Trim('"', ' ');
        var idx = trimmed.LastIndexOfAny(PathSeparators);
        return idx < 0 ? trimmed.ToLowerInvariant() : trimmed[(idx + 1)..].ToLowerInvariant();
    }

    /// <summary>
    /// Stable 32-bit hash for finding IDs. Dùng xxHash-ish FNV-1a vì <c>string.GetHashCode</c>
    /// không ổn định giữa process (.NET randomizes) và chúng ta muốn cùng một record
    /// sinh cùng Finding.Id kể cả khi quét lại lần 2.
    /// </summary>
    public static string StableHash(string input)
    {
        unchecked
        {
            const uint offset = 2166136261u;
            const uint prime = 16777619u;
            uint h = offset;
            foreach (var c in input)
            {
                h ^= c;
                h *= prime;
            }
            return h.ToString("X8");
        }
    }
}
