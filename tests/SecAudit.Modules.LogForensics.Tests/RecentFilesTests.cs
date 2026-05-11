using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Recent;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class RecentFilesTests : IDisposable
{
    private readonly string _tmp;

    public RecentFilesTests()
    {
        _tmp = Path.Combine(Path.GetTempPath(),
            "secaudit-rct-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(_tmp);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmp, recursive: true); } catch { /* best effort */ }
    }

    /// <summary>
    /// Builds a minimal valid .lnk file with the requested target local path,
    /// drive type, working dir and arguments. Implements a subset of MS-SHLLINK
    /// sufficient for LnkFileParser to recognise.
    /// </summary>
    private static byte[] BuildSyntheticLnk(
        string targetPath,
        uint driveType = 3,         // 3 = Fixed
        string workingDir = "",
        string arguments = "",
        string description = "")
    {
        var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // Header (76 bytes)
        w.Write(0x0000004Cu);                            // HeaderSize
        w.Write(new byte[] {                              // LinkCLSID {00021401-0000-0000-C000-000000000046}
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 });
        // LinkFlags: HasLinkInfo + HasName + HasWorkingDir + HasArguments + IsUnicode
        uint flags = 0x02;
        if (!string.IsNullOrEmpty(description)) flags |= 0x04;
        if (!string.IsNullOrEmpty(workingDir))  flags |= 0x10;
        if (!string.IsNullOrEmpty(arguments))   flags |= 0x20;
        flags |= 0x80; // IsUnicode for StringData
        w.Write(flags);
        w.Write(0u);                                      // FileAttributes
        w.Write(0L);                                      // CreationTime
        w.Write(0L);                                      // AccessTime
        w.Write(0L);                                      // WriteTime
        w.Write(0u);                                      // FileSize
        w.Write(0u);                                      // IconIndex
        w.Write(0u);                                      // ShowCommand
        w.Write((ushort)0);                               // HotKey
        w.Write(new byte[10]);                            // Reserved

        // LinkInfo (no IDList): build a small structure.
        // Layout: LinkInfoSize | LinkInfoHeaderSize | LinkInfoFlags | VolumeIDOffset
        //         | LocalBaseOffset | CommonNetworkRelativeLinkOffset | CommonPathSuffixOffset
        // VolumeID block (16 bytes) at offset 0x1C, then LocalBasePath ANSI, then null suffix.
        var pathBytes = System.Text.Encoding.ASCII.GetBytes(targetPath);
        var volLabelBytes = System.Text.Encoding.ASCII.GetBytes("TEST"); // 4 + null
        // Volume block: 4 size + 4 type + 4 serial + 4 labelOffset(=0x10) + label(5 with null)
        int volBlockSize = 4 + 4 + 4 + 4 + volLabelBytes.Length + 1;
        int volStart = 0x1C;
        int localBaseStart = volStart + volBlockSize;
        int commonSuffixStart = localBaseStart + pathBytes.Length + 1;
        int linkInfoSize = commonSuffixStart + 1; // single null = empty common suffix

        w.Write((uint)linkInfoSize);                     // LinkInfoSize
        w.Write(0x1Cu);                                  // LinkInfoHeaderSize (no unicode)
        w.Write(0x01u);                                  // VolumeIDAndLocalBasePath
        w.Write((uint)volStart);                         // VolumeIDOffset
        w.Write((uint)localBaseStart);                   // LocalBasePathOffset
        w.Write(0u);                                     // CommonNetworkRelativeLinkOffset
        w.Write((uint)commonSuffixStart);                // CommonPathSuffixOffset

        // Volume block
        w.Write((uint)volBlockSize);                     // VolumeIDSize
        w.Write(driveType);                              // DriveType
        w.Write(0xDEADBEEFu);                            // DriveSerialNumber
        w.Write(0x10u);                                  // VolumeLabelOffset (relative to vol block start)
        w.Write(volLabelBytes);                          // label
        w.Write((byte)0);                                // null

        // LocalBasePath (ANSI null-terminated)
        w.Write(pathBytes);
        w.Write((byte)0);
        // Common suffix (empty)
        w.Write((byte)0);

        // StringData (Unicode CountChars + chars)
        void WriteUnicodeStringIfFlag(bool present, string s)
        {
            if (!present) return;
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            w.Write((ushort)s.Length);
            w.Write(b);
        }
        WriteUnicodeStringIfFlag((flags & 0x04) != 0, description);
        // (no relative path)
        WriteUnicodeStringIfFlag((flags & 0x10) != 0, workingDir);
        WriteUnicodeStringIfFlag((flags & 0x20) != 0, arguments);
        // (no icon)

        return ms.ToArray();
    }

    [Fact]
    public void Parser_extracts_local_path_from_synthetic_lnk()
    {
        var p = Path.Combine(_tmp, "test.lnk");
        File.WriteAllBytes(p, BuildSyntheticLnk(@"C:\Users\victim\Downloads\setup.exe"));

        var info = LnkFileParser.TryParse(p);

        info.Should().NotBeNull();
        info!.TargetLocalPath.Should().Be(@"C:\Users\victim\Downloads\setup.exe");
        info.DriveType.Should().Be("Fixed");
        info.VolumeSerial.Should().Be(0xDEADBEEF);
    }

    [Fact]
    public void Parser_extracts_arguments_and_working_dir()
    {
        var p = Path.Combine(_tmp, "with-args.lnk");
        File.WriteAllBytes(p, BuildSyntheticLnk(
            @"C:\Windows\System32\cmd.exe",
            workingDir: @"C:\Users\victim",
            arguments: "/c whoami"));

        var info = LnkFileParser.TryParse(p);
        info.Should().NotBeNull();
        info!.WorkingDir.Should().Be(@"C:\Users\victim");
        info.Arguments.Should().Be("/c whoami");
    }

    [Fact]
    public void Parser_returns_null_for_non_lnk_file()
    {
        var p = Path.Combine(_tmp, "fake.lnk");
        File.WriteAllBytes(p, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });
        LnkFileParser.TryParse(p).Should().BeNull();
    }

    [Fact]
    public void Parser_returns_null_for_missing_file()
    {
        LnkFileParser.TryParse(Path.Combine(_tmp, "no-such-file.lnk")).Should().BeNull();
    }

    [Fact]
    public void Analyzer_flags_executable_in_user_writable_path()
    {
        var users = Path.Combine(_tmp, "Users");
        var recent = Path.Combine(users, "alice", "AppData", "Roaming",
            "Microsoft", "Windows", "Recent");
        Directory.CreateDirectory(recent);
        File.WriteAllBytes(Path.Combine(recent, "downloaded.lnk"),
            BuildSyntheticLnk(@"C:\Users\alice\Downloads\bad.exe"));

        var ar = new RecentFilesAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.UsersExamined.Should().Be(1);
        ar.LnkFilesParsed.Should().Be(1);
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("RCT-EXEC-USERPATH-")
            && f.Severity == Severity.High
            && f.Evidence.Contains("Downloads", StringComparison.Ordinal));
    }

    [Fact]
    public void Analyzer_flags_removable_drive_target()
    {
        var users = Path.Combine(_tmp, "Users");
        var recent = Path.Combine(users, "bob", "AppData", "Roaming",
            "Microsoft", "Windows", "Recent");
        Directory.CreateDirectory(recent);
        File.WriteAllBytes(Path.Combine(recent, "usb.lnk"),
            BuildSyntheticLnk(@"E:\secret-doc.pdf", driveType: 2)); // 2 = Removable

        var ar = new RecentFilesAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("RCT-REMOVABLE-")
            && f.Severity == Severity.Medium);
    }

    [Fact]
    public void Analyzer_flags_LOLBin_arguments()
    {
        var users = Path.Combine(_tmp, "Users");
        var recent = Path.Combine(users, "carol", "AppData", "Roaming",
            "Microsoft", "Windows", "Recent");
        Directory.CreateDirectory(recent);
        // Arguments stored base64-encoded to keep test DLL clean
        var args = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(
            "L2MgcG93ZXJzaGVsbCAtbm9wIC1lbmMgQUFBQQ==")); // /c powershell -nop -enc AAAA
        File.WriteAllBytes(Path.Combine(recent, "evil.lnk"),
            BuildSyntheticLnk(@"C:\Windows\System32\cmd.exe", arguments: args));

        var ar = new RecentFilesAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("RCT-LOLBIN-LNK-")
            && f.Severity == Severity.High);
    }

    [Fact]
    public void Analyzer_skips_default_user_directories()
    {
        var users = Path.Combine(_tmp, "Users");
        foreach (var skipName in new[] { "Public", "Default", "All Users" })
        {
            var recent = Path.Combine(users, skipName, "AppData", "Roaming",
                "Microsoft", "Windows", "Recent");
            Directory.CreateDirectory(recent);
            File.WriteAllBytes(Path.Combine(recent, "x.lnk"),
                BuildSyntheticLnk(@"C:\Users\X\Downloads\y.exe"));
        }

        var ar = new RecentFilesAnalyzer().Analyze(users, "TEST", CancellationToken.None);
        ar.UsersExamined.Should().Be(0);
        ar.Findings.Where(f => f.Id.StartsWith("RCT-EXEC-USERPATH-"))
            .Should().BeEmpty();
    }

    [Fact]
    public void Analyzer_emits_jumplist_summary_when_present()
    {
        var users = Path.Combine(_tmp, "Users");
        var jl = Path.Combine(users, "dave", "AppData", "Roaming",
            "Microsoft", "Windows", "Recent", "AutomaticDestinations");
        Directory.CreateDirectory(jl);
        File.WriteAllBytes(Path.Combine(jl, "abc123.automaticDestinations-ms"), new byte[256]);
        File.WriteAllBytes(Path.Combine(jl, "def456.automaticDestinations-ms"), new byte[512]);

        var ar = new RecentFilesAnalyzer().Analyze(users, "TEST", CancellationToken.None);

        ar.JumpListFilesFound.Should().Be(2);
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("RCT-JUMPLIST-INFO-")
            && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyzer_returns_empty_for_no_users_dir()
    {
        var ar = new RecentFilesAnalyzer().Analyze(
            Path.Combine(_tmp, "no-such"), "TEST", CancellationToken.None);
        ar.UsersExamined.Should().Be(0);
        ar.LnkFilesParsed.Should().Be(0);
    }
}
