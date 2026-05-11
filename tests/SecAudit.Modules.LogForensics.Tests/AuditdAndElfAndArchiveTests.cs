using FluentAssertions;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.LinuxIncident;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Parsers;
using SecAudit.Modules.LogForensics.Rules;
using SecAudit.Modules.LogForensics.Sources;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class AuditdAndElfAndArchiveTests : IDisposable
{
    private readonly string _tmpDir;

    public AuditdAndElfAndArchiveTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(),
            "secaudit-aea-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* best effort */ }
    }

    // -------------------- Auditd parser --------------------

    [Fact]
    public async Task AuditdParser_extracts_execve_command()
    {
        var auditPath = Path.Combine(_tmpDir, "audit.log");
        File.WriteAllText(auditPath,
            "type=EXECVE msg=audit(1741991352.000:570): argc=3 a0=\"/usr/local/bin/.crond\" a1=\"--encrypt\" a2=\"/home/victim/Documents/\"\n"
            + "type=PATH msg=audit(1741991352.000:574): item=0 name=\"/home/victim/Documents/Cong_van_bi_mat.pdf.locked\" inode=1234 mode=0100644 nametype=CREATE\n"
            + "type=SYSCALL msg=audit(1741991352.000:570): arch=c000003e syscall=59 success=yes uid=1000 euid=0 exe=\"/usr/local/bin/.crond\" key=\"crypto\"\n");

        var parser = new LinuxAuditdParser();
        var raw = new RawLogFile(auditPath, auditPath, "linux", new FileInfo(auditPath).Length, "h");
        var records = new List<LogRecord>();
        await foreach (var r in parser.ParseAsync(raw, CancellationToken.None))
        {
            records.Add(r);
        }

        records.Should().HaveCount(3);
        records.Should().Contain(r => r.EventKind == "audit.execve"
            && r.GetField("Command")!.Contains("--encrypt", StringComparison.Ordinal));
        records.Should().Contain(r => r.EventKind == "audit.path"
            && r.GetField("Path")!.EndsWith(".locked", StringComparison.Ordinal)
            && r.GetField("Op") == "CREATE");
        records.Should().Contain(r => r.EventKind == "audit.syscall"
            && r.GetField("Exe") == "/usr/local/bin/.crond");
    }

    [Fact]
    public void AuditdEncryptionRule_fires_on_execve_with_encrypt_flag()
    {
        var rule = new AuditdEncryptionRule();
        var ctx = new ForensicsContext
        {
            UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            InternalCidrs = Array.Empty<CidrRange>(),
            MachineName = "TEST"
        };

        rule.Observe(MakeRec("audit.execve",
            ("Command", "/usr/local/bin/.crond --encrypt /home/victim/Documents/")), ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-AUDITD-CRYPTO-")
            && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AuditdEncryptionRule_fires_on_locked_path_burst_at_flush()
    {
        var rule = new AuditdEncryptionRule();
        var ctx = new ForensicsContext
        {
            UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            InternalCidrs = Array.Empty<CidrRange>(),
            MachineName = "TEST"
        };

        for (var i = 0; i < 5; i++)
        {
            rule.Observe(MakeRec("audit.path",
                ("Path", $"/home/victim/Documents/file{i}.pdf.locked"),
                ("Op", "CREATE")), ctx);
        }
        rule.Flush(ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id == "FOR-AUDITD-LOCKED-BURST"
            && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AuditdEncryptionRule_fires_on_hidden_binary_syscall()
    {
        var rule = new AuditdEncryptionRule();
        var ctx = new ForensicsContext
        {
            UserWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            InternalCidrs = Array.Empty<CidrRange>(),
            MachineName = "TEST"
        };

        rule.Observe(MakeRec("audit.syscall",
            ("Exe", "/usr/local/bin/.crond"),
            ("EffectiveUser", "euid:0")), ctx);

        ctx.Findings.Should().Contain(f =>
            f.Id.StartsWith("FOR-AUDITD-HIDDEN-")
            && f.Severity == Severity.High);
    }

    private static LogRecord MakeRec(string kind, params (string K, string V)[] fields)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in fields) { dict[k] = v; }
        return new LogRecord
        {
            Timestamp = DateTimeOffset.UtcNow,
            SourceFile = "audit.log",
            SourceOffset = 1,
            Os = "linux",
            EventKind = kind,
            RawLine = $"type={kind}",
            Fields = dict
        };
    }

    // -------------------- ELF triage --------------------

    [Fact]
    public void ElfTriage_returns_not_elf_for_text_file()
    {
        var p = Path.Combine(_tmpDir, "plain.txt");
        File.WriteAllText(p, "hello world this is just text");
        var r = ElfTriageAnalyzer.Analyze(p);
        r.IsElf.Should().BeFalse();
    }

    [Fact]
    public void ElfTriage_recognises_minimal_elf_header_and_extracts_strings()
    {
        // Construct a minimal but valid-looking ELF64 LE x86-64 stub with embedded strings.
        var p = Path.Combine(_tmpDir, ".crond");
        var bytes = new byte[2048];
        bytes[0] = 0x7F; bytes[1] = (byte)'E'; bytes[2] = (byte)'L'; bytes[3] = (byte)'F';
        bytes[4] = 2;   // EI_CLASS = ELF64
        bytes[5] = 1;   // EI_DATA = LE
        bytes[18] = 0x3E; bytes[19] = 0x00; // e_machine = x86-64
        // Embed strings starting at offset 64
        var s = "ChaCha20Poly1305\0_MEIPASS\0https://89.187.163.211:8443/api/v1/keys\0/usr/local/bin/.crond\0__libc_start_main\0";
        var sb = System.Text.Encoding.ASCII.GetBytes(s);
        Array.Copy(sb, 0, bytes, 64, sb.Length);
        File.WriteAllBytes(p, bytes);

        var r = ElfTriageAnalyzer.Analyze(p);
        r.IsElf.Should().BeTrue();
        r.ElfClass.Should().Be("ELF64");
        r.Endianness.Should().Be("LE");
        r.Machine.Should().Be("x86-64");
        r.Packer.Should().Be("PyInstaller");
        r.CryptoMarkers.Should().Contain(s => s.Contains("ChaCha20", StringComparison.Ordinal));
        r.SuspiciousUrls.Should().ContainSingle()
            .Which.Should().StartWith("https://89.187.163.211");
        r.SuspiciousPaths.Should().Contain(p2 => p2.Contains(".crond", StringComparison.Ordinal));
    }

    // -------------------- Archive extractor --------------------

    [Fact]
    public void ArchiveExtractor_detects_tar_gz_by_extension()
    {
        var p = Path.Combine(_tmpDir, "x.tar.gz");
        File.WriteAllBytes(p, new byte[] { 0x1F, 0x8B, 0x08, 0x00 });
        ArchiveExtractor.Detect(p).Should().Be(ArchiveExtractor.ArchiveKind.TarGz);
    }

    [Fact]
    public void ArchiveExtractor_detects_zip_by_magic()
    {
        var p = Path.Combine(_tmpDir, "weird-name");
        File.WriteAllBytes(p, new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00 });
        ArchiveExtractor.Detect(p).Should().Be(ArchiveExtractor.ArchiveKind.Zip);
    }

    [Fact]
    public void ArchiveExtractor_extracts_real_zip_with_nested_paths()
    {
        var zipPath = Path.Combine(_tmpDir, "evidence.zip");
        using (var zs = new System.IO.Compression.ZipArchive(File.Create(zipPath),
                   System.IO.Compression.ZipArchiveMode.Create))
        {
            var entry = zs.CreateEntry("var/log/auth.log");
            using var w = new StreamWriter(entry.Open());
            w.Write("Mar 14 23:45:17 host sshd[3]: Accepted password for victim from 89.187.163.211 port 22 ssh2");
        }

        var dest = Path.Combine(_tmpDir, "extract");
        ArchiveExtractor.Extract(zipPath, dest, CancellationToken.None);

        File.Exists(Path.Combine(dest, "var", "log", "auth.log")).Should().BeTrue();
    }

    [Fact]
    public void ArchiveExtractor_refuses_path_traversal_zip_slip()
    {
        var zipPath = Path.Combine(_tmpDir, "evil.zip");
        using (var zs = new System.IO.Compression.ZipArchive(File.Create(zipPath),
                   System.IO.Compression.ZipArchiveMode.Create))
        {
            var entry = zs.CreateEntry("../../../escaped.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write("pwned");
        }

        var dest = Path.Combine(_tmpDir, "safe-extract");
        ArchiveExtractor.Extract(zipPath, dest, CancellationToken.None);

        // The escaped file must NOT exist anywhere outside dest.
        var parentEscaped = Path.Combine(_tmpDir, "..", "..", "..", "escaped.txt");
        File.Exists(Path.GetFullPath(parentEscaped)).Should().BeFalse();
    }
}
