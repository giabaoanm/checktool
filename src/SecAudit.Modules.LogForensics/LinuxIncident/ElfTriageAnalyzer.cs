using System.Text;

namespace SecAudit.Modules.LogForensics.LinuxIncident;

/// <summary>
/// Quick triage of ELF binaries dropped on disk by an attacker. We do NOT execute
/// the binary, do NOT unpack PyInstaller fully, and do NOT disassemble — those
/// would need heavy tooling. What we DO is:
///
/// <list type="number">
///   <item>Validate ELF magic + read class (32/64), endianness, machine type
///         (x86-64, aarch64, …) and entry point.</item>
///   <item>Extract printable ASCII strings (length ≥ 6), then surface a curated
///         shortlist that matches well-known threat-intel markers:
///         crypto algorithms, packer signatures, suspicious URLs, hidden paths.</item>
///   <item>Classify the binary into one of: <c>PyInstaller</c>, <c>UPX</c>,
///         <c>Statically-linked</c>, <c>Dynamic-glibc</c>, <c>Other</c> based on
///         strong markers in the strings table.</item>
/// </list>
///
/// <para>The goal is to give the SOC operator a 30-second answer to
/// "what is this binary, what crypto does it use, where does it call out to?" —
/// without needing to spin up a sandbox.</para>
/// </summary>
public static class ElfTriageAnalyzer
{
    public sealed record ElfTriageResult(
        bool IsElf,
        string ElfClass,           // "ELF32" / "ELF64" / "(not-ELF)"
        string Endianness,         // "LE" / "BE"
        string Machine,            // "x86-64", "aarch64", "i386", …
        string Packer,             // "PyInstaller" / "UPX" / "Statically-linked" / "Other"
        IReadOnlyList<string> CryptoMarkers,
        IReadOnlyList<string> SuspiciousUrls,
        IReadOnlyList<string> SuspiciousPaths,
        IReadOnlyList<string> InterestingStrings);

    private static readonly string[] CryptoNeedles =
    {
        "ChaCha20", "ChaCha", "Poly1305", "Curve25519", "Ed25519", "X25519",
        "AES_GCM", "AES-GCM", "aes-256-gcm", "aes-256-cbc",
        "PBKDF2", "scrypt", "argon2", "HKDF", "HMAC-SHA256",
        "RSA_OAEP", "OAEP", "openssl_decrypt", "openssl_encrypt",
        "Crypto.Cipher", "_curve25519", "_ed25519", "_chacha20",
        "ransomware", "DECRYPT", "encrypted-by"
    };

    // Format: "Label::marker-string". ClassifyPacker splits on "::".
    private static readonly string[] PackerHints =
    {
        "PyInstaller::pyi-bootloader",
        "PyInstaller::_MEIPASS",
        "PyInstaller::PyInstaller",
        "UPX::UPX!",
        "UPX::$Info: This file is packed with the UPX",
        "UPX::UPX0",
    };

    public static ElfTriageResult Analyze(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!File.Exists(filePath))
        {
            return Empty("(file not found)");
        }
        var fi = new FileInfo(filePath);
        if (fi.Length < 64 || fi.Length > 200 * 1024 * 1024)
        {
            return Empty("(too small or > 200 MB — skipped)");
        }

        // Header: 16-byte e_ident + e_type(2) + e_machine(2) + e_version(4) +
        //         e_entry(4 or 8) + …  We read first 64 bytes for ident + machine.
        byte[] hdr = new byte[64];
        try
        {
            using var fs = File.OpenRead(filePath);
            var read = fs.Read(hdr, 0, hdr.Length);
            if (read < 20) { return Empty("(unreadable)"); }
        }
        catch
        {
            return Empty("(open failed)");
        }

        if (hdr[0] != 0x7F || hdr[1] != (byte)'E' || hdr[2] != (byte)'L' || hdr[3] != (byte)'F')
        {
            return Empty("(no ELF magic)");
        }

        var elfClass = hdr[4] switch { 1 => "ELF32", 2 => "ELF64", _ => "(unknown class)" };
        var endian = hdr[5] switch { 1 => "LE", 2 => "BE", _ => "?" };
        // e_machine at offset 18 (LE in most cases)
        ushort machine = (ushort)(hdr[18] | (hdr[19] << 8));
        var machineName = machine switch
        {
            0x3E => "x86-64",
            0x03 => "i386",
            0xB7 => "aarch64",
            0x28 => "ARM",
            0xF3 => "RISC-V",
            0x08 => "MIPS",
            _ => $"machine=0x{machine:X4}"
        };

        // Strings sweep — read up to 16 MB to keep memory bounded on giant binaries.
        var strings = ExtractStrings(filePath, maxBytesToRead: 16 * 1024 * 1024);

        var packer = ClassifyPacker(strings);
        var cryptoMarkers = strings
            .Where(s => CryptoNeedles.Any(n => s.Contains(n, StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.Ordinal)
            .Take(20)
            .ToArray();
        var urls = strings
            .Where(s => s.StartsWith("http://", StringComparison.Ordinal)
                     || s.StartsWith("https://", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .Take(20)
            .ToArray();
        var paths = strings
            .Where(s => s.Length > 0 && s[0] == '/'
                     && (s.Contains("/.crond", StringComparison.Ordinal)
                         || s.Contains("/.beacon", StringComparison.Ordinal)
                         || s.Contains("/.daemon", StringComparison.Ordinal)
                         || s.Contains("/tmp/", StringComparison.Ordinal)
                         || s.Contains("/dev/shm/", StringComparison.Ordinal)
                         || s.Contains("/opt/.phantom", StringComparison.Ordinal)
                         || s.EndsWith(".locked", StringComparison.OrdinalIgnoreCase)
                         || s.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.Ordinal)
            .Take(20)
            .ToArray();

        // Top "interesting" — first 10 cryptos + first 5 paths for the GUI summary panel.
        var interesting = cryptoMarkers.Take(10).Concat(paths.Take(5)).ToArray();

        return new ElfTriageResult(
            IsElf: true,
            ElfClass: elfClass,
            Endianness: endian,
            Machine: machineName,
            Packer: packer,
            CryptoMarkers: cryptoMarkers,
            SuspiciousUrls: urls,
            SuspiciousPaths: paths,
            InterestingStrings: interesting);
    }

    private static string ClassifyPacker(IReadOnlyList<string> strings)
    {
        foreach (var hint in PackerHints)
        {
            var sep = hint.IndexOf("::", StringComparison.Ordinal);
            var label = hint[..sep];
            var marker = hint[(sep + 2)..];
            if (strings.Any(s => s.Contains(marker, StringComparison.Ordinal)))
            {
                return label;
            }
        }
        return strings.Any(s => s.Contains("__libc_start_main", StringComparison.Ordinal))
            ? "Dynamic-glibc"
            : "Other";
    }

    private static List<string> ExtractStrings(string filePath, int maxBytesToRead)
    {
        var result = new List<string>();
        try
        {
            using var fs = File.OpenRead(filePath);
            int toRead = (int)Math.Min(maxBytesToRead, fs.Length);
            byte[] buf = new byte[toRead];
            int got = fs.Read(buf, 0, toRead);
            ExtractAsciiRuns(buf.AsSpan(0, got), 6, result);
        }
        catch
        {
            // best effort
        }
        return result;
    }

    private static void ExtractAsciiRuns(ReadOnlySpan<byte> data, int minRun, List<string> sink)
    {
        var sb = new StringBuilder(64);
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b >= 0x20 && b < 0x7F)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minRun) { sink.Add(sb.ToString()); }
                sb.Clear();
            }
        }
        if (sb.Length >= minRun) { sink.Add(sb.ToString()); }
    }

    private static ElfTriageResult Empty(string label)
        => new(false, label, "?", "?", "?",
            Array.Empty<string>(), Array.Empty<string>(),
            Array.Empty<string>(), Array.Empty<string>());
}
