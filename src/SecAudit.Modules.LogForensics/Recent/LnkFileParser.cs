using System.Text;

namespace SecAudit.Modules.LogForensics.Recent;

/// <summary>
/// Minimal MS-SHLLINK (Windows .lnk shell shortcut) parser. We extract only the
/// fields a SOC analyst needs to trace user behaviour:
///
/// <list type="bullet">
///   <item><b>Target local path</b> — what file/folder the shortcut points at
///         (read from LinkInfo block).</item>
///   <item><b>Working directory + arguments</b> — from StringData; reveals
///         <c>cmd.exe /c …</c> launchers buried inside .lnk droppers.</item>
///   <item><b>Created/Accessed/Written times</b> of the TARGET at the moment
///         the shortcut was last refreshed.</item>
///   <item><b>Drive type</b> — fixed / removable / network (catches USB usage).</item>
/// </list>
///
/// <para>We deliberately skip full ItemIDList walking, ExtraData blob parsing,
/// and Unicode StringData (rare but supported via flag check). What we extract
/// covers ~95% of forensic value at ~250 LOC of code.</para>
/// </summary>
public static class LnkFileParser
{
    public sealed record LnkInfo(
        string FilePath,
        string TargetLocalPath,
        string WorkingDir,
        string Arguments,
        string Description,
        string IconLocation,
        DateTimeOffset? TargetCreationTime,
        DateTimeOffset? TargetAccessTime,
        DateTimeOffset? TargetWriteTime,
        long TargetFileSize,
        string DriveType,
        string VolumeLabel,
        uint VolumeSerial);

    private const uint MagicHeaderSize = 0x0000004C;

    [Flags]
    private enum LinkFlags : uint
    {
        HasLinkTargetIDList = 0x01,
        HasLinkInfo         = 0x02,
        HasName             = 0x04,
        HasRelativePath     = 0x08,
        HasWorkingDir       = 0x10,
        HasArguments        = 0x20,
        HasIconLocation     = 0x40,
        IsUnicode           = 0x80
    }

    public static LnkInfo? TryParse(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return null;
        }
        byte[] bytes;
        try { bytes = File.ReadAllBytes(filePath); }
        catch { return null; }
        if (bytes.Length < 76) { return null; }

        // ---- Header ----
        if (ReadU32(bytes, 0) != MagicHeaderSize) { return null; }
        var flags = (LinkFlags)ReadU32(bytes, 20);
        var creation = FileTimeToDto(ReadU64(bytes, 28));
        var access   = FileTimeToDto(ReadU64(bytes, 36));
        var write    = FileTimeToDto(ReadU64(bytes, 44));
        var fileSize = ReadU32(bytes, 52);
        bool isUnicode = flags.HasFlag(LinkFlags.IsUnicode);

        int offset = 76;

        // ---- Skip LinkTargetIDList ----
        if (flags.HasFlag(LinkFlags.HasLinkTargetIDList))
        {
            if (offset + 2 > bytes.Length) { return Empty(filePath); }
            ushort idListSize = ReadU16(bytes, offset);
            offset += 2 + idListSize;
        }

        // ---- LinkInfo ----
        var localPath = string.Empty;
        var driveType = "(unknown)";
        var volumeLabel = string.Empty;
        uint volumeSerial = 0;
        if (flags.HasFlag(LinkFlags.HasLinkInfo) && offset + 4 < bytes.Length)
        {
            int linkInfoStart = offset;
            uint linkInfoSize = ReadU32(bytes, linkInfoStart);
            if (linkInfoSize >= 0x1C && linkInfoStart + linkInfoSize <= bytes.Length)
            {
                uint linkInfoHeaderSize = ReadU32(bytes, linkInfoStart + 4);
                uint linkInfoFlags = ReadU32(bytes, linkInfoStart + 8);
                uint volumeIdOffset = ReadU32(bytes, linkInfoStart + 12);
                uint localBaseOffset = ReadU32(bytes, linkInfoStart + 16);
                uint commonPathSuffixOffset = ReadU32(bytes, linkInfoStart + 28);
                uint localBaseUnicodeOffset = 0;
                uint commonPathSuffixUnicodeOffset = 0;
                if (linkInfoHeaderSize >= 0x24 && linkInfoStart + 36 <= bytes.Length)
                {
                    localBaseUnicodeOffset = ReadU32(bytes, linkInfoStart + 32);
                    if (linkInfoHeaderSize >= 0x28 && linkInfoStart + 40 <= bytes.Length)
                    {
                        commonPathSuffixUnicodeOffset = ReadU32(bytes, linkInfoStart + 36);
                    }
                }

                // VolumeIDAndLocalBasePath flag bit 0
                if ((linkInfoFlags & 0x01) != 0)
                {
                    if (volumeIdOffset != 0 && linkInfoStart + volumeIdOffset + 16 <= bytes.Length)
                    {
                        int volStart = linkInfoStart + (int)volumeIdOffset;
                        uint volSize = ReadU32(bytes, volStart);
                        uint dt = ReadU32(bytes, volStart + 4);
                        volumeSerial = ReadU32(bytes, volStart + 8);
                        driveType = dt switch
                        {
                            0 => "Unknown", 1 => "NoRootDir", 2 => "Removable",
                            3 => "Fixed",   4 => "Remote",    5 => "CDRom", 6 => "RamDisk",
                            _ => $"DriveType={dt}"
                        };
                        // Volume label string pointer
                        uint volLabelOffset = ReadU32(bytes, volStart + 12);
                        if (volLabelOffset != 0 && volLabelOffset != 0x14
                            && volStart + volLabelOffset < bytes.Length)
                        {
                            volumeLabel = ReadAsciiZ(bytes, volStart + (int)volLabelOffset);
                        }
                        else if (volLabelOffset == 0x14 && volSize >= 0x18
                                 && volStart + 0x14 + 4 <= bytes.Length)
                        {
                            // Unicode label offset is at +0x10
                            uint volLabelUnicodeOffset = ReadU32(bytes, volStart + 16);
                            if (volStart + volLabelUnicodeOffset < bytes.Length)
                            {
                                volumeLabel = ReadUtf16Z(bytes, volStart + (int)volLabelUnicodeOffset);
                            }
                        }
                    }

                    // LocalBasePath: prefer Unicode if available, else ANSI
                    if (localBaseUnicodeOffset != 0
                        && linkInfoStart + localBaseUnicodeOffset < bytes.Length)
                    {
                        localPath = ReadUtf16Z(bytes, linkInfoStart + (int)localBaseUnicodeOffset);
                    }
                    else if (localBaseOffset != 0
                             && linkInfoStart + localBaseOffset < bytes.Length)
                    {
                        localPath = ReadAsciiZ(bytes, linkInfoStart + (int)localBaseOffset);
                    }

                    // Append common path suffix if present
                    string commonSuffix = string.Empty;
                    if (commonPathSuffixUnicodeOffset != 0
                        && linkInfoStart + commonPathSuffixUnicodeOffset < bytes.Length)
                    {
                        commonSuffix = ReadUtf16Z(bytes, linkInfoStart + (int)commonPathSuffixUnicodeOffset);
                    }
                    else if (commonPathSuffixOffset != 0
                             && linkInfoStart + commonPathSuffixOffset < bytes.Length)
                    {
                        commonSuffix = ReadAsciiZ(bytes, linkInfoStart + (int)commonPathSuffixOffset);
                    }
                    if (!string.IsNullOrEmpty(commonSuffix))
                    {
                        localPath += commonSuffix;
                    }
                }
            }
            offset = linkInfoStart + (int)linkInfoSize;
        }

        // ---- StringData (5 optional strings) ----
        var description = ReadStringData(bytes, ref offset, isUnicode, flags.HasFlag(LinkFlags.HasName));
        var relativePath = ReadStringData(bytes, ref offset, isUnicode, flags.HasFlag(LinkFlags.HasRelativePath));
        var workingDir   = ReadStringData(bytes, ref offset, isUnicode, flags.HasFlag(LinkFlags.HasWorkingDir));
        var arguments    = ReadStringData(bytes, ref offset, isUnicode, flags.HasFlag(LinkFlags.HasArguments));
        var iconLocation = ReadStringData(bytes, ref offset, isUnicode, flags.HasFlag(LinkFlags.HasIconLocation));

        // Fall back to relative path if we couldn't read LinkInfo (rare)
        if (string.IsNullOrEmpty(localPath) && !string.IsNullOrEmpty(relativePath))
        {
            localPath = relativePath;
        }

        return new LnkInfo(
            FilePath: filePath,
            TargetLocalPath: localPath,
            WorkingDir: workingDir,
            Arguments: arguments,
            Description: description,
            IconLocation: iconLocation,
            TargetCreationTime: creation,
            TargetAccessTime: access,
            TargetWriteTime: write,
            TargetFileSize: fileSize,
            DriveType: driveType,
            VolumeLabel: volumeLabel,
            VolumeSerial: volumeSerial);
    }

    // ---- Binary readers (little-endian) ----
    private static uint ReadU32(byte[] b, int o)
        => o + 4 <= b.Length ? (uint)(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) : 0;
    private static ushort ReadU16(byte[] b, int o)
        => o + 2 <= b.Length ? (ushort)(b[o] | b[o + 1] << 8) : (ushort)0;
    private static ulong ReadU64(byte[] b, int o)
    {
        if (o + 8 > b.Length) { return 0; }
        ulong lo = ReadU32(b, o);
        ulong hi = ReadU32(b, o + 4);
        return lo | hi << 32;
    }

    private static DateTimeOffset? FileTimeToDto(ulong ft)
    {
        if (ft is 0 or 0xFFFFFFFFFFFFFFFFUL) { return null; }
        try { return DateTimeOffset.FromFileTime((long)ft); }
        catch { return null; }
    }

    private static string ReadAsciiZ(byte[] b, int start)
    {
        int end = start;
        while (end < b.Length && b[end] != 0) { end++; }
        return Encoding.ASCII.GetString(b, start, end - start);
    }

    private static string ReadUtf16Z(byte[] b, int start)
    {
        int end = start;
        while (end + 1 < b.Length && !(b[end] == 0 && b[end + 1] == 0)) { end += 2; }
        return Encoding.Unicode.GetString(b, start, end - start);
    }

    private static string ReadStringData(byte[] b, ref int offset, bool isUnicode, bool present)
    {
        if (!present || offset + 2 > b.Length) { return string.Empty; }
        ushort count = ReadU16(b, offset);
        offset += 2;
        if (count == 0) { return string.Empty; }
        int byteLen = isUnicode ? count * 2 : count;
        if (offset + byteLen > b.Length) { return string.Empty; }
        var s = isUnicode
            ? Encoding.Unicode.GetString(b, offset, byteLen)
            : Encoding.Default.GetString(b, offset, byteLen);
        offset += byteLen;
        return s;
    }

    private static LnkInfo Empty(string path)
        => new(path, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty,
            null, null, null, 0, "(unknown)", string.Empty, 0);
}
