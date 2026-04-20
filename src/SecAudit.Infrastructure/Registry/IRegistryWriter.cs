namespace SecAudit.Infrastructure.Registry;

// Mirrors Microsoft.Win32.RegistryValueKind so callers don't need a Win32 reference.
// 'String' shadows a CLR type name — accepted intentionally; CA1720 suppressed below.
#pragma warning disable CA1720 // Identifier contains type name
public enum RegistryValueKind
{
    String,
    DWord,
    QWord,
    MultiString,
    Binary
}
#pragma warning restore CA1720

/// <summary>
/// Write-side counterpart to <see cref="IRegistryReader"/>. Kept separate so audit-only
/// code paths (the read-only modules) can depend solely on the reader and not be tempted
/// to mutate state, while remediation actions opt into the writer explicitly.
/// </summary>
public interface IRegistryWriter
{
    /// <summary>
    /// Create the sub-key chain if missing, then set <paramref name="valueName"/> to
    /// <paramref name="value"/> with the given <paramref name="kind"/>. View defaults
    /// to 64-bit (matches reader). Throws on permission failure — caller catches.
    /// </summary>
    void SetValue(
        RegistryHive hive,
        string subKey,
        string valueName,
        object value,
        RegistryValueKind kind,
        bool view64 = true);
}
