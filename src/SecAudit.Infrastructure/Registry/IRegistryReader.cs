namespace SecAudit.Infrastructure.Registry;

public enum RegistryHive
{
    LocalMachine,
    CurrentUser,
    Users,
    ClassesRoot
}

public interface IRegistryReader
{
    object? GetValue(RegistryHive hive, string subKey, string valueName, bool view64 = true);
    IReadOnlyList<string> GetSubKeyNames(RegistryHive hive, string subKey, bool view64 = true);
    IReadOnlyList<string> GetValueNames(RegistryHive hive, string subKey, bool view64 = true);

    /// <summary>
    /// Returns the LastWriteTime (UTC) of the registry key, or null if the key does not exist
    /// or the platform call fails. Used by forensic collectors to derive "config last
    /// modified at" timelines (e.g. when a Tcpip\Parameters\Interfaces\{guid} key was last
    /// touched).
    /// </summary>
    DateTime? GetLastWriteTime(RegistryHive hive, string subKey, bool view64 = true);
}
