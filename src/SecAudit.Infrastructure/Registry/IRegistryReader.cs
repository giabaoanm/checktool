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
}
