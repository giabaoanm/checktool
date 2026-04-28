using SecAudit.Security;

namespace SecAudit.Modules.LogForensics.Tests;

internal static class TestAuditLog
{
    public static AuditLog Create()
    {
        var folder = Path.Combine(
            Path.GetTempPath(),
            "SecAudit.Tests",
            "audit",
            Guid.NewGuid().ToString("N"));
        return new AuditLog(folder);
    }
}
