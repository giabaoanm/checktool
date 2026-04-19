namespace SecAudit.Plugins.Abstractions;

/// <summary>
/// All audit modules implement this contract. Modules are discovered and registered with DI;
/// the orchestrator iterates IEnumerable&lt;IAuditModule&gt; and runs them sequentially or in
/// parallel depending on user choice.
/// </summary>
public interface IAuditModule
{
    ModuleMetadata Metadata { get; }

    Task<ModuleResult> RunAsync(
        ScanContext context,
        IProgress<ProgressUpdate> progress,
        CancellationToken cancellationToken);
}
