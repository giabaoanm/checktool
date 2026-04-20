using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Parsers;
using SecAudit.Modules.LogForensics.Rules;
using SecAudit.Modules.LogForensics.Sources;
using SecAudit.Security;

namespace SecAudit.Modules.LogForensics.Services;

/// <summary>
/// Runs a forensics session end-to-end: pick source &#8594; download/snapshot &#8594; parse
/// &#8594; dispatch records to every rule &#8594; flush &#8594; return findings + manifest
/// of evidence files (for chain-of-custody). Thread-safe for single caller.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LogForensicsEngine
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new() { WriteIndented = true };

    private readonly IEnumerable<ILogParser> _parsers;
    private readonly IEnumerable<IDetectionRule> _rules;
    private readonly Func<ForensicsSourceKind, ILogSource> _sourceFactory;
    private readonly AuditLog _audit;
    private readonly ILogger<LogForensicsEngine> _log;

    public LogForensicsEngine(
        IEnumerable<ILogParser> parsers,
        IEnumerable<IDetectionRule> rules,
        Func<ForensicsSourceKind, ILogSource> sourceFactory,
        AuditLog audit,
        ILogger<LogForensicsEngine> log)
    {
        _parsers = parsers;
        _rules = rules;
        _sourceFactory = sourceFactory;
        _audit = audit;
        _log = log;
    }

    public async Task<ForensicsResult> RunAsync(
        ForensicsSettings settings,
        IProgress<ForensicsProgress> progress,
        CancellationToken ct)
    {
        var sessionId = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss")
            + "-" + Guid.NewGuid().ToString("N")[..8];
        if (string.IsNullOrWhiteSpace(settings.EvidenceRoot))
        {
            settings.EvidenceRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecAudit", "forensics", sessionId);
        }
        Directory.CreateDirectory(settings.EvidenceRoot);

        _audit.Write("LogForensics.Start", new Dictionary<string, string>
        {
            ["session"] = sessionId,
            ["source"] = settings.SourceKind.ToString(),
            ["evidence"] = settings.EvidenceRoot,
            ["whitelist"] = settings.UserWhitelist,
            ["internal_cidrs"] = settings.InternalCidrs
        });

        var ctx = BuildContext(settings);
        var manifest = new List<EvidenceEntry>();
        var source = _sourceFactory(settings.SourceKind);
        long totalRecords = 0;
        int fileCount = 0;

        var textProgress = new Progress<string>(msg =>
            progress.Report(new ForensicsProgress(sessionId, fileCount, totalRecords, msg)));

        try
        {
            await foreach (var file in source.EnumerateAsync(settings, textProgress, ct).ConfigureAwait(false))
            {
                ct.ThrowIfCancellationRequested();
                fileCount++;
                manifest.Add(new EvidenceEntry(file.OriginalPath, file.LocalPath, file.SizeBytes, file.Sha256));
                progress.Report(new ForensicsProgress(sessionId, fileCount, totalRecords,
                    $"parsing {Path.GetFileName(file.LocalPath)} ({FormatBytes(file.SizeBytes)})"));

                var parser = _parsers.FirstOrDefault(p => p.CanHandle(file));
                if (parser is null)
                {
                    _log.LogDebug("No parser for {Path}", file.LocalPath);
                    continue;
                }
                long perFile = 0;
                await foreach (var rec in parser.ParseAsync(file, ct).ConfigureAwait(false))
                {
                    ct.ThrowIfCancellationRequested();
                    perFile++;
                    totalRecords++;
                    foreach (var rule in _rules)
                    {
                        try { rule.Observe(rec, ctx); }
                        catch (Exception ex) { _log.LogWarning(ex, "Rule {Rule} threw on record", rule.Id); }
                    }
                    if (perFile % 2000 == 0)
                    {
                        progress.Report(new ForensicsProgress(sessionId, fileCount, totalRecords,
                            $"{Path.GetFileName(file.LocalPath)}: {perFile} records"));
                    }
                }
            }

            foreach (var rule in _rules)
            {
                try { rule.Flush(ctx); }
                catch (Exception ex) { _log.LogWarning(ex, "Rule {Rule} threw on flush", rule.Id); }
            }
        }
        catch (OperationCanceledException)
        {
            _audit.Write("LogForensics.Cancelled", new Dictionary<string, string> { ["session"] = sessionId });
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Forensics run failed");
            _audit.Write("LogForensics.Failed", new Dictionary<string, string>
            {
                ["session"] = sessionId,
                ["error"] = ex.Message
            });
            throw;
        }

        // Chain-of-custody: write signed manifest.json of every evidence file.
        var manifestPath = Path.Combine(settings.EvidenceRoot, "manifest.json");
        try
        {
            var manifestDoc = new
            {
                session = sessionId,
                machine = ctx.MachineName,
                source = settings.SourceKind.ToString(),
                started_utc = DateTimeOffset.UtcNow.ToString("u"),
                total_files = fileCount,
                total_records = totalRecords,
                total_findings = ctx.Findings.Count,
                evidence = manifest
            };
            await File.WriteAllTextAsync(manifestPath,
                JsonSerializer.Serialize(manifestDoc, ManifestJsonOptions),
                ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to write manifest.json");
        }

        _audit.Write("LogForensics.End", new Dictionary<string, string>
        {
            ["session"] = sessionId,
            ["files"] = fileCount.ToString(),
            ["records"] = totalRecords.ToString(),
            ["findings"] = ctx.Findings.Count.ToString(),
            ["manifest"] = manifestPath
        });

        return new ForensicsResult(
            SessionId: sessionId,
            EvidenceRoot: settings.EvidenceRoot,
            Findings: ctx.Findings.ToList(),
            Manifest: manifest,
            TotalRecords: totalRecords,
            TotalFiles: fileCount);
    }

    private static ForensicsContext BuildContext(ForensicsSettings s)
    {
        var whitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in (s.UserWhitelist ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            whitelist.Add(raw.ToLowerInvariant());
        }
        var cidrs = new List<CidrRange>();
        foreach (var raw in (s.InternalCidrs ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (CidrRange.TryParse(raw, out var r) && r is not null) { cidrs.Add(r); }
        }
        return new ForensicsContext
        {
            UserWhitelist = whitelist,
            InternalCidrs = cidrs,
            MachineName = Environment.MachineName
        };
    }

    private static string FormatBytes(long n)
        => n switch
        {
            < 1024 => $"{n} B",
            < 1024 * 1024 => $"{n / 1024.0:0.0} KB",
            < 1024L * 1024 * 1024 => $"{n / 1024.0 / 1024:0.0} MB",
            _ => $"{n / 1024.0 / 1024 / 1024:0.0} GB"
        };
}

public sealed record ForensicsProgress(string SessionId, int FilesProcessed, long RecordsProcessed, string Message);

public sealed record EvidenceEntry(string OriginalPath, string LocalPath, long SizeBytes, string Sha256);

public sealed record ForensicsResult(
    string SessionId,
    string EvidenceRoot,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<EvidenceEntry> Manifest,
    long TotalRecords,
    int TotalFiles);
