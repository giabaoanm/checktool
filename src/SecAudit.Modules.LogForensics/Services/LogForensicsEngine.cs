using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecAudit.Core.Models;
using SecAudit.Modules.LogForensics.Models;
using SecAudit.Modules.LogForensics.Correlation;
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
    private readonly CorrelationEngine _correlation;
    private readonly AuditLog _audit;
    private readonly ILogger<LogForensicsEngine> _log;

    public LogForensicsEngine(
        IEnumerable<ILogParser> parsers,
        IEnumerable<IDetectionRule> rules,
        Func<ForensicsSourceKind, ILogSource> sourceFactory,
        CorrelationEngine correlation,
        AuditLog audit,
        ILogger<LogForensicsEngine> log)
    {
        _parsers = parsers;
        _rules = rules;
        _sourceFactory = sourceFactory;
        _correlation = correlation;
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
            ["internal_cidrs"] = settings.InternalCidrs,
            ["from_utc"] = settings.FromUtc?.ToString("u") ?? "(any)",
            ["to_utc"] = settings.ToUtc?.ToString("u") ?? "(any)"
        });

        // CRITICAL: rules are DI singletons and hold accumulated state (e.g.
        // BruteForceRule._alreadyEmittedUser, UnknownLogonRule._seen). Without
        // this reset, the 2nd+ RunAsync() call sees every key as "already
        // emitted" and returns zero findings. Each rule's Reset() is a
        // default-method no-op unless overridden — safe to call blindly.
        foreach (var rule in _rules)
        {
            try { rule.Reset(); }
            catch (Exception ex) { _log.LogWarning(ex, "Rule {Rule} threw on reset", rule.Id); }
        }
        try { _correlation.Reset(); }
        catch (Exception ex) { _log.LogWarning(ex, "Correlation engine threw on reset"); }

        var ctx = BuildContext(settings);
        var manifest = new List<EvidenceEntry>();
        var source = _sourceFactory(settings.SourceKind);
        long totalRecords = 0;
        int fileCount = 0;

        var textProgress = new Progress<string>(msg =>
            progress.Report(new ForensicsProgress(sessionId, fileCount, totalRecords, msg)));

        // Copy raw log files vào subfolder "raw/" của evidence root để preserve
        // nguồn gốc. Nếu user điều tra sau này cần xem lại log thực → có bản
        // snapshot tại đây (hash SHA-256 đã ghi trong manifest để verify không
        // bị sửa đổi).
        var rawFolder = Path.Combine(settings.EvidenceRoot, "raw");
        Directory.CreateDirectory(rawFolder);

        try
        {
            await foreach (var file in source.EnumerateAsync(settings, textProgress, ct).ConfigureAwait(false))
            {
                ct.ThrowIfCancellationRequested();
                fileCount++;

                // Copy tệp gốc vào raw/ trước khi parse. Đặt tên an toàn, tránh
                // collision giữa các file trùng tên khác thư mục bằng prefix 8
                // ký tự đầu của SHA-256.
                string snapshotPath = file.LocalPath; // fallback nếu copy fail
                try
                {
                    var safeName = MakeSafeSnapshotName(file.OriginalPath, file.Sha256);
                    snapshotPath = Path.Combine(rawFolder, safeName);
                    if (!File.Exists(snapshotPath))
                    {
                        File.Copy(file.LocalPath, snapshotPath, overwrite: false);
                    }
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to snapshot {Src} to raw folder", file.LocalPath);
                    snapshotPath = file.LocalPath;
                }

                manifest.Add(new EvidenceEntry(file.OriginalPath, snapshotPath, file.SizeBytes, file.Sha256));
                progress.Report(new ForensicsProgress(sessionId, fileCount, totalRecords,
                    $"parsing {Path.GetFileName(file.LocalPath)} ({FormatBytes(file.SizeBytes)})"));

                var parser = _parsers.FirstOrDefault(p => p.CanHandle(file));
                if (parser is null)
                {
                    _log.LogDebug("No parser for {Path}", file.LocalPath);
                    continue;
                }
                long perFile = 0;
                long skippedByWindow = 0;
                await foreach (var rec in parser.ParseAsync(file, ct).ConfigureAwait(false))
                {
                    ct.ThrowIfCancellationRequested();
                    perFile++;

                    // Time window filter (FromUtc / ToUtc). Được áp dụng SAU parse
                    // chứ không trong source layer vì nhiều parser (EVTX, syslog,
                    // bash history) không thể seek nhanh theo timestamp — stream
                    // tuần tự rồi skip vẫn rẻ hơn indexing. Với Windows EVTX ta
                    // đã xử lý XPath-filter ở WindowsEventLogSource cho live
                    // channel; ở đây là safety-net cho tất cả formats.
                    if (settings.FromUtc.HasValue && rec.Timestamp < settings.FromUtc.Value)
                    {
                        skippedByWindow++;
                        continue;
                    }
                    if (settings.ToUtc.HasValue && rec.Timestamp > settings.ToUtc.Value)
                    {
                        skippedByWindow++;
                        continue;
                    }

                    totalRecords++;
                    foreach (var rule in _rules)
                    {
                        try { rule.Observe(rec, ctx); }
                        catch (Exception ex) { _log.LogWarning(ex, "Rule {Rule} threw on record", rule.Id); }
                    }
                    // Correlation engine sees the exact same record stream so it
                    // can chain findings emitted inside this same Observe cycle.
                    try { _correlation.Observe(rec, ctx); }
                    catch (Exception ex) { _log.LogWarning(ex, "Correlation engine threw on record"); }

                    if (perFile % 2000 == 0)
                    {
                        progress.Report(new ForensicsProgress(sessionId, fileCount, totalRecords,
                            $"{Path.GetFileName(file.LocalPath)}: {perFile} records"));
                    }
                }
                if (skippedByWindow > 0)
                {
                    _log.LogInformation("Time-window skipped {Count} records in {File}",
                        skippedByWindow, Path.GetFileName(file.LocalPath));
                }
            }

            foreach (var rule in _rules)
            {
                try { rule.Flush(ctx); }
                catch (Exception ex) { _log.LogWarning(ex, "Rule {Rule} threw on flush", rule.Id); }
            }
            // Flush correlation LAST so it sees findings emitted by rule.Flush().
            try { _correlation.Flush(ctx); }
            catch (Exception ex) { _log.LogWarning(ex, "Correlation engine threw on flush"); }
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

        // Findings JSON — danh sách phát hiện chi tiết kèm trích đoạn log gốc.
        // Đây là file user cần để làm biên bản, tách biệt khỏi manifest (chỉ
        // chứa metadata file). findings.jsonl = 1 finding/dòng để tool ngoài
        // (jq, Excel import) parse dễ. findings.json = pretty-printed array.
        try
        {
            var findingsJsonPath = Path.Combine(settings.EvidenceRoot, "findings.json");
            var findingsDoc = new
            {
                session = sessionId,
                machine = ctx.MachineName,
                generated_utc = DateTimeOffset.UtcNow.ToString("u"),
                count = ctx.Findings.Count,
                findings = ctx.Findings.Select(f => new
                {
                    id = f.Id,
                    title = f.Title,
                    severity = f.Severity.ToString(),
                    category = f.Category,
                    asset = f.Asset,
                    detected_utc = f.DetectedAt.UtcDateTime.ToString("u"),
                    evidence = f.Evidence,
                    remediation = f.Remediation,
                    references = f.References
                }).ToArray()
            };
            await File.WriteAllTextAsync(findingsJsonPath,
                JsonSerializer.Serialize(findingsDoc, ManifestJsonOptions),
                ct).ConfigureAwait(false);

            var findingsJsonlPath = Path.Combine(settings.EvidenceRoot, "findings.jsonl");
            var sb = new System.Text.StringBuilder();
            foreach (var f in ctx.Findings)
            {
                sb.AppendLine(JsonSerializer.Serialize(new
                {
                    id = f.Id,
                    title = f.Title,
                    severity = f.Severity.ToString(),
                    category = f.Category,
                    asset = f.Asset,
                    evidence = f.Evidence
                }));
            }
            await File.WriteAllTextAsync(findingsJsonlPath, sb.ToString(), ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to write findings.json");
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

    /// <summary>
    /// Sinh tên file an toàn cho snapshot trong thư mục raw/. Prefix bằng 8
    /// ký tự đầu SHA-256 để tránh collision khi 2 thư mục khác nhau có file
    /// trùng tên (e.g. nhiều auth.log từ nhiều máy). Thay các ký tự không
    /// hợp lệ trong Windows filename bằng '_'.
    /// </summary>
    private static string MakeSafeSnapshotName(string originalPath, string sha256)
    {
        var baseName = Path.GetFileName(originalPath);
        if (string.IsNullOrWhiteSpace(baseName)) { baseName = "unnamed"; }
        var invalid = Path.GetInvalidFileNameChars();
        var safe = new string(baseName.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        var prefix = sha256.Length >= 8 ? sha256[..8] : sha256;
        return $"{prefix}-{safe}";
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
