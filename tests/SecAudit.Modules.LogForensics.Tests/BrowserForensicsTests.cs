using FluentAssertions;
using Microsoft.Data.Sqlite;
using SecAudit.Modules.LogForensics.Browser;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

public sealed class BrowserForensicsTests : IDisposable
{
    private readonly string _tmpDir;

    public BrowserForensicsTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(),
            "secaudit-bf-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(_tmpDir);
        SQLitePCL.Batteries_V2.Init();
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); } catch { /* best effort */ }
    }

    /// <summary>Builds a synthetic Chromium History DB with one visit + one download row.</summary>
    private string BuildChromiumDb()
    {
        var dbPath = Path.Combine(_tmpDir, "History");
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
                CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT, mime_type TEXT,
                    total_bytes INTEGER, start_time INTEGER, end_time INTEGER, danger_type INTEGER, tab_referrer_url TEXT);
                CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
                INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
                    ('https://attacker.click/payload', 'Free Software', 1, 13350000000000000),
                    ('https://benign.example.com', 'Hello', 5, 13350000000000000),
                    ('http://1.2.3.4/exploit', 'IP-only', 1, 13350000000000000);
                INSERT INTO downloads (target_path, current_path, mime_type, total_bytes, start_time,
                    end_time, danger_type, tab_referrer_url) VALUES
                    ('C:\Users\victim\Downloads\setup.exe', 'C:\Users\victim\Downloads\setup.exe',
                     'application/octet-stream', 4096000, 13350000000000000, 13350000000001000, 0,
                     'https://phishing.zip/landing'),
                    ('C:\Users\victim\Downloads\bad.exe', 'C:\Users\victim\Downloads\bad.exe',
                     'application/x-msdos-program', 1024000, 13350000000000000, 13350000000001000, 4,
                     'https://attacker.click/');
                INSERT INTO downloads_url_chains (id, chain_index, url) VALUES
                    (1, 0, 'https://attacker.click/setup.exe'),
                    (2, 0, 'https://attacker.click/bad.exe');";
            cmd.ExecuteNonQuery();
        }
        return dbPath;
    }

    [Fact]
    public void ChromiumReader_returns_visits_and_downloads()
    {
        var db = BuildChromiumDb();

        var (visits, downloads) = BrowserHistoryReader.ReadChromium(db, "Chrome");

        visits.Should().HaveCount(3);
        visits.Should().Contain(v => v.Url == "https://attacker.click/payload");
        visits.Should().Contain(v => v.Url == "http://1.2.3.4/exploit");
        downloads.Should().HaveCount(2);
        downloads.Should().Contain(d => d.TargetPath.EndsWith("setup.exe", StringComparison.Ordinal)
            && d.SourceUrl == "https://attacker.click/setup.exe");
        downloads.Should().Contain(d => d.DangerType == 4); // SafeBrowsing-flagged
    }

    [Fact]
    public void ChromiumReader_returns_empty_for_missing_db()
    {
        var (v, d) = BrowserHistoryReader.ReadChromium(Path.Combine(_tmpDir, "missing"), "Chrome");
        v.Should().BeEmpty();
        d.Should().BeEmpty();
    }

    [Fact]
    public void Analyzer_flags_executable_downloads_from_internet()
    {
        // Build a synthetic users tree mimicking C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\History
        var usersRoot = Path.Combine(_tmpDir, "Users");
        var profileDir = Path.Combine(usersRoot, "victim",
            "AppData", "Local", "Google", "Chrome", "User Data", "Default");
        Directory.CreateDirectory(profileDir);
        var historyDb = BuildChromiumDb();
        File.Copy(historyDb, Path.Combine(profileDir, "History"), overwrite: true);

        var ar = new BrowserForensicsAnalyzer().AnalyzeHost(usersRoot, "TEST", CancellationToken.None);

        ar.ProfilesScanned.Should().Be(1);
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("BRW-DANGEROUS-DL-")
            && f.Severity == SecAudit.Core.Models.Severity.Critical);
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("BRW-EXEC-DL-"));
        ar.Findings.Should().Contain(f =>
            f.Id.StartsWith("BRW-SUSPICIOUS-VISIT-")
            && f.Evidence.Contains(".click", StringComparison.Ordinal));
    }

    [Fact]
    public void Analyzer_emits_no_profile_when_users_root_is_empty()
    {
        var ar = new BrowserForensicsAnalyzer().AnalyzeHost(_tmpDir, "TEST", CancellationToken.None);
        ar.ProfilesScanned.Should().Be(0);
        ar.VisitsExamined.Should().Be(0);
    }

    [Fact]
    public void DiscoverProfiles_finds_chrome_edge_firefox()
    {
        var usersRoot = Path.Combine(_tmpDir, "users");
        // Chrome
        Directory.CreateDirectory(Path.Combine(usersRoot, "alice",
            "AppData", "Local", "Google", "Chrome", "User Data", "Default"));
        File.WriteAllBytes(Path.Combine(usersRoot, "alice",
            "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History"),
            new byte[] { 0 });
        // Edge
        Directory.CreateDirectory(Path.Combine(usersRoot, "bob",
            "AppData", "Local", "Microsoft", "Edge", "User Data", "Profile 1"));
        File.WriteAllBytes(Path.Combine(usersRoot, "bob",
            "AppData", "Local", "Microsoft", "Edge", "User Data", "Profile 1", "History"),
            new byte[] { 0 });
        // Firefox
        Directory.CreateDirectory(Path.Combine(usersRoot, "carol",
            "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "abc.default"));
        File.WriteAllBytes(Path.Combine(usersRoot, "carol",
            "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "abc.default", "places.sqlite"),
            new byte[] { 0 });

        var profiles = BrowserForensicsAnalyzer.DiscoverProfiles(usersRoot).ToList();

        profiles.Should().HaveCount(3);
        profiles.Select(p => p.Browser).Should().BeEquivalentTo(new[] { "Chrome", "Edge", "Firefox" });
        profiles.Select(p => p.UserName).Should().BeEquivalentTo(new[] { "alice", "bob", "carol" });
    }

    [Fact]
    public void DiscoverProfiles_skips_default_user_directories()
    {
        var usersRoot = Path.Combine(_tmpDir, "users-skip");
        foreach (var skipName in new[] { "Public", "Default", "Default User", "All Users" })
        {
            var dir = Path.Combine(usersRoot, skipName,
                "AppData", "Local", "Google", "Chrome", "User Data", "Default");
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, "History"), new byte[] { 0 });
        }

        BrowserForensicsAnalyzer.DiscoverProfiles(usersRoot).Should().BeEmpty();
    }

    [Fact]
    public void ZoneIdentifierReader_returns_null_when_no_motw()
    {
        var p = Path.Combine(_tmpDir, "plain.exe");
        File.WriteAllBytes(p, new byte[] { 0x4D, 0x5A });
        ZoneIdentifierReader.TryRead(p).Should().BeNull();
    }

    [Fact]
    public void ZoneIdentifierReader_parses_full_motw()
    {
        var p = Path.Combine(_tmpDir, "downloaded.exe");
        File.WriteAllBytes(p, new byte[] { 0x4D, 0x5A });
        // Write the alternate data stream :Zone.Identifier
        var ads = p + ":Zone.Identifier";
        try
        {
            File.WriteAllText(ads,
                "[ZoneTransfer]\r\n"
                + "ZoneId=3\r\n"
                + "HostUrl=https://attacker.example/payload.exe\r\n"
                + "ReferrerUrl=https://phishing.zip/landing\r\n");
        }
        catch (UnauthorizedAccessException)
        {
            // Some test runners hit a security policy; skip the assertion in that case.
            return;
        }
        catch (NotSupportedException)
        {
            // Non-NTFS volume — skip.
            return;
        }

        var motw = ZoneIdentifierReader.TryRead(p);
        motw.Should().NotBeNull();
        motw!.ZoneId.Should().Be(3);
        motw.ZoneName.Should().Be("Internet");
        motw.HostUrl.Should().Be("https://attacker.example/payload.exe");
        motw.ReferrerUrl.Should().Be("https://phishing.zip/landing");
    }
}
