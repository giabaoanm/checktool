using System.Runtime.Versioning;
using FluentAssertions;
using SecAudit.Infrastructure.Registry;
using Xunit;

namespace SecAudit.Infrastructure.Tests;

/// <summary>
/// Locks down the offline/live path-translation matrix in <see cref="RegistryReader"/>.
///
/// This class exercises the INTERNAL <c>Translate</c> + <c>StartsWithSegment</c> helpers so
/// the logic can be verified without actually mounting a Windows volume or loading a hive.
/// Any behavior change in how HKLM\SOFTWARE / HKLM\SYSTEM are redirected under WinPE must
/// first update these tests — they ARE the spec for that translation.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryReaderOfflineTranslateTests
{
    // ---------------------------------------------------------------------------------------
    //  LIVE mode — Translate must be an identity function regardless of subKey content.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion")]
    [InlineData(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mrxsmb10")]
    [InlineData(RegistryHive.CurrentUser, @"Software\Microsoft\Windows")]
    [InlineData(RegistryHive.Users, @".DEFAULT\Control Panel")]
    [InlineData(RegistryHive.ClassesRoot, @"CLSID\{00000000-0000-0000-0000-000000000000}")]
    [InlineData(RegistryHive.LocalMachine, "")]
    public void Live_mode_is_identity_passthrough(RegistryHive hive, string subKey)
    {
        var reader = new RegistryReader(new FakeOfflineTarget { IsLive = true });

        reader.Translate(hive, subKey).Should().Be(subKey);
    }

    // ---------------------------------------------------------------------------------------
    //  OFFLINE mode — only HKLM\SOFTWARE and HKLM\SYSTEM are supported.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Offline_rejects_non_HKLM_hives()
    {
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = "SW_LOADED",
            LoadedSystemHiveKey = "SY_LOADED",
        });

        reader.Translate(RegistryHive.CurrentUser, @"Software\Microsoft").Should().BeNull();
        reader.Translate(RegistryHive.Users, @".DEFAULT").Should().BeNull();
        reader.Translate(RegistryHive.ClassesRoot, "CLSID").Should().BeNull();
    }

    [Fact]
    public void Offline_HKLM_SOFTWARE_with_subpath_is_redirected_under_loaded_key()
    {
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = "SecAudit_Offline_abc12345_SOFTWARE",
        });

        reader.Translate(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
              .Should().Be(@"SecAudit_Offline_abc12345_SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    }

    [Fact]
    public void Offline_HKLM_SOFTWARE_root_has_no_trailing_separator()
    {
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = "SW_LOADED",
        });

        reader.Translate(RegistryHive.LocalMachine, "SOFTWARE")
              .Should().Be("SW_LOADED", because: "root hive reference must not emit a dangling backslash");
    }

    [Fact]
    public void Offline_HKLM_SYSTEM_with_subpath_is_redirected_under_loaded_key()
    {
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSystemHiveKey = "SecAudit_Offline_abc12345_SYSTEM",
        });

        reader.Translate(RegistryHive.LocalMachine,
                         @"SYSTEM\CurrentControlSet\Control\SecureBoot\State")
              .Should().Be(
                 @"SecAudit_Offline_abc12345_SYSTEM\CurrentControlSet\Control\SecureBoot\State");
    }

    [Theory]
    [InlineData(@"software\microsoft\windows", "SW", @"SW\microsoft\windows")]
    [InlineData(@"Software\Microsoft\Windows", "SW", @"SW\Microsoft\Windows")]
    [InlineData("SOFTWARE", "SW", "SW")]
    [InlineData(@"system\currentcontrolset\services\lanmanserver", "SY",
                @"SY\currentcontrolset\services\lanmanserver")]
    public void Offline_match_is_case_insensitive_and_preserves_tail_casing(
        string input, string loadedKey, string expected)
    {
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = loadedKey,
            LoadedSystemHiveKey = loadedKey,
        });

        reader.Translate(RegistryHive.LocalMachine, input).Should().Be(expected);
    }

    [Fact]
    public void Offline_forward_slash_separator_is_accepted_and_normalized()
    {
        // StartsWithSegment accepts either '\\' or '/' as the separator — callers occasionally
        // pass a unix-style path (e.g. copy-paste from a registry URL).
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = "SW",
        });

        reader.Translate(RegistryHive.LocalMachine, "SOFTWARE/Microsoft/Windows")
              .Should().Be(@"SW\Microsoft/Windows",
                  because: "only the SEGMENT separator is consumed — the rest is opaque tail");
    }

    [Theory]
    [InlineData("SOFTWAREX")]                     // longer name, no separator → not a match
    [InlineData("SOFTWAREX\\Microsoft")]          // "SOFTWAREX" ≠ "SOFTWARE"
    [InlineData("SYS")]                           // prefix shorter than any segment
    [InlineData("")]                              // empty path
    [InlineData("FooBar\\Baz")]                   // unrelated root
    public void Offline_unrecognized_roots_return_null(string subKey)
    {
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = "SW",
            LoadedSystemHiveKey = "SY",
        });

        reader.Translate(RegistryHive.LocalMachine, subKey).Should().BeNull();
    }

    [Fact]
    public void Offline_SOFTWARE_without_loaded_key_returns_null()
    {
        // Target reports IsLive=false but never loaded the SOFTWARE hive — e.g. mount failed
        // halfway. We must NOT fall through to the live HKLM. Returning null forces callers
        // to treat the read as "no data", which is the safer default.
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = null,
            LoadedSystemHiveKey = "SY",
        });

        reader.Translate(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft").Should().BeNull();
    }

    [Fact]
    public void Offline_SYSTEM_without_loaded_key_returns_null()
    {
        var reader = new RegistryReader(new FakeOfflineTarget
        {
            IsLive = false,
            LoadedSoftwareHiveKey = "SW",
            LoadedSystemHiveKey = null,
        });

        reader.Translate(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet").Should().BeNull();
    }

    // ---------------------------------------------------------------------------------------
    //  Low-level helper — StartsWithSegment.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("SOFTWARE", "SOFTWARE", true, "")]
    [InlineData("software", "SOFTWARE", true, "")]
    [InlineData(@"SOFTWARE\Foo", "SOFTWARE", true, "Foo")]
    [InlineData("SOFTWARE/Foo", "SOFTWARE", true, "Foo")]
    [InlineData(@"SOFTWARE\Foo\Bar", "SOFTWARE", true, @"Foo\Bar")]
    [InlineData("SOFTWAREX", "SOFTWARE", false, "")]
    [InlineData("SOFT", "SOFTWARE", false, "")]
    [InlineData("", "SOFTWARE", false, "")]
    [InlineData("SOFTWARE-Foo", "SOFTWARE", false, "")] // '-' is NOT a separator
    public void StartsWithSegment_contract(string path, string segment, bool expectedMatch,
                                           string expectedRest)
    {
        var matched = RegistryReader.StartsWithSegment(path, segment, out var rest);

        matched.Should().Be(expectedMatch);
        rest.Should().Be(expectedRest);
    }
}
