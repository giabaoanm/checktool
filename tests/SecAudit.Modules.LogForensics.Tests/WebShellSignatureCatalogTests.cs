using FluentAssertions;
using SecAudit.Modules.LogForensics.WebIncident;
using Xunit;

namespace SecAudit.Modules.LogForensics.Tests;

/// <summary>
/// Verifies the webshell signature catalog matches representative shell snippets
/// without flagging legitimate-looking PHP. Test inputs are assembled at runtime
/// from harmless fragments to keep the compiled test DLL clean of full webshell
/// strings (avoids AV false-positive on the test assembly itself).
/// </summary>
public sealed class WebShellSignatureCatalogTests
{
    [Fact]
    public void China_Chopper_one_liner_is_detected()
    {
        var php = "<?php @e" + "val($_PO" + "ST['x']);?>";
        var hits = WebShellSignatureCatalog.Scan(php);

        hits.Should().Contain(h => h.Family == "China-Chopper");
    }

    [Fact]
    public void B374k_marker_is_detected()
    {
        var php = "<?php /* fake header */\n$GLOBALS['__b3" + "74k_v'] = '1.0';\n?>";
        var hits = WebShellSignatureCatalog.Scan(php);

        hits.Should().Contain(h => h.Family == "b374k");
    }

    [Fact]
    public void Weevely_requires_two_markers_to_match()
    {
        var single = "<?php function w" + "fe_decoder() { return; } ?>";
        WebShellSignatureCatalog.Scan(single).Should().NotContain(h => h.Family == "Weevely");

        var dual = single
            + "\n<?php $h = function($k, $s) { return $k; }; ?>";
        WebShellSignatureCatalog.Scan(dual).Should().Contain(h => h.Family == "Weevely");
    }

    [Fact]
    public void Generic_obfuscated_eval_chain_is_detected()
    {
        var php = "<?php e" + "val(base" + "64_decode($_GET['z'])); ?>";
        var hits = WebShellSignatureCatalog.Scan(php);

        hits.Should().Contain(h => h.Family == "GenericObfuscatedShell");
    }

    [Fact]
    public void Benign_php_with_normal_template_does_not_match()
    {
        var php = "<?php echo 'Hello'; $name = $_GET['name'] ?? 'guest'; ?>";
        WebShellSignatureCatalog.Scan(php).Should().BeEmpty();
    }

    [Fact]
    public void Benign_aspx_page_does_not_match()
    {
        var aspx = "<%@ Page Language=\"C#\" %>\n<html><body>Welcome</body></html>";
        WebShellSignatureCatalog.Scan(aspx).Should().BeEmpty();
    }

    [Fact]
    public void Empty_or_oversize_inputs_return_empty()
    {
        WebShellSignatureCatalog.Scan(string.Empty).Should().BeEmpty();
        var huge = new string('a', 6 * 1024 * 1024);
        WebShellSignatureCatalog.Scan(huge).Should().BeEmpty();
    }

    [Fact]
    public void Catalog_advertises_at_least_six_families()
    {
        WebShellSignatureCatalog.Signatures
            .Select(s => s.Family)
            .Distinct()
            .Count()
            .Should().BeGreaterThanOrEqualTo(6);
    }
}
