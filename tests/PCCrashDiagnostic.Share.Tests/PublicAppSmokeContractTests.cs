using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;
using PCCrashDiagnostic.Core;
using PCCrashDiagnostic.Contracts;

namespace PCCrashDiagnostic.Share.Tests;

public sealed class PublicAppSmokeContractTests
{
    [Fact]
    public void SmokeContractWritesExpectedShareReadOnlyMarkerWithoutPrivilege()
    {
        using var directory = new BF6CrashDiagnostic.Tests.TestDirectory();

        int exitCode = ShareReadOnlySmokeContract.Run(["--smoke-test", "--data-root", directory.Path]);

        Assert.Equal(0, exitCode);
        string markerPath = Path.Combine(directory.Path, "smoke-test.json");
        using JsonDocument marker = JsonDocument.Parse(File.ReadAllBytes(markerPath));
        JsonElement root = marker.RootElement;
        Assert.Equal("passed", root.GetProperty("Status").GetString());
        Assert.Equal(BuildProfile.Version, root.GetProperty("ToolVersion").GetString());
        Assert.Equal(ProductFeatureProfile.ShareReadOnly.ToString(), root.GetProperty("FeatureProfile").GetString());
        Assert.False(root.GetProperty("PrivilegedOperationsEnabled").GetBoolean());
        Assert.Equal("10.0.11", root.GetProperty("RuntimeVersion").GetString());
    }

    [Fact]
    public void SmokeContractRejectsInvalidArgumentsAndExistingMarker()
    {
        using var directory = new BF6CrashDiagnostic.Tests.TestDirectory();

        Assert.Equal(2, ShareReadOnlySmokeContract.Run(["--smoke-test", directory.Path]));
        Assert.False(File.Exists(Path.Combine(directory.Path, "smoke-test.json")));

        string markerPath = Path.Combine(directory.Path, "smoke-test.json");
        File.WriteAllText(markerPath, "do-not-overwrite");
        Assert.Equal(3, ShareReadOnlySmokeContract.Run(["--smoke-test", "--data-root", directory.Path]));
        Assert.Equal("do-not-overwrite", File.ReadAllText(markerPath));
    }

    [Fact]
    public void PublicAppAssemblyHasNoPrivilegedProjectReference()
    {
        string[] references = typeof(PCCrashDiagnostic.App.App).Assembly
            .GetReferencedAssemblies()
            .Select(reference => reference.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(references, name =>
            name.Contains("Privileged", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("ElevatedHelper", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("PCCrashDiagnostic.Core", references, StringComparer.Ordinal);
        Assert.Contains("PCCrashDiagnostic.LocalTools", references, StringComparer.Ordinal);
    }

    [Fact]
    public void BattlefieldExecutableUsesProtectedBuiltInProfileInEveryPickerFlow()
    {
        TargetProfile target = PCCrashDiagnostic.App.MainWindow.CreateTargetProfile("BF6");

        Assert.Same(TargetProfile.Battlefield6, target);
        Assert.Contains("EAAntiCheat", target.RelatedProcessNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("Javelin", target.RelatedProcessNames, StringComparer.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(IncidentEvidenceOrigin.WindowsEventLog, "Windows Event Log")]
    [InlineData(IncidentEvidenceOrigin.ReliabilityMonitor, "Reliability Monitor")]
    [InlineData(IncidentEvidenceOrigin.MonitorObservation, "app monitor")]
    [InlineData(IncidentEvidenceOrigin.ManualTime, "manual time")]
    public void IncidentOriginUsesControlledUserFacingLabels(IncidentEvidenceOrigin origin, string expected)
    {
        Assert.Equal(expected, PCCrashDiagnostic.App.MainWindow.IncidentOriginLabel(origin));
    }
}
