using System.Reflection;
using PCCrashDiagnostic.Contracts;

namespace PCCrashDiagnostic.Share.Tests;

public sealed class BuildProfileBoundaryTests
{
    [Fact]
    public void DefaultProfileIsShareReadOnlyAndHasNoPrivilegedCapabilities()
    {
        Assert.Equal(ProductFeatureProfile.ShareReadOnly, BuildProfile.Current.Profile);
        Assert.False(BuildProfile.Current.HasAnyPrivilegedCapability);
        Assert.True(BuildProfile.Current.SafeSummaryExport);
        Assert.True(BuildProfile.Current.TechnicalReportExport);
        Assert.True(BuildProfile.Current.RecycleBinDeletion);
        Assert.True(BuildProfile.Current.WinDbg);
        Assert.True(BuildProfile.Current.MicrosoftSymbolsAfterConsent);
    }

    [Fact]
    public void PublicCoreAssemblyContainsNoPrivilegedSurface()
    {
        Assembly core = typeof(BF6CrashDiagnostic.Core.Models.DiagnosticReportV3).Assembly;
        string[] forbidden =
        [
            "ElevatedHelper",
            "ProtectedEvidence",
            "CrashCapturePlan",
            "CrashCaptureReceipt",
            "WerLocalDump",
            "DumpPackager",
            "ApplyCrashCapture",
            "RestoreCrashCapture"
        ];

        string[] violations = core.GetTypes()
            .Select(type => type.FullName ?? type.Name)
            .Where(name => forbidden.Any(token => name.Contains(token, StringComparison.OrdinalIgnoreCase)))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Empty(violations);
    }
}
