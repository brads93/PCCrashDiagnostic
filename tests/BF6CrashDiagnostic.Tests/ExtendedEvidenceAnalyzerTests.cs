using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class ExtendedEvidenceAnalyzerTests
{
    private readonly ExtendedEvidenceAnalyzer _analyzer = new();

    [Beta2Fact]
    public void Analyze_ReportsOnlyActionableExtendedEvidence()
    {
        DateTimeOffset incident = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);
        var quality = new DumpQuality(
            incident,
            DumpQualityClassification.Truncated,
            DumpFormat.MiniDump,
            DumpInternalQualityState.Invalid,
            true,
            false,
            false,
            DumpChkState.NotRequested,
            string.Empty,
            "The MDMP stream directory was outside the file.");
        var changes = new RecentChangeTimeline(
            incident,
            incident.AddDays(-7),
            incident,
            [new RecentSystemChange(incident.AddHours(-2), RecentChangeKind.DriverInstallation,
                "Display driver", "Published driver package", "Succeeded", string.Empty,
                TimeSpan.FromHours(2), true, true)],
            []);
        var storage = new StorageHealthSnapshot(
            incident,
            [new StorageHealthRecord(1, "Disk", "SSD", "NVMe", "1", "Warning", ["Degraded"],
                1_000, 35, 70, 5, 0, 1, 0, 0, 1, 1, 1, 100)],
            []);
        var verifier = new DriverVerifierState(
            incident,
            DriverVerifierStatusKind.Enabled,
            "0x9",
            ["example.sys"],
            "Windows reported Driver Verifier settings.");

        IReadOnlyList<DiagnosticFinding> findings = _analyzer.Analyze(quality, changes, storage, verifier);

        Assert.Equal(4, findings.Count);
        Assert.Contains(findings, item => item.Id == "dump-quality-truncated");
        Assert.Contains(findings, item => item.Id == "storage-health-warning");
        Assert.Contains(findings, item => item.Id == "driver-verifier-enabled");
        DiagnosticFinding recent = Assert.Single(findings, item => item.Id == "recent-system-changes");
        Assert.Contains("Timing alone", recent.DoesNotProve, StringComparison.Ordinal);
        Assert.All(findings, item => Assert.DoesNotContain("caused", item.Meaning, StringComparison.OrdinalIgnoreCase));
    }

    [Beta2Fact]
    public void Analyze_DoesNotTurnHealthyOrUnavailableSourcesIntoNegativeEvidence()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var quality = new DumpQuality(
            now,
            DumpQualityClassification.Valid,
            DumpFormat.MiniDump,
            DumpInternalQualityState.Valid,
            true,
            true,
            true,
            DumpChkState.Passed,
            "10.0",
            "Valid.");
        var changes = new RecentChangeTimeline(now, now.AddDays(-7), now, [], []);
        var storage = new StorageHealthSnapshot(
            now,
            [new StorageHealthRecord(1, "Disk", "SSD", "NVMe", "1", "Healthy", ["OK"],
                1_000, 35, 70, 5, 0, 0, 0, 0, 1, 1, 1, 100)],
            []);
        var verifier = new DriverVerifierState(
            now,
            DriverVerifierStatusKind.Unavailable,
            string.Empty,
            [],
            "Unavailable.");

        Assert.Empty(_analyzer.Analyze(quality, changes, storage, verifier));
    }
}
