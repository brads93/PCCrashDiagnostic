using System.Reflection;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using PCCrashDiagnostic.Core;

namespace PCCrashDiagnostic.Share.Tests;

public sealed class DiagnosticCoverageTests
{
    [Fact]
    public void KernelEventTracingCoverageCountsCollectedEvent29()
    {
        var event29 = new DiagnosticEvent(
            DateTimeOffset.Parse("2026-08-02T04:42:18Z", System.Globalization.CultureInfo.InvariantCulture),
            KernelEventTracingCatalog.AdminLogName,
            KernelEventTracingCatalog.ProviderName,
            Guid.Parse("B675EC37-BDB6-4648-BC92-F3FDC74D3CA2"),
            29,
            2,
            "Error",
            "Error setting traits on Provider {8444a4fb-d8d3-4f38-84f8-89960a1ef12f}. Error: 0xC0000001",
            new Dictionary<string, string>());
        CollectionStatus[] statuses =
        [
            new(
                "Windows Event Log/Kernel-EventTracing Admin",
                CollectionState.Available,
                "Collected one bounded metadata record.")
        ];
        MethodInfo buildCoverage = typeof(ReadOnlyDiagnosticCoordinator).GetMethod(
            "BuildCoverage",
            BindingFlags.NonPublic | BindingFlags.Static) ??
            throw new MissingMethodException(nameof(ReadOnlyDiagnosticCoordinator), "BuildCoverage");

        object? value = buildCoverage.Invoke(
            null,
            [
                statuses,
                new[] { event29 },
                Array.Empty<ReliabilityRecord>(),
                Array.Empty<CrashArtifact>(),
                Array.Empty<DumpCandidate>(),
                null,
                null,
                null,
                null,
                null,
                null
            ]);

        SourceCoverage coverage = Assert.Single(Assert.IsType<SourceCoverage[]>(value));
        Assert.Equal("Windows Event Log/Kernel-EventTracing Admin", coverage.Source);
        Assert.Equal(1, coverage.RecordCount);
    }
}
