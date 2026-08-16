using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class CoordinatorSecurityBoundaryTests
{
    [Fact]
    public void DumpInspection_WithNullTargetFailsClosedForProtectedAlias()
    {
        using var directory = new TestDirectory();
        using var coordinator = new PCCrashDiagnosticCoordinator(
            directory.Path,
            static (_, _) => Task.CompletedTask,
            elevatedHelperClient: null,
            protectedEvidenceHelper: null,
            helperRequestStore: null,
            isBf6RunningFailClosed: static () => false,
            protectedDumpPathValidator: null,
            isProtectedProcessRunning: processName =>
                processName.Equals("EAAntiCheat.GameService", StringComparison.OrdinalIgnoreCase));

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            coordinator.InspectSelectedDump(
                Path.Combine(directory.Path, "not-read.dmp"),
                DumpKind.WindowsMinidump,
                "Synthetic dump"));

        Assert.Contains("EA AntiCheat", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DumpInventory_DiscardsInspectedCandidatesWhenProtectedTargetStartsMidEnumeration()
    {
        using var directory = new TestDirectory();
        DateTimeOffset nowUtc = DateTimeOffset.UtcNow;
        CreateMiniDump(directory.Path, "candidate.dmp", nowUtc);
        var collector = new DumpInventoryCollector(
            new SafeDumpInspector(),
            [new DumpSearchRoot(
                "Synthetic dump root",
                directory.Path,
                DumpKind.WindowsMinidump,
                MaximumDepth: 0)]);
        int boundaryChecks = 0;
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(
            directory.Path,
            collector,
            () => Interlocked.Increment(ref boundaryChecks) >= 8);

        DumpInventory inventory = await coordinator.CollectDumpInventoryForReportAsync(
            nowUtc.AddMinutes(-1),
            nowUtc.AddMinutes(1),
            targetProfile: null,
            CancellationToken.None);

        Assert.Empty(inventory.Candidates);
        CollectionStatus status = Assert.Single(inventory.Statuses);
        Assert.Equal("Dump inventory", status.Source);
        Assert.Equal(CollectionState.Unavailable, status.State);
        Assert.Contains("partial results were discarded", status.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.True(boundaryChecks >= 8);
    }

    [Fact]
    public async Task DumpInventory_DiscardsCandidatesWhenProtectedTargetStartsDuringMetadataInspection()
    {
        using var directory = new TestDirectory();
        DateTimeOffset nowUtc = DateTimeOffset.UtcNow;
        CreateMiniDump(directory.Path, "candidate.dmp", nowUtc);
        var collector = new DumpInventoryCollector(
            new SafeDumpInspector(),
            [new DumpSearchRoot(
                "Synthetic dump root",
                directory.Path,
                DumpKind.WindowsMinidump,
                MaximumDepth: 0)]);
        int boundaryChecks = 0;
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(
            directory.Path,
            collector,
            () => Interlocked.Increment(ref boundaryChecks) >= 12);

        DumpInventory inventory = await coordinator.CollectDumpInventoryForReportAsync(
            nowUtc.AddMinutes(-1),
            nowUtc.AddMinutes(1),
            targetProfile: null,
            CancellationToken.None);

        Assert.Empty(inventory.Candidates);
        CollectionStatus status = Assert.Single(inventory.Statuses);
        Assert.Equal(CollectionState.Unavailable, status.State);
        Assert.Contains("partial results were discarded", status.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.True(boundaryChecks >= 12);
    }

    [Fact]
    public void CustomDataRoot_DoesNotControlElevatedHelperIpcOrStagingPaths()
    {
        using var directory = new TestDirectory();
        string customDataRoot = Path.Combine(directory.Path, "custom-report-data");

        using var coordinator = new PCCrashDiagnosticCoordinator(customDataRoot);

        Assert.Equal(
            Path.GetFullPath(ElevatedHelperRequestStore.DefaultRoot),
            coordinator.HelperRequestRoot,
            ignoreCase: true);
        Assert.Equal(
            Path.GetFullPath(ProtectedEvidenceHelper.DefaultStagingRoot()),
            coordinator.ProtectedStagingRoot,
            ignoreCase: true);
        Assert.False(IsWithin(customDataRoot, coordinator.HelperRequestRoot));
        Assert.False(IsWithin(customDataRoot, coordinator.ProtectedStagingRoot));
    }

    private static PCCrashDiagnosticCoordinator CreateCoordinator(
        string root,
        DumpInventoryCollector collector,
        Func<bool> isProtectedTargetRunning)
    {
        string helperRoot = Path.Combine(root, "HelperRequests");
        string stagingRoot = Path.Combine(root, "ProtectedStaging");
        var protectedRoots = new ProtectedEvidenceRoots(
            Path.Combine(root, "Windows", "MEMORY.DMP"),
            Path.Combine(root, "Windows", "Minidump"),
            Path.Combine(root, "Windows", "LiveKernelReports"));
        var helper = new ProtectedEvidenceHelper(
            stagingRoot,
            protectedRoots,
            _ => long.MaxValue,
            () => false);
        return new PCCrashDiagnosticCoordinator(
            root,
            (_, _) => Task.CompletedTask,
            elevatedHelperClient: null,
            protectedEvidenceHelper: helper,
            helperRequestStore: new ElevatedHelperRequestStore(helperRoot),
            isBf6RunningFailClosed: isProtectedTargetRunning,
            protectedDumpPathValidator: _ => true,
            dumpInventoryCollector: collector);
    }

    private static void CreateMiniDump(string root, string name, DateTimeOffset lastWriteUtc)
    {
        string path = Path.Combine(root, name);
        byte[] bytes = new byte[32];
        "MDMP"u8.CopyTo(bytes);
        File.WriteAllBytes(path, bytes);
        File.SetLastWriteTimeUtc(path, lastWriteUtc.UtcDateTime);
    }

    private static bool IsWithin(string root, string candidate)
    {
        string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string fullCandidate = Path.GetFullPath(candidate);
        return fullCandidate.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
    }
}
