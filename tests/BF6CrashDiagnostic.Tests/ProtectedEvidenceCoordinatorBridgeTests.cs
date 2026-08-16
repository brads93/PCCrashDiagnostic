using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class ProtectedEvidenceCoordinatorBridgeTests
{
    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task RetryProtectedSource_BindsMergesDeduplicatesAndRefreshesReport()
    {
        using var directory = new TestDirectory();
        DateTimeOffset time = DateTimeOffset.UtcNow.AddMinutes(-5);
        DiagnosticEvent duplicate = SystemEvent(time, "Microsoft-Windows-Kernel-Power", 41, "Windows restarted.");
        DiagnosticEvent added = SystemEvent(time.AddSeconds(1), "EventLog", 6008, "The prior shutdown was unexpected.");
        DiagnosticOperationResultV3 report = CreateDeniedReport(
            directory.Path,
            ProtectedEvidenceSource.SystemEventLog,
            [duplicate]);
        var client = new StubHelperClient((request, _, _) => Task.FromResult(
            new ProtectedEvidenceResponse(
                true,
                "evidence returned",
                EvidenceBatch: new ProtectedEvidenceBatch(
                    1,
                    request.ReportSessionId!,
                    request.ReportSha256!,
                    request.Source!.Value,
                    request.WindowStartUtc!.Value,
                    request.WindowEndUtc!.Value,
                    [duplicate, added],
                    [],
                    [new CollectionStatus("Windows Event Log/System", CollectionState.Available, "Read two records.")],
                    false))));
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, client);

        DiagnosticOperationResultV3 updated = await coordinator.RetryProtectedEvidenceSourceAsync(
            report,
            ProtectedEvidenceSource.SystemEventLog,
            helperTimeout: TimeSpan.FromSeconds(30),
            cancellationToken: CancellationToken.None);

        Assert.Equal(2, updated.Package.Report.Events.Count);
        SourceCoverage coverage = Assert.Single(updated.Package.Report.SourceCoverage,
            item => item.Source == "Windows Event Log/System");
        Assert.Equal(CollectionState.Available, coverage.State);
        Assert.Equal(2, coverage.RecordCount);
        Assert.DoesNotContain(updated.CollectionFailures,
            item => item.StartsWith("Windows Event Log/System:", StringComparison.OrdinalIgnoreCase));
        Assert.True(File.Exists(updated.Package.ZipPath));
        Assert.Equal(ProtectedEvidenceOperation.RetryNamedSource, client.LastRequest!.Operation);
        Assert.Equal(ProtectedEvidenceSource.SystemEventLog, client.LastRequest.Source);
        Assert.Equal(report.Package.Report.SessionId, client.LastRequest.ReportSessionId);
        Assert.Equal(report.Package.Sha256, client.LastRequest.ReportSha256);
        Assert.Equal(report.Package.Report.StartUtc, client.LastRequest.WindowStartUtc);
        Assert.Equal(report.Package.Report.EndUtc, client.LastRequest.WindowEndUtc);
        Assert.Null(client.LastRequest.DumpPath);
        Assert.Null(client.LastRequest.ExpectedSizeBytes);
        Assert.False(client.LastRequest.PrivacyConfirmed);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task RetryProtectedSource_FailsClosedWhileBattlefield6IsRunning()
    {
        using var directory = new TestDirectory();
        var client = new StubHelperClient((_, _, _) => throw new InvalidOperationException("must not launch"));
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(
            directory.Path,
            client,
            isBf6Running: () => true);

        DiagnosticOperationResultV3 report = CreateDeniedReport(
            directory.Path,
            ProtectedEvidenceSource.WindowsMemoryDump,
            []);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.RetryProtectedEvidenceSourceAsync(
                report,
                ProtectedEvidenceSource.WindowsMemoryDump,
                helperTimeout: TimeSpan.FromSeconds(30),
                cancellationToken: CancellationToken.None));

        Assert.Contains("Battlefield 6", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, client.CallCount);
    }

    [Fact]
    public async Task RetryProtectedSource_RejectsReportMismatchedHelperResponse()
    {
        using var directory = new TestDirectory();
        DiagnosticOperationResultV3 report = CreateDeniedReport(
            directory.Path,
            ProtectedEvidenceSource.SystemEventLog,
            []);
        var client = new StubHelperClient((request, _, _) => Task.FromResult(
            SuccessfulEventResponse(request) with
            {
                EvidenceBatch = SuccessfulEventResponse(request).EvidenceBatch! with
                {
                    ReportSessionId = "substituted-session"
                }
            }));
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, client);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            coordinator.RetryProtectedEvidenceSourceAsync(
                report,
                ProtectedEvidenceSource.SystemEventLog,
                helperTimeout: TimeSpan.FromSeconds(30),
                cancellationToken: CancellationToken.None));

        Assert.Equal(1, client.CallCount);
        Assert.False(Directory.Exists(Path.Combine(directory.Path, "Reports")) &&
                     Directory.EnumerateFiles(Path.Combine(directory.Path, "Reports"), "*.zip").Any());
    }

    [Fact]
    public async Task RetryProtectedSource_RejectsNonAllowlistedEventFromHelper()
    {
        using var directory = new TestDirectory();
        DiagnosticOperationResultV3 report = CreateDeniedReport(
            directory.Path,
            ProtectedEvidenceSource.SystemEventLog,
            []);
        var client = new StubHelperClient((request, _, _) =>
        {
            DiagnosticEvent unexpected = SystemEvent(
                request.WindowStartUtc!.Value.AddSeconds(1),
                "Unexpected-Provider",
                999,
                "not allowlisted");
            ProtectedEvidenceResponse response = SuccessfulEventResponse(request);
            return Task.FromResult(response with
            {
                EvidenceBatch = response.EvidenceBatch! with { Events = [unexpected] }
            });
        });
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, client);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            coordinator.RetryProtectedEvidenceSourceAsync(
                report,
                ProtectedEvidenceSource.SystemEventLog,
                helperTimeout: TimeSpan.FromSeconds(30),
                cancellationToken: CancellationToken.None));
    }

    [Fact]
    public async Task RetryProtectedSource_RejectsOversizedEventBatch()
    {
        using var directory = new TestDirectory();
        DiagnosticOperationResultV3 report = CreateDeniedReport(
            directory.Path,
            ProtectedEvidenceSource.SystemEventLog,
            []);
        var client = new StubHelperClient((request, _, _) =>
        {
            DiagnosticEvent[] tooMany = Enumerable.Range(0, ProtectedEvidenceHelper.MaximumRetryEvents + 1)
                .Select(index => SystemEvent(
                    request.WindowStartUtc!.Value.AddSeconds(index),
                    "EventLog",
                    6008,
                    $"unexpected restart {index}"))
                .ToArray();
            ProtectedEvidenceResponse response = SuccessfulEventResponse(request);
            return Task.FromResult(response with
            {
                EvidenceBatch = response.EvidenceBatch! with { Events = tooMany }
            });
        });
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, client);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            coordinator.RetryProtectedEvidenceSourceAsync(
                report,
                ProtectedEvidenceSource.SystemEventLog,
                helperTimeout: TimeSpan.FromSeconds(30),
                cancellationToken: CancellationToken.None));
    }

    [Fact]
    public async Task RetryProtectedSource_RejectsSourceThatWasNotDeniedBeforeUac()
    {
        using var directory = new TestDirectory();
        DateTimeOffset time = DateTimeOffset.UtcNow.AddMinutes(-5);
        var candidate = new DumpCandidate(
            DumpKind.WindowsMinidump,
            "Dump inventory/Windows minidumps",
            "placeholder.dmp",
            "%SystemRoot%\\Minidump\\placeholder.dmp",
            4096,
            time,
            DumpFormat.MiniDump,
            DumpInspectionState.Recognized,
            32,
            true,
            "Test dump.",
            Path.Combine(directory.Path, "placeholder.dmp"));
        DiagnosticOperationResultV3 report = CreateReport(directory.Path, candidate);
        var client = new StubHelperClient((_, _, _) => throw new InvalidOperationException("must not launch"));
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, client);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.RetryProtectedEvidenceSourceAsync(
                report,
                ProtectedEvidenceSource.SystemEventLog,
                helperTimeout: TimeSpan.FromSeconds(30),
                cancellationToken: CancellationToken.None));

        Assert.Equal(0, client.CallCount);
    }

    [Fact]
    public async Task RetryProtectedDumpSource_UpgradesMatchingDeniedCandidateWithoutDuplicate()
    {
        using var directory = new TestDirectory();
        string dumpRoot = Path.Combine(directory.Path, "Windows", "Minidump");
        Directory.CreateDirectory(dumpRoot);
        string path = Path.Combine(dumpRoot, "matching.dmp");
        byte[] bytes = new byte[4096];
        "MDMP"u8.CopyTo(bytes);
        await File.WriteAllBytesAsync(path, bytes, CancellationToken.None);
        var info = new FileInfo(path);
        var denied = new DumpCandidate(
            DumpKind.WindowsMinidump,
            "Dump inventory/Windows minidumps",
            info.Name,
            "%SystemRoot%\\Minidump\\matching.dmp",
            info.Length,
            info.LastWriteTimeUtc,
            DumpFormat.Unknown,
            DumpInspectionState.Denied,
            0,
            false,
            "Windows denied content access.",
            path);
        DiagnosticOperationResultV3 baseReport = CreateReport(directory.Path, denied);
        IncidentFingerprint fingerprint = baseReport.Package.Report.IncidentFingerprint!;
        var incident = new IncidentCandidate(
            fingerprint,
            info.LastWriteTimeUtc,
            IncidentKind.Bugcheck,
            "Blue screen",
            "Windows",
            1001,
            null,
            "0x00000000",
            info.Name,
            500,
            1,
            info.LastWriteTimeUtc,
            info.LastWriteTimeUtc);
        var selection = new IncidentSelection(
            incident,
            info.LastWriteTimeUtc.AddMinutes(-1),
            info.LastWriteTimeUtc.AddMinutes(1),
            IncidentSelectionMethod.UserSelected);
        var deniedStatus = new CollectionStatus(
            "Dump inventory/Windows minidumps",
            CollectionState.Denied,
            "Windows denied access.");
        DiagnosticReportV3 reportModel = baseReport.Package.Report with
        {
            StartUtc = selection.WindowStartUtc,
            EndUtc = selection.WindowEndUtc,
            IncidentSelection = selection,
            CollectionStatus = [deniedStatus],
            SourceCoverage = [new SourceCoverage(deniedStatus.Source, deniedStatus.State, 0, deniedStatus.Detail)],
            DumpInventory = new DumpInventory([denied], [deniedStatus])
        };
        DiagnosticOperationResultV3 report = baseReport with
        {
            Package = baseReport.Package with { Report = reportModel },
            DumpChoices = [denied]
        };
        var client = new StubHelperClient((request, _, _) => Task.FromResult(
            new ProtectedEvidenceResponse(
                true,
                "dump metadata returned",
                EvidenceBatch: new ProtectedEvidenceBatch(
                    1,
                    request.ReportSessionId!,
                    request.ReportSha256!,
                    request.Source!.Value,
                    request.WindowStartUtc!.Value,
                    request.WindowEndUtc!.Value,
                    [],
                    [new ProtectedDumpEvidence(
                        DumpKind.WindowsMinidump,
                        denied.Source,
                        denied.Name,
                        denied.RedactedPath,
                        denied.SizeBytes,
                        denied.LastWriteUtc,
                        DumpFormat.MiniDump,
                        DumpInspectionState.Recognized,
                        32,
                        true,
                        "Recognized a Windows dump signature using a bounded header read.",
                        path)],
                    [new CollectionStatus(denied.Source, CollectionState.Available, "Inspected one dump candidate.")],
                    false))));
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, client);

        DiagnosticOperationResultV3 updated = await coordinator.RetryProtectedEvidenceSourceAsync(
            report,
            ProtectedEvidenceSource.WindowsMinidumps,
            helperTimeout: TimeSpan.FromSeconds(30),
            cancellationToken: CancellationToken.None);

        DumpCandidate upgraded = Assert.Single(updated.Package.Report.DumpInventory.Candidates);
        Assert.Equal(DumpInspectionState.Recognized, upgraded.InspectionState);
        Assert.Equal(DumpFormat.MiniDump, upgraded.Format);
        Assert.Single(updated.DumpChoices);
        Assert.DoesNotContain(updated.CollectionFailures,
            item => item.StartsWith(denied.Source + ":", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task InspectProtectedDump_StagesValidReportBoundDumpThenAlwaysDeletesStaging()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;

        ProtectedDumpOperationResult<ProtectedDumpInspection> result =
            await coordinator.InspectSelectedProtectedDumpAsync(
                setup.Report,
                setup.Candidate,
                Confirmed(),
                TimeSpan.FromSeconds(30),
                CancellationToken.None);

        Assert.True(result.Succeeded, result.Message);
        ProtectedDumpInspection inspection = Assert.IsType<ProtectedDumpInspection>(result.Value);
        Assert.Equal(DumpFormat.MiniDump, inspection.Format);
        Assert.Equal(DumpInspectionState.Recognized, inspection.InspectionState);
        Assert.Equal(setup.Candidate.SizeBytes, inspection.SizeBytes);
        Assert.Equal(64, inspection.Sha256.Length);
        Assert.NotNull(inspection.Metadata);
        Assert.Equal(ProtectedEvidenceOperation.CopySelectedDump, setup.Client.LastRequest!.Operation);
        Assert.Equal(setup.Candidate.OriginalPath, setup.Client.LastRequest.DumpPath);
        Assert.Equal(setup.Candidate.SizeBytes, setup.Client.LastRequest.ExpectedSizeBytes);
        Assert.True(setup.Client.LastRequest.PrivacyConfirmed);
        Assert.True(setup.Client.LastRequest.SizeConfirmed);
        Assert.True(setup.Client.LastRequest.FreeSpaceConfirmed);
        Assert.NotNull(setup.Client.LastResponse?.StagedDump);
        Assert.False(File.Exists(setup.Client.LastResponse!.StagedDump!.Path));
        Assert.Empty(Directory.Exists(setup.StagingRoot)
            ? Directory.EnumerateDirectories(setup.StagingRoot)
            : []);
    }

    [Fact]
    public async Task InspectProtectedDump_AllowsReportBoundAccessDeniedCandidateWithRecordedMetadata()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;
        DumpCandidate denied = setup.Candidate with
        {
            Format = DumpFormat.Unknown,
            InspectionState = DumpInspectionState.Denied,
            HeaderBytesRead = 0,
            SizePlausible = false,
            Detail = "Windows denied content access; size and timestamp were recorded."
        };
        DiagnosticOperationResultV3 report = CreateReport(directory.Path, denied);

        ProtectedDumpOperationResult<ProtectedDumpInspection> result =
            await coordinator.InspectSelectedProtectedDumpAsync(
                report,
                denied,
                Confirmed(),
                TimeSpan.FromSeconds(30),
                CancellationToken.None);

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(DumpFormat.MiniDump, result.Value!.Format);
        Assert.False(File.Exists(setup.Client.LastResponse!.StagedDump!.Path));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectProtectedDump_RequiresAllUiConfirmationsBeforeUac()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;

        ProtectedDumpOperationResult<ProtectedDumpInspection> result =
            await coordinator.InspectSelectedProtectedDumpAsync(
                setup.Report,
                setup.Candidate,
                Confirmed() with { FreeSpaceConfirmed = false },
                TimeSpan.FromSeconds(30),
                CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("confirmation", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, setup.Client.CallCount);
    }

    [Fact]
    public async Task InspectProtectedDump_RejectsCandidateOutsideReportContext()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;
        DumpCandidate substituted = setup.Candidate with { Source = "untrusted selection" };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.InspectSelectedProtectedDumpAsync(
                setup.Report,
                substituted,
                Confirmed(),
                TimeSpan.FromSeconds(30),
                CancellationToken.None));

        Assert.Equal(0, setup.Client.CallCount);
    }

    [Fact]
    public async Task InspectProtectedDump_RejectsRecordedIdentityDriftBeforeUac()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;
        await File.AppendAllTextAsync(setup.Candidate.OriginalPath!, "changed", CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(() =>
            coordinator.InspectSelectedProtectedDumpAsync(
                setup.Report,
                setup.Candidate,
                Confirmed(),
                TimeSpan.FromSeconds(30),
                CancellationToken.None));

        Assert.Equal(0, setup.Client.CallCount);
    }

    [Fact]
    public async Task PackageProtectedDump_UsesStagingAndDeletesItAfterArchiveCreation()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;

        ProtectedDumpOperationResult<string> result = await coordinator.PackageSelectedProtectedDumpAsync(
            setup.Report,
            setup.Candidate,
            Confirmed(),
            helperTimeout: TimeSpan.FromSeconds(30),
            cancellationToken: CancellationToken.None);

        Assert.True(result.Succeeded, result.Message);
        Assert.NotNull(result.Value);
        Assert.True(File.Exists(result.Value));
        Assert.True(File.Exists(result.Value + ".sha256"));
        Assert.False(File.Exists(setup.Client.LastResponse!.StagedDump!.Path));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task PackageProtectedDump_CancellationDeletesStagingAndPublishesNothing()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;
        using var cancellation = new CancellationTokenSource();
        var progress = new InlineProgress<double>(_ => cancellation.Cancel());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            coordinator.PackageSelectedProtectedDumpAsync(
                setup.Report,
                setup.Candidate,
                Confirmed(),
                progress,
                TimeSpan.FromSeconds(30),
                cancellation.Token));

        Assert.False(File.Exists(setup.Client.LastResponse!.StagedDump!.Path));
        string reports = Path.Combine(directory.Path, "Reports");
        Assert.False(Directory.Exists(reports) && Directory.EnumerateFiles(reports, "*.zip").Any());
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task HashMismatch_FailsAndStillDeletesStaging()
    {
        using var directory = new TestDirectory();
        TestSetup setup = await CreateDirectSetupAsync(directory.Path, corruptReturnedHash: true);
        using PCCrashDiagnosticCoordinator coordinator = setup.Coordinator;

        ProtectedDumpOperationResult<ProtectedDumpInspection> result =
            await coordinator.InspectSelectedProtectedDumpAsync(
                setup.Report,
                setup.Candidate,
                Confirmed(),
                TimeSpan.FromSeconds(30),
                CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("SHA-256", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(setup.Client.LastResponse!.StagedDump!.Path));
    }

    [Fact]
    public async Task Cleanup_RemovesOnlyValidatedStaleStagingAndRequestArtifacts()
    {
        using var directory = new TestDirectory();
        string stagingRoot = Path.Combine(directory.Path, "ProtectedStaging");
        string requestRoot = Path.Combine(directory.Path, "HelperRequests");
        var roots = new ProtectedEvidenceRoots(
            Path.Combine(directory.Path, "Windows", "MEMORY.DMP"),
            Path.Combine(directory.Path, "Windows", "Minidump"),
            Path.Combine(directory.Path, "Windows", "LiveKernelReports"));
        var helper = new ProtectedEvidenceHelper(stagingRoot, roots, _ => long.MaxValue, () => false);
        var store = new ElevatedHelperRequestStore(requestRoot);
        var client = new StubHelperClient((_, _, _) => throw new InvalidOperationException());
        using var coordinator = new PCCrashDiagnosticCoordinator(
            directory.Path,
            (_, _) => Task.CompletedTask,
            client,
            helper,
            store,
            () => false,
            _ => true);

        string stage = Path.Combine(stagingRoot, "stage-old");
        Directory.CreateDirectory(stage);
        string marker = Path.Combine(stage, ".pc-crash-diagnostic-staging");
        File.WriteAllText(marker, "old");
        File.SetCreationTimeUtc(marker, DateTime.UtcNow.AddHours(-25));
        ElevatedHelperTicket ticket = await store.CreateRequestAsync(
            new ProtectedEvidenceRequest(
                ProtectedEvidenceOperation.RetryNamedSource,
                ProtectedEvidenceSource.SystemEventLog,
                null,
                null,
                null,
                false,
                false,
                false),
            CancellationToken.None);
        File.SetCreationTimeUtc(ticket.RequestPath, DateTime.UtcNow.AddHours(-25));

        ProtectedEvidenceCleanupResult cleanup = coordinator.CleanupProtectedEvidenceArtifacts(DateTimeOffset.UtcNow);

        Assert.Equal(1, cleanup.StagingDirectoriesRemoved);
        Assert.Equal(1, cleanup.RequestArtifactsRemoved);
        Assert.False(Directory.Exists(stage));
        Assert.False(File.Exists(ticket.RequestPath));
    }

    private static async Task<TestSetup> CreateDirectSetupAsync(
        string root,
        bool corruptReturnedHash = false)
    {
        string windows = Path.Combine(root, "Windows");
        var roots = new ProtectedEvidenceRoots(
            Path.Combine(windows, "MEMORY.DMP"),
            Path.Combine(windows, "Minidump"),
            Path.Combine(windows, "LiveKernelReports"));
        Directory.CreateDirectory(roots.MinidumpRoot);
        string dumpPath = Path.Combine(roots.MinidumpRoot, "fixture.dmp");
        byte[] dump = new byte[4096];
        "MDMP"u8.CopyTo(dump);
        await File.WriteAllBytesAsync(dumpPath, dump, CancellationToken.None);
        var info = new FileInfo(dumpPath);
        var candidate = new DumpCandidate(
            DumpKind.WindowsMinidump,
            "Dump inventory/Windows minidumps",
            info.Name,
            "<Windows>\\Minidump\\fixture.dmp",
            info.Length,
            info.LastWriteTimeUtc,
            DumpFormat.MiniDump,
            DumpInspectionState.Recognized,
            32,
            true,
            "Recognized Windows minidump.",
            dumpPath);
        DiagnosticOperationResultV3 report = CreateReport(root, candidate);
        string staging = Path.Combine(root, "ProtectedStaging");
        string requests = Path.Combine(root, "HelperRequests");
        var helper = new ProtectedEvidenceHelper(staging, roots, _ => long.MaxValue, () => false);
        var client = new DirectHelperClient(helper, corruptReturnedHash);
        var coordinator = new PCCrashDiagnosticCoordinator(
            root,
            (_, _) => Task.CompletedTask,
            client,
            helper,
            new ElevatedHelperRequestStore(requests),
            () => false,
            path => ProtectedEvidenceHelper.TryClassifyApprovedDumpPath(path, roots, out _, out _));
        return new TestSetup(coordinator, client, report, candidate, staging);
    }

    private static PCCrashDiagnosticCoordinator CreateCoordinator(
        string root,
        IElevatedHelperClient client,
        Func<bool>? isBf6Running = null)
    {
        string staging = Path.Combine(root, "ProtectedStaging");
        var roots = new ProtectedEvidenceRoots(
            Path.Combine(root, "Windows", "MEMORY.DMP"),
            Path.Combine(root, "Windows", "Minidump"),
            Path.Combine(root, "Windows", "LiveKernelReports"));
        return new PCCrashDiagnosticCoordinator(
            root,
            (_, _) => Task.CompletedTask,
            client,
            new ProtectedEvidenceHelper(staging, roots, _ => long.MaxValue, () => false),
            new ElevatedHelperRequestStore(Path.Combine(root, "HelperRequests")),
            isBf6Running ?? (() => false),
            _ => true);
    }

    private static DiagnosticOperationResultV3 CreateDeniedReport(
        string root,
        ProtectedEvidenceSource source,
        IReadOnlyList<DiagnosticEvent> events)
    {
        DateTimeOffset time = events.Count == 0
            ? DateTimeOffset.UtcNow.AddMinutes(-5)
            : events.Min(item => item.TimeUtc);
        var candidate = new DumpCandidate(
            DumpKind.WindowsMinidump,
            "Dump inventory/Windows minidumps",
            "placeholder.dmp",
            "%SystemRoot%\\Minidump\\placeholder.dmp",
            4096,
            time,
            DumpFormat.MiniDump,
            DumpInspectionState.Recognized,
            32,
            true,
            "Test dump.",
            Path.Combine(root, "Windows", "Minidump", "placeholder.dmp"));
        DiagnosticOperationResultV3 result = CreateReport(root, candidate);
        string sourceName = source switch
        {
            ProtectedEvidenceSource.SystemEventLog => "Windows Event Log/System",
            ProtectedEvidenceSource.ApplicationEventLog => "Windows Event Log/Application",
            ProtectedEvidenceSource.WindowsMemoryDump => "Dump inventory/Windows memory dump",
            ProtectedEvidenceSource.WindowsMinidumps => "Dump inventory/Windows minidumps",
            ProtectedEvidenceSource.LiveKernelReports => "Dump inventory/LiveKernelReports",
            _ => throw new ArgumentOutOfRangeException(nameof(source))
        };
        var denied = new CollectionStatus(sourceName, CollectionState.Denied, "Windows denied access.");
        DiagnosticReportV3 report = result.Package.Report with
        {
            StartUtc = time.AddMinutes(-1),
            EndUtc = time.AddMinutes(1),
            Events = events,
            EventGroups = [],
            CollectionStatus = [denied],
            SourceCoverage = [new SourceCoverage(sourceName, CollectionState.Denied, 0, denied.Detail)],
            DumpInventory = result.Package.Report.DumpInventory with
            {
                Statuses = source is ProtectedEvidenceSource.WindowsMemoryDump or
                    ProtectedEvidenceSource.WindowsMinidumps or
                    ProtectedEvidenceSource.LiveKernelReports
                    ? [denied]
                    : []
            }
        };
        return result with { Package = result.Package with { Report = report } };
    }

    private static DiagnosticEvent SystemEvent(
        DateTimeOffset time,
        string provider,
        int eventId,
        string message) => new(
            time,
            "System",
            provider,
            null,
            eventId,
            1,
            "Critical",
            message,
            new Dictionary<string, string>());

    private static ProtectedEvidenceResponse SuccessfulEventResponse(
        ProtectedEvidenceRequest request) => new(
            true,
            "evidence returned",
            EvidenceBatch: new ProtectedEvidenceBatch(
                1,
                request.ReportSessionId!,
                request.ReportSha256!,
                request.Source!.Value,
                request.WindowStartUtc!.Value,
                request.WindowEndUtc!.Value,
                [],
                [],
                [new CollectionStatus(
                    "Windows Event Log/System",
                    CollectionState.Available,
                    "The source was read.")],
                false));

    private static DiagnosticOperationResultV3 CreateReport(string root, DumpCandidate candidate)
    {
        DateTimeOffset time = candidate.LastWriteUtc;
        IncidentFingerprint fingerprint = IncidentFingerprint.Create(
            IncidentKind.Bugcheck,
            time,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001);
        var correlation = new CrashCorrelation(
            fingerprint,
            null,
            candidate,
            CrashCorrelationBasis.TimestampProximity,
            TimeSpan.Zero,
            [candidate],
            "Test correlation.");
        var report = new DiagnosticReportV3(
            3,
            PCCrashDiagnosticCoordinator.ToolVersion,
            PCCrashDiagnosticCoordinator.ProductName,
            "test-session",
            DiagnosticMode.Retrospective,
            time.AddMinutes(-1),
            time.AddMinutes(1),
            "SelectedIncidentAnalyzed",
            null,
            null,
            null,
            null,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            null,
            new DumpInventory([candidate], []),
            null,
            correlation,
            null,
            fingerprint,
            "Test report.");
        var package = new ReportPackageV3(
            report,
            Path.Combine(root, "Sessions", "test-session"),
            Path.Combine(root, "Reports", "test.zip"),
            Path.Combine(root, "Reports", "test.zip.sha256"),
            new string('a', 64));
        return new DiagnosticOperationResultV3(package, [candidate], false, []);
    }

    private static ProtectedDumpCopyConfirmation Confirmed() => new(true, true, true);

    private sealed class StubHelperClient(
        Func<ProtectedEvidenceRequest, Func<bool>, CancellationToken, Task<ProtectedEvidenceResponse>> execute)
        : IElevatedHelperClient
    {
        public int CallCount { get; private set; }

        public ProtectedEvidenceRequest? LastRequest { get; private set; }

        public Task<ProtectedEvidenceResponse> ExecuteAsync(
            ProtectedEvidenceRequest request,
            Func<bool> isProtectedTargetRunning,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            LastRequest = request;
            return execute(request, isProtectedTargetRunning, cancellationToken);
        }
    }

    private sealed class DirectHelperClient(
        ProtectedEvidenceHelper helper,
        bool corruptReturnedHash) : IElevatedHelperClient
    {
        public int CallCount { get; private set; }

        public ProtectedEvidenceRequest? LastRequest { get; private set; }

        public ProtectedEvidenceResponse? LastResponse { get; private set; }

        public async Task<ProtectedEvidenceResponse> ExecuteAsync(
            ProtectedEvidenceRequest request,
            Func<bool> isProtectedTargetRunning,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            LastRequest = request;
            if (isProtectedTargetRunning())
            {
                return new ProtectedEvidenceResponse(false, "protected target running");
            }

            ProtectedEvidenceResponse response = await helper.ExecuteAsync(request, cancellationToken);
            if (corruptReturnedHash && response.StagedDump is not null)
            {
                response = response with
                {
                    StagedDump = response.StagedDump with { Sha256 = new string('0', 64) }
                };
            }

            LastResponse = response;
            return response;
        }
    }

    private sealed record TestSetup(
        PCCrashDiagnosticCoordinator Coordinator,
        DirectHelperClient Client,
        DiagnosticOperationResultV3 Report,
        DumpCandidate Candidate,
        string StagingRoot);

    private sealed class InlineProgress<T>(Action<T> action) : IProgress<T>
    {
        public void Report(T value) => action(value);
    }
}
