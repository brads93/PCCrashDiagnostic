using System.IO;
using System.Text.Json;
using System.Collections.Concurrent;
using BF6CrashDiagnostic.App.Models;
using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.App.Services;

internal sealed class CoreDiagnosticService : IDiagnosticService, IDisposable
{
    private readonly string _dataRoot;
    private readonly PCCrashDiagnosticCoordinator _coordinator;
    private readonly bool _hasDumpChk;
    private readonly ConcurrentDictionary<string, IncidentCandidate> _incidentCandidates = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DiagnosticOperationResultV3> _coreResults = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, CrashCapturePlan> _crashCapturePlans = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CrashCaptureReceipt> _crashCaptureReceipts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, WerLocalDumpPlan> _werLocalDumpPlans = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, WerLocalDumpReceipt> _werLocalDumpReceipts = new(StringComparer.Ordinal);

    public bool SupportsCrashPreparation => true;

    public bool SupportsPerAppCrashCaptureApply => ReleaseStage.WerLocalDumpCaptureEnabled;

    public bool SupportsDumpCheck => _hasDumpChk;

    public CoreDiagnosticService(string dataRoot)
    {
        _dataRoot = dataRoot;
        _coordinator = new PCCrashDiagnosticCoordinator(dataRoot);
        _hasDumpChk = ReleaseStage.Beta2FeaturesEnabled &&
            _coordinator.DiscoverInstalledDumpCheckers().Count > 0;
        CleanupExpiredHelperArtifacts();
    }

    public Task<UiRestorableConfigurationReceipts> DiscoverRestorableConfigurationReceiptsAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RestorableConfigurationReceipts discovered = _coordinator.DiscoverRestorableConfigurationReceipts();

        _crashCaptureReceipts.Clear();
        if (discovered.CrashCaptureReceipt is { } crashReceipt)
        {
            _crashCaptureReceipts[crashReceipt.ReceiptId] = crashReceipt;
        }

        _werLocalDumpReceipts.Clear();
        foreach (WerLocalDumpReceipt receipt in discovered.WerLocalDumpReceipts)
        {
            _werLocalDumpReceipts[receipt.ReceiptId] = receipt;
        }

        UiRestorablePerAppCaptureReceipt[] perAppReceipts = discovered.WerLocalDumpReceipts
            .Select(receipt => new UiRestorablePerAppCaptureReceipt(
                receipt.ReceiptId,
                receipt.ExecutableName,
                receipt.TargetProfile?.DisplayName ?? receipt.ExecutableName,
                receipt.AppliedUtc,
                receipt.TargetProfile?.Id,
                receipt.TargetProfile?.ProcessNames ?? [Path.GetFileNameWithoutExtension(receipt.ExecutableName)]))
            .ToArray();
        return Task.FromResult(new UiRestorableConfigurationReceipts(
            discovered.CrashCaptureReceipt?.ReceiptId,
            perAppReceipts,
            discovered.Warnings));
    }

    private void CleanupExpiredHelperArtifacts()
    {
        try
        {
            _ = _coordinator.CleanupProtectedEvidenceArtifacts(DateTimeOffset.UtcNow);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Startup cleanup is best effort. Unsafe or inaccessible paths are left untouched.
        }
    }

    public async Task<UiCrashPreparationPreview> PreviewCrashCapturePreparationAsync(
        UiDiagnosticResult result,
        UiCrashPreparationPreset preset,
        bool includePerAppCapture,
        CancellationToken cancellationToken)
    {
        DiagnosticOperationResultV3 bound = GetBoundResult(result, "Crash-capture preparation");
        if (preset != UiCrashPreparationPreset.Recommended)
        {
            throw new ArgumentOutOfRangeException(nameof(preset));
        }

        CrashCapturePlan plan = await _coordinator
            .PreviewCrashCapturePreparationAsync(
                bound,
                CrashCapturePreset.AutomaticMemoryDump,
                includePerAppCapture,
                cancellationToken)
            .ConfigureAwait(false);
        _crashCapturePlans[plan.PlanId] = plan;
        return MapCrashCapturePreview(plan);
    }

    public async Task<UiCrashPreparationOutcome> PrepareCrashCaptureAsync(
        UiDiagnosticResult result,
        UiCrashPreparationPreview preview,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        DiagnosticOperationResultV3 bound = GetBoundResult(result, "Crash-capture preparation");
        if (!_crashCapturePlans.TryRemove(preview.PlanId, out CrashCapturePlan? plan))
        {
            throw new InvalidOperationException("The crash-capture preview expired. Review the current settings again.");
        }

        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        CrashCapturePreparationResult prepared = await _coordinator
            .PrepareCrashCaptureAsync(
                bound,
                plan,
                coreProgress,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (prepared.Receipt is { } receipt)
        {
            _crashCaptureReceipts[receipt.ReceiptId] = receipt;
        }
        if (prepared.WerReceipt is { } werReceipt)
        {
            _werLocalDumpReceipts[werReceipt.ReceiptId] = werReceipt;
        }

        return MapPreparationOutcome(
            prepared,
            result.EndUtc,
            prepared.Receipt?.ReceiptId,
            canRestore: prepared.Succeeded && prepared.Receipt is { Restored: false });
    }

    public async Task<UiCrashPreparationOutcome> RestoreCrashCaptureAsync(
        string receiptId,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        CrashCapturePreparationResult restored = await _coordinator
            .RestoreCrashCaptureAsync(
                receiptId,
                coreProgress,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (restored.Succeeded)
        {
            _crashCaptureReceipts.TryRemove(receiptId, out _);
        }

        return MapPreparationOutcome(restored, DateTimeOffset.UtcNow, null, canRestore: false);
    }

    public async Task<UiCrashPreparationPreview> PreviewPerAppCrashCaptureAsync(
        UiDiagnosticResult result,
        bool ordinaryAppConfirmed,
        CancellationToken cancellationToken)
    {
        DiagnosticOperationResultV3 bound = GetBoundResult(result, "Per-app crash capture");
        WerLocalDumpPlan plan = await _coordinator
            .PreviewWerLocalDumpPlanAsync(
                bound,
                executableName: null,
                ordinaryAppConfirmed: ordinaryAppConfirmed,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        _werLocalDumpPlans[plan.PlanId] = plan;
        return MapWerLocalDumpPreview(plan);
    }

    public async Task<UiCrashPreparationOutcome> EnablePerAppCrashCaptureAsync(
        UiDiagnosticResult result,
        UiCrashPreparationPreview preview,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        DiagnosticOperationResultV3 bound = GetBoundResult(result, "Per-app crash capture");
        if (!_werLocalDumpPlans.TryRemove(preview.PlanId, out WerLocalDumpPlan? plan))
        {
            throw new InvalidOperationException("The app-dump preview expired. Review the current settings again.");
        }

        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        CrashCapturePreparationResult prepared = await _coordinator
            .ApplyWerLocalDumpPlanAsync(
                bound,
                plan,
                coreProgress,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (prepared.WerReceipt is { } receipt)
        {
            _werLocalDumpReceipts[receipt.ReceiptId] = receipt;
        }

        return MapPreparationOutcome(
            prepared,
            result.EndUtc,
            prepared.WerReceipt?.ReceiptId,
            canRestore: prepared.Succeeded && prepared.WerReceipt is { Restored: false });
    }

    public async Task<UiCrashPreparationOutcome> RestorePerAppCrashCaptureAsync(
        string receiptId,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        CrashCapturePreparationResult restored = await _coordinator
            .RestoreWerLocalDumpAsync(
                receiptId,
                coreProgress,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (restored.Succeeded)
        {
            _werLocalDumpReceipts.TryRemove(receiptId, out _);
        }

        return MapPreparationOutcome(restored, DateTimeOffset.UtcNow, null, canRestore: false);
    }

    public async Task<UiSystemSnapshot> GetSystemSnapshotAsync(CancellationToken cancellationToken)
    {
        SystemSnapshotCollection collected = await _coordinator
            .GetSystemSnapshotAsync(cancellationToken)
            .ConfigureAwait(false);
        SystemSnapshot snapshot = collected.Snapshot;

        string memoryRate = string.Join(
            ", ",
            snapshot.MemoryModules
                .Select(module => module.ConfiguredSpeedMtPerSecond ?? module.SpeedMtPerSecond)
                .Where(rate => rate is > 0)
                .Distinct()
                .OrderBy(rate => rate)
                .Select(rate => $"{rate} MT/s"));
        if (string.IsNullOrWhiteSpace(memoryRate))
        {
            memoryRate = "Configured rate unavailable";
        }

        var facts = new List<UiSystemFact>
        {
            new("CPU", snapshot.CpuName)
        };

        if (snapshot.Gpus.Count == 0)
        {
            facts.Add(new UiSystemFact("GPU", "Unavailable", "Driver unavailable"));
        }
        else
        {
            for (int index = 0; index < snapshot.Gpus.Count; index++)
            {
                GpuInfo gpu = snapshot.Gpus[index];
                string label = snapshot.Gpus.Count == 1 ? "GPU" : $"GPU {index + 1}";
                string driver = string.IsNullOrWhiteSpace(gpu.DriverVersion) || gpu.DriverVersion == "Unknown"
                    ? "Driver unavailable"
                    : $"Driver {gpu.DriverVersion}";
                facts.Add(new UiSystemFact(label, gpu.Name, driver));
            }
        }

        string moduleLabel = snapshot.MemoryModules.Count == 1 ? "1 module" : $"{snapshot.MemoryModules.Count} modules";
        facts.Add(new UiSystemFact("RAM", FormatGiB(snapshot.TotalPhysicalMemoryBytes), $"{moduleLabel} · {memoryRate}"));

        string motherboard = JoinNonEmpty(snapshot.MotherboardManufacturer, snapshot.MotherboardProduct);
        facts.Add(new UiSystemFact("Motherboard", motherboard));
        facts.Add(new UiSystemFact("BIOS", snapshot.BiosVersion, snapshot.BiosReleaseDate));

        string windowsChannel = string.IsNullOrWhiteSpace(snapshot.WindowsChannel)
            ? "Channel unavailable"
            : snapshot.WindowsChannel;
        facts.Add(new UiSystemFact(
            "Windows",
            JoinNonEmpty(snapshot.WindowsCaption, $"build {snapshot.WindowsBuild}"),
            snapshot.PreviewBuildDetected ? $"Preview build · {windowsChannel}" : windowsChannel));

        string computerModel = JoinNonEmpty(snapshot.ComputerManufacturer, snapshot.ComputerModel);
        bool duplicatesMotherboard = computerModel.Equals(motherboard, StringComparison.OrdinalIgnoreCase) ||
            snapshot.ComputerModel.Equals(snapshot.MotherboardProduct, StringComparison.OrdinalIgnoreCase);
        if (!duplicatesMotherboard && computerModel != "Unavailable")
        {
            facts.Add(new UiSystemFact("System model", computerModel));
        }

        CollectionStatus[] statuses = collected.Statuses
            .GroupBy(status => status.Source, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.Last())
            .ToArray();
        string[] issues = statuses
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.Detail}")
            .ToArray();
        return new UiSystemSnapshot(
            facts.ToArray(),
            issues,
            statuses.Count(status => status.State == CollectionState.Available),
            statuses.Length);
    }

    public async Task<IReadOnlyList<UiDiagnosticResult>> RecoverInterruptedSessionsAsync(
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        IReadOnlyList<DiagnosticOperationResultV3> recovered = await _coordinator
            .RecoverInterruptedMonitoringAsync(coreProgress, cancellationToken)
            .ConfigureAwait(false);
        return recovered.Select(result => MapResult(result, null, null)).ToArray();
    }

    public async Task<IReadOnlyList<UiIncidentCandidate>> FindRecentIncidentsAsync(
        UiIncidentSearchOptions options,
        CancellationToken cancellationToken)
    {
        UiTargetProfile? uiTarget = options.IncidentKind == UiIncidentKind.ApplicationCrashOrFreeze
            ? options.Target ?? UiTargetProfile.Battlefield6
            : null;
        TargetProfile? target = uiTarget is null ? null : MapTarget(uiTarget);
        DateTimeOffset endUtc = DateTimeOffset.UtcNow;
        IncidentSearchResult result = await _coordinator.FindRecentIncidentsAsync(
            new IncidentSearchOptions(endUtc - options.Lookback, endUtc, target),
            cancellationToken).ConfigureAwait(false);
        IncidentCandidate[] matching = result.Candidates
            .Where(candidate => options.IncidentKind == UiIncidentKind.SystemCrash
                ? candidate.Kind is IncidentKind.Bugcheck or IncidentKind.UnexpectedRestart or IncidentKind.HardwareError
                : candidate.Kind is IncidentKind.ApplicationCrash or IncidentKind.ApplicationHang)
            .ToArray();
        foreach (IncidentCandidate candidate in matching)
        {
            _incidentCandidates[candidate.Fingerprint.Value] = candidate;
        }

        return matching.Select(candidate => new UiIncidentCandidate(
            candidate.Fingerprint.Value,
            options.IncidentKind,
            candidate.TimeUtc,
            $"{candidate.Title} · {candidate.TimeUtc.ToLocalTime():MMM d, h:mm:ss tt}",
            $"{candidate.SupportingRecordCount} matching Windows record{(candidate.SupportingRecordCount == 1 ? string.Empty : "s")}",
            candidate.Source,
            uiTarget)).ToArray();
    }

    public async Task<UiDiagnosticResult> AnalyzeIncidentAsync(
        UiIncidentSelection selection,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        TargetProfile? target = selection.Target is null ? null : MapTarget(selection.Target);
        IncidentCandidate candidate;
        if (!_incidentCandidates.TryGetValue(selection.CandidateId, out candidate!))
        {
            DateTimeOffset timeUtc = selection.AnchorUtc?.ToUniversalTime()
                ?? throw new ArgumentException("Choose an incident or enter its time.", nameof(selection));
            IncidentKind kind = selection.IncidentKind == UiIncidentKind.SystemCrash
                ? IncidentKind.Unknown
                : IncidentKind.ApplicationCrash;
            candidate = new IncidentCandidate(
                IncidentFingerprint.Create(kind, timeUtc, "Manual incident time", 0, target?.Id),
                timeUtc,
                kind,
                "Incident at entered time",
                "Manual incident time",
                0,
                target?.Id,
                null,
                null,
                1,
                1,
                timeUtc,
                timeUtc);
        }

        IncidentSelection coreSelection = new IncidentDiscovery().Select(
            candidate,
            selection.CandidateId == "manual-time" ? IncidentSelectionMethod.ManualTime : IncidentSelectionMethod.UserSelected);
        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        DiagnosticOperationResultV3 result = await _coordinator
            .AnalyzeSelectedIncidentAsync(coreSelection, target, coreProgress, cancellationToken)
            .ConfigureAwait(false);
        return MapResult(result, selection.Target, selection.IncidentKind);
    }

    public async Task<UiDiagnosticResult> MonitorTargetAsync(
        UiTargetProfile target,
        IProgress<UiDiagnosticProgress> progress,
        IProgress<UiTelemetrySample> telemetry,
        CancellationToken cancellationToken)
    {
        var combinedProgress = new Progress<TargetMonitorProgress>(item =>
        {
            double? percent = item.Percent is >= 0 and <= 1 ? item.Percent * 100 : item.Percent;
            progress.Report(new UiDiagnosticProgress(item.Stage, item.Message, percent));
            if (item.Sample is not null)
            {
                telemetry.Report(MapSample(item.Sample));
            }
        });
        DiagnosticOperationResultV3 result = await _coordinator
            .MonitorSelectedTargetAsync(MapTarget(target), combinedProgress, cancellationToken)
            .ConfigureAwait(false);
        return MapResult(result, target, UiIncidentKind.ApplicationCrashOrFreeze);
    }

    public async Task<UiIncidentHistory> OpenPreviousReportsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IncidentLibrarySnapshot snapshot = await _coordinator.IncidentLibrary
            .BuildAsync(cancellationToken)
            .ConfigureAwait(false);
        UiPreviousReport[] reports = snapshot.Incidents
            .Where(incident => Path.GetExtension(incident.ReportPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
            .Where(incident => File.Exists(incident.ReportPath))
            .Select(incident =>
            {
                var file = new FileInfo(incident.ReportPath);
                string signal = incident.StopCodes.FirstOrDefault()
                    ?? incident.FailureBuckets.FirstOrDefault()
                    ?? incident.Modules.FirstOrDefault()
                    ?? incident.WheaCategories.FirstOrDefault()
                    ?? incident.Kind.ToString();
                string title = incident.Kind == IncidentKind.Unknown
                    ? incident.TargetName
                    : $"{FormatIncidentKind(incident.Kind)} · {incident.TargetName}";
                string detail = $"{incident.StartUtc.ToLocalTime():MMM d, yyyy · h:mm tt} · {signal} · {FormatFileSize(file.Length)}";
                if (incident.Imported)
                {
                    detail += " · imported";
                }

                return new UiPreviousReport(
                    incident.SessionId,
                    incident.StartUtc,
                    title,
                    detail,
                    incident.ReportPath);
            })
            .OrderByDescending(report => report.CreatedUtc)
            .ToArray();
        UiRecurringIncidentGroup[] recurring = snapshot.RecurringGroups
            .Select(group => new UiRecurringIncidentGroup(
                $"{group.Value} · {group.Count} reports",
                $"{FormatHistoryCategory(group.Category)} · {group.FirstSeenUtc.ToLocalTime():MMM d, yyyy} to {group.LastSeenUtc.ToLocalTime():MMM d, yyyy}"))
            .ToArray();
        string[] issues = snapshot.Statuses
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.Detail}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new UiIncidentHistory(reports, recurring, issues);
    }

    private static string FormatIncidentKind(IncidentKind kind) => kind switch
    {
        IncidentKind.Bugcheck => "Blue screen",
        IncidentKind.UnexpectedRestart => "Unexpected restart",
        IncidentKind.HardwareError => "Hardware error record",
        IncidentKind.GpuTimeout => "GPU reset",
        IncidentKind.ApplicationCrash => "App crash",
        IncidentKind.ApplicationHang => "App hang",
        _ => "Incident"
    };

    private static string FormatHistoryCategory(string category) => category switch
    {
        "StopCode" => "Stop code",
        "FailureBucket" => "WinDbg failure bucket",
        "Module" => "WinDbg named module",
        "WheaCategory" => "WHEA category",
        "Target" => "Selected target",
        _ => category
    };

    public Task<int> GetLegacyV2ReportCountAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(LegacyImportMarkerPath))
        {
            return Task.FromResult(0);
        }

        return Task.FromResult(IncidentLibrary.FindLegacyV2Reports(LegacyV2DataRoot).Count);
    }

    public async Task<int> CompleteLegacyV2ImportOfferAsync(
        bool importReports,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int imported = 0;
        if (importReports)
        {
            IReadOnlyList<string> paths = IncidentLibrary.FindLegacyV2Reports(LegacyV2DataRoot);
            IReadOnlyList<ReportImportResult> results = await _coordinator.IncidentLibrary
                .ImportValidatedReportsAsync(paths, cancellationToken)
                .ConfigureAwait(false);
            imported = results.Count(result => result.Imported);
        }

        string? markerFolder = Path.GetDirectoryName(LegacyImportMarkerPath);
        Directory.CreateDirectory(markerFolder!);
        await File.WriteAllTextAsync(
            LegacyImportMarkerPath,
            importReports ? $"Imported {imported} validated report(s)." : "Import declined.",
            cancellationToken).ConfigureAwait(false);
        return imported;
    }

    public async Task<UiDiagnosticResult> LoadPreviousReportAsync(
        UiPreviousReport previous,
        CancellationToken cancellationToken)
    {
        string reportsRoot = Path.GetFullPath(Path.Combine(_dataRoot, "Reports"));
        string importsRoot = Path.GetFullPath(Path.Combine(_dataRoot, "Library", "ImportedReports"));
        string zipPath = Path.GetFullPath(previous.ZipPath);
        bool trustedLocation = zipPath.StartsWith(reportsRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            zipPath.StartsWith(importsRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        if (!trustedLocation ||
            !File.Exists(zipPath))
        {
            throw new FileNotFoundException("The selected report is no longer available.");
        }

        ValidatedReportArchive validated = await IncidentLibrary
            .ReadValidatedArchiveAsync(zipPath, cancellationToken)
            .ConfigureAwait(false);
        byte[] json = validated.ReportJson.ToArray();
        int schema = validated.ReportSchemaVersion;
        var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        if (schema == 3)
        {
            DiagnosticReportV3? report = JsonSerializer.Deserialize<DiagnosticReportV3>(json, jsonOptions);
            if (report is null)
            {
                throw new InvalidDataException("The selected schema-v3 report could not be read.");
            }

            string[] issues = report.CollectionStatus
                .Where(status => status.State != CollectionState.Available)
                .Select(status => $"{status.Source}: {status.State} · {status.Detail}")
                .ToArray();
            string checksumPath = zipPath + ".sha256";
            return MapReport(
                report,
                zipPath,
                File.Exists(checksumPath) ? checksumPath : null,
                issues,
                null,
                null,
                false,
                null,
                isHistorical: true);
        }

        if (schema == 2)
        {
            DiagnosticReport? report = JsonSerializer.Deserialize<DiagnosticReport>(json, jsonOptions);
            return report is null
                ? throw new InvalidDataException("The selected schema-v2 report could not be read.")
                : MapStoredReport(report, zipPath);
        }

        throw new InvalidDataException($"Report schema {schema} is not supported.");
    }

    public async Task<string> PackageCrashDumpAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        UiProtectedDumpConsent? protectedDumpConsent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        if (!_coreResults.TryGetValue(result.SessionId, out DiagnosticOperationResultV3? coreResult))
        {
            throw new InvalidOperationException("Crash dump packaging is available only for a report created in this app session.");
        }
        DumpCandidate selected = FindBoundDump(coreResult, dump);

        var dumpProgress = new Progress<double>(value => progress.Report(new UiDiagnosticProgress(
            "Packaging crash dump separately",
            $"Copying the dump into a local ZIP… {value:P0}",
            value * 100)));

        if (dump.RequiresAdministratorAccess)
        {
            if (protectedDumpConsent is null)
            {
                throw new InvalidOperationException("Administrator access requires the privacy, size, and free-space confirmation.");
            }
            ProtectedDumpOperationResult<string> protectedResult = await _coordinator
                .PackageSelectedProtectedDumpAsync(
                    coreResult,
                    selected,
                    MapConsent(protectedDumpConsent),
                    dumpProgress,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return protectedResult.Succeeded && protectedResult.Value is not null
                ? protectedResult.Value
                : throw new InvalidOperationException(protectedResult.Message);
        }

        return await _coordinator.PackageBoundDumpAsync(
            dump.Path,
            dumpProgress,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<UiProtectedOperationResult> InspectProtectedDumpAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        UiProtectedDumpConsent consent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        if (!_coreResults.TryGetValue(result.SessionId, out DiagnosticOperationResultV3? coreResult))
        {
            throw new InvalidOperationException("Protected dump inspection is available only for a report created in this app session.");
        }
        DumpCandidate selected = FindBoundDump(coreResult, dump);
        progress.Report(new UiDiagnosticProgress(
            "Inspecting protected dump",
            "Waiting for Windows administrator approval…"));
        ProtectedDumpOperationResult<ProtectedDumpInspection> operation = await _coordinator
            .InspectSelectedProtectedDumpAsync(
                coreResult,
                selected,
                MapConsent(consent),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        string message = operation.Value is null
            ? operation.Message
            : $"{operation.Message} Format: {operation.Value.Format}.";
        return new UiProtectedOperationResult(operation.Succeeded, message);
    }

    public async Task<UiDiagnosticResult> RetryProtectedEvidenceSourceAsync(
        UiDiagnosticResult result,
        UiProtectedEvidenceSourceChoice source,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        if (!_coreResults.TryGetValue(result.SessionId, out DiagnosticOperationResultV3? coreResult))
        {
            throw new InvalidOperationException("Administrator evidence retry is available only for a report created in this app session.");
        }

        if (!Enum.TryParse(source.SourceId, ignoreCase: false, out ProtectedEvidenceSource coreSource) ||
            !Enum.IsDefined(coreSource))
        {
            throw new ArgumentException("The selected protected evidence source is not supported.", nameof(source));
        }

        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        DiagnosticOperationResultV3 updated = await _coordinator
            .RetryProtectedEvidenceSourceAsync(
                coreResult,
                coreSource,
                coreProgress,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return MapResult(updated, null, null);
    }

    public async Task<UiDiagnosticResult> RunDebuggerAnalysisAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        bool allowMicrosoftSymbolDownload,
        UiProtectedDumpConsent? protectedDumpConsent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        if (!_coreResults.TryGetValue(result.SessionId, out DiagnosticOperationResultV3? coreResult))
        {
            throw new InvalidOperationException("WinDbg analysis is available only for a report created in this app session.");
        }

        DumpCandidate selected = FindBoundDump(coreResult, dump);
        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        DiagnosticOperationResultV3 updated;
        if (dump.RequiresAdministratorAccess)
        {
            if (protectedDumpConsent is null)
            {
                throw new InvalidOperationException("Administrator access requires the privacy, size, and free-space confirmation.");
            }
            ProtectedDumpOperationResult<DiagnosticOperationResultV3> operation = await _coordinator
                .RunOptionalDebuggerAnalysisForProtectedDumpAsync(
                    coreResult,
                    selected,
                    MapConsent(protectedDumpConsent),
                    allowMicrosoftSymbolDownload ? SymbolAccessMode.MicrosoftPublicServer : SymbolAccessMode.LocalOnly,
                    allowMicrosoftSymbolDownload,
                    coreResult.Package.Report.TargetProfile,
                    coreProgress,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            updated = operation.Succeeded && operation.Value is not null
                ? operation.Value
                : throw new InvalidOperationException(operation.Message);
        }
        else
        {
            updated = await _coordinator.RunOptionalDebuggerAnalysisAsync(
                coreResult,
                selected,
                allowMicrosoftSymbolDownload ? SymbolAccessMode.MicrosoftPublicServer : SymbolAccessMode.LocalOnly,
                allowMicrosoftSymbolDownload,
                coreResult.Package.Report.TargetProfile,
                coreProgress,
                cancellationToken).ConfigureAwait(false);
        }
        return MapResult(updated, null, null);
    }

    public async Task<UiDiagnosticResult> RunDumpCheckAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        UiProtectedDumpConsent? protectedDumpConsent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken)
    {
        if (!_coreResults.TryGetValue(result.SessionId, out DiagnosticOperationResultV3? coreResult))
        {
            throw new InvalidOperationException("DumpChk validation is available only for a report created in this app session.");
        }

        DumpCandidate selected = FindBoundDump(coreResult, dump);
        var coreProgress = new Progress<DiagnosticProgress>(item => progress.Report(MapProgress(item)));
        DiagnosticOperationResultV3 updated;
        if (dump.RequiresAdministratorAccess)
        {
            if (protectedDumpConsent is null)
            {
                throw new InvalidOperationException(
                    "Administrator access requires the privacy, size, and free-space confirmation.");
            }

            ProtectedDumpOperationResult<DiagnosticOperationResultV3> operation = await _coordinator
                .RunOptionalDumpCheckForProtectedDumpAsync(
                    coreResult,
                    selected,
                    MapConsent(protectedDumpConsent),
                    coreResult.Package.Report.TargetProfile,
                    coreProgress,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            updated = operation.Succeeded && operation.Value is not null
                ? operation.Value
                : throw new InvalidOperationException(operation.Message);
        }
        else
        {
            updated = await _coordinator.RunOptionalDumpCheckAsync(
                    coreResult,
                    selected,
                    coreResult.Package.Report.TargetProfile,
                    coreProgress,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return MapResult(updated, null, null);
    }

    public void Dispose() => _coordinator.Dispose();

    private string LegacyImportMarkerPath => Path.Combine(_dataRoot, "Library", "v2-import-offer-complete.txt");

    private static string LegacyV2DataRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "UnofficialBF6Diagnostic");

    internal async Task RunSmokeTestAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_dataRoot);
        string finalPath = Path.Combine(_dataRoot, "smoke-test.json");
        string temporaryPath = finalPath + ".partial";
        var marker = new
        {
            SchemaVersion = 1,
            Status = "passed",
            AppInitialized = true,
            CoreAssembly = typeof(DiagnosticReport).Assembly.GetName().Version?.ToString(),
            ToolVersion = PCCrashDiagnosticCoordinator.ToolVersion,
            Beta2FeaturesEnabled = ReleaseStage.Beta2FeaturesEnabled,
            WerLocalDumpCaptureEnabled = ReleaseStage.WerLocalDumpCaptureEnabled,
            TimestampUtc = DateTimeOffset.UtcNow
        };

        await using (FileStream stream = new(
            temporaryPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await JsonSerializer.SerializeAsync(stream, marker, cancellationToken: cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        File.Move(temporaryPath, finalPath, overwrite: true);
    }

    private static UiDiagnosticProgress MapProgress(DiagnosticProgress progress)
    {
        double? percent = progress.Percent is >= 0 and <= 1
            ? progress.Percent * 100
            : progress.Percent;
        return new UiDiagnosticProgress(
            progress.Stage,
            progress.Message,
            percent,
            progress.CollectionFailure);
    }

    private DiagnosticOperationResultV3 GetBoundResult(UiDiagnosticResult result, string operation)
    {
        ArgumentNullException.ThrowIfNull(result);
        return _coreResults.TryGetValue(result.SessionId, out DiagnosticOperationResultV3? bound)
            ? bound
            : throw new InvalidOperationException($"{operation} is available only for a report created in this app session.");
    }

    private static UiCrashPreparationPreview MapCrashCapturePreview(CrashCapturePlan plan)
    {
        UiCrashReadiness current = MapCrashReadiness(
            plan.BeforeReadiness,
            plan.CreatedUtc,
            isHistorical: false,
            preferBootVolumeFacts: true);
        var changes = plan.Changes
            .Where(change => change.Setting != CrashCaptureSetting.MinidumpDirectory)
            .Select(DescribeCrashCaptureChange)
            .ToList();
        if (plan.WerLocalDumpPlan is { } werPlan)
        {
            changes.Add($"Save up to {werPlan.DesiredDumpCount} full app crash dumps for {werPlan.ExecutableName}.");
        }
        if (changes.Count == 0)
        {
            changes.Add("No Windows settings need to change.");
        }

        string diskImpact = plan.BeforeReadiness.RecommendedDestinationFreeBytes is long recommended
            ? $"Keep at least {FormatBytes(recommended)} free at the dump destination. Actual dump size depends on the crash."
            : "System memory dumps can be large. The app will verify the destination and available space before applying changes.";
        diskImpact += " A later system crash may replace an older %SystemRoot%\\MEMORY.DMP file.";
        string restartImpact = plan.RequiresRestart
            ? "Restart Windows once after applying these settings. Until then, the previous capture setup may still be active."
            : "No restart is needed because the system crash-capture settings already match this preset.";
        string perAppSummary = plan.WerLocalDumpPlan is { } perApp
            ? $"Full user-mode dumps will be enabled for {perApp.ExecutableName}; Windows will keep up to {perApp.DesiredDumpCount}."
            : string.Empty;
        string actionText = plan.RequiresElevation ? "Continue to Windows UAC" : "Confirm settings";
        string uacNotice = plan.RequiresElevation
            ? "Windows will show a UAC prompt after you continue."
            : "No administrator prompt is needed because the settings already match.";
        return new UiCrashPreparationPreview(
            plan.PlanId,
            true,
            $"{current.DumpType} · {current.Status}",
            "Automatic memory dump with crash event logging and standard Windows dump locations",
            changes,
            diskImpact,
            "A system memory dump can contain sensitive information from memory. Dumps remain local and are never added to the standard report.",
            restartImpact,
            plan.WerLocalDumpPlan is not null,
            perAppSummary,
            string.Empty,
            ActionText: actionText,
            UacNotice: uacNotice);
    }

    private static UiCrashPreparationPreview MapWerLocalDumpPreview(WerLocalDumpPlan plan)
    {
        string current = plan.PreviousKeyExists
            ? $"Windows already has app-specific dump settings for {plan.ExecutableName}."
            : $"No app-specific crash-dump settings were found for {plan.ExecutableName}.";
        string proposed = $"Keep up to {plan.DesiredDumpCount} full crash dumps for {plan.ExecutableName}";
        return new UiCrashPreparationPreview(
            plan.PlanId,
            true,
            current,
            proposed,
            [
                $"Enable full user-mode crash dumps for {plan.ExecutableName}.",
                $"Keep the newest {plan.DesiredDumpCount} dumps.",
                "Store them in PC Crash Diagnostic's private app-dump folder.",
                "Programs with their own crash reporting may not use this Windows setting.",
                $"Disable this capture before you later run {plan.ExecutableName} as administrator."
            ],
            "Full app dumps can be large. Windows will keep only the configured number, but free space should still be monitored.",
            "A full app dump can contain account data, names, messages, or other information held by the app. It remains local and is excluded from standard reports.",
            "This per-app setting takes effect without restarting Windows.",
            true,
            $"This Windows setting follows the executable name {plan.ExecutableName}. It does not attach a debugger or read the running process. A program with custom crash reporting may ignore it; disable capture before running the same executable as administrator.",
            string.Empty,
            Heading: "Enable full app crash dumps",
            Introduction: $"Review the Windows Error Reporting setting for this app. Keep {plan.ExecutableName} open until setup finishes; you do not need to use it or make it crash. Existing settings are saved for restore.",
            ActionText: "Continue to Windows UAC",
            UacNotice: "Windows will show a UAC prompt after you continue.");
    }

    private static UiCrashPreparationOutcome MapPreparationOutcome(
        CrashCapturePreparationResult result,
        DateTimeOffset fallbackCapturedUtc,
        string? receiptId,
        bool canRestore)
    {
        UiCrashPreparationState state = result.Succeeded
            ? result.ActivationState switch
            {
                CrashCaptureActivationState.PendingRestart => UiCrashPreparationState.PendingRestart,
                CrashCaptureActivationState.Restored => UiCrashPreparationState.RolledBack,
                _ => UiCrashPreparationState.Succeeded
            }
            : result.RollbackAttempted && result.RollbackSucceeded
                ? UiCrashPreparationState.RolledBack
                : UiCrashPreparationState.Failed;
        UiCrashReadiness? verified = result.AfterReadiness is null
            ? null
            : MapCrashReadiness(
                result.AfterReadiness,
                fallbackCapturedUtc,
                isHistorical: false,
                preferBootVolumeFacts: true);
        return new UiCrashPreparationOutcome(
            state,
            result.Message,
            verified,
            null,
            receiptId,
            canRestore);
    }

    private static string DescribeCrashCaptureChange(CrashCaptureChange change) => change.Setting switch
    {
        CrashCaptureSetting.CrashDumpEnabled =>
            $"System dump type: {CurrentDumpType(change)} → Automatic memory dump.",
        CrashCaptureSetting.FilterPages =>
            $"Active memory-dump filter: {OnOffValue(change)} → Off.",
        CrashCaptureSetting.DumpFile =>
            $"System dump location: {CurrentDumpLocation(change)} → %SystemRoot%\\MEMORY.DMP.",
        CrashCaptureSetting.MinidumpDirectory =>
            "Small-dump folder: no change.",
        CrashCaptureSetting.EventLogging =>
            $"Crash event logging: {OnOffValue(change)} → On.",
        CrashCaptureSetting.OverwriteExistingDump =>
            $"Replace an older system dump after a later crash: {OnOffValue(change)} → On.",
        CrashCaptureSetting.AutomaticManagedPagefile =>
            $"Page-file management: {AutomaticPageFileValue(change)} → Windows managed.",
        _ => "One Windows crash-capture setting will be updated."
    };

    private static string CurrentDumpType(CrashCaptureChange change)
    {
        if (!change.PreviousValueExists ||
            !int.TryParse(change.PreviousValue, out int value))
        {
            return change.PreviousValueExists ? "Unrecognized" : "Not configured";
        }

        return value switch
        {
            0 => "Off",
            1 => "Complete or Active memory dump",
            2 => "Kernel memory dump",
            3 => "Small memory dump",
            7 => "Automatic memory dump",
            10 => "Active memory dump",
            _ => "Unrecognized"
        };
    }

    private static string OnOffValue(CrashCaptureChange change)
    {
        if (!change.PreviousValueExists)
        {
            return "Not configured";
        }

        return change.PreviousValue switch
        {
            "0" => "Off",
            "1" => "On",
            _ => "Unrecognized"
        };
    }

    private static string AutomaticPageFileValue(CrashCaptureChange change) =>
        !change.PreviousValueExists
            ? "Unavailable"
            : string.Equals(change.PreviousValue, "true", StringComparison.OrdinalIgnoreCase)
                ? "Windows managed"
                : string.Equals(change.PreviousValue, "false", StringComparison.OrdinalIgnoreCase)
                    ? "Custom or fixed"
                    : "Unrecognized";

    private static string CurrentDumpLocation(CrashCaptureChange change)
    {
        if (!change.PreviousValueExists || string.IsNullOrWhiteSpace(change.PreviousValue))
        {
            return "Not configured";
        }

        return string.Equals(
            change.PreviousValue.Trim(),
            @"%SystemRoot%\MEMORY.DMP",
            StringComparison.OrdinalIgnoreCase)
            ? @"%SystemRoot%\MEMORY.DMP"
            : SafeSettingText(change.PreviousValue);
    }

    private static string SafeSettingText(string value)
    {
        string safe = new(value
            .Where(character => !char.IsControl(character))
            .Take(160)
            .ToArray());
        return string.IsNullOrWhiteSpace(safe) ? "Unrecognized" : safe.Trim();
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => $"{bytes / 1024d / 1024d / 1024d:0.#} GiB",
        >= 1024L * 1024 => $"{bytes / 1024d / 1024d:0.#} MiB",
        _ => $"{bytes} bytes"
    };

    private static UiTelemetrySample MapSample(PerformanceSample sample)
    {
        double totalPhysical = sample.SystemMemoryUsedGB + sample.SystemMemoryAvailableGB;
        double? ramPercent = totalPhysical <= 0 ? null : 100 * sample.SystemMemoryUsedGB / totalPhysical;
        return new UiTelemetrySample(
            sample.TimestampUtc,
            ramPercent,
            sample.SystemCommitPct,
            sample.BF6PrivateMB / 1024d,
            sample.BF6DedicatedGpuMB / 1024d);
    }

    private static UiTelemetrySample MapSample(TargetPerformanceSample sample)
    {
        double totalPhysical = sample.SystemMemoryUsedGB + sample.SystemMemoryAvailableGB;
        double? ramPercent = totalPhysical <= 0 ? null : 100 * sample.SystemMemoryUsedGB / totalPhysical;
        return new UiTelemetrySample(
            sample.TimestampUtc,
            ramPercent,
            sample.SystemCommitPct,
            sample.TargetPrivateMB / 1024d,
            sample.TargetDedicatedGpuMB / 1024d);
    }

    private UiDiagnosticResult MapResult(
        DiagnosticOperationResultV3 result,
        UiTargetProfile? target,
        UiIncidentKind? incidentKind)
    {
        DiagnosticReportV3 report = result.Package.Report;
        _coreResults[report.SessionId] = result;
        DumpCandidate? selectedDump = report.CrashCorrelation?.SelectedDump;
        string? selectedPath = !result.DumpSelectionRequired &&
            !string.IsNullOrWhiteSpace(selectedDump?.OriginalPath)
                ? selectedDump.OriginalPath
                : null;
        bool canPackage = !result.DumpSelectionRequired &&
            selectedDump is not null &&
            selectedPath is not null &&
            selectedDump.InspectionState != DumpInspectionState.Denied &&
            File.Exists(selectedPath);
        UiDiagnosticResult mapped = MapReport(
            report,
            result.Package.ZipPath,
            result.Package.Sha256Path,
            result.CollectionFailures,
            target,
            incidentKind,
            canPackage,
            selectedPath);
        UiDumpChoice[] choices = result.DumpChoices
            .Where(candidate => !string.IsNullOrWhiteSpace(candidate.OriginalPath))
            .Select(candidate => new UiDumpChoice(
                candidate.Name,
                candidate.Kind.ToString(),
                FormatFileSize(candidate.SizeBytes),
                candidate.InspectionState == DumpInspectionState.Denied
                    ? candidate.Detail + " Administrator access may be needed."
                    : candidate.Detail,
                candidate.OriginalPath!,
                RequiresAdministratorAccess(candidate)))
            .ToArray();
        bool canRetrySymbols = report.DebuggerAnalysis is
        {
            SymbolAccess: SymbolAccessMode.LocalOnly,
            State: DebuggerAnalysisState.Completed or DebuggerAnalysisState.Failed
        } analysis && analysis.SymbolStatus is "Unavailable" or "Incomplete" or "Not reported";
        return mapped with
        {
            DumpChoices = choices,
            CanRunDumpCheck = _hasDumpChk && choices.Length > 0,
            CanRunDebugger = choices.Length > 0,
            CanRetryWithMicrosoftSymbols = canRetrySymbols,
            ProtectedEvidenceSources = BuildProtectedSourceChoices(result.CollectionFailures)
        };
    }

    private static DumpCandidate FindBoundDump(DiagnosticOperationResultV3 result, UiDumpChoice dump) =>
        result.DumpChoices.FirstOrDefault(candidate =>
            string.Equals(candidate.OriginalPath, dump.Path, StringComparison.OrdinalIgnoreCase))
        ?? throw new InvalidOperationException("The selected dump is no longer bound to this report.");

    private static ProtectedDumpCopyConfirmation MapConsent(UiProtectedDumpConsent consent) => new(
        consent.PrivacyConfirmed,
        consent.SizeConfirmed,
        consent.FreeSpaceConfirmed);

    private static bool RequiresAdministratorAccess(DumpCandidate candidate) =>
        candidate.InspectionState == DumpInspectionState.Denied &&
        candidate.Kind is DumpKind.WindowsMemoryDump or DumpKind.WindowsMinidump or DumpKind.LiveKernelDump;

    private static UiProtectedEvidenceSourceChoice[] BuildProtectedSourceChoices(IReadOnlyList<string> issues)
    {
        var choices = new Dictionary<ProtectedEvidenceSource, UiProtectedEvidenceSourceChoice>();
        foreach (string issue in issues.Where(item => item.Contains(": Denied", StringComparison.OrdinalIgnoreCase)))
        {
            (ProtectedEvidenceSource Source, string DisplayName)? match = issue switch
            {
                _ when issue.StartsWith("Windows Event Log/System:", StringComparison.OrdinalIgnoreCase) =>
                    (ProtectedEvidenceSource.SystemEventLog, "Windows System event log"),
                _ when issue.StartsWith("Windows Event Log/Application:", StringComparison.OrdinalIgnoreCase) =>
                    (ProtectedEvidenceSource.ApplicationEventLog, "Windows Application event log"),
                _ when issue.StartsWith("Dump inventory/Windows memory dump:", StringComparison.OrdinalIgnoreCase) =>
                    (ProtectedEvidenceSource.WindowsMemoryDump, "Windows memory dump"),
                _ when issue.StartsWith("Dump inventory/Windows minidumps:", StringComparison.OrdinalIgnoreCase) =>
                    (ProtectedEvidenceSource.WindowsMinidumps, "Windows minidump folder"),
                _ when issue.StartsWith("Dump inventory/LiveKernelReports:", StringComparison.OrdinalIgnoreCase) =>
                    (ProtectedEvidenceSource.LiveKernelReports, "Windows live-kernel report folder"),
                _ => null
            };
            if (match is { } value)
            {
                choices[value.Source] = new UiProtectedEvidenceSourceChoice(
                    value.Source.ToString(),
                    value.DisplayName,
                    "Windows denied the standard-user collection attempt.");
            }
        }

        return choices.Values.OrderBy(choice => choice.DisplayName, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static UiDiagnosticResult MapReport(
        DiagnosticReportV3 report,
        string zipPath,
        string? checksumPath,
        IReadOnlyList<string> issues,
        UiTargetProfile? target,
        UiIncidentKind? incidentKind,
        bool canPackageDump,
        string? eligibleDumpPath,
        bool isHistorical = false)
    {
        UiFinding[] findings = report.Findings
            .OrderBy(finding => finding.Rank)
            .Select(MapFinding)
            .ToArray();
        string targetName = target?.DisplayName ?? report.TargetProfile?.DisplayName ?? "This PC";
        string incidentTitle = report.IncidentSelection?.Candidate.Title ?? incidentKind switch
        {
            UiIncidentKind.SystemCrash => "Windows crash or unexpected restart",
            UiIncidentKind.ApplicationCrashOrFreeze => $"{targetName} incident",
            _ => "Windows incident"
        };
        string completion = report.CompletionReason == "TargetClosed"
            ? report.IncidentSelection?.Candidate.Kind is IncidentKind.ApplicationCrash or IncidentKind.ApplicationHang
                ? $"{targetName} closed and Windows recorded {report.IncidentSelection.Candidate.Title.ToLowerInvariant()}."
                : $"{targetName} closed. Process disappearance alone is not classified as a crash."
            : report.IncidentSelection is null
                ? "No incident selection was stored."
                : $"Analyzed the selected {report.IncidentSelection.Candidate.Title.ToLowerInvariant()}.";
        int available = report.SourceCoverage.Count(source => source.State == CollectionState.Available);
        int total = report.SourceCoverage.Count;
        var mapped = new UiDiagnosticResult(
            report.SessionId,
            report.Summary,
            zipPath,
            Path.GetDirectoryName(zipPath) ?? string.Empty,
            checksumPath,
            findings,
            issues.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            available,
            total,
            incidentTitle,
            targetName,
            completion,
            report.StartUtc,
            report.EndUtc,
            canPackageDump,
            eligibleDumpPath);
        return mapped with
        {
            CrashReadiness = MapCrashReadiness(
                report.CrashReadiness,
                report.EndUtc,
                isHistorical,
                report.ToolVersion.StartsWith("3.1.", StringComparison.OrdinalIgnoreCase)),
            IsHistoricalReport = isHistorical,
            CanOfferPerAppCrashCapture = IsEligiblePerAppCaptureTarget(report.TargetProfile),
            TargetProfileId = report.TargetProfile?.Id,
            TargetExecutableNames = report.TargetProfile?.ProcessNames
                .Select(name => Path.GetFileNameWithoutExtension(name))
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray() ?? []
        };
    }

    private static bool IsEligiblePerAppCaptureTarget(TargetProfile? target) =>
        target is { ProcessNames.Count: > 0 } &&
        !target.Id.Equals(TargetProfile.Battlefield6.Id, StringComparison.OrdinalIgnoreCase) &&
        !target.ProcessNames.Any(name => name.Equals("BF6", StringComparison.OrdinalIgnoreCase) ||
                                         name.Equals("BF6.exe", StringComparison.OrdinalIgnoreCase));

    private static UiCrashReadiness MapCrashReadiness(
        CrashReadiness? readiness,
        DateTimeOffset reportEndUtc,
        bool isHistorical,
        bool preferBootVolumeFacts)
    {
        if (readiness is null)
        {
            return UiCrashReadiness.Missing(reportEndUtc, isHistorical);
        }

        bool pendingRestart = readiness.Assessment == CrashReadinessState.PendingRestart ||
            readiness.ActivationState == CrashCaptureActivationState.PendingRestart;
        UiCrashReadinessLevel level = pendingRestart
            ? UiCrashReadinessLevel.PendingRestart
            : readiness.Assessment switch
        {
            CrashReadinessState.Configured => UiCrashReadinessLevel.Ready,
            CrashReadinessState.Limited => UiCrashReadinessLevel.Limited,
            CrashReadinessState.AtRisk => UiCrashReadinessLevel.AtRisk,
            CrashReadinessState.Off => UiCrashReadinessLevel.Off,
            _ => UiCrashReadinessLevel.Unavailable
        };
        string status = level switch
        {
            UiCrashReadinessLevel.Ready => "Ready",
            UiCrashReadinessLevel.Limited => "Limited",
            UiCrashReadinessLevel.AtRisk => "At risk",
            UiCrashReadinessLevel.Off => "Off",
            UiCrashReadinessLevel.PendingRestart => "Restart needed",
            _ => "Unavailable"
        };
        string dumpType = readiness.DumpMode switch
        {
            CrashDumpMode.CompleteMemory => "Complete memory dump",
            CrashDumpMode.KernelMemory => "Kernel memory dump",
            CrashDumpMode.SmallMemory => "Small memory dump",
            CrashDumpMode.AutomaticMemory => "Automatic memory dump",
            CrashDumpMode.ActiveMemory => "Active memory dump",
            CrashDumpMode.None => "Crash dumps are off",
            _ => "Dump type not recognized"
        };
        int configuredPageFileCount = preferBootVolumeFacts
            ? readiness.BootVolumePageFileEntryCount
            : readiness.PageFileEntryCount;
        int runtimePageFileCount = preferBootVolumeFacts
            ? readiness.BootVolumeRuntimePageFileCount
            : readiness.RuntimePageFileCount;
        long? runtimePageFileBytes = preferBootVolumeFacts
            ? readiness.BootVolumeRuntimePageFileAllocatedBytes
            : readiness.RuntimePageFileAllocatedBytes;
        string backingStorage = readiness.DedicatedDumpFileConfigured
            ? "Dedicated dump storage is configured"
            : readiness.RuntimePageFileStateAvailable && runtimePageFileCount > 0 &&
              runtimePageFileBytes is long runtimeBytes
                ? $"{runtimePageFileCount} active page file{(runtimePageFileCount == 1 ? string.Empty : "s")}{(preferBootVolumeFacts ? " on the Windows drive" : string.Empty)} · {runtimeBytes / 1024d / 1024d / 1024d:0.#} GiB allocated"
            : readiness.RuntimePageFileStateAvailable && preferBootVolumeFacts && runtimePageFileCount == 0
                ? "No active page file was confirmed on the Windows drive"
            : configuredPageFileCount <= 0
                ? preferBootVolumeFacts
                    ? "No page file was confirmed on the Windows drive"
                    : "No page file was confirmed"
                : readiness.SystemManagedPageFile switch
                {
                    true => preferBootVolumeFacts
                        ? "A system-managed page file was detected for the Windows drive"
                        : "A system-managed page file was detected",
                    false => configuredPageFileCount == 1
                        ? preferBootVolumeFacts
                            ? "One configured page file was detected on the Windows drive"
                            : "One configured page file was detected"
                        : $"{configuredPageFileCount} configured page files were detected{(preferBootVolumeFacts ? " on the Windows drive" : string.Empty)}",
                    _ => "Page-file sizing could not be confirmed"
                };
        string freeSpace = readiness.DumpDestinationAccessible == false
            ? "The configured dump destination could not be accessed"
            : readiness.DumpDestinationFreeBytes is long dumpBytes
                ? $"{dumpBytes / 1024d / 1024d / 1024d:0.#} GiB free at the dump destination"
                : readiness.SystemDriveFreeBytes is long systemBytes
                    ? $"{systemBytes / 1024d / 1024d / 1024d:0.#} GiB free on the Windows drive"
                    : "Dump-destination free space was not confirmed";
        string eventLogging = readiness.EventLoggingEnabled switch
        {
            true => "Crash event logging is on",
            false => "Crash event logging is off",
            _ => "Crash event logging was not confirmed"
        };
        string automaticRestart = readiness.AutoRebootEnabled switch
        {
            true => "Windows is set to restart automatically after a system crash",
            false => "Windows is set to remain on the crash screen",
            _ => "Automatic restart was not confirmed"
        };
        string detail = string.IsNullOrWhiteSpace(readiness.AssessmentDetail)
            ? "Windows did not provide a readiness explanation."
            : readiness.AssessmentDetail;
        return new UiCrashReadiness(
            level,
            status,
            dumpType,
            detail,
            backingStorage,
            freeSpace,
            eventLogging,
            automaticRestart,
            readiness.CapturedUtc,
            isHistorical,
            pendingRestart);
    }

    private static UiFinding MapFinding(DiagnosticFinding finding) => new(
        finding.Rank,
        finding.Severity switch
        {
            BF6CrashDiagnostic.Core.Models.FindingSeverity.Critical => FindingImpact.SystemFailure,
            BF6CrashDiagnostic.Core.Models.FindingSeverity.Warning => FindingImpact.NeedsReview,
            BF6CrashDiagnostic.Core.Models.FindingSeverity.Information => FindingImpact.Information,
            _ => FindingImpact.Context
        },
        finding.Confidence switch
        {
            FindingConfidence.High => FindingEvidenceStrength.ConfirmedRecord,
            FindingConfidence.Medium => FindingEvidenceStrength.StrongSignal,
            _ => FindingEvidenceStrength.LimitedSignal
        },
        finding.Title,
        finding.Evidence,
        finding.Meaning,
        finding.DoesNotProve,
        finding.NextCheck,
        finding.OccurrenceCount,
        finding.FirstSeenUtc,
        finding.LastSeenUtc);

    private static TargetProfile MapTarget(UiTargetProfile target)
    {
        if (target.Kind == UiTargetKind.Battlefield6Preset)
        {
            return TargetProfile.Battlefield6;
        }

        string[] processNames = target.ProcessNames
            .Select(name => Path.GetFileNameWithoutExtension(name) ?? string.Empty)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        string[] signals = target.RelatedSignals
            .Concat(processNames)
            .Concat(processNames.Select(name => name + ".exe"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new TargetProfile(
            target.Id,
            target.DisplayName,
            processNames,
            [],
            signals,
            signals,
            signals,
            processNames.FirstOrDefault() ?? target.DisplayName,
            target.BlockSensitiveOperationsWhileRunning,
            TargetPrivacyRules.Strict);
    }

    private static UiDiagnosticResult MapResult(
        DiagnosticOperationResult result,
        UiTargetProfile? target,
        UiIncidentKind? incidentKind)
    {
        DiagnosticReport report = result.Package.Report;
        string[] issues = result.CollectionFailures
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        bool canPackageDump = !string.IsNullOrWhiteSpace(result.EligibleDumpPath) && File.Exists(result.EligibleDumpPath);
        return MapReport(
            report,
            result.Package.ZipPath,
            result.Package.Sha256Path,
            issues,
            target,
            incidentKind,
            canPackageDump,
            canPackageDump ? result.EligibleDumpPath : null);
    }

    private static UiDiagnosticResult MapStoredReport(DiagnosticReport report, string zipPath)
    {
        string[] issues = report.CollectionStatus
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.State} · {status.Detail}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        string checksumPath = zipPath + ".sha256";
        return MapReport(
            report,
            zipPath,
            File.Exists(checksumPath) ? checksumPath : null,
            issues,
            null,
            null,
            canPackageDump: false,
            eligibleDumpPath: null,
            isHistorical: true);
    }

    private static UiDiagnosticResult MapReport(
        DiagnosticReport report,
        string zipPath,
        string? checksumPath,
        IReadOnlyList<string> issues,
        UiTargetProfile? target,
        UiIncidentKind? incidentKind,
        bool canPackageDump,
        string? eligibleDumpPath,
        bool isHistorical = false)
    {
        UiFinding[] findings = report.Findings
            .OrderBy(finding => finding.Rank)
            .Select(finding => new UiFinding(
                finding.Rank,
                finding.Severity switch
                {
                    BF6CrashDiagnostic.Core.Models.FindingSeverity.Critical => FindingImpact.SystemFailure,
                    BF6CrashDiagnostic.Core.Models.FindingSeverity.Warning => FindingImpact.NeedsReview,
                    BF6CrashDiagnostic.Core.Models.FindingSeverity.Information => FindingImpact.Information,
                    _ => FindingImpact.Context
                },
                finding.Confidence switch
                {
                    FindingConfidence.High => FindingEvidenceStrength.ConfirmedRecord,
                    FindingConfidence.Medium => FindingEvidenceStrength.StrongSignal,
                    _ => FindingEvidenceStrength.LimitedSignal
                },
                finding.Title,
                finding.Evidence,
                finding.Meaning,
                finding.DoesNotProve,
                finding.NextCheck,
                finding.OccurrenceCount,
                finding.FirstSeenUtc,
                finding.LastSeenUtc))
            .ToArray();

        CollectionStatus[] statuses = report.CollectionStatus
            .GroupBy(status => status.Source, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.Last())
            .ToArray();
        string targetName = target?.DisplayName ?? InferTargetName(report);
        string incidentTitle = incidentKind switch
        {
            UiIncidentKind.SystemCrash => "Windows crash or unexpected restart",
            UiIncidentKind.ApplicationCrashOrFreeze => $"{targetName} crash or freeze",
            _ when report.Mode is DiagnosticMode.Monitor or DiagnosticMode.Recovered => $"Monitored session · {targetName}",
            _ => "Windows crash analysis"
        };
        string completion = report.Anchor is not null
            ? $"Windows recorded {report.Anchor.Description.ToLowerInvariant()} at {report.Anchor.TimeUtc.ToLocalTime():MMM d, h:mm:ss tt}."
            : report.Mode is DiagnosticMode.Monitor or DiagnosticMode.Recovered
                ? "The monitored app exited. No matching Windows crash record was found."
                : "No matching crash record was found in the selected time window.";

        var mapped = new UiDiagnosticResult(
            report.SessionId,
            NormalizeSummaryHeader(report.Summary),
            zipPath,
            Path.GetDirectoryName(zipPath) ?? string.Empty,
            checksumPath,
            findings,
            issues,
            statuses.Count(status => status.State == CollectionState.Available),
            statuses.Length,
            incidentTitle,
            targetName,
            completion,
            report.StartUtc,
            report.EndUtc,
            canPackageDump,
            eligibleDumpPath);
        return mapped with
        {
            CrashReadiness = UiCrashReadiness.Missing(report.EndUtc, isHistorical),
            IsHistoricalReport = isHistorical,
            TargetProfileId = target?.Id,
            TargetExecutableNames = target?.ProcessNames ?? []
        };
    }

    private static bool IsLegacyBattlefieldTarget(UiTargetProfile target) =>
        target.ProcessNames.Any(name => name.Equals("BF6", StringComparison.OrdinalIgnoreCase));

    private static string InferTargetName(DiagnosticReport report) =>
        report.Samples.Any(sample => sample.BF6Running) || report.Mode is DiagnosticMode.Monitor or DiagnosticMode.Recovered
            ? "Battlefield 6"
            : "This PC";

    private static string NormalizeSummaryHeader(string summary)
    {
        const string oldHeader = "Unofficial BF6 Crash Diagnostic";
        return summary.StartsWith(oldHeader, StringComparison.Ordinal)
            ? "PC Crash Diagnostic" + summary[oldHeader.Length..]
            : summary;
    }

    private static string FormatGiB(ulong bytes) =>
        bytes == 0 ? "Unavailable" : $"{bytes / 1024d / 1024d / 1024d:0.#} GiB";

    private static string FormatFileSize(long bytes) => bytes switch
    {
        >= 1024L * 1024L => $"{bytes / 1024d / 1024d:0.0} MB",
        >= 1024L => $"{bytes / 1024d:0.0} KB",
        _ => $"{bytes} bytes"
    };

    private static string JoinNonEmpty(params string[] values)
    {
        string result = string.Join(" · ", values.Where(value => !string.IsNullOrWhiteSpace(value) && value != "Unknown"));
        return string.IsNullOrWhiteSpace(result) ? "Unavailable" : result;
    }
}
