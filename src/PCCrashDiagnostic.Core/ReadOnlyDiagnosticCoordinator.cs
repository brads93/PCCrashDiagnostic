using System.Diagnostics;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using PCCrashDiagnostic.Contracts;

namespace PCCrashDiagnostic.Core;

/// <summary>
/// Standard-user incident coordinator. This assembly has no reference to the
/// privileged project and exposes no settings mutation or dump packaging API.
/// </summary>
public sealed class ReadOnlyDiagnosticCoordinator : IDisposable
{
    private static readonly TimeSpan MonitorInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan EvidencePollLimit = TimeSpan.FromSeconds(60);

    private readonly string _dataRoot;
    private readonly WindowsEventCollector _events = new();
    private readonly ReliabilityCollector _reliability = new();
    private readonly ArtifactCollector _artifacts = new();
    private readonly SystemSnapshotCollector _snapshots = new();
    private readonly ReadOnlyCrashReadinessCollector _readiness = new();
    private readonly DumpInventoryCollector _dumps = new();
    private readonly DriverDeviceCollector _drivers = new();
    private readonly RecentChangeCollector _recentChanges = new();
    private readonly StorageHealthCollector _storageHealth = new();
    private readonly DriverVerifierCollector _driverVerifier = new();
    private readonly IncidentDiscovery _incidentDiscovery = new();
    private readonly CrashCorrelator _correlator = new();
    private readonly EventAnalyzer _eventAnalyzer = new();
    private readonly ExtendedEvidenceAnalyzer _extendedAnalyzer = new();
    private readonly PrivacyRedactor _redactor = new();
    private readonly BootSessionReconstructor _bootSessions = new();
    private readonly ReportWriter _reportWriter;
    private readonly SummaryBuilderV3 _summaryBuilder = new();
    private readonly TargetSessionStore _activeSessions = new();
    private readonly TargetSampleJournal _sampleJournal = new();
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;
    private bool _disposed;

    public ReadOnlyDiagnosticCoordinator(string dataRoot)
        : this(dataRoot, static (delay, token) => Task.Delay(delay, token))
    {
    }

    internal ReadOnlyDiagnosticCoordinator(
        string dataRoot,
        Func<TimeSpan, CancellationToken, Task> delayAsync)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The diagnostic data root must be absolute.", nameof(dataRoot));
        }

        if (BuildProfile.Current.Profile != ProductFeatureProfile.ShareReadOnly)
        {
            throw new InvalidOperationException("The public coordinator is available only in the ShareReadOnly profile.");
        }

        _dataRoot = Path.GetFullPath(dataRoot);
        _reportWriter = new ReportWriter(_dataRoot);
        _delayAsync = delayAsync ?? throw new ArgumentNullException(nameof(delayAsync));
    }

    public string DataRoot => _dataRoot;

    public IncidentLibrary IncidentLibrary => new(_dataRoot);

    public Task<SystemSnapshotCollection> GetSystemSnapshotAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _snapshots.CollectAsync(cancellationToken);
    }

    public Task<CrashReadinessCollection> InspectCrashReadinessAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _readiness.CollectAsync(cancellationToken);
    }

    public async Task<IncidentSearchResult> FindRecentIncidentsAsync(
        IncidentSearchOptions options,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateSearchWindow(options);
        WindowsEventCollection eventCollection = await _events
            .CollectWindowAsync(options.StartUtc, options.EndUtc, options.TargetProfile, cancellationToken)
            .ConfigureAwait(false);
        ReliabilityCollection reliability = await _reliability
            .CollectAsync(options.StartUtc, options.EndUtc, options.TargetProfile, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlyList<IncidentCandidate> candidates = _incidentDiscovery.Discover(
            eventCollection.Events,
            reliability.Records,
            options.TargetProfile,
            maximumCandidates: 64);
        CollectionStatus[] statuses = [.. eventCollection.Statuses, .. reliability.Statuses];
        return new IncidentSearchResult(
            options.StartUtc,
            options.EndUtc,
            candidates,
            BuildCoverage(statuses, eventCollection.Events, reliability.Records, [], [], null, null),
            statuses.Select(_redactor.RedactStatus).ToArray());
    }

    public async Task<DiagnosticOperationResultV3> AnalyzeSelectedIncidentAsync(
        IncidentSelection selection,
        TargetProfile? targetProfile = null,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateSelection(selection);
        if (selection.Method == IncidentSelectionMethod.ManualTime &&
            selection.Candidate.EvidenceOrigin == IncidentEvidenceOrigin.Unknown)
        {
            selection = selection with
            {
                Candidate = selection.Candidate with { EvidenceOrigin = IncidentEvidenceOrigin.ManualTime }
            };
        }

        if (targetProfile is not null)
        {
            ValidateTarget(targetProfile);
        }

        progress?.Report(new DiagnosticProgress("Collecting", "Reading Windows records for the selected incident.", 0.08));
        SystemSnapshotCollection snapshot = await _snapshots.CollectAsync(cancellationToken).ConfigureAwait(false);
        return await BuildReportAsync(
            CreateSessionId(selection.Candidate.TimeUtc),
            DiagnosticMode.Retrospective,
            selection.WindowStartUtc,
            selection.WindowEndUtc,
            "SelectedIncidentAnalyzed",
            selection,
            targetProfile,
            snapshot.Snapshot,
            snapshot.Snapshot,
            [],
            snapshot.Statuses,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<DiagnosticOperationResultV3> MonitorSelectedTargetAsync(
        TargetProfile targetProfile,
        IProgress<TargetMonitorProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateTarget(targetProfile);
        DateTimeOffset startedUtc = DateTimeOffset.UtcNow;
        string sessionId = CreateSessionId(startedUtc);
        Directory.CreateDirectory(_reportWriter.SessionsRoot);
        string sessionFolder = Path.Combine(_reportWriter.SessionsRoot, sessionId);
        Directory.CreateDirectory(sessionFolder);
        SystemSnapshotCollection startSnapshot = await _snapshots.CollectAsync(cancellationToken).ConfigureAwait(false);
        var marker = new ActiveTargetSessionMarker(
            3,
            sessionId,
            Environment.ProcessId,
            startedUtc,
            startSnapshot.Snapshot.LastBootUtc ?? EstimateCurrentBootUtc(),
            startedUtc,
            sessionFolder,
            targetProfile);
        await _activeSessions.WriteAsync(marker, _reportWriter.SessionsRoot, cancellationToken).ConfigureAwait(false);

        var samples = new List<TargetPerformanceSample>();
        bool observed = false;
        int missed = 0;
        using var sampler = new PerformanceSampler(targetProfile.ProcessNames);
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                TargetPerformanceSample sample = await sampler.SampleTargetAsync(cancellationToken).ConfigureAwait(false);
                samples.Add(sample);
                await _sampleJournal.AppendAsync(sessionFolder, sample, cancellationToken).ConfigureAwait(false);
                marker = marker with { LastSampleUtc = sample.TimestampUtc };
                await _activeSessions.WriteAsync(marker, _reportWriter.SessionsRoot, cancellationToken).ConfigureAwait(false);

                if (sample.TargetRunning)
                {
                    observed = true;
                    missed = 0;
                    progress?.Report(new TargetMonitorProgress(
                        "Monitoring",
                        $"{targetProfile.DisplayName} is running in {sample.TargetProcessCount} matching process{(sample.TargetProcessCount == 1 ? string.Empty : "es")}.",
                        sample));
                }
                else if (!observed)
                {
                    progress?.Report(new TargetMonitorProgress("Waiting", $"Start {targetProfile.DisplayName} when ready.", sample));
                }
                else if (++missed >= 2)
                {
                    break;
                }
                else
                {
                    progress?.Report(new TargetMonitorProgress("Checking closure", "The target was absent for one of two required samples.", sample));
                }

                await _delayAsync(MonitorInterval, cancellationToken).ConfigureAwait(false);
            }

            DateTimeOffset disappearedUtc = DateTimeOffset.UtcNow;
            progress?.Report(new TargetMonitorProgress(
                "Checking Windows records",
                "The app closed. Waiting up to 60 seconds for related Windows evidence.",
                Percent: 0.15));
            IncidentCandidate? detected = await PollForIncidentAsync(
                startedUtc,
                disappearedUtc,
                targetProfile,
                cancellationToken).ConfigureAwait(false);
            DateTimeOffset endedUtc = DateTimeOffset.UtcNow;
            IncidentCandidate candidate = detected ?? new IncidentCandidate(
                IncidentFingerprint.Create(IncidentKind.Unknown, disappearedUtc, "Process monitoring", 0, targetProfile.Id),
                disappearedUtc,
                IncidentKind.Unknown,
                "App closed",
                "Process monitoring",
                0,
                targetProfile.Id,
                null,
                null,
                1,
                1,
                disappearedUtc,
                disappearedUtc,
                IncidentEvidenceOrigin.MonitorObservation);
            IncidentSelection selection = _incidentDiscovery.Select(
                candidate,
                IncidentSelectionMethod.Automatic,
                disappearedUtc - startedUtc,
                endedUtc - disappearedUtc);
            SystemSnapshotCollection endSnapshot = await _snapshots.CollectAsync(cancellationToken).ConfigureAwait(false);
            DiagnosticOperationResultV3 result = await BuildReportAsync(
                sessionId,
                DiagnosticMode.Monitor,
                startedUtc,
                endedUtc,
                "TargetClosed",
                selection,
                targetProfile,
                startSnapshot.Snapshot,
                endSnapshot.Snapshot,
                samples,
                [.. startSnapshot.Statuses, .. endSnapshot.Statuses],
                null,
                cancellationToken).ConfigureAwait(false);
            _activeSessions.Complete(sessionFolder, _reportWriter.SessionsRoot);
            progress?.Report(new TargetMonitorProgress("Report ready", "Monitoring ended and the local report is ready.", Percent: 1));
            return result;
        }
        catch (OperationCanceledException)
        {
            if (!observed)
            {
                _activeSessions.Complete(sessionFolder, _reportWriter.SessionsRoot);
            }

            throw;
        }
    }

    public DumpCandidate InspectAccessibleDump(
        string path,
        DumpKind kind,
        string source,
        TargetProfile? targetProfile = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (IsSensitiveOperationBlocked(targetProfile))
        {
            throw new InvalidOperationException("Dump inspection is unavailable while Battlefield 6 or the protected target is running.");
        }

        return new SafeDumpInspector().Inspect(path, kind, source, cancellationToken);
    }

    public void Dispose() => _disposed = true;

    private async Task<DiagnosticOperationResultV3> BuildReportAsync(
        string sessionId,
        DiagnosticMode mode,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        string completionReason,
        IncidentSelection selection,
        TargetProfile? targetProfile,
        SystemSnapshot? startSnapshot,
        SystemSnapshot? endSnapshot,
        IReadOnlyList<TargetPerformanceSample> samples,
        IReadOnlyList<CollectionStatus> initialStatuses,
        IProgress<DiagnosticProgress>? progress,
        CancellationToken cancellationToken)
    {
        progress?.Report(new DiagnosticProgress("Collecting", "Reading crash, reliability, readiness, dump, and driver evidence.", 0.28));
        Task<WindowsEventCollection> eventTask = _events.CollectWindowAsync(startUtc, endUtc, targetProfile, cancellationToken);
        Task<WindowsEventCollection> bootMarkerTask = _events.CollectBootMarkersAsync(
            selection.Candidate.TimeUtc,
            cancellationToken);
        Task<ReliabilityCollection> reliabilityTask = _reliability.CollectAsync(startUtc, endUtc, targetProfile, cancellationToken);
        Task<ArtifactCollection> artifactTask = _artifacts.CollectAsync(startUtc, endUtc, targetProfile, cancellationToken);
        Task<CrashReadinessCollection> readinessTask = _readiness.CollectAsync(cancellationToken);
        Task<DriverInventory> driverTask = _drivers.CollectAsync(cancellationToken);
        Task<RecentChangeTimeline> recentTask = _recentChanges.CollectForIncidentAsync(selection.Candidate.TimeUtc, cancellationToken);
        Task<StorageHealthSnapshot> storageTask = _storageHealth.CollectAsync(cancellationToken);
        Task<DriverVerifierState> verifierTask = _driverVerifier.CollectAsync(cancellationToken);
        Task<DumpInventory> dumpTask = _dumps.CollectAsync(
            startUtc,
            endUtc,
            targetProfile,
            cancellationToken,
            () => IsSensitiveOperationBlocked(targetProfile));

        await Task.WhenAll(eventTask, bootMarkerTask, reliabilityTask, artifactTask, readinessTask, driverTask, recentTask, storageTask, verifierTask, dumpTask)
            .ConfigureAwait(false);
        WindowsEventCollection eventCollection = await eventTask.ConfigureAwait(false);
        WindowsEventCollection bootMarkers = await bootMarkerTask.ConfigureAwait(false);
        ReliabilityCollection reliability = await reliabilityTask.ConfigureAwait(false);
        ArtifactCollection artifacts = await artifactTask.ConfigureAwait(false);
        CrashReadinessCollection readiness = await readinessTask.ConfigureAwait(false);
        DriverInventory drivers = await driverTask.ConfigureAwait(false);
        RecentChangeTimeline recent = await recentTask.ConfigureAwait(false);
        StorageHealthSnapshot storage = await storageTask.ConfigureAwait(false);
        DriverVerifierState verifier = await verifierTask.ConfigureAwait(false);
        DumpInventory dumps = await dumpTask.ConfigureAwait(false);

        BootSessionContext bootSession = _bootSessions.Reconstruct(
            selection.Candidate.TimeUtc,
            bootMarkers.Events,
            endSnapshot?.LastBootUtc);
        IReadOnlyList<BugcheckRecord> bugchecks = BugcheckRecordDecoder.Decode(eventCollection.Events);
        IReadOnlyList<WheaEvidence> wheaEvidence = WheaEvidenceSummarizer.Summarize(eventCollection.Events);
        CrashCorrelation correlation = _correlator.Correlate(
            selection,
            bugchecks,
            dumps.Candidates,
            endSnapshot?.LastBootUtc,
            bootSession);
        CrashAnchor anchor = new(
            selection.Candidate.TimeUtc,
            selection.Candidate.Source,
            selection.Candidate.EventId,
            selection.Candidate.Title,
            selection.Candidate.BugcheckCode,
            selection.Candidate.DumpFileName,
            selection.Candidate.EvidencePriority);
        IReadOnlyList<DuplicateEventGroup> groups = _eventAnalyzer.GroupDuplicates(eventCollection.Events);
        IReadOnlyList<PerformanceSample> compatibilitySamples = samples.Select(ToCompatibilitySample).ToArray();
        var findings = _eventAnalyzer.Analyze(
                anchor,
                eventCollection.Events,
                groups,
                reliability.Records,
                artifacts.Artifacts,
                compatibilitySamples,
                targetProfile,
                selection.Candidate)
            .Concat(CreateWheaCategoryFindings(eventCollection.Events))
            .Concat(_extendedAnalyzer.Analyze(null, recent, storage, verifier))
            .Concat(DiagnosticContextAnalyzer.CreatePreviewBuildFinding(startSnapshot, endSnapshot) is { } preview
                ? [preview]
                : [])
            .OrderBy(finding => finding.Rank)
            .ToArray();
        DiagnosticEvent[] safeEvents = eventCollection.Events.Select(_redactor.RedactEvent).ToArray();
        DuplicateEventGroup[] safeGroups = groups.Select(_redactor.RedactGroup).ToArray();
        ReliabilityRecord[] safeReliability = reliability.Records.Select(_redactor.RedactReliability).ToArray();
        CrashArtifact[] safeArtifacts = artifacts.Artifacts.Select(_redactor.RedactArtifact).ToArray();
        DiagnosticFinding[] safeFindings = findings.Select(_redactor.RedactFinding).ToArray();
        CollectionStatus[] statuses = initialStatuses
            .Concat(eventCollection.Statuses)
            .Concat(bootMarkers.Statuses)
            .Concat(reliability.Statuses)
            .Concat(artifacts.Statuses)
            .Concat(readiness.Statuses)
            .Concat(dumps.Statuses)
            .Concat(drivers.Statuses)
            .Concat(recent.CollectionStatus)
            .Concat(storage.CollectionStatus)
            .Concat([CreateDriverVerifierStatus(verifier)])
            .Select(_redactor.RedactStatus)
            .GroupBy(status => new { status.Source, status.State, status.Detail })
            .Select(group => group.First())
            .ToArray();
        DriverInventory safeDrivers = RedactDrivers(drivers);
        SourceCoverage[] coverage = BuildCoverage(
            statuses,
            safeEvents,
            safeReliability,
            safeArtifacts,
            dumps.Candidates,
            safeDrivers,
            readiness.Readiness,
            recent,
            storage,
            verifier,
            bootSession);
        string summary = _summaryBuilder.Build(
            BuildProfile.Version,
            sessionId,
            startUtc,
            endUtc,
            completionReason,
            selection,
            targetProfile,
            safeFindings,
            coverage,
            correlation,
            null,
            readiness.Readiness,
            null,
            recent,
            storage,
            verifier,
            bootSession);
        var report = new DiagnosticReportV3(
            3,
            BuildProfile.Version,
            "PC Crash Diagnostic",
            sessionId,
            mode,
            startUtc,
            endUtc,
            completionReason,
            selection,
            targetProfile,
            startSnapshot,
            endSnapshot,
            samples,
            safeEvents,
            safeGroups,
            safeReliability,
            safeArtifacts,
            safeFindings,
            statuses,
            coverage,
            bugchecks,
            readiness.Readiness,
            dumps,
            safeDrivers,
            correlation,
            null,
            selection.Candidate.Fingerprint,
            summary,
            null,
            recent,
            storage,
            verifier,
            bootSession,
            wheaEvidence);

        progress?.Report(new DiagnosticProgress("Packaging", "Writing the local schema-v3 report and checksum.", 0.88));
        ReportPackageV3 package = await _reportWriter.WriteV3Async(report, cancellationToken).ConfigureAwait(false);
        string[] failures = statuses
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.State} · {status.Detail}")
            .ToArray();
        return new DiagnosticOperationResultV3(
            package,
            correlation.RelatedDumps,
            correlation.SelectedDump is null && correlation.RelatedDumps.Count > 1,
            failures);
    }

    private async Task<IncidentCandidate?> PollForIncidentAsync(
        DateTimeOffset startedUtc,
        DateTimeOffset disappearedUtc,
        TargetProfile target,
        CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + EvidencePollLimit;
        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            IncidentCandidate? candidate = await FindBestIncidentAsync(
                startedUtc,
                DateTimeOffset.UtcNow,
                target,
                cancellationToken).ConfigureAwait(false);
            if (candidate is not null && candidate.TimeUtc >= disappearedUtc.AddMinutes(-2))
            {
                return candidate;
            }

            await _delayAsync(MonitorInterval, cancellationToken).ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);

        return null;
    }

    private async Task<IncidentCandidate?> FindBestIncidentAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile target,
        CancellationToken cancellationToken)
    {
        WindowsEventCollection events = await _events.CollectWindowAsync(startUtc, endUtc, target, cancellationToken).ConfigureAwait(false);
        ReliabilityCollection reliability = await _reliability.CollectAsync(startUtc, endUtc, target, cancellationToken).ConfigureAwait(false);
        return _incidentDiscovery.Discover(events.Events, reliability.Records, target)
            .OrderByDescending(candidate => candidate.TimeUtc)
            .FirstOrDefault();
    }

    private static IReadOnlyList<DiagnosticFinding> CreateWheaCategoryFindings(IEnumerable<DiagnosticEvent> events)
    {
        return events
            .Select(item => WheaEventDecoder.TryDecode(item, out DecodedWheaEvent? decoded) ? decoded : null)
            .Where(item => item is not null && item.Fields.TryGetValue("CperSectionCategories", out _))
            .Cast<DecodedWheaEvent>()
            .GroupBy(item => item.Fields["CperSectionCategories"], StringComparer.OrdinalIgnoreCase)
            .Select(group => new DiagnosticFinding(
                "whea-cper-" + group.Key.Replace(' ', '-').ToLowerInvariant(),
                35,
                FindingSeverity.Warning,
                FindingConfidence.High,
                "Hardware error record",
                $"WHEA {group.Key} section",
                $"Windows stored {group.Count()} standardized hardware error record{(group.Count() == 1 ? string.Empty : "s")} with {group.Key} section metadata.",
                "The section category can help choose the next diagnostic check.",
                "The record does not establish that a particular component is defective.",
                "Compare repeated records and matching bugcheck or debugger evidence before testing hardware.",
                group.Count()))
            .ToArray();
    }

    private DriverInventory RedactDrivers(DriverInventory drivers) => drivers with
    {
        Drivers = drivers.Drivers.Select(item => item with
        {
            DeviceName = _redactor.Redact(item.DeviceName),
            Manufacturer = _redactor.Redact(item.Manufacturer),
            DriverProvider = _redactor.Redact(item.DriverProvider),
            InfName = _redactor.Redact(item.InfName),
            Signer = _redactor.Redact(item.Signer)
        }).ToArray()
    };

    private static PerformanceSample ToCompatibilitySample(TargetPerformanceSample sample) => new(
        sample.TimestampUtc,
        sample.TargetRunning,
        null,
        "Target",
        sample.SystemCpuPct,
        sample.SystemMemoryUsedGB,
        sample.SystemMemoryAvailableGB,
        sample.SystemCommittedGB,
        sample.SystemCommitLimitGB,
        sample.SystemCommitPct,
        sample.TargetWorkingSetMB,
        sample.TargetPrivateMB,
        sample.TargetCpuPct,
        sample.TargetGpu3DPct,
        sample.TargetGpuMaxEnginePct,
        sample.TargetDedicatedGpuMB,
        sample.TargetSharedGpuMB,
        sample.SampleCollectionMs);

    private static CollectionStatus CreateDriverVerifierStatus(DriverVerifierState verifier)
    {
        CollectionState state = verifier.Status switch
        {
            DriverVerifierStatusKind.Disabled or DriverVerifierStatusKind.Enabled or DriverVerifierStatusKind.Indeterminate => CollectionState.Available,
            DriverVerifierStatusKind.TimedOut => CollectionState.TimedOut,
            DriverVerifierStatusKind.Failed => CollectionState.Error,
            _ => CollectionState.Unavailable
        };
        return new CollectionStatus("Driver Verifier settings", state, verifier.Detail);
    }

    private static SourceCoverage[] BuildCoverage(
        IReadOnlyList<CollectionStatus> statuses,
        IReadOnlyList<DiagnosticEvent> events,
        IReadOnlyList<ReliabilityRecord> reliability,
        IReadOnlyList<CrashArtifact> artifacts,
        IReadOnlyList<DumpCandidate> dumps,
        DriverInventory? drivers,
        CrashReadiness? readiness,
        RecentChangeTimeline? recent = null,
        StorageHealthSnapshot? storage = null,
        DriverVerifierState? verifier = null,
        BootSessionContext? bootSession = null)
    {
        return statuses
            .GroupBy(status => status.Source, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                CollectionStatus status = group.Last();
                int count = status.Source switch
                {
                    string source when source.Contains("boot markers", StringComparison.OrdinalIgnoreCase) =>
                        bootSession?.Records.Count ?? 0,
                    string source when source.Contains("Event Log/System", StringComparison.OrdinalIgnoreCase) =>
                        events.Count(item => item.LogName.Equals("System", StringComparison.OrdinalIgnoreCase)),
                    string source when source.Contains("Event Log/Application", StringComparison.OrdinalIgnoreCase) =>
                        events.Count(item => item.LogName.Equals("Application", StringComparison.OrdinalIgnoreCase)),
                    string source when source.Contains("Kernel-EventTracing", StringComparison.OrdinalIgnoreCase) =>
                        events.Count(item => item.LogName.Equals(
                            KernelEventTracingCatalog.AdminLogName,
                            StringComparison.OrdinalIgnoreCase)),
                    string source when source.Contains("Reliability", StringComparison.OrdinalIgnoreCase) => reliability.Count,
                    string source when source.Contains("artifact", StringComparison.OrdinalIgnoreCase) => artifacts.Count,
                    string source when source.Contains("Dump inventory", StringComparison.OrdinalIgnoreCase) => dumps.Count,
                    string source when source.Contains("Driver inventory", StringComparison.OrdinalIgnoreCase) => drivers?.Drivers.Count ?? 0,
                    string source when source.Contains("Crash readiness", StringComparison.OrdinalIgnoreCase) => readiness is null ? 0 : 1,
                    string source when source.Contains("Windows Update", StringComparison.OrdinalIgnoreCase) => recent?.Records.Count ?? 0,
                    string source when source.Contains("SetupAPI", StringComparison.OrdinalIgnoreCase) => recent?.Records.Count ?? 0,
                    string source when source.Contains("Storage health", StringComparison.OrdinalIgnoreCase) => storage?.Devices.Count ?? 0,
                    string source when source.Contains("Driver Verifier", StringComparison.OrdinalIgnoreCase) => verifier is null ? 0 : 1,
                    _ => 0
                };
                return new SourceCoverage(status.Source, status.State, count, status.Detail);
            })
            .OrderBy(item => item.Source, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void ValidateSearchWindow(IncidentSearchOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.EndUtc < options.StartUtc || options.EndUtc - options.StartUtc > TimeSpan.FromDays(31))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The incident search window must be between zero and 31 days.");
        }
    }

    private static void ValidateSelection(IncidentSelection selection)
    {
        ArgumentNullException.ThrowIfNull(selection);
        if (selection.WindowEndUtc < selection.WindowStartUtc ||
            selection.Candidate.TimeUtc < selection.WindowStartUtc ||
            selection.Candidate.TimeUtc > selection.WindowEndUtc)
        {
            throw new ArgumentException("The incident selection window is invalid.", nameof(selection));
        }
    }

    private static void ValidateTarget(TargetProfile target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.ProcessNames.Count is 0 or > 16 || target.RelatedProcessNames.Count > 32 ||
            target.ProcessNames.Concat(target.RelatedProcessNames).Any(name =>
                string.IsNullOrWhiteSpace(name) ||
                !string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal) ||
                name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
        {
            throw new ArgumentException("The target profile contains an invalid executable name.", nameof(target));
        }

        TargetPrivacyRules privacy = target.EffectivePrivacyRules;
        if (privacy.ReadProcessMemory || privacy.ReadModules || privacy.ReadCommandLines || privacy.ReadInputs ||
            privacy.ReadAntiCheatData || privacy.ExportProcessIds)
        {
            throw new ArgumentException("Only privacy-bounded target profiles are accepted.", nameof(target));
        }
    }

    private static bool IsSensitiveOperationBlocked(TargetProfile? target)
        => ProtectedProcessGuard.IsBlocked(target, IsProcessRunning);

    private static bool IsProcessRunning(string processName)
    {
        Process[] matches = Process.GetProcessesByName(ProtectedProcessGuard.NormalizeProcessName(processName));
        try
        {
            return matches.Any(process =>
            {
                try { return !process.HasExited; }
                catch { return true; }
            });
        }
        finally
        {
            foreach (Process process in matches)
            {
                process.Dispose();
            }
        }
    }

    private static DateTimeOffset EstimateCurrentBootUtc() =>
        DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64));

    private static string CreateSessionId(DateTimeOffset timeUtc) =>
        timeUtc.ToUniversalTime().ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8];

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
