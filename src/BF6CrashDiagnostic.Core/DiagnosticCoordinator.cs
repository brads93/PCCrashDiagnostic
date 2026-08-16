using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

[assembly: InternalsVisibleTo("BF6CrashDiagnostic.Tests")]

namespace BF6CrashDiagnostic.Core;

public sealed class DiagnosticCoordinator : IDisposable
{
    public const string ToolVersion = ReleaseStage.Version;
    private static readonly TimeSpan MonitorSampleInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan PostExitCollectionDelay = TimeSpan.FromSeconds(30);

    private readonly string _dataRoot;
    private readonly WindowsEventCollector _eventCollector;
    private readonly SystemSnapshotCollector _snapshotCollector;
    private readonly ReliabilityCollector _reliabilityCollector;
    private readonly ArtifactCollector _artifactCollector;
    private readonly EventAnalyzer _analyzer;
    private readonly PrivacyRedactor _redactor;
    private readonly ReportWriter _reportWriter;
    private readonly SummaryBuilder _summaryBuilder;
    private readonly ActiveSessionStore _activeStore;
    private readonly SessionSampleJournal _journal;
    private readonly DumpPackager _dumpPackager;
    private readonly Func<CancellationToken, Task<PerformanceSample>>? _monitorSampleOverride;
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;
    private readonly ConcurrentDictionary<string, DumpArtifactIdentity> _eligibleDumps =
        new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public DiagnosticCoordinator(string dataRoot)
        : this(
            dataRoot,
            monitorSampleOverride: null,
            static (delay, cancellationToken) => Task.Delay(delay, cancellationToken),
            useTestOverrides: false)
    {
    }

    internal DiagnosticCoordinator(
        string dataRoot,
        Func<CancellationToken, Task<PerformanceSample>> monitorSampleOverride,
        Func<TimeSpan, CancellationToken, Task> delayAsync)
        : this(dataRoot, monitorSampleOverride, delayAsync, useTestOverrides: true)
    {
    }

    private DiagnosticCoordinator(
        string dataRoot,
        Func<CancellationToken, Task<PerformanceSample>>? monitorSampleOverride,
        Func<TimeSpan, CancellationToken, Task> delayAsync,
        bool useTestOverrides = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (useTestOverrides)
        {
            ArgumentNullException.ThrowIfNull(monitorSampleOverride);
        }

        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The diagnostic data root must be an absolute path.", nameof(dataRoot));
        }

        _dataRoot = Path.GetFullPath(dataRoot);
        _eventCollector = new WindowsEventCollector(
            anchorLookback: TimeSpan.FromHours(48),
            evidenceBeforeAnchor: TimeSpan.FromMinutes(15),
            evidenceAfterAnchor: TimeSpan.FromMinutes(10));
        _snapshotCollector = new SystemSnapshotCollector();
        _reliabilityCollector = new ReliabilityCollector();
        _artifactCollector = new ArtifactCollector();
        _analyzer = new EventAnalyzer();
        _redactor = new PrivacyRedactor();
        _reportWriter = new ReportWriter(_dataRoot);
        _summaryBuilder = new SummaryBuilder();
        _activeStore = new ActiveSessionStore();
        _journal = new SessionSampleJournal();
        _dumpPackager = new DumpPackager();
        _monitorSampleOverride = monitorSampleOverride;
        _delayAsync = delayAsync ?? throw new ArgumentNullException(nameof(delayAsync));
    }

    public string DataRoot => _dataRoot;

    public async Task<SystemSnapshotCollection> GetSystemSnapshotAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<DiagnosticOperationResult> AnalyzeLatestAsync(
        DateTimeOffset? manualCrashTime = null,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        progress?.Report(new DiagnosticProgress("Crash records", manualCrashTime is null
            ? "Searching the last 48 hours for the most recent crash record…"
            : "Collecting records around the selected time…", 0.08));

        Task<SystemSnapshotCollection> snapshotTask = _snapshotCollector.CollectAsync(cancellationToken);
        WindowsEventCollection eventCollection = await _eventCollector
            .CollectRetrospectiveAsync(manualCrashTime, cancellationToken)
            .ConfigureAwait(false);
        SystemSnapshotCollection snapshot = await snapshotTask.ConfigureAwait(false);

        progress?.Report(new DiagnosticProgress("Windows records", "Reading Reliability history and crash file details…", 0.42));
        ReliabilityCollection reliability = await _reliabilityCollector
            .CollectAsync(eventCollection.WindowStartUtc, eventCollection.WindowEndUtc, cancellationToken)
            .ConfigureAwait(false);
        ArtifactCollection artifacts = await _artifactCollector
            .CollectAsync(eventCollection.WindowStartUtc, eventCollection.WindowEndUtc, cancellationToken)
            .ConfigureAwait(false);

        progress?.Report(new DiagnosticProgress("Analysis", "Preparing findings and redacting personal information…", 0.7));
        DiagnosticOperationResult result = await BuildAndWriteAsync(
            CreateSessionId(eventCollection.WindowStartUtc),
            DiagnosticMode.Retrospective,
            eventCollection.WindowStartUtc,
            eventCollection.WindowEndUtc,
            "RetrospectiveAnalysisCompleted",
            eventCollection.Anchor ?? _analyzer.SelectCrashAnchor(eventCollection.Events),
            snapshot.Snapshot,
            snapshot.Snapshot,
            [],
            eventCollection.Events,
            reliability,
            artifacts,
            [.. snapshot.Statuses, .. eventCollection.Statuses],
            progress,
            cancellationToken).ConfigureAwait(false);

        progress?.Report(new DiagnosticProgress("Report ready", "The local report is ready for review.", 1));
        return result;
    }

    public async Task<DiagnosticOperationResult> MonitorNextSessionAsync(
        IProgress<DiagnosticProgress>? progress = null,
        IProgress<PerformanceSample>? telemetry = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        DateTimeOffset startedUtc = DateTimeOffset.UtcNow;
        string sessionId = CreateSessionId(startedUtc);
        string sessionFolder = PathSafety.EnsureDirectory(
            _reportWriter.SessionsRoot,
            Path.Combine(_reportWriter.SessionsRoot, sessionId));

        SystemSnapshotCollection startSnapshot = await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
        DateTimeOffset? bootUtc = startSnapshot.Snapshot.LastBootUtc ?? EstimateCurrentBootUtc();
        var marker = new ActiveSessionMarker(
            1,
            sessionId,
            Environment.ProcessId,
            startedUtc,
            bootUtc,
            startedUtc,
            sessionFolder,
            "BF6",
            DiagnosticMode.Monitor);
        await _activeStore.WriteAsync(marker, _reportWriter.SessionsRoot, cancellationToken).ConfigureAwait(false);

        var samples = new List<PerformanceSample>();
        bool observedBf6 = false;
        bool finalizing = false;
        using PerformanceSampler? sampler = _monitorSampleOverride is null ? new PerformanceSampler("BF6") : null;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                PerformanceSample sample = _monitorSampleOverride is null
                    ? await sampler!.SampleAsync(cancellationToken).ConfigureAwait(false)
                    : await _monitorSampleOverride(cancellationToken).ConfigureAwait(false);
                samples.Add(sample);
                observedBf6 |= sample.BF6Running;
                telemetry?.Report(sample);
                await _journal.AppendAsync(sessionFolder, sample, cancellationToken).ConfigureAwait(false);
                marker = marker with { LastSampleUtc = sample.TimestampUtc };
                await _activeStore.WriteAsync(marker, _reportWriter.SessionsRoot, cancellationToken).ConfigureAwait(false);

                if (sample.BF6Running)
                {
                    progress?.Report(new DiagnosticProgress(
                        "Monitoring BF6",
                        $"BF6 is running (PID {sample.BF6Pid}); sampling every five seconds…"));
                }
                else if (!observedBf6)
                {
                    progress?.Report(new DiagnosticProgress("Waiting for BF6", "Start BF6 when ready."));
                }
                else
                {
                    break;
                }

                await _delayAsync(MonitorSampleInterval, cancellationToken).ConfigureAwait(false);
            }

            finalizing = true;
            progress?.Report(new DiagnosticProgress("Finalizing", "BF6 exited. Waiting 30 seconds for Windows to finish writing crash records…", 0.2));
            await _delayAsync(PostExitCollectionDelay, cancellationToken).ConfigureAwait(false);
            DateTimeOffset endedUtc = DateTimeOffset.UtcNow;

            WindowsEventCollection events = await _eventCollector.CollectWindowAsync(startedUtc, endedUtc, cancellationToken).ConfigureAwait(false);
            CrashAnchor? anchor = _analyzer.SelectCrashAnchor(events.Events);
            ReliabilityCollection reliability = await _reliabilityCollector.CollectAsync(startedUtc, endedUtc, cancellationToken).ConfigureAwait(false);
            ArtifactCollection artifacts = await _artifactCollector.CollectAsync(startedUtc, endedUtc, cancellationToken).ConfigureAwait(false);
            SystemSnapshotCollection endSnapshot = await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);

            DiagnosticOperationResult result = await BuildAndWriteAsync(
                sessionId,
                DiagnosticMode.Monitor,
                startedUtc,
                endedUtc,
                "BF6Exited",
                anchor,
                startSnapshot.Snapshot,
                endSnapshot.Snapshot,
                samples,
                events.Events,
                reliability,
                artifacts,
                [.. startSnapshot.Statuses, .. events.Statuses, .. endSnapshot.Statuses],
                progress,
                cancellationToken).ConfigureAwait(false);
            _activeStore.Complete(sessionFolder, _reportWriter.SessionsRoot);
            progress?.Report(new DiagnosticProgress("Report ready", "Monitoring completed and the report is ready for review.", 1));
            return result;
        }
        catch (OperationCanceledException)
        {
            if (!observedBf6 && !finalizing)
            {
                _activeStore.Complete(sessionFolder, _reportWriter.SessionsRoot);
            }

            throw;
        }
    }

    public async Task<IReadOnlyList<DiagnosticOperationResult>> RecoverInterruptedSessionsAsync(
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        DateTimeOffset currentBootUtc = EstimateCurrentBootUtc();
        IReadOnlyList<RecoveryCandidate> candidates = await _activeStore
            .FindStaleAsync(_reportWriter.SessionsRoot, currentBootUtc, cancellationToken)
            .ConfigureAwait(false);
        var results = new List<DiagnosticOperationResult>();

        foreach (RecoveryCandidate candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new DiagnosticProgress("Recovery", $"Recovering interrupted session {candidate.Marker.SessionId}…"));
            IReadOnlyList<PerformanceSample> samples = await _journal.ReadAsync(candidate.Marker.SessionFolder, cancellationToken).ConfigureAwait(false);
            DateTimeOffset lastRecordedSample = samples.Count == 0
                ? candidate.Marker.LastSampleUtc
                : samples.Max(sample => sample.TimestampUtc);
            DateTimeOffset evidenceEnd = (lastRecordedSample > candidate.Marker.LastSampleUtc
                    ? lastRecordedSample
                    : candidate.Marker.LastSampleUtc) +
                                         (candidate.BootChanged ? TimeSpan.FromMinutes(10) : TimeSpan.FromSeconds(30));
            if (evidenceEnd > DateTimeOffset.UtcNow)
            {
                evidenceEnd = DateTimeOffset.UtcNow;
            }

            WindowsEventCollection events = await _eventCollector
                .CollectWindowAsync(candidate.Marker.StartedUtc, evidenceEnd, cancellationToken)
                .ConfigureAwait(false);
            ReliabilityCollection reliability = await _reliabilityCollector
                .CollectAsync(candidate.Marker.StartedUtc, evidenceEnd, cancellationToken)
                .ConfigureAwait(false);
            ArtifactCollection artifacts = await _artifactCollector
                .CollectAsync(candidate.Marker.StartedUtc, evidenceEnd, cancellationToken)
                .ConfigureAwait(false);
            SystemSnapshotCollection snapshot = await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);

            DiagnosticOperationResult result = await BuildAndWriteAsync(
                candidate.Marker.SessionId,
                DiagnosticMode.Recovered,
                candidate.Marker.StartedUtc,
                evidenceEnd,
                candidate.CompletionReason,
                _analyzer.SelectCrashAnchor(events.Events),
                null,
                snapshot.Snapshot,
                samples,
                events.Events,
                reliability,
                artifacts,
                [.. events.Statuses, .. snapshot.Statuses],
                progress,
                cancellationToken).ConfigureAwait(false);
            _activeStore.Complete(candidate.Marker.SessionFolder, _reportWriter.SessionsRoot);
            results.Add(result);
        }

        return results;
    }

    public Task<string> PackageDumpAsync(
        string dumpPath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        string fullDumpPath = Path.GetFullPath(dumpPath);
        if (!_eligibleDumps.TryGetValue(fullDumpPath, out DumpArtifactIdentity? dumpIdentity))
        {
            throw new InvalidOperationException("The crash dump is not bound to a completed analysis in this app session.");
        }

        return _dumpPackager.PackageAsync(
            dumpIdentity,
            _reportWriter.ReportsRoot,
            IsBf6Running,
            progress,
            cancellationToken);
    }

    public void Dispose()
    {
        _disposed = true;
    }

    private async Task<DiagnosticOperationResult> BuildAndWriteAsync(
        string sessionId,
        DiagnosticMode mode,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        string completionReason,
        CrashAnchor? rawAnchor,
        SystemSnapshot? startSnapshot,
        SystemSnapshot? endSnapshot,
        IReadOnlyList<PerformanceSample> samples,
        IReadOnlyList<DiagnosticEvent> rawEvents,
        ReliabilityCollection rawReliability,
        ArtifactCollection rawArtifacts,
        IReadOnlyList<CollectionStatus> initialStatuses,
        IProgress<DiagnosticProgress>? progress,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<DuplicateEventGroup> rawGroups = _analyzer.GroupDuplicates(rawEvents);
        IReadOnlyList<DiagnosticFinding> rawFindings = _analyzer.Analyze(
            rawAnchor,
            rawEvents,
            rawGroups,
            rawReliability.Records,
            rawArtifacts.Artifacts,
            samples,
            TargetProfile.Battlefield6);

        DiagnosticEvent[] safeEvents = rawEvents.Select(_redactor.RedactEvent).ToArray();
        DuplicateEventGroup[] safeGroups = rawGroups.Select(_redactor.RedactGroup).ToArray();
        ReliabilityRecord[] safeReliability = rawReliability.Records.Select(_redactor.RedactReliability).ToArray();
        CrashArtifact[] safeArtifacts = rawArtifacts.Artifacts.Select(_redactor.RedactArtifact).ToArray();
        DiagnosticFinding[] safeFindings = rawFindings.Select(_redactor.RedactFinding).ToArray();
        CollectionStatus[] safeStatuses = initialStatuses
            .Concat(rawReliability.Statuses)
            .Concat(rawArtifacts.Statuses)
            .Select(_redactor.RedactStatus)
            .GroupBy(status => new { status.Source, status.State, status.Detail })
            .Select(group => group.First())
            .ToArray();
        CrashAnchor? safeAnchor = _redactor.RedactAnchor(rawAnchor);

        string summary = _summaryBuilder.Build(
            sessionId,
            mode,
            startUtc,
            endUtc,
            completionReason,
            safeAnchor,
            samples,
            safeArtifacts,
            safeFindings,
            safeStatuses);
        var report = new DiagnosticReport(
            2,
            ToolVersion,
            sessionId,
            mode,
            startUtc,
            endUtc,
            completionReason,
            safeAnchor,
            startSnapshot,
            endSnapshot,
            samples,
            safeEvents,
            safeGroups,
            safeReliability,
            safeArtifacts,
            safeFindings,
            safeStatuses,
            summary);

        progress?.Report(new DiagnosticProgress("Packaging", "Creating the report ZIP and checksum…", 0.88));
        ReportPackage package = await _reportWriter.WriteAsync(report, cancellationToken).ConfigureAwait(false);
        DumpArtifactIdentity? eligibleDumpIdentity = ChooseEligibleDump(rawArtifacts.Artifacts, rawAnchor);
        if (eligibleDumpIdentity is not null)
        {
            _eligibleDumps[eligibleDumpIdentity.FullPath] = eligibleDumpIdentity;
        }

        string? eligibleDump = eligibleDumpIdentity?.FullPath;
        string[] failures = safeStatuses
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.State} · {status.Detail}")
            .ToArray();
        return new DiagnosticOperationResult(package, eligibleDump, failures);
    }

    private static DumpArtifactIdentity? ChooseEligibleDump(
        IReadOnlyList<CrashArtifact> artifacts,
        CrashAnchor? anchor)
    {
        foreach (CrashArtifact artifact in artifacts
            .Where(artifact => artifact.MayContainSensitiveData &&
                               !string.IsNullOrWhiteSpace(artifact.OriginalPath) &&
                               Path.GetExtension(artifact.OriginalPath).Equals(".dmp", StringComparison.OrdinalIgnoreCase))
            .OrderBy(artifact => artifact.Kind.Contains("minidump", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(artifact => anchor is null ? TimeSpan.Zero : (artifact.LastWriteUtc - anchor.TimeUtc).Duration()))
        {
            if (DumpPackager.TryCaptureIdentity(
                    artifact.OriginalPath!,
                    artifact.SizeBytes,
                    artifact.LastWriteUtc,
                    out DumpArtifactIdentity identity))
            {
                return identity;
            }
        }

        return null;
    }

    private static bool IsBf6Running()
    {
        try
        {
            Process[] matches = Process.GetProcessesByName("BF6");
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
        catch
        {
            return true;
        }
    }

    private static DateTimeOffset EstimateCurrentBootUtc() =>
        DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64));

    private static string CreateSessionId(DateTimeOffset startUtc) =>
        startUtc.ToUniversalTime().ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8];

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
