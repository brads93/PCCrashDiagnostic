using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core;

/// <summary>
/// Incident- and target-based v3 coordinator. Legacy v2 entry points remain available
/// through <see cref="DiagnosticCoordinator"/> only for report compatibility.
/// </summary>
public sealed class PCCrashDiagnosticCoordinator : IDisposable
{
    public const string ToolVersion = ReleaseStage.Version;
    public const string ProductName = "PC Crash Diagnostic";
    private static readonly TimeSpan MonitorInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan EvidencePollLimit = TimeSpan.FromSeconds(60);

    private readonly string _dataRoot;
    private readonly WindowsEventCollector _eventCollector = new();
    private readonly SystemSnapshotCollector _snapshotCollector = new();
    private readonly ReliabilityCollector _reliabilityCollector = new();
    private readonly ArtifactCollector _artifactCollector = new();
    private readonly CrashReadinessCollector _readinessCollector;
    private readonly Func<CancellationToken, Task<CrashReadinessCollection>> _collectReadinessAsync;
    private readonly ICrashCaptureConfigurationStore _crashCaptureConfigurationStore;
    private readonly CrashCaptureReceiptStore _crashCaptureReceiptStore;
    private readonly DumpInventoryCollector _dumpCollector;
    private readonly DriverDeviceCollector _driverCollector = new();
    private readonly DumpQualityCollector _dumpQualityCollector;
    private readonly Func<IReadOnlyList<DumpChkInstallation>> _discoverInstalledDumpCheckers;
    private readonly RecentChangeCollector _recentChangeCollector = new();
    private readonly StorageHealthCollector _storageHealthCollector = new();
    private readonly DriverVerifierCollector _driverVerifierCollector = new();
    private readonly IncidentDiscovery _incidentDiscovery = new();
    private readonly CrashCorrelator _correlator = new();
    private readonly EventAnalyzer _eventAnalyzer = new();
    private readonly ExtendedEvidenceAnalyzer _extendedEvidenceAnalyzer = new();
    private readonly PrivacyRedactor _redactor = new();
    private readonly ReportWriter _reportWriter;
    private readonly SummaryBuilderV3 _summaryBuilder = new();
    private readonly TargetSessionStore _activeSessions = new();
    private readonly TargetSampleJournal _sampleJournal = new();
    private readonly DumpPackager _dumpPackager = new();
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;
    private readonly IElevatedHelperClient _elevatedHelperClient;
    private readonly ProtectedEvidenceHelper _protectedEvidenceHelper;
    private readonly ElevatedHelperRequestStore _helperRequestStore;
    private readonly Func<bool> _isBf6RunningFailClosed;
    private readonly Func<string, bool> _protectedDumpPathValidator;
    private readonly ConcurrentDictionary<string, BoundDump> _boundDumps = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public PCCrashDiagnosticCoordinator(string dataRoot)
        : this(dataRoot, static (delay, token) => Task.Delay(delay, token))
    {
    }

    internal PCCrashDiagnosticCoordinator(
        string dataRoot,
        Func<TimeSpan, CancellationToken, Task> delayAsync)
        : this(dataRoot, delayAsync, null, null, null, null, null, null)
    {
    }

    internal PCCrashDiagnosticCoordinator(
        string dataRoot,
        Func<TimeSpan, CancellationToken, Task> delayAsync,
        IElevatedHelperClient? elevatedHelperClient,
        ProtectedEvidenceHelper? protectedEvidenceHelper,
        ElevatedHelperRequestStore? helperRequestStore,
        Func<bool>? isBf6RunningFailClosed,
        Func<string, bool>? protectedDumpPathValidator,
        DumpInventoryCollector? dumpInventoryCollector = null,
        ICrashCaptureConfigurationStore? crashCaptureConfigurationStore = null,
        CrashCaptureReceiptStore? crashCaptureReceiptStore = null,
        Func<CancellationToken, Task<CrashReadinessCollection>>? collectReadinessAsync = null,
        DumpQualityCollector? dumpQualityCollector = null,
        Func<IReadOnlyList<DumpChkInstallation>>? discoverInstalledDumpCheckers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The diagnostic data root must be absolute.", nameof(dataRoot));
        }

        _dataRoot = Path.GetFullPath(dataRoot);
        _reportWriter = new ReportWriter(_dataRoot);
        _delayAsync = delayAsync ?? throw new ArgumentNullException(nameof(delayAsync));
        _isBf6RunningFailClosed = isBf6RunningFailClosed ?? IsBf6RunningFailClosed;
        _dumpCollector = dumpInventoryCollector ?? new DumpInventoryCollector();
        _crashCaptureConfigurationStore = crashCaptureConfigurationStore ?? new WindowsCrashCaptureConfigurationStore();
        _crashCaptureReceiptStore = crashCaptureReceiptStore ?? new CrashCaptureReceiptStore();
        _readinessCollector = new CrashReadinessCollector(
            TimeProvider.System,
            _crashCaptureConfigurationStore,
            _crashCaptureReceiptStore);
        _collectReadinessAsync = collectReadinessAsync ?? _readinessCollector.CollectAsync;
        _dumpQualityCollector = dumpQualityCollector ?? new DumpQualityCollector();
        _discoverInstalledDumpCheckers = discoverInstalledDumpCheckers ?? (() => new DumpChkDiscovery().Discover());
        _helperRequestStore = helperRequestStore ?? new ElevatedHelperRequestStore();
        ProtectedEvidenceRoots protectedRoots = ProtectedEvidenceRoots.CreateDefault();
        _protectedEvidenceHelper = protectedEvidenceHelper ?? new ProtectedEvidenceHelper();
        _elevatedHelperClient = elevatedHelperClient ?? new ElevatedHelperClient(
            Path.Combine(AppContext.BaseDirectory, "PCCrashDiagnostic.ElevatedHelper.exe"),
            _helperRequestStore);
        _protectedDumpPathValidator = protectedDumpPathValidator ?? (path =>
            ProtectedEvidenceHelper.TryClassifyApprovedDumpPath(path, protectedRoots, out _, out _));
    }

    public string DataRoot => _dataRoot;

    internal string HelperRequestRoot => _helperRequestStore.Root;

    internal string ProtectedStagingRoot => _protectedEvidenceHelper.StagingRoot;

    public IncidentLibrary IncidentLibrary => new(_dataRoot);

    public Task<SystemSnapshotCollection> GetSystemSnapshotAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _snapshotCollector.CollectAsync(cancellationToken);
    }

    public async Task<CrashCapturePlan> PreviewCrashCapturePreparationAsync(
        DiagnosticOperationResultV3 boundResult,
        CrashCapturePreset preset = CrashCapturePreset.AutomaticMemoryDump,
        bool includePerAppCapture = false,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateConfigurationReportBinding(boundResult);
        if (preset != CrashCapturePreset.AutomaticMemoryDump)
        {
            throw new ArgumentOutOfRangeException(nameof(preset));
        }
        if (includePerAppCapture && !ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            throw new NotSupportedException("Per-application crash capture is not enabled in this build.");
        }

        DiagnosticReportV3 report = boundResult.Package.Report;
        if (IsSensitiveOperationBlocked(report.TargetProfile))
        {
            throw new InvalidOperationException(
                "Crash-capture preparation is unavailable while Battlefield 6 or the protected target is running.");
        }

        CrashReadinessCollection before = await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
        PageFileConfigurationSnapshot pageFileConfiguration =
            _crashCaptureConfigurationStore.ReadPageFileConfiguration();
        var changes = new List<CrashCaptureChange>();
        foreach ((CrashCaptureSetting setting, StoredConfigurationValue desired) in AutomaticCrashCapturePresetValues())
        {
            cancellationToken.ThrowIfCancellationRequested();
            StoredConfigurationValue current = _crashCaptureConfigurationStore.ReadCrashSetting(setting);
            if (!CanRestoreRegistryValueExactly(current))
            {
                throw new InvalidDataException(
                    $"Windows exposed {setting} in a registry format this app cannot restore exactly. No UAC request was started.");
            }

            if (current != desired)
            {
                changes.Add(ToChange(setting, current, desired));
            }
        }

        CrashCaptureEnvironmentSnapshot environment = _crashCaptureConfigurationStore.ReadEnvironment();
        if (CrashReadinessCollector.AutomaticManagementEnabledWithoutBootBacking(environment))
        {
            throw new InvalidOperationException(
                "Windows reports automatic page-file management, but no boot-volume page file is configured or active. Restart Windows or repair the page-file configuration before preparing crash capture.");
        }

        bool needsSystemManagedPagefile =
            CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(environment);
        if (needsSystemManagedPagefile)
        {
            StoredConfigurationValue current = _crashCaptureConfigurationStore.ReadCrashSetting(
                CrashCaptureSetting.AutomaticManagedPagefile);
            changes.Add(ToChange(
                CrashCaptureSetting.AutomaticManagedPagefile,
                current,
                new StoredConfigurationValue(true, "true"),
                pageFileConfiguration));
        }

        DateTimeOffset nowUtc = DateTimeOffset.UtcNow;
        WerLocalDumpPlan? werPlan = includePerAppCapture
            ? CreateWerLocalDumpPlan(boundResult, executableName: null, nowUtc)
            : null;
        return new CrashCapturePlan(
            1,
            NewConfigurationId(),
            report.SessionId,
            boundResult.Package.Sha256.ToLowerInvariant(),
            nowUtc,
            nowUtc.AddMinutes(10),
            preset,
            changes,
            before.Readiness,
            RequiresElevation: changes.Count != 0 || werPlan is not null,
            RequiresRestart: changes.Count != 0,
            werPlan,
            report.TargetProfile);
    }

    public async Task<CrashCapturePreparationResult> PrepareCrashCaptureAsync(
        DiagnosticOperationResultV3 boundResult,
        CrashCapturePlan preview,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(preview);
        ValidateConfigurationReportBinding(boundResult);
        if (preview.WerLocalDumpPlan is not null && !ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            return FailedPreparation(
                "Per-application crash capture is not enabled in this build. Existing saved settings can still be restored.",
                preview,
                preview.BeforeReadiness);
        }

        ValidatePlanBinding(boundResult, preview);
        bool IsBlocked() => IsSensitiveOperationBlocked(preview.TargetProfile ?? boundResult.Package.Report.TargetProfile);
        if (IsBlocked())
        {
            return FailedPreparation(
                "Crash-capture preparation is unavailable while Battlefield 6 or the protected target is running.",
                preview,
                preview.BeforeReadiness);
        }

        if (!preview.RequiresElevation || preview.Changes.Count == 0 && preview.WerLocalDumpPlan is null)
        {
            CrashReadinessCollection current = await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
            return new CrashCapturePreparationResult(
                true,
                "Windows crash capture already matches the selected preset.",
                preview,
                null,
                null,
                preview.BeforeReadiness,
                current.Readiness,
                current.Readiness.ActivationState,
                false,
                false);
        }

        progress?.Report(new DiagnosticProgress(
            "Preparing crash capture",
            "Waiting for Windows administrator approval…",
            0.15));
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.ApplyCrashCapturePlan,
            null,
            null,
            null,
            null,
            false,
            false,
            false,
            CrashCapturePlan: preview);
        ProtectedEvidenceResponse response = await _elevatedHelperClient.ExecuteAsync(
            request,
            IsBlocked,
            NormalizeHelperTimeout(helperTimeout),
            cancellationToken).ConfigureAwait(false);
        if (!response.Succeeded)
        {
            return new CrashCapturePreparationResult(
                false,
                response.Message,
                preview,
                null,
                null,
                preview.BeforeReadiness,
                null,
                response.RollbackAttempted
                    ? response.RollbackSucceeded
                        ? CrashCaptureActivationState.FailedRolledBack
                        : CrashCaptureActivationState.FailedRollbackIncomplete
                    : CrashCaptureActivationState.Unknown,
                response.RollbackAttempted,
                response.RollbackSucceeded);
        }

        CrashCaptureReceipt receipt = ValidateCrashCaptureApplyResponse(response, preview);
        if (!AppliedConfigurationStillMatches(receipt))
        {
            CrashReadinessCollection changedCollection =
                await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
            return new CrashCapturePreparationResult(
                false,
                "Windows or Group Policy changed the crash-capture configuration immediately after setup. The app did not mark it ready; review the current settings before retrying.",
                preview,
                receipt,
                receipt.WerLocalDumpReceipt,
                preview.BeforeReadiness,
                changedCollection.Readiness,
                CrashCaptureActivationState.Unknown,
                false,
                false);
        }

        CrashReadinessCollection afterCollection = await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
        if (!AppliedConfigurationStillMatches(receipt))
        {
            return new CrashCapturePreparationResult(
                false,
                "Windows or Group Policy changed the crash-capture configuration while readiness was being checked. The app did not mark it ready.",
                preview,
                receipt,
                receipt.WerLocalDumpReceipt,
                preview.BeforeReadiness,
                afterCollection.Readiness,
                CrashCaptureActivationState.Unknown,
                false,
                false);
        }

        CrashReadiness after = receipt.ActivationState == CrashCaptureActivationState.PendingRestart
            ? afterCollection.Readiness with
            {
                Assessment = CrashReadinessState.PendingRestart,
                AssessmentDetail = "Crash-capture settings changed after the current Windows boot; restart is required.",
                ActivationState = CrashCaptureActivationState.PendingRestart,
                ConfigurationAppliedUtc = receipt.AppliedUtc
            }
            : afterCollection.Readiness;
        progress?.Report(new DiagnosticProgress(
            "Crash capture prepared",
            response.Message,
            1));
        return new CrashCapturePreparationResult(
            true,
            response.Message,
            preview,
            receipt,
            response.WerLocalDumpReceipt,
            preview.BeforeReadiness,
            after,
            receipt.ActivationState,
            false,
            false);
    }

    public async Task<CrashCapturePreparationResult> RestoreCrashCaptureAsync(
        CrashCaptureReceipt receipt,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(receipt);
        bool IsBlocked() => IsSensitiveOperationBlocked(receipt.TargetProfile);
        if (IsBlocked())
        {
            return FailedPreparation(
                "Crash-capture settings cannot be restored while Battlefield 6 or the protected target is running.");
        }

        CrashReadinessCollection before = await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
        progress?.Report(new DiagnosticProgress("Restoring settings", "Waiting for Windows administrator approval…", 0.15));
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.RestoreCrashCapturePlan,
            null,
            null,
            null,
            null,
            false,
            false,
            false,
            ConfigurationReceiptId: receipt.ReceiptId);
        ProtectedEvidenceResponse response = await _elevatedHelperClient.ExecuteAsync(
            request,
            IsBlocked,
            NormalizeHelperTimeout(helperTimeout),
            cancellationToken).ConfigureAwait(false);
        if (!response.Succeeded)
        {
            return new CrashCapturePreparationResult(
                false,
                response.Message,
                null,
                receipt,
                receipt.WerLocalDumpReceipt,
                before.Readiness,
                null,
                response.RollbackAttempted
                    ? response.RollbackSucceeded
                        ? CrashCaptureActivationState.FailedRolledBack
                        : CrashCaptureActivationState.FailedRollbackIncomplete
                    : CrashCaptureActivationState.Unknown,
                response.RollbackAttempted,
                response.RollbackSucceeded);
        }

        CrashCaptureReceipt restored = response.CrashCaptureReceipt is { Restored: true } candidate &&
                                         string.Equals(candidate.ReceiptId, receipt.ReceiptId, StringComparison.Ordinal)
            ? candidate
            : throw new InvalidDataException("The elevated helper returned an invalid crash-capture restore receipt.");
        if (!PreviousConfigurationStillMatches(restored))
        {
            CrashReadinessCollection changedCollection =
                await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
            return new CrashCapturePreparationResult(
                false,
                "Windows or Group Policy changed the crash-capture configuration immediately after restore. The app did not mark the restore verified.",
                null,
                restored,
                restored.WerLocalDumpReceipt,
                before.Readiness,
                changedCollection.Readiness,
                CrashCaptureActivationState.Unknown,
                false,
                false);
        }

        CrashReadinessCollection afterCollection = await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
        if (!PreviousConfigurationStillMatches(restored))
        {
            return new CrashCapturePreparationResult(
                false,
                "Windows or Group Policy changed the crash-capture configuration while readiness was being checked. The app did not mark the restore verified.",
                null,
                restored,
                restored.WerLocalDumpReceipt,
                before.Readiness,
                afterCollection.Readiness,
                CrashCaptureActivationState.Unknown,
                false,
                false);
        }

        CrashReadiness after = restored.ActivationState == CrashCaptureActivationState.PendingRestart
            ? afterCollection.Readiness with
            {
                Assessment = CrashReadinessState.PendingRestart,
                AssessmentDetail = "The prior crash-capture settings were restored after the current boot; restart is required.",
                ActivationState = CrashCaptureActivationState.PendingRestart,
                ConfigurationAppliedUtc = restored.RestoredUtc
            }
            : afterCollection.Readiness;
        progress?.Report(new DiagnosticProgress("Settings restored", response.Message, 1));
        return new CrashCapturePreparationResult(
            true,
            response.Message,
            null,
            restored,
            restored.WerLocalDumpReceipt,
            before.Readiness,
            after,
            restored.ActivationState,
            false,
            false);
    }

    public Task<CrashCapturePreparationResult> RestoreCrashCaptureAsync(
        DiagnosticOperationResultV3 boundResult,
        CrashCaptureReceipt receipt,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ValidateConfigurationReportBinding(boundResult);
        if (!string.Equals(receipt.ReportSessionId, boundResult.Package.Report.SessionId, StringComparison.Ordinal) ||
            !string.Equals(receipt.ReportSha256, boundResult.Package.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The crash-capture receipt was not bound to this report.");
        }

        return RestoreCrashCaptureAsync(receipt, progress, helperTimeout, cancellationToken);
    }

    public RestorableConfigurationReceipts DiscoverRestorableConfigurationReceipts()
    {
        ThrowIfDisposed();
        ReceiptStoreDiscovery candidates = _crashCaptureReceiptStore.DiscoverCandidates();
        var warnings = new List<string>(candidates.Warnings);
        int invalid = 0;

        CrashCaptureReceipt? crashReceipt = null;
        foreach (CrashCaptureReceipt candidate in candidates.CrashReceipts)
        {
            if (_protectedEvidenceHelper.TryValidateCrashReceipt(candidate, out _) &&
                AppliedConfigurationStillMatches(candidate))
            {
                crashReceipt = candidate;
                break;
            }

            invalid++;
        }

        string? embeddedWerReceiptId = crashReceipt?.WerLocalDumpReceipt?.ReceiptId;
        var werReceipts = new List<WerLocalDumpReceipt>();
        var seenExecutables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (WerLocalDumpReceipt candidate in candidates.WerReceipts)
        {
            if (!_protectedEvidenceHelper.TryValidateWerReceipt(candidate, out _) ||
                !WerConfigurationStillMatches(candidate))
            {
                invalid++;
                continue;
            }

            if (string.Equals(candidate.ReceiptId, embeddedWerReceiptId, StringComparison.OrdinalIgnoreCase) ||
                !seenExecutables.Add(candidate.ExecutableName))
            {
                continue;
            }

            werReceipts.Add(candidate);
        }

        if (invalid > 0)
        {
            warnings.Add($"{invalid} stale or invalid saved configuration receipt(s) were ignored.");
        }

        return new RestorableConfigurationReceipts(crashReceipt, werReceipts, warnings);
    }

    private bool WerConfigurationStillMatches(WerLocalDumpReceipt receipt)
    {
        try
        {
            return WerConfigurationComparison.Matches(
                _crashCaptureConfigurationStore.ReadWerSettings(receipt.ExecutableName),
                AppliedWerSettings(receipt));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          InvalidDataException or System.Management.ManagementException or
                                          System.ComponentModel.Win32Exception or ArgumentException)
        {
            return false;
        }
    }

    public Task<CrashCapturePreparationResult> RestoreLatestCrashCaptureAsync(
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        RestorableConfigurationReceipts discovery = DiscoverRestorableConfigurationReceipts();
        return discovery.CrashCaptureReceipt is { } receipt
            ? RestoreCrashCaptureAsync(receipt, progress, helperTimeout, cancellationToken)
            : Task.FromResult(FailedPreparation("No saved crash-capture settings are waiting to be restored."));
    }

    public Task<CrashCapturePreparationResult> RestoreCrashCaptureAsync(
        string persistedReceiptId,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        string normalized;
        try
        {
            normalized = CrashCaptureReceiptStore.NormalizeReceiptId(persistedReceiptId);
        }
        catch (ArgumentException)
        {
            return Task.FromResult(FailedPreparation("The saved crash-capture receipt id was invalid."));
        }

        CrashCaptureReceipt? receipt = DiscoverRestorableConfigurationReceipts().CrashCaptureReceipt;
        return receipt is not null && string.Equals(receipt.ReceiptId, normalized, StringComparison.OrdinalIgnoreCase)
            ? RestoreCrashCaptureAsync(receipt, progress, helperTimeout, cancellationToken)
            : Task.FromResult(FailedPreparation("The saved crash-capture receipt was unavailable or no longer restorable."));
    }

    public Task<WerLocalDumpPlan> PreviewWerLocalDumpPlanAsync(
        DiagnosticOperationResultV3 boundResult,
        string? executableName = null,
        bool ordinaryAppConfirmed = false,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            throw new NotSupportedException("Per-application crash capture is not enabled in this build.");
        }
        cancellationToken.ThrowIfCancellationRequested();
        ValidateConfigurationReportBinding(boundResult);
        if (IsSensitiveOperationBlocked(boundResult.Package.Report.TargetProfile))
        {
            throw new InvalidOperationException(
                "Per-application dump setup is unavailable while Battlefield 6 or the protected target is running.");
        }

        return Task.FromResult(CreateWerLocalDumpPlan(
            boundResult,
            executableName,
            DateTimeOffset.UtcNow,
            ordinaryAppConfirmed));
    }

    public async Task<CrashCapturePreparationResult> ApplyWerLocalDumpPlanAsync(
        DiagnosticOperationResultV3 boundResult,
        WerLocalDumpPlan plan,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            throw new NotSupportedException("Per-application crash capture is not enabled in this build.");
        }
        ArgumentNullException.ThrowIfNull(plan);
        ValidateConfigurationReportBinding(boundResult);
        ValidateWerPlanBinding(boundResult, plan);
        bool IsBlocked() => IsSensitiveOperationBlocked(plan.TargetProfile ?? boundResult.Package.Report.TargetProfile);
        if (IsBlocked())
        {
            return FailedPreparation("Per-application dump setup is unavailable while the protected target is running.");
        }

        CrashReadinessCollection readiness = await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
        progress?.Report(new DiagnosticProgress("Enabling application dumps", "Waiting for Windows administrator approval…", 0.15));
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.ApplyWerLocalDumpPlan,
            null,
            null,
            null,
            null,
            false,
            false,
            false,
            WerLocalDumpPlan: plan);
        ProtectedEvidenceResponse response = await _elevatedHelperClient.ExecuteAsync(
            request,
            IsBlocked,
            NormalizeHelperTimeout(helperTimeout),
            cancellationToken).ConfigureAwait(false);
        WerLocalDumpReceipt? receipt = response.WerLocalDumpReceipt;
        bool valid = response.Succeeded && receipt is not null &&
                     string.Equals(receipt.PlanId, plan.PlanId, StringComparison.Ordinal) &&
                     string.Equals(receipt.ReportSha256, plan.ReportSha256, StringComparison.OrdinalIgnoreCase) &&
                     string.Equals(receipt.ExecutableName, plan.ExecutableName, StringComparison.OrdinalIgnoreCase);
        if (response.Succeeded && !valid)
        {
            throw new InvalidDataException("The elevated helper returned an invalid per-application dump receipt.");
        }

        return new CrashCapturePreparationResult(
            response.Succeeded,
            response.Message,
            null,
            null,
            valid ? receipt : null,
            readiness.Readiness,
            response.Succeeded ? readiness.Readiness : null,
            response.Succeeded ? CrashCaptureActivationState.Active : CrashCaptureActivationState.Unknown,
            response.RollbackAttempted,
            response.RollbackSucceeded);
    }

    public async Task<CrashCapturePreparationResult> RestoreWerLocalDumpAsync(
        WerLocalDumpReceipt receipt,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(receipt);
        bool IsBlocked() => IsSensitiveOperationBlocked(receipt.TargetProfile);
        if (IsBlocked())
        {
            return FailedPreparation("Per-application dump settings cannot be restored while the protected target is running.");
        }

        CrashReadinessCollection readiness = await _collectReadinessAsync(cancellationToken).ConfigureAwait(false);
        progress?.Report(new DiagnosticProgress("Restoring application dumps", "Waiting for Windows administrator approval…", 0.15));
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.RestoreWerLocalDumpPlan,
            null,
            null,
            null,
            null,
            false,
            false,
            false,
            ConfigurationReceiptId: receipt.ReceiptId);
        ProtectedEvidenceResponse response = await _elevatedHelperClient.ExecuteAsync(
            request,
            IsBlocked,
            NormalizeHelperTimeout(helperTimeout),
            cancellationToken).ConfigureAwait(false);
        WerLocalDumpReceipt? restored = response.WerLocalDumpReceipt;
        if (response.Succeeded && (restored is not { Restored: true } ||
                                   !string.Equals(restored.ReceiptId, receipt.ReceiptId, StringComparison.Ordinal)))
        {
            throw new InvalidDataException("The elevated helper returned an invalid per-application restore receipt.");
        }

        return new CrashCapturePreparationResult(
            response.Succeeded,
            response.Message,
            null,
            null,
            restored,
            readiness.Readiness,
            response.Succeeded ? readiness.Readiness : null,
            response.Succeeded ? CrashCaptureActivationState.Restored : CrashCaptureActivationState.Unknown,
            response.RollbackAttempted,
            response.RollbackSucceeded);
    }

    public Task<CrashCapturePreparationResult> RestoreWerLocalDumpAsync(
        string persistedReceiptId,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        string normalized;
        try
        {
            normalized = CrashCaptureReceiptStore.NormalizeReceiptId(persistedReceiptId);
        }
        catch (ArgumentException)
        {
            return Task.FromResult(FailedPreparation("The saved per-application dump receipt id was invalid."));
        }

        WerLocalDumpReceipt? receipt = DiscoverRestorableConfigurationReceipts().WerLocalDumpReceipts
            .FirstOrDefault(candidate => string.Equals(
                candidate.ReceiptId,
                normalized,
                StringComparison.OrdinalIgnoreCase));
        return receipt is not null
            ? RestoreWerLocalDumpAsync(receipt, progress, helperTimeout, cancellationToken)
            : Task.FromResult(FailedPreparation("The saved per-application dump receipt was unavailable or no longer restorable."));
    }

    public async Task<IncidentSearchResult> FindRecentIncidentsAsync(
        IncidentSearchOptions options,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateSearchWindow(options);
        WindowsEventCollection events = await _eventCollector
            .CollectWindowAsync(options.StartUtc, options.EndUtc, options.TargetProfile, cancellationToken)
            .ConfigureAwait(false);
        ReliabilityCollection reliability = await _reliabilityCollector
            .CollectAsync(options.StartUtc, options.EndUtc, options.TargetProfile, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlyList<IncidentCandidate> candidates = _incidentDiscovery.Discover(
            events.Events,
            reliability.Records,
            options.TargetProfile,
            maximumCandidates: 64);
        CollectionStatus[] statuses = [.. events.Statuses, .. reliability.Statuses];
        return new IncidentSearchResult(
            options.StartUtc,
            options.EndUtc,
            candidates,
            BuildCoverage(statuses, events.Events, reliability.Records, [], [], null, null),
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
        progress?.Report(new DiagnosticProgress("Collecting", "Reading Windows records for the selected incident.", 0.08));
        SystemSnapshotCollection snapshot = await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
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
        PathSafety.EnsureDirectory(_dataRoot, _dataRoot);
        string sessionsRoot = PathSafety.EnsureDirectory(_dataRoot, _reportWriter.SessionsRoot);
        string sessionFolder = PathSafety.EnsureDirectory(sessionsRoot, Path.Combine(sessionsRoot, sessionId));
        SystemSnapshotCollection startSnapshot = await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
        var marker = new ActiveTargetSessionMarker(
            3,
            sessionId,
            Environment.ProcessId,
            startedUtc,
            startSnapshot.Snapshot.LastBootUtc ?? EstimateCurrentBootUtc(),
            startedUtc,
            sessionFolder,
            targetProfile);
        await _activeSessions.WriteAsync(marker, sessionsRoot, cancellationToken).ConfigureAwait(false);

        var samples = new List<TargetPerformanceSample>();
        bool observed = false;
        int missedSamples = 0;
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
                await _activeSessions.WriteAsync(marker, sessionsRoot, cancellationToken).ConfigureAwait(false);

                if (sample.TargetRunning)
                {
                    observed = true;
                    missedSamples = 0;
                    progress?.Report(new TargetMonitorProgress(
                        "Monitoring",
                        $"{targetProfile.DisplayName} is running in {sample.TargetProcessCount} matching process{(sample.TargetProcessCount == 1 ? string.Empty : "es")}.",
                        sample));
                }
                else if (!observed)
                {
                    progress?.Report(new TargetMonitorProgress(
                        "Waiting",
                        $"Start {targetProfile.DisplayName} when ready.",
                        sample));
                }
                else
                {
                    missedSamples++;
                    progress?.Report(new TargetMonitorProgress(
                        "Checking closure",
                        $"The target was absent for {missedSamples} of 2 required samples.",
                        sample));
                    if (missedSamples >= 2)
                    {
                        break;
                    }
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
                progress,
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
                disappearedUtc);
            IncidentSelection selection = _incidentDiscovery.Select(
                candidate,
                IncidentSelectionMethod.Automatic,
                evidenceBefore: disappearedUtc - startedUtc,
                evidenceAfter: endedUtc - disappearedUtc);
            SystemSnapshotCollection endSnapshot = await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
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
                new Progress<DiagnosticProgress>(item => progress?.Report(new TargetMonitorProgress(item.Stage, item.Message, Percent: item.Percent))),
                cancellationToken).ConfigureAwait(false);
            _activeSessions.Complete(sessionFolder, sessionsRoot);
            progress?.Report(new TargetMonitorProgress("Report ready", "Monitoring ended and the local report is ready.", Percent: 1));
            return result;
        }
        catch (OperationCanceledException)
        {
            if (!observed)
            {
                _activeSessions.Complete(sessionFolder, sessionsRoot);
            }

            throw;
        }
    }

    public async Task<IReadOnlyList<DiagnosticOperationResultV3>> RecoverInterruptedMonitoringAsync(
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        IReadOnlyList<TargetRecoveryCandidate> candidates = await _activeSessions.FindStaleAsync(
            _reportWriter.SessionsRoot,
            EstimateCurrentBootUtc(),
            cancellationToken).ConfigureAwait(false);
        var results = new List<DiagnosticOperationResultV3>();
        foreach (TargetRecoveryCandidate recovery in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ActiveTargetSessionMarker marker = recovery.Marker;
            IReadOnlyList<TargetPerformanceSample> samples = await _sampleJournal.ReadAsync(marker.SessionFolder, cancellationToken).ConfigureAwait(false);
            DateTimeOffset lastSample = samples.Count == 0 ? marker.LastSampleUtc : samples.Max(sample => sample.TimestampUtc);
            DateTimeOffset endUtc = Min(DateTimeOffset.UtcNow, lastSample + (recovery.BootChanged ? TimeSpan.FromMinutes(10) : TimeSpan.FromSeconds(60)));
            IncidentCandidate? candidate = await FindBestIncidentAsync(marker.StartedUtc, endUtc, marker.TargetProfile, cancellationToken).ConfigureAwait(false);
            candidate ??= new IncidentCandidate(
                IncidentFingerprint.Create(IncidentKind.Unknown, lastSample, "Recovered monitoring", 0, marker.TargetProfile.Id),
                lastSample,
                IncidentKind.Unknown,
                recovery.BootChanged ? "Monitoring interrupted by a restart" : "Monitoring was interrupted",
                "Recovered monitoring",
                0,
                marker.TargetProfile.Id,
                null,
                null,
                1,
                1,
                lastSample,
                lastSample);
            IncidentSelection selection = _incidentDiscovery.Select(
                candidate,
                IncidentSelectionMethod.RecoveredSession,
                candidate.TimeUtc - marker.StartedUtc,
                endUtc - candidate.TimeUtc);
            SystemSnapshotCollection snapshot = await _snapshotCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
            DiagnosticOperationResultV3 result = await BuildReportAsync(
                marker.SessionId,
                DiagnosticMode.Recovered,
                marker.StartedUtc,
                endUtc,
                recovery.CompletionReason,
                selection,
                marker.TargetProfile,
                null,
                snapshot.Snapshot,
                samples,
                snapshot.Statuses,
                progress,
                cancellationToken).ConfigureAwait(false);
            _activeSessions.Complete(marker.SessionFolder, _reportWriter.SessionsRoot);
            results.Add(result);
        }

        return results;
    }

    public DumpCandidate InspectSelectedDump(
        string path,
        DumpKind kind,
        string source,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_isBf6RunningFailClosed())
        {
            throw new InvalidOperationException("Dump inspection is unavailable while Battlefield 6 is running.");
        }

        return new SafeDumpInspector().Inspect(path, kind, source, cancellationToken);
    }

    public IReadOnlyList<DumpChkInstallation> DiscoverInstalledDumpCheckers()
    {
        ThrowIfDisposed();
        return ReleaseStage.Beta2FeaturesEnabled
            ? _discoverInstalledDumpCheckers()
            : [];
    }

    public Task<DumpQuality> InspectSelectedDumpQualityAsync(
        DumpCandidate selectedDump,
        bool runInstalledDumpChk,
        TargetProfile? targetProfile = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(selectedDump);
        if (!ReleaseStage.Beta2FeaturesEnabled)
        {
            throw new NotSupportedException("Dump-quality analysis is introduced in PC Crash Diagnostic 3.1 beta 2.");
        }

        bool IsBlocked() => IsSensitiveOperationBlocked(targetProfile);
        if (IsBlocked())
        {
            throw new InvalidOperationException(
                "Dump-quality analysis is unavailable while Battlefield 6 or the protected target is running.");
        }

        DumpChkInstallation? dumpChk = runInstalledDumpChk
            ? DiscoverInstalledDumpCheckers().FirstOrDefault()
            : null;
        return _dumpQualityCollector.InspectAsync(
            new DumpQualityRequest(
                selectedDump,
                RunDumpChk: runInstalledDumpChk,
                DumpChk: dumpChk,
                Timeout: TimeSpan.FromMinutes(1)),
            cancellationToken,
            IsBlocked);
    }

    /// <summary>
    /// Retries one source that was denied during standard-user collection. The
    /// helper response is bound to the exact schema-v3 report, independently
    /// revalidated, deduplicated, and written as a new local report package.
    /// </summary>
    public async Task<DiagnosticOperationResultV3> RetryProtectedEvidenceSourceAsync(
        DiagnosticOperationResultV3 priorResult,
        ProtectedEvidenceSource source,
        IProgress<DiagnosticProgress>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(priorResult);
        if (!Enum.IsDefined(source))
        {
            throw new ArgumentOutOfRangeException(nameof(source));
        }

        DiagnosticReportV3 prior = priorResult.Package.Report;
        ValidateProtectedRetryReportBinding(priorResult, source);
        bool IsBlocked() => IsSensitiveOperationBlocked(prior.TargetProfile);
        if (IsBlocked())
        {
            throw new InvalidOperationException(
                "Administrator evidence retry is unavailable while Battlefield 6 or the protected target is running.");
        }

        progress?.Report(new DiagnosticProgress(
            "Retrying protected evidence",
            "Waiting for Windows administrator approval…",
            0.1));
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.RetryNamedSource,
            source,
            null,
            null,
            null,
            false,
            false,
            false,
            prior.SessionId,
            priorResult.Package.Sha256,
            prior.StartUtc,
            prior.EndUtc,
            prior.TargetProfile);
        ProtectedEvidenceResponse response = await _elevatedHelperClient.ExecuteAsync(
            request,
            IsBlocked,
            NormalizeHelperTimeout(helperTimeout),
            cancellationToken).ConfigureAwait(false);
        if (!response.Succeeded)
        {
            throw new InvalidOperationException(response.Message);
        }

        if (IsBlocked())
        {
            throw new InvalidOperationException(
                "Protected evidence validation stopped because Battlefield 6 or the protected target started running.");
        }

        ProtectedEvidenceBatch batch = ValidateProtectedEvidenceResponse(
            response,
            request,
            prior.TargetProfile);
        progress?.Report(new DiagnosticProgress(
            "Refreshing results",
            "Validating and merging the newly readable Windows evidence.",
            0.55));
        DiagnosticOperationResultV3 updated = await MergeProtectedEvidenceAsync(
            priorResult,
            batch,
            cancellationToken).ConfigureAwait(false);
        progress?.Report(new DiagnosticProgress(
            "Report ready",
            "The privacy-filtered evidence was added to a refreshed local report.",
            1));
        return updated;
    }

    private static void ValidateProtectedRetryReportBinding(
        DiagnosticOperationResultV3 priorResult,
        ProtectedEvidenceSource source)
    {
        DiagnosticReportV3 report = priorResult.Package.Report;
        if (report.ReportSchemaVersion != 3 ||
            !SessionIdValidator.IsValid(report.SessionId) ||
            priorResult.Package.Sha256 is not { Length: 64 } sha256 ||
            sha256.Any(character => !Uri.IsHexDigit(character)) ||
            report.EndUtc < report.StartUtc ||
            report.EndUtc - report.StartUtc > TimeSpan.FromDays(14) ||
            report.EndUtc > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw new InvalidDataException("The protected retry requires a valid, bounded schema-v3 report context.");
        }

        string expectedSource = ProtectedSourceName(source);
        bool wasDenied = report.CollectionStatus.Any(status =>
                             status.Source.Equals(expectedSource, StringComparison.OrdinalIgnoreCase) &&
                             status.State == CollectionState.Denied) ||
                         report.SourceCoverage.Any(status =>
                             status.Source.Equals(expectedSource, StringComparison.OrdinalIgnoreCase) &&
                             status.State == CollectionState.Denied);
        if (!wasDenied)
        {
            throw new InvalidOperationException(
                "Administrator retry is available only for a source that this report recorded as access denied.");
        }
    }

    private ProtectedEvidenceBatch ValidateProtectedEvidenceResponse(
        ProtectedEvidenceResponse response,
        ProtectedEvidenceRequest request,
        TargetProfile? targetProfile)
    {
        if (response.Probe is not null || response.StagedDump is not null ||
            response.Message is null || response.Message.Length > 512 || response.EvidenceBatch is not { } batch ||
            batch.SchemaVersion != 1 ||
            !Enum.IsDefined(batch.Source) ||
            !string.Equals(batch.ReportSessionId, request.ReportSessionId, StringComparison.Ordinal) ||
            !string.Equals(batch.ReportSha256, request.ReportSha256, StringComparison.OrdinalIgnoreCase) ||
            batch.Source != request.Source ||
            batch.WindowStartUtc.ToUniversalTime() != request.WindowStartUtc!.Value.ToUniversalTime() ||
            batch.WindowEndUtc.ToUniversalTime() != request.WindowEndUtc!.Value.ToUniversalTime() ||
            batch.Events is null || batch.Dumps is null || batch.Statuses is null ||
            batch.Events.Count > ProtectedEvidenceHelper.MaximumRetryEvents ||
            batch.Dumps.Count > ProtectedEvidenceHelper.MaximumRetryDumps ||
            batch.Statuses.Count is < 1 or > ProtectedEvidenceHelper.MaximumRetryStatuses)
        {
            throw new InvalidDataException("The elevated helper returned a malformed or report-mismatched evidence response.");
        }

        string expectedSource = ProtectedSourceName(batch.Source);
        if (batch.Statuses.Any(status =>
                status is null ||
                status.Source is null || status.Detail is null ||
                !status.Source.Equals(expectedSource, StringComparison.Ordinal) ||
                status.Source.Length > 128 || status.Detail.Length > 512 ||
                status.State != CollectionState.Available) ||
            batch.Statuses[^1].State != CollectionState.Available)
        {
            throw new InvalidDataException("The elevated helper returned an invalid protected-source status.");
        }

        bool eventSource = batch.Source is ProtectedEvidenceSource.SystemEventLog or
            ProtectedEvidenceSource.ApplicationEventLog;
        if (eventSource && batch.Dumps.Count != 0 || !eventSource && batch.Events.Count != 0)
        {
            throw new InvalidDataException("The elevated helper returned the wrong evidence type for the selected source.");
        }

        foreach (DiagnosticEvent item in batch.Events)
        {
            if (item is null ||
                item.TimeUtc < batch.WindowStartUtc || item.TimeUtc > batch.WindowEndUtc ||
                string.IsNullOrWhiteSpace(item.LogName) || item.LogName.Length > 32 ||
                string.IsNullOrWhiteSpace(item.ProviderName) || item.ProviderName.Length > 128 ||
                item.LevelName is null || item.LevelName.Length > 32 ||
                item.Message is null || item.Message.Length > 512 ||
                item.Data is null || item.Data.Count > 8 ||
                item.Data.Any(pair => string.IsNullOrWhiteSpace(pair.Key) || pair.Key.Length > 64 ||
                                      pair.Value is null || pair.Value.Length > 256 ||
                                      pair.Key.Equals("ProcessId", StringComparison.OrdinalIgnoreCase) ||
                                      pair.Key.Equals("DeviceName", StringComparison.OrdinalIgnoreCase)) ||
                !WindowsEventCollector.IsAllowedProtectedEvidenceEvent(batch.Source, item, targetProfile))
            {
                throw new InvalidDataException("The elevated helper returned a non-allowlisted or oversized event record.");
            }
        }

        foreach (ProtectedDumpEvidence item in batch.Dumps)
        {
            if (item is null || item.Source is null || item.Name is null ||
                item.RedactedPath is null || item.Detail is null || item.ApprovedPath is null)
            {
                throw new InvalidDataException("The elevated helper returned incomplete dump metadata.");
            }

            DumpKind expectedKind = batch.Source switch
            {
                ProtectedEvidenceSource.WindowsMemoryDump => DumpKind.WindowsMemoryDump,
                ProtectedEvidenceSource.WindowsMinidumps => DumpKind.WindowsMinidump,
                ProtectedEvidenceSource.LiveKernelReports => DumpKind.LiveKernelDump,
                _ => throw new InvalidDataException("The protected dump source was invalid.")
            };
            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(item.ApprovedPath);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or IOException or System.Security.SecurityException)
            {
                throw new InvalidDataException("The elevated helper returned an invalid dump path.", exception);
            }

            if (item.Kind != expectedKind ||
                !item.Source.Equals(expectedSource, StringComparison.Ordinal) ||
                item.Source.Length > 128 || item.Name.Length is 0 or > 128 ||
                item.ApprovedPath.Length > 1_024 ||
                !string.Equals(
                    _redactor.Redact(Path.GetFileName(fullPath)),
                    item.Name,
                    StringComparison.OrdinalIgnoreCase) ||
                !Path.GetExtension(fullPath).Equals(".dmp", StringComparison.OrdinalIgnoreCase) ||
                !_protectedDumpPathValidator(fullPath) ||
                item.RedactedPath.Length is 0 or > 512 || item.Detail.Length > 512 ||
                item.SizeBytes is <= 0 or > ProtectedEvidenceHelper.MaximumDumpBytes ||
                item.LastWriteUtc < batch.WindowStartUtc || item.LastWriteUtc > batch.WindowEndUtc ||
                item.HeaderBytesRead is < 0 or > SafeDumpInspector.MaximumHeaderBytesRead ||
                item.InspectionState == DumpInspectionState.Recognized && item.Format == DumpFormat.Unknown)
            {
                throw new InvalidDataException("The elevated helper returned invalid or non-allowlisted dump metadata.");
            }
        }

        return batch;
    }

    private async Task<DiagnosticOperationResultV3> MergeProtectedEvidenceAsync(
        DiagnosticOperationResultV3 priorResult,
        ProtectedEvidenceBatch batch,
        CancellationToken cancellationToken)
    {
        DiagnosticReportV3 prior = priorResult.Package.Report;
        string sourceName = ProtectedSourceName(batch.Source);
        DiagnosticEvent[] events = prior.Events
            .Concat(batch.Events.Select(_redactor.RedactEvent))
            .GroupBy(EventIdentity, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderBy(item => item.TimeUtc)
            .ThenBy(item => item.LogName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.ProviderName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.EventId)
            .ToArray();

        DumpCandidate[] addedDumps = batch.Dumps.Select(item => new DumpCandidate(
            item.Kind,
            item.Source,
            item.Name,
            _redactor.RedactPath(item.RedactedPath),
            item.SizeBytes,
            item.LastWriteUtc,
            item.Format,
            item.InspectionState,
            item.HeaderBytesRead,
            item.SizePlausible,
            _redactor.Redact(item.Detail),
            Path.GetFullPath(item.ApprovedPath))).ToArray();
        DumpCandidate[] dumps = MergeDumpCandidates(prior.DumpInventory.Candidates, addedDumps);

        CollectionStatus[] replacementStatuses = batch.Statuses
            .Select(_redactor.RedactStatus)
            .ToArray();
        CollectionStatus[] statuses = prior.CollectionStatus
            .Where(status => !status.Source.Equals(sourceName, StringComparison.OrdinalIgnoreCase))
            .Concat(replacementStatuses)
            .GroupBy(status => new { status.Source, status.State, status.Detail })
            .Select(group => group.First())
            .ToArray();
        CollectionStatus[] dumpStatuses = prior.DumpInventory.Statuses.ToArray();
        if (batch.Source is ProtectedEvidenceSource.WindowsMemoryDump or
            ProtectedEvidenceSource.WindowsMinidumps or
            ProtectedEvidenceSource.LiveKernelReports)
        {
            dumpStatuses = prior.DumpInventory.Statuses
                .Where(status => !status.Source.Equals(sourceName, StringComparison.OrdinalIgnoreCase))
                .Concat(replacementStatuses)
                .ToArray();
        }

        var dumpInventory = new DumpInventory(dumps, dumpStatuses);
        IReadOnlyList<DuplicateEventGroup> groups = _eventAnalyzer.GroupDuplicates(events);
        IReadOnlyList<BugcheckRecord> bugchecks = BugcheckRecordDecoder.Decode(events);
        IncidentSelection? selection = prior.IncidentSelection;
        CrashCorrelation? correlation = selection is null
            ? prior.CrashCorrelation
            : _correlator.Correlate(selection, bugchecks, dumps, prior.EndSnapshot?.LastBootUtc);
        CrashAnchor? anchor = selection is null
            ? null
            : new CrashAnchor(
                selection.Candidate.TimeUtc,
                selection.Candidate.Source,
                selection.Candidate.EventId,
                selection.Candidate.Title,
                selection.Candidate.BugcheckCode,
                selection.Candidate.DumpFileName,
                selection.Candidate.EvidencePriority);
        IReadOnlyList<PerformanceSample> compatibilitySamples = prior.Samples
            .Select(ToCompatibilitySample)
            .ToArray();
        DiagnosticFinding[] findings = _eventAnalyzer.Analyze(
                anchor,
                events,
                groups,
                prior.Reliability,
                prior.Artifacts,
                compatibilitySamples,
                prior.TargetProfile)
            .Concat(CreateWheaCategoryFindings(events))
            .Concat(_extendedEvidenceAnalyzer.Analyze(
                prior.DumpQuality,
                prior.RecentChanges,
                prior.StorageHealth,
                prior.DriverVerifier))
            .OrderBy(finding => finding.Rank)
            .Select(_redactor.RedactFinding)
            .ToArray();
        SourceCoverage[] coverage = BuildCoverage(
            statuses,
            events,
            prior.Reliability,
            prior.Artifacts,
            dumps,
            prior.DriverInventory,
            prior.CrashReadiness,
            prior.DumpQuality,
            prior.RecentChanges,
            prior.StorageHealth,
            prior.DriverVerifier);
        string summary = _summaryBuilder.Build(
            ToolVersion,
            prior.SessionId,
            prior.StartUtc,
            prior.EndUtc,
            prior.CompletionReason,
            selection,
            prior.TargetProfile,
            findings,
            coverage,
            correlation,
            prior.DebuggerAnalysis,
            prior.CrashReadiness,
            prior.DumpQuality,
            prior.RecentChanges,
            prior.StorageHealth,
            prior.DriverVerifier);
        DiagnosticReportV3 updated = prior with
        {
            ToolVersion = ToolVersion,
            ProductName = ProductName,
            Events = events,
            EventGroups = groups,
            Findings = findings,
            CollectionStatus = statuses,
            SourceCoverage = coverage,
            Bugchecks = bugchecks,
            DumpInventory = dumpInventory,
            CrashCorrelation = correlation,
            Summary = summary
        };

        ReportPackageV3 package = await _reportWriter.WriteV3Async(updated, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlyList<DumpCandidate> choices = correlation?.RelatedDumps ?? dumps;
        foreach (DumpCandidate candidate in choices)
        {
            if (candidate.OriginalPath is not null && DumpPackager.TryCaptureIdentity(
                    candidate.OriginalPath,
                    candidate.SizeBytes,
                    candidate.LastWriteUtc,
                    out DumpArtifactIdentity identity))
            {
                _boundDumps[identity.FullPath] = new BoundDump(
                    identity,
                    updated.SessionId,
                    package.Sha256,
                    candidate.Source,
                    updated.TargetProfile);
            }
        }

        string[] failures = statuses
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.State} · {status.Detail}")
            .ToArray();
        return new DiagnosticOperationResultV3(
            package,
            choices,
            correlation?.SelectedDump is null && choices.Count > 1,
            failures);
    }

    private static DumpCandidate[] MergeDumpCandidates(
        IEnumerable<DumpCandidate> existing,
        IEnumerable<DumpCandidate> added)
    {
        var merged = new Dictionary<string, DumpCandidate>(StringComparer.OrdinalIgnoreCase);
        foreach (DumpCandidate candidate in existing.Concat(added))
        {
            string key = DumpIdentity(candidate);
            if (!merged.TryGetValue(key, out DumpCandidate? current) ||
                DumpQuality(candidate) >= DumpQuality(current))
            {
                merged[key] = candidate;
            }
        }

        return merged.Values
            .OrderBy(item => item.LastWriteUtc)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string DumpIdentity(DumpCandidate candidate)
    {
        if (!string.IsNullOrWhiteSpace(candidate.OriginalPath))
        {
            try
            {
                return "path|" + Path.GetFullPath(candidate.OriginalPath);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or IOException or System.Security.SecurityException)
            {
            }
        }

        return $"redacted|{candidate.Kind}|{candidate.RedactedPath}|{candidate.Name}";
    }

    private static int DumpQuality(DumpCandidate candidate) => candidate.InspectionState switch
    {
        DumpInspectionState.Recognized => 5,
        DumpInspectionState.Unrecognized => 4,
        DumpInspectionState.Error => 3,
        DumpInspectionState.Unavailable => 2,
        DumpInspectionState.Denied => 1,
        _ => 0
    };

    private static string EventIdentity(DiagnosticEvent item) => string.Join(
        '|',
        item.TimeUtc.ToUniversalTime().Ticks,
        item.LogName.ToUpperInvariant(),
        item.ProviderName.ToUpperInvariant(),
        item.ProviderGuid?.ToString("D") ?? string.Empty,
        item.EventId,
        item.Level,
        item.Message,
        string.Join(';', item.Data
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => $"{pair.Key.ToUpperInvariant()}={pair.Value}")));

    private static string ProtectedSourceName(ProtectedEvidenceSource source) => source switch
    {
        ProtectedEvidenceSource.SystemEventLog => "Windows Event Log/System",
        ProtectedEvidenceSource.ApplicationEventLog => "Windows Event Log/Application",
        ProtectedEvidenceSource.WindowsMemoryDump => "Dump inventory/Windows memory dump",
        ProtectedEvidenceSource.WindowsMinidumps => "Dump inventory/Windows minidumps",
        ProtectedEvidenceSource.LiveKernelReports => "Dump inventory/LiveKernelReports",
        _ => throw new ArgumentOutOfRangeException(nameof(source))
    };

    public Task<ProtectedDumpOperationResult<ProtectedDumpInspection>> InspectSelectedProtectedDumpAsync(
        DiagnosticOperationResultV3 reportContext,
        DumpCandidate selectedDump,
        ProtectedDumpCopyConfirmation confirmation,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default) =>
        UseSelectedProtectedDumpAsync(
            reportContext,
            selectedDump,
            confirmation,
            (prepared, _) => Task.FromResult(new ProtectedDumpInspection(
                prepared.Candidate.Format,
                prepared.Candidate.InspectionState,
                prepared.Candidate.Metadata,
                prepared.StagedDump.SizeBytes,
                prepared.StagedDump.Sha256,
                "The private staging copy was inspected and then deleted.")),
            helperTimeout,
            cancellationToken);

    public Task<ProtectedDumpOperationResult<DiagnosticOperationResultV3>>
        RunOptionalDebuggerAnalysisForProtectedDumpAsync(
            DiagnosticOperationResultV3 priorResult,
            DumpCandidate selectedDump,
            ProtectedDumpCopyConfirmation confirmation,
            SymbolAccessMode symbolAccess,
            bool microsoftSymbolDownloadConsent,
            TargetProfile? targetProfile = null,
            IProgress<DiagnosticProgress>? progress = null,
            TimeSpan? helperTimeout = null,
            CancellationToken cancellationToken = default) =>
        UseSelectedProtectedDumpAsync(
            priorResult,
            selectedDump,
            confirmation,
            (prepared, token) => RunOptionalDebuggerAnalysisCoreAsync(
                priorResult,
                selectedDump,
                prepared.Candidate,
                symbolAccess,
                microsoftSymbolDownloadConsent,
                targetProfile,
                progress,
                token),
            helperTimeout,
            cancellationToken);

    public Task<ProtectedDumpOperationResult<DiagnosticOperationResultV3>>
        RunOptionalDumpCheckForProtectedDumpAsync(
            DiagnosticOperationResultV3 priorResult,
            DumpCandidate selectedDump,
            ProtectedDumpCopyConfirmation confirmation,
            TargetProfile? targetProfile = null,
            IProgress<DiagnosticProgress>? progress = null,
            TimeSpan? helperTimeout = null,
            CancellationToken cancellationToken = default) =>
        UseSelectedProtectedDumpAsync(
            priorResult,
            selectedDump,
            confirmation,
            (prepared, token) => RunOptionalDumpCheckCoreAsync(
                priorResult,
                selectedDump,
                prepared.Candidate,
                targetProfile,
                progress,
                token),
            helperTimeout,
            cancellationToken);

    public Task<ProtectedDumpOperationResult<string>> PackageSelectedProtectedDumpAsync(
        DiagnosticOperationResultV3 reportContext,
        DumpCandidate selectedDump,
        ProtectedDumpCopyConfirmation confirmation,
        IProgress<double>? progress = null,
        TimeSpan? helperTimeout = null,
        CancellationToken cancellationToken = default) =>
        UseSelectedProtectedDumpAsync(
            reportContext,
            selectedDump,
            confirmation,
            async (prepared, token) =>
            {
                DumpArtifactIdentity identity = DumpPackager.CaptureIdentity(
                    prepared.Candidate.OriginalPath!,
                    prepared.Candidate.SizeBytes,
                    prepared.Candidate.LastWriteUtc);
                DiagnosticReportV3 report = reportContext.Package.Report;
                return await _dumpPackager.PackageForReportAsync(
                    identity,
                    _reportWriter.ReportsRoot,
                    () => _isBf6RunningFailClosed() || IsTargetRunningFailClosed(report.TargetProfile),
                    new DumpPackageContext(
                        report.SessionId,
                        reportContext.Package.Sha256,
                        selectedDump.Source),
                    progress,
                    token).ConfigureAwait(false);
            },
            helperTimeout,
            cancellationToken);

    public ProtectedEvidenceCleanupResult CleanupProtectedEvidenceArtifacts(DateTimeOffset? nowUtc = null)
    {
        ThrowIfDisposed();
        DateTimeOffset now = nowUtc ?? DateTimeOffset.UtcNow;
        return new ProtectedEvidenceCleanupResult(
            _protectedEvidenceHelper.CleanupStaleStagingDirectories(now),
            _helperRequestStore.CleanupExpiredMessages(now));
    }

    public Task<string> PackageBoundDumpAsync(
        string dumpPath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        string path = Path.GetFullPath(dumpPath);
        if (!_boundDumps.TryGetValue(path, out BoundDump? bound))
        {
            throw new InvalidOperationException("The selected dump is not bound to a completed report in this app session.");
        }

        return _dumpPackager.PackageForReportAsync(
            bound.Identity,
            _reportWriter.ReportsRoot,
            () => _isBf6RunningFailClosed() || IsTargetRunningFailClosed(bound.TargetProfile),
            new DumpPackageContext(bound.SessionId, bound.ReportSha256, bound.SourceType),
            progress,
            cancellationToken);
    }

    public IReadOnlyList<CdbInstallation> DiscoverInstalledDebuggers()
    {
        ThrowIfDisposed();
        return new CdbDiscovery().Discover();
    }

    public async Task<DiagnosticOperationResultV3> RunOptionalDebuggerAnalysisAsync(
        DiagnosticOperationResultV3 priorResult,
        DumpCandidate selectedDump,
        SymbolAccessMode symbolAccess,
        bool microsoftSymbolDownloadConsent,
        TargetProfile? targetProfile = null,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default) =>
        await RunOptionalDebuggerAnalysisCoreAsync(
            priorResult,
            selectedDump,
            selectedDump,
            symbolAccess,
            microsoftSymbolDownloadConsent,
            targetProfile,
            progress,
            cancellationToken).ConfigureAwait(false);

    public Task<DiagnosticOperationResultV3> RunOptionalDumpCheckAsync(
        DiagnosticOperationResultV3 priorResult,
        DumpCandidate selectedDump,
        TargetProfile? targetProfile = null,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default) =>
        RunOptionalDumpCheckCoreAsync(
            priorResult,
            selectedDump,
            selectedDump,
            targetProfile,
            progress,
            cancellationToken);

    private async Task<DiagnosticOperationResultV3> RunOptionalDumpCheckCoreAsync(
        DiagnosticOperationResultV3 priorResult,
        DumpCandidate correlationDump,
        DumpCandidate analysisDump,
        TargetProfile? targetProfile,
        IProgress<DiagnosticProgress>? progress,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(priorResult);
        ArgumentNullException.ThrowIfNull(correlationDump);
        ArgumentNullException.ThrowIfNull(analysisDump);
        if (!ReleaseStage.Beta2FeaturesEnabled)
        {
            throw new NotSupportedException("DumpChk validation is introduced in PC Crash Diagnostic 3.1 beta 2.");
        }

        DiagnosticReportV3 prior = priorResult.Package.Report;
        bool IsBlocked() =>
            IsSensitiveOperationBlocked(prior.TargetProfile) ||
            (targetProfile is not null && IsSensitiveOperationBlocked(targetProfile));
        if (IsBlocked())
        {
            throw new InvalidOperationException(
                "DumpChk validation is unavailable while Battlefield 6 or the protected target is running.");
        }

        CrashCorrelation correlation = prior.CrashCorrelation is null
            ? throw new InvalidOperationException("The report has no dump correlation to validate.")
            : _correlator.SelectDump(prior.CrashCorrelation, correlationDump);
        DumpChkInstallation dumpChk = DiscoverInstalledDumpCheckers().FirstOrDefault()
            ?? throw new InvalidOperationException(
                "No Microsoft-signed x64 dumpchk.exe was found in an installed Windows SDK directory.");

        progress?.Report(new DiagnosticProgress(
            "DumpChk",
            "Validating the selected dump with the installed Microsoft tool.",
            0.2));
        DumpQuality quality = await _dumpQualityCollector.InspectAsync(
            new DumpQualityRequest(
                analysisDump,
                RunDumpChk: true,
                DumpChk: dumpChk,
                Timeout: TimeSpan.FromMinutes(1)),
            cancellationToken,
            IsBlocked).ConfigureAwait(false);

        DiagnosticFinding[] findings = prior.Findings
            .Where(finding => !IsExtendedEvidenceFinding(finding.Id))
            .Concat(_extendedEvidenceAnalyzer.Analyze(
                quality,
                prior.RecentChanges,
                prior.StorageHealth,
                prior.DriverVerifier))
            .OrderBy(finding => finding.Rank)
            .ThenBy(finding => finding.Id, StringComparer.Ordinal)
            .Select(_redactor.RedactFinding)
            .ToArray();
        CollectionStatus dumpQualityStatus = _redactor.RedactStatus(CreateDumpQualityStatus(quality, correlation));
        CollectionStatus[] statuses = prior.CollectionStatus
            .Where(status => !status.Source.Equals("Dump quality", StringComparison.OrdinalIgnoreCase))
            .Append(dumpQualityStatus)
            .ToArray();
        SourceCoverage[] coverage = BuildCoverage(
            statuses,
            prior.Events,
            prior.Reliability,
            prior.Artifacts,
            prior.DumpInventory.Candidates,
            prior.DriverInventory,
            prior.CrashReadiness,
            quality,
            prior.RecentChanges,
            prior.StorageHealth,
            prior.DriverVerifier);
        string summary = _summaryBuilder.Build(
            ToolVersion,
            prior.SessionId,
            prior.StartUtc,
            prior.EndUtc,
            prior.CompletionReason,
            prior.IncidentSelection,
            prior.TargetProfile,
            findings,
            coverage,
            correlation,
            prior.DebuggerAnalysis,
            prior.CrashReadiness,
            quality,
            prior.RecentChanges,
            prior.StorageHealth,
            prior.DriverVerifier);
        DiagnosticReportV3 updated = prior with
        {
            ToolVersion = ToolVersion,
            ProductName = ProductName,
            Findings = findings,
            CollectionStatus = statuses,
            SourceCoverage = coverage,
            CrashCorrelation = correlation,
            DumpQuality = quality,
            Summary = summary
        };

        progress?.Report(new DiagnosticProgress(
            "Packaging",
            "Writing a new report package with the DumpChk result.",
            0.85));
        ReportPackageV3 package = await _reportWriter.WriteV3Async(updated, cancellationToken).ConfigureAwait(false);
        if (correlationDump.OriginalPath is not null && DumpPackager.TryCaptureIdentity(
                correlationDump.OriginalPath,
                correlationDump.SizeBytes,
                correlationDump.LastWriteUtc,
                out DumpArtifactIdentity identity))
        {
            _boundDumps[identity.FullPath] = new BoundDump(
                identity,
                updated.SessionId,
                package.Sha256,
                correlationDump.Source,
                prior.TargetProfile);
        }

        string[] failures = statuses
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.State} · {status.Detail}")
            .ToArray();
        progress?.Report(new DiagnosticProgress(
            "Report ready",
            "The DumpChk result was added to a new local report.",
            1));
        return new DiagnosticOperationResultV3(
            package,
            priorResult.DumpChoices,
            false,
            failures);
    }

    private async Task<DiagnosticOperationResultV3> RunOptionalDebuggerAnalysisCoreAsync(
        DiagnosticOperationResultV3 priorResult,
        DumpCandidate correlationDump,
        DumpCandidate analysisDump,
        SymbolAccessMode symbolAccess,
        bool microsoftSymbolDownloadConsent,
        TargetProfile? targetProfile,
        IProgress<DiagnosticProgress>? progress,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(priorResult);
        ArgumentNullException.ThrowIfNull(correlationDump);
        ArgumentNullException.ThrowIfNull(analysisDump);
        DiagnosticReportV3 prior = priorResult.Package.Report;
        bool IsBlocked() =>
            IsSensitiveOperationBlocked(prior.TargetProfile) ||
            (targetProfile is not null && IsSensitiveOperationBlocked(targetProfile));
        if (IsBlocked())
        {
            throw new InvalidOperationException(
                "WinDbg analysis is unavailable while Battlefield 6 or the protected target is running.");
        }

        CrashCorrelation correlation = prior.CrashCorrelation is null
            ? throw new InvalidOperationException("The report has no dump correlation to analyze.")
            : _correlator.SelectDump(prior.CrashCorrelation, correlationDump);
        CdbInstallation? debugger = DiscoverInstalledDebuggers().FirstOrDefault();
        DebuggerAnalysis analysis;
        if (debugger is null)
        {
            analysis = new DebuggerAnalysis(
                DebuggerAnalysisState.DebuggerNotFound,
                null,
                DateTimeOffset.UtcNow,
                symbolAccess,
                string.Empty,
                string.Empty,
                string.Empty,
                [],
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                [],
                "No Microsoft-signed x64 cdb.exe was found in an installed WinDbg or Windows SDK directory.");
        }
        else
        {
            progress?.Report(new DiagnosticProgress("WinDbg", "Running the installed debugger with a fixed command list.", 0.2));
            string symbolCache = Path.Combine(_dataRoot, "Symbols", "Microsoft");
            string rawLogs = Path.Combine(_dataRoot, "DebuggerLogs", prior.SessionId);
            analysis = await new WinDbgRunner().AnalyzeAsync(
                new WinDbgAnalysisRequest(
                    analysisDump,
                    debugger,
                    symbolAccess,
                    symbolCache,
                    rawLogs,
                    microsoftSymbolDownloadConsent,
                    TimeSpan.FromMinutes(2),
                    IsBlocked),
                cancellationToken).ConfigureAwait(false);
        }

        string summary = _summaryBuilder.Build(
            prior.ToolVersion,
            prior.SessionId,
            prior.StartUtc,
            prior.EndUtc,
            prior.CompletionReason,
            prior.IncidentSelection,
            prior.TargetProfile,
            prior.Findings,
            prior.SourceCoverage,
            correlation,
            analysis,
            prior.CrashReadiness,
            prior.DumpQuality,
            prior.RecentChanges,
            prior.StorageHealth,
            prior.DriverVerifier);
        DiagnosticReportV3 updated = prior with
        {
            CrashCorrelation = correlation,
            DebuggerAnalysis = analysis,
            Summary = summary
        };
        progress?.Report(new DiagnosticProgress("Packaging", "Writing a new report package with structured WinDbg fields.", 0.85));
        ReportPackageV3 package = await _reportWriter.WriteV3Async(updated, cancellationToken).ConfigureAwait(false);
        if (correlationDump.OriginalPath is not null && DumpPackager.TryCaptureIdentity(
                correlationDump.OriginalPath,
                correlationDump.SizeBytes,
                correlationDump.LastWriteUtc,
                out DumpArtifactIdentity identity))
        {
            _boundDumps[identity.FullPath] = new BoundDump(
                identity,
                updated.SessionId,
                package.Sha256,
                correlationDump.Source,
                prior.TargetProfile);
        }

        progress?.Report(new DiagnosticProgress("Report ready", "The structured WinDbg result was added to a new local report.", 1));
        return new DiagnosticOperationResultV3(
            package,
            priorResult.DumpChoices,
            false,
            priorResult.CollectionFailures);
    }

    private async Task<ProtectedDumpOperationResult<T>> UseSelectedProtectedDumpAsync<T>(
        DiagnosticOperationResultV3 reportContext,
        DumpCandidate selectedDump,
        ProtectedDumpCopyConfirmation confirmation,
        Func<PreparedProtectedDump, CancellationToken, Task<T>> operation,
        TimeSpan? helperTimeout,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(reportContext);
        ArgumentNullException.ThrowIfNull(selectedDump);
        ArgumentNullException.ThrowIfNull(confirmation);
        ArgumentNullException.ThrowIfNull(operation);
        DumpCandidate allowed = ValidateProtectedDumpSelection(reportContext, selectedDump);
        if (!confirmation.IsComplete)
        {
            return new ProtectedDumpOperationResult<T>(
                false,
                "Privacy, dump size, and destination free-space confirmation are required before UAC staging.",
                default);
        }

        TargetProfile? targetProfile = reportContext.Package.Report.TargetProfile;
        bool IsBlocked() => IsSensitiveOperationBlocked(targetProfile);
        if (IsBlocked())
        {
            return new ProtectedDumpOperationResult<T>(
                false,
                "Protected dump staging is unavailable while Battlefield 6 or the protected target is running.",
                default);
        }

        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.CopySelectedDump,
            null,
            allowed.OriginalPath,
            allowed.SizeBytes,
            allowed.LastWriteUtc,
            confirmation.PrivacyConfirmed,
            confirmation.SizeConfirmed,
            confirmation.FreeSpaceConfirmed);
        ProtectedEvidenceResponse transfer = await _elevatedHelperClient.ExecuteAsync(
            request,
            IsBlocked,
            NormalizeHelperTimeout(helperTimeout),
            cancellationToken).ConfigureAwait(false);
        if (!transfer.Succeeded)
        {
            if (transfer.StagedDump is not null &&
                !_protectedEvidenceHelper.DeleteStagedCopy(transfer.StagedDump))
            {
                throw new IOException("The elevated helper reported failure and its unexpected staging copy could not be deleted safely.");
            }

            return new ProtectedDumpOperationResult<T>(false, transfer.Message, default);
        }

        StagedDump staged = transfer.StagedDump ??
            throw new InvalidDataException("The elevated helper reported success without a staged dump.");
        try
        {
            ValidateStagedDumpDescriptor(staged, allowed);
            await using var stableInput = new FileStream(
                staged.Path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (stableInput.Length != staged.SizeBytes)
            {
                return new ProtectedDumpOperationResult<T>(
                    false,
                    "The private staging copy changed before normal-process validation.",
                    default);
            }

            string actualSha256;
            using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                byte[] buffer = new byte[1024 * 1024];
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (IsBlocked())
                    {
                        return new ProtectedDumpOperationResult<T>(
                            false,
                            "Protected dump validation stopped because Battlefield 6 or the protected target started running.",
                            default);
                    }

                    int read = await stableInput.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    hash.AppendData(buffer.AsSpan(0, read));
                }

                actualSha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            }

            if (!string.Equals(actualSha256, staged.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                return new ProtectedDumpOperationResult<T>(
                    false,
                    "The private staging copy did not match the helper's SHA-256.",
                    default);
            }

            DumpCandidate stagedCandidate = new SafeDumpInspector().Inspect(
                staged.Path,
                allowed.Kind,
                "Elevated helper staging",
                cancellationToken);
            if (stagedCandidate.InspectionState != DumpInspectionState.Recognized ||
                stagedCandidate.Format == DumpFormat.Unknown ||
                !stagedCandidate.SizePlausible)
            {
                return new ProtectedDumpOperationResult<T>(
                    false,
                    "The private staging copy did not contain a supported Windows dump signature.",
                    default);
            }

            MiniDumpMetadata metadata = new MiniDumpMetadataReader().Read(stagedCandidate, cancellationToken);
            stagedCandidate = stagedCandidate with { Metadata = metadata };
            if (IsBlocked())
            {
                return new ProtectedDumpOperationResult<T>(
                    false,
                    "The protected dump operation stopped because Battlefield 6 or the protected target started running.",
                    default);
            }

            T value = await operation(
                new PreparedProtectedDump(staged, stagedCandidate),
                cancellationToken).ConfigureAwait(false);
            return new ProtectedDumpOperationResult<T>(
                true,
                "The protected dump operation completed and its private staging copy was deleted.",
                value);
        }
        finally
        {
            if (!_protectedEvidenceHelper.DeleteStagedCopy(staged))
            {
                throw new IOException("The private protected-dump staging copy could not be deleted safely.");
            }
        }
    }

    private DumpCandidate ValidateProtectedDumpSelection(
        DiagnosticOperationResultV3 reportContext,
        DumpCandidate selectedDump)
    {
        DiagnosticReportV3 report = reportContext.Package.Report;
        if (string.IsNullOrWhiteSpace(report.SessionId) ||
            reportContext.Package.Sha256.Length != 64 ||
            reportContext.Package.Sha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException("The report context was not a validated schema-v3 package.");
        }

        DumpCandidate? allowed = report.DumpInventory.Candidates
            .Concat(reportContext.DumpChoices)
            .Concat(report.CrashCorrelation?.RelatedDumps ?? [])
            .FirstOrDefault(candidate => SameDumpIdentity(candidate, selectedDump));
        if (allowed is null || string.IsNullOrWhiteSpace(allowed.OriginalPath))
        {
            throw new InvalidOperationException("The selected protected dump is not in this report's validated dump inventory.");
        }

        string fullPath = Path.GetFullPath(allowed.OriginalPath);
        if (!Path.GetExtension(fullPath).Equals(".dmp", StringComparison.OrdinalIgnoreCase) ||
            !_protectedDumpPathValidator(fullPath))
        {
            throw new InvalidOperationException("The selected dump is outside the approved Windows dump roots.");
        }

        if (allowed.SizeBytes is <= 0 or > ProtectedEvidenceHelper.MaximumDumpBytes ||
            allowed.LastWriteUtc <= DateTimeOffset.UnixEpoch ||
            allowed.InspectionState is not (DumpInspectionState.Recognized or DumpInspectionState.Denied) ||
            (allowed.InspectionState == DumpInspectionState.Recognized && allowed.Format == DumpFormat.Unknown))
        {
            throw new InvalidDataException("The selected protected dump lacks a usable recorded identity or signature state.");
        }

        try
        {
            var current = new FileInfo(fullPath);
            current.Refresh();
            if (current.Exists &&
                (current.Length != allowed.SizeBytes || current.LastWriteTimeUtc != allowed.LastWriteUtc.UtcDateTime))
            {
                throw new IOException("The selected protected dump no longer matches the report inventory.");
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Expected for a protected dump. The elevated helper repeats the
            // exact length, timestamp, signature, reparse, and identity checks.
        }

        return allowed with { OriginalPath = fullPath };
    }

    private static bool SameDumpIdentity(DumpCandidate left, DumpCandidate right)
    {
        if (string.IsNullOrWhiteSpace(left.OriginalPath) || string.IsNullOrWhiteSpace(right.OriginalPath))
        {
            return false;
        }

        try
        {
            return string.Equals(
                       Path.GetFullPath(left.OriginalPath),
                       Path.GetFullPath(right.OriginalPath),
                       StringComparison.OrdinalIgnoreCase) &&
                   left.Kind == right.Kind &&
                   string.Equals(left.Source, right.Source, StringComparison.Ordinal) &&
                   left.SizeBytes == right.SizeBytes &&
                   left.LastWriteUtc == right.LastWriteUtc;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static void ValidateStagedDumpDescriptor(StagedDump staged, DumpCandidate allowed)
    {
        if (staged.SizeBytes != allowed.SizeBytes ||
            staged.SizeBytes is <= 0 or > ProtectedEvidenceHelper.MaximumDumpBytes ||
            staged.Sha256.Length != 64 ||
            staged.Sha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException("The elevated helper returned invalid staging metadata.");
        }

        string directory = Path.GetFullPath(staged.StagingDirectory);
        string path = Path.GetFullPath(staged.Path);
        if (!string.Equals(Path.GetDirectoryName(path), directory, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(directory).StartsWith("stage-", StringComparison.Ordinal) ||
            !Path.GetFileName(path).Equals("protected-dump.dmp", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The elevated helper returned an unexpected staging path.");
        }
    }

    private WerLocalDumpPlan CreateWerLocalDumpPlan(
        DiagnosticOperationResultV3 boundResult,
        string? executableName,
        DateTimeOffset nowUtc,
        bool ordinaryAppConfirmed = false)
    {
        DiagnosticReportV3 report = boundResult.Package.Report;
        TargetProfile target = report.TargetProfile ??
            throw new InvalidOperationException("Per-application dumps require a selected target profile.");
        ValidateTarget(target);
        if (IsExcludedWerTarget(target))
        {
            throw new InvalidOperationException(
                "Per-application WER dumps are not offered for Battlefield 6 or another protected target profile.");
        }
        if (target.BlockSensitiveOperationsWhileRunning && !ordinaryAppConfirmed)
        {
            throw new InvalidOperationException(
                "Confirm that the selected executable is an ordinary app without anti-cheat or other process protection.");
        }

        TargetProfile planTarget = target.BlockSensitiveOperationsWhileRunning
            ? target with { BlockSensitiveOperationsWhileRunning = false }
            : target;
        string selected = string.IsNullOrWhiteSpace(executableName)
            ? target.ProcessNames.FirstOrDefault() ?? string.Empty
            : executableName;
        string baseName = Path.GetFileNameWithoutExtension(selected) + ".exe";
        baseName = WindowsCrashCaptureConfigurationStore.NormalizeExecutableName(baseName);
        if (!target.MatchesProcessName(baseName))
        {
            throw new ArgumentException("The executable was not part of the report's selected target.", nameof(executableName));
        }

        WerConfigurationSnapshot previous = _crashCaptureConfigurationStore.ReadWerSettings(baseName);
        string desiredFolder = ProtectedEvidenceHelper.ApprovedWerDumpFolder(
            ProtectedEvidenceHelper.DefaultWerDumpRoot(),
            baseName);
        return new WerLocalDumpPlan(
            1,
            NewConfigurationId(),
            report.SessionId,
            boundResult.Package.Sha256.ToLowerInvariant(),
            nowUtc.ToUniversalTime(),
            nowUtc.ToUniversalTime().AddMinutes(10),
            baseName,
            previous.KeyExists,
            previous.DumpType.Exists,
            ParseOptionalInt(previous.DumpType),
            previous.DumpCount.Exists,
            ParseOptionalInt(previous.DumpCount),
            previous.DumpFolder.Exists,
            previous.DumpFolder.Value,
            DesiredDumpType: 2,
            DesiredDumpCount: 2,
            desiredFolder,
            planTarget,
            PreviousDumpTypeRegistryValueKind: previous.DumpType.RegistryValueKind,
            PreviousDumpCountRegistryValueKind: previous.DumpCount.RegistryValueKind,
            PreviousDumpFolderRegistryValueKind: previous.DumpFolder.RegistryValueKind);
    }

    private static bool IsExcludedWerTarget(TargetProfile target)
    {
        if (target.Id.Equals(TargetProfile.Battlefield6.Id, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string[] protectedNames = ["BF6", "EAAntiCheat", "Javelin"];
        return target.ProcessNames
                   .Concat(target.RelatedProcessNames)
                   .Any(name => protectedNames.Contains(
                       Path.GetFileNameWithoutExtension(name),
                       StringComparer.OrdinalIgnoreCase)) ||
               target.ApplicationEventSignals.Any(signal =>
                   signal.Contains("anti-cheat", StringComparison.OrdinalIgnoreCase) ||
                   signal.Contains("anticheat", StringComparison.OrdinalIgnoreCase));
    }

    private static int? ParseOptionalInt(StoredConfigurationValue value)
    {
        if (!value.Exists)
        {
            return null;
        }

        return int.TryParse(
            value.Value,
            System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,
            out int parsed)
            ? parsed
            : throw new InvalidDataException("Windows exposed a non-numeric WER setting.");
    }

    private static CrashCaptureChange ToChange(
        CrashCaptureSetting setting,
        StoredConfigurationValue current,
        StoredConfigurationValue desired,
        PageFileConfigurationSnapshot? previousPageFileConfiguration = null) => new(
            setting,
            current.Exists,
            current.Value,
            desired.Exists,
            desired.Value,
            RequiresRestart: true,
            previousPageFileConfiguration,
            current.RegistryValueKind,
            desired.RegistryValueKind);

    private static IEnumerable<(CrashCaptureSetting Setting, StoredConfigurationValue Value)>
        AutomaticCrashCapturePresetValues()
    {
        yield return (CrashCaptureSetting.CrashDumpEnabled, new StoredConfigurationValue(true, "7", (int)Microsoft.Win32.RegistryValueKind.DWord));
        yield return (CrashCaptureSetting.FilterPages, new StoredConfigurationValue(false, null));
        yield return (CrashCaptureSetting.DumpFile, new StoredConfigurationValue(true, @"%SystemRoot%\MEMORY.DMP", (int)Microsoft.Win32.RegistryValueKind.ExpandString));
        yield return (CrashCaptureSetting.EventLogging, new StoredConfigurationValue(true, "1", (int)Microsoft.Win32.RegistryValueKind.DWord));
        yield return (CrashCaptureSetting.OverwriteExistingDump, new StoredConfigurationValue(true, "1", (int)Microsoft.Win32.RegistryValueKind.DWord));
    }

    private static void ValidateConfigurationReportBinding(DiagnosticOperationResultV3 result)
    {
        ArgumentNullException.ThrowIfNull(result);
        DiagnosticReportV3 report = result.Package.Report;
        if (report.ReportSchemaVersion != 3 ||
            !SessionIdValidator.IsValid(report.SessionId) ||
            result.Package.Sha256 is not { Length: 64 } hash ||
            hash.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException("Crash-capture preparation requires a valid schema-v3 report binding.");
        }

        if (report.TargetProfile is not null)
        {
            ValidateTarget(report.TargetProfile);
        }
    }

    private static void ValidatePlanBinding(
        DiagnosticOperationResultV3 boundResult,
        CrashCapturePlan plan)
    {
        if (plan.SchemaVersion != 1 ||
            plan.PlanId is not { Length: 32 } || plan.PlanId.Any(character => !Uri.IsHexDigit(character)) ||
            !string.Equals(plan.ReportSessionId, boundResult.Package.Report.SessionId, StringComparison.Ordinal) ||
            !string.Equals(plan.ReportSha256, boundResult.Package.Sha256, StringComparison.OrdinalIgnoreCase) ||
            plan.ExpiresUtc < DateTimeOffset.UtcNow ||
            plan.ExpiresUtc - plan.CreatedUtc > TimeSpan.FromMinutes(15) ||
            plan.Preset != CrashCapturePreset.AutomaticMemoryDump ||
            plan.Changes is null || plan.Changes.Count > Enum.GetValues<CrashCaptureSetting>().Length)
        {
            throw new InvalidDataException("The crash-capture preview was invalid, expired, or belonged to another report.");
        }

        if (plan.TargetProfile is not null)
        {
            ValidateTarget(plan.TargetProfile);
        }

        if (plan.WerLocalDumpPlan is not null)
        {
            ValidateWerPlanBinding(boundResult, plan.WerLocalDumpPlan);
        }
    }

    private static void ValidateWerPlanBinding(
        DiagnosticOperationResultV3 boundResult,
        WerLocalDumpPlan plan)
    {
        if (plan.SchemaVersion != 1 ||
            plan.PlanId is not { Length: 32 } || plan.PlanId.Any(character => !Uri.IsHexDigit(character)) ||
            !string.Equals(plan.ReportSessionId, boundResult.Package.Report.SessionId, StringComparison.Ordinal) ||
            !string.Equals(plan.ReportSha256, boundResult.Package.Sha256, StringComparison.OrdinalIgnoreCase) ||
            plan.ExpiresUtc < DateTimeOffset.UtcNow ||
            plan.ExpiresUtc - plan.CreatedUtc > TimeSpan.FromMinutes(15) ||
            plan.DesiredDumpType != 2 || plan.DesiredDumpCount != 2)
        {
            throw new InvalidDataException("The per-application dump preview was invalid, expired, or belonged to another report.");
        }

        _ = WindowsCrashCaptureConfigurationStore.NormalizeExecutableName(plan.ExecutableName);
        string expectedFolder = ProtectedEvidenceHelper.ApprovedWerDumpFolder(
            ProtectedEvidenceHelper.DefaultWerDumpRoot(),
            plan.ExecutableName);
        if (!string.Equals(Path.GetFullPath(plan.DesiredDumpFolder), expectedFolder, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The per-application dump folder was not the fixed private destination.");
        }

        if (plan.TargetProfile is not null)
        {
            ValidateTarget(plan.TargetProfile);
        }
    }

    private static CrashCaptureReceipt ValidateCrashCaptureApplyResponse(
        ProtectedEvidenceResponse response,
        CrashCapturePlan plan)
    {
        if (response.Probe is not null || response.StagedDump is not null || response.EvidenceBatch is not null ||
            response.CrashCaptureReceipt is not { } receipt || receipt.Restored ||
            !string.Equals(receipt.PlanId, plan.PlanId, StringComparison.Ordinal) ||
            !string.Equals(receipt.ReportSessionId, plan.ReportSessionId, StringComparison.Ordinal) ||
            !string.Equals(receipt.ReportSha256, plan.ReportSha256, StringComparison.OrdinalIgnoreCase) ||
            receipt.AppliedChanges.Count != plan.Changes.Count ||
            receipt.ActivationState != (plan.RequiresRestart
                ? CrashCaptureActivationState.PendingRestart
                : CrashCaptureActivationState.Active))
        {
            throw new InvalidDataException("The elevated helper returned an invalid crash-capture receipt.");
        }

        return receipt;
    }

    private static bool CanRestoreRegistryValueExactly(StoredConfigurationValue value)
    {
        if (!value.Exists)
        {
            return value.RegistryValueKind is null;
        }

        return value.RegistryValueKind is (int)Microsoft.Win32.RegistryValueKind.DWord or
            (int)Microsoft.Win32.RegistryValueKind.QWord or
            (int)Microsoft.Win32.RegistryValueKind.String or
            (int)Microsoft.Win32.RegistryValueKind.ExpandString;
    }

    private bool AppliedConfigurationStillMatches(CrashCaptureReceipt receipt)
    {
        try
        {
            foreach (CrashCaptureChange change in receipt.AppliedChanges)
            {
                var desired = new StoredConfigurationValue(
                    change.DesiredValueExists,
                    change.DesiredValue,
                    change.DesiredRegistryValueKind);
                if (_crashCaptureConfigurationStore.ReadCrashSetting(change.Setting) != desired)
                {
                    return false;
                }

                if (change.Setting == CrashCaptureSetting.AutomaticManagedPagefile &&
                    (change.AppliedPageFileConfiguration is not { } applied ||
                     !PageFileConfigurationsEqual(
                         applied,
                         _crashCaptureConfigurationStore.ReadPageFileConfiguration())))
                {
                    return false;
                }
            }

            return receipt.WerLocalDumpReceipt is not { } wer ||
                   WerConfigurationComparison.Matches(
                       _crashCaptureConfigurationStore.ReadWerSettings(wer.ExecutableName),
                       AppliedWerSettings(wer));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          InvalidDataException or System.Management.ManagementException or
                                          System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private bool PreviousConfigurationStillMatches(CrashCaptureReceipt receipt)
    {
        try
        {
            foreach (CrashCaptureChange change in receipt.AppliedChanges)
            {
                var previous = new StoredConfigurationValue(
                    change.PreviousValueExists,
                    change.PreviousValue,
                    change.PreviousRegistryValueKind);
                if (_crashCaptureConfigurationStore.ReadCrashSetting(change.Setting) != previous)
                {
                    return false;
                }

                if (change.Setting == CrashCaptureSetting.AutomaticManagedPagefile &&
                    (change.PreviousPageFileConfiguration is not { } prior ||
                     !PageFileConfigurationsEqual(
                         prior,
                         _crashCaptureConfigurationStore.ReadPageFileConfiguration())))
                {
                    return false;
                }
            }

            return receipt.WerLocalDumpReceipt is not { } wer ||
                   WerConfigurationComparison.Matches(
                       _crashCaptureConfigurationStore.ReadWerSettings(wer.ExecutableName),
                       PreviousWerSettings(wer));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          InvalidDataException or System.Management.ManagementException or
                                          System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static bool PageFileConfigurationsEqual(
        PageFileConfigurationSnapshot left,
        PageFileConfigurationSnapshot right) =>
        left.AutomaticManagementStateKnown == right.AutomaticManagementStateKnown &&
        left.AutomaticManagementEnabled == right.AutomaticManagementEnabled &&
        left.PagingFilesValueExists == right.PagingFilesValueExists &&
        left.PagingFiles.SequenceEqual(right.PagingFiles, StringComparer.Ordinal);

    private static WerConfigurationSnapshot AppliedWerSettings(WerLocalDumpReceipt receipt) => new(
        true,
        new StoredConfigurationValue(true, receipt.AppliedDumpType.ToString(System.Globalization.CultureInfo.InvariantCulture), (int)Microsoft.Win32.RegistryValueKind.DWord),
        new StoredConfigurationValue(true, receipt.AppliedDumpCount.ToString(System.Globalization.CultureInfo.InvariantCulture), (int)Microsoft.Win32.RegistryValueKind.DWord),
        new StoredConfigurationValue(true, receipt.AppliedDumpFolder, (int)Microsoft.Win32.RegistryValueKind.ExpandString));

    private static WerConfigurationSnapshot PreviousWerSettings(WerLocalDumpReceipt receipt) => new(
        receipt.PreviousKeyExists,
        new StoredConfigurationValue(receipt.PreviousDumpTypeExists, OptionalNumber(receipt.PreviousDumpType), receipt.PreviousDumpTypeRegistryValueKind),
        new StoredConfigurationValue(receipt.PreviousDumpCountExists, OptionalNumber(receipt.PreviousDumpCount), receipt.PreviousDumpCountRegistryValueKind),
        new StoredConfigurationValue(receipt.PreviousDumpFolderExists, receipt.PreviousDumpFolder, receipt.PreviousDumpFolderRegistryValueKind));

    private static string? OptionalNumber(int? value) =>
        value?.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static CrashCapturePreparationResult FailedPreparation(
        string message,
        CrashCapturePlan? plan = null,
        CrashReadiness? before = null) => new(
            false,
            message,
            plan,
            null,
            null,
            before,
            null,
            CrashCaptureActivationState.Unknown,
            false,
            false);

    private static string NewConfigurationId() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    private bool IsSensitiveOperationBlocked(TargetProfile? targetProfile)
    {
        try
        {
            return _isBf6RunningFailClosed() || IsTargetRunningFailClosed(targetProfile);
        }
        catch
        {
            return true;
        }
    }

    private static TimeSpan NormalizeHelperTimeout(TimeSpan? timeout)
    {
        TimeSpan value = timeout ?? TimeSpan.FromMinutes(10);
        if (value < TimeSpan.FromSeconds(30) || value > TimeSpan.FromHours(2))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "The helper timeout must be between 30 seconds and 2 hours.");
        }

        return value;
    }

    internal async Task<DumpInventory> CollectDumpInventoryForReportAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        bool IsBlocked() => IsSensitiveOperationBlocked(targetProfile);

        try
        {
            if (IsBlocked())
            {
                throw new SensitiveDumpOperationBlockedException();
            }

            DumpInventory inventory = await _dumpCollector
                .CollectAsync(startUtc, endUtc, targetProfile, cancellationToken, IsBlocked)
                .ConfigureAwait(false);

            // The collector returns an unavailable inventory when its boundary
            // changes. Preserve that result even if the target exits again before
            // this continuation runs.
            if (inventory.Statuses.Any(status =>
                    status.Source.Equals("Dump inventory", StringComparison.OrdinalIgnoreCase) &&
                    status.State == CollectionState.Unavailable))
            {
                return inventory;
            }

            if (IsBlocked())
            {
                throw new SensitiveDumpOperationBlockedException();
            }

            var metadataReader = new MiniDumpMetadataReader();
            var enriched = new List<DumpCandidate>(inventory.Candidates.Count);
            foreach (DumpCandidate candidate in inventory.Candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (IsBlocked())
                {
                    throw new SensitiveDumpOperationBlockedException();
                }

                MiniDumpMetadata metadata = metadataReader.Read(
                    candidate,
                    cancellationToken,
                    IsBlocked);
                if (IsBlocked())
                {
                    throw new SensitiveDumpOperationBlockedException();
                }

                enriched.Add(candidate with { Metadata = metadata });
            }

            if (IsBlocked())
            {
                throw new SensitiveDumpOperationBlockedException();
            }

            return inventory with { Candidates = enriched.ToArray() };
        }
        catch (SensitiveDumpOperationBlockedException)
        {
            return BlockedDumpInventory();
        }
    }

    private static DumpInventory BlockedDumpInventory() => new(
        [],
        [new CollectionStatus(
            "Dump inventory",
            CollectionState.Unavailable,
            "Dump inspection stopped because Battlefield 6 or the protected target started running; partial results were discarded.")]);

    public void Dispose() => _disposed = true;

    private async Task<RecentChangeTimeline?> CollectRecentChangesForReleaseAsync(
        DateTimeOffset incidentTimeUtc,
        CancellationToken cancellationToken)
    {
        if (!ReleaseStage.Beta2FeaturesEnabled)
        {
            return null;
        }

        return await _recentChangeCollector
            .CollectForIncidentAsync(incidentTimeUtc, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<StorageHealthSnapshot?> CollectStorageHealthForReleaseAsync(
        CancellationToken cancellationToken)
    {
        if (!ReleaseStage.Beta2FeaturesEnabled)
        {
            return null;
        }

        return await _storageHealthCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<DriverVerifierState?> CollectDriverVerifierForReleaseAsync(
        CancellationToken cancellationToken)
    {
        if (!ReleaseStage.Beta2FeaturesEnabled)
        {
            return null;
        }

        return await _driverVerifierCollector.CollectAsync(cancellationToken).ConfigureAwait(false);
    }

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
        Task<WindowsEventCollection> eventTask = _eventCollector.CollectWindowAsync(startUtc, endUtc, targetProfile, cancellationToken);
        Task<ReliabilityCollection> reliabilityTask = _reliabilityCollector.CollectAsync(startUtc, endUtc, targetProfile, cancellationToken);
        Task<ArtifactCollection> artifactTask = _artifactCollector.CollectAsync(startUtc, endUtc, targetProfile, cancellationToken);
        Task<CrashReadinessCollection> readinessTask = _collectReadinessAsync(cancellationToken);
        Task<DriverInventory> driverTask = _driverCollector.CollectAsync(cancellationToken);
        Task<RecentChangeTimeline?> recentChangesTask = CollectRecentChangesForReleaseAsync(
            selection.Candidate.TimeUtc,
            cancellationToken);
        Task<StorageHealthSnapshot?> storageHealthTask = CollectStorageHealthForReleaseAsync(cancellationToken);
        Task<DriverVerifierState?> driverVerifierTask = CollectDriverVerifierForReleaseAsync(cancellationToken);
        Task<DumpInventory> dumpTask = CollectDumpInventoryForReportAsync(
            startUtc,
            endUtc,
            targetProfile,
            cancellationToken);

        WindowsEventCollection events = await eventTask.ConfigureAwait(false);
        ReliabilityCollection reliability = await reliabilityTask.ConfigureAwait(false);
        ArtifactCollection artifacts = await artifactTask.ConfigureAwait(false);
        CrashReadinessCollection readiness = await readinessTask.ConfigureAwait(false);
        DriverInventory drivers = await driverTask.ConfigureAwait(false);
        RecentChangeTimeline? recentChanges = await recentChangesTask.ConfigureAwait(false);
        StorageHealthSnapshot? storageHealth = await storageHealthTask.ConfigureAwait(false);
        DriverVerifierState? driverVerifier = await driverVerifierTask.ConfigureAwait(false);
        DumpInventory dumps = await dumpTask.ConfigureAwait(false);
        IReadOnlyList<BugcheckRecord> bugchecks = BugcheckRecordDecoder.Decode(events.Events);
        CrashCorrelation correlation = _correlator.Correlate(selection, bugchecks, dumps.Candidates, endSnapshot?.LastBootUtc);
        DumpQuality? dumpQuality = !ReleaseStage.Beta2FeaturesEnabled || correlation.SelectedDump is null
            ? null
            : await _dumpQualityCollector.InspectAsync(
                    new DumpQualityRequest(correlation.SelectedDump),
                    cancellationToken,
                    () => IsSensitiveOperationBlocked(targetProfile))
                .ConfigureAwait(false);
        CrashAnchor anchor = new(
            selection.Candidate.TimeUtc,
            selection.Candidate.Source,
            selection.Candidate.EventId,
            selection.Candidate.Title,
            selection.Candidate.BugcheckCode,
            selection.Candidate.DumpFileName,
            selection.Candidate.EvidencePriority);
        IReadOnlyList<PerformanceSample> compatibilitySamples = samples.Select(ToCompatibilitySample).ToArray();
        IReadOnlyList<DuplicateEventGroup> groups = _eventAnalyzer.GroupDuplicates(events.Events);
        var findings = _eventAnalyzer.Analyze(
                anchor,
                events.Events,
                groups,
                reliability.Records,
                artifacts.Artifacts,
                compatibilitySamples,
                targetProfile)
            .Concat(CreateWheaCategoryFindings(events.Events))
            .Concat(_extendedEvidenceAnalyzer.Analyze(dumpQuality, recentChanges, storageHealth, driverVerifier))
            .OrderBy(finding => finding.Rank)
            .ToArray();

        DiagnosticEvent[] safeEvents = events.Events.Select(_redactor.RedactEvent).ToArray();
        DuplicateEventGroup[] safeGroups = groups.Select(_redactor.RedactGroup).ToArray();
        ReliabilityRecord[] safeReliability = reliability.Records.Select(_redactor.RedactReliability).ToArray();
        CrashArtifact[] safeArtifacts = artifacts.Artifacts.Select(_redactor.RedactArtifact).ToArray();
        DiagnosticFinding[] safeFindings = findings.Select(_redactor.RedactFinding).ToArray();
        CollectionStatus[] statuses = initialStatuses
            .Concat(events.Statuses)
            .Concat(reliability.Statuses)
            .Concat(artifacts.Statuses)
            .Concat(readiness.Statuses)
            .Concat(dumps.Statuses)
            .Concat(drivers.Statuses)
            .Concat(recentChanges?.CollectionStatus ?? [])
            .Concat(storageHealth?.CollectionStatus ?? [])
            .Concat(ReleaseStage.Beta2FeaturesEnabled
                ? [CreateDumpQualityStatus(dumpQuality, correlation)]
                : [])
            .Concat(driverVerifier is null
                ? []
                : [CreateDriverVerifierStatus(driverVerifier)])
            .Select(_redactor.RedactStatus)
            .GroupBy(status => new { status.Source, status.State, status.Detail })
            .Select(group => group.First())
            .ToArray();
        SourceCoverage[] coverage = BuildCoverage(
            statuses,
            safeEvents,
            safeReliability,
            safeArtifacts,
            dumps.Candidates,
            drivers,
            readiness.Readiness,
            dumpQuality,
            recentChanges,
            storageHealth,
            driverVerifier);
        string summary = _summaryBuilder.Build(
            ToolVersion,
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
            dumpQuality,
            recentChanges,
            storageHealth,
            driverVerifier);
        var report = new DiagnosticReportV3(
            3,
            ToolVersion,
            ProductName,
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
            RedactDrivers(drivers),
            correlation,
            null,
            selection.Candidate.Fingerprint,
            summary,
            dumpQuality,
            recentChanges,
            storageHealth,
            driverVerifier);

        progress?.Report(new DiagnosticProgress("Packaging", "Writing the local schema-v3 report and checksum.", 0.88));
        ReportPackageV3 package = await _reportWriter.WriteV3Async(report, cancellationToken).ConfigureAwait(false);
        foreach (DumpCandidate candidate in correlation.RelatedDumps)
        {
            if (candidate.OriginalPath is not null && DumpPackager.TryCaptureIdentity(
                    candidate.OriginalPath,
                    candidate.SizeBytes,
                    candidate.LastWriteUtc,
                    out DumpArtifactIdentity identity))
            {
                _boundDumps[identity.FullPath] = new BoundDump(
                    identity,
                    sessionId,
                    package.Sha256,
                    candidate.Source,
                    targetProfile);
            }
        }

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
        IProgress<TargetMonitorProgress>? progress,
        CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + EvidencePollLimit;
        int poll = 0;
        while (true)
        {
            IncidentCandidate? candidate = await FindBestIncidentAsync(startedUtc, DateTimeOffset.UtcNow, target, cancellationToken).ConfigureAwait(false);
            if (candidate is not null && candidate.TimeUtc >= disappearedUtc.AddMinutes(-2))
            {
                return candidate;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                return null;
            }

            poll++;
            progress?.Report(new TargetMonitorProgress(
                "Checking Windows records",
                "No matching crash record yet; the app remains classified as closed.",
                Percent: Math.Min(0.8, 0.15 + poll / 12d * 0.65)));
            await _delayAsync(MonitorInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<IncidentCandidate?> FindBestIncidentAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile target,
        CancellationToken cancellationToken)
    {
        WindowsEventCollection events = await _eventCollector.CollectWindowAsync(startUtc, endUtc, target, cancellationToken).ConfigureAwait(false);
        return _incidentDiscovery.Discover(events.Events, targetProfile: target)
            .OrderByDescending(candidate => candidate.TimeUtc)
            .FirstOrDefault();
    }

    private static IReadOnlyList<DiagnosticFinding> CreateWheaCategoryFindings(IEnumerable<DiagnosticEvent> events)
    {
        var findings = new List<DiagnosticFinding>();
        foreach (IGrouping<string, DecodedWheaEvent> group in events
                     .Select(item => WheaEventDecoder.TryDecode(item, out DecodedWheaEvent? decoded) ? decoded : null)
                     .Where(item => item is not null && item.Fields.TryGetValue("CperSectionCategories", out _))
                     .Cast<DecodedWheaEvent>()
                     .GroupBy(item => item.Fields["CperSectionCategories"], StringComparer.OrdinalIgnoreCase))
        {
            findings.Add(new DiagnosticFinding(
                "whea-cper-" + group.Key.Replace(' ', '-').ToLowerInvariant(),
                35,
                FindingSeverity.Warning,
                FindingConfidence.High,
                "Hardware error record",
                $"WHEA {group.Key} section",
                $"Windows stored {group.Count()} standardized hardware error record{(group.Count() == 1 ? string.Empty : "s")} with {group.Key} section metadata.",
                "The section category can help choose the next diagnostic check.",
                "The record does not establish that a particular component is defective.",
                "Compare repeated records and any matching bugcheck or debugger evidence before testing hardware.",
                group.Count()));
        }

        return findings;
    }

    private static TargetPerformanceSample ToTargetSample(PerformanceSample sample) => new(
        sample.TimestampUtc,
        sample.BF6Running,
        sample.BF6Running ? 1 : 0,
        sample.SystemCpuPct,
        sample.SystemMemoryUsedGB,
        sample.SystemMemoryAvailableGB,
        sample.SystemCommittedGB,
        sample.SystemCommitLimitGB,
        sample.SystemCommitPct,
        sample.BF6WorkingSetMB,
        sample.BF6PrivateMB,
        sample.BF6CpuPct,
        sample.BF6Gpu3DPct,
        sample.BF6GpuMaxEnginePct,
        sample.BF6DedicatedGpuMB,
        sample.BF6SharedGpuMB,
        sample.SampleCollectionMs);

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

    private static CollectionStatus CreateDumpQualityStatus(
        DumpQuality? quality,
        CrashCorrelation correlation)
    {
        if (quality is null)
        {
            string detail = correlation.RelatedDumps.Count == 0
                ? "No related dump was available for the selected incident."
                : "No single dump was selected because correlation was ambiguous; select a dump before quality inspection.";
            return new CollectionStatus("Dump quality", CollectionState.Unavailable, detail);
        }

        CollectionState state = quality.Classification switch
        {
            DumpQualityClassification.Inaccessible => CollectionState.Denied,
            DumpQualityClassification.AnalysisUnavailable => CollectionState.Unavailable,
            _ => CollectionState.Available
        };
        return new CollectionStatus("Dump quality", state, quality.Detail);
    }

    private static bool IsExtendedEvidenceFinding(string id) =>
        id.StartsWith("dump-quality-", StringComparison.Ordinal) ||
        id.Equals("storage-health-warning", StringComparison.Ordinal) ||
        id.Equals("driver-verifier-enabled", StringComparison.Ordinal) ||
        id.Equals("recent-system-changes", StringComparison.Ordinal);

    private static CollectionStatus CreateDriverVerifierStatus(DriverVerifierState verifier)
    {
        CollectionState state = verifier.Status switch
        {
            DriverVerifierStatusKind.Disabled or
                DriverVerifierStatusKind.Enabled or
                DriverVerifierStatusKind.Indeterminate => CollectionState.Available,
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
        DumpQuality? dumpQuality = null,
        RecentChangeTimeline? recentChanges = null,
        StorageHealthSnapshot? storageHealth = null,
        DriverVerifierState? driverVerifier = null)
    {
        return statuses
            .GroupBy(status => status.Source, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                CollectionStatus status = group.Last();
                int count = status.Source switch
                {
                    string source when source.Contains("Event Log/System", StringComparison.OrdinalIgnoreCase) =>
                        events.Count(item => item.LogName.Equals("System", StringComparison.OrdinalIgnoreCase)),
                    string source when source.Contains("Event Log/Application", StringComparison.OrdinalIgnoreCase) =>
                        events.Count(item => item.LogName.Equals("Application", StringComparison.OrdinalIgnoreCase)),
                    string source when source.Contains("Reliability", StringComparison.OrdinalIgnoreCase) => reliability.Count,
                    string source when source.Contains("artifact", StringComparison.OrdinalIgnoreCase) => artifacts.Count,
                    string source when source.Contains("Dump inventory", StringComparison.OrdinalIgnoreCase) => dumps.Count,
                    string source when source.Contains("Driver inventory", StringComparison.OrdinalIgnoreCase) => drivers?.Drivers.Count ?? 0,
                    string source when source.Contains("Crash readiness", StringComparison.OrdinalIgnoreCase) => readiness is null ? 0 : 1,
                    string source when source.Contains("Dump quality", StringComparison.OrdinalIgnoreCase) => dumpQuality is null ? 0 : 1,
                    string source when source.Contains("Windows Update history", StringComparison.OrdinalIgnoreCase) =>
                        recentChanges?.Records.Count(item => item.Kind == RecentChangeKind.WindowsUpdate) ?? 0,
                    string source when source.Contains("SetupAPI", StringComparison.OrdinalIgnoreCase) =>
                        recentChanges?.Records.Count(item => item.Kind == RecentChangeKind.DriverInstallation) ?? 0,
                    string source when source.Contains("Storage health", StringComparison.OrdinalIgnoreCase) => storageHealth?.Devices.Count ?? 0,
                    string source when source.Contains("Driver Verifier", StringComparison.OrdinalIgnoreCase) => driverVerifier is null ? 0 : 1,
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

        if (options.EndUtc > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The incident search cannot end in the future.");
        }
    }

    private static void ValidateSelection(IncidentSelection selection)
    {
        ArgumentNullException.ThrowIfNull(selection);
        if (selection.WindowEndUtc < selection.WindowStartUtc || selection.Candidate.TimeUtc < selection.WindowStartUtc ||
            selection.Candidate.TimeUtc > selection.WindowEndUtc)
        {
            throw new ArgumentException("The incident selection window is invalid.", nameof(selection));
        }
    }

    private static void ValidateTarget(TargetProfile target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.ProcessNames.Count is 0 or > 16 ||
            target.ProcessNames.Any(name => string.IsNullOrWhiteSpace(name) ||
                                            !string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal) ||
                                            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) ||
            target.RelatedProcessNames.Count > 32 ||
            target.RelatedProcessNames.Any(name => string.IsNullOrWhiteSpace(name) ||
                                                   !string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal) ||
                                                   name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
        {
            throw new ArgumentException("The target profile contains an invalid executable name.", nameof(target));
        }

        TargetPrivacyRules privacy = target.EffectivePrivacyRules;
        if (privacy.ReadProcessMemory || privacy.ReadModules || privacy.ReadCommandLines || privacy.ReadInputs ||
            privacy.ReadAntiCheatData || privacy.ExportProcessIds)
        {
            throw new ArgumentException("This app accepts only privacy-bounded target profiles.", nameof(target));
        }
    }

    private static bool IsTargetRunningFailClosed(TargetProfile? target)
    {
        if (target is null || !target.BlockSensitiveOperationsWhileRunning)
        {
            return false;
        }

        try
        {
            return target.ProcessNames
                .Concat(target.RelatedProcessNames)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Any(IsProcessRunning);
        }
        catch
        {
            return true;
        }
    }

    private static bool IsBf6RunningFailClosed()
    {
        try
        {
            return IsProcessRunning("BF6");
        }
        catch
        {
            return true;
        }
    }

    private static bool IsProcessRunning(string processName)
    {
        Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));
        try
        {
            return processes.Any(process =>
            {
                try
                {
                    return !process.HasExited;
                }
                catch
                {
                    return true;
                }
            });
        }
        finally
        {
            foreach (Process process in processes)
            {
                process.Dispose();
            }
        }
    }

    private static DateTimeOffset EstimateCurrentBootUtc() =>
        DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64));

    private static string CreateSessionId(DateTimeOffset timeUtc) =>
        timeUtc.ToUniversalTime().ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8];

    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private sealed record BoundDump(
        DumpArtifactIdentity Identity,
        string SessionId,
        string ReportSha256,
        string SourceType,
        TargetProfile? TargetProfile);

    private sealed record PreparedProtectedDump(
        StagedDump StagedDump,
        DumpCandidate Candidate);
}
