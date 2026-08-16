using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Fixed-operation implementation intended to be hosted by the one-shot UAC
/// helper. It cannot launch a debugger, run arbitrary commands, accept an
/// arbitrary destination, or copy files outside approved Windows dump roots.
/// </summary>
public sealed class ProtectedEvidenceHelper
{
    public const long MaximumDumpBytes = 64L * 1024 * 1024 * 1024;
    internal const int MaximumRetryEvents = 12;
    internal const int MaximumRetryDumps = 16;
    internal const int MaximumRetryStatuses = 2;
    private const string MarkerName = ".pc-crash-diagnostic-staging";
    private readonly string _stagingRoot;
    private readonly ProtectedEvidenceRoots _roots;
    private readonly Func<string, long> _availableFreeSpace;
    private readonly Func<bool> _isProtectedTargetRunning;
    private readonly ICrashCaptureConfigurationStore _configurationStore;
    private readonly CrashCaptureReceiptStore _receiptStore;
    private readonly TimeProvider _timeProvider;
    private readonly string _werDumpRoot;
    private readonly Func<string, IReadOnlyList<WerProcessIdentity>> _matchingProcessIdentities;
    private readonly Func<string, bool> _isNamedProcessRunning;
    private readonly System.Security.Principal.SecurityIdentifier _originatingUserSid;
    private readonly bool _productionOriginBoundary;
    private readonly PrivacyRedactor _redactor = new();

    internal string StagingRoot => _stagingRoot;

    public ProtectedEvidenceHelper()
        : this(
            DefaultStagingRoot(),
            ProtectedEvidenceRoots.CreateDefault(),
            GetAvailableFreeSpace,
            IsBattlefield6Running,
            new WindowsCrashCaptureConfigurationStore(),
            new CrashCaptureReceiptStore(),
            TimeProvider.System,
            DefaultWerDumpRoot())
    {
    }

    internal ProtectedEvidenceHelper(
        string stagingRoot,
        ProtectedEvidenceRoots roots,
        Func<string, long>? availableFreeSpace = null,
        Func<bool>? isProtectedTargetRunning = null,
        ICrashCaptureConfigurationStore? configurationStore = null,
        CrashCaptureReceiptStore? receiptStore = null,
        TimeProvider? timeProvider = null,
        string? werDumpRoot = null,
        Func<string, IReadOnlyList<WerProcessIdentity>>? matchingProcessIdentities = null,
        string? originatingUserSid = null,
        Func<string, bool>? isNamedProcessRunning = null)
    {
        _stagingRoot = Path.GetFullPath(stagingRoot);
        _roots = roots;
        _availableFreeSpace = availableFreeSpace ?? GetAvailableFreeSpace;
        _isProtectedTargetRunning = isProtectedTargetRunning ?? (() => false);
        _configurationStore = configurationStore ?? new WindowsCrashCaptureConfigurationStore();
        _receiptStore = receiptStore ?? new CrashCaptureReceiptStore();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _werDumpRoot = Path.GetFullPath(werDumpRoot ?? DefaultWerDumpRoot());
        _matchingProcessIdentities = matchingProcessIdentities ?? GetMatchingProcessIdentities;
        _isNamedProcessRunning = isNamedProcessRunning ?? IsProcessRunningFailClosed;
        _originatingUserSid = string.IsNullOrWhiteSpace(originatingUserSid)
            ? System.Security.Principal.WindowsIdentity.GetCurrent().User ??
              throw new InvalidOperationException("The originating Windows user SID was unavailable.")
            : new System.Security.Principal.SecurityIdentifier(originatingUserSid);
        _productionOriginBoundary = !string.IsNullOrWhiteSpace(originatingUserSid);
    }

    public static ProtectedEvidenceHelper CreateForElevatedOrigin(ElevatedHelperOrigin origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        var sid = new System.Security.Principal.SecurityIdentifier(origin.OriginatingUserSid);
        string dataRoot = MachineDataRoot(sid);
        EnsureMachineDataRoot(dataRoot, sid);
        return new ProtectedEvidenceHelper(
            Path.Combine(dataRoot, "ProtectedStaging"),
            ProtectedEvidenceRoots.CreateDefault(),
            GetAvailableFreeSpace,
            IsBattlefield6Running,
            new WindowsCrashCaptureConfigurationStore(),
            CrashCaptureReceiptStore.CreateForElevatedOrigin(dataRoot, sid),
            TimeProvider.System,
            Path.Combine(dataRoot, "ApplicationDumps"),
            matchingProcessIdentities: null,
            originatingUserSid: sid.Value);
    }

    public async Task<ProtectedEvidenceResponse> ExecuteAsync(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_isProtectedTargetRunning())
        {
            return new ProtectedEvidenceResponse(
                false,
                "Protected evidence operations are unavailable while Battlefield 6 is running.");
        }
        if (!ReleaseStage.WerLocalDumpCaptureEnabled &&
            (request.Operation == ProtectedEvidenceOperation.ApplyWerLocalDumpPlan ||
             request.CrashCapturePlan?.WerLocalDumpPlan is not null))
        {
            return new ProtectedEvidenceResponse(
                false,
                "Per-application crash capture is not enabled in this build. Existing saved settings can still be restored.");
        }

        return request.Operation switch
        {
            ProtectedEvidenceOperation.RetryNamedSource =>
                await RetryNamedSourceAsync(request, cancellationToken).ConfigureAwait(false),
            ProtectedEvidenceOperation.CopySelectedDump =>
                await CopySelectedDumpAsync(request, cancellationToken).ConfigureAwait(false),
            ProtectedEvidenceOperation.ApplyCrashCapturePlan =>
                ApplyCrashCapturePlan(request, cancellationToken),
            ProtectedEvidenceOperation.RestoreCrashCapturePlan =>
                RestoreCrashCapturePlan(request, cancellationToken),
            ProtectedEvidenceOperation.ApplyWerLocalDumpPlan =>
                ApplyWerLocalDumpPlan(request, cancellationToken),
            ProtectedEvidenceOperation.RestoreWerLocalDumpPlan =>
                RestoreWerLocalDumpPlan(request, cancellationToken),
            _ => new ProtectedEvidenceResponse(false, "The helper operation was not recognized.")
        };
    }

    public int CleanupStaleStagingDirectories(DateTimeOffset nowUtc)
    {
        PathSafety.EnsureNoReparseComponents(_stagingRoot);
        if (!Directory.Exists(_stagingRoot))
        {
            return 0;
        }

        int removed = 0;
        foreach (string directory in Directory.EnumerateDirectories(
                     _stagingRoot,
                     "stage-*",
                     SearchOption.TopDirectoryOnly))
        {
            try
            {
                string fullDirectory = PathSafety.EnsureContained(_stagingRoot, directory);
                PathSafety.EnsureNoReparseComponents(_stagingRoot, fullDirectory);
                string marker = Path.Combine(fullDirectory, MarkerName);
                if (!File.Exists(marker) || ContainsReparseEntry(fullDirectory))
                {
                    continue;
                }

                DateTimeOffset createdUtc = File.GetCreationTimeUtc(marker);
                if (nowUtc - createdUtc < TimeSpan.FromHours(24))
                {
                    continue;
                }

                Directory.Delete(fullDirectory, recursive: true);
                removed++;
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return removed;
    }

    public bool DeleteStagedCopy(StagedDump stagedDump)
    {
        ArgumentNullException.ThrowIfNull(stagedDump);
        try
        {
            string directory = PathSafety.EnsureContained(_stagingRoot, stagedDump.StagingDirectory);
            string path = PathSafety.EnsureContained(directory, stagedDump.Path);
            if (!Path.GetFileName(directory).StartsWith("stage-", StringComparison.Ordinal) ||
                !File.Exists(Path.Combine(directory, MarkerName)) ||
                !string.Equals(Path.GetDirectoryName(path), directory, StringComparison.OrdinalIgnoreCase) ||
                ContainsReparseEntry(directory))
            {
                return false;
            }

            Directory.Delete(directory, recursive: true);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task<ProtectedEvidenceResponse> RetryNamedSourceAsync(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken)
    {
        bool validBinding = TryValidateRetryBinding(request, out string bindingError);
        if (request.Source is not { } source ||
            !Enum.IsDefined(source) ||
            request.DumpPath is not null ||
            request.ExpectedSizeBytes is not null ||
            request.ExpectedLastWriteUtc is not null ||
            request.PrivacyConfirmed ||
            request.SizeConfirmed ||
            request.FreeSpaceConfirmed ||
            request.CrashCapturePlan is not null ||
            request.WerLocalDumpPlan is not null ||
            request.ConfigurationReceiptId is not null ||
            !validBinding)
        {
            return new ProtectedEvidenceResponse(
                false,
                string.IsNullOrWhiteSpace(bindingError)
                    ? "A retry request must name exactly one supported evidence source."
                    : bindingError);
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_isProtectedTargetRunning())
            {
                throw new ProtectedTargetRunningException();
            }

            ProtectedEvidenceBatch batch = source is ProtectedEvidenceSource.SystemEventLog or
                ProtectedEvidenceSource.ApplicationEventLog
                ? await CollectEventBatchAsync(request, source, cancellationToken).ConfigureAwait(false)
                : await CollectDumpBatchAsync(request, source, cancellationToken).ConfigureAwait(false);
            CollectionStatus finalStatus = batch.Statuses.LastOrDefault()
                ?? new CollectionStatus(SourceName(source), CollectionState.Error, "The helper returned no source status.");
            bool succeeded = finalStatus.State == CollectionState.Available;
            int count = batch.Events.Count + batch.Dumps.Count;
            string message = succeeded
                ? $"Administrator retry completed and returned {count} privacy-filtered evidence item{(count == 1 ? string.Empty : "s")}."
                : finalStatus.Detail;
            return new ProtectedEvidenceResponse(
                succeeded,
                BoundText(message, 512),
                EvidenceBatch: succeeded ? batch : null);
        }
        catch (UnauthorizedAccessException)
        {
            return new ProtectedEvidenceResponse(false,
                "Windows denied the helper access to the named source.");
        }
        catch (Exception exception) when (exception is IOException or EventLogException or System.Security.SecurityException)
        {
            return new ProtectedEvidenceResponse(false, "The helper could not read the named source.");
        }
        catch (ProtectedTargetRunningException)
        {
            return new ProtectedEvidenceResponse(
                false,
                "Protected evidence collection stopped because Battlefield 6 or the protected target started running.");
        }
        catch (InvalidOperationException)
        {
            return new ProtectedEvidenceResponse(
                false,
                "Protected evidence collection stopped because a protected target started running.");
        }
    }

    private async Task<ProtectedEvidenceBatch> CollectEventBatchAsync(
        ProtectedEvidenceRequest request,
        ProtectedEvidenceSource source,
        CancellationToken cancellationToken)
    {
        var collector = new WindowsEventCollector(maxEventsPerLog: MaximumRetryEvents);
        WindowsEventCollection collected = await collector.CollectProtectedSourceWindowAsync(
            source,
            request.WindowStartUtc!.Value,
            request.WindowEndUtc!.Value,
            request.TargetProfile,
            cancellationToken).ConfigureAwait(false);
        if (_isProtectedTargetRunning())
        {
            throw new ProtectedTargetRunningException();
        }

        DiagnosticEvent[] events = collected.Events
            .Where(item => WindowsEventCollector.IsAllowedProtectedEvidenceEvent(source, item, request.TargetProfile))
            .Take(MaximumRetryEvents)
            .Select(BoundEvent)
            .ToArray();
        CollectionStatus[] statuses = collected.Statuses
            .Take(MaximumRetryStatuses)
            .Select(BoundStatus)
            .ToArray();
        bool truncated = collected.Statuses.Any(status =>
            status.Detail.Contains("additional", StringComparison.OrdinalIgnoreCase));
        return CreateBatch(request, source, events, [], statuses, truncated);
    }

    private async Task<ProtectedEvidenceBatch> CollectDumpBatchAsync(
        ProtectedEvidenceRequest request,
        ProtectedEvidenceSource source,
        CancellationToken cancellationToken)
    {
        DumpSearchRoot root = source switch
        {
            ProtectedEvidenceSource.WindowsMemoryDump => new DumpSearchRoot(
                SourceName(source),
                _roots.MemoryDumpPath,
                DumpKind.WindowsMemoryDump,
                MaximumDepth: 0,
                IsSingleFile: true),
            ProtectedEvidenceSource.WindowsMinidumps => new DumpSearchRoot(
                SourceName(source),
                _roots.MinidumpRoot,
                DumpKind.WindowsMinidump,
                MaximumDepth: 0),
            ProtectedEvidenceSource.LiveKernelReports => new DumpSearchRoot(
                SourceName(source),
                _roots.LiveKernelRoot,
                DumpKind.LiveKernelDump,
                MaximumDepth: 2),
            _ => throw new ArgumentOutOfRangeException(nameof(source), "The selected dump source is not allowlisted.")
        };
        var collector = new DumpInventoryCollector(
            new SafeDumpInspector(),
            [root],
            MaximumRetryDumps,
            _isProtectedTargetRunning);
        DumpInventory inventory = await collector.CollectAsync(
            request.WindowStartUtc!.Value,
            request.WindowEndUtc!.Value,
            request.TargetProfile,
            cancellationToken).ConfigureAwait(false);
        if (_isProtectedTargetRunning())
        {
            throw new ProtectedTargetRunningException();
        }

        ProtectedDumpEvidence[] dumps = inventory.Candidates
            .Where(candidate => candidate.OriginalPath is not null &&
                                candidate.OriginalPath.Length <= 1_024 &&
                                TryClassifyApprovedDumpPath(candidate.OriginalPath, _roots, out _, out _))
            .Take(MaximumRetryDumps)
            .Select(BoundDump)
            .ToArray();
        CollectionStatus[] statuses = inventory.Statuses
            .Take(MaximumRetryStatuses)
            .Select(BoundStatus)
            .ToArray();
        bool truncated = inventory.Statuses.Any(status =>
            status.Detail.Contains("additional", StringComparison.OrdinalIgnoreCase));
        return CreateBatch(request, source, [], dumps, statuses, truncated);
    }

    private static ProtectedEvidenceBatch CreateBatch(
        ProtectedEvidenceRequest request,
        ProtectedEvidenceSource source,
        IReadOnlyList<DiagnosticEvent> events,
        IReadOnlyList<ProtectedDumpEvidence> dumps,
        IReadOnlyList<CollectionStatus> statuses,
        bool truncated) => new(
            1,
            request.ReportSessionId!,
            request.ReportSha256!.ToLowerInvariant(),
            source,
            request.WindowStartUtc!.Value.ToUniversalTime(),
            request.WindowEndUtc!.Value.ToUniversalTime(),
            events,
            dumps,
            statuses,
            truncated);

    private DiagnosticEvent BoundEvent(DiagnosticEvent item)
    {
        DiagnosticEvent safe = _redactor.RedactEvent(item);
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, string> pair in safe.Data
                     .Where(pair => !pair.Key.Equals("ProcessId", StringComparison.OrdinalIgnoreCase) &&
                                    !pair.Key.Equals("DeviceName", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            string key = BoundText(pair.Key, 64);
            if (string.IsNullOrWhiteSpace(key) || data.ContainsKey(key))
            {
                continue;
            }

            data.Add(key, BoundText(pair.Value, 256));
            if (data.Count == 8)
            {
                break;
            }
        }
        return safe with
        {
            LogName = BoundText(safe.LogName, 32),
            ProviderName = BoundText(safe.ProviderName, 128),
            LevelName = BoundText(safe.LevelName, 32),
            Message = BoundText(safe.Message, 512),
            Data = data
        };
    }

    private CollectionStatus BoundStatus(CollectionStatus status)
    {
        CollectionStatus safe = _redactor.RedactStatus(status);
        return safe with
        {
            Source = BoundText(safe.Source, 128),
            Detail = BoundText(safe.Detail, 512)
        };
    }

    private ProtectedDumpEvidence BoundDump(DumpCandidate candidate) => new(
        candidate.Kind,
        BoundText(_redactor.Redact(candidate.Source), 128),
        BoundText(_redactor.Redact(candidate.Name), 128),
        BoundText(_redactor.RedactPath(candidate.RedactedPath), 512),
        candidate.SizeBytes,
        candidate.LastWriteUtc.ToUniversalTime(),
        candidate.Format,
        candidate.InspectionState,
        Math.Clamp(candidate.HeaderBytesRead, 0, SafeDumpInspector.MaximumHeaderBytesRead),
        candidate.SizePlausible,
        BoundText(_redactor.Redact(candidate.Detail), 512),
        candidate.OriginalPath!);

    private static bool TryValidateRetryBinding(
        ProtectedEvidenceRequest request,
        out string error)
    {
        error = string.Empty;
        if (!SessionIdValidator.IsValid(request.ReportSessionId) ||
            request.ReportSha256 is not { Length: 64 } hash ||
            hash.Any(character => !Uri.IsHexDigit(character)) ||
            request.WindowStartUtc is not { } startUtc ||
            request.WindowEndUtc is not { } endUtc ||
            endUtc < startUtc ||
            endUtc - startUtc > TimeSpan.FromDays(14) ||
            endUtc > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            error = "The protected-source retry was not bound to a valid report and evidence window.";
            return false;
        }

        if (!IsBoundedTargetProfile(request.TargetProfile))
        {
            error = "The protected-source retry contained an invalid target profile.";
            return false;
        }

        return true;
    }

    private static bool IsBoundedTargetProfile(TargetProfile? target)
    {
        if (target is null)
        {
            return true;
        }

        TargetPrivacyRules privacy = target.EffectivePrivacyRules;
        return IsBoundedText(target.Id) &&
               IsBoundedText(target.DisplayName) &&
               IsBoundedText(target.OutputLabel) &&
               IsBoundedList(target.ProcessNames, 16, executableNames: true) &&
               IsBoundedList(target.RelatedProcessNames, 32, executableNames: true) &&
               IsBoundedList(target.ApplicationEventSignals, 32, executableNames: false) &&
               IsBoundedList(target.ArtifactSignals, 32, executableNames: false) &&
               IsBoundedList(target.ReliabilitySignals, 32, executableNames: false) &&
               !privacy.ReadProcessMemory && !privacy.ReadModules && !privacy.ReadCommandLines &&
               !privacy.ReadInputs && !privacy.ReadAntiCheatData && !privacy.ExportProcessIds;
    }

    private static bool IsBoundedText(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 128;

    private static bool IsBoundedList(
        IReadOnlyList<string>? values,
        int maximumCount,
        bool executableNames) => values is not null &&
        values.Count <= maximumCount &&
        values.All(value => !string.IsNullOrWhiteSpace(value) &&
                            value.Length <= 128 &&
                            (!executableNames ||
                             (string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal) &&
                              value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0)));

    private static string SourceName(ProtectedEvidenceSource source) => source switch
    {
        ProtectedEvidenceSource.SystemEventLog => "Windows Event Log/System",
        ProtectedEvidenceSource.ApplicationEventLog => "Windows Event Log/Application",
        ProtectedEvidenceSource.WindowsMemoryDump => "Dump inventory/Windows memory dump",
        ProtectedEvidenceSource.WindowsMinidumps => "Dump inventory/Windows minidumps",
        ProtectedEvidenceSource.LiveKernelReports => "Dump inventory/LiveKernelReports",
        _ => "Protected evidence source"
    };

    private static string BoundText(string? value, int maximumLength)
    {
        string collapsed = string.Join(' ', (value ?? string.Empty)
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return collapsed.Length <= maximumLength ? collapsed : collapsed[..maximumLength];
    }

    private ProtectedEvidenceResponse ApplyCrashCapturePlan(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken)
    {
        string validationError = string.Empty;
        if (!IsConfigurationRequestShape(request, requireCrashPlan: true, requireWerPlan: false, requireReceipt: false) ||
            request.CrashCapturePlan is not { } plan ||
            !TryValidateCrashCapturePlan(plan, out validationError))
        {
            return new ProtectedEvidenceResponse(
                false,
                string.IsNullOrWhiteSpace(validationError)
                    ? "The crash-capture plan request was malformed."
                    : validationError);
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureProtectedTargetNotRunning(plan.TargetProfile);
            if (!PlanMatchesCurrentConfiguration(plan, out string compareError))
            {
                return new ProtectedEvidenceResponse(false, compareError);
            }

            var applied = new List<CrashCaptureChange>();
            WerConfigurationSnapshot? appliedWerBefore = null;
            bool appliedWer = false;
            string? createdWerFolder = null;
            try
            {
                foreach (CrashCaptureChange change in plan.Changes)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    EnsureProtectedTargetNotRunning(plan.TargetProfile);
                    if (!PreviousMatchesCurrent(change))
                    {
                        throw new IOException("A crash-capture setting changed after preview; the remaining settings were not written.");
                    }

                    StoredConfigurationValue desired = Desired(change);
                    applied.Add(change);
                    try
                    {
                        _configurationStore.WriteCrashSetting(change.Setting, desired);
                    }
                    catch
                    {
                        TryCaptureAppliedPageFileSnapshot(applied, change);
                        throw;
                    }

                    CaptureAppliedPageFileSnapshot(applied, change);
                    if (_configurationStore.ReadCrashSetting(change.Setting) != desired)
                    {
                        throw new IOException("Windows did not retain a crash-capture setting.");
                    }
                }

                WerLocalDumpReceipt? werReceipt = null;
                if (plan.WerLocalDumpPlan is { } werPlan)
                {
                    appliedWerBefore = Previous(werPlan);
                    createdWerFolder = EnsureWerDumpFolder(werPlan);
                    WerConfigurationSnapshot desired = Desired(werPlan);
                    EnsureProtectedTargetNotRunning(plan.TargetProfile);
                    EnsureWerTargetEligibleAtCommit(werPlan);
                    EnsureWerVolumeHasFreeSpace();
                    if (!WerConfigurationComparison.Matches(
                            _configurationStore.ReadWerSettings(werPlan.ExecutableName),
                            appliedWerBefore))
                    {
                        throw new IOException("The per-application dump settings changed after preview; they were not overwritten.");
                    }

                    appliedWer = true;
                    _configurationStore.WriteWerSettings(werPlan.ExecutableName, desired);
                    if (!WerConfigurationComparison.Matches(
                            _configurationStore.ReadWerSettings(werPlan.ExecutableName),
                            desired))
                    {
                        throw new IOException("Windows did not retain the per-application dump settings.");
                    }

                    werReceipt = CreateWerReceipt(werPlan);
                }

                DateTimeOffset nowUtc = _timeProvider.GetUtcNow().ToUniversalTime();
                DateTimeOffset? bootUtc = TryReadBootUtc();
                string receiptId = NewId();
                var receipt = new CrashCaptureReceipt(
                    1,
                    receiptId,
                    plan.PlanId,
                    plan.ReportSessionId,
                    plan.ReportSha256.ToLowerInvariant(),
                    nowUtc,
                    bootUtc,
                    applied.ToArray(),
                    plan.RequiresRestart
                        ? CrashCaptureActivationState.PendingRestart
                        : CrashCaptureActivationState.Active,
                    werReceipt,
                    Restored: false,
                    TargetProfile: plan.TargetProfile);
                _receiptStore.Save(receipt);
                return new ProtectedEvidenceResponse(
                    true,
                    plan.RequiresRestart
                        ? "Crash capture was prepared. Restart Windows before relying on the new system-dump settings."
                        : "Crash capture was already active and the requested settings were verified.",
                    CrashCaptureReceipt: receipt,
                    WerLocalDumpReceipt: werReceipt);
            }
            catch (OperationCanceledException)
            {
                _ = RollBackApply(plan, applied, appliedWerBefore, appliedWer, createdWerFolder);
                throw;
            }
            catch (ProtectedTargetRunningException)
            {
                _ = RollBackApply(plan, applied, appliedWerBefore, appliedWer, createdWerFolder);
                throw;
            }
            catch (Exception exception) when (IsConfigurationFailure(exception))
            {
                bool rollbackSucceeded = RollBackApply(plan, applied, appliedWerBefore, appliedWer, createdWerFolder);
                return new ProtectedEvidenceResponse(
                    false,
                    rollbackSucceeded
                        ? "Crash-capture preparation failed and every applied setting was restored."
                        : "Crash-capture preparation failed and Windows did not confirm a complete rollback.",
                    RollbackAttempted: applied.Count != 0 || appliedWer,
                    RollbackSucceeded: rollbackSucceeded);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ProtectedTargetRunningException)
        {
            return new ProtectedEvidenceResponse(
                false,
                "Crash-capture preparation is unavailable while Battlefield 6 or the protected target is running.");
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
            return new ProtectedEvidenceResponse(false, "The fixed crash-capture plan could not be validated safely.");
        }
    }

    private ProtectedEvidenceResponse RestoreCrashCapturePlan(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken)
    {
        if (!IsConfigurationRequestShape(request, requireCrashPlan: false, requireWerPlan: false, requireReceipt: true))
        {
            return new ProtectedEvidenceResponse(false, "The crash-capture restore request was malformed.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            CrashCaptureReceipt receipt = _receiptStore.ReadCrash(request.ConfigurationReceiptId!);
            if (!TryValidateCrashReceipt(receipt, out string validationError))
            {
                return new ProtectedEvidenceResponse(false, validationError);
            }

            EnsureProtectedTargetNotRunning(receipt.TargetProfile);
            if (!ReceiptMatchesAppliedConfiguration(receipt, out string compareError))
            {
                return new ProtectedEvidenceResponse(false, compareError);
            }

            var restored = new List<CrashCaptureChange>();
            bool werRestored = false;
            try
            {
                if (receipt.WerLocalDumpReceipt is { } werReceipt)
                {
                    EnsureProtectedTargetNotRunning(receipt.TargetProfile);
                    if (!WerConfigurationComparison.Matches(
                            _configurationStore.ReadWerSettings(werReceipt.ExecutableName),
                            Applied(werReceipt)))
                    {
                        throw new IOException("The prepared per-application dump settings changed before restore; they were not overwritten.");
                    }

                    werRestored = true;
                    _configurationStore.WriteWerSettings(werReceipt.ExecutableName, Previous(werReceipt));
                    if (!WerConfigurationComparison.Matches(
                            _configurationStore.ReadWerSettings(werReceipt.ExecutableName),
                            Previous(werReceipt)))
                    {
                        throw new IOException("Windows did not restore the prior per-application dump settings.");
                    }
                }

                foreach (CrashCaptureChange change in receipt.AppliedChanges.Reverse())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    EnsureProtectedTargetNotRunning(receipt.TargetProfile);
                    if (!AppliedMatchesCurrent(change))
                    {
                        throw new IOException("A prepared crash-capture setting changed before restore; it was not overwritten.");
                    }

                    restored.Add(change);
                    RestorePrevious(change);
                    if (!PreviousMatchesCurrent(change))
                    {
                        throw new IOException("Windows did not restore a prior crash-capture setting.");
                    }
                }

                DateTimeOffset nowUtc = _timeProvider.GetUtcNow().ToUniversalTime();
                CrashCaptureActivationState activation = receipt.AppliedChanges.Any(change => change.RequiresRestart)
                    ? CrashCaptureActivationState.PendingRestart
                    : CrashCaptureActivationState.Restored;
                CrashCaptureReceipt updated = receipt with
                {
                    ActivationState = activation,
                    Restored = true,
                    RestoredUtc = nowUtc,
                    WerLocalDumpReceipt = receipt.WerLocalDumpReceipt is null
                        ? null
                        : receipt.WerLocalDumpReceipt with { Restored = true, RestoredUtc = nowUtc }
                };
                _receiptStore.Replace(updated);
                return new ProtectedEvidenceResponse(
                    true,
                    activation == CrashCaptureActivationState.PendingRestart
                        ? "The prior settings were restored. Restart Windows to activate them."
                        : "The prior settings were restored.",
                    CrashCaptureReceipt: updated,
                    WerLocalDumpReceipt: updated.WerLocalDumpReceipt);
            }
            catch (OperationCanceledException)
            {
                _ = RollForwardRestore(receipt, restored, werRestored);
                throw;
            }
            catch (ProtectedTargetRunningException)
            {
                _ = RollForwardRestore(receipt, restored, werRestored);
                throw;
            }
            catch (Exception exception) when (IsConfigurationFailure(exception))
            {
                bool rollbackSucceeded = RollForwardRestore(receipt, restored, werRestored);
                return new ProtectedEvidenceResponse(
                    false,
                    rollbackSucceeded
                        ? "The restore failed and the prepared settings were put back."
                        : "The restore failed and Windows did not confirm a complete rollback.",
                    RollbackAttempted: restored.Count != 0 || werRestored,
                    RollbackSucceeded: rollbackSucceeded);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ProtectedTargetRunningException)
        {
            return new ProtectedEvidenceResponse(false, "Settings cannot be restored while Battlefield 6 is running.");
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
            return new ProtectedEvidenceResponse(false, "The local crash-capture receipt could not be read safely.");
        }
    }

    private ProtectedEvidenceResponse ApplyWerLocalDumpPlan(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken)
    {
        string validationError = string.Empty;
        if (!IsConfigurationRequestShape(request, requireCrashPlan: false, requireWerPlan: true, requireReceipt: false) ||
            request.WerLocalDumpPlan is not { } plan ||
            !TryValidateWerPlan(plan, out validationError))
        {
            return new ProtectedEvidenceResponse(
                false,
                string.IsNullOrWhiteSpace(validationError)
                    ? "The per-application dump plan was malformed."
                    : validationError);
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureProtectedTargetNotRunning(plan.TargetProfile);
            if (!WerConfigurationComparison.Matches(
                    _configurationStore.ReadWerSettings(plan.ExecutableName),
                    Previous(plan)))
            {
                return new ProtectedEvidenceResponse(
                    false,
                    "The per-application dump settings changed after preview; no settings were written.");
            }

            string? createdFolder = null;
            bool wrote = false;
            try
            {
                createdFolder = EnsureWerDumpFolder(plan);
                EnsureProtectedTargetNotRunning(plan.TargetProfile);
                EnsureWerTargetEligibleAtCommit(plan);
                EnsureWerVolumeHasFreeSpace();
                if (!WerConfigurationComparison.Matches(
                        _configurationStore.ReadWerSettings(plan.ExecutableName),
                        Previous(plan)))
                {
                    throw new IOException("The per-application dump settings changed after preview; they were not overwritten.");
                }

                wrote = true;
                _configurationStore.WriteWerSettings(plan.ExecutableName, Desired(plan));
                if (!WerConfigurationComparison.Matches(
                        _configurationStore.ReadWerSettings(plan.ExecutableName),
                        Desired(plan)))
                {
                    throw new IOException("Windows did not retain the per-application dump settings.");
                }

                WerLocalDumpReceipt receipt = CreateWerReceipt(plan);
                _receiptStore.Save(receipt);
                return new ProtectedEvidenceResponse(
                    true,
                    "Full local crash dumps were enabled for the selected application. The volume was accessible with free space, but a future full dump's size cannot be known in advance.",
                    WerLocalDumpReceipt: receipt);
            }
            catch (OperationCanceledException)
            {
                if (wrote)
                {
                    _ = TryRollbackWer(plan.ExecutableName, Desired(plan), Previous(plan));
                }

                TryRemoveEmptyCreatedWerFolder(createdFolder);
                throw;
            }
            catch (ProtectedTargetRunningException)
            {
                if (wrote)
                {
                    _ = TryRollbackWer(plan.ExecutableName, Desired(plan), Previous(plan));
                }

                TryRemoveEmptyCreatedWerFolder(createdFolder);
                throw;
            }
            catch (Exception exception) when (IsConfigurationFailure(exception))
            {
                bool rollbackSucceeded = !wrote || TryRollbackWer(plan.ExecutableName, Desired(plan), Previous(plan));
                TryRemoveEmptyCreatedWerFolder(createdFolder);
                return new ProtectedEvidenceResponse(
                    false,
                    rollbackSucceeded
                        ? "Per-application dump setup failed and the prior settings were restored."
                        : "Per-application dump setup failed and Windows did not confirm a complete rollback.",
                    RollbackAttempted: wrote,
                    RollbackSucceeded: rollbackSucceeded);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ProtectedTargetRunningException)
        {
            return new ProtectedEvidenceResponse(false, "Per-application dump setup is unavailable while the protected target is running.");
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
            return new ProtectedEvidenceResponse(false, "The per-application dump plan could not be applied safely.");
        }
    }

    private ProtectedEvidenceResponse RestoreWerLocalDumpPlan(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken)
    {
        if (!IsConfigurationRequestShape(request, requireCrashPlan: false, requireWerPlan: false, requireReceipt: true))
        {
            return new ProtectedEvidenceResponse(false, "The per-application dump restore request was malformed.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            WerLocalDumpReceipt receipt = _receiptStore.ReadWer(request.ConfigurationReceiptId!);
            if (!TryValidateWerReceipt(receipt, out string validationError))
            {
                return new ProtectedEvidenceResponse(false, validationError);
            }

            EnsureProtectedTargetNotRunning(receipt.TargetProfile);
            if (!WerConfigurationComparison.Matches(
                    _configurationStore.ReadWerSettings(receipt.ExecutableName),
                    Applied(receipt)))
            {
                return new ProtectedEvidenceResponse(
                    false,
                    "The per-application dump settings changed after setup; no settings were restored.");
            }

            EnsureProtectedTargetNotRunning(receipt.TargetProfile);
            bool restoreAttempted = false;
            try
            {
                if (!WerConfigurationComparison.Matches(
                        _configurationStore.ReadWerSettings(receipt.ExecutableName),
                        Applied(receipt)))
                {
                    return new ProtectedEvidenceResponse(
                        false,
                        "The per-application dump settings changed before restore; they were not overwritten.");
                }

                restoreAttempted = true;
                _configurationStore.WriteWerSettings(receipt.ExecutableName, Previous(receipt));
                if (!WerConfigurationComparison.Matches(
                        _configurationStore.ReadWerSettings(receipt.ExecutableName),
                        Previous(receipt)))
                {
                    throw new IOException("Windows did not restore the prior per-application dump settings.");
                }

                WerLocalDumpReceipt updated = receipt with
                {
                    Restored = true,
                    RestoredUtc = _timeProvider.GetUtcNow().ToUniversalTime()
                };
                _receiptStore.Replace(updated);
                return new ProtectedEvidenceResponse(
                    true,
                    "The prior per-application dump settings were restored.",
                    WerLocalDumpReceipt: updated);
            }
            catch (OperationCanceledException)
            {
                if (restoreAttempted)
                {
                    _ = TryRollForwardWer(receipt.ExecutableName, Previous(receipt), Applied(receipt));
                }

                throw;
            }
            catch (Exception exception) when (IsConfigurationFailure(exception))
            {
                bool rollbackSucceeded = !restoreAttempted ||
                                         TryRollForwardWer(
                                             receipt.ExecutableName,
                                             Previous(receipt),
                                             Applied(receipt));
                return new ProtectedEvidenceResponse(
                    false,
                    rollbackSucceeded
                        ? "The restore failed and the prepared settings were put back."
                        : "The restore failed and Windows did not confirm a safe roll-forward.",
                    RollbackAttempted: restoreAttempted,
                    RollbackSucceeded: rollbackSucceeded);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ProtectedTargetRunningException)
        {
            return new ProtectedEvidenceResponse(false, "Settings cannot be restored while Battlefield 6 is running.");
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
            return new ProtectedEvidenceResponse(false, "The local per-application dump receipt could not be read safely.");
        }
    }

    private bool PlanMatchesCurrentConfiguration(CrashCapturePlan plan, out string error)
    {
        foreach (CrashCaptureChange change in plan.Changes)
        {
            if (!PreviousMatchesCurrent(change))
            {
                error = "A crash-capture setting changed after preview; no settings were written.";
                return false;
            }
        }

        if (plan.WerLocalDumpPlan is { } werPlan &&
            !WerConfigurationComparison.Matches(
                _configurationStore.ReadWerSettings(werPlan.ExecutableName),
                Previous(werPlan)))
        {
            error = "The per-application dump settings changed after preview; no settings were written.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private bool ReceiptMatchesAppliedConfiguration(CrashCaptureReceipt receipt, out string error)
    {
        foreach (CrashCaptureChange change in receipt.AppliedChanges)
        {
            if (!AppliedMatchesCurrent(change))
            {
                error = "A prepared crash-capture setting was changed later; no settings were restored.";
                return false;
            }
        }

        if (receipt.WerLocalDumpReceipt is { } werReceipt &&
            !WerConfigurationComparison.Matches(
                _configurationStore.ReadWerSettings(werReceipt.ExecutableName),
                Applied(werReceipt)))
        {
            error = "The prepared per-application dump settings were changed later; no settings were restored.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private bool PreviousMatchesCurrent(CrashCaptureChange change)
    {
        if (_configurationStore.ReadCrashSetting(change.Setting) != Previous(change))
        {
            return false;
        }

        return change.Setting != CrashCaptureSetting.AutomaticManagedPagefile ||
               change.PreviousPageFileConfiguration is { } previous &&
               PageFileSnapshotsEqual(previous, _configurationStore.ReadPageFileConfiguration());
    }

    private bool AppliedMatchesCurrent(CrashCaptureChange change)
    {
        if (_configurationStore.ReadCrashSetting(change.Setting) != Desired(change))
        {
            return false;
        }

        return change.Setting != CrashCaptureSetting.AutomaticManagedPagefile ||
               change.AppliedPageFileConfiguration is { } applied &&
               PageFileSnapshotsEqual(applied, _configurationStore.ReadPageFileConfiguration());
    }

    private void RestorePrevious(CrashCaptureChange change)
    {
        if (change.Setting == CrashCaptureSetting.AutomaticManagedPagefile)
        {
            _configurationStore.RestorePageFileConfiguration(
                change.PreviousPageFileConfiguration ??
                throw new InvalidDataException("The page-file rollback snapshot was missing."));
            return;
        }

        _configurationStore.WriteCrashSetting(change.Setting, Previous(change));
    }

    private void RestoreApplied(CrashCaptureChange change)
    {
        if (change.Setting == CrashCaptureSetting.AutomaticManagedPagefile)
        {
            _configurationStore.RestorePageFileConfiguration(
                change.AppliedPageFileConfiguration ??
                throw new InvalidDataException("The applied page-file configuration snapshot was missing."));
            return;
        }

        _configurationStore.WriteCrashSetting(change.Setting, Desired(change));
    }

    private static bool PageFileSnapshotsEqual(
        PageFileConfigurationSnapshot left,
        PageFileConfigurationSnapshot right) =>
        left.AutomaticManagementStateKnown == right.AutomaticManagementStateKnown &&
        left.AutomaticManagementEnabled == right.AutomaticManagementEnabled &&
        left.PagingFilesValueExists == right.PagingFilesValueExists &&
        left.PagingFiles.SequenceEqual(right.PagingFiles, StringComparer.Ordinal);

    private bool RollBackApply(
        CrashCapturePlan plan,
        IReadOnlyList<CrashCaptureChange> applied,
        WerConfigurationSnapshot? appliedWerBefore,
        bool appliedWer,
        string? createdWerFolder)
    {
        bool succeeded = true;
        if (appliedWer && appliedWerBefore is not null && plan.WerLocalDumpPlan is { } werPlan)
        {
            succeeded &= TryRollbackWer(werPlan.ExecutableName, Desired(werPlan), appliedWerBefore);
        }

        foreach (CrashCaptureChange change in applied.Reverse())
        {
            try
            {
                if (PreviousMatchesCurrent(change))
                {
                    continue;
                }

                if (!AppliedMatchesCurrent(change))
                {
                    succeeded = false;
                    continue;
                }

                RestorePrevious(change);
                succeeded &= PreviousMatchesCurrent(change);
            }
            catch (Exception exception) when (IsConfigurationFailure(exception))
            {
                succeeded = false;
            }
        }

        TryRemoveEmptyCreatedWerFolder(createdWerFolder);
        return succeeded;
    }

    private bool RollForwardRestore(
        CrashCaptureReceipt receipt,
        IReadOnlyList<CrashCaptureChange> restored,
        bool werRestored)
    {
        bool succeeded = true;
        foreach (CrashCaptureChange change in restored.Reverse())
        {
            try
            {
                if (AppliedMatchesCurrent(change))
                {
                    continue;
                }

                if (!PreviousMatchesCurrent(change))
                {
                    succeeded = false;
                    continue;
                }

                RestoreApplied(change);
                succeeded &= AppliedMatchesCurrent(change);
            }
            catch (Exception exception) when (IsConfigurationFailure(exception))
            {
                succeeded = false;
            }
        }

        if (werRestored && receipt.WerLocalDumpReceipt is { } werReceipt)
        {
            succeeded &= TryRollForwardWer(
                werReceipt.ExecutableName,
                Previous(werReceipt),
                Applied(werReceipt));
        }

        return succeeded;
    }

    private bool TryRollbackWer(
        string executableName,
        WerConfigurationSnapshot applied,
        WerConfigurationSnapshot previous)
    {
        try
        {
            WerConfigurationSnapshot current = _configurationStore.ReadWerSettings(executableName);
            if (WerConfigurationComparison.Matches(current, previous))
            {
                return true;
            }

            if (!WerConfigurationComparison.Matches(current, applied))
            {
                return false;
            }

            _configurationStore.WriteWerSettings(executableName, previous);
            return WerConfigurationComparison.Matches(
                _configurationStore.ReadWerSettings(executableName),
                previous);
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
            return false;
        }
    }

    private bool TryRollForwardWer(
        string executableName,
        WerConfigurationSnapshot restored,
        WerConfigurationSnapshot applied)
    {
        try
        {
            WerConfigurationSnapshot current = _configurationStore.ReadWerSettings(executableName);
            if (WerConfigurationComparison.Matches(current, applied))
            {
                return true;
            }

            if (!WerConfigurationComparison.Matches(current, restored))
            {
                return false;
            }

            _configurationStore.WriteWerSettings(executableName, applied);
            return WerConfigurationComparison.Matches(
                _configurationStore.ReadWerSettings(executableName),
                applied);
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
            return false;
        }
    }

    private void CaptureAppliedPageFileSnapshot(
        IList<CrashCaptureChange> applied,
        CrashCaptureChange change)
    {
        if (change.Setting == CrashCaptureSetting.AutomaticManagedPagefile)
        {
            applied[^1] = change with
            {
                AppliedPageFileConfiguration = _configurationStore.ReadPageFileConfiguration()
            };
        }
    }

    private void TryCaptureAppliedPageFileSnapshot(
        IList<CrashCaptureChange> applied,
        CrashCaptureChange change)
    {
        try
        {
            CaptureAppliedPageFileSnapshot(applied, change);
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
        }
    }

    private string EnsureWerDumpFolder(WerLocalDumpPlan plan)
    {
        string expected = ApprovedWerDumpFolder(_werDumpRoot, plan.ExecutableName);
        if (!string.Equals(Path.GetFullPath(plan.DesiredDumpFolder), expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The WER dump folder was not the helper-derived private folder.");
        }

        PathSafety.EnsureNoReparseComponents(_werDumpRoot);
        EnsureWerVolumeHasFreeSpace();
        Directory.CreateDirectory(_werDumpRoot);
        PathSafety.EnsureNoReparseComponents(_werDumpRoot);
        if (_productionOriginBoundary)
        {
            ConfigurationReceiptAcl.ProtectDirectory(_werDumpRoot, _originatingUserSid);
        }
        else
        {
            PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(_werDumpRoot);
        }
        bool existed = Directory.Exists(expected);
        Directory.CreateDirectory(expected);
        PathSafety.EnsureContained(_werDumpRoot, expected);
        PathSafety.EnsureNoReparseComponents(_werDumpRoot, expected);
        if (_productionOriginBoundary)
        {
            WerDumpDirectoryAcl.ProtectLeaf(expected, _originatingUserSid);
        }
        else
        {
            PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(expected);
        }
        return existed ? string.Empty : expected;
    }

    private void EnsureWerVolumeHasFreeSpace()
    {
        long freeBytes = _availableFreeSpace(_werDumpRoot);
        if (freeBytes <= 0)
        {
            throw new IOException("The per-application dump volume was inaccessible or had no usable free space.");
        }
    }

    private void EnsureWerTargetEligibleAtCommit(WerLocalDumpPlan plan)
    {
        if (plan.TargetProfile is null ||
            IsPermanentlyExcludedWerTarget(plan.TargetProfile, plan.ExecutableName) ||
            IsCriticalWindowsExecutable(plan.ExecutableName))
        {
            throw new InvalidDataException("The executable is not eligible for per-application dump capture.");
        }

        IReadOnlyList<WerProcessIdentity> identities = _matchingProcessIdentities(plan.ExecutableName);
        bool IsEligible(WerProcessIdentity identity) => identity.ClassificationSucceeded &&
            identity.SessionId > 0 &&
            !identity.IsElevated &&
            string.Equals(identity.OwnerSid, _originatingUserSid.Value, StringComparison.OrdinalIgnoreCase);
        if (identities.Count == 0 || identities.Any(identity => !IsEligible(identity)))
        {
            throw new InvalidDataException(
                "The selected ordinary application must be running unelevated under the originating user outside Windows session 0 when dump capture is enabled.");
        }
    }

    private static bool IsCriticalWindowsExecutable(string executableName)
    {
        string name = Path.GetFileNameWithoutExtension(executableName);
        string[] blocked =
        [
            "System", "Registry", "Secure System", "smss", "csrss", "wininit", "winlogon",
            "services", "lsass", "lsaiso", "svchost", "fontdrvhost", "dwm", "audiodg",
            "Memory Compression", "PCCrashDiagnostic", "PCCrashDiagnostic.ElevatedHelper",
            "BF6CrashDiagnostic", "BF6CrashDiagnostic.ElevatedHelper"
        ];
        return blocked.Contains(name, StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<WerProcessIdentity> GetMatchingProcessIdentities(string executableName)
    {
        var identities = new List<WerProcessIdentity>();
        try
        {
            Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(executableName));
            try
            {
                foreach (Process process in processes)
                {
                    if (TryGetProcessIdentity(process, out WerProcessIdentity identity))
                    {
                        identities.Add(identity);
                    }
                    else
                    {
                        identities.Add(new WerProcessIdentity(-1, string.Empty, false, ClassificationSucceeded: false));
                    }
                }
            }
            finally
            {
                foreach (Process process in processes)
                {
                    process.Dispose();
                }
            }
        }
        catch
        {
            identities.Add(new WerProcessIdentity(-1, string.Empty, false, ClassificationSucceeded: false));
        }

        return identities;
    }

    private static bool TryGetProcessIdentity(Process process, out WerProcessIdentity identity)
    {
        identity = null!;
        using Microsoft.Win32.SafeHandles.SafeProcessHandle processHandle = OpenProcess(
            0x1000,
            inheritHandle: false,
            process.Id);
        if (processHandle.IsInvalid || !OpenProcessToken(
                processHandle,
                0x0008,
                out Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token))
        {
            return false;
        }

        using (token)
        using (var windowsIdentity = new System.Security.Principal.WindowsIdentity(token.DangerousGetHandle()))
        {
            string? ownerSid = windowsIdentity.User?.Value;
            int elevated = 0;
            if (string.IsNullOrWhiteSpace(ownerSid) ||
                !GetTokenInformation(token, 20, ref elevated, sizeof(int), out _))
            {
                return false;
            }

            identity = new WerProcessIdentity(process.SessionId, ownerSid, elevated != 0);
            return true;
        }
    }

    private void TryRemoveEmptyCreatedWerFolder(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            string fullPath = PathSafety.EnsureContained(_werDumpRoot, path);
            PathSafety.EnsureNoReparseComponents(_werDumpRoot, fullPath);
            if (!Directory.EnumerateFileSystemEntries(fullPath).Any())
            {
                Directory.Delete(fullPath, recursive: false);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
        }
    }

    private WerLocalDumpReceipt CreateWerReceipt(WerLocalDumpPlan plan) => new(
        1,
        NewId(),
        plan.PlanId,
        plan.ReportSessionId,
        plan.ReportSha256.ToLowerInvariant(),
        _timeProvider.GetUtcNow().ToUniversalTime(),
        plan.ExecutableName,
        plan.PreviousKeyExists,
        plan.PreviousDumpTypeExists,
        plan.PreviousDumpType,
        plan.PreviousDumpCountExists,
        plan.PreviousDumpCount,
        plan.PreviousDumpFolderExists,
        plan.PreviousDumpFolder,
        plan.DesiredDumpType,
        plan.DesiredDumpCount,
        plan.DesiredDumpFolder,
        Restored: false,
        TargetProfile: plan.TargetProfile,
        PreviousDumpTypeRegistryValueKind: plan.PreviousDumpTypeRegistryValueKind,
        PreviousDumpCountRegistryValueKind: plan.PreviousDumpCountRegistryValueKind,
        PreviousDumpFolderRegistryValueKind: plan.PreviousDumpFolderRegistryValueKind);

    private bool TryValidateCrashCapturePlan(CrashCapturePlan plan, out string error)
    {
        if (plan.SchemaVersion != 1 ||
            !IsId(plan.PlanId) ||
            !IsValidReportBinding(plan.ReportSessionId, plan.ReportSha256) ||
            plan.CreatedUtc > _timeProvider.GetUtcNow().AddMinutes(1) ||
            plan.ExpiresUtc < _timeProvider.GetUtcNow() ||
            plan.ExpiresUtc - plan.CreatedUtc > TimeSpan.FromMinutes(15) ||
            plan.Preset != CrashCapturePreset.AutomaticMemoryDump ||
            !plan.RequiresElevation ||
            plan.Changes is null ||
            plan.Changes.Count > Enum.GetValues<CrashCaptureSetting>().Length ||
            plan.Changes.Select(change => change.Setting).Distinct().Count() != plan.Changes.Count ||
            plan.RequiresRestart != plan.Changes.Any(change => change.RequiresRestart) ||
            !IsBoundedTargetProfile(plan.TargetProfile) ||
            plan.Changes.Any(change => !IsValidAutomaticChange(change, requireAppliedPageFileSnapshot: false)))
        {
            error = "The fixed Automatic memory dump plan was invalid or expired.";
            return false;
        }

        foreach ((CrashCaptureSetting setting, StoredConfigurationValue desired) in AutomaticPresetValues())
        {
            StoredConfigurationValue current = _configurationStore.ReadCrashSetting(setting);
            CrashCaptureChange? change = plan.Changes.FirstOrDefault(item => item.Setting == setting);
            if (current == desired)
            {
                if (change is not null)
                {
                    error = "The crash-capture plan contained an unnecessary setting change.";
                    return false;
                }
            }
            else if (change is null || Previous(change) != current || Desired(change) != desired)
            {
                error = "The crash-capture plan did not exactly match the current Automatic dump requirements.";
                return false;
            }
        }

        CrashCaptureEnvironmentSnapshot environment = _configurationStore.ReadEnvironment();
        if (CrashReadinessCollector.AutomaticManagementEnabledWithoutBootBacking(environment))
        {
            error = "Automatic page-file management was enabled without configured or active boot-volume dump backing.";
            return false;
        }

        bool needsSystemManagedPagefile =
            CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(environment);
        CrashCaptureChange? pagefileChange = plan.Changes.FirstOrDefault(
            item => item.Setting == CrashCaptureSetting.AutomaticManagedPagefile);
        if (needsSystemManagedPagefile != (pagefileChange is not null) ||
            pagefileChange is not null &&
            (Previous(pagefileChange) != _configurationStore.ReadCrashSetting(pagefileChange.Setting) ||
             Desired(pagefileChange) != new StoredConfigurationValue(true, "true")))
        {
            error = "Automatic page-file management was not limited to a system without dump backing.";
            return false;
        }

        if (plan.WerLocalDumpPlan is { } werPlan &&
            (!TryValidateWerPlan(werPlan, out error) ||
             !string.Equals(werPlan.ReportSessionId, plan.ReportSessionId, StringComparison.Ordinal) ||
             !string.Equals(werPlan.ReportSha256, plan.ReportSha256, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        error = string.Empty;
        return true;
    }

    private bool TryValidateWerPlan(WerLocalDumpPlan plan, out string error)
    {
        string expectedFolder;
        try
        {
            _ = WindowsCrashCaptureConfigurationStore.NormalizeExecutableName(plan.ExecutableName);
            expectedFolder = ApprovedWerDumpFolder(_werDumpRoot, plan.ExecutableName);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            error = "The per-application dump plan named an invalid executable or folder.";
            return false;
        }

        if (plan.SchemaVersion != 1 ||
            !IsId(plan.PlanId) ||
            !IsValidReportBinding(plan.ReportSessionId, plan.ReportSha256) ||
            plan.CreatedUtc > _timeProvider.GetUtcNow().AddMinutes(1) ||
            plan.ExpiresUtc < _timeProvider.GetUtcNow() ||
            plan.ExpiresUtc - plan.CreatedUtc > TimeSpan.FromMinutes(15) ||
            plan.DesiredDumpType != 2 ||
            plan.DesiredDumpCount != 2 ||
            !string.Equals(Path.GetFullPath(plan.DesiredDumpFolder), expectedFolder, StringComparison.OrdinalIgnoreCase) ||
            !IsOptionalDword(plan.PreviousDumpTypeExists, plan.PreviousDumpType) ||
            !IsOptionalDword(plan.PreviousDumpCountExists, plan.PreviousDumpCount) ||
            !IsOptionalRegistryKind(plan.PreviousDumpTypeExists, plan.PreviousDumpTypeRegistryValueKind) ||
            !IsOptionalRegistryKind(plan.PreviousDumpCountExists, plan.PreviousDumpCountRegistryValueKind) ||
            !IsOptionalRegistryKind(plan.PreviousDumpFolderExists, plan.PreviousDumpFolderRegistryValueKind) ||
            plan.PreviousDumpFolderExists != (plan.PreviousDumpFolder is not null) ||
            plan.PreviousDumpFolder is { Length: > 1_024 } ||
            !IsBoundedTargetProfile(plan.TargetProfile) ||
            plan.TargetProfile is null || plan.TargetProfile.BlockSensitiveOperationsWhileRunning ||
            !plan.TargetProfile.MatchesProcessName(plan.ExecutableName) ||
            IsPermanentlyExcludedWerTarget(plan.TargetProfile, plan.ExecutableName) ||
            IsCriticalWindowsExecutable(plan.ExecutableName))
        {
            error = "The fixed per-application dump plan was invalid or expired.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    internal bool TryValidateCrashReceipt(CrashCaptureReceipt receipt, out string error)
    {
        if (receipt.SchemaVersion != 1 || !IsId(receipt.ReceiptId) || !IsId(receipt.PlanId) ||
            !IsValidReportBinding(receipt.ReportSessionId, receipt.ReportSha256) ||
            receipt.Restored || receipt.AppliedChanges is null ||
            receipt.AppliedChanges.Count > Enum.GetValues<CrashCaptureSetting>().Length ||
            receipt.AppliedChanges.Select(change => change.Setting).Distinct().Count() != receipt.AppliedChanges.Count ||
            receipt.AppliedChanges.Any(change => !IsValidAutomaticChange(change, requireAppliedPageFileSnapshot: true)) ||
            !IsBoundedTargetProfile(receipt.TargetProfile) ||
            receipt.WerLocalDumpReceipt is { } wer &&
            (!TryValidateWerReceipt(wer, out _) ||
             !string.Equals(wer.ReportSessionId, receipt.ReportSessionId, StringComparison.Ordinal) ||
             !string.Equals(wer.ReportSha256, receipt.ReportSha256, StringComparison.OrdinalIgnoreCase)))
        {
            error = "The local crash-capture receipt was invalid or had already been restored.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    internal bool TryValidateWerReceipt(WerLocalDumpReceipt receipt, out string error)
    {
        string expectedFolder;
        string actualFolder;
        try
        {
            _ = WindowsCrashCaptureConfigurationStore.NormalizeExecutableName(receipt.ExecutableName);
            expectedFolder = ApprovedWerDumpFolder(_werDumpRoot, receipt.ExecutableName);
            actualFolder = Path.GetFullPath(receipt.AppliedDumpFolder);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            error = "The local per-application dump receipt was invalid.";
            return false;
        }

        if (receipt.SchemaVersion != 1 || !IsId(receipt.ReceiptId) || !IsId(receipt.PlanId) ||
            !IsValidReportBinding(receipt.ReportSessionId, receipt.ReportSha256) || receipt.Restored ||
            !IsOptionalDword(receipt.PreviousDumpTypeExists, receipt.PreviousDumpType) ||
            !IsOptionalDword(receipt.PreviousDumpCountExists, receipt.PreviousDumpCount) ||
            !IsOptionalRegistryKind(receipt.PreviousDumpTypeExists, receipt.PreviousDumpTypeRegistryValueKind) ||
            !IsOptionalRegistryKind(receipt.PreviousDumpCountExists, receipt.PreviousDumpCountRegistryValueKind) ||
            !IsOptionalRegistryKind(receipt.PreviousDumpFolderExists, receipt.PreviousDumpFolderRegistryValueKind) ||
            receipt.PreviousDumpFolderExists != (receipt.PreviousDumpFolder is not null) ||
            receipt.PreviousDumpFolder is { Length: > 1_024 } ||
            receipt.AppliedDumpType != 2 || receipt.AppliedDumpCount != 2 ||
            string.IsNullOrWhiteSpace(receipt.AppliedDumpFolder) || receipt.AppliedDumpFolder.Length > 1_024 ||
            !string.Equals(
                actualFolder,
                expectedFolder,
                StringComparison.OrdinalIgnoreCase) ||
            !IsBoundedTargetProfile(receipt.TargetProfile) || receipt.TargetProfile is null ||
            receipt.TargetProfile.BlockSensitiveOperationsWhileRunning ||
            !receipt.TargetProfile.MatchesProcessName(receipt.ExecutableName) ||
            IsPermanentlyExcludedWerTarget(receipt.TargetProfile, receipt.ExecutableName) ||
            IsCriticalWindowsExecutable(receipt.ExecutableName))
        {
            error = "The local per-application dump receipt was invalid or had already been restored.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool IsPermanentlyExcludedWerTarget(TargetProfile target, string executableName)
    {
        if (target.Id.Equals(TargetProfile.Battlefield6.Id, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        IEnumerable<string> names = target.ProcessNames
            .Concat(target.RelatedProcessNames)
            .Append(executableName);
        return names.Any(name => ProtectedProcessGuard.AlwaysProtectedProcessNames.Contains(
                   ProtectedProcessGuard.NormalizeProcessName(name),
                   StringComparer.OrdinalIgnoreCase)) ||
               target.ApplicationEventSignals.Any(signal =>
                   signal.Contains("anti-cheat", StringComparison.OrdinalIgnoreCase) ||
                   signal.Contains("anticheat", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsValidAutomaticChange(
        CrashCaptureChange change,
        bool requireAppliedPageFileSnapshot)
    {
        if (!Enum.IsDefined(change.Setting) ||
            change.PreviousValueExists != (change.PreviousValue is not null) ||
            change.DesiredValueExists != (change.DesiredValue is not null) ||
            change.PreviousValue is { Length: > 1_024 } ||
            change.DesiredValue is { Length: > 1_024 } ||
            Previous(change) == Desired(change) ||
            !change.RequiresRestart ||
            change.Setting != CrashCaptureSetting.AutomaticManagedPagefile &&
            (change.PreviousPageFileConfiguration is not null || change.AppliedPageFileConfiguration is not null) ||
            change.Setting == CrashCaptureSetting.AutomaticManagedPagefile &&
            (change.PreviousRegistryValueKind is not null || change.DesiredRegistryValueKind is not null) ||
            change.Setting == CrashCaptureSetting.AutomaticManagedPagefile &&
            requireAppliedPageFileSnapshot != (change.AppliedPageFileConfiguration is not null) ||
            change.Setting != CrashCaptureSetting.AutomaticManagedPagefile &&
            (change.PreviousValueExists != change.PreviousRegistryValueKind.HasValue ||
             change.DesiredValueExists != change.DesiredRegistryValueKind.HasValue ||
             !IsSupportedRegistryKind(change.PreviousRegistryValueKind) ||
             !IsSupportedRegistryKind(change.DesiredRegistryValueKind)))
        {
            return false;
        }

        StoredConfigurationValue desired = Desired(change);
        return AutomaticPresetValues().Any(item => item.Setting == change.Setting && item.Value == desired) ||
               change.Setting == CrashCaptureSetting.AutomaticManagedPagefile &&
               desired == new StoredConfigurationValue(true, "true") &&
               IsValidPageFileSnapshots(change, requireAppliedPageFileSnapshot);
    }

    private static bool IsValidPageFileSnapshots(
        CrashCaptureChange change,
        bool requireAppliedPageFileSnapshot)
    {
        if (change.PreviousPageFileConfiguration is not { } snapshot ||
            !change.PreviousValueExists ||
            !bool.TryParse(change.PreviousValue, out bool previousAutomatic) ||
            previousAutomatic != snapshot.AutomaticManagementEnabled)
        {
            return false;
        }

        try
        {
            WindowsCrashCaptureConfigurationStore.ValidatePageFileConfigurationSnapshot(snapshot);
            if (requireAppliedPageFileSnapshot)
            {
                PageFileConfigurationSnapshot applied = change.AppliedPageFileConfiguration!;
                WindowsCrashCaptureConfigurationStore.ValidatePageFileConfigurationSnapshot(applied);
                if (!applied.AutomaticManagementEnabled)
                {
                    return false;
                }
            }

            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static IEnumerable<(CrashCaptureSetting Setting, StoredConfigurationValue Value)> AutomaticPresetValues()
    {
        yield return (CrashCaptureSetting.CrashDumpEnabled, new StoredConfigurationValue(true, "7", (int)Microsoft.Win32.RegistryValueKind.DWord));
        yield return (CrashCaptureSetting.FilterPages, new StoredConfigurationValue(false, null));
        yield return (CrashCaptureSetting.DumpFile, new StoredConfigurationValue(true, @"%SystemRoot%\MEMORY.DMP", (int)Microsoft.Win32.RegistryValueKind.ExpandString));
        yield return (CrashCaptureSetting.EventLogging, new StoredConfigurationValue(true, "1", (int)Microsoft.Win32.RegistryValueKind.DWord));
        yield return (CrashCaptureSetting.OverwriteExistingDump, new StoredConfigurationValue(true, "1", (int)Microsoft.Win32.RegistryValueKind.DWord));
    }

    private static StoredConfigurationValue Previous(CrashCaptureChange change) =>
        new(change.PreviousValueExists, change.PreviousValue, change.PreviousRegistryValueKind);

    private static StoredConfigurationValue Desired(CrashCaptureChange change) =>
        new(change.DesiredValueExists, change.DesiredValue, change.DesiredRegistryValueKind);

    private static WerConfigurationSnapshot Previous(WerLocalDumpPlan plan) => new(
        plan.PreviousKeyExists,
        new StoredConfigurationValue(plan.PreviousDumpTypeExists, OptionalNumber(plan.PreviousDumpType), plan.PreviousDumpTypeRegistryValueKind),
        new StoredConfigurationValue(plan.PreviousDumpCountExists, OptionalNumber(plan.PreviousDumpCount), plan.PreviousDumpCountRegistryValueKind),
        new StoredConfigurationValue(plan.PreviousDumpFolderExists, plan.PreviousDumpFolder, plan.PreviousDumpFolderRegistryValueKind));

    private static WerConfigurationSnapshot Desired(WerLocalDumpPlan plan) => new(
        true,
        new StoredConfigurationValue(true, plan.DesiredDumpType.ToString(System.Globalization.CultureInfo.InvariantCulture), (int)Microsoft.Win32.RegistryValueKind.DWord),
        new StoredConfigurationValue(true, plan.DesiredDumpCount.ToString(System.Globalization.CultureInfo.InvariantCulture), (int)Microsoft.Win32.RegistryValueKind.DWord),
        new StoredConfigurationValue(true, plan.DesiredDumpFolder, (int)Microsoft.Win32.RegistryValueKind.ExpandString));

    private static WerConfigurationSnapshot Previous(WerLocalDumpReceipt receipt) => new(
        receipt.PreviousKeyExists,
        new StoredConfigurationValue(receipt.PreviousDumpTypeExists, OptionalNumber(receipt.PreviousDumpType), receipt.PreviousDumpTypeRegistryValueKind),
        new StoredConfigurationValue(receipt.PreviousDumpCountExists, OptionalNumber(receipt.PreviousDumpCount), receipt.PreviousDumpCountRegistryValueKind),
        new StoredConfigurationValue(receipt.PreviousDumpFolderExists, receipt.PreviousDumpFolder, receipt.PreviousDumpFolderRegistryValueKind));

    private static WerConfigurationSnapshot Applied(WerLocalDumpReceipt receipt) => new(
        true,
        new StoredConfigurationValue(true, receipt.AppliedDumpType.ToString(System.Globalization.CultureInfo.InvariantCulture), (int)Microsoft.Win32.RegistryValueKind.DWord),
        new StoredConfigurationValue(true, receipt.AppliedDumpCount.ToString(System.Globalization.CultureInfo.InvariantCulture), (int)Microsoft.Win32.RegistryValueKind.DWord),
        new StoredConfigurationValue(true, receipt.AppliedDumpFolder, (int)Microsoft.Win32.RegistryValueKind.ExpandString));

    private static string? OptionalNumber(int? value) =>
        value?.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static bool IsOptionalDword(bool exists, int? value) => exists == value.HasValue;

    private static bool IsOptionalRegistryKind(bool exists, int? value) =>
        exists == value.HasValue && IsSupportedRegistryKind(value);

    private static bool IsSupportedRegistryKind(int? value) => value is null ||
        value == (int)Microsoft.Win32.RegistryValueKind.DWord ||
        value == (int)Microsoft.Win32.RegistryValueKind.QWord ||
        value == (int)Microsoft.Win32.RegistryValueKind.String ||
        value == (int)Microsoft.Win32.RegistryValueKind.ExpandString;

    private static bool IsConfigurationRequestShape(
        ProtectedEvidenceRequest request,
        bool requireCrashPlan,
        bool requireWerPlan,
        bool requireReceipt) =>
        request.Source is null &&
        request.DumpPath is null &&
        request.ExpectedSizeBytes is null &&
        request.ExpectedLastWriteUtc is null &&
        !request.PrivacyConfirmed && !request.SizeConfirmed && !request.FreeSpaceConfirmed &&
        request.ReportSessionId is null && request.ReportSha256 is null &&
        request.WindowStartUtc is null && request.WindowEndUtc is null && request.TargetProfile is null &&
        (request.CrashCapturePlan is not null) == requireCrashPlan &&
        (request.WerLocalDumpPlan is not null) == requireWerPlan &&
        (request.ConfigurationReceiptId is not null) == requireReceipt;

    private static bool IsValidReportBinding(string sessionId, string hash) =>
        SessionIdValidator.IsValid(sessionId) &&
        hash is { Length: 64 } && hash.All(Uri.IsHexDigit);

    private static bool IsId(string value) => value is { Length: 32 } && value.All(Uri.IsHexDigit);

    private static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    private DateTimeOffset? TryReadBootUtc()
    {
        try
        {
            return _configurationStore.ReadPageFileRuntime().BootUtc;
        }
        catch (Exception exception) when (IsConfigurationFailure(exception))
        {
            return null;
        }
    }

    private void EnsureProtectedTargetNotRunning(TargetProfile? target)
    {
        if (_isProtectedTargetRunning() || target is { BlockSensitiveOperationsWhileRunning: true } &&
            target.ProcessNames
                .Concat(target.RelatedProcessNames)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Any(_isNamedProcessRunning))
        {
            throw new ProtectedTargetRunningException();
        }
    }

    private static bool IsProcessRunningFailClosed(string processName)
    {
        try
        {
            Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));
            try
            {
                return processes.Any(process => !process.HasExited);
            }
            finally
            {
                foreach (Process process in processes)
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

    private static bool IsConfigurationFailure(Exception exception) => exception is
        IOException or
        UnauthorizedAccessException or
        InvalidDataException or
        ArgumentException or
        System.Security.SecurityException or
        System.ComponentModel.Win32Exception or
        PlatformNotSupportedException or
        System.Management.ManagementException or
        ProtectedTargetRunningException;

    internal static string DefaultWerDumpRoot() => Path.Combine(
        MachineDataRoot(System.Security.Principal.WindowsIdentity.GetCurrent().User ??
                        throw new InvalidOperationException("The current Windows user SID was unavailable.")),
        "ApplicationDumps");

    internal static string ApprovedWerDumpFolder(string root, string executableName)
    {
        string safeName = WindowsCrashCaptureConfigurationStore.NormalizeExecutableName(executableName);
        string hash = Convert.ToHexString(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(safeName.ToUpperInvariant())))[..16].ToLowerInvariant();
        return Path.GetFullPath(Path.Combine(Path.GetFullPath(root), hash));
    }

    private async Task<ProtectedEvidenceResponse> CopySelectedDumpAsync(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken)
    {
        if (!request.PrivacyConfirmed || !request.SizeConfirmed || !request.FreeSpaceConfirmed)
        {
            return new ProtectedEvidenceResponse(false,
                "Privacy, dump size, and destination free-space confirmation are all required before staging.");
        }

        if (request.Source is not null ||
            string.IsNullOrWhiteSpace(request.DumpPath) ||
            request.ExpectedSizeBytes is null or < 0 ||
            request.ExpectedLastWriteUtc is null ||
            request.ReportSessionId is not null ||
            request.ReportSha256 is not null ||
            request.WindowStartUtc is not null ||
            request.WindowEndUtc is not null ||
            request.TargetProfile is not null ||
            request.CrashCapturePlan is not null ||
            request.WerLocalDumpPlan is not null ||
            request.ConfigurationReceiptId is not null)
        {
            return new ProtectedEvidenceResponse(false, "The selected-dump request was incomplete.");
        }

        if (request.ExpectedSizeBytes > MaximumDumpBytes)
        {
            return new ProtectedEvidenceResponse(false,
                "The selected dump is larger than the helper's 64 GiB staging limit. Use a manual WinDbg handoff.");
        }

        string sourcePath;
        string sourceType;
        DumpArtifactIdentity initialIdentity;
        try
        {
            (sourcePath, sourceType) = ValidateApprovedDumpPath(request.DumpPath);
            initialIdentity = DumpPackager.CaptureIdentity(
                sourcePath,
                request.ExpectedSizeBytes.Value,
                request.ExpectedLastWriteUtc.Value);
            if (initialIdentity.SizeBytes > MaximumDumpBytes)
            {
                return new ProtectedEvidenceResponse(false,
                    "The selected dump is larger than the helper's 64 GiB staging limit. Use a manual WinDbg handoff.");
            }
        }
        catch (UnauthorizedAccessException)
        {
            return new ProtectedEvidenceResponse(false, "The selected file was outside the approved Windows dump roots.");
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or ArgumentException)
        {
            return new ProtectedEvidenceResponse(false,
                "The selected dump failed extension, signature, reparse-path, or file-identity validation.");
        }

        string? stagingDirectory = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureStagingRoot();
            long requiredBytes = checked(request.ExpectedSizeBytes.Value +
                                         Math.Max(64L * 1024 * 1024, request.ExpectedSizeBytes.Value / 20));
            if (_availableFreeSpace(_stagingRoot) < requiredBytes)
            {
                return new ProtectedEvidenceResponse(false,
                    "The private staging drive does not have enough free space for the dump and safety margin.");
            }

            stagingDirectory = ReserveStagingDirectory();
            string destinationPath = Path.Combine(stagingDirectory, "protected-dump.dmp");
            await File.WriteAllTextAsync(
                Path.Combine(stagingDirectory, MarkerName),
                DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                cancellationToken).ConfigureAwait(false);

            string sha256;
            await using (var input = new FileStream(
                             sourcePath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read,
                             1024 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var output = new FileStream(
                             destinationPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             1024 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough))
            using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                if (input.Length != request.ExpectedSizeBytes.Value)
                {
                    throw new IOException("The dump changed before copying began.");
                }

                byte[] buffer = new byte[1024 * 1024];
                long copied = 0;
                while (true)
                {
                    if (_isProtectedTargetRunning())
                    {
                        throw new ProtectedTargetRunningException();
                    }

                    int read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    copied = checked(copied + read);
                    if (copied > MaximumDumpBytes || copied > request.ExpectedSizeBytes.Value)
                    {
                        throw new InvalidDataException("The dump exceeded its approved size during copying.");
                    }

                    hash.AppendData(buffer.AsSpan(0, read));
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }

                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                if (copied != request.ExpectedSizeBytes.Value)
                {
                    throw new IOException("The staged dump length did not match the approved source length.");
                }

                sha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            }

            DumpArtifactIdentity finalIdentity = DumpPackager.CaptureIdentity(
                sourcePath,
                request.ExpectedSizeBytes.Value,
                request.ExpectedLastWriteUtc.Value);
            var stagedInfo = new FileInfo(destinationPath);
            if (_isProtectedTargetRunning())
            {
                throw new ProtectedTargetRunningException();
            }

            if (stagedInfo.Length != finalIdentity.SizeBytes ||
                !string.Equals(
                    initialIdentity.FileIdentityHash,
                    finalIdentity.FileIdentityHash,
                    StringComparison.Ordinal))
            {
                throw new IOException("The staged dump did not match the source identity.");
            }

            var staged = new StagedDump(
                stagingDirectory,
                destinationPath,
                stagedInfo.Length,
                sha256,
                sourceType,
                DateTimeOffset.UtcNow,
                sourcePath);
            return new ProtectedEvidenceResponse(true,
                "The selected dump was copied to private temporary staging and hashed.",
                StagedDump: staged);
        }
        catch (OperationCanceledException)
        {
            if (stagingDirectory is not null)
            {
                TryDeleteValidatedStagingDirectory(stagingDirectory);
            }

            throw;
        }
        catch (Exception exception) when (exception is IOException or
                                          UnauthorizedAccessException or
                                          InvalidDataException or
                                          ProtectedTargetRunningException or
                                          System.ComponentModel.Win32Exception)
        {
            if (stagingDirectory is not null)
            {
                TryDeleteValidatedStagingDirectory(stagingDirectory);
            }

            return new ProtectedEvidenceResponse(false,
                "The protected dump could not be staged safely; any partial copy was removed.");
        }
    }

    private (string Path, string SourceType) ValidateApprovedDumpPath(string path)
    {
        if (TryClassifyApprovedDumpPath(path, _roots, out string fullPath, out string sourceType))
        {
            return (fullPath, sourceType);
        }

        throw new UnauthorizedAccessException("The dump is not in an approved Windows dump root.");
    }

    internal static bool TryClassifyApprovedDumpPath(
        string path,
        ProtectedEvidenceRoots roots,
        out string fullPath,
        out string sourceType)
    {
        fullPath = string.Empty;
        sourceType = string.Empty;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return false;
        }

        if (!Path.GetExtension(fullPath).Equals(".dmp", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.Equals(fullPath, Path.GetFullPath(roots.MemoryDumpPath), StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                PathSafety.EnsureNoReparseComponents(fullPath);
                sourceType = "Windows memory dump";
                return true;
            }
            catch (IOException)
            {
                return false;
            }
        }

        if (IsContainedDump(roots.MinidumpRoot, fullPath))
        {
            sourceType = "Windows minidump";
            return true;
        }

        if (IsContainedDump(roots.LiveKernelRoot, fullPath))
        {
            sourceType = "Windows live kernel dump";
            return true;
        }

        return false;
    }

    private static bool IsContainedDump(string root, string fullPath)
    {
        try
        {
            string contained = PathSafety.EnsureContained(root, fullPath);
            if (string.Equals(contained, Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            PathSafety.EnsureNoReparseComponents(root, contained);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static ProtectedEvidenceProbe ProbeEventLog(ProtectedEvidenceSource source, string logName)
    {
        using var session = new EventLogSession();
        EventLogInformation information = session.GetLogInformation(logName, PathType.LogName);
        int count = information.RecordCount is > int.MaxValue
            ? int.MaxValue
            : checked((int)(information.RecordCount ?? 0));
        return new ProtectedEvidenceProbe(source, CollectionState.Available, count,
            $"The helper could read the {logName} event log. No settings were changed.");
    }

    private static ProtectedEvidenceProbe ProbeFile(ProtectedEvidenceSource source, string path)
    {
        PathSafety.EnsureNoReparseComponents(path);
        int count = File.Exists(path) ? 1 : 0;
        return new ProtectedEvidenceProbe(source, CollectionState.Available, count,
            count == 1 ? "The protected dump source was accessible." : "The protected dump source was accessible but no file was present.");
    }

    private static ProtectedEvidenceProbe ProbeDirectory(ProtectedEvidenceSource source, string path)
    {
        PathSafety.EnsureNoReparseComponents(path);
        int count = Directory.Exists(path) ? CountDumpFilesWithoutFollowingReparsePoints(path, 10_001) : 0;
        return new ProtectedEvidenceProbe(source, CollectionState.Available, Math.Min(count, 10_000),
            count > 10_000
                ? "The protected source was accessible; more than 10,000 dump candidates were present."
                : "The protected source was accessible. No settings were changed.");
    }

    private void EnsureStagingRoot()
    {
        Directory.CreateDirectory(_stagingRoot);
        PathSafety.EnsureNoReparseComponents(_stagingRoot);
        if (_productionOriginBoundary)
        {
            OriginDataAcl.ProtectDirectory(_stagingRoot, _originatingUserSid, userCanWrite: true);
        }
        else
        {
            PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(_stagingRoot);
        }
    }

    private string ReserveStagingDirectory()
    {
        for (int attempt = 0; attempt < 64; attempt++)
        {
            string candidate = Path.Combine(
                _stagingRoot,
                "stage-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant());
            PathSafety.EnsureContained(_stagingRoot, candidate);
            PathSafety.EnsureNoReparseComponents(_stagingRoot, candidate);
            if (!CreateDirectory(candidate, IntPtr.Zero))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 183)
                {
                    continue;
                }

                throw new System.ComponentModel.Win32Exception(error, "Could not reserve a private staging directory.");
            }

            try
            {
                if (_productionOriginBoundary)
                {
                    OriginDataAcl.ProtectDirectory(candidate, _originatingUserSid, userCanWrite: true);
                }
                else
                {
                    PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(candidate);
                }
                return candidate;
            }
            catch
            {
                try
                {
                    Directory.Delete(candidate, recursive: false);
                }
                catch (IOException)
                {
                }

                throw;
            }
        }

        throw new IOException("Could not reserve a private random staging directory.");
    }

    private void TryDeleteValidatedStagingDirectory(string directory)
    {
        try
        {
            string fullDirectory = PathSafety.EnsureContained(_stagingRoot, directory);
            if (!Path.GetFileName(fullDirectory).StartsWith("stage-", StringComparison.Ordinal) ||
                ContainsReparseEntry(fullDirectory))
            {
                return;
            }

            Directory.Delete(fullDirectory, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static bool ContainsReparseEntry(string directory)
    {
        var pending = new Stack<string>();
        pending.Push(directory);
        while (pending.TryPop(out string? current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }

            foreach (string child in Directory.EnumerateFileSystemEntries(current, "*", SearchOption.TopDirectoryOnly))
            {
                FileAttributes attributes = File.GetAttributes(child);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return true;
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(child);
                }
            }
        }

        return false;
    }

    private static int CountDumpFilesWithoutFollowingReparsePoints(string root, int limit)
    {
        int count = 0;
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out string? current))
        {
            foreach (string child in Directory.EnumerateFileSystemEntries(current, "*", SearchOption.TopDirectoryOnly))
            {
                FileAttributes attributes = File.GetAttributes(child);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(child);
                }
                else if (Path.GetExtension(child).Equals(".dmp", StringComparison.OrdinalIgnoreCase) &&
                         ++count >= limit)
                {
                    return count;
                }
            }
        }

        return count;
    }

    private static long GetAvailableFreeSpace(string directory)
    {
        string root = Path.GetPathRoot(directory)
            ?? throw new IOException("The staging directory has no filesystem root.");
        return new DriveInfo(root).AvailableFreeSpace;
    }

    internal static string DefaultStagingRoot() => Path.Combine(
        MachineDataRoot(System.Security.Principal.WindowsIdentity.GetCurrent().User ??
                        throw new InvalidOperationException("The current Windows user SID was unavailable.")),
        "ProtectedStaging");

    private static string MachineDataRoot(System.Security.Principal.SecurityIdentifier sid) => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "PCCrashDiagnostic",
        sid.Value);

    private static void EnsureMachineDataRoot(
        string dataRoot,
        System.Security.Principal.SecurityIdentifier originatingUserSid)
    {
        string globalRoot = Path.GetDirectoryName(Path.GetFullPath(dataRoot))
            ?? throw new IOException("The machine diagnostic data root was invalid.");
        MachineDataRootAcl.EnsureAdminOwned(globalRoot);
        PathSafety.EnsureNoReparseComponents(dataRoot);
        Directory.CreateDirectory(dataRoot);
        PathSafety.EnsureNoReparseComponents(dataRoot);
        ConfigurationReceiptAcl.ProtectDirectory(dataRoot, originatingUserSid);
    }

    private static bool IsBattlefield6Running()
    {
        try
        {
            Process[] processes = Process.GetProcessesByName("BF6");
            try
            {
                return processes.Length > 0;
            }
            finally
            {
                foreach (Process process in processes)
                {
                    process.Dispose();
                }
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or
                                          System.ComponentModel.Win32Exception or
                                          System.Security.SecurityException or
                                          PlatformNotSupportedException)
        {
            // The anti-cheat boundary is fail-closed. If Windows cannot answer the
            // process query reliably, the elevated helper must not touch dumps.
            return true;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string pathName, IntPtr securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        Microsoft.Win32.SafeHandles.SafeProcessHandle processHandle,
        uint desiredAccess,
        out Microsoft.Win32.SafeHandles.SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        Microsoft.Win32.SafeHandles.SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        ref int tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    private sealed class ProtectedTargetRunningException : Exception;
}

internal sealed record WerProcessIdentity(
    int SessionId,
    string OwnerSid,
    bool IsElevated,
    bool ClassificationSucceeded = true);

internal static class WerDumpDirectoryAcl
{
    public static void ProtectLeaf(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid)
    {
        try
        {
            var directory = new DirectoryInfo(path);
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var administrators = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
                null);
            var system = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid,
                null);
            security.SetOwner(administrators);
            foreach (System.Security.Principal.SecurityIdentifier sid in new[] { administrators, system })
            {
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    sid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));
            }

            const System.Security.AccessControl.FileSystemRights dumpRights =
                System.Security.AccessControl.FileSystemRights.ReadAndExecute |
                System.Security.AccessControl.FileSystemRights.WriteData |
                System.Security.AccessControl.FileSystemRights.AppendData |
                System.Security.AccessControl.FileSystemRights.WriteAttributes |
                System.Security.AccessControl.FileSystemRights.WriteExtendedAttributes |
                System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles |
                System.Security.AccessControl.FileSystemRights.Synchronize;
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                originatingUserSid,
                dumpRights,
                System.Security.AccessControl.InheritanceFlags.None,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                originatingUserSid,
                System.Security.AccessControl.FileSystemRights.Modify |
                System.Security.AccessControl.FileSystemRights.Synchronize,
                System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.InheritOnly,
                System.Security.AccessControl.AccessControlType.Allow));
            directory.SetAccessControl(security);
            PathSafety.EnsureNoReparseComponents(path);
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or
                                          UnauthorizedAccessException or System.Security.SecurityException or
                                          InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            throw new IOException("The per-application dump folder ACL could not be restricted.", exception);
        }
    }
}

internal sealed record ProtectedEvidenceRoots(
    string MemoryDumpPath,
    string MinidumpRoot,
    string LiveKernelRoot)
{
    public static ProtectedEvidenceRoots CreateDefault()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return new ProtectedEvidenceRoots(
            Path.Combine(windows, "MEMORY.DMP"),
            Path.Combine(windows, "Minidump"),
            Path.Combine(windows, "LiveKernelReports"));
    }
}
