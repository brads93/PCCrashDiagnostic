using System.Globalization;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using PCCrashDiagnostic.Contracts;

namespace BF6CrashDiagnostic.Core.Sharing;

public static partial class SafeSummaryProjector
{
    private const int MaximumBugchecks = 16;
    private const int MaximumDumps = 24;
    private const int MaximumStorageDevices = 32;
    private const int MaximumRecentChanges = 32;
    private const int MaximumVerifiedDrivers = 32;
    private const int MaximumDriverFacts = 32;
    private const int MaximumStackModules = 24;

    private static readonly IReadOnlyDictionary<string, SafeFindingKind> FindingMap =
        new Dictionary<string, SafeFindingKind>(StringComparer.Ordinal)
        {
            ["bugcheck"] = SafeFindingKind.Bugcheck,
            ["whea"] = SafeFindingKind.HardwareError,
            ["dump-write-failure"] = SafeFindingKind.DumpWriteFailure,
            ["gpu-timeout"] = SafeFindingKind.GpuTimeout,
            ["resource-exhaustion"] = SafeFindingKind.ResourceExhaustion,
            ["rising-memory-trend"] = SafeFindingKind.RisingMemoryUse,
            ["application-failure"] = SafeFindingKind.ApplicationFailure,
            ["unclean-shutdown"] = SafeFindingKind.UnexpectedShutdown,
            ["storage-health-warning"] = SafeFindingKind.StorageHealthWarning,
            ["driver-verifier-enabled"] = SafeFindingKind.DriverVerifierEnabled,
            ["recent-system-changes"] = SafeFindingKind.RecentSystemChanges
        };

    public static SafeSummaryV1 Project(DiagnosticReportV3 report)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.ReportSchemaVersion != 3)
        {
            throw new InvalidDataException("Safe Summary v1 accepts report schema 3 only.");
        }

        bool omitted = false;
        string sourceReportVersion = SafeVersion(report.ToolVersion) ?? "unknown";
        omitted |= sourceReportVersion == "unknown" && !string.IsNullOrWhiteSpace(report.ToolVersion);

        IncidentKind incidentKind = report.IncidentSelection?.Candidate.Kind ?? IncidentKind.Unknown;
        DateTimeOffset? incidentTime = RoundToMinute(
            report.IncidentSelection?.Candidate.TimeUtc ?? report.Bugchecks?.OrderBy(item => item.TimeUtc).FirstOrDefault()?.TimeUtc);
        string? targetExecutable = FirstSafeExecutable(report.TargetProfile?.ProcessNames);
        omitted |= report.TargetProfile is not null && targetExecutable is null;

        SystemSnapshot? snapshot = report.EndSnapshot ?? report.StartSnapshot;
        SafeSystemFacts? system = snapshot is null ? null : ProjectSystem(snapshot, ref omitted);
        SafeBugcheck[] bugchecks = (report.Bugchecks ?? [])
            .Where(item => item.Code.HasValue)
            .OrderBy(item => item.TimeUtc)
            .Take(MaximumBugchecks)
            .Select(item => new SafeBugcheck(
                item.Code!.Value,
                BugcheckCatalog.GetName(item.Code.Value),
                NormalizeParameters(item.Parameters),
                Enum.IsDefined(item.EvidenceSource) ? item.EvidenceSource : BugcheckEvidenceSource.Unknown))
            .ToArray();
        omitted |= (report.Bugchecks?.Count ?? 0) > bugchecks.Length;

        SafeWheaSignal[] whea = ProjectWhea(report, ref omitted);
        SafeEvidenceSignal[] signals = ProjectSignals(report, ref omitted);
        SafeReadinessFacts? readiness = ProjectReadiness(report.CrashReadiness);

        SafeDumpFact[] dumps = (report.DumpInventory?.Candidates ?? [])
            .Take(MaximumDumps)
            .Select(item => new SafeDumpFact(
                DefinedOr(item.Kind, DumpKind.Unknown),
                DefinedOr(item.Format, DumpFormat.Unknown),
                DefinedOr(item.InspectionState, DumpInspectionState.Error),
                Bucket(item.SizeBytes)))
            .ToArray();
        omitted |= (report.DumpInventory?.Candidates?.Count ?? 0) > dumps.Length;

        SafeDumpQualityFact? dumpQuality = report.DumpQuality is null
            ? null
            : new SafeDumpQualityFact(
                DefinedOr(report.DumpQuality.Classification, DumpQualityClassification.AnalysisUnavailable),
                DefinedOr(report.DumpQuality.Format, DumpFormat.Unknown),
                DefinedOr(report.DumpQuality.DumpChkState, DumpChkState.Error));

        SafeStorageFact[] storage = ProjectStorage(report.StorageHealth, ref omitted);
        SafeRecentChangeFact[] changes = ProjectRecentChanges(report.RecentChanges, ref omitted);
        SafeDriverFact[] drivers = ProjectDrivers(report.DriverInventory, ref omitted);
        SafeDriverVerifierFact? verifier = ProjectVerifier(report.DriverVerifier, ref omitted);
        SafeDebuggerFact? debugger = ProjectDebugger(report.DebuggerAnalysis, ref omitted);
        SafeCoverageFact[] coverage = ProjectCoverage(report.SourceCoverage, ref omitted);
        SafeFindingKind[] findings = ProjectFindings(report.Findings, ref omitted);

        return new SafeSummaryV1(
            FormatVersion: 1,
            GeneratorVersion: BuildProfile.Version,
            GeneratorProfile: BuildProfile.Current.Profile,
            SourceReportVersion: sourceReportVersion,
            IncidentKind: DefinedOr(incidentKind, IncidentKind.Unknown),
            IncidentTimeUtc: incidentTime,
            TargetExecutable: targetExecutable,
            System: system,
            Bugchecks: bugchecks,
            WheaSignals: whea,
            EvidenceSignals: signals,
            CrashReadiness: readiness,
            Dumps: dumps,
            DumpQuality: dumpQuality,
            Storage: storage,
            RecentChanges: changes,
            Drivers: drivers,
            DriverVerifier: verifier,
            Debugger: debugger,
            Coverage: coverage,
            Findings: findings,
            ValuesWereOmitted: omitted);
    }

    private static SafeSystemFacts ProjectSystem(SystemSnapshot snapshot, ref bool omitted)
    {
        string? cpu = SafeCpuLabel(snapshot.CpuName);
        omitted |= cpu is null && !string.IsNullOrWhiteSpace(snapshot.CpuName);
        string[] gpus = (snapshot.Gpus ?? [])
            .Select(item => SafeGpuLabel(item.Name))
            .Where(item => item is not null)
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(4)
            .ToArray();
        omitted |= (snapshot.Gpus?.Count ?? 0) > gpus.Length;
        string? caption = SafeWindowsLabel(snapshot.WindowsCaption);
        string? version = SafeVersion(snapshot.WindowsVersion);
        string? build = SafeVersion(snapshot.WindowsBuild);
        string? architecture = SafeArchitecture(snapshot.WindowsArchitecture);
        omitted |= (!string.IsNullOrWhiteSpace(snapshot.WindowsCaption) && caption is null) ||
                   (!string.IsNullOrWhiteSpace(snapshot.WindowsVersion) && version is null) ||
                   (!string.IsNullOrWhiteSpace(snapshot.WindowsBuild) && build is null) ||
                   (!string.IsNullOrWhiteSpace(snapshot.WindowsArchitecture) && architecture is null);
        SafeMotherboardVendor boardVendor = MapMotherboardVendor(snapshot.MotherboardManufacturer);
        string? boardProduct = boardVendor == SafeMotherboardVendor.Unknown
            ? null
            : SafeBoardProduct(snapshot.MotherboardProduct);
        string? biosVersion = boardVendor == SafeMotherboardVendor.Unknown
            ? null
            : SafeBiosVersion(snapshot.BiosVersion);
        omitted |= (boardVendor == SafeMotherboardVendor.Unknown &&
                    (!string.IsNullOrWhiteSpace(snapshot.MotherboardManufacturer) || !string.IsNullOrWhiteSpace(snapshot.MotherboardProduct))) ||
                   (boardVendor != SafeMotherboardVendor.Unknown && !string.IsNullOrWhiteSpace(snapshot.MotherboardProduct) && boardProduct is null) ||
                   (boardVendor != SafeMotherboardVendor.Unknown && !string.IsNullOrWhiteSpace(snapshot.BiosVersion) && biosVersion is null);
        return new SafeSystemFacts(
            cpu,
            gpus,
            snapshot.TotalPhysicalMemoryBytes == 0 ? null : snapshot.TotalPhysicalMemoryBytes,
            caption,
            version,
            build,
            architecture,
            snapshot.PreviewBuildDetected,
            boardVendor,
            boardProduct,
            biosVersion);
    }

    private static SafeWheaSignal[] ProjectWhea(DiagnosticReportV3 report, ref bool omitted)
    {
        if (report.WheaEvidence is { Count: > 0 })
        {
            WheaEvidence[] accepted = report.WheaEvidence
                .Where(item => WheaEventCatalog.IsKnown(item.EventId) &&
                               Enum.IsDefined(item.Classification) &&
                               Enum.IsDefined(item.Category) &&
                               item.Count > 0)
                .Take(64)
                .ToArray();
            omitted |= accepted.Length != report.WheaEvidence.Count;
            return accepted
                .GroupBy(item => (item.EventId, item.Classification, item.Category))
                .Select(group => new SafeWheaSignal(
                    group.Key.EventId,
                    group.Key.Classification,
                    group.Key.Category,
                    group.Aggregate(0, (count, item) =>
                        count > int.MaxValue - item.Count ? int.MaxValue : count + item.Count)))
                .OrderBy(item => item.EventId)
                .ThenBy(item => item.Category)
                .ToArray();
        }

        var eventCounts = new Dictionary<(int Id, WheaEventClassification Classification), int>();
        var groupCounts = new Dictionary<(int Id, WheaEventClassification Classification), int>();
        foreach (DiagnosticEvent item in report.Events ?? [])
        {
            if (!WheaEventCatalog.IsProvider(item.ProviderName, item.ProviderGuid) || !WheaEventCatalog.IsKnown(item.EventId))
            {
                continue;
            }

            Add(eventCounts, (item.EventId, WheaEventCatalog.Classify(item.EventId)), 1);
        }

        foreach (DuplicateEventGroup item in report.EventGroups ?? [])
        {
            if (!WheaEventCatalog.IsProvider(item.ProviderName, item.ProviderGuid) || !WheaEventCatalog.IsKnown(item.EventId))
            {
                continue;
            }

            Add(groupCounts, (item.EventId, WheaEventCatalog.Classify(item.EventId)), Math.Max(1, item.Count));
        }

        var counts = MergeDerivedCounts(eventCounts, groupCounts);
        if (counts.Count > WheaEventCatalog.KnownEventIds.Count)
        {
            omitted = true;
        }

        return counts
            .OrderBy(item => item.Key.Id)
            .Select(item => new SafeWheaSignal(item.Key.Id, item.Key.Classification, null, item.Value))
            .ToArray();
    }

    private static SafeEvidenceSignal[] ProjectSignals(DiagnosticReportV3 report, ref bool omitted)
    {
        var eventCounts = new Dictionary<(SafeEvidenceSignalKind Kind, int EventId), int>();
        var groupCounts = new Dictionary<(SafeEvidenceSignalKind Kind, int EventId), int>();
        foreach (DiagnosticEvent item in report.Events ?? [])
        {
            if (TryClassifySignal(item.ProviderName, item.EventId, out SafeEvidenceSignalKind kind))
            {
                Add(eventCounts, (kind, item.EventId), 1);
            }
        }

        foreach (DuplicateEventGroup item in report.EventGroups ?? [])
        {
            if (TryClassifySignal(item.ProviderName, item.EventId, out SafeEvidenceSignalKind kind))
            {
                Add(groupCounts, (kind, item.EventId), Math.Max(1, item.Count));
            }
        }

        var counts = MergeDerivedCounts(eventCounts, groupCounts);
        if (counts.Count > 64)
        {
            omitted = true;
        }

        return counts
            .OrderBy(item => item.Key.Kind)
            .ThenBy(item => item.Key.EventId)
            .Take(64)
            .Select(item => new SafeEvidenceSignal(item.Key.Kind, item.Key.EventId, item.Value))
            .ToArray();
    }

    private static SafeReadinessFacts? ProjectReadiness(CrashReadiness? readiness)
    {
        if (readiness is null)
        {
            return null;
        }

        return new SafeReadinessFacts(
            DefinedOr(readiness.DumpMode, CrashDumpMode.Unknown),
            DefinedOr(readiness.Assessment, CrashReadinessState.Unavailable),
            DefinedOr(readiness.ActivationState, CrashCaptureActivationState.Unknown),
            readiness.EventLoggingEnabled,
            readiness.OverwriteEnabled,
            readiness.SystemManagedPageFile,
            readiness.DumpDestinationAccessible,
            Bucket(readiness.RequiredDumpBackingBytes),
            Bucket(readiness.DumpDestinationFreeBytes));
    }

    private static SafeStorageFact[] ProjectStorage(StorageHealthSnapshot? snapshot, ref bool omitted)
    {
        if (snapshot is null)
        {
            return [];
        }

        SafeStorageFact[] values = (snapshot.Devices ?? [])
            .Take(MaximumStorageDevices)
            .Select(item => new SafeStorageFact(
                Math.Clamp(item.Ordinal, 0, 255),
                MapMedia(item.MediaType),
                MapBus(item.BusType),
                MapHealth(item.HealthStatus),
                ClampTemperature(item.TemperatureCelsius),
                item.WearPercent is <= 100 ? item.WearPercent : null,
                Positive(item.ReadErrorsTotal) || Positive(item.ReadErrorsUncorrected) ||
                Positive(item.WriteErrorsTotal) || Positive(item.WriteErrorsUncorrected),
                Above(item.ReadLatencyMaximumMilliseconds, 1_000) ||
                Above(item.WriteLatencyMaximumMilliseconds, 1_000) ||
                Above(item.FlushLatencyMaximumMilliseconds, 1_000)))
            .ToArray();
        omitted |= (snapshot.Devices?.Count ?? 0) > values.Length;
        return values;
    }

    private static SafeRecentChangeFact[] ProjectRecentChanges(RecentChangeTimeline? timeline, ref bool omitted)
    {
        if (timeline is null)
        {
            return [];
        }

        SafeRecentChangeFact[] values = (timeline.Records ?? [])
            .OrderByDescending(item => item.TimeUtc)
            .Take(MaximumRecentChanges)
            .Select(item => new SafeRecentChangeFact(
                DefinedOr(item.Kind, RecentChangeKind.WindowsUpdate),
                SafeChangeReference(item),
                MapChangeResult(item.Result),
                item.Within24Hours,
                item.WithinSevenDays))
            .ToArray();
        omitted |= (timeline.Records?.Count ?? 0) > values.Length ||
                   (timeline.Records ?? []).Any(item => SafeChangeReference(item) is null && !string.IsNullOrWhiteSpace(item.Title));
        return values;
    }

    private static SafeDriverVerifierFact? ProjectVerifier(DriverVerifierState? state, ref bool omitted)
    {
        if (state is null)
        {
            return null;
        }

        string[] drivers = (state.VerifiedDriverBasenames ?? [])
            .Select(SafeDriverBasename)
            .Where(item => item is not null)
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaximumVerifiedDrivers)
            .ToArray();
        int omittedDrivers = Math.Max(0, (state.VerifiedDriverBasenames?.Count ?? 0) - drivers.Length);
        omitted |= omittedDrivers > 0;
        return new SafeDriverVerifierFact(
            DefinedOr(state.Status, DriverVerifierStatusKind.Indeterminate),
            ParseUInt32(state.Flags),
            drivers,
            omittedDrivers);
    }

    private static SafeDriverFact[] ProjectDrivers(DriverInventory? inventory, ref bool omitted)
    {
        if (inventory is null)
        {
            return [];
        }

        var facts = new List<SafeDriverFact>();
        foreach (DriverDeviceRecord item in inventory.Drivers ?? [])
        {
            SafeDriverProvider provider = MapDriverProvider(item.DriverProvider);
            SafeDriverDeviceClass deviceClass = MapDriverClass(item.DeviceClass);
            string? version = SafeDriverVersion(item.DriverVersion);
            string? inf = SafeInfBasename(item.InfName);
            int? problem = item.DeviceManagerProblemCode is >= 0 and <= 255
                ? item.DeviceManagerProblemCode
                : null;
            bool rejected = provider == SafeDriverProvider.Unknown ||
                            deviceClass == SafeDriverDeviceClass.Unknown ||
                            (!string.IsNullOrWhiteSpace(item.DriverVersion) && version is null) ||
                            (!string.IsNullOrWhiteSpace(item.InfName) && inf is null) ||
                            (item.DeviceManagerProblemCode.HasValue && problem is null);
            if (rejected)
            {
                omitted = true;
                continue;
            }

            if (facts.Count >= MaximumDriverFacts)
            {
                omitted = true;
                continue;
            }

            facts.Add(new SafeDriverFact(
                provider,
                deviceClass,
                version,
                item.DriverDateUtc.HasValue ? DateOnly.FromDateTime(item.DriverDateUtc.Value.UtcDateTime) : null,
                inf,
                item.IsSigned,
                problem));
        }

        return facts
            .OrderBy(item => item.DeviceClass)
            .ThenBy(item => item.Provider)
            .ThenBy(item => item.InfBasename, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static SafeDebuggerFact? ProjectDebugger(DebuggerAnalysis? analysis, ref bool omitted)
    {
        if (analysis is null)
        {
            return null;
        }

        string? bucket = SafeDebuggerToken(analysis.FailureBucket);
        string? module = SafeModuleBasename(analysis.ModuleName);
        string? image = SafeModuleBasename(analysis.ImageName);
        string? process = SafeProcessBasename(analysis.ProcessName);
        string[] stack = (analysis.StackModules ?? [])
            .Select(SafeModuleBasename)
            .Where(item => item is not null)
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaximumStackModules)
            .ToArray();
        int omittedStack = Math.Max(0, (analysis.StackModules?.Count ?? 0) - stack.Length);
        omitted |= (!string.IsNullOrWhiteSpace(analysis.FailureBucket) && bucket is null) ||
                   (!string.IsNullOrWhiteSpace(analysis.ModuleName) && module is null) ||
                   (!string.IsNullOrWhiteSpace(analysis.ImageName) && image is null) ||
                   (!string.IsNullOrWhiteSpace(analysis.ProcessName) && process is null) ||
                   omittedStack > 0;
        return new SafeDebuggerFact(
            DefinedOr(analysis.State, DebuggerAnalysisState.Failed),
            DefinedOr(analysis.SymbolAccess, SymbolAccessMode.LocalOnly),
            bucket,
            module,
            image,
            process,
            MapSymbolStatus(analysis.SymbolStatus),
            stack,
            omittedStack);
    }

    private static SafeCoverageFact[] ProjectCoverage(IReadOnlyList<SourceCoverage>? values, ref bool omitted)
    {
        var projected = new Dictionary<SafeCoverageSource, SafeCoverageFact>();
        foreach (SourceCoverage item in values ?? [])
        {
            SafeCoverageSource source = MapCoverageSource(item.Source);
            if (source == SafeCoverageSource.Unknown)
            {
                omitted = true;
                continue;
            }

            int count = Math.Clamp(item.RecordCount, 0, 1_000_000);
            CollectionState state = DefinedOr(item.State, CollectionState.Error);
            projected[source] = new SafeCoverageFact(source, state, count);
        }

        return projected.Values.OrderBy(item => item.Source).ToArray();
    }

    private static SafeFindingKind[] ProjectFindings(IReadOnlyList<DiagnosticFinding>? values, ref bool omitted)
    {
        var findings = new HashSet<SafeFindingKind>();
        foreach (DiagnosticFinding item in values ?? [])
        {
            if (item.Id.StartsWith("dump-quality-", StringComparison.Ordinal))
            {
                findings.Add(SafeFindingKind.DumpQuality);
            }
            else if (FindingMap.TryGetValue(item.Id, out SafeFindingKind finding))
            {
                findings.Add(finding);
            }
            else
            {
                omitted = true;
            }
        }

        return findings.Order().ToArray();
    }

    private static bool TryClassifySignal(string? provider, int eventId, out SafeEvidenceSignalKind kind)
    {
        kind = default;
        string value = provider?.Trim() ?? string.Empty;
        if (Is(value, "Microsoft-Windows-WER-SystemErrorReporting", "Windows Error Reporting") && eventId == 1001)
        {
            kind = SafeEvidenceSignalKind.BugcheckReport;
        }
        else if (Is(value, "Microsoft-Windows-Kernel-Power") && eventId == 41)
        {
            kind = SafeEvidenceSignalKind.UnexpectedPowerLoss;
        }
        else if (Is(value, "EventLog") && eventId == 6008)
        {
            kind = SafeEvidenceSignalKind.UnexpectedShutdown;
        }
        else if (Is(value, "volmgr") && eventId is 46 or 161)
        {
            kind = SafeEvidenceSignalKind.DumpWriteFailure;
        }
        else if (Is(value, "Display") && eventId == 4101)
        {
            kind = SafeEvidenceSignalKind.GpuReset;
        }
        else if (StorageEventCatalog.TryClassify(value, eventId, out _))
        {
            kind = SafeEvidenceSignalKind.StorageError;
        }
        else if (Is(value, "Ntfs", "Microsoft-Windows-Ntfs") && eventId is 50 or 55 or 98 or 140 ||
                 Is(value, "ReFS", "Microsoft-Windows-ReFS") && eventId == 134)
        {
            kind = SafeEvidenceSignalKind.FileSystemError;
        }
        else if (Is(value, "Microsoft-Windows-MemoryDiagnostics-Results") && eventId is >= 1101 and <= 1104 or 1201 or 1202)
        {
            kind = SafeEvidenceSignalKind.MemoryDiagnostic;
        }
        else if (Is(value, "Application Error") && eventId == 1000)
        {
            kind = SafeEvidenceSignalKind.ApplicationCrash;
        }
        else if (Is(value, "Application Hang") && eventId == 1002)
        {
            kind = SafeEvidenceSignalKind.ApplicationHang;
        }
        else if (Is(value, "Microsoft-Windows-Resource-Exhaustion-Detector") && eventId == 2004)
        {
            kind = SafeEvidenceSignalKind.ResourceExhaustion;
        }
        else
        {
            return false;
        }

        return true;
    }

    private static string? SafeChangeReference(RecentSystemChange item)
    {
        string combined = string.Join(' ', item.Title, item.Operation);
        if (item.Kind == RecentChangeKind.WindowsUpdate)
        {
            Match kb = KbReferenceRegex().Match(combined);
            return kb.Success ? "KB" + kb.Groups[1].Value : null;
        }

        if (item.Kind == RecentChangeKind.DriverInstallation)
        {
            Match inf = InfReferenceRegex().Match(combined);
            return inf.Success ? inf.Value.ToLowerInvariant() : null;
        }

        return null;
    }

    private static string? SafeCpuLabel(string? value)
    {
        if (!IsSafeLabel(value, 96))
        {
            return null;
        }

        string normalized = CollapseWhitespace(value!);
        string[] prefixes =
        [
            "AMD Ryzen ", "AMD EPYC ", "AMD Athlon ",
            "Intel(R) Core(TM) ", "Intel(R) Core ", "Intel Core ",
            "Intel(R) Xeon(R) ", "Intel Xeon ",
            "Qualcomm Snapdragon ", "Microsoft SQ"
        ];
        return prefixes.Any(prefix => normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) ||
               IntelGenerationCpuRegex().IsMatch(normalized)
            ? normalized
            : null;
    }

    private static string? SafeGpuLabel(string? value)
    {
        if (!IsSafeLabel(value, 96))
        {
            return null;
        }

        string normalized = CollapseWhitespace(value!);
        string[] prefixes =
        [
            "NVIDIA GeForce", "NVIDIA RTX", "NVIDIA Quadro",
            "AMD Radeon", "Intel(R) Arc", "Intel Arc", "Intel(R) UHD", "Intel UHD",
            "Intel(R) Iris", "Intel Iris", "Microsoft Basic Display Adapter"
        ];
        return prefixes.Any(prefix => normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            ? normalized
            : null;
    }

    private static string? SafeWindowsLabel(string? value)
    {
        if (!IsSafeLabel(value, 64))
        {
            return null;
        }

        string normalized = CollapseWhitespace(value!);
        return normalized.StartsWith("Microsoft Windows ", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("Windows 10 ", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("Windows 11 ", StringComparison.OrdinalIgnoreCase)
            ? normalized
            : null;
    }

    private static SafeMotherboardVendor MapMotherboardVendor(string? value)
    {
        string normalized = Normalize(value);
        if (normalized.Contains("asustek", StringComparison.Ordinal) || normalized is "asus") return SafeMotherboardVendor.Asus;
        if (normalized.Contains("gigabyte", StringComparison.Ordinal)) return SafeMotherboardVendor.Gigabyte;
        if (normalized.Contains("micro-star", StringComparison.Ordinal) || normalized is "msi") return SafeMotherboardVendor.Msi;
        if (normalized.Contains("asrock", StringComparison.Ordinal)) return SafeMotherboardVendor.Asrock;
        if (normalized.Contains("dell", StringComparison.Ordinal)) return SafeMotherboardVendor.Dell;
        if (normalized.Contains("hewlett-packard", StringComparison.Ordinal) || normalized is "hp" or "hp inc.") return SafeMotherboardVendor.Hp;
        if (normalized.Contains("lenovo", StringComparison.Ordinal)) return SafeMotherboardVendor.Lenovo;
        if (normalized.Contains("acer", StringComparison.Ordinal)) return SafeMotherboardVendor.Acer;
        if (normalized.Contains("microsoft", StringComparison.Ordinal)) return SafeMotherboardVendor.Microsoft;
        if (normalized.Contains("framework", StringComparison.Ordinal)) return SafeMotherboardVendor.Framework;
        if (normalized.Contains("supermicro", StringComparison.Ordinal)) return SafeMotherboardVendor.Supermicro;
        return SafeMotherboardVendor.Unknown;
    }

    private static string? SafeBoardProduct(string? value)
    {
        if (!IsSafeLabel(value, 64))
        {
            return null;
        }

        string normalized = CollapseWhitespace(value!);
        if (!BoardProductRegex().IsMatch(normalized) ||
            normalized.Equals("To be filled by O.E.M.", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("Default string", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("System Product Name", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return normalized;
    }

    private static string? SafeBiosVersion(string? value)
    {
        string normalized = value?.Trim() ?? string.Empty;
        return BiosVersionRegex().IsMatch(normalized) ? normalized : null;
    }

    private static string? SafeArchitecture(string? value)
    {
        string normalized = value?.Trim().ToLowerInvariant() ?? string.Empty;
        return normalized switch
        {
            "64-bit" or "x64" or "amd64" => "x64",
            "32-bit" or "x86" => "x86",
            "arm64" => "arm64",
            _ => null
        };
    }

    private static string? SafeVersion(string? value)
    {
        string normalized = value?.Trim() ?? string.Empty;
        return SafeVersionRegex().IsMatch(normalized) ? normalized : null;
    }

    private static string? FirstSafeExecutable(IReadOnlyList<string>? values)
    {
        foreach (string value in values ?? [])
        {
            string name = Path.GetFileName(value.Trim());
            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                name += ".exe";
            }

            if (SafeExecutableRegex().IsMatch(name))
            {
                return name.ToLowerInvariant();
            }
        }

        return null;
    }

    private static string? SafeDriverBasename(string value)
    {
        string name = Path.GetFileName(value.Trim());
        return SafeDriverRegex().IsMatch(name) ? name.ToLowerInvariant() : null;
    }

    private static SafeDriverProvider MapDriverProvider(string? value) => Normalize(value) switch
    {
        "microsoft" or "microsoft corporation" => SafeDriverProvider.Microsoft,
        "nvidia" or "nvidia corporation" => SafeDriverProvider.Nvidia,
        "amd" or "advanced micro devices" or "advanced micro devices, inc." => SafeDriverProvider.Amd,
        "intel" or "intel corporation" => SafeDriverProvider.Intel,
        "realtek" or "realtek semiconductor corp." or "realtek semiconductor corp" => SafeDriverProvider.Realtek,
        "broadcom" or "broadcom inc." => SafeDriverProvider.Broadcom,
        "qualcomm" or "qualcomm technologies, inc." => SafeDriverProvider.Qualcomm,
        "marvell" or "marvell semiconductor, inc." => SafeDriverProvider.Marvell,
        "mediatek" or "mediatek, inc." => SafeDriverProvider.MediaTek,
        "logitech" or "logitech, inc." => SafeDriverProvider.Logitech,
        "corsair" or "corsair memory, inc." => SafeDriverProvider.Corsair,
        "steelseries" or "steelseries aps" => SafeDriverProvider.SteelSeries,
        "asus" or "asustek computer inc." => SafeDriverProvider.Asus,
        "gigabyte" or "gigabyte technology co., ltd." => SafeDriverProvider.Gigabyte,
        "msi" or "micro-star international co., ltd." => SafeDriverProvider.Msi,
        _ => SafeDriverProvider.Unknown
    };

    private static SafeDriverDeviceClass MapDriverClass(string? value) => Normalize(value) switch
    {
        "display" => SafeDriverDeviceClass.Display,
        "hdc" => SafeDriverDeviceClass.Hdc,
        "scsiadapter" or "scsi adapter" => SafeDriverDeviceClass.ScsiAdapter,
        "net" or "network" => SafeDriverDeviceClass.Net,
        "media" => SafeDriverDeviceClass.Media,
        "system" => SafeDriverDeviceClass.System,
        "processor" => SafeDriverDeviceClass.Processor,
        "memory" => SafeDriverDeviceClass.Memory,
        "usb" => SafeDriverDeviceClass.Usb,
        "bluetooth" => SafeDriverDeviceClass.Bluetooth,
        _ => SafeDriverDeviceClass.Unknown
    };

    private static string? SafeDriverVersion(string? value)
    {
        string normalized = value?.Trim() ?? string.Empty;
        return DriverVersionRegex().IsMatch(normalized) ? normalized : null;
    }

    private static string? SafeInfBasename(string? value)
    {
        string basename = Path.GetFileName(value?.Trim() ?? string.Empty);
        return SafeOemInfRegex().IsMatch(basename) ? basename.ToLowerInvariant() : null;
    }

    private static string? SafeModuleBasename(string? value)
    {
        string name = Path.GetFileName(value?.Trim() ?? string.Empty);
        return SafeModuleRegex().IsMatch(name) ? name.ToLowerInvariant() : null;
    }

    private static string? SafeProcessBasename(string? value)
    {
        string name = Path.GetFileName(value?.Trim() ?? string.Empty);
        return SafeProcessRegex().IsMatch(name) ? name.ToLowerInvariant() : null;
    }

    private static string? SafeDebuggerToken(string? value)
    {
        string normalized = value?.Trim() ?? string.Empty;
        if (!SafeDebuggerTokenRegex().IsMatch(normalized) ||
            GuidRegex().IsMatch(normalized) || SidRegex().IsMatch(normalized) ||
            IpAddressRegex().IsMatch(normalized) || MacAddressRegex().IsMatch(normalized))
        {
            return null;
        }

        return normalized;
    }

    private static bool IsSafeLabel(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength ||
            value.Any(character => char.IsControl(character) || IsBidiControl(character)) ||
            value.IndexOfAny(['\\', '/', '@', '<', '>', '|']) >= 0)
        {
            return false;
        }

        string normalized = value.Trim();
        return !GuidRegex().IsMatch(normalized) &&
               !SidRegex().IsMatch(normalized) &&
               !IpAddressRegex().IsMatch(normalized) &&
               !MacAddressRegex().IsMatch(normalized) &&
               !EmailRegex().IsMatch(normalized) &&
               !WindowsPathRegex().IsMatch(normalized);
    }

    private static string CollapseWhitespace(string value) =>
        WhitespaceRegex().Replace(value.Trim(), " ");

    private static DateTimeOffset? RoundToMinute(DateTimeOffset? value)
    {
        if (!value.HasValue)
        {
            return null;
        }

        DateTimeOffset utc = value.Value.ToUniversalTime();
        long ticks = utc.Ticks - utc.Ticks % TimeSpan.TicksPerMinute;
        return new DateTimeOffset(ticks, TimeSpan.Zero);
    }

    private static IReadOnlyList<ulong?> NormalizeParameters(IReadOnlyList<ulong?>? parameters)
    {
        var result = new ulong?[4];
        for (int index = 0; index < result.Length && index < (parameters?.Count ?? 0); index++)
        {
            result[index] = parameters![index];
        }

        return result;
    }

    private static T DefinedOr<T>(T value, T fallback) where T : struct, Enum =>
        Enum.IsDefined(value) ? value : fallback;

    private static SafeSizeBucket Bucket(long? value) => value.HasValue ? Bucket(value.Value) : SafeSizeBucket.Unknown;

    private static SafeSizeBucket Bucket(long value) => value switch
    {
        < 0 => SafeSizeBucket.Unknown,
        0 => SafeSizeBucket.Empty,
        < 1L * 1024 * 1024 => SafeSizeBucket.UnderOneMiB,
        < 16L * 1024 * 1024 => SafeSizeBucket.OneToSixteenMiB,
        < 256L * 1024 * 1024 => SafeSizeBucket.SixteenToTwoHundredFiftySixMiB,
        < 1L * 1024 * 1024 * 1024 => SafeSizeBucket.TwoHundredFiftySixMiBToOneGiB,
        < 8L * 1024 * 1024 * 1024 => SafeSizeBucket.OneToEightGiB,
        < 32L * 1024 * 1024 * 1024 => SafeSizeBucket.EightToThirtyTwoGiB,
        _ => SafeSizeBucket.OverThirtyTwoGiB
    };

    private static SafeStorageMediaType MapMedia(string? value) => Normalize(value) switch
    {
        "hdd" or "hard disk drive" => SafeStorageMediaType.Hdd,
        "ssd" or "solid state drive" => SafeStorageMediaType.Ssd,
        "scm" or "storage class memory" => SafeStorageMediaType.Scm,
        _ => SafeStorageMediaType.Unknown
    };

    private static SafeStorageBusType MapBus(string? value) => Normalize(value) switch
    {
        "ata" => SafeStorageBusType.Ata,
        "sata" => SafeStorageBusType.Sata,
        "sas" => SafeStorageBusType.Sas,
        "nvme" => SafeStorageBusType.Nvme,
        "usb" => SafeStorageBusType.Usb,
        "sd" => SafeStorageBusType.Sd,
        "mmc" => SafeStorageBusType.Mmc,
        "virtual" or "file backed virtual" => SafeStorageBusType.Virtual,
        "raid" => SafeStorageBusType.Raid,
        "storage spaces" => SafeStorageBusType.StorageSpaces,
        _ => SafeStorageBusType.Unknown
    };

    private static SafeStorageHealth MapHealth(string? value) => Normalize(value) switch
    {
        "healthy" => SafeStorageHealth.Healthy,
        "warning" => SafeStorageHealth.Warning,
        "unhealthy" => SafeStorageHealth.Unhealthy,
        _ => SafeStorageHealth.Unknown
    };

    private static SafeRecentChangeResult MapChangeResult(string? value) => Normalize(value) switch
    {
        "succeeded" or "success" or "successful" => SafeRecentChangeResult.Succeeded,
        "succeeded with errors" => SafeRecentChangeResult.SucceededWithErrors,
        "failed" or "failure" => SafeRecentChangeResult.Failed,
        "in progress" => SafeRecentChangeResult.InProgress,
        _ => SafeRecentChangeResult.Unknown
    };

    private static SafeSymbolStatus MapSymbolStatus(string? value)
    {
        string normalized = Normalize(value);
        if (normalized is "loaded" or "symbols loaded" or "full") return SafeSymbolStatus.Loaded;
        if (normalized.Contains("partial", StringComparison.Ordinal)) return SafeSymbolStatus.Partial;
        if (normalized.Contains("missing", StringComparison.Ordinal) || normalized.Contains("not found", StringComparison.Ordinal)) return SafeSymbolStatus.Missing;
        if (normalized.Contains("deferred", StringComparison.Ordinal)) return SafeSymbolStatus.Deferred;
        if (normalized.Contains("error", StringComparison.Ordinal) || normalized.Contains("failed", StringComparison.Ordinal)) return SafeSymbolStatus.Error;
        return SafeSymbolStatus.Unknown;
    }

    private static SafeCoverageSource MapCoverageSource(string? value)
    {
        string source = value?.Trim() ?? string.Empty;
        if (source.StartsWith("Windows Event Log/System", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.SystemEvents;
        if (source.StartsWith("Windows Event Log/Application", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.ApplicationEvents;
        if (source.Contains("Kernel-EventTracing", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.KernelEventTracing;
        if (source.StartsWith("Reliability Monitor", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.ReliabilityHistory;
        if (source.StartsWith("Crash artifact", StringComparison.OrdinalIgnoreCase) || source.StartsWith("Artifact", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.CrashArtifacts;
        if (source.StartsWith("Crash readiness", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.CrashReadiness;
        if (source.StartsWith("Dump inventory", StringComparison.OrdinalIgnoreCase) || source.StartsWith("Dump quality", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.DumpInventory;
        if (source.StartsWith("Driver inventory", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.DriverInventory;
        if (source.StartsWith("Recent changes/Windows Update", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.WindowsUpdateHistory;
        if (source.StartsWith("Recent changes/SetupAPI", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.DriverInstallHistory;
        if (source.StartsWith("Storage health", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.StorageHealth;
        if (source.StartsWith("Driver Verifier", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.DriverVerifier;
        if (source.StartsWith("System snapshot", StringComparison.OrdinalIgnoreCase)) return SafeCoverageSource.SystemSnapshot;
        return SafeCoverageSource.Unknown;
    }

    private static uint? ParseUInt32(string? value)
    {
        string normalized = value?.Trim() ?? string.Empty;
        NumberStyles styles = NumberStyles.Integer;
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
            styles = NumberStyles.AllowHexSpecifier;
        }

        return uint.TryParse(normalized, styles, CultureInfo.InvariantCulture, out uint result) ? result : null;
    }

    private static byte? ClampTemperature(byte? value) => value is <= 125 ? value : null;
    private static bool Positive(ulong? value) => value.GetValueOrDefault() > 0;
    private static bool Above(ulong? value, ulong threshold) => value.GetValueOrDefault() > threshold;
    private static string Normalize(string? value) => value?.Trim().ToLowerInvariant() ?? string.Empty;
    private static bool Is(string value, params string[] expected) => expected.Contains(value, StringComparer.OrdinalIgnoreCase);

    private static void Add<TKey>(IDictionary<TKey, int> counts, TKey key, int increment) where TKey : notnull
    {
        counts.TryGetValue(key, out int current);
        counts[key] = current > int.MaxValue - increment ? int.MaxValue : current + increment;
    }

    private static Dictionary<TKey, int> MergeDerivedCounts<TKey>(
        IReadOnlyDictionary<TKey, int> events,
        IReadOnlyDictionary<TKey, int> groups)
        where TKey : notnull
    {
        var result = events.ToDictionary(item => item.Key, item => item.Value);
        foreach ((TKey key, int count) in groups)
        {
            result.TryGetValue(key, out int eventCount);
            result[key] = Math.Max(eventCount, count);
        }

        return result;
    }

    private static bool IsBidiControl(char value) => value is '\u061c' or '\u200e' or '\u200f' or
        >= '\u202a' and <= '\u202e' or >= '\u2066' and <= '\u2069';

    [GeneratedRegex("^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeVersionRegex();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+ -]{0,63}\\.exe$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SafeExecutableRegex();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\\.(?:sys|dll)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SafeDriverRegex();

    [GeneratedRegex("^\\d{1,5}(?:\\.\\d{1,10}){1,5}$", RegexOptions.CultureInvariant)]
    private static partial Regex DriverVersionRegex();

    [GeneratedRegex("^oem\\d{1,6}\\.inf$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SafeOemInfRegex();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\\.(?:sys|dll|exe)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SafeModuleRegex();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+ -]{0,63}\\.exe$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SafeProcessRegex();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_.!+\\-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeDebuggerTokenRegex();

    [GeneratedRegex("\\bKB[ -]?(\\d{6,8})\\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex KbReferenceRegex();

    [GeneratedRegex("\\boem\\d{1,6}\\.inf\\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex InfReferenceRegex();

    [GeneratedRegex("\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex GuidRegex();

    [GeneratedRegex("\\bS-1-(?:\\d+-){1,14}\\d+\\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SidRegex();

    [GeneratedRegex("(?<!\\d)(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}(?!\\d)", RegexOptions.CultureInvariant)]
    private static partial Regex IpAddressRegex();

    [GeneratedRegex("\\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex MacAddressRegex();

    [GeneratedRegex("\\b[^\\s@]+@[^\\s@]+\\.[^\\s@]+\\b", RegexOptions.CultureInvariant)]
    private static partial Regex EmailRegex();

    [GeneratedRegex("(?:[A-Za-z]:\\\\|\\\\\\\\)", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsPathRegex();

    [GeneratedRegex("\\s+", RegexOptions.CultureInvariant)]
    private static partial Regex WhitespaceRegex();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+() -]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex BoardProductRegex();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex BiosVersionRegex();

    [GeneratedRegex("^\\d{1,2}(?:st|nd|rd|th) Gen Intel\\(R\\) Core\\(TM\\) ", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex IntelGenerationCpuRegex();
}
