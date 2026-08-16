namespace PCCrashDiagnostic.Contracts;

public enum ProductFeatureProfile
{
    ShareReadOnly,
    FullDiagnostic,
    WerResearch
}

public sealed record ProductCapabilities(
    ProductFeatureProfile Profile,
    bool StandardEvidence,
    bool TargetMonitoring,
    bool CrashReadinessReadOnly,
    bool AccessibleDumpMetadata,
    bool LocalHistory,
    bool SafeSummaryExport,
    bool TechnicalReportExport,
    bool RecycleBinDeletion,
    bool DumpChk,
    bool WinDbg,
    bool MicrosoftSymbolsAfterConsent,
    bool ElevatedHelper,
    bool SettingsApply,
    bool SettingsRestore,
    bool WerLocalDumps,
    bool ProtectedEvidence,
    bool ProtectedDumpStaging,
    bool DumpPackaging)
{
    public bool HasAnyPrivilegedCapability =>
        ElevatedHelper || SettingsApply || SettingsRestore || WerLocalDumps ||
        ProtectedEvidence || ProtectedDumpStaging || DumpPackaging;
}

public static class BuildProfile
{
    public const string Version = "3.2.0-beta.1";

    public static ProductCapabilities Current { get; } = CreateCurrent();

    private static ProductCapabilities CreateCurrent()
    {
#if PCD_SHARE_READ_ONLY
        ProductCapabilities capabilities = Create(ProductFeatureProfile.ShareReadOnly, privileged: false, wer: false);
#elif PCD_WER_RESEARCH
        ProductCapabilities capabilities = Create(ProductFeatureProfile.WerResearch, privileged: true, wer: true);
#elif PCD_FULL_DIAGNOSTIC
        ProductCapabilities capabilities = Create(ProductFeatureProfile.FullDiagnostic, privileged: true, wer: false);
#else
#error Exactly one PC Crash Diagnostic feature profile must be compiled.
#endif

        Validate(capabilities);
        return capabilities;
    }

    private static ProductCapabilities Create(ProductFeatureProfile profile, bool privileged, bool wer) => new(
        profile,
        StandardEvidence: true,
        TargetMonitoring: true,
        CrashReadinessReadOnly: true,
        AccessibleDumpMetadata: true,
        LocalHistory: true,
        SafeSummaryExport: true,
        TechnicalReportExport: true,
        RecycleBinDeletion: true,
        DumpChk: true,
        WinDbg: true,
        MicrosoftSymbolsAfterConsent: true,
        ElevatedHelper: privileged,
        SettingsApply: privileged,
        SettingsRestore: privileged,
        WerLocalDumps: wer,
        ProtectedEvidence: privileged,
        ProtectedDumpStaging: privileged,
        DumpPackaging: privileged);

    private static void Validate(ProductCapabilities capabilities)
    {
        if (capabilities.Profile == ProductFeatureProfile.ShareReadOnly && capabilities.HasAnyPrivilegedCapability)
        {
            throw new InvalidOperationException("The ShareReadOnly profile cannot contain privileged capabilities.");
        }

        if (capabilities.WerLocalDumps && capabilities.Profile != ProductFeatureProfile.WerResearch)
        {
            throw new InvalidOperationException("WER LocalDumps are restricted to the WerResearch profile.");
        }
    }
}
