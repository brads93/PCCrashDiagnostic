namespace BF6CrashDiagnostic.Core;

/// <summary>
/// Compatibility facade for code written before the feature-profile split.
/// New code should consume PCCrashDiagnostic.Contracts.BuildProfile directly.
/// </summary>
public static class ReleaseStage
{
    public const string Version = PCCrashDiagnostic.Contracts.BuildProfile.Version;
    public static bool Beta2FeaturesEnabled => true;
    public static bool WerLocalDumpCaptureEnabled =>
        PCCrashDiagnostic.Contracts.BuildProfile.Current.WerLocalDumps;
    public static bool PrivilegedOperationsEnabled =>
        PCCrashDiagnostic.Contracts.BuildProfile.Current.ElevatedHelper;
}
