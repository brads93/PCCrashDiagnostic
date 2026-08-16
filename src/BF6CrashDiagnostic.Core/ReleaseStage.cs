namespace BF6CrashDiagnostic.Core;

/// <summary>
/// Compile-time release staging. Beta 1 contains the shared implementation but
/// exposes only crash-readiness preparation and rollback. Beta 2 activates the
/// additive per-app capture and broader diagnostic sources.
/// </summary>
public static class ReleaseStage
{
#if PCD_BETA1
    public const string Version = "3.1.0-beta.1";
    public static bool Beta2FeaturesEnabled => false;
#else
    public const string Version = "3.1.0-beta.2";
    public static bool Beta2FeaturesEnabled => true;
#endif

#if PCD_WER_LOCAL_DUMPS
    public static bool WerLocalDumpCaptureEnabled => true;
#else
    public static bool WerLocalDumpCaptureEnabled => false;
#endif
}
