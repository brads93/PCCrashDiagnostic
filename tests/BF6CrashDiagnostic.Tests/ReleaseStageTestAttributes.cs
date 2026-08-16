using BF6CrashDiagnostic.Core;

namespace BF6CrashDiagnostic.Tests;

/// <summary>
/// Marks behavior that is intentionally dormant in the beta.1 binary. Release
/// builds compile the tests with the same stage symbol as the packaged app, so
/// beta.1 reports these tests as skipped instead of claiming beta.2 coverage.
/// </summary>
internal sealed class Beta2FactAttribute : FactAttribute
{
    public Beta2FactAttribute()
    {
        if (!ReleaseStage.Beta2FeaturesEnabled)
        {
            Skip = "Available beginning with PC Crash Diagnostic 3.1.0-beta.2.";
        }
    }
}

internal sealed class Beta2TheoryAttribute : TheoryAttribute
{
    public Beta2TheoryAttribute()
    {
        if (!ReleaseStage.Beta2FeaturesEnabled)
        {
            Skip = "Available beginning with PC Crash Diagnostic 3.1.0-beta.2.";
        }
    }
}

internal sealed class WerLocalDumpCaptureFactAttribute : FactAttribute
{
    public WerLocalDumpCaptureFactAttribute()
    {
        if (!ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            Skip = "Requires a build compiled with PCD_WER_LOCAL_DUMPS.";
        }
    }
}

internal sealed class WerLocalDumpCaptureTheoryAttribute : TheoryAttribute
{
    public WerLocalDumpCaptureTheoryAttribute()
    {
        if (!ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            Skip = "Requires a build compiled with PCD_WER_LOCAL_DUMPS.";
        }
    }
}
