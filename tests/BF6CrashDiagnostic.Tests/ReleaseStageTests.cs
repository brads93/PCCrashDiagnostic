using BF6CrashDiagnostic.Core;

namespace BF6CrashDiagnostic.Tests;

public sealed class ReleaseStageTests
{
    [Fact]
    public void CompileTimeStageMatchesToolVersionAndFeatureSurface()
    {
#if PCD_BETA1
        Assert.Equal("3.1.0-beta.1", ReleaseStage.Version);
        Assert.False(ReleaseStage.Beta2FeaturesEnabled);
#else
        Assert.Equal("3.1.0-beta.2", ReleaseStage.Version);
        Assert.True(ReleaseStage.Beta2FeaturesEnabled);
#endif
        Assert.Equal(ReleaseStage.Version, PCCrashDiagnosticCoordinator.ToolVersion);
#if PCD_WER_LOCAL_DUMPS
        Assert.True(ReleaseStage.WerLocalDumpCaptureEnabled);
#else
        Assert.False(ReleaseStage.WerLocalDumpCaptureEnabled);
#endif
    }
}
