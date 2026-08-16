using BF6CrashDiagnostic.Core;
using PCCrashDiagnostic.Contracts;

namespace BF6CrashDiagnostic.Tests;

public sealed class ReleaseStageTests
{
    [Fact]
    public void CompileTimeProfileMatchesToolVersionAndFeatureSurface()
    {
#if PCD_SHARE_READ_ONLY
        Assert.Equal(ProductFeatureProfile.ShareReadOnly, BuildProfile.Current.Profile);
        Assert.False(BuildProfile.Current.HasAnyPrivilegedCapability);
#elif PCD_WER_RESEARCH
        Assert.Equal(ProductFeatureProfile.WerResearch, BuildProfile.Current.Profile);
        Assert.True(BuildProfile.Current.WerLocalDumps);
#elif PCD_FULL_DIAGNOSTIC
        Assert.Equal(ProductFeatureProfile.FullDiagnostic, BuildProfile.Current.Profile);
        Assert.True(BuildProfile.Current.HasAnyPrivilegedCapability);
#endif
        Assert.Equal("3.2.0-beta.1", ReleaseStage.Version);
        Assert.True(ReleaseStage.Beta2FeaturesEnabled);
        Assert.Equal(ReleaseStage.Version, PCCrashDiagnosticCoordinator.ToolVersion);
        Assert.Equal(BuildProfile.Current.WerLocalDumps, ReleaseStage.WerLocalDumpCaptureEnabled);
    }
}
