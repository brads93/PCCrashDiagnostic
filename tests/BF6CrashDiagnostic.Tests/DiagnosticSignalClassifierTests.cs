using BF6CrashDiagnostic.Core.Analysis;

namespace BF6CrashDiagnostic.Tests;

public sealed class DiagnosticSignalClassifierTests
{
    [Theory]
    [InlineData("PCCrashDiagnostic.exe")]
    [InlineData("AppCrash_PCCrashDiagnost_a1b2c3")]
    [InlineData(@"C:\Program Files\PCCrashDiagnostic\PCCrashDiagnostic.exe")]
    [InlineData("PC Crash Diagnostic")]
    [InlineData("BF6CrashDiagnostic.exe")]
    [InlineData("AppCrash_BF6CrashDiagnost_7f8a9b")]
    [InlineData(@"C:\work\bf6-crash-diagnostic-dotnet\BF6CrashDiagnostic.exe")]
    [InlineData("Unofficial BF6 Crash Diagnostic")]
    public void IsDiagnosticToolSelfSignal_RecognizesOwnExecutableAndWerNames(string value)
    {
        Assert.True(DiagnosticSignalClassifier.IsDiagnosticToolSelfSignal(value));
    }

    [Theory]
    [InlineData("BF6.exe")]
    [InlineData("Battlefield 6")]
    [InlineData("EAAntiCheat.GameService.exe")]
    [InlineData("AppCrash_BF6.exe_1234")]
    public void IsDiagnosticToolSelfSignal_DoesNotRejectGameOrEaNames(string value)
    {
        Assert.False(DiagnosticSignalClassifier.IsDiagnosticToolSelfSignal(value));
    }
}
