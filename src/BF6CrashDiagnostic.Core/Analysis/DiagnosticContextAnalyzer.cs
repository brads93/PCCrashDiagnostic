using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public static class DiagnosticContextAnalyzer
{
    public static DiagnosticFinding? CreatePreviewBuildFinding(
        SystemSnapshot? startSnapshot,
        SystemSnapshot? endSnapshot)
    {
        SystemSnapshot? snapshot = endSnapshot is { PreviewBuildDetected: true }
            ? endSnapshot
            : startSnapshot is { PreviewBuildDetected: true }
                ? startSnapshot
                : null;
        if (snapshot is null)
        {
            return null;
        }

        string channel = string.IsNullOrWhiteSpace(snapshot.WindowsChannel)
            ? "channel unavailable"
            : snapshot.WindowsChannel;
        return new DiagnosticFinding(
            "windows-preview-build",
            85,
            FindingSeverity.Context,
            FindingConfidence.High,
            "Windows",
            "Windows preview build detected",
            $"The Windows snapshot reports build {snapshot.WindowsBuild} on {channel} as a preview build.",
            "Preview-build status is useful version context when comparing incidents across Windows builds.",
            "Preview-build status does not establish that Windows caused the crash.",
            "Keep the exact Windows build and channel with this report when comparing another incident.");
    }
}
