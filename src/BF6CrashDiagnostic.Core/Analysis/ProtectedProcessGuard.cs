using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Shared fail-closed boundary for operations that must not inspect dumps or
/// launch local debugger tools while protected game processes are running.
/// </summary>
public static class ProtectedProcessGuard
{
    public static IReadOnlyList<string> AlwaysProtectedProcessNames { get; } =
    [
        "BF6",
        "EAAntiCheat",
        "EAAntiCheat.GameService",
        "EAAntiCheat.GameServiceLauncher",
        "EAAntiCheatService",
        "Javelin"
    ];

    public static bool IsBlocked(TargetProfile? targetProfile, Func<string, bool> isProcessRunning)
    {
        ArgumentNullException.ThrowIfNull(isProcessRunning);
        try
        {
            IEnumerable<string> names = AlwaysProtectedProcessNames;
            if (targetProfile is { BlockSensitiveOperationsWhileRunning: true })
            {
                names = names
                    .Concat(targetProfile.ProcessNames)
                    .Concat(targetProfile.RelatedProcessNames);
            }

            return names
                .Select(NormalizeProcessName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Any(isProcessRunning);
        }
        catch
        {
            return true;
        }
    }

    public static string NormalizeProcessName(string processName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processName);
        string name = Path.GetFileName(processName.Trim());
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? name[..^4]
            : name;
    }
}
