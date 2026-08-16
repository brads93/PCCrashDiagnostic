namespace BF6CrashDiagnostic.Core.Sharing;

internal static class SafeExportDestinationClassifier
{
    public static SafeExportDestinationAssessment Classify(string parentDirectory) =>
        Classify(parentDirectory, syncRoots: null, driveType: null);

    internal static SafeExportDestinationAssessment Classify(
        string parentDirectory,
        IEnumerable<string>? syncRoots,
        DriveType? driveType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(parentDirectory);
        string fullPath = Path.GetFullPath(parentDirectory);
        string root = Path.GetPathRoot(fullPath) ?? throw new IOException("The export destination has no drive root.");
        DriveType actualDriveType = driveType ?? new DriveInfo(root).DriveType;
        bool syncManaged = EnumerateSyncRoots(syncRoots).Any(syncRoot => IsContained(syncRoot, fullPath));
        SafeExportDestinationKind kind = actualDriveType switch
        {
            DriveType.Fixed => SafeExportDestinationKind.LocalFixed,
            DriveType.Removable => SafeExportDestinationKind.Removable,
            _ => SafeExportDestinationKind.OtherLocal
        };
        bool acknowledgement = syncManaged || kind == SafeExportDestinationKind.Removable;
        string warning = (syncManaged, kind == SafeExportDestinationKind.Removable) switch
        {
            (true, true) => "This is removable storage inside a sync-managed folder. Saving here may copy or upload the report outside this PC.",
            (true, false) => "This folder appears to be managed by a sync provider. Saving here may upload the report according to that provider's settings.",
            (false, true) => "This is removable storage. The report can leave this PC with the device.",
            _ => "The report is saved only to the selected local folder; this app does not upload it."
        };
        return new SafeExportDestinationAssessment(kind, syncManaged, acknowledgement, warning);
    }

    private static IEnumerable<string> EnumerateSyncRoots(IEnumerable<string>? supplied)
    {
        if (supplied is not null)
        {
            return supplied.Select(TryNormalizeRoot)
                .Where(value => value is not null)
                .Cast<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        var roots = new List<string>();
        foreach (string variable in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
        {
            string? value = Environment.GetEnvironmentVariable(variable);
            string? normalized = TryNormalizeRoot(value);
            if (normalized is not null)
            {
                roots.Add(normalized);
            }
        }

        string? userProfile = TryNormalizeRoot(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        if (userProfile is not null)
        {
            foreach (string name in new[] { "OneDrive", "Dropbox", "Google Drive", "iCloudDrive" })
            {
                string candidate = Path.Combine(userProfile, name);
                if (Directory.Exists(candidate))
                {
                    roots.Add(Path.GetFullPath(candidate));
                }
            }
        }

        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string? TryNormalizeRoot(string? value)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(value) && Path.IsPathFullyQualified(value)
                ? Path.GetFullPath(value)
                : null;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException)
        {
            return null;
        }
    }

    private static bool IsContained(string root, string candidate)
    {
        string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string fullCandidate = Path.GetFullPath(candidate);
        return string.Equals(fullRoot, fullCandidate, StringComparison.OrdinalIgnoreCase) ||
               fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
