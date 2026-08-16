using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Sharing;

internal sealed record ValidatedExportDestination(
    string FullPath,
    string ParentDirectory,
    LocalFileIdentity ParentIdentity,
    SafeExportDestinationAssessment Assessment);

internal static class SafeExportPathValidator
{
    public static ValidatedExportDestination ValidateNewTextFile(string destinationPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        if (!Path.IsPathFullyQualified(destinationPath))
        {
            throw new ArgumentException("Choose an absolute local destination path.", nameof(destinationPath));
        }

        string fullPath = Path.GetFullPath(destinationPath);
        if (fullPath.StartsWith("\\\\", StringComparison.Ordinal) ||
            fullPath.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            fullPath.StartsWith("\\\\.\\", StringComparison.Ordinal))
        {
            throw new IOException("Safe Summary export requires a local filesystem destination.");
        }

        if (!Path.GetExtension(fullPath).Equals(".txt", StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("Safe Summary export creates a .txt file.");
        }

        string? fileName = Path.GetFileName(fullPath);
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Length > 120)
        {
            throw new IOException("The Safe Summary filename is invalid or too long.");
        }

        string parent = Path.GetDirectoryName(fullPath)
            ?? throw new IOException("The Safe Summary destination has no parent directory.");
        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException("Create the destination folder before exporting the Safe Summary.");
        }

        EnsureLocalDrive(parent);
        PathSafety.EnsureNoReparseComponents(parent);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new IOException("The Safe Summary destination already exists. Choose a new filename.");
        }

        LocalFileIdentity parentIdentity = WindowsFileIdentity.Capture(parent);
        if (!parentIdentity.IsDirectory || parentIdentity.IsReparsePoint)
        {
            throw new IOException("The Safe Summary destination folder is not a regular local directory.");
        }

        return new ValidatedExportDestination(
            fullPath,
            parent,
            parentIdentity,
            SafeExportDestinationClassifier.Classify(parent));
    }

    public static void VerifyUnchanged(ValidatedExportDestination destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        PathSafety.EnsureNoReparseComponents(destination.ParentDirectory);
        LocalFileIdentity current = WindowsFileIdentity.Capture(destination.ParentDirectory);
        if (current.VolumeSerialNumber != destination.ParentIdentity.VolumeSerialNumber ||
            current.FileIndex != destination.ParentIdentity.FileIndex ||
            !current.IsDirectory || current.IsReparsePoint)
        {
            throw new IOException("The Safe Summary destination folder changed during export.");
        }

        if (File.Exists(destination.FullPath) || Directory.Exists(destination.FullPath))
        {
            throw new IOException("The Safe Summary destination was created by another process.");
        }
    }

    private static void EnsureLocalDrive(string path)
    {
        string root = Path.GetPathRoot(path) ?? throw new IOException("The destination has no filesystem root.");
        var drive = new DriveInfo(root);
        if (drive.DriveType is DriveType.Network or DriveType.CDRom or DriveType.NoRootDirectory)
        {
            throw new IOException("Safe Summary export requires a writable local filesystem destination.");
        }
    }
}
