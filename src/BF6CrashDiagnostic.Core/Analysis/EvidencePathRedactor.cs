namespace BF6CrashDiagnostic.Core.Analysis;

internal static class EvidencePathRedactor
{
    public static string? Redact(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        string trimmed = path.Trim().Trim('"');
        try
        {
            string fullPath = Environment.ExpandEnvironmentVariables(trimmed);
            foreach ((string Token, string Root) root in Roots()
                         .Where(item => !string.IsNullOrWhiteSpace(item.Root))
                         .OrderByDescending(item => item.Root.Length))
            {
                string normalizedRoot = Path.GetFullPath(root.Root)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string normalizedPath = Path.GetFullPath(fullPath);
                if (normalizedPath.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase))
                {
                    return root.Token;
                }

                string prefix = normalizedRoot + Path.DirectorySeparatorChar;
                if (normalizedPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return root.Token + Path.DirectorySeparatorChar + normalizedPath[prefix.Length..];
                }
            }

            string fileName = Path.GetFileName(fullPath);
            return string.IsNullOrWhiteSpace(fileName) ? "<custom path>" : "<custom path>" + Path.DirectorySeparatorChar + fileName;
        }
        catch (ArgumentException)
        {
            return "<invalid path>";
        }
        catch (NotSupportedException)
        {
            return "<invalid path>";
        }
        catch (IOException)
        {
            return "<invalid path>";
        }
        catch (System.Security.SecurityException)
        {
            return "<invalid path>";
        }
    }

    public static string? FileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            string fileName = Path.GetFileName(path.Trim().Trim('"'));
            return string.IsNullOrWhiteSpace(fileName) ? null : fileName;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    private static IEnumerable<(string Token, string Root)> Roots()
    {
        yield return ("%LocalAppData%", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        yield return ("%ProgramData%", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        yield return ("%SystemRoot%", Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        yield return ("%UserProfile%", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

        string systemDirectory = Environment.SystemDirectory;
        string? systemDrive = string.IsNullOrWhiteSpace(systemDirectory) ? null : Path.GetPathRoot(systemDirectory);
        if (!string.IsNullOrWhiteSpace(systemDrive))
        {
            yield return ("%SystemDrive%", systemDrive);
        }
    }
}
