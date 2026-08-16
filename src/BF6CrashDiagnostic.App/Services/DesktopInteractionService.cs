using System.Diagnostics;
using System.IO;
using System.Windows;
using BF6CrashDiagnostic.App.Models;
using Microsoft.Win32;

namespace BF6CrashDiagnostic.App.Services;

internal sealed class DesktopInteractionService : IUserInteractionService
{
    public void CopyText(string text) => Clipboard.SetText(text);

    public string? ChooseExecutablePath()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose an application",
            Filter = "Applications (*.exe)|*.exe",
            CheckFileExists = true,
            Multiselect = false
        };
        return dialog.ShowDialog(Application.Current.MainWindow) == true ? dialog.FileName : null;
    }

    public IReadOnlyList<UiRunningProcess> GetRunningProcesses()
    {
        var processes = new List<UiRunningProcess>();
        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.Id == Environment.ProcessId || process.HasExited)
                    {
                        continue;
                    }

                    string name = process.ProcessName;
                    if (string.IsNullOrWhiteSpace(name) ||
                        name.Equals("Idle", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("System", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string title = process.MainWindowTitle;
                    string display = string.IsNullOrWhiteSpace(title)
                        ? $"{name}.exe · PID {process.Id}"
                        : $"{title} · {name}.exe · PID {process.Id}";
                    processes.Add(new UiRunningProcess(process.Id, name, display));
                }
                catch (InvalidOperationException)
                {
                    // The process exited while the list was being read.
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Windows denied details for this process; omit it from the picker.
                }
            }
        }

        return processes
            .GroupBy(item => item.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderByDescending(item => item.DisplayText.Length)
                .ThenBy(item => item.ProcessId)
                .First())
            .OrderBy(item => item.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public string? ChooseExportPath(string sourcePath)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export diagnostic report",
            FileName = Path.GetFileName(sourcePath),
            DefaultExt = ".zip",
            Filter = "ZIP report (*.zip)|*.zip",
            AddExtension = true,
            OverwritePrompt = true
        };
        return dialog.ShowDialog(Application.Current.MainWindow) == true ? dialog.FileName : null;
    }

    public void OpenFolder(string folderPath)
    {
        if (!Directory.Exists(folderPath))
        {
            throw new DirectoryNotFoundException("The report folder is no longer available.");
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            ArgumentList = { folderPath },
            UseShellExecute = true
        });
    }

    public bool ConfirmDumpPackaging()
    {
        const string message =
            "Crash dumps can contain personal or account data. The app stores the dump locally in a separate ZIP and does not upload it.\n\n" +
            "Create the ZIP only if someone you trust needs it.";

        return MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Create a crash dump ZIP?",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    public UiProtectedDumpConsent? ConfirmProtectedDumpCopy(UiDumpChoice dump, string operationName)
    {
        string message =
            $"Windows administrator access is needed to {operationName} {dump.Name} ({dump.Size}).\n\n" +
            "If you continue, PC Crash Diagnostic will:\n" +
            "• ask for UAC approval;\n" +
            "• confirm the selected file and available free space;\n" +
            "• make a private local staging copy, which can contain personal or account data; and\n" +
            "• delete that copy when the operation finishes or is cancelled.\n\n" +
            "Nothing is uploaded. Continue?";
        bool confirmed = MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Use administrator access?",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
        return confirmed ? new UiProtectedDumpConsent(true, true, true) : null;
    }

    public bool ConfirmProtectedEvidenceRetry(UiProtectedEvidenceSourceChoice source)
    {
        string message =
            $"Retry {source.DisplayName} with administrator access?\n\n" +
            "PC Crash Diagnostic will read only the allowlisted records or dump metadata from this report's time window, add the privacy-filtered results to a refreshed local report, and then exit the helper. It will not change Windows settings, include dump contents, or upload anything.";
        return MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Retry with administrator access?",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    public bool ConfirmLegacyReportImport(int reportCount)
    {
        string message = $"Found {reportCount} report{(reportCount == 1 ? string.Empty : "s")} from BF6 Crash Diagnostic v2.\n\n" +
            "Import validated copies into the PC Crash Diagnostic history? The original reports will not be changed or deleted.";
        return MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Import earlier reports?",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.Yes) == MessageBoxResult.Yes;
    }

    public bool ConfirmMicrosoftSymbolDownload()
    {
        const string message =
            "Retry WinDbg using Microsoft's public symbol server?\n\n" +
            "The crash dump stays on this PC. WinDbg may download symbol files from Microsoft into a private local cache.";
        return MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Download Microsoft symbols and retry?",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    public bool ConfirmCrashPreparation(UiCrashPreparationPreview preview)
    {
        ArgumentNullException.ThrowIfNull(preview);
        var window = new CrashPreparationWindow(preview)
        {
            Owner = Application.Current.MainWindow
        };
        return window.ShowDialog() == true;
    }

    public bool ConfirmCrashPreparationRestore()
    {
        const string message =
            "Restore the Windows crash-capture settings saved before the last preparation?\n\n" +
            "PC Crash Diagnostic will ask for administrator approval, restore only those saved settings, and then check the result.";
        return MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Restore earlier crash-capture settings?",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    public bool ConfirmPerAppCrashCaptureRestore(string targetName)
    {
        string message =
            $"Restore the app crash-dump settings that existed for {targetName} before PC Crash Diagnostic enabled full dumps?\n\n" +
            "Windows will ask for administrator approval. Existing dump files will not be deleted.";
        return MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Restore earlier app crash-dump settings?",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    public bool ConfirmOrdinaryAppForCrashCapture(string targetName)
    {
        string message =
            $"Is {targetName} an ordinary app without anti-cheat or other process protection?\n\n" +
            "Do not enable this for Battlefield 6, another anti-cheat game, security software, or a protected system process. " +
            $"Open {targetName} normally and leave it running until setup finishes. You do not need to use it or make it crash. " +
            "Disable capture before later running an executable with the same name as administrator.";
        return MessageBox.Show(
            Application.Current.MainWindow,
            message,
            "Confirm ordinary app",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    public void ShowMessage(string title, string message, bool isError = false) =>
        MessageBox.Show(
            Application.Current.MainWindow,
            message,
            title,
            MessageBoxButton.OK,
            isError ? MessageBoxImage.Error : MessageBoxImage.Information);
}
