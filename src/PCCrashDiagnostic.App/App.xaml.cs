using System.Windows;
using PCCrashDiagnostic.Contracts;
using PCCrashDiagnostic.Core;

namespace PCCrashDiagnostic.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Contains("--smoke-test", StringComparer.Ordinal))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            int exitCode = ShareReadOnlySmokeContract.Run(e.Args);
            Shutdown(exitCode);
            return;
        }

        if (e.Args.Length != 0)
        {
            MessageBox.Show(
                "PC Crash Diagnostic does not recognize those command-line options.",
                "PC Crash Diagnostic",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown(2);
            return;
        }

        base.OnStartup(e);
        MainWindow = new MainWindow();
        MainWindow.Show();
    }
}
