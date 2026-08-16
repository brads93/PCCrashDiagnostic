using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using BF6CrashDiagnostic.App.Services;
using BF6CrashDiagnostic.App.ViewModels;
using BF6CrashDiagnostic.Core.Collectors;

namespace BF6CrashDiagnostic.App;

public partial class App : Application
{
    private const string MutexName = "Local\\PCCrashDiagnostic.Singleton.v3";
    private const string ActivationEventName = "Local\\PCCrashDiagnostic.Activate.v3";

    private Mutex? _instanceMutex;
    private EventWaitHandle? _activationEvent;
    private CancellationTokenSource? _activationCancellation;

    protected override async void OnStartup(StartupEventArgs e)
    {
        CommandLineOptions options;
        try
        {
            options = CommandLineOptions.Parse(e.Args);
        }
        catch (ArgumentException exception)
        {
            MessageBox.Show(exception.Message, "Invalid command line", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(2);
            return;
        }

        base.OnStartup(e);

        if (options.VerifyHelperBinding)
        {
            try
            {
                var helperClient = new ElevatedHelperClient();
                var verification = await helperClient
                    .VerifyBindingAsync(CancellationToken.None)
                    .ConfigureAwait(true);
                Shutdown(verification.Succeeded ? 0 : 4);
            }
            catch
            {
                Shutdown(4);
            }

            return;
        }

        if (!options.SmokeTest)
        {
            _activationEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ActivationEventName);
            _instanceMutex = new Mutex(initiallyOwned: true, MutexName, out bool isFirstInstance);
            if (!isFirstInstance)
            {
                _activationEvent.Set();
                _instanceMutex.Dispose();
                _instanceMutex = null;
                _activationEvent.Dispose();
                _activationEvent = null;
                Shutdown(0);
                return;
            }
        }

        var diagnosticService = new CoreDiagnosticService(options.DataRoot);

        if (options.SmokeTest)
        {
            try
            {
                var smokeViewModel = new MainViewModel(diagnosticService, options.DataRoot);
                var smokeWindow = new MainWindow(smokeViewModel);
                var reviewWindow = new ReviewWindow("Smoke-test summary", []);
                await diagnosticService.RunSmokeTestAsync(CancellationToken.None).ConfigureAwait(true);
                reviewWindow.Close();
                smokeWindow.Close();
                Shutdown(0);
            }
            catch (Exception exception)
            {
                try
                {
                    Directory.CreateDirectory(options.DataRoot);
                    File.WriteAllText(Path.Combine(options.DataRoot, "smoke-test-error.txt"), exception.ToString());
                }
                catch
                {
                    // Preserve the original failure code even if the requested test folder is unavailable.
                }
                Shutdown(3);
            }

            return;
        }

        var viewModel = new MainViewModel(diagnosticService, options.DataRoot);
        var window = new MainWindow(viewModel);
        _activationCancellation = new CancellationTokenSource();
        MainWindow = window;
        window.Show();

        StartActivationListener(window, _activationCancellation.Token);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _activationCancellation?.Cancel();
        _activationEvent?.Set();
        _activationEvent?.Dispose();
        _activationCancellation?.Dispose();
        _instanceMutex?.ReleaseMutex();
        _instanceMutex?.Dispose();
        base.OnExit(e);
    }

    private void StartActivationListener(Window window, CancellationToken cancellationToken)
    {
        EventWaitHandle activationEvent = _activationEvent!;
        _ = Task.Run(() =>
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    activationEvent.WaitOne();
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                Dispatcher.BeginInvoke(DispatcherPriority.Normal, () => ActivateWindow(window));
            }
        }, cancellationToken);
    }

    private static void ActivateWindow(Window window)
    {
        if (window.WindowState == WindowState.Minimized)
        {
            window.WindowState = WindowState.Normal;
        }

        window.Show();
        window.Activate();
        window.Topmost = true;
        window.Topmost = false;
        window.Focus();
    }
}
