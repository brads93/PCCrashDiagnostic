using System.Runtime.ExceptionServices;
using System.Reflection;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;

namespace PCCrashDiagnostic.Share.Tests;

public sealed class PublicWpfContractTests
{
    [Fact]
    public void StartScreenHasShareIdentityAccessibleNamesAndScaledMinimums()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var application = new PCCrashDiagnostic.App.App
                {
                    ShutdownMode = ShutdownMode.OnExplicitShutdown
                };
                application.InitializeComponent();
                var window = new PCCrashDiagnostic.App.MainWindow();
                try
                {
                    window.Show();
                    window.Activate();
                    window.UpdateLayout();
                    Assert.True(window.MinWidth <= 640);
                    Assert.True(window.MinHeight <= 480);
                    Assert.InRange(window.ActualWidth, 1, SystemParameters.WorkArea.Width);
                    Assert.InRange(window.ActualHeight, 1, SystemParameters.WorkArea.Height);
                    Assert.Contains("3.2.0-beta.1", ((TextBlock)window.FindName("BuildIdentityText")).Text, StringComparison.Ordinal);
                    Assert.Contains("ShareReadOnly", ((TextBlock)window.FindName("BuildIdentityText")).Text, StringComparison.Ordinal);
                    Assert.Equal("PC Crash Diagnostic does not upload", ((TextBlock)window.FindName("UploadStatementText")).Text);

                    foreach (string name in new[] { "BlueScreenButton", "AppClosedButton", "MonitorButton", "OpenReportButton" })
                    {
                        var button = Assert.IsType<Button>(window.FindName(name));
                        Assert.False(string.IsNullOrWhiteSpace(AutomationProperties.GetName(button)));
                    }

                    var range = Assert.IsType<ComboBox>(window.FindName("TimeRangeCombo"));
                    Assert.Equal(1, range.SelectedIndex);
                    Assert.NotNull(AutomationProperties.GetLabeledBy(range));
                    Assert.False(Assert.IsType<TextBox>(window.FindName("CustomDaysText")).IsEnabled);
                    Assert.Equal(AutomationLiveSetting.Polite,
                        AutomationProperties.GetLiveSetting(Assert.IsType<TextBlock>(window.FindName("CollectingStatusText"))));
                    Assert.True(Assert.IsType<TextBlock>(window.FindName("StartHeading")).Focusable);
                    Assert.True(Assert.IsType<TextBlock>(window.FindName("ResultsHeading")).Focusable);
                    Assert.True(Assert.IsType<TextBlock>(window.FindName("PreviewHeading")).Focusable);

                    string[] screenNames = ["StartPanel", "CollectingPanel", "ResultsPanel", "PreviewPanel"];
                    var screens = screenNames.Select(name => Assert.IsType<StackPanel>(window.FindName(name))).ToArray();
                    MethodInfo showOnly = Assert.IsAssignableFrom<MethodInfo>(typeof(PCCrashDiagnostic.App.MainWindow).GetMethod(
                        "ShowOnly",
                        BindingFlags.Instance | BindingFlags.NonPublic));
                    foreach (StackPanel screen in screens)
                    {
                        showOnly.Invoke(window, [screen]);
                        window.UpdateLayout();
                        Assert.All(screens, candidate => Assert.Equal(
                            ReferenceEquals(candidate, screen) ? Visibility.Visible : Visibility.Collapsed,
                            candidate.Visibility));
                        FrameworkElement expectedFocus = ReferenceEquals(screen, screens[0])
                            ? Assert.IsType<TextBlock>(window.FindName("StartHeading"))
                            : ReferenceEquals(screen, screens[1])
                                ? Assert.IsType<TextBlock>(window.FindName("CollectingHeading"))
                                : ReferenceEquals(screen, screens[2])
                                    ? Assert.IsType<TextBlock>(window.FindName("ResultsHeading"))
                                    : Assert.IsType<TextBlock>(window.FindName("PreviewHeading"));
                        Assert.True(
                            expectedFocus.IsKeyboardFocused || ReferenceEquals(Keyboard.FocusedElement, expectedFocus),
                            $"Screen transition did not place keyboard focus on {expectedFocus.Name}.");
                    }

                    var results = Assert.IsType<StackPanel>(window.FindName("ResultsPanel"));
                    int safeSummaryIndex = results.Children.IndexOf(Assert.IsType<Button>(window.FindName("ReviewSafeSummaryButton")));
                    int technicalIndex = results.Children.IndexOf(Assert.IsType<Expander>(window.FindName("TechnicalReportExportExpander")));
                    Assert.InRange(safeSummaryIndex, 0, technicalIndex - 1);
                }
                finally
                {
                    window.Close();
                    application.Shutdown();
                }
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "The WPF contract test timed out.");
        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    [Fact]
    public void InitialWindowBoundsFitScaledWorkAreas()
    {
        Rect scaledLaptop = new(0, 0, 960, 500);
        Rect smallWorkArea = new(100, 50, 640, 420);

        foreach (Rect workArea in new[] { scaledLaptop, smallWorkArea })
        {
            Rect bounds = PCCrashDiagnostic.App.MainWindow.CalculateInitialWindowBounds(workArea);
            Assert.True(bounds.Left >= workArea.Left);
            Assert.True(bounds.Top >= workArea.Top);
            Assert.True(bounds.Right <= workArea.Right);
            Assert.True(bounds.Bottom <= workArea.Bottom);
        }
    }

    [Fact]
    public void ReadinessLabelUsesItsOwnCaptureTimeAndHandlesMissingSnapshots()
    {
        BF6CrashDiagnostic.Core.Models.CrashReadiness? readiness =
            BF6CrashDiagnostic.Tests.SafeSummaryTestData.Create().CrashReadiness;
        Assert.NotNull(readiness);

        string captured = PCCrashDiagnostic.App.MainWindow.ReadinessCapturedLabel(readiness);

        Assert.Contains(readiness.CapturedUtc.ToLocalTime().ToString("g"), captured, StringComparison.Ordinal);
        Assert.Equal(
            "No readiness snapshot was captured.",
            PCCrashDiagnostic.App.MainWindow.ReadinessCapturedLabel(null));
    }
}
