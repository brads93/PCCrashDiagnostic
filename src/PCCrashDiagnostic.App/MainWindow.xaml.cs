using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using BF6CrashDiagnostic.Core.Sharing;
using Microsoft.Win32;
using PCCrashDiagnostic.App.Services;

namespace PCCrashDiagnostic.App;

public partial class MainWindow : Window
{
    private readonly IReadOnlyDiagnosticService _diagnostics;
    private CancellationTokenSource? _operation;
    private UiCollectedReport? _current;
    private SafeSummaryPreview? _preview;

    public MainWindow()
        : this(new CoreReadOnlyDiagnosticService())
    {
    }

    internal MainWindow(IReadOnlyDiagnosticService diagnostics)
    {
        _diagnostics = diagnostics ?? throw new ArgumentNullException(nameof(diagnostics));
        InitializeComponent();
        ApplyInitialWorkAreaBounds(SystemParameters.WorkArea);
        Closed += (_, _) =>
        {
            _operation?.Cancel();
            _operation?.Dispose();
            _diagnostics.Dispose();
        };
    }

    private async void BlueScreenButton_Click(object sender, RoutedEventArgs e) =>
        await ScanAsync(target: null).ConfigureAwait(true);

    private async void AppClosedButton_Click(object sender, RoutedEventArgs e)
    {
        string? executable = PickExecutable();
        if (executable is not null)
        {
            await ScanAsync(CreateTargetProfile(Path.GetFileNameWithoutExtension(executable))).ConfigureAwait(true);
        }
    }

    private async void MonitorButton_Click(object sender, RoutedEventArgs e)
    {
        TargetProfile? target = PickMonitoringTarget();
        if (target is null)
        {
            return;
        }

        BeginOperation("Waiting for the selected app…");
        var progress = new Progress<TargetMonitorProgress>(item =>
        {
            CollectingStatusText.Text = item.Message;
            if (item.Percent is { } percent)
            {
                CollectingProgress.IsIndeterminate = false;
                CollectingProgress.Value = percent * 100;
            }
        });
        try
        {
            _current = await _diagnostics.MonitorSelectedTargetAsync(target, progress, _operation!.Token).ConfigureAwait(true);
            ShowResults(_current);
        }
        catch (OperationCanceledException)
        {
            ShowStart();
        }
        catch (Exception exception)
        {
            ShowFailure(exception);
        }
    }

    private async void OpenReportButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open a PC Crash Diagnostic report",
            Filter = "PC Crash Diagnostic reports (*.zip)|*.zip",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        BeginOperation("Validating the report archive…");
        try
        {
            _current = await _diagnostics.OpenPreviousReportAsync(dialog.FileName, _operation!.Token).ConfigureAwait(true);
            ShowResults(_current);
        }
        catch (Exception exception) when (exception is InvalidDataException or NotSupportedException or IOException or UnauthorizedAccessException)
        {
            ShowFailure(exception);
        }
    }

    private async Task ScanAsync(TargetProfile? target)
    {
        TimeSpan range;
        try
        {
            range = GetSelectedRange();
        }
        catch (ArgumentOutOfRangeException exception)
        {
            MessageBox.Show(this, exception.Message, "Check the time range", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        BeginOperation("Looking for incident records…");
        try
        {
            DateTimeOffset end = DateTimeOffset.UtcNow;
            var options = new IncidentSearchOptions(end - range, end, target);
            IncidentSearchResult search = await _diagnostics.FindRecentIncidentsAsync(options, _operation!.Token).ConfigureAwait(true);
            IncidentCandidate? candidate = ChooseIncident(search.Candidates);
            if (candidate is null)
            {
                MessageBox.Show(
                    this,
                    "No incident candidates were found in that time range. Try a longer range or collect again soon after the next problem.",
                    "No incident found",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                ShowStart();
                return;
            }

            CollectingStatusText.Text = "Reading evidence around the selected incident…";
            IncidentSelection selection = new IncidentDiscovery().Select(candidate, IncidentSelectionMethod.UserSelected);
            var progress = new Progress<DiagnosticProgress>(item =>
            {
                CollectingStatusText.Text = item.Message;
                if (item.Percent is { } percent)
                {
                    CollectingProgress.IsIndeterminate = false;
                    CollectingProgress.Value = percent * 100;
                }
            });
            _current = await _diagnostics.AnalyzeSelectedIncidentAsync(
                selection,
                target,
                progress,
                _operation.Token).ConfigureAwait(true);
            ShowResults(_current);
        }
        catch (OperationCanceledException)
        {
            ShowStart();
        }
        catch (Exception exception)
        {
            ShowFailure(exception);
        }
    }

    private IncidentCandidate? ChooseIncident(IReadOnlyList<IncidentCandidate> candidates)
    {
        if (candidates.Count == 0)
        {
            return null;
        }

        if (candidates.Count == 1)
        {
            return candidates[0];
        }

        var choices = candidates.Select(candidate => new IncidentChoice(candidate)).ToArray();
        var list = new ListBox
        {
            ItemsSource = choices,
            DisplayMemberPath = nameof(IncidentChoice.DisplayText),
            SelectedIndex = 0,
            MinHeight = 220,
            MaxHeight = Math.Max(220, SystemParameters.WorkArea.Height * 0.55)
        };
        var select = new Button { Content = "Use selected incident", IsDefault = true, HorizontalAlignment = HorizontalAlignment.Right };
        var cancel = new Button { Content = "Cancel", IsCancel = true, HorizontalAlignment = HorizontalAlignment.Right };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(cancel);
        buttons.Children.Add(select);
        var content = new StackPanel { Margin = new Thickness(22) };
        content.Children.Add(new TextBlock { Text = "Choose the incident to analyze", FontSize = 22, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 12) });
        content.Children.Add(list);
        content.Children.Add(buttons);
        var window = new Window
        {
            Title = "Choose an incident",
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            SizeToContent = SizeToContent.WidthAndHeight,
            MinWidth = Math.Min(650, SystemParameters.WorkArea.Width * 0.85),
            MaxWidth = SystemParameters.WorkArea.Width * 0.9,
            MaxHeight = SystemParameters.WorkArea.Height * 0.9,
            Content = content
        };
        select.Click += (_, _) => window.DialogResult = true;
        return window.ShowDialog() == true && list.SelectedItem is IncidentChoice choice
            ? choice.Candidate
            : null;
    }

    private void ShowResults(UiCollectedReport collected)
    {
        RevokePreview();
        ShowOnly(ResultsPanel);
        DiagnosticReportV3 report = collected.Result.Package.Report;
        ResultIncidentText.Text = report.IncidentSelection is null
            ? $"Report completed {report.EndUtc.ToLocalTime():g}."
            : $"{report.IncidentSelection.Candidate.Title} · {report.IncidentSelection.Candidate.TimeUtc.ToLocalTime():g} · {IncidentOriginLabel(report.IncidentSelection.Candidate.EvidenceOrigin)}";
        EvidencePresentation[] evidence = report.Findings
            .OrderBy(finding => finding.Rank)
            .Select(finding => new EvidencePresentation(finding))
            .ToArray();
        EvidenceItems.ItemsSource = evidence;
        NoEvidenceText.Visibility = evidence.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        CrashReadiness? readiness = report.CrashReadiness;
        ReadinessStateText.Text = readiness is null ? "Unavailable" : ReadinessLabel(readiness.Assessment);
        ReadinessCapturedText.Text = ReadinessCapturedLabel(readiness);
        ReadinessDetailText.Text = readiness?.AssessmentDetail ?? "No readiness record was available in this report.";
        CoverageItems.ItemsSource = report.SourceCoverage
            .OrderBy(source => source.Source, StringComparer.OrdinalIgnoreCase)
            .Select(source => $"{source.Source}: {source.State} · {source.RecordCount} record{(source.RecordCount == 1 ? string.Empty : "s")}")
            .ToArray();
        LocalDumpList.ItemsSource = Array.Empty<UiDumpChoice>();
        DebuggerAvailabilityText.Text = "Checking for an installed Microsoft debugger…";
        DumpCheckerAvailabilityText.Text = string.Empty;
        BuiltInDumpCheckButton.IsEnabled = false;
        DumpChkButton.IsEnabled = false;
        WinDbgOfflineButton.IsEnabled = false;
        WinDbgSymbolsButton.IsEnabled = false;
        LocalToolsResultText.Text = report.DebuggerAnalysis is { } debugger
            ? $"WinDbg reported: {debugger.State}; symbols {debugger.SymbolStatus}. This does not confirm a faulty driver."
            : report.DumpQuality is { } quality
                ? $"Dump quality: {quality.Classification}; DumpChk {quality.DumpChkState}."
                : string.Empty;
        TechnicalReportConfirm.IsChecked = false;
        _ = RefreshLocalToolOptionsAsync(collected.Handle, report);
    }

    private async Task RefreshLocalToolOptionsAsync(UiReportHandle handle, DiagnosticReportV3 report)
    {
        try
        {
            UiLocalToolOptions options = await _diagnostics.GetLocalToolOptionsAsync(handle).ConfigureAwait(true);
            if (_current is null || !_current.Handle.Equals(handle) || ResultsPanel.Visibility != Visibility.Visible)
            {
                return;
            }

            LocalDumpList.ItemsSource = options.DumpChoices;
            LocalDumpList.SelectedIndex = options.DumpChoices.Count == 0 ? -1 : 0;
            DebuggerAvailabilityText.Text = options.Debugger.Detail;
            DumpCheckerAvailabilityText.Text = options.DumpChecker.Detail;
            bool hasDump = options.DumpChoices.Count > 0;
            BuiltInDumpCheckButton.IsEnabled = hasDump;
            DumpChkButton.IsEnabled = hasDump && options.DumpChecker.IsAvailable;
            WinDbgOfflineButton.IsEnabled = hasDump && options.Debugger.IsAvailable;
            WinDbgSymbolsButton.IsEnabled = hasDump && options.Debugger.IsAvailable &&
                                                report.DebuggerAnalysis is { SymbolAccess: SymbolAccessMode.LocalOnly };
            if (!hasDump)
            {
                LocalToolsResultText.Text = "No readable dump was correlated closely enough to this incident for local analysis.";
            }
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            if (_current is not null && _current.Handle.Equals(handle))
            {
                DebuggerAvailabilityText.Text = "Optional local-tool availability could not be checked.";
                LocalToolsResultText.Text = exception.Message;
            }
        }
    }

    private async void BuiltInDumpCheckButton_Click(object sender, RoutedEventArgs e) =>
        await RunDumpQualityAsync(runInstalledDumpChk: false).ConfigureAwait(true);

    private async void DumpChkButton_Click(object sender, RoutedEventArgs e) =>
        await RunDumpQualityAsync(runInstalledDumpChk: true).ConfigureAwait(true);

    private async Task RunDumpQualityAsync(bool runInstalledDumpChk)
    {
        if (_current is null || LocalDumpList.SelectedItem is not UiDumpChoice choice)
        {
            MessageBox.Show(this, "Select one of the correlated dumps first.", "Select a dump", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        UiReportHandle report = _current.Handle;
        BeginOperation(runInstalledDumpChk ? "Starting Microsoft DumpChk…" : "Checking bounded dump metadata…");
        var progress = new Progress<DiagnosticProgress>(item =>
        {
            CollectingStatusText.Text = item.Message;
            if (item.Percent is { } percent)
            {
                CollectingProgress.IsIndeterminate = false;
                CollectingProgress.Value = percent * 100;
            }
        });
        try
        {
            _current = await _diagnostics.RunDumpQualityAsync(
                report,
                choice.ChoiceToken,
                runInstalledDumpChk,
                progress,
                _operation!.Token).ConfigureAwait(true);
            ShowResults(_current);
        }
        catch (OperationCanceledException)
        {
            ShowStart();
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            ShowFailure(exception);
        }
    }

    private async void WinDbgOfflineButton_Click(object sender, RoutedEventArgs e) =>
        await RunWinDbgAsync(allowMicrosoftSymbols: false).ConfigureAwait(true);

    private async void WinDbgSymbolsButton_Click(object sender, RoutedEventArgs e)
    {
        MessageBoxResult consent = MessageBox.Show(
            this,
            "PC Crash Diagnostic will let the installed Microsoft debugger download symbol files only from Microsoft's public symbol server into a private local cache. The crash dump stays on this PC and is not uploaded.\n\nContinue with Microsoft symbol downloads?",
            "Allow Microsoft symbol downloads",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Information);
        if (consent == MessageBoxResult.OK)
        {
            await RunWinDbgAsync(allowMicrosoftSymbols: true).ConfigureAwait(true);
        }
    }

    private async Task RunWinDbgAsync(bool allowMicrosoftSymbols)
    {
        if (_current is null || LocalDumpList.SelectedItem is not UiDumpChoice choice)
        {
            MessageBox.Show(this, "Select one of the correlated dumps first.", "Select a dump", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        UiReportHandle report = _current.Handle;
        BeginOperation(allowMicrosoftSymbols ? "Starting WinDbg with Microsoft symbols…" : "Starting WinDbg offline…");
        var progress = new Progress<DiagnosticProgress>(item =>
        {
            CollectingStatusText.Text = item.Message;
            if (item.Percent is { } percent)
            {
                CollectingProgress.IsIndeterminate = false;
                CollectingProgress.Value = percent * 100;
            }
        });
        try
        {
            _current = await _diagnostics.RunWinDbgAnalysisAsync(
                report,
                choice.ChoiceToken,
                allowMicrosoftSymbols,
                progress,
                _operation!.Token).ConfigureAwait(true);
            ShowResults(_current);
        }
        catch (OperationCanceledException)
        {
            ShowStart();
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            ShowFailure(exception);
        }
    }

    private void OfficialWinDbgLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
            e.Handled = true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            MessageBox.Show(this, exception.Message, "Could not open the Microsoft page", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void ReviewSafeSummaryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_current is null)
        {
            return;
        }

        try
        {
            _preview = await _diagnostics.CreateSupportSummaryPreviewAsync(_current.Handle).ConfigureAwait(true);
            SafeSummaryText.Text = _preview.Text;
            IncludedItems.ItemsSource = _preview.IncludedCategories.Select(item => "• " + item).ToArray();
            ExcludedItems.ItemsSource = _preview.ExcludedCategories.Select(item => "• " + item).ToArray();
            ShowOnly(PreviewPanel);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, exception.Message, "Could not preview the summary", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void CopySafeSummaryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_preview is null)
        {
            return;
        }

        try
        {
            string exactText = await _diagnostics.GetExactSupportSummaryTextAsync(_preview.PreviewToken).ConfigureAwait(true);
            Clipboard.SetText(exactText, TextDataFormat.UnicodeText);
            MessageBox.Show(this, "The exact previewed safe-summary text was copied.", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or InvalidOperationException or
                                          UnauthorizedAccessException or System.Runtime.InteropServices.ExternalException)
        {
            MessageBox.Show(this, exception.Message, "Could not copy the summary", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void SaveSafeSummaryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_preview is null)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Save the safe summary",
            Filter = "Text files (*.txt)|*.txt",
            FileName = _preview.SuggestedFileName,
            AddExtension = true,
            DefaultExt = ".txt"
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            UiExportDestination destination = _diagnostics.PrepareSupportSummaryDestination(dialog.FileName);
            SafeExportDestinationAssessment assessment = destination.Assessment;
            if (assessment.RequiresPrivacyAcknowledgement &&
                MessageBox.Show(
                    this,
                    assessment.Warning + "\n\nSave there anyway?",
                    "Check the save location",
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Warning) != MessageBoxResult.OK)
            {
                return;
            }

            SafeSummaryExportResult result = await _diagnostics.ExportSupportSummaryAsync(
                _preview.PreviewToken,
                destination).ConfigureAwait(true);
            MessageBox.Show(this, $"Saved {result.DestinationFileName}.", "Safe summary saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or UnauthorizedAccessException or InvalidDataException)
        {
            MessageBox.Show(this, exception.Message, "Could not save the summary", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void ExportTechnicalReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_current is null || TechnicalReportConfirm.IsChecked != true)
        {
            MessageBox.Show(this, "Confirm the technical-report privacy warning first.", "Confirmation required", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            TechnicalReportExportTicket ticket = await _diagnostics.PrepareTechnicalReportExportAsync(_current.Handle).ConfigureAwait(true);
            string memberPreview = string.Join(Environment.NewLine, ticket.Members.Select(member => "• " + member));
            MessageBoxResult review = MessageBox.Show(
                this,
                $"This validated technical ZIP will contain exactly these report members:\n\n{memberPreview}\n\nIt contains more machine detail than the safe summary. Continue to choose a save location?",
                "Review technical report contents",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning);
            if (review != MessageBoxResult.OK)
            {
                return;
            }

            var dialog = new SaveFileDialog
            {
                Title = "Save the technical report",
                Filter = "ZIP archives (*.zip)|*.zip",
                FileName = ticket.SuggestedFileName,
                AddExtension = true,
                DefaultExt = ".zip"
            };
            if (dialog.ShowDialog(this) == true)
            {
                UiExportDestination destination = _diagnostics.PrepareTechnicalReportDestination(dialog.FileName);
                SafeExportDestinationAssessment assessment = destination.Assessment;
                if (assessment.RequiresPrivacyAcknowledgement &&
                    MessageBox.Show(
                        this,
                        assessment.Warning + "\n\nSave the technical report there anyway?",
                        "Check the save location",
                        MessageBoxButton.OKCancel,
                        MessageBoxImage.Warning) != MessageBoxResult.OK)
                {
                    return;
                }

                await _diagnostics.ExportTechnicalReportAsync(ticket.Ticket, destination).ConfigureAwait(true);
                MessageBox.Show(this, "The validated technical report was saved.", "Report saved", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, exception.Message, "Could not export the report", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void HistoryExpander_Expanded(object sender, RoutedEventArgs e) => await RefreshHistoryAsync().ConfigureAwait(true);

    private async Task RefreshHistoryAsync()
    {
        try
        {
            IReadOnlyList<UiHistoryReport> history = await _diagnostics.GetHistoryAsync().ConfigureAwait(true);
            HistoryList.ItemsSource = history.Select(report => new HistoryListItem(report)).ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            HistoryList.ItemsSource = new[] { new HistoryListItem(exception.Message) };
        }
    }

    private async void OpenHistoryButton_Click(object sender, RoutedEventArgs e)
    {
        if (HistoryList.SelectedItem is not HistoryListItem { Report: { } report })
        {
            return;
        }

        BeginOperation("Opening the validated local report…");
        try
        {
            _current = await _diagnostics.OpenHistoryReportAsync(report, _operation!.Token).ConfigureAwait(true);
            ShowResults(_current);
        }
        catch (Exception exception)
        {
            ShowFailure(exception);
        }
    }

    private async void RecycleHistoryButton_Click(object sender, RoutedEventArgs e)
    {
        if (HistoryList.SelectedItem is HistoryListItem { Report: { } report })
        {
            bool isCurrent = _current?.Handle.Equals(report.Handle) == true;
            await RecycleReportAsync(report.Handle, resetCurrent: isCurrent).ConfigureAwait(true);
            await RefreshHistoryAsync().ConfigureAwait(true);
        }
    }

    private async void RecycleCurrentButton_Click(object sender, RoutedEventArgs e)
    {
        if (_current is not null)
        {
            await RecycleReportAsync(_current.Handle, resetCurrent: true).ConfigureAwait(true);
        }
    }

    private async Task RecycleReportAsync(UiReportHandle handle, bool resetCurrent)
    {
        ReportDeletionPreview preview = _diagnostics.PreviewRecycleReport(handle);
        MessageBoxResult answer = MessageBox.Show(
            this,
            $"Move {preview.ReportFileCount} report file(s) and {preview.RelatedFolderCount} related local folder(s) to the Windows Recycle Bin?\n\nExternal imports, exported summaries, dumps, and Windows settings are excluded.",
            "Move local report to Recycle Bin",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.OK)
        {
            return;
        }

        ReportDeletionResult result = await _diagnostics.RecycleAsync(preview.PreviewToken).ConfigureAwait(true);
        MessageBox.Show(this, result.Detail, "Recycle Bin result", MessageBoxButton.OK,
            result.State == ReportDeletionState.Recycled ? MessageBoxImage.Information : MessageBoxImage.Warning);
        if (resetCurrent && result.State == ReportDeletionState.Recycled)
        {
            _current = null;
            ShowStart();
        }
    }

    private async void RecycleAllButton_Click(object sender, RoutedEventArgs e)
    {
        ReportDeletionPreview preview = await _diagnostics.PreviewRecycleAllHistoryAsync().ConfigureAwait(true);
        MessageBoxResult answer = MessageBox.Show(
            this,
            $"Move {preview.ReportFileCount} local report file(s) and {preview.RelatedFolderCount} related folder(s) to the Windows Recycle Bin?\n\n{preview.ExcludedItemCount} unrecognized item(s) will be left untouched.",
            "Move all local report history to Recycle Bin",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning);
        if (answer == MessageBoxResult.OK)
        {
            ReportDeletionResult result = await _diagnostics.RecycleAsync(preview.PreviewToken).ConfigureAwait(true);
            MessageBox.Show(this, result.Detail, "Recycle Bin result", MessageBoxButton.OK,
                result.State == ReportDeletionState.Recycled ? MessageBoxImage.Information : MessageBoxImage.Warning);
            if (result.State == ReportDeletionState.Recycled)
            {
                _current = null;
                ShowStart();
            }
            await RefreshHistoryAsync().ConfigureAwait(true);
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => _operation?.Cancel();

    private void StartOverButton_Click(object sender, RoutedEventArgs e) => ShowStart();

    private void TimeRangeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CustomDaysText is null || CustomDaysLabel is null)
        {
            return;
        }

        bool custom = (TimeRangeCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString()
            ?.Equals("custom", StringComparison.OrdinalIgnoreCase) == true;
        CustomDaysText.IsEnabled = custom;
        CustomDaysLabel.Opacity = custom ? 1 : 0.55;
    }

    private void BackToResultsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_current is not null)
        {
            ShowResults(_current);
        }
    }

    private void BeginOperation(string status)
    {
        RevokePreview();
        _operation?.Cancel();
        _operation?.Dispose();
        _operation = new CancellationTokenSource();
        CollectingStatusText.Text = status;
        CollectingProgress.IsIndeterminate = true;
        CollectingProgress.Value = 0;
        ShowOnly(CollectingPanel);
    }

    private void ShowStart()
    {
        RevokePreview();
        _operation?.Cancel();
        ShowOnly(StartPanel);
    }

    private void RevokePreview()
    {
        if (_preview is not null)
        {
            _diagnostics.RevokeSupportSummary(_preview.PreviewToken);
            _preview = null;
        }

        SafeSummaryText.Clear();
    }

    private void ShowOnly(UIElement panel)
    {
        StartPanel.Visibility = ReferenceEquals(panel, StartPanel) ? Visibility.Visible : Visibility.Collapsed;
        CollectingPanel.Visibility = ReferenceEquals(panel, CollectingPanel) ? Visibility.Visible : Visibility.Collapsed;
        ResultsPanel.Visibility = ReferenceEquals(panel, ResultsPanel) ? Visibility.Visible : Visibility.Collapsed;
        PreviewPanel.Visibility = ReferenceEquals(panel, PreviewPanel) ? Visibility.Visible : Visibility.Collapsed;

        FrameworkElement focusTarget = ReferenceEquals(panel, StartPanel)
            ? StartHeading
            : ReferenceEquals(panel, CollectingPanel)
                ? CollectingHeading
                : ReferenceEquals(panel, ResultsPanel)
                    ? ResultsHeading
                    : PreviewHeading;
        focusTarget.Focus();
    }

    private void ApplyInitialWorkAreaBounds(Rect workArea)
    {
        Rect bounds = CalculateInitialWindowBounds(workArea);
        MinWidth = Math.Min(640, bounds.Width);
        MinHeight = Math.Min(480, bounds.Height);
        MaxWidth = Math.Max(MinWidth, Math.Max(bounds.Width, workArea.Width));
        MaxHeight = Math.Max(MinHeight, Math.Max(bounds.Height, workArea.Height));
        Width = bounds.Width;
        Height = bounds.Height;
        Left = bounds.Left;
        Top = bounds.Top;
        WindowStartupLocation = WindowStartupLocation.Manual;
    }

    internal static Rect CalculateInitialWindowBounds(Rect workArea)
    {
        double workWidth = double.IsFinite(workArea.Width) && workArea.Width > 0 ? workArea.Width : 1120;
        double workHeight = double.IsFinite(workArea.Height) && workArea.Height > 0 ? workArea.Height : 780;
        double availableWidth = Math.Max(1, workWidth - Math.Min(32, workWidth * 0.05));
        double availableHeight = Math.Max(1, workHeight - Math.Min(32, workHeight * 0.05));
        double width = Math.Min(1120, availableWidth);
        double height = Math.Min(780, availableHeight);
        double left = workArea.Left + Math.Max(0, (workWidth - width) / 2);
        double top = workArea.Top + Math.Max(0, (workHeight - height) / 2);
        return new Rect(left, top, width, height);
    }

    internal static string ReadinessCapturedLabel(CrashReadiness? readiness) => readiness is null
        ? "No readiness snapshot was captured."
        : $"At time of report · captured {readiness.CapturedUtc.ToLocalTime():g}";

    private void ShowFailure(Exception exception)
    {
        ShowStart();
        MessageBox.Show(this, exception.Message, "PC Crash Diagnostic", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private TimeSpan GetSelectedRange()
    {
        string tag = (TimeRangeCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "7";
        int days = tag.Equals("custom", StringComparison.OrdinalIgnoreCase)
            ? int.TryParse(CustomDaysText.Text, out int custom) ? custom : 0
            : int.Parse(tag, System.Globalization.CultureInfo.InvariantCulture);
        if (days is < 1 or > 31)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "Enter a custom range from 1 to 31 days.");
        }

        return TimeSpan.FromDays(days);
    }

    private string? PickExecutable()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose the app or game executable",
            Filter = "Windows programs (*.exe)|*.exe",
            CheckFileExists = true,
            Multiselect = false
        };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }

    private TargetProfile? PickMonitoringTarget()
    {
        RunningProcessChoice[] running = GetRunningProcessChoices();
        var list = new ListBox
        {
            ItemsSource = running,
            DisplayMemberPath = nameof(RunningProcessChoice.DisplayName),
            SelectedIndex = running.Length == 0 ? -1 : 0,
            MinHeight = 220,
            MaxHeight = Math.Max(220, SystemParameters.WorkArea.Height * 0.55)
        };
        System.Windows.Automation.AutomationProperties.SetAutomationId(list, "RunningProcessList");

        var useRunning = new Button
        {
            Content = "Monitor selected running app",
            IsDefault = true,
            HorizontalAlignment = HorizontalAlignment.Right,
            IsEnabled = running.Length > 0
        };
        var chooseExecutable = new Button
        {
            Content = "Choose an executable…",
            HorizontalAlignment = HorizontalAlignment.Right
        };
        var cancel = new Button
        {
            Content = "Cancel",
            IsCancel = true,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        var buttons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(cancel);
        buttons.Children.Add(chooseExecutable);
        buttons.Children.Add(useRunning);
        var content = new StackPanel { Margin = new Thickness(22) };
        content.Children.Add(new TextBlock
        {
            Text = "Choose an app to monitor",
            FontSize = 22,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 6)
        });
        content.Children.Add(new TextBlock
        {
            Text = "Only process names are listed. All matching instances are monitored; process memory, modules, command lines, and input are not read.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 12)
        });
        content.Children.Add(list);
        content.Children.Add(buttons);
        var window = new Window
        {
            Title = "Choose an app to monitor",
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            SizeToContent = SizeToContent.WidthAndHeight,
            MinWidth = Math.Min(680, SystemParameters.WorkArea.Width * 0.85),
            MaxWidth = SystemParameters.WorkArea.Width * 0.9,
            MaxHeight = SystemParameters.WorkArea.Height * 0.9,
            Content = content
        };

        bool chooseFile = false;
        useRunning.Click += (_, _) =>
        {
            if (list.SelectedItem is not null)
            {
                window.DialogResult = true;
            }
        };
        chooseExecutable.Click += (_, _) =>
        {
            chooseFile = true;
            window.DialogResult = true;
        };
        if (window.ShowDialog() != true)
        {
            return null;
        }

        if (chooseFile)
        {
            string? executable = PickExecutable();
            return executable is null ? null : CreateTargetProfile(Path.GetFileNameWithoutExtension(executable));
        }

        return list.SelectedItem is RunningProcessChoice choice
            ? CreateTargetProfile(choice.ProcessName)
            : null;
    }

    private static RunningProcessChoice[] GetRunningProcessChoices()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                if (!process.HasExited && process.MainWindowHandle != IntPtr.Zero &&
                    !string.IsNullOrWhiteSpace(process.ProcessName))
                {
                    names.Add(process.ProcessName);
                }
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
                // A process can exit or deny metadata access while the list is
                // being built. Omit it and retain the executable-picker option.
            }
            finally
            {
                process.Dispose();
            }
        }

        return names
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Take(512)
            .Select(name => new RunningProcessChoice(name, name + ".exe"))
            .ToArray();
    }

    internal static TargetProfile CreateTargetProfile(string processName) =>
        processName.Equals("BF6", StringComparison.OrdinalIgnoreCase)
            ? TargetProfile.Battlefield6
            : TargetProfile.FromExecutable(processName + ".exe");

    internal static string IncidentOriginLabel(IncidentEvidenceOrigin origin) => origin switch
    {
        IncidentEvidenceOrigin.WindowsEventLog => "Windows Event Log",
        IncidentEvidenceOrigin.ReliabilityMonitor => "Reliability Monitor",
        IncidentEvidenceOrigin.MonitorObservation => "app monitor",
        IncidentEvidenceOrigin.ManualTime => "manual time",
        _ => "source not recorded"
    };

    private static string ReadinessLabel(CrashReadinessState state) => state switch
    {
        CrashReadinessState.Ready => "Ready",
        CrashReadinessState.Limited => "Limited",
        CrashReadinessState.AtRisk => "At risk",
        CrashReadinessState.Off => "Off",
        CrashReadinessState.PendingRestart => "Pending restart",
        _ => "Unavailable"
    };

    private sealed record IncidentChoice(IncidentCandidate Candidate)
    {
        public string DisplayText =>
            $"{Candidate.TimeUtc.ToLocalTime():g} · {Candidate.Title} · {IncidentOriginLabel(Candidate.EvidenceOrigin)} · {Candidate.SupportingRecordCount} supporting record{(Candidate.SupportingRecordCount == 1 ? string.Empty : "s")}";
    }

    private sealed record EvidencePresentation(
        string Title,
        string EvidenceLabel,
        string Observed,
        string Relevance,
        string Limitation,
        string NextCheck)
    {
        public EvidencePresentation(DiagnosticFinding finding)
            : this(
                finding.Title,
                finding.Severity == FindingSeverity.Context
                    ? "Context only"
                    : finding.Confidence switch
                    {
                        FindingConfidence.High => "Direct evidence",
                        FindingConfidence.Medium => "Supporting evidence",
                        _ => "Context only"
                    },
                "Observed: " + finding.Evidence,
                "Possible relevance: " + finding.Meaning,
                "Does not establish: " + finding.DoesNotProve,
                "Next check: " + finding.NextCheck)
        {
        }
    }

    private sealed record HistoryListItem(UiHistoryReport? Report, string DisplayText)
    {
        public HistoryListItem(UiHistoryReport report)
            : this(
                report,
                $"{report.StartUtc.ToLocalTime():g} · {report.Kind} · {report.TargetName} · {(report.StopCodes.Count == 0 ? "no stop code" : string.Join(", ", report.StopCodes))}")
        {
        }

        public HistoryListItem(string message) : this(null, message)
        {
        }
    }

    private sealed record RunningProcessChoice(string ProcessName, string DisplayName);
}
