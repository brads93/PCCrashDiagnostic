using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Input;
using BF6CrashDiagnostic.App.Commands;
using BF6CrashDiagnostic.App.Models;
using BF6CrashDiagnostic.App.Services;
using BF6CrashDiagnostic.Core;

namespace BF6CrashDiagnostic.App.ViewModels;

internal sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly IDiagnosticService _diagnosticService;
    private readonly IUserInteractionService _interactionService;

    public string AppVersionLabel =>
        $"Version {PCCrashDiagnosticCoordinator.ToolVersion} · Open source · Controlled test build";

    public string AdvancedDumpToolsNote => _diagnosticService.SupportsDumpCheck
        ? "The dump file is never placed in the standard report. DumpChk and WinDbg run only when Microsoft-signed x64 tools are already installed."
        : "The dump file is never placed in the standard report. WinDbg runs only when a Microsoft-signed x64 cdb.exe is already installed.";
    private readonly AsyncRelayCommand _showSystemCrashCommand;
    private readonly AsyncRelayCommand _showApplicationCrashCommand;
    private readonly RelayCommand _showMonitorCommand;
    private readonly AsyncRelayCommand _showPreviousReportsCommand;
    private readonly AsyncRelayCommand _refreshIncidentsCommand;
    private readonly AsyncRelayCommand _analyzeSelectedIncidentCommand;
    private readonly RelayCommand _useBattlefieldPresetCommand;
    private readonly RelayCommand _chooseExecutableCommand;
    private readonly RelayCommand _refreshRunningProcessesCommand;
    private readonly RelayCommand _useRunningProcessCommand;
    private readonly AsyncRelayCommand _startMonitoringCommand;
    private readonly AsyncRelayCommand _openPreviousReportCommand;
    private readonly RelayCommand _cancelCommand;
    private readonly RelayCommand _reviewExportCommand;
    private readonly RelayCommand _backToResultsCommand;
    private readonly RelayCommand _startOverCommand;
    private readonly AsyncRelayCommand _packageDumpCommand;
    private readonly AsyncRelayCommand _inspectProtectedDumpCommand;
    private readonly AsyncRelayCommand _retryProtectedSourceCommand;
    private readonly AsyncRelayCommand _runDumpCheckCommand;
    private readonly AsyncRelayCommand _runDebuggerCommand;
    private readonly AsyncRelayCommand _retrySymbolsCommand;
    private readonly AsyncRelayCommand _prepareCrashCaptureCommand;
    private readonly AsyncRelayCommand _restoreCrashCaptureCommand;
    private readonly AsyncRelayCommand _restoreSavedCrashCaptureCommand;
    private readonly AsyncRelayCommand _enablePerAppCrashCaptureCommand;
    private readonly AsyncRelayCommand _restorePerAppCrashCaptureCommand;
    private readonly AsyncRelayCommand _restoreSavedPerAppCrashCaptureCommand;
    private readonly RelayCommand _copySummaryCommand;
    private readonly RelayCommand _exportCommand;
    private readonly RelayCommand _openFolderCommand;
    private readonly CancellationTokenSource _lifetimeCancellation = new();
    private CancellationTokenSource? _operationCancellation;
    private UiDiagnosticResult? _latestResult;
    private WorkflowView _currentView = WorkflowView.Start;
    private StartPanel _startPanel = StartPanel.None;
    private UiIncidentKind _selectedIncidentKind = UiIncidentKind.SystemCrash;
    private UiTargetProfile _selectedTarget = UiTargetProfile.Battlefield6;
    private UiIncidentCandidate? _selectedIncident;
    private UiLookbackOption _selectedLookback;
    private UiRunningProcess? _selectedRunningProcess;
    private UiPreviousReport? _selectedPreviousReport;
    private UiDumpChoice? _selectedDumpChoice;
    private UiProtectedEvidenceSourceChoice? _selectedProtectedEvidenceSource;
    private UiCrashReadiness _crashReadiness = UiCrashReadiness.Missing(null, false);
    private UiCrashPreparationState _crashPreparationState = UiCrashPreparationState.NotStarted;
    private string _crashPreparationMessage = string.Empty;
    private string? _crashPreparationReceiptId;
    private bool _canRestoreCrashPreparation;
    private string _perAppCrashCaptureMessage = string.Empty;
    private UiCrashPreparationState _perAppCrashCaptureState = UiCrashPreparationState.NotStarted;
    private string? _perAppCrashCaptureReceiptId;
    private bool _canRestorePerAppCrashCapture;
    private UiRestorableConfigurationReceipts _restorableConfigurationReceipts =
        UiRestorableConfigurationReceipts.Empty;
    private UiRestorablePerAppCaptureReceipt? _selectedRestorablePerAppCaptureReceipt;
    private bool _isBusy;
    private bool _isMonitoring;
    private bool _useAutomaticCrashTime = true;
    private DateTime? _selectedCrashDate;
    private string _manualCrashTimeText = string.Empty;
    private string _manualTimeValidation = string.Empty;
    private string _setupMessage = string.Empty;
    private string _statusTitle = "Ready";
    private string _statusDetail = "Choose what happened.";
    private double _progressValue;
    private bool _isProgressIndeterminate;
    private string _lastUpdatedText = "No session collected";
    private string _coverageSummary = "Data coverage will appear after collection.";
    private string _resultIncidentTitle = "No report selected";
    private string _resultCompletionDetail = string.Empty;
    private string _resultTargetName = "This PC";
    private string _resultTimeRange = string.Empty;
    private string _exportStatus = string.Empty;
    private string _systemCoverageSummary = "Checking system details…";

    public MainViewModel(IDiagnosticService diagnosticService, string dataRoot)
        : this(diagnosticService, new DesktopInteractionService(), dataRoot)
    {
    }

    internal MainViewModel(
        IDiagnosticService diagnosticService,
        IUserInteractionService interactionService,
        string dataRoot)
    {
        _diagnosticService = diagnosticService;
        _interactionService = interactionService;
        DataRoot = dataRoot;

        DateTime defaultCrashTime = DateTime.Now.AddHours(-1);
        _selectedCrashDate = defaultCrashTime.Date;
        _manualCrashTimeText = defaultCrashTime.ToString("h:mm tt", CultureInfo.CurrentCulture);
        IncidentLookbackOptions =
        [
            new UiLookbackOption("Last 24 hours", TimeSpan.FromHours(24)),
            new UiLookbackOption("Last 7 days", TimeSpan.FromDays(7)),
            new UiLookbackOption("Last 14 days", TimeSpan.FromDays(14))
        ];
        _selectedLookback = IncidentLookbackOptions[1];

        TelemetryCards =
        [
            new MetricCardViewModel("System RAM", "—", "Physical memory in use"),
            new MetricCardViewModel("System commit", "—", "Committed memory versus limit"),
            new MetricCardViewModel("Target memory", "Not sampled", "Private bytes"),
            new MetricCardViewModel("Target VRAM", "Not sampled", "Dedicated GPU memory")
        ];
        WorkflowSteps =
        [
            new WorkflowStepViewModel("1", "Selection"),
            new WorkflowStepViewModel("2", "Collecting"),
            new WorkflowStepViewModel("3", "Windows records"),
            new WorkflowStepViewModel("4", "Report")
        ];

        _showSystemCrashCommand = new AsyncRelayCommand(
            () => ShowIncidentSetupAsync(UiIncidentKind.SystemCrash),
            () => !IsBusy);
        _showApplicationCrashCommand = new AsyncRelayCommand(
            () => ShowIncidentSetupAsync(UiIncidentKind.ApplicationCrashOrFreeze),
            () => !IsBusy);
        _showMonitorCommand = new RelayCommand(ShowMonitorSetup, () => !IsBusy);
        _showPreviousReportsCommand = new AsyncRelayCommand(ShowPreviousReportsAsync, () => !IsBusy);
        _refreshIncidentsCommand = new AsyncRelayCommand(RefreshIncidentsAsync, () => !IsBusy);
        _analyzeSelectedIncidentCommand = new AsyncRelayCommand(AnalyzeSelectedIncidentAsync, () => !IsBusy);
        _useBattlefieldPresetCommand = new RelayCommand(UseBattlefieldPreset, () => !IsBusy);
        _chooseExecutableCommand = new RelayCommand(ChooseExecutable, () => !IsBusy);
        _refreshRunningProcessesCommand = new RelayCommand(RefreshRunningProcesses, () => !IsBusy);
        _useRunningProcessCommand = new RelayCommand(UseRunningProcess, () => !IsBusy && SelectedRunningProcess is not null);
        _startMonitoringCommand = new AsyncRelayCommand(StartMonitoringAsync, () => !IsBusy);
        _openPreviousReportCommand = new AsyncRelayCommand(OpenPreviousReportAsync, () => !IsBusy && SelectedPreviousReport is not null);
        _cancelCommand = new RelayCommand(CancelOperation, () => IsBusy);
        _reviewExportCommand = new RelayCommand(OpenReviewExport, () => _latestResult is not null && !IsBusy);
        _backToResultsCommand = new RelayCommand(() => CurrentView = WorkflowView.Results, () => _latestResult is not null && !IsBusy);
        _startOverCommand = new RelayCommand(StartOver, () => !IsBusy);
        _packageDumpCommand = new AsyncRelayCommand(PackageDumpAsync, () => CanPackageDump);
        _inspectProtectedDumpCommand = new AsyncRelayCommand(InspectProtectedDumpAsync, () => CanInspectProtectedDump);
        _retryProtectedSourceCommand = new AsyncRelayCommand(RetryProtectedSourceAsync, () => CanRetryProtectedEvidenceSource);
        _runDumpCheckCommand = new AsyncRelayCommand(RunDumpCheckAsync, () => CanRunDumpCheck);
        _runDebuggerCommand = new AsyncRelayCommand(() => RunDebuggerAsync(false), () => CanRunDebugger);
        _retrySymbolsCommand = new AsyncRelayCommand(RetryWithSymbolsAsync, () => CanRetryWithMicrosoftSymbols);
        _prepareCrashCaptureCommand = new AsyncRelayCommand(PrepareCrashCaptureAsync, () => CanPrepareCrashCapture);
        _restoreCrashCaptureCommand = new AsyncRelayCommand(RestoreCrashCaptureAsync, () => CanRestoreCrashPreparation);
        _restoreSavedCrashCaptureCommand = new AsyncRelayCommand(
            RestoreSavedCrashCaptureAsync,
            () => CanRestoreSavedCrashCapture);
        _enablePerAppCrashCaptureCommand = new AsyncRelayCommand(EnablePerAppCrashCaptureAsync, () => CanEnablePerAppCrashCapture);
        _restorePerAppCrashCaptureCommand = new AsyncRelayCommand(RestorePerAppCrashCaptureAsync, () => CanRestorePerAppCrashCapture);
        _restoreSavedPerAppCrashCaptureCommand = new AsyncRelayCommand(
            RestoreSavedPerAppCrashCaptureAsync,
            () => CanRestoreSavedPerAppCrashCapture);
        _copySummaryCommand = new RelayCommand(CopySummary, () => _latestResult is not null && !IsBusy);
        _exportCommand = new RelayCommand(ExportReport, () => _latestResult is not null && !IsBusy);
        _openFolderCommand = new RelayCommand(OpenReportFolder, () => _latestResult is not null && !IsBusy);
    }

    public string DataRoot { get; }

    public ObservableCollection<UiSystemFact> SystemFacts { get; } = [];

    public ObservableCollection<string> SystemCollectionIssues { get; } = [];

    public ObservableCollection<MetricCardViewModel> TelemetryCards { get; }

    public ObservableCollection<UiTelemetrySample> TelemetryHistory { get; } = [];

    public ObservableCollection<FindingViewModel> Findings { get; } = [];

    public ObservableCollection<string> CollectionIssues { get; } = [];

    public ObservableCollection<UiIncidentCandidate> RecentIncidents { get; } = [];

    public IReadOnlyList<UiLookbackOption> IncidentLookbackOptions { get; }

    public ObservableCollection<UiRunningProcess> RunningProcesses { get; } = [];

    public ObservableCollection<UiPreviousReport> PreviousReports { get; } = [];

    public ObservableCollection<UiRecurringIncidentGroup> RecurringIncidentGroups { get; } = [];

    public ObservableCollection<UiDumpChoice> DumpChoices { get; } = [];

    public ObservableCollection<UiProtectedEvidenceSourceChoice> ProtectedEvidenceSources { get; } = [];

    public ObservableCollection<UiRestorablePerAppCaptureReceipt> RestorablePerAppCaptureReceipts { get; } = [];

    public ObservableCollection<WorkflowStepViewModel> WorkflowSteps { get; }

    public ICommand ShowSystemCrashCommand => _showSystemCrashCommand;
    public ICommand ShowApplicationCrashCommand => _showApplicationCrashCommand;
    public ICommand ShowMonitorCommand => _showMonitorCommand;
    public ICommand ShowPreviousReportsCommand => _showPreviousReportsCommand;
    public ICommand RefreshIncidentsCommand => _refreshIncidentsCommand;
    public ICommand AnalyzeSelectedIncidentCommand => _analyzeSelectedIncidentCommand;
    public ICommand UseBattlefieldPresetCommand => _useBattlefieldPresetCommand;
    public ICommand ChooseExecutableCommand => _chooseExecutableCommand;
    public ICommand RefreshRunningProcessesCommand => _refreshRunningProcessesCommand;
    public ICommand UseRunningProcessCommand => _useRunningProcessCommand;
    public ICommand StartMonitoringCommand => _startMonitoringCommand;
    public ICommand OpenPreviousReportCommand => _openPreviousReportCommand;
    public ICommand CancelCommand => _cancelCommand;
    public ICommand ReviewExportCommand => _reviewExportCommand;
    public ICommand BackToResultsCommand => _backToResultsCommand;
    public ICommand StartOverCommand => _startOverCommand;
    public ICommand PackageDumpCommand => _packageDumpCommand;
    public ICommand InspectProtectedDumpCommand => _inspectProtectedDumpCommand;
    public ICommand RetryProtectedSourceCommand => _retryProtectedSourceCommand;
    public ICommand RunDumpCheckCommand => _runDumpCheckCommand;
    public ICommand RunDebuggerCommand => _runDebuggerCommand;
    public ICommand RetrySymbolsCommand => _retrySymbolsCommand;
    public ICommand PrepareCrashCaptureCommand => _prepareCrashCaptureCommand;
    public ICommand RestoreCrashCaptureCommand => _restoreCrashCaptureCommand;
    public ICommand RestoreSavedCrashCaptureCommand => _restoreSavedCrashCaptureCommand;
    public ICommand EnablePerAppCrashCaptureCommand => _enablePerAppCrashCaptureCommand;
    public ICommand RestorePerAppCrashCaptureCommand => _restorePerAppCrashCaptureCommand;
    public ICommand RestoreSavedPerAppCrashCaptureCommand => _restoreSavedPerAppCrashCaptureCommand;
    public ICommand CopySummaryCommand => _copySummaryCommand;
    public ICommand ExportCommand => _exportCommand;
    public ICommand OpenFolderCommand => _openFolderCommand;

    public WorkflowView CurrentView
    {
        get => _currentView;
        private set
        {
            if (!SetProperty(ref _currentView, value))
            {
                return;
            }

            OnPropertyChanged(nameof(IsStartView));
            OnPropertyChanged(nameof(IsCollectingView));
            OnPropertyChanged(nameof(IsResultsView));
            OnPropertyChanged(nameof(IsReviewExportView));
            RaiseCommandStates();
        }
    }

    public bool IsStartView => CurrentView == WorkflowView.Start;
    public bool IsCollectingView => CurrentView == WorkflowView.Collecting;
    public bool IsResultsView => CurrentView == WorkflowView.Results;
    public bool IsReviewExportView => CurrentView == WorkflowView.ReviewExport;

    public StartPanel StartPanel
    {
        get => _startPanel;
        private set
        {
            if (!SetProperty(ref _startPanel, value))
            {
                return;
            }

            OnPropertyChanged(nameof(IsIncidentPanelVisible));
            OnPropertyChanged(nameof(IsMonitorPanelVisible));
            OnPropertyChanged(nameof(IsPreviousReportsPanelVisible));
        }
    }

    public bool IsIncidentPanelVisible => StartPanel == StartPanel.Incident;
    public bool IsMonitorPanelVisible => StartPanel == StartPanel.Monitor;
    public bool IsPreviousReportsPanelVisible => StartPanel == StartPanel.PreviousReports;

    public UiIncidentKind SelectedIncidentKind
    {
        get => _selectedIncidentKind;
        private set
        {
            if (SetProperty(ref _selectedIncidentKind, value))
            {
                OnPropertyChanged(nameof(IsApplicationIncident));
                OnPropertyChanged(nameof(IncidentSetupTitle));
                OnPropertyChanged(nameof(IncidentSetupDetail));
            }
        }
    }

    public bool IsApplicationIncident => SelectedIncidentKind == UiIncidentKind.ApplicationCrashOrFreeze;

    public string IncidentSetupTitle => IsApplicationIncident
        ? "Analyze an app crash or freeze"
        : "Analyze a Windows crash or restart";

    public string IncidentSetupDetail => IsApplicationIncident
        ? "Choose the app and the matching incident."
        : "Choose the Windows incident that matches what happened.";

    public UiTargetProfile SelectedTarget
    {
        get => _selectedTarget;
        private set
        {
            if (!SetProperty(ref _selectedTarget, value))
            {
                return;
            }

            OnPropertyChanged(nameof(SelectedTargetName));
            OnPropertyChanged(nameof(SelectedTargetDetail));
            RecentIncidents.Clear();
            SelectedIncident = null;
            SetupMessage = "The app changed. Select Search again.";
        }
    }

    public string SelectedTargetName => SelectedTarget.DisplayName;
    public string SelectedTargetDetail => SelectedTarget.ProcessSummary;

    public UiIncidentCandidate? SelectedIncident
    {
        get => _selectedIncident;
        set => SetProperty(ref _selectedIncident, value);
    }

    public UiLookbackOption SelectedLookback
    {
        get => _selectedLookback;
        set
        {
            if (SetProperty(ref _selectedLookback, value))
            {
                RecentIncidents.Clear();
                SelectedIncident = null;
                SetupMessage = "The search period changed. Select Search again.";
            }
        }
    }

    public UiRunningProcess? SelectedRunningProcess
    {
        get => _selectedRunningProcess;
        set
        {
            if (SetProperty(ref _selectedRunningProcess, value))
            {
                _useRunningProcessCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public UiPreviousReport? SelectedPreviousReport
    {
        get => _selectedPreviousReport;
        set
        {
            if (SetProperty(ref _selectedPreviousReport, value))
            {
                _openPreviousReportCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public UiDumpChoice? SelectedDumpChoice
    {
        get => _selectedDumpChoice;
        set
        {
            if (!SetProperty(ref _selectedDumpChoice, value))
            {
                return;
            }

            if (_latestResult is not null && value is not null)
            {
                _latestResult = _latestResult with
                {
                    EligibleDumpPath = value.Path,
                    CanPackageDump = File.Exists(value.Path)
                };
            }

            OnPropertyChanged(nameof(CanPackageDump));
            OnPropertyChanged(nameof(CanInspectProtectedDump));
            OnPropertyChanged(nameof(CanRunDumpCheck));
            OnPropertyChanged(nameof(CanRunDebugger));
            OnPropertyChanged(nameof(CanRetryWithMicrosoftSymbols));
            RaiseCommandStates();
        }
    }

    public UiProtectedEvidenceSourceChoice? SelectedProtectedEvidenceSource
    {
        get => _selectedProtectedEvidenceSource;
        set
        {
            if (SetProperty(ref _selectedProtectedEvidenceSource, value))
            {
                _retryProtectedSourceCommand.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(CanRetryProtectedEvidenceSource));
            }
        }
    }

    public UiRestorablePerAppCaptureReceipt? SelectedRestorablePerAppCaptureReceipt
    {
        get => _selectedRestorablePerAppCaptureReceipt;
        set
        {
            if (SetProperty(ref _selectedRestorablePerAppCaptureReceipt, value))
            {
                OnPropertyChanged(nameof(CanRestoreSavedPerAppCrashCapture));
                _restoreSavedPerAppCrashCaptureCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                RaiseCommandStates();
            }
        }
    }

    public bool IsMonitoring
    {
        get => _isMonitoring;
        private set => SetProperty(ref _isMonitoring, value);
    }

    public bool UseAutomaticCrashTime
    {
        get => _useAutomaticCrashTime;
        set
        {
            if (SetProperty(ref _useAutomaticCrashTime, value))
            {
                OnPropertyChanged(nameof(UseManualCrashTime));
                if (value)
                {
                    ManualTimeValidation = string.Empty;
                }
            }
        }
    }

    public bool UseManualCrashTime
    {
        get => !UseAutomaticCrashTime;
        set
        {
            if (value)
            {
                UseAutomaticCrashTime = false;
            }
        }
    }

    public DateTime? SelectedCrashDate
    {
        get => _selectedCrashDate;
        set => SetProperty(ref _selectedCrashDate, value);
    }

    public string ManualCrashTimeText
    {
        get => _manualCrashTimeText;
        set => SetProperty(ref _manualCrashTimeText, value);
    }

    public string ManualTimeValidation
    {
        get => _manualTimeValidation;
        private set => SetProperty(ref _manualTimeValidation, value);
    }

    public string SetupMessage
    {
        get => _setupMessage;
        private set
        {
            if (SetProperty(ref _setupMessage, value))
            {
                OnPropertyChanged(nameof(HasSetupMessage));
            }
        }
    }

    public bool HasSetupMessage => !string.IsNullOrWhiteSpace(SetupMessage);

    public string StatusTitle
    {
        get => _statusTitle;
        private set => SetProperty(ref _statusTitle, value);
    }

    public string StatusDetail
    {
        get => _statusDetail;
        private set => SetProperty(ref _statusDetail, value);
    }

    public double ProgressValue
    {
        get => _progressValue;
        private set => SetProperty(ref _progressValue, value);
    }

    public bool IsProgressIndeterminate
    {
        get => _isProgressIndeterminate;
        private set => SetProperty(ref _isProgressIndeterminate, value);
    }

    public string LastUpdatedText
    {
        get => _lastUpdatedText;
        private set => SetProperty(ref _lastUpdatedText, value);
    }

    public string CoverageSummary
    {
        get => _coverageSummary;
        private set => SetProperty(ref _coverageSummary, value);
    }

    public string ResultIncidentTitle
    {
        get => _resultIncidentTitle;
        private set => SetProperty(ref _resultIncidentTitle, value);
    }

    public string ResultCompletionDetail
    {
        get => _resultCompletionDetail;
        private set => SetProperty(ref _resultCompletionDetail, value);
    }

    public string ResultTargetName
    {
        get => _resultTargetName;
        private set => SetProperty(ref _resultTargetName, value);
    }

    public string ResultTimeRange
    {
        get => _resultTimeRange;
        private set => SetProperty(ref _resultTimeRange, value);
    }

    public string CrashReadinessStatus => _crashReadiness.Status;

    public string CrashReadinessDumpType => _crashReadiness.DumpType;

    public string CrashReadinessDetail => _crashReadiness.Detail;

    public string CrashReadinessBackingStorage => _crashReadiness.BackingStorage;

    public string CrashReadinessFreeSpace => _crashReadiness.FreeSpace;

    public string CrashReadinessEventLogging => _crashReadiness.EventLogging;

    public string CrashReadinessAutomaticRestart => _crashReadiness.AutomaticRestart;

    public string CrashReadinessCapturedText
    {
        get
        {
            string prefix = _crashReadiness.IsHistorical ? "At time of report" : "Checked for this report";
            return _crashReadiness.CapturedUtc is null
                ? prefix
                : $"{prefix} · {_crashReadiness.CapturedUtc.Value.ToLocalTime():MMM d, yyyy h:mm tt}";
        }
    }

    public bool IsHistoricalCrashReadiness => _crashReadiness.IsHistorical;

    public bool IsCurrentCrashReadiness => !_crashReadiness.IsHistorical;

    public bool HasRestorableSettings => HasRestorableCrashCapture || HasRestorablePerAppCrashCapture;

    public bool HasRestorableCrashCapture =>
        !string.IsNullOrWhiteSpace(_restorableConfigurationReceipts.CrashCaptureReceiptId);

    public bool HasRestorablePerAppCrashCapture => RestorablePerAppCaptureReceipts.Count > 0;

    public bool CanRestoreSavedCrashCapture => HasRestorableCrashCapture && !IsBusy;

    public bool CanRestoreSavedPerAppCrashCapture => HasRestorablePerAppCrashCapture &&
        SelectedRestorablePerAppCaptureReceipt is not null && !IsBusy;

    public string RestorableSettingsSummary
    {
        get
        {
            int appCount = RestorablePerAppCaptureReceipts.Count;
            if (HasRestorableCrashCapture && appCount > 0)
            {
                return $"Previous Windows crash-capture settings and settings for {appCount} app{(appCount == 1 ? string.Empty : "s")} are saved.";
            }
            if (HasRestorableCrashCapture)
            {
                return "Previous Windows crash-capture settings are saved.";
            }
            return $"Previous crash-dump settings for {appCount} app{(appCount == 1 ? string.Empty : "s")} are saved.";
        }
    }

    public bool ShowPerAppCrashCapture => _latestResult?.CanOfferPerAppCrashCapture == true;

    public bool CanEnablePerAppCrashCapture => _latestResult is { IsHistoricalReport: false } &&
        ShowPerAppCrashCapture && _diagnosticService.SupportsPerAppCrashCaptureApply &&
        !_canRestorePerAppCrashCapture && !IsBusy;

    public bool ShowEnablePerAppCrashCapture => ShowPerAppCrashCapture &&
        _diagnosticService.SupportsPerAppCrashCaptureApply &&
        !_canRestorePerAppCrashCapture;

    public bool CanRestorePerAppCrashCapture => _canRestorePerAppCrashCapture &&
        _latestResult is { IsHistoricalReport: false } &&
        !string.IsNullOrWhiteSpace(_perAppCrashCaptureReceiptId) && !IsBusy;

    public string PerAppCrashCaptureAvailability => ShowPerAppCrashCapture && _canRestorePerAppCrashCapture
            ? $"Full local crash dumps are enabled for {ResultTargetName}."
        : ShowPerAppCrashCapture && _diagnosticService.SupportsPerAppCrashCaptureApply &&
          _latestResult is { IsHistoricalReport: false }
            ? $"Optionally save full local dumps if {ResultTargetName} crashes. This is off by default."
            : ShowPerAppCrashCapture
            ? _latestResult is { IsHistoricalReport: true }
                ? "Run a new scan before changing app crash-dump settings."
                : "Per-app crash capture is not available in this build."
            : "Per-app crash capture is not offered for this target.";

    public string PerAppCrashCaptureMessage => _perAppCrashCaptureMessage;

    public bool HasPerAppCrashCaptureMessage => !string.IsNullOrWhiteSpace(PerAppCrashCaptureMessage);

    public bool IsPerAppCrashCaptureSuccess => HasPerAppCrashCaptureMessage &&
        _perAppCrashCaptureState is UiCrashPreparationState.Succeeded or UiCrashPreparationState.RolledBack;

    public bool IsPerAppCrashCaptureFailure => HasPerAppCrashCaptureMessage &&
        _perAppCrashCaptureState is UiCrashPreparationState.Failed or UiCrashPreparationState.Unavailable;

    public bool IsPerAppCrashCaptureNotice => HasPerAppCrashCaptureMessage &&
        !IsPerAppCrashCaptureSuccess && !IsPerAppCrashCaptureFailure;

    public bool CanPrepareCrashCapture => _latestResult is { IsHistoricalReport: false } &&
        _diagnosticService.SupportsCrashPreparation && !_canRestoreCrashPreparation && !IsBusy;

    public string CrashPreparationAvailability => _latestResult is { IsHistoricalReport: true }
        ? "This is a saved snapshot. Run a new scan before changing this PC."
        : _canRestoreCrashPreparation
            ? "PC Crash Diagnostic changed these settings earlier. You can restore the previous settings."
        : _diagnosticService.SupportsCrashPreparation
            ? "Review the exact plan first. Windows asks for administrator approval only when settings need to change."
            : "Automatic crash-capture setup is not available in this build.";

    public string CrashPreparationMessage => _crashPreparationMessage;

    public bool HasCrashPreparationMessage => !string.IsNullOrWhiteSpace(CrashPreparationMessage);

    public bool IsCrashPreparationSuccess => HasCrashPreparationMessage &&
        _crashPreparationState is UiCrashPreparationState.Succeeded or UiCrashPreparationState.RolledBack;

    public bool IsCrashPreparationFailure => HasCrashPreparationMessage &&
        _crashPreparationState is UiCrashPreparationState.Failed or UiCrashPreparationState.Unavailable;

    public bool IsCrashPreparationNotice => HasCrashPreparationMessage &&
        !IsCrashPreparationSuccess && !IsCrashPreparationFailure;

    public bool IsCrashPreparationPendingRestart => _crashPreparationState == UiCrashPreparationState.PendingRestart ||
        _crashReadiness.PendingRestart;

    public bool CanRestoreCrashPreparation => _canRestoreCrashPreparation &&
        _latestResult is { IsHistoricalReport: false } &&
        !string.IsNullOrWhiteSpace(_crashPreparationReceiptId) && !IsBusy;

    public string ExportStatus
    {
        get => _exportStatus;
        private set
        {
            if (SetProperty(ref _exportStatus, value))
            {
                OnPropertyChanged(nameof(HasExportStatus));
            }
        }
    }

    public bool HasExportStatus => !string.IsNullOrWhiteSpace(ExportStatus);

    public string SystemCoverageSummary
    {
        get => _systemCoverageSummary;
        private set => SetProperty(ref _systemCoverageSummary, value);
    }

    public string ReviewSummary => _latestResult?.Summary ?? string.Empty;
    public string OutgoingZipName => _latestResult is null ? "Report ZIP" : Path.GetFileName(_latestResult.ReportZipPath);
    public bool HasFindings => Findings.Count > 0;
    public bool HasNoFindings => _latestResult is not null && Findings.Count == 0;
    public bool HasCollectionIssues => CollectionIssues.Count > 0;
    public bool HasSystemCollectionIssues => SystemCollectionIssues.Count > 0;
    public bool HasPreviousReports => PreviousReports.Count > 0;
    public bool HasNoPreviousReports => StartPanel == StartPanel.PreviousReports && PreviousReports.Count == 0;
    public bool HasRecurringIncidentGroups => RecurringIncidentGroups.Count > 0;
    public bool HasDumpChoices => DumpChoices.Count > 0;
    public bool HasProtectedEvidenceSources => ProtectedEvidenceSources.Count > 0;
    public bool CanPackageDump => _latestResult is not null && SelectedDumpChoice is not null &&
        (_latestResult.CanPackageDump || SelectedDumpChoice.RequiresAdministratorAccess) && !IsBusy;
    public bool CanInspectProtectedDump => _latestResult is not null &&
        SelectedDumpChoice is { RequiresAdministratorAccess: true } && !IsBusy;
    public bool CanRunDumpCheck => _latestResult is { CanRunDumpCheck: true } &&
        SelectedDumpChoice is not null && !IsBusy;
    public bool CanRunDebugger => _latestResult is { CanRunDebugger: true } && SelectedDumpChoice is not null && !IsBusy;
    public bool CanRetryWithMicrosoftSymbols => _latestResult is { CanRetryWithMicrosoftSymbols: true } &&
        SelectedDumpChoice is not null && !IsBusy;
    public bool CanRetryProtectedEvidenceSource => _latestResult is not null &&
        SelectedProtectedEvidenceSource is not null && !IsBusy;

    public async Task InitializeAsync()
    {
        CancellationToken cancellationToken = _lifetimeCancellation.Token;
        try
        {
            UiSystemSnapshot snapshot = await _diagnosticService
                .GetSystemSnapshotAsync(cancellationToken)
                .ConfigureAwait(true);
            SystemFacts.Clear();
            foreach (UiSystemFact fact in snapshot.Facts)
            {
                SystemFacts.Add(fact);
            }

            SystemCollectionIssues.Clear();
            foreach (string issue in snapshot.CollectionIssues)
            {
                SystemCollectionIssues.Add(issue);
            }

            SystemCoverageSummary = FormatCoverage(snapshot.AvailableSourceCount, snapshot.TotalSourceCount);
            OnPropertyChanged(nameof(HasSystemCollectionIssues));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception)
        {
            SystemCoverageSummary = "System details could not be read.";
            SystemCollectionIssues.Add($"System details: {GetSafeMessage(exception)}");
            OnPropertyChanged(nameof(HasSystemCollectionIssues));
        }

        RefreshRunningProcesses();

        try
        {
            int legacyCount = await _diagnosticService.GetLegacyV2ReportCountAsync(cancellationToken).ConfigureAwait(true);
            if (legacyCount > 0)
            {
                bool import = _interactionService.ConfirmLegacyReportImport(legacyCount);
                int imported = await _diagnosticService
                    .CompleteLegacyV2ImportOfferAsync(import, cancellationToken)
                    .ConfigureAwait(true);
                if (import)
                {
                    _interactionService.ShowMessage(
                        "Earlier reports imported",
                        $"Imported {imported} validated report{(imported == 1 ? string.Empty : "s")}. The originals were not changed.");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception)
        {
            SystemCollectionIssues.Add($"Earlier report import: {GetSafeMessage(exception)}");
            OnPropertyChanged(nameof(HasSystemCollectionIssues));
        }

        try
        {
            _restorableConfigurationReceipts = await _diagnosticService
                .DiscoverRestorableConfigurationReceiptsAsync(cancellationToken)
                .ConfigureAwait(true);
            SynchronizeRestorableConfigurationUi();
            foreach (string warning in _restorableConfigurationReceipts.Warnings)
            {
                string message = $"Saved settings: {warning}";
                if (!SystemCollectionIssues.Contains(message))
                {
                    SystemCollectionIssues.Add(message);
                }
            }
            OnPropertyChanged(nameof(HasSystemCollectionIssues));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception)
        {
            SystemCollectionIssues.Add($"Saved settings: {GetSafeMessage(exception)}");
            OnPropertyChanged(nameof(HasSystemCollectionIssues));
        }

        try
        {
            IReadOnlyList<UiDiagnosticResult> recovered = await _diagnosticService
                .RecoverInterruptedSessionsAsync(new Progress<UiDiagnosticProgress>(OnProgress), cancellationToken)
                .ConfigureAwait(true);
            if (recovered.Count > 0)
            {
                ShowResult(recovered[^1]);
                StatusTitle = "Recovered report";
                StatusDetail = recovered.Count == 1
                    ? "Recovered an interrupted monitoring report."
                    : $"Recovered {recovered.Count} reports. The newest is open.";
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception)
        {
            SystemCollectionIssues.Add($"Report recovery: {GetSafeMessage(exception)}");
            OnPropertyChanged(nameof(HasSystemCollectionIssues));
        }
    }

    public void Dispose()
    {
        _lifetimeCancellation.Cancel();
        _operationCancellation?.Cancel();
        _operationCancellation?.Dispose();
        _lifetimeCancellation.Dispose();
        if (_diagnosticService is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    private async Task ShowIncidentSetupAsync(UiIncidentKind kind)
    {
        CurrentView = WorkflowView.Start;
        StartPanel = StartPanel.Incident;
        SelectedIncidentKind = kind;
        SetupMessage = string.Empty;
        await RefreshIncidentsAsync().ConfigureAwait(true);
    }

    private void ShowMonitorSetup()
    {
        CurrentView = WorkflowView.Start;
        StartPanel = StartPanel.Monitor;
        SetupMessage = "Choose the application to monitor.";
        RefreshRunningProcesses();
    }

    private async Task ShowPreviousReportsAsync()
    {
        CurrentView = WorkflowView.Start;
        StartPanel = StartPanel.PreviousReports;
        SetupMessage = "Loading saved reports…";
        PreviousReports.Clear();
        RecurringIncidentGroups.Clear();
        try
        {
            UiIncidentHistory history = await _diagnosticService
                .OpenPreviousReportsAsync(_lifetimeCancellation.Token)
                .ConfigureAwait(true);
            foreach (UiPreviousReport report in history.Reports)
            {
                PreviousReports.Add(report);
            }
            foreach (UiRecurringIncidentGroup group in history.RecurringGroups)
            {
                RecurringIncidentGroups.Add(group);
            }
            SelectedPreviousReport = PreviousReports.FirstOrDefault();
            SetupMessage = history.Reports.Count == 0
                ? "No saved reports were found."
                : $"{history.Reports.Count} saved report{(history.Reports.Count == 1 ? string.Empty : "s")}.";
            if (history.CollectionIssues.Count > 0)
            {
                SetupMessage += $" {history.CollectionIssues.Count} report file{(history.CollectionIssues.Count == 1 ? string.Empty : "s")} could not be read.";
            }
        }
        catch (Exception exception)
        {
            SetupMessage = GetSafeMessage(exception);
        }
        OnPropertyChanged(nameof(HasPreviousReports));
        OnPropertyChanged(nameof(HasNoPreviousReports));
        OnPropertyChanged(nameof(HasRecurringIncidentGroups));
    }

    private async Task RefreshIncidentsAsync()
    {
        SetupMessage = "Looking for recent Windows records…";
        RecentIncidents.Clear();
        SelectedIncident = null;
        try
        {
            var options = new UiIncidentSearchOptions(
                SelectedIncidentKind,
                IsApplicationIncident ? SelectedTarget : null,
                SelectedLookback.Duration);
            IReadOnlyList<UiIncidentCandidate> candidates = await _diagnosticService
                .FindRecentIncidentsAsync(options, _lifetimeCancellation.Token)
                .ConfigureAwait(true);
            foreach (UiIncidentCandidate candidate in candidates)
            {
                RecentIncidents.Add(candidate);
            }
            SelectedIncident = null;
            SetupMessage = candidates.Count == 0
                ? "No matching incident was found. You can enter the time instead."
                : "Choose the incident that matches what happened.";
        }
        catch (Exception exception)
        {
            SetupMessage = GetSafeMessage(exception);
        }
    }

    private async Task AnalyzeSelectedIncidentAsync()
    {
        DateTimeOffset? manualTime = null;
        if (UseManualCrashTime && !TryGetManualCrashTime(out manualTime))
        {
            return;
        }

        UiIncidentCandidate? candidate = SelectedIncident;
        if (UseAutomaticCrashTime && candidate is null)
        {
            SetupMessage = "Choose an incident or enter the time.";
            return;
        }

        var selection = new UiIncidentSelection(
            UseAutomaticCrashTime ? candidate!.CandidateId : "manual-time",
            SelectedIncidentKind,
            UseAutomaticCrashTime ? candidate!.AnchorUtc : manualTime,
            IsApplicationIncident ? SelectedTarget : null);
        string title = IsApplicationIncident ? "Reading application crash records" : "Reading Windows crash records";
        await RunDiagnosticAsync(
            title,
            "This may take a minute.",
            (progress, _, token) => _diagnosticService.AnalyzeIncidentAsync(selection, progress, token),
            isMonitoring: false).ConfigureAwait(true);
    }

    private void UseBattlefieldPreset()
    {
        SelectedTarget = UiTargetProfile.Battlefield6;
        SetupMessage = "Battlefield 6 selected.";
    }

    private void ChooseExecutable()
    {
        string? path = _interactionService.ChooseExecutablePath();
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        string processName = Path.GetFileNameWithoutExtension(path);
        SelectedTarget = new UiTargetProfile(
            "exe-" + CreateStableTargetId(path),
            processName,
            [processName],
            [processName, Path.GetFileName(path)],
            BlockSensitiveOperationsWhileRunning: true,
            UiTargetKind.Executable,
            path);
        SetupMessage = $"{processName}.exe selected.";
    }

    private void RefreshRunningProcesses()
    {
        try
        {
            RunningProcesses.Clear();
            foreach (UiRunningProcess process in _interactionService.GetRunningProcesses())
            {
                RunningProcesses.Add(process);
            }
            SelectedRunningProcess = RunningProcesses.FirstOrDefault();
        }
        catch (Exception exception)
        {
            SetupMessage = GetSafeMessage(exception);
        }
    }

    private void UseRunningProcess()
    {
        UiRunningProcess? process = SelectedRunningProcess;
        if (process is null)
        {
            SetupMessage = "Choose a running application.";
            return;
        }

        SelectedTarget = new UiTargetProfile(
            $"process-{process.ProcessName.ToLowerInvariant()}",
            process.ProcessName,
            [process.ProcessName],
            [process.ProcessName, process.ProcessName + ".exe"],
            BlockSensitiveOperationsWhileRunning: true,
            UiTargetKind.RunningProcess);
        SetupMessage = $"{process.ProcessName}.exe selected.";
    }

    private async Task StartMonitoringAsync()
    {
        await RunDiagnosticAsync(
            $"Waiting for {SelectedTarget.DisplayName}",
            $"Start {SelectedTarget.DisplayName} when ready. Leave this window open.",
            (progress, telemetry, token) => _diagnosticService.MonitorTargetAsync(SelectedTarget, progress, telemetry, token),
            isMonitoring: true).ConfigureAwait(true);
    }

    private async Task OpenPreviousReportAsync()
    {
        UiPreviousReport? report = SelectedPreviousReport;
        if (report is null)
        {
            SetupMessage = "Choose a saved report.";
            return;
        }

        CurrentView = WorkflowView.Collecting;
        IsBusy = true;
        IsMonitoring = false;
        StatusTitle = "Opening saved report";
        StatusDetail = Path.GetFileName(report.ZipPath);
        IsProgressIndeterminate = true;
        SetWorkflowPhase(3);
        try
        {
            UiDiagnosticResult result = await _diagnosticService
                .LoadPreviousReportAsync(report, _lifetimeCancellation.Token)
                .ConfigureAwait(true);
            ShowResult(result);
        }
        catch (Exception exception)
        {
            CurrentView = WorkflowView.Start;
            StartPanel = StartPanel.PreviousReports;
            SetupMessage = GetSafeMessage(exception);
        }
        finally
        {
            IsBusy = false;
            IsProgressIndeterminate = false;
        }
    }

    private async Task RunDiagnosticAsync(
        string initialStatus,
        string initialDetail,
        Func<IProgress<UiDiagnosticProgress>, IProgress<UiTelemetrySample>, CancellationToken, Task<UiDiagnosticResult>> operation,
        bool isMonitoring)
    {
        ResetForOperation(initialStatus, initialDetail, isMonitoring);
        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        var progress = new Progress<UiDiagnosticProgress>(OnProgress);
        var telemetry = new Progress<UiTelemetrySample>(OnTelemetry);

        try
        {
            UiDiagnosticResult result = await operation(progress, telemetry, cancellation.Token).ConfigureAwait(true);
            ShowResult(result);
        }
        catch (OperationCanceledException)
        {
            bool targetObserved = TelemetryHistory.Any(sample => sample.TargetPrivateGiB is not null);
            CurrentView = WorkflowView.Start;
            SetupMessage = isMonitoring && targetObserved
                ? "Monitoring stopped. The saved session can be recovered when the app starts again."
                : "Collection stopped. No report was created.";
        }
        catch (Exception exception)
        {
            CurrentView = WorkflowView.Start;
            SetupMessage = GetSafeMessage(exception);
            CollectionIssues.Add($"Diagnostic run: {GetSafeMessage(exception)}");
            OnPropertyChanged(nameof(HasCollectionIssues));
        }
        finally
        {
            _operationCancellation = null;
            IsBusy = false;
            IsMonitoring = false;
            IsProgressIndeterminate = false;
            cancellation.Cancel();
        }
    }

    private async Task PackageDumpAsync()
    {
        UiDiagnosticResult? result = _latestResult;
        UiDumpChoice? dump = SelectedDumpChoice;
        if (result is null || dump is null || !CanPackageDump || !_interactionService.ConfirmDumpPackaging())
        {
            return;
        }
        UiProtectedDumpConsent? protectedConsent = null;
        if (dump.RequiresAdministratorAccess)
        {
            protectedConsent = _interactionService.ConfirmProtectedDumpCopy(dump, "create a separate dump ZIP from");
            if (protectedConsent is null)
            {
                return;
            }
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        StatusTitle = "Creating crash dump ZIP";
        StatusDetail = "The standard report will not be changed.";
        IsProgressIndeterminate = true;

        try
        {
            string path = await _diagnosticService.PackageCrashDumpAsync(
                result,
                dump,
                protectedConsent,
                new Progress<UiDiagnosticProgress>(OnProgress),
                cancellation.Token).ConfigureAwait(true);
            ExportStatus = $"Created {Path.GetFileName(path)}. Crash dumps can contain private data.";
            _interactionService.ShowMessage("Crash dump ZIP ready", ExportStatus);
        }
        catch (OperationCanceledException)
        {
            ExportStatus = "Crash dump packaging stopped. The standard report was not changed.";
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("Couldn’t package the dump", GetSafeMessage(exception), isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsProgressIndeterminate = false;
            IsBusy = false;
        }
    }

    private async Task InspectProtectedDumpAsync()
    {
        UiDiagnosticResult? result = _latestResult;
        UiDumpChoice? dump = SelectedDumpChoice;
        if (result is null || dump is not { RequiresAdministratorAccess: true })
        {
            return;
        }
        UiProtectedDumpConsent? consent = _interactionService.ConfirmProtectedDumpCopy(dump, "inspect");
        if (consent is null)
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        StatusTitle = "Inspecting protected dump";
        StatusDetail = "Waiting for Windows administrator approval…";
        IsProgressIndeterminate = true;
        try
        {
            UiProtectedOperationResult operation = await _diagnosticService.InspectProtectedDumpAsync(
                result,
                dump,
                consent,
                new Progress<UiDiagnosticProgress>(OnProgress),
                cancellation.Token).ConfigureAwait(true);
            ExportStatus = operation.Message;
            _interactionService.ShowMessage(
                operation.Succeeded ? "Protected dump inspected" : "Protected dump was not inspected",
                operation.Message,
                isError: !operation.Succeeded);
        }
        catch (OperationCanceledException)
        {
            ExportStatus = "Protected dump inspection stopped; any private staging copy was removed.";
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("Protected dump inspection did not complete", GetSafeMessage(exception), isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsProgressIndeterminate = false;
            IsBusy = false;
        }
    }

    private async Task RetryProtectedSourceAsync()
    {
        UiDiagnosticResult? result = _latestResult;
        UiProtectedEvidenceSourceChoice? source = SelectedProtectedEvidenceSource;
        if (result is null || source is null || !_interactionService.ConfirmProtectedEvidenceRetry(source))
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        StatusTitle = "Retrying protected evidence";
        StatusDetail = "Waiting for Windows administrator approval…";
        IsProgressIndeterminate = true;
        try
        {
            UiDiagnosticResult updated = await _diagnosticService
                .RetryProtectedEvidenceSourceAsync(
                    result,
                    source,
                    new Progress<UiDiagnosticProgress>(OnProgress),
                    cancellation.Token)
                .ConfigureAwait(true);
            ShowResult(updated);
            ExportStatus = "Administrator retry completed. Results and source coverage were refreshed.";
            _interactionService.ShowMessage(
                "Protected evidence added",
                ExportStatus);
        }
        catch (OperationCanceledException)
        {
            ExportStatus = "Protected evidence retry stopped.";
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("Protected evidence retry did not complete", GetSafeMessage(exception), isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsProgressIndeterminate = false;
            IsBusy = false;
        }
    }

    private async Task PrepareCrashCaptureAsync()
    {
        UiDiagnosticResult? result = _latestResult;
        if (result is null || result.IsHistoricalReport || !_diagnosticService.SupportsCrashPreparation)
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        IsProgressIndeterminate = true;
        SetCrashPreparationState(
            UiCrashPreparationState.NotStarted,
            "Checking the current Windows crash-capture settings…");

        try
        {
            UiCrashPreparationPreview preview = await _diagnosticService
                .PreviewCrashCapturePreparationAsync(
                    result,
                    UiCrashPreparationPreset.Recommended,
                    includePerAppCapture: false,
                    cancellation.Token)
                .ConfigureAwait(true);
            if (!preview.CanProceed)
            {
                string reason = string.IsNullOrWhiteSpace(preview.BlockedReason)
                    ? "Windows crash capture could not be prepared."
                    : preview.BlockedReason;
                SetCrashPreparationState(UiCrashPreparationState.Unavailable, reason);
                _interactionService.ShowMessage("Crash capture was not changed", reason, isError: true);
                return;
            }

            if (!_interactionService.ConfirmCrashPreparation(preview))
            {
                SetCrashPreparationState(UiCrashPreparationState.NotStarted, "No settings were changed.");
                return;
            }

            StatusTitle = "Preparing Windows crash capture";
            StatusDetail = "Waiting for Windows administrator approval…";
            SetCrashPreparationState(
                UiCrashPreparationState.NotStarted,
                "Waiting for Windows administrator approval…");
            UiCrashPreparationOutcome outcome = await _diagnosticService
                .PrepareCrashCaptureAsync(
                    result,
                    preview,
                    new Progress<UiDiagnosticProgress>(OnProgress),
                    cancellation.Token)
                .ConfigureAwait(true);
            ApplyCrashPreparationOutcome(outcome);
            _interactionService.ShowMessage(
                CrashPreparationResultTitle(outcome.State),
                outcome.Message,
                isError: outcome.State is UiCrashPreparationState.Failed or UiCrashPreparationState.Unavailable);
        }
        catch (OperationCanceledException)
        {
            SetCrashPreparationState(UiCrashPreparationState.Failed, "Crash-capture preparation was cancelled. Any partial change was rolled back when possible.");
        }
        catch (Exception exception)
        {
            string message = GetSafeMessage(exception);
            SetCrashPreparationState(UiCrashPreparationState.Failed, message);
            _interactionService.ShowMessage("Crash capture was not prepared", message, isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsProgressIndeterminate = false;
            IsBusy = false;
        }
    }

    private Task RestoreCrashCaptureAsync() =>
        RestoreCrashCaptureByReceiptAsync(_crashPreparationReceiptId);

    private Task RestoreSavedCrashCaptureAsync() =>
        RestoreCrashCaptureByReceiptAsync(_restorableConfigurationReceipts.CrashCaptureReceiptId);

    private async Task RestoreCrashCaptureByReceiptAsync(string? receiptId)
    {
        if (string.IsNullOrWhiteSpace(receiptId) ||
            !_interactionService.ConfirmCrashPreparationRestore())
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        IsProgressIndeterminate = true;
        StatusTitle = "Restoring crash-capture settings";
        StatusDetail = "Waiting for Windows administrator approval…";
        SetCrashPreparationState(UiCrashPreparationState.NotStarted, StatusDetail);
        try
        {
            UiCrashPreparationOutcome outcome = await _diagnosticService
                .RestoreCrashCaptureAsync(
                    receiptId,
                    new Progress<UiDiagnosticProgress>(OnProgress),
                    cancellation.Token)
                .ConfigureAwait(true);
            ApplyCrashPreparationOutcome(outcome);
            _interactionService.ShowMessage(
                CrashPreparationResultTitle(outcome.State),
                outcome.Message,
                isError: outcome.State is UiCrashPreparationState.Failed or UiCrashPreparationState.Unavailable);
        }
        catch (OperationCanceledException)
        {
            SetCrashPreparationState(UiCrashPreparationState.Failed, "The restore was cancelled.");
        }
        catch (Exception exception)
        {
            string message = GetSafeMessage(exception);
            SetCrashPreparationState(UiCrashPreparationState.Failed, message);
            _interactionService.ShowMessage("Settings were not restored", message, isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsProgressIndeterminate = false;
            IsBusy = false;
        }
    }

    private async Task EnablePerAppCrashCaptureAsync()
    {
        UiDiagnosticResult? result = _latestResult;
        if (result is null || !CanEnablePerAppCrashCapture ||
            !_interactionService.ConfirmOrdinaryAppForCrashCapture(ResultTargetName))
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        IsProgressIndeterminate = true;
        SetPerAppCrashCaptureMessage("Checking the current app crash-dump settings…", UiCrashPreparationState.NotStarted);
        try
        {
            UiCrashPreparationPreview preview = await _diagnosticService
                .PreviewPerAppCrashCaptureAsync(
                    result,
                    ordinaryAppConfirmed: true,
                    cancellationToken: cancellation.Token)
                .ConfigureAwait(true);
            if (!preview.CanProceed)
            {
                string reason = string.IsNullOrWhiteSpace(preview.BlockedReason)
                    ? "Per-app crash capture could not be enabled."
                    : preview.BlockedReason;
                SetPerAppCrashCaptureMessage(reason, UiCrashPreparationState.Unavailable);
                _interactionService.ShowMessage("App crash dumps were not enabled", reason, isError: true);
                return;
            }
            if (!_interactionService.ConfirmCrashPreparation(preview))
            {
                SetPerAppCrashCaptureMessage("No app crash-dump settings were changed.", UiCrashPreparationState.NotStarted);
                return;
            }

            StatusTitle = "Enabling app crash dumps";
            StatusDetail = "Waiting for Windows administrator approval…";
            SetPerAppCrashCaptureMessage(StatusDetail, UiCrashPreparationState.NotStarted);
            UiCrashPreparationOutcome outcome = await _diagnosticService
                .EnablePerAppCrashCaptureAsync(
                    result,
                    preview,
                    new Progress<UiDiagnosticProgress>(OnProgress),
                    cancellation.Token)
                .ConfigureAwait(true);
            if (outcome.State is UiCrashPreparationState.Failed or UiCrashPreparationState.Unavailable)
            {
                outcome = outcome with
                {
                    Message = outcome.Message +
                        $" If {ResultTargetName} was not open, start it normally and try again; it does not need to crash or be used during setup."
                };
            }
            ApplyPerAppCrashCaptureOutcome(outcome);
            _interactionService.ShowMessage(
                outcome.State == UiCrashPreparationState.Succeeded
                    ? "Full app crash dumps enabled"
                    : "App crash dumps were not enabled",
                outcome.Message,
                isError: outcome.State is UiCrashPreparationState.Failed or UiCrashPreparationState.Unavailable);
        }
        catch (OperationCanceledException)
        {
            SetPerAppCrashCaptureMessage("App crash-dump setup was cancelled.", UiCrashPreparationState.Failed);
        }
        catch (Exception exception)
        {
            string message = GetSafeMessage(exception);
            SetPerAppCrashCaptureMessage(message, UiCrashPreparationState.Failed);
            _interactionService.ShowMessage("App crash dumps were not enabled", message, isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsProgressIndeterminate = false;
            IsBusy = false;
        }
    }

    private Task RestorePerAppCrashCaptureAsync() =>
        RestorePerAppCrashCaptureByReceiptAsync(_perAppCrashCaptureReceiptId, ResultTargetName);

    private Task RestoreSavedPerAppCrashCaptureAsync()
    {
        UiRestorablePerAppCaptureReceipt? receipt = SelectedRestorablePerAppCaptureReceipt;
        return receipt is null
            ? Task.CompletedTask
            : RestorePerAppCrashCaptureByReceiptAsync(receipt.ReceiptId, receipt.DisplayName);
    }

    private async Task RestorePerAppCrashCaptureByReceiptAsync(string? receiptId, string displayName)
    {
        if (string.IsNullOrWhiteSpace(receiptId) ||
            !_interactionService.ConfirmPerAppCrashCaptureRestore(displayName))
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        IsProgressIndeterminate = true;
        StatusTitle = "Restoring app crash-dump settings";
        StatusDetail = "Waiting for Windows administrator approval…";
        SetPerAppCrashCaptureMessage(StatusDetail, UiCrashPreparationState.NotStarted);
        try
        {
            UiCrashPreparationOutcome outcome = await _diagnosticService
                .RestorePerAppCrashCaptureAsync(
                    receiptId,
                    new Progress<UiDiagnosticProgress>(OnProgress),
                    cancellation.Token)
                .ConfigureAwait(true);
            ApplyPerAppCrashCaptureOutcome(outcome, receiptId);
            _interactionService.ShowMessage(
                outcome.State == UiCrashPreparationState.RolledBack
                    ? "Earlier app settings restored"
                    : "App settings were not restored",
                outcome.Message,
                isError: outcome.State is UiCrashPreparationState.Failed or UiCrashPreparationState.Unavailable);
        }
        catch (OperationCanceledException)
        {
            SetPerAppCrashCaptureMessage("The app crash-dump restore was cancelled.", UiCrashPreparationState.Failed);
        }
        catch (Exception exception)
        {
            string message = GetSafeMessage(exception);
            SetPerAppCrashCaptureMessage(message, UiCrashPreparationState.Failed);
            _interactionService.ShowMessage("App settings were not restored", message, isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsProgressIndeterminate = false;
            IsBusy = false;
        }
    }

    private void ApplyPerAppCrashCaptureOutcome(
        UiCrashPreparationOutcome outcome,
        string? restoredReceiptId = null)
    {
        if (outcome.VerifiedReadiness is not null)
        {
            SetCrashReadiness(outcome.VerifiedReadiness);
        }

        string? previousReceiptId = restoredReceiptId ?? _perAppCrashCaptureReceiptId;
        if (outcome.CanRestore && !string.IsNullOrWhiteSpace(outcome.ReceiptId))
        {
            _perAppCrashCaptureReceiptId = outcome.ReceiptId;
            _canRestorePerAppCrashCapture = true;
            RememberPerAppReceipt(outcome.ReceiptId);
        }
        else if (outcome.State == UiCrashPreparationState.RolledBack)
        {
            if (string.Equals(
                    _perAppCrashCaptureReceiptId,
                    previousReceiptId,
                    StringComparison.OrdinalIgnoreCase))
            {
                _perAppCrashCaptureReceiptId = null;
                _canRestorePerAppCrashCapture = false;
            }
            ForgetPerAppReceipt(previousReceiptId);
        }
        SetPerAppCrashCaptureMessage(outcome.Message, outcome.State);
        OnPropertyChanged(nameof(CanEnablePerAppCrashCapture));
        OnPropertyChanged(nameof(ShowEnablePerAppCrashCapture));
        OnPropertyChanged(nameof(CanRestorePerAppCrashCapture));
        OnPropertyChanged(nameof(PerAppCrashCaptureAvailability));
        SynchronizeRestorableConfigurationUi();
        RaiseCommandStates();
    }

    private void SetPerAppCrashCaptureMessage(string message, UiCrashPreparationState state)
    {
        _perAppCrashCaptureMessage = message;
        _perAppCrashCaptureState = state;
        OnPropertyChanged(nameof(PerAppCrashCaptureMessage));
        OnPropertyChanged(nameof(HasPerAppCrashCaptureMessage));
        OnPropertyChanged(nameof(IsPerAppCrashCaptureSuccess));
        OnPropertyChanged(nameof(IsPerAppCrashCaptureFailure));
        OnPropertyChanged(nameof(IsPerAppCrashCaptureNotice));
    }

    private void ApplyCrashPreparationOutcome(UiCrashPreparationOutcome outcome)
    {
        if (outcome.UpdatedResult is not null)
        {
            ShowResult(outcome.UpdatedResult);
        }
        if (outcome.VerifiedReadiness is not null)
        {
            SetCrashReadiness(outcome.VerifiedReadiness);
        }

        if (outcome.CanRestore && !string.IsNullOrWhiteSpace(outcome.ReceiptId))
        {
            _crashPreparationReceiptId = outcome.ReceiptId;
            _canRestoreCrashPreparation = true;
            _restorableConfigurationReceipts = _restorableConfigurationReceipts with
            {
                CrashCaptureReceiptId = outcome.ReceiptId
            };
        }
        else if (outcome.State == UiCrashPreparationState.RolledBack)
        {
            _crashPreparationReceiptId = null;
            _canRestoreCrashPreparation = false;
            _restorableConfigurationReceipts = _restorableConfigurationReceipts with
            {
                CrashCaptureReceiptId = null
            };
        }
        SetCrashPreparationState(outcome.State, outcome.Message);
        SynchronizeRestorableConfigurationUi();
        OnPropertyChanged(nameof(CanRestoreCrashPreparation));
        OnPropertyChanged(nameof(CanPrepareCrashCapture));
        OnPropertyChanged(nameof(CrashPreparationAvailability));
        RaiseCommandStates();
    }

    private void SetCrashPreparationState(UiCrashPreparationState state, string message)
    {
        _crashPreparationState = state;
        _crashPreparationMessage = message;
        OnPropertyChanged(nameof(CrashPreparationMessage));
        OnPropertyChanged(nameof(HasCrashPreparationMessage));
        OnPropertyChanged(nameof(IsCrashPreparationSuccess));
        OnPropertyChanged(nameof(IsCrashPreparationFailure));
        OnPropertyChanged(nameof(IsCrashPreparationNotice));
        OnPropertyChanged(nameof(IsCrashPreparationPendingRestart));
    }

    private static string CrashPreparationResultTitle(UiCrashPreparationState state) => state switch
    {
        UiCrashPreparationState.Succeeded => "Crash capture is ready",
        UiCrashPreparationState.PendingRestart => "Restart needed",
        UiCrashPreparationState.RolledBack => "Earlier settings restored",
        UiCrashPreparationState.Unavailable => "Crash capture was not changed",
        _ => "Crash-capture preparation did not complete"
    };

    private Task RetryWithSymbolsAsync()
    {
        if (!_interactionService.ConfirmMicrosoftSymbolDownload())
        {
            return Task.CompletedTask;
        }

        return RunDebuggerAsync(true);
    }

    private async Task RunDumpCheckAsync()
    {
        UiDiagnosticResult? result = _latestResult;
        UiDumpChoice? dump = SelectedDumpChoice;
        if (result is null || dump is null)
        {
            return;
        }

        UiProtectedDumpConsent? protectedConsent = null;
        if (dump.RequiresAdministratorAccess)
        {
            protectedConsent = _interactionService.ConfirmProtectedDumpCopy(dump, "run DumpChk against");
            if (protectedConsent is null)
            {
                return;
            }
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        StatusTitle = "Checking the selected dump";
        StatusDetail = "DumpChk runs locally and the dump stays on this PC.";
        IsProgressIndeterminate = true;
        try
        {
            UiDiagnosticResult updated = await _diagnosticService.RunDumpCheckAsync(
                result,
                dump,
                protectedConsent,
                new Progress<UiDiagnosticProgress>(OnProgress),
                cancellation.Token).ConfigureAwait(true);
            ShowResult(updated);
            ExportStatus = "The DumpChk result was added to a new local report.";
        }
        catch (OperationCanceledException)
        {
            ExportStatus = "DumpChk stopped; any private staging copy was removed.";
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("DumpChk did not complete", GetSafeMessage(exception), isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsBusy = false;
            IsProgressIndeterminate = false;
        }
    }

    private async Task RunDebuggerAsync(bool allowMicrosoftSymbols)
    {
        UiDiagnosticResult? result = _latestResult;
        UiDumpChoice? dump = SelectedDumpChoice;
        if (result is null || dump is null)
        {
            return;
        }
        UiProtectedDumpConsent? protectedConsent = null;
        if (dump.RequiresAdministratorAccess)
        {
            protectedConsent = _interactionService.ConfirmProtectedDumpCopy(dump, "run WinDbg against");
            if (protectedConsent is null)
            {
                return;
            }
        }

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        IsBusy = true;
        StatusTitle = allowMicrosoftSymbols ? "Retrying WinDbg with Microsoft symbols" : "Running WinDbg offline";
        StatusDetail = "The dump stays on this PC.";
        IsProgressIndeterminate = true;
        try
        {
            UiDiagnosticResult updated = await _diagnosticService.RunDebuggerAnalysisAsync(
                result,
                dump,
                allowMicrosoftSymbols,
                protectedConsent,
                new Progress<UiDiagnosticProgress>(OnProgress),
                cancellation.Token).ConfigureAwait(true);
            ShowResult(updated);
            string state = updated.Summary.Contains("DebuggerNotFound", StringComparison.OrdinalIgnoreCase)
                ? "No installed Microsoft debugger was found."
                : "The structured WinDbg result was added to a new report.";
            ExportStatus = state;
        }
        catch (OperationCanceledException)
        {
            ExportStatus = "WinDbg analysis stopped.";
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("WinDbg analysis did not complete", GetSafeMessage(exception), isError: true);
        }
        finally
        {
            _operationCancellation = null;
            IsBusy = false;
            IsProgressIndeterminate = false;
        }
    }

    private void ResetForOperation(string initialStatus, string initialDetail, bool isMonitoring)
    {
        CurrentView = WorkflowView.Collecting;
        IsBusy = true;
        IsMonitoring = isMonitoring;
        StatusTitle = initialStatus;
        StatusDetail = initialDetail;
        IsProgressIndeterminate = true;
        ProgressValue = 0;
        Findings.Clear();
        CollectionIssues.Clear();
        TelemetryHistory.Clear();
        DumpChoices.Clear();
        ProtectedEvidenceSources.Clear();
        _selectedDumpChoice = null;
        _selectedProtectedEvidenceSource = null;
        _crashPreparationReceiptId = null;
        _canRestoreCrashPreparation = false;
        _perAppCrashCaptureReceiptId = null;
        _canRestorePerAppCrashCapture = false;
        SetPerAppCrashCaptureMessage(string.Empty, UiCrashPreparationState.NotStarted);
        SetCrashReadiness(UiCrashReadiness.Missing(null, false));
        SetCrashPreparationState(UiCrashPreparationState.NotStarted, string.Empty);
        TelemetryCards[0].Value = "—";
        TelemetryCards[1].Value = "—";
        TelemetryCards[2].Value = isMonitoring ? "Waiting for app" : "Not sampled";
        TelemetryCards[3].Value = isMonitoring ? "Waiting for app" : "Not sampled";
        LastUpdatedText = isMonitoring ? "Waiting for first sample" : "Live sampling is not used";
        ExportStatus = string.Empty;
        SetWorkflowPhase(2);
        OnPropertyChanged(nameof(HasFindings));
        OnPropertyChanged(nameof(HasNoFindings));
        OnPropertyChanged(nameof(HasCollectionIssues));
        OnPropertyChanged(nameof(CanPackageDump));
        OnPropertyChanged(nameof(HasDumpChoices));
        OnPropertyChanged(nameof(HasProtectedEvidenceSources));
        OnPropertyChanged(nameof(CanInspectProtectedDump));
        OnPropertyChanged(nameof(CanRunDumpCheck));
        OnPropertyChanged(nameof(CanRunDebugger));
        OnPropertyChanged(nameof(CanRetryWithMicrosoftSymbols));
        OnPropertyChanged(nameof(CanPrepareCrashCapture));
        OnPropertyChanged(nameof(CanRestoreCrashPreparation));
    }

    private void ShowResult(UiDiagnosticResult result)
    {
        bool sameSession = _latestResult is not null &&
            string.Equals(_latestResult.SessionId, result.SessionId, StringComparison.OrdinalIgnoreCase);
        _latestResult = result;
        if (!sameSession)
        {
            _crashPreparationReceiptId = null;
            _canRestoreCrashPreparation = false;
            _perAppCrashCaptureReceiptId = null;
            _canRestorePerAppCrashCapture = false;
            SetPerAppCrashCaptureMessage(string.Empty, UiCrashPreparationState.NotStarted);
            SetCrashPreparationState(UiCrashPreparationState.NotStarted, string.Empty);
            SetCrashReadiness(result.CrashReadiness ?? UiCrashReadiness.Missing(result.EndUtc, result.IsHistoricalReport));
            HydrateRestorableConfigurationForResult(result);
        }
        DumpChoices.Clear();
        foreach (UiDumpChoice choice in result.DumpChoices ?? [])
        {
            DumpChoices.Add(choice);
        }
        ProtectedEvidenceSources.Clear();
        foreach (UiProtectedEvidenceSourceChoice source in result.ProtectedEvidenceSources ?? [])
        {
            ProtectedEvidenceSources.Add(source);
        }
        SelectedProtectedEvidenceSource = ProtectedEvidenceSources.FirstOrDefault();
        SelectedDumpChoice = !string.IsNullOrWhiteSpace(result.EligibleDumpPath)
            ? DumpChoices.FirstOrDefault(choice => string.Equals(choice.Path, result.EligibleDumpPath, StringComparison.OrdinalIgnoreCase))
            : null;
        Findings.Clear();
        int displayRank = 1;
        foreach (UiFinding finding in result.Findings.OrderBy(finding => finding.Rank))
        {
            Findings.Add(new FindingViewModel(finding, displayRank++));
        }

        CollectionIssues.Clear();
        foreach (string issue in result.CollectionIssues.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            CollectionIssues.Add(issue);
        }
        foreach (string warning in _restorableConfigurationReceipts.Warnings)
        {
            string message = $"Saved settings: {warning}";
            if (!CollectionIssues.Contains(message))
            {
                CollectionIssues.Add(message);
            }
        }

        CoverageSummary = FormatCoverage(result.AvailableSourceCount, result.TotalSourceCount);
        ResultIncidentTitle = result.IncidentTitle;
        ResultCompletionDetail = result.CompletionDetail;
        ResultTargetName = result.TargetDisplayName;
        ResultTimeRange = $"{result.StartUtc.ToLocalTime():MMM d, h:mm tt} – {result.EndUtc.ToLocalTime():MMM d, h:mm tt} local";
        StatusTitle = "Report ready";
        StatusDetail = Findings.Count == 0
            ? "No cause was identified in the Windows records this app could read."
            : $"{Findings.Count} evidence item{(Findings.Count == 1 ? string.Empty : "s")} found.";
        LastUpdatedText = TelemetryHistory.Count == 0 ? "No live samples" : $"Completed {DateTime.Now:g}";
        ProgressValue = 100;
        IsProgressIndeterminate = false;
        SetWorkflowPhase(4);
        CurrentView = WorkflowView.Results;
        OnPropertyChanged(nameof(ReviewSummary));
        OnPropertyChanged(nameof(OutgoingZipName));
        OnPropertyChanged(nameof(HasFindings));
        OnPropertyChanged(nameof(HasNoFindings));
        OnPropertyChanged(nameof(HasCollectionIssues));
        OnPropertyChanged(nameof(CanPackageDump));
        OnPropertyChanged(nameof(HasDumpChoices));
        OnPropertyChanged(nameof(HasProtectedEvidenceSources));
        OnPropertyChanged(nameof(CanInspectProtectedDump));
        OnPropertyChanged(nameof(CanRunDumpCheck));
        OnPropertyChanged(nameof(CanRunDebugger));
        OnPropertyChanged(nameof(CanRetryWithMicrosoftSymbols));
        OnPropertyChanged(nameof(ShowPerAppCrashCapture));
        OnPropertyChanged(nameof(CanEnablePerAppCrashCapture));
        OnPropertyChanged(nameof(ShowEnablePerAppCrashCapture));
        OnPropertyChanged(nameof(CanRestorePerAppCrashCapture));
        OnPropertyChanged(nameof(PerAppCrashCaptureAvailability));
        OnPropertyChanged(nameof(PerAppCrashCaptureMessage));
        OnPropertyChanged(nameof(HasPerAppCrashCaptureMessage));
        OnPropertyChanged(nameof(CanPrepareCrashCapture));
        OnPropertyChanged(nameof(CrashPreparationAvailability));
        OnPropertyChanged(nameof(CanRestoreCrashPreparation));
    }

    private void HydrateRestorableConfigurationForResult(UiDiagnosticResult result)
    {
        if (!result.IsHistoricalReport &&
            !string.IsNullOrWhiteSpace(_restorableConfigurationReceipts.CrashCaptureReceiptId))
        {
            _crashPreparationReceiptId = _restorableConfigurationReceipts.CrashCaptureReceiptId;
            _canRestoreCrashPreparation = true;
            SetCrashPreparationState(
                UiCrashPreparationState.NotStarted,
                "Earlier Windows crash-capture settings are saved and can be restored.");
        }

        UiRestorablePerAppCaptureReceipt? perAppReceipt = FindPerAppReceipt(result);
        if (!result.IsHistoricalReport && perAppReceipt is not null)
        {
            _perAppCrashCaptureReceiptId = perAppReceipt.ReceiptId;
            _canRestorePerAppCrashCapture = true;
            SetPerAppCrashCaptureMessage(
                $"Full local crash dumps are enabled for {result.TargetDisplayName}. Earlier settings can be restored.",
                UiCrashPreparationState.Succeeded);
        }
    }

    private UiRestorablePerAppCaptureReceipt? FindPerAppReceipt(UiDiagnosticResult result)
    {
        if (!result.CanOfferPerAppCrashCapture)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(result.TargetProfileId))
        {
            UiRestorablePerAppCaptureReceipt? profileMatch = _restorableConfigurationReceipts.PerAppCaptureReceipts
                .FirstOrDefault(receipt => string.Equals(
                    receipt.TargetProfileId,
                    result.TargetProfileId,
                    StringComparison.OrdinalIgnoreCase));
            if (profileMatch is not null)
            {
                return profileMatch;
            }
        }

        string[] resultExecutables = (result.TargetExecutableNames ?? [])
            .Select(NormalizeExecutableName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return _restorableConfigurationReceipts.PerAppCaptureReceipts.FirstOrDefault(receipt =>
            receipt.TargetExecutableNames
                .Append(receipt.ExecutableName)
                .Select(NormalizeExecutableName)
                .Any(name => resultExecutables.Contains(name, StringComparer.OrdinalIgnoreCase)));
    }

    private void RememberPerAppReceipt(string receiptId)
    {
        if (_latestResult is null)
        {
            return;
        }

        string[] executables = (_latestResult.TargetExecutableNames ?? [])
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        string executable = executables.FirstOrDefault() ?? _latestResult.TargetDisplayName;
        var remembered = new UiRestorablePerAppCaptureReceipt(
            receiptId,
            executable,
            _latestResult.TargetDisplayName,
            DateTimeOffset.UtcNow,
            _latestResult.TargetProfileId,
            executables);
        UiRestorablePerAppCaptureReceipt[] receipts = _restorableConfigurationReceipts.PerAppCaptureReceipts
            .Where(receipt => !string.Equals(receipt.ReceiptId, receiptId, StringComparison.OrdinalIgnoreCase) &&
                              (string.IsNullOrWhiteSpace(_latestResult.TargetProfileId) ||
                               !string.Equals(receipt.TargetProfileId, _latestResult.TargetProfileId, StringComparison.OrdinalIgnoreCase)) &&
                              !receipt.TargetExecutableNames
                                  .Append(receipt.ExecutableName)
                                  .Select(NormalizeExecutableName)
                                  .Any(name => executables
                                      .Select(NormalizeExecutableName)
                                      .Contains(name, StringComparer.OrdinalIgnoreCase)))
            .Append(remembered)
            .ToArray();
        _restorableConfigurationReceipts = _restorableConfigurationReceipts with
        {
            PerAppCaptureReceipts = receipts
        };
    }

    private void ForgetPerAppReceipt(string? receiptId)
    {
        if (string.IsNullOrWhiteSpace(receiptId))
        {
            return;
        }

        _restorableConfigurationReceipts = _restorableConfigurationReceipts with
        {
            PerAppCaptureReceipts = _restorableConfigurationReceipts.PerAppCaptureReceipts
                .Where(receipt => !string.Equals(receipt.ReceiptId, receiptId, StringComparison.OrdinalIgnoreCase))
                .ToArray()
        };
    }

    private static string NormalizeExecutableName(string value) =>
        Path.GetFileNameWithoutExtension(value.Trim());

    private void SynchronizeRestorableConfigurationUi()
    {
        string? selectedReceiptId = SelectedRestorablePerAppCaptureReceipt?.ReceiptId;
        RestorablePerAppCaptureReceipts.Clear();
        foreach (UiRestorablePerAppCaptureReceipt receipt in _restorableConfigurationReceipts.PerAppCaptureReceipts
                     .OrderByDescending(receipt => receipt.AppliedUtc))
        {
            RestorablePerAppCaptureReceipts.Add(receipt);
        }
        SelectedRestorablePerAppCaptureReceipt = RestorablePerAppCaptureReceipts.FirstOrDefault(receipt =>
                string.Equals(receipt.ReceiptId, selectedReceiptId, StringComparison.OrdinalIgnoreCase))
            ?? RestorablePerAppCaptureReceipts.FirstOrDefault();
        OnPropertyChanged(nameof(HasRestorableSettings));
        OnPropertyChanged(nameof(HasRestorableCrashCapture));
        OnPropertyChanged(nameof(HasRestorablePerAppCrashCapture));
        OnPropertyChanged(nameof(CanRestoreSavedCrashCapture));
        OnPropertyChanged(nameof(CanRestoreSavedPerAppCrashCapture));
        OnPropertyChanged(nameof(RestorableSettingsSummary));
        _restoreSavedCrashCaptureCommand.RaiseCanExecuteChanged();
        _restoreSavedPerAppCrashCaptureCommand.RaiseCanExecuteChanged();
    }

    private void SetCrashReadiness(UiCrashReadiness readiness)
    {
        _crashReadiness = readiness;
        if (_latestResult is { IsHistoricalReport: false })
        {
            _latestResult = _latestResult with { CrashReadiness = readiness };
        }
        OnPropertyChanged(nameof(CrashReadinessStatus));
        OnPropertyChanged(nameof(CrashReadinessDumpType));
        OnPropertyChanged(nameof(CrashReadinessDetail));
        OnPropertyChanged(nameof(CrashReadinessBackingStorage));
        OnPropertyChanged(nameof(CrashReadinessFreeSpace));
        OnPropertyChanged(nameof(CrashReadinessEventLogging));
        OnPropertyChanged(nameof(CrashReadinessAutomaticRestart));
        OnPropertyChanged(nameof(CrashReadinessCapturedText));
        OnPropertyChanged(nameof(IsHistoricalCrashReadiness));
        OnPropertyChanged(nameof(IsCurrentCrashReadiness));
        OnPropertyChanged(nameof(IsCrashPreparationPendingRestart));
    }

    private void OnProgress(UiDiagnosticProgress progress)
    {
        string stage = NormalizeTargetText(progress.Stage);
        string message = NormalizeTargetText(progress.Message);
        StatusTitle = string.IsNullOrWhiteSpace(stage) ? StatusTitle : stage;
        StatusDetail = message;
        IsProgressIndeterminate = progress.Percent is null;
        if (progress.Percent is not null)
        {
            ProgressValue = Math.Clamp(progress.Percent.Value, 0, 100);
        }

        if (stage.Contains("report", StringComparison.OrdinalIgnoreCase))
        {
            SetWorkflowPhase(4);
        }
        else if (stage.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                 stage.Contains("analysis", StringComparison.OrdinalIgnoreCase) ||
                 stage.Contains("final", StringComparison.OrdinalIgnoreCase) ||
                 stage.Contains("packag", StringComparison.OrdinalIgnoreCase))
        {
            SetWorkflowPhase(3);
        }
        else
        {
            SetWorkflowPhase(2);
        }

        if (!string.IsNullOrWhiteSpace(progress.CollectionIssue) &&
            !CollectionIssues.Contains(progress.CollectionIssue))
        {
            CollectionIssues.Add(progress.CollectionIssue);
            OnPropertyChanged(nameof(HasCollectionIssues));
        }
    }

    private void OnTelemetry(UiTelemetrySample sample)
    {
        TelemetryHistory.Add(sample);
        while (TelemetryHistory.Count > 120)
        {
            TelemetryHistory.RemoveAt(0);
        }

        TelemetryCards[0].Value = FormatPercent(sample.SystemRamPercent);
        TelemetryCards[1].Value = FormatPercent(sample.CommitPercent);
        TelemetryCards[2].Value = FormatGiB(sample.TargetPrivateGiB, "App not detected");
        TelemetryCards[3].Value = FormatGiB(sample.TargetGpuGiB, "Counter unavailable");
        LastUpdatedText = $"Sampled {sample.Timestamp.LocalDateTime:T}";
    }

    private void SetWorkflowPhase(int phase)
    {
        for (int index = 0; index < WorkflowSteps.Count; index++)
        {
            WorkflowStepViewModel step = WorkflowSteps[index];
            int stepNumber = index + 1;
            step.IsComplete = stepNumber < phase || phase >= 4;
            step.IsCurrent = stepNumber == phase && phase < 4;
            step.State = step.IsComplete ? "Complete" : step.IsCurrent ? "Current" : "Waiting";
        }
    }

    private bool TryGetManualCrashTime(out DateTimeOffset? crashTime)
    {
        crashTime = null;
        if (SelectedCrashDate is null)
        {
            ManualTimeValidation = "Choose the date when the crash occurred.";
            return false;
        }

        if (!DateTime.TryParse(ManualCrashTimeText, CultureInfo.CurrentCulture, DateTimeStyles.AllowWhiteSpaces, out DateTime time))
        {
            ManualTimeValidation = "Enter a time such as 10:45 PM.";
            return false;
        }

        DateTime local = DateTime.SpecifyKind(SelectedCrashDate.Value.Date.Add(time.TimeOfDay), DateTimeKind.Unspecified);
        TimeZoneInfo localZone = TimeZoneInfo.Local;
        if (localZone.IsInvalidTime(local))
        {
            ManualTimeValidation = "That local time did not occur because the clocks moved forward.";
            return false;
        }
        if (localZone.IsAmbiguousTime(local))
        {
            ManualTimeValidation = "That local time occurred twice. Choose a time outside the repeated hour.";
            return false;
        }

        var selected = new DateTimeOffset(local, localZone.GetUtcOffset(local));
        if (selected > DateTimeOffset.Now.AddMinutes(5))
        {
            ManualTimeValidation = "The crash time cannot be in the future.";
            return false;
        }

        crashTime = selected;
        ManualTimeValidation = string.Empty;
        return true;
    }

    private void CancelOperation() => _operationCancellation?.Cancel();

    private void OpenReviewExport()
    {
        ExportStatus = string.Empty;
        CurrentView = WorkflowView.ReviewExport;
    }

    private void StartOver()
    {
        CurrentView = WorkflowView.Start;
        StartPanel = StartPanel.None;
        SetupMessage = string.Empty;
        StatusTitle = "Ready";
        StatusDetail = "Choose what happened.";
    }

    private void CopySummary()
    {
        if (_latestResult is null)
        {
            return;
        }
        try
        {
            _interactionService.CopyText(_latestResult.Summary);
            ExportStatus = "Summary copied.";
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("Couldn’t copy the summary", GetSafeMessage(exception), isError: true);
        }
    }

    private void ExportReport()
    {
        if (_latestResult is null)
        {
            return;
        }
        try
        {
            string? destination = _interactionService.ChooseExportPath(_latestResult.ReportZipPath);
            if (destination is null)
            {
                return;
            }

            File.Copy(_latestResult.ReportZipPath, destination, overwrite: true);
            ExportStatus = $"Exported {Path.GetFileName(destination)}.";
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("Couldn’t export the report", GetSafeMessage(exception), isError: true);
        }
    }

    private void OpenReportFolder()
    {
        if (_latestResult is null)
        {
            return;
        }
        try
        {
            _interactionService.OpenFolder(_latestResult.ReportFolder);
        }
        catch (Exception exception)
        {
            _interactionService.ShowMessage("Couldn’t open the report folder", GetSafeMessage(exception), isError: true);
        }
    }

    private void RaiseCommandStates()
    {
        _showSystemCrashCommand.RaiseCanExecuteChanged();
        _showApplicationCrashCommand.RaiseCanExecuteChanged();
        _showMonitorCommand.RaiseCanExecuteChanged();
        _showPreviousReportsCommand.RaiseCanExecuteChanged();
        _refreshIncidentsCommand.RaiseCanExecuteChanged();
        _analyzeSelectedIncidentCommand.RaiseCanExecuteChanged();
        _useBattlefieldPresetCommand.RaiseCanExecuteChanged();
        _chooseExecutableCommand.RaiseCanExecuteChanged();
        _refreshRunningProcessesCommand.RaiseCanExecuteChanged();
        _useRunningProcessCommand.RaiseCanExecuteChanged();
        _startMonitoringCommand.RaiseCanExecuteChanged();
        _openPreviousReportCommand.RaiseCanExecuteChanged();
        _cancelCommand.RaiseCanExecuteChanged();
        _reviewExportCommand.RaiseCanExecuteChanged();
        _backToResultsCommand.RaiseCanExecuteChanged();
        _startOverCommand.RaiseCanExecuteChanged();
        _packageDumpCommand.RaiseCanExecuteChanged();
        _inspectProtectedDumpCommand.RaiseCanExecuteChanged();
        _retryProtectedSourceCommand.RaiseCanExecuteChanged();
        _runDumpCheckCommand.RaiseCanExecuteChanged();
        _runDebuggerCommand.RaiseCanExecuteChanged();
        _retrySymbolsCommand.RaiseCanExecuteChanged();
        _prepareCrashCaptureCommand.RaiseCanExecuteChanged();
        _restoreCrashCaptureCommand.RaiseCanExecuteChanged();
        _restoreSavedCrashCaptureCommand.RaiseCanExecuteChanged();
        _enablePerAppCrashCaptureCommand.RaiseCanExecuteChanged();
        _restorePerAppCrashCaptureCommand.RaiseCanExecuteChanged();
        _restoreSavedPerAppCrashCaptureCommand.RaiseCanExecuteChanged();
        _copySummaryCommand.RaiseCanExecuteChanged();
        _exportCommand.RaiseCanExecuteChanged();
        _openFolderCommand.RaiseCanExecuteChanged();
        OnPropertyChanged(nameof(CanPackageDump));
        OnPropertyChanged(nameof(CanInspectProtectedDump));
        OnPropertyChanged(nameof(CanRunDumpCheck));
        OnPropertyChanged(nameof(CanRunDebugger));
        OnPropertyChanged(nameof(CanRetryWithMicrosoftSymbols));
        OnPropertyChanged(nameof(CanRetryProtectedEvidenceSource));
        OnPropertyChanged(nameof(CanPrepareCrashCapture));
        OnPropertyChanged(nameof(CanRestoreCrashPreparation));
        OnPropertyChanged(nameof(CanRestoreSavedCrashCapture));
        OnPropertyChanged(nameof(CanEnablePerAppCrashCapture));
        OnPropertyChanged(nameof(ShowEnablePerAppCrashCapture));
        OnPropertyChanged(nameof(CanRestorePerAppCrashCapture));
        OnPropertyChanged(nameof(PerAppCrashCaptureAvailability));
        OnPropertyChanged(nameof(CanRestoreSavedPerAppCrashCapture));
    }

    private string NormalizeTargetText(string text)
    {
        if (SelectedTarget.Kind == UiTargetKind.Battlefield6Preset || string.IsNullOrWhiteSpace(text))
        {
            return text;
        }
        return text.Replace("BF6", SelectedTarget.DisplayName, StringComparison.OrdinalIgnoreCase)
            .Replace("Battlefield", SelectedTarget.DisplayName, StringComparison.OrdinalIgnoreCase);
    }

    private static string FormatCoverage(int available, int total)
    {
        if (total <= 0)
        {
            return "Data coverage was not reported.";
        }
        int unavailable = Math.Max(0, total - available);
        return unavailable == 0
            ? $"Data coverage: {available} of {total} sources read"
            : $"Data coverage: {available} of {total} sources read · {unavailable} unavailable";
    }

    private static string FormatPercent(double? value) =>
        value is null ? "Counter unavailable" : $"{value.Value:0.#}%";

    private static string FormatGiB(double? value, string fallback) =>
        value is null ? fallback : $"{value.Value:0.00} GiB";

    private static string CreateStableTargetId(string path)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant()));
        return Convert.ToHexString(hash)[..12].ToLowerInvariant();
    }

    private static string GetSafeMessage(Exception exception) => exception switch
    {
        UnauthorizedAccessException => "Windows denied access to part of the requested evidence. The app did not request administrator access.",
        IOException => "A report file could not be read or written. Check available disk space and folder access.",
        NotSupportedException => exception.Message,
        _ => string.IsNullOrWhiteSpace(exception.Message) ? "An unexpected error occurred." : exception.Message
    };
}
