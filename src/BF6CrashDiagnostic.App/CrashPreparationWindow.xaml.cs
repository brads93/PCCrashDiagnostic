using System.Collections.ObjectModel;
using System.Windows;
using BF6CrashDiagnostic.App.Models;

namespace BF6CrashDiagnostic.App;

public partial class CrashPreparationWindow : Window
{
    internal CrashPreparationWindow(UiCrashPreparationPreview preview)
    {
        ArgumentNullException.ThrowIfNull(preview);
        InitializeComponent();
        DataContext = new PreviewViewModel(preview);
    }

    private void Continue_Click(object sender, RoutedEventArgs e) => DialogResult = true;

    private sealed class PreviewViewModel
    {
        public PreviewViewModel(UiCrashPreparationPreview preview)
        {
            CurrentSummary = preview.CurrentSummary;
            ProposedSummary = preview.ProposedSummary;
            Changes = new ObservableCollection<string>(preview.Changes);
            DiskImpact = preview.DiskImpact;
            PrivacyImpact = preview.PrivacyImpact;
            RestartImpact = preview.RestartImpact;
            PerAppCaptureSummary = preview.PerAppCaptureSummary;
            PerAppVisibility = preview.IncludesPerAppCapture ? Visibility.Visible : Visibility.Collapsed;
            Heading = preview.Heading;
            Introduction = preview.Introduction;
            ActionText = preview.ActionText;
            UacNotice = preview.UacNotice;
        }

        public string CurrentSummary { get; }
        public string ProposedSummary { get; }
        public ObservableCollection<string> Changes { get; }
        public string DiskImpact { get; }
        public string PrivacyImpact { get; }
        public string RestartImpact { get; }
        public string PerAppCaptureSummary { get; }
        public Visibility PerAppVisibility { get; }
        public string Heading { get; }
        public string Introduction { get; }
        public string ActionText { get; }
        public string UacNotice { get; }
    }
}
