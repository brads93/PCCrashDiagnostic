using System.Collections.ObjectModel;
using System.Windows;

namespace BF6CrashDiagnostic.App;

public partial class ReviewWindow : Window
{
    public ReviewWindow(string summary, IReadOnlyList<string> collectionFailures)
    {
        InitializeComponent();
        DataContext = new ReviewViewModel(summary, collectionFailures);
    }

    private void CopySummary_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ReviewViewModel viewModel)
        {
            try
            {
                Clipboard.SetText(viewModel.Summary);
            }
            catch (Exception exception)
            {
                MessageBox.Show(this, exception.Message, "Couldn’t copy the summary", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void Done_Click(object sender, RoutedEventArgs e) => Close();

    private sealed class ReviewViewModel
    {
        public ReviewViewModel(string summary, IReadOnlyList<string> collectionFailures)
        {
            Summary = summary;
            CollectionFailures = new ObservableCollection<string>(collectionFailures);
        }

        public string Summary { get; }

        public ObservableCollection<string> CollectionFailures { get; }

        public Visibility NoFailuresVisibility => CollectionFailures.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        public Visibility FailuresVisibility => CollectionFailures.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }
}
