using System.ComponentModel;
using System.Windows;
using BF6CrashDiagnostic.App.ViewModels;

namespace BF6CrashDiagnostic.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    internal MainWindow(MainViewModel viewModel)
    {
        _viewModel = viewModel;
        DataContext = viewModel;
        InitializeComponent();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e) =>
        await _viewModel.InitializeAsync().ConfigureAwait(true);

    private void Window_Closing(object? sender, CancelEventArgs e) => _viewModel.Dispose();
}
