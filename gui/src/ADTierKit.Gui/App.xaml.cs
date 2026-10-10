using System.Windows;
using System.Windows.Threading;
using ADTierKit.Gui.Services;
using ADTierKit.Gui.ViewModels;

namespace ADTierKit.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;

        var viewModel = new MainViewModel(new Shell(), GuiSettings.Load());
        var window = new MainWindow(viewModel);
        MainWindow = window;
        window.Show();
    }

    private static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // A failing button must not take a running deployment's window with it.
        MessageBox.Show(e.Exception.Message, "ADTierKit - unexpected error", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
