using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using ADTierKit.Gui.ViewModels;

namespace ADTierKit.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        viewModel.OutputAppended += ScrollToEnd;

        // Ctrl+C copies the selected output lines.
        OutputList.CommandBindings.Add(new CommandBinding(ApplicationCommands.Copy, (_, _) =>
        {
            var lines = OutputList.SelectedItems.Cast<OutputLine>().OrderBy(l => viewModel.Output.IndexOf(l)).Select(l => l.Text);
            Clipboard.SetText(string.Join(Environment.NewLine, lines));
        }));
    }

    private void ScrollToEnd()
    {
        if (OutputList.Items.Count > 0) OutputList.ScrollIntoView(OutputList.Items[^1]);
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_viewModel.ConfirmClose())
        {
            e.Cancel = true;
            return;
        }
        _viewModel.SaveSettings();
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _viewModel.Dispose();
        base.OnClosed(e);
    }
}
