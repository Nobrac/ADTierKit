using ADTierKit.Gui.Core;
using ADTierKit.Gui.Mvvm;

namespace ADTierKit.Gui.ViewModels;

public sealed class StageItem(string name, string description, Action changed) : ObservableObject
{
    private bool _isSelected = true;

    public string Name { get; } = name;

    public string Description { get; } = description;

    public bool IsSelected
    {
        get => _isSelected;
        set { if (SetProperty(ref _isSelected, value)) changed(); }
    }

    /// <summary>Sets the value without reporting a manual change (used by presets).</summary>
    internal void Set(bool value)
    {
        if (_isSelected == value) return;
        _isSelected = value;
        OnPropertyChanged(nameof(IsSelected));
    }
}

public sealed record OutputLine(string Text, LineKind Kind);
