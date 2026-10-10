using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ADTierKit.Gui.Core;

namespace ADTierKit.Gui.Converters;

/// <summary>Binds a group of radio buttons to one enum value: ConverterParameter names the member.</summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value?.ToString() == parameter?.ToString();

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true && parameter is string name ? Enum.Parse(targetType, name) : Binding.DoNothing;
}

/// <summary>Colours an output line the way the console colours it.</summary>
public sealed class LineKindBrushConverter : IValueConverter
{
    private static readonly Brush Normal = Frozen(0x24, 0x29, 0x2F);
    private static readonly Brush Header = Frozen(0x09, 0x69, 0xDA);
    private static readonly Brush Success = Frozen(0x1A, 0x7F, 0x37);
    private static readonly Brush Skip = Frozen(0x6E, 0x77, 0x81);
    private static readonly Brush Plan = Frozen(0x8A, 0x63, 0x00);
    private static readonly Brush Warning = Frozen(0x9A, 0x67, 0x00);
    private static readonly Brush Error = Frozen(0xCF, 0x22, 0x2E);
    private static readonly Brush Info = Frozen(0x57, 0x60, 0x6A);

    private static SolidColorBrush Frozen(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        LineKind.Header => Header,
        LineKind.Success => Success,
        LineKind.Skip => Skip,
        LineKind.Plan => Plan,
        LineKind.Warning => Warning,
        LineKind.Error => Error,
        LineKind.Info => Info,
        _ => Normal,
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class InverseBooleanConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
}

public sealed class BooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        (value is true) ^ (parameter as string == "Invert") ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
