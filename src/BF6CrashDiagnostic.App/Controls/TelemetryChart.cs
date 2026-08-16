using System.Collections.Specialized;
using System.Windows;
using System.Windows.Media;
using BF6CrashDiagnostic.App.Models;

namespace BF6CrashDiagnostic.App.Controls;

public sealed class TelemetryChart : FrameworkElement
{
    public static readonly DependencyProperty SamplesProperty = DependencyProperty.Register(
        nameof(Samples),
        typeof(IEnumerable<UiTelemetrySample>),
        typeof(TelemetryChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, OnSamplesChanged));

    private INotifyCollectionChanged? _observableSamples;

    public IEnumerable<UiTelemetrySample>? Samples
    {
        get => (IEnumerable<UiTelemetrySample>?)GetValue(SamplesProperty);
        set => SetValue(SamplesProperty, value);
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        base.OnRender(drawingContext);

        double width = Math.Max(0, ActualWidth);
        double height = Math.Max(0, ActualHeight);
        if (width < 40 || height < 40)
        {
            return;
        }

        var borderPen = new Pen(new SolidColorBrush(Color.FromRgb(42, 58, 78)), 1);
        var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(110, 42, 58, 78)), 1);
        var background = new SolidColorBrush(Color.FromRgb(13, 20, 30));
        drawingContext.DrawRoundedRectangle(background, borderPen, new Rect(0.5, 0.5, width - 1, height - 1), 8, 8);

        const double left = 38;
        const double right = 44;
        const double top = 18;
        const double bottom = 26;
        Rect plot = new(left, top, Math.Max(1, width - left - right), Math.Max(1, height - top - bottom));

        for (int i = 0; i <= 4; i++)
        {
            double y = plot.Top + (plot.Height * i / 4d);
            drawingContext.DrawLine(gridPen, new Point(plot.Left, y), new Point(plot.Right, y));
        }

        IReadOnlyList<UiTelemetrySample> samples = Samples?.ToList() ?? [];
        if (samples.Count < 2)
        {
            DrawLabel(drawingContext, "Live trends appear after two samples", 13, Brushes.LightSlateGray,
                new Point(plot.Left + 10, plot.Top + (plot.Height / 2) - 8));
            DrawAxes(drawingContext, plot, 1);
            return;
        }

        double gibMax = samples
            .SelectMany(sample => new[] { sample.TargetPrivateGiB, sample.TargetGpuGiB })
            .Where(value => value is not null)
            .Select(value => value!.Value)
            .DefaultIfEmpty(1)
            .Max();
        gibMax = Math.Max(1, Math.Ceiling(gibMax * 1.15));

        DrawSeries(drawingContext, samples, plot, sample => sample.SystemRamPercent, 100,
            new Pen(new SolidColorBrush(Color.FromRgb(85, 194, 255)), 2));
        DrawSeries(drawingContext, samples, plot, sample => sample.CommitPercent, 100,
            new Pen(new SolidColorBrush(Color.FromRgb(255, 203, 102)), 2));
        DrawSeries(drawingContext, samples, plot, sample => sample.TargetPrivateGiB, gibMax,
            new Pen(new SolidColorBrush(Color.FromRgb(102, 214, 160)), 2));
        DrawSeries(drawingContext, samples, plot, sample => sample.TargetGpuGiB, gibMax,
            new Pen(new SolidColorBrush(Color.FromRgb(199, 146, 234)), 2));

        DrawAxes(drawingContext, plot, gibMax);
        DrawLabel(drawingContext, samples[0].Timestamp.LocalDateTime.ToString("h:mm:ss tt"), 10, Brushes.LightSlateGray,
            new Point(plot.Left, plot.Bottom + 5));
        string end = samples[^1].Timestamp.LocalDateTime.ToString("h:mm:ss tt");
        FormattedText endText = CreateText(end, 10, Brushes.LightSlateGray);
        drawingContext.DrawText(endText, new Point(plot.Right - endText.Width, plot.Bottom + 5));
    }

    private static void DrawAxes(DrawingContext context, Rect plot, double gibMax)
    {
        DrawLabel(context, "100%", 10, Brushes.LightSlateGray, new Point(3, plot.Top - 6));
        DrawLabel(context, "50%", 10, Brushes.LightSlateGray, new Point(8, plot.Top + (plot.Height / 2) - 6));
        DrawLabel(context, "0%", 10, Brushes.LightSlateGray, new Point(13, plot.Bottom - 8));
        DrawLabel(context, $"{gibMax:0.#} GiB", 10, Brushes.LightSlateGray, new Point(plot.Right + 5, plot.Top - 6));
        DrawLabel(context, "0 GiB", 10, Brushes.LightSlateGray, new Point(plot.Right + 5, plot.Bottom - 8));
    }

    private static void DrawSeries(
        DrawingContext context,
        IReadOnlyList<UiTelemetrySample> samples,
        Rect plot,
        Func<UiTelemetrySample, double?> selector,
        double maximum,
        Pen pen)
    {
        StreamGeometry geometry = new();
        using (StreamGeometryContext geometryContext = geometry.Open())
        {
            bool hasFigure = false;
            for (int index = 0; index < samples.Count; index++)
            {
                double? raw = selector(samples[index]);
                if (raw is null || double.IsNaN(raw.Value) || double.IsInfinity(raw.Value))
                {
                    hasFigure = false;
                    continue;
                }

                double x = plot.Left + (plot.Width * index / Math.Max(1, samples.Count - 1d));
                double ratio = Math.Clamp(raw.Value / maximum, 0, 1);
                double y = plot.Bottom - (plot.Height * ratio);
                Point point = new(x, y);
                if (!hasFigure)
                {
                    geometryContext.BeginFigure(point, isFilled: false, isClosed: false);
                    hasFigure = true;
                }
                else
                {
                    geometryContext.LineTo(point, isStroked: true, isSmoothJoin: true);
                }
            }
        }

        geometry.Freeze();
        pen.Freeze();
        context.DrawGeometry(null, pen, geometry);
    }

    private static void DrawLabel(DrawingContext context, string text, double size, Brush brush, Point point) =>
        context.DrawText(CreateText(text, size, brush), point);

    private static FormattedText CreateText(string text, double size, Brush brush) => new(
        text,
        System.Globalization.CultureInfo.CurrentUICulture,
        FlowDirection.LeftToRight,
        new Typeface("Segoe UI"),
        size,
        brush,
        1);

    private static void OnSamplesChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs eventArgs)
    {
        var chart = (TelemetryChart)dependencyObject;
        if (chart._observableSamples is not null)
        {
            chart._observableSamples.CollectionChanged -= chart.OnCollectionChanged;
        }

        chart._observableSamples = eventArgs.NewValue as INotifyCollectionChanged;
        if (chart._observableSamples is not null)
        {
            chart._observableSamples.CollectionChanged += chart.OnCollectionChanged;
        }

        chart.InvalidateVisual();
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs eventArgs) => InvalidateVisual();
}
