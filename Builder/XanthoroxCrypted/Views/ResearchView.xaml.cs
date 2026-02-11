using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace XanthoroxCrypted.Views
{
    public enum ResearchPackage
    {
        None = 0,
        Ghost = 1,
        Neuromancer = 2,
        Darknet = 3,
        VoidWalker = 4,
    }

    public partial class ResearchView : UserControl
    {
        private ResearchPackage _selected = ResearchPackage.None;

        public ResearchView()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Returns the currently selected research package.
        /// Called by BuilderView during build to decide encryption method.
        /// </summary>
        public ResearchPackage GetSelectedPackage() => _selected;

        // ═══ Card click → toggle detail panel ═══

        private void CardGhost_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            DetailGhost.Visibility = DetailGhost.Visibility == Visibility.Visible
                ? Visibility.Collapsed : Visibility.Visible;
        }

        private void CardNeuro_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            DetailNeuro.Visibility = DetailNeuro.Visibility == Visibility.Visible
                ? Visibility.Collapsed : Visibility.Visible;
        }

        private void CardDarknet_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            DetailDarknet.Visibility = DetailDarknet.Visibility == Visibility.Visible
                ? Visibility.Collapsed : Visibility.Visible;
        }

        private void CardVoid_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            DetailVoid.Visibility = DetailVoid.Visibility == Visibility.Visible
                ? Visibility.Collapsed : Visibility.Visible;
        }

        // ═══ Checkbox logic — radio-button behavior (only one active) ═══

        private void ChkGhost_Checked(object sender, RoutedEventArgs e)
        {
            _selected = ResearchPackage.Ghost;
            ChkNeuro.IsChecked = false;
            ChkDarknet.IsChecked = false;
            ChkVoid.IsChecked = false;
            UpdateBorders();
            UpdateStatus();
        }

        private void ChkGhost_Unchecked(object sender, RoutedEventArgs e)
        {
            if (_selected == ResearchPackage.Ghost)
            {
                _selected = ResearchPackage.None;
                UpdateBorders();
                UpdateStatus();
            }
        }

        private void ChkNeuro_Checked(object sender, RoutedEventArgs e)
        {
            _selected = ResearchPackage.Neuromancer;
            ChkGhost.IsChecked = false;
            ChkDarknet.IsChecked = false;
            ChkVoid.IsChecked = false;
            UpdateBorders();
            UpdateStatus();
        }

        private void ChkNeuro_Unchecked(object sender, RoutedEventArgs e)
        {
            if (_selected == ResearchPackage.Neuromancer)
            {
                _selected = ResearchPackage.None;
                UpdateBorders();
                UpdateStatus();
            }
        }

        private void ChkDarknet_Checked(object sender, RoutedEventArgs e)
        {
            _selected = ResearchPackage.Darknet;
            ChkGhost.IsChecked = false;
            ChkNeuro.IsChecked = false;
            ChkVoid.IsChecked = false;
            UpdateBorders();
            UpdateStatus();
        }

        private void ChkDarknet_Unchecked(object sender, RoutedEventArgs e)
        {
            if (_selected == ResearchPackage.Darknet)
            {
                _selected = ResearchPackage.None;
                UpdateBorders();
                UpdateStatus();
            }
        }

        private void ChkVoid_Checked(object sender, RoutedEventArgs e)
        {
            _selected = ResearchPackage.VoidWalker;
            ChkGhost.IsChecked = false;
            ChkNeuro.IsChecked = false;
            ChkDarknet.IsChecked = false;
            UpdateBorders();
            UpdateStatus();
        }

        private void ChkVoid_Unchecked(object sender, RoutedEventArgs e)
        {
            if (_selected == ResearchPackage.VoidWalker)
            {
                _selected = ResearchPackage.None;
                UpdateBorders();
                UpdateStatus();
            }
        }

        // ═══ Visual feedback ═══

        private void UpdateBorders()
        {
            Color cyan = Color.FromRgb(0, 212, 255);
            Color orange = Color.FromRgb(255, 140, 0);
            Color pink = Color.FromRgb(255, 64, 129);
            Color purple = Color.FromRgb(138, 43, 226);
            Color clear = Colors.Transparent;

            BorderGhost.Color = _selected == ResearchPackage.Ghost ? cyan : clear;
            BorderNeuro.Color = _selected == ResearchPackage.Neuromancer ? orange : clear;
            BorderDarknet.Color = _selected == ResearchPackage.Darknet ? pink : clear;
            BorderVoid.Color = _selected == ResearchPackage.VoidWalker ? purple : clear;
        }

        private void UpdateStatus()
        {
            switch (_selected)
            {
                case ResearchPackage.Ghost:
                    LblActivePackage.Text = "GHOST PROTOCOL";
                    LblActivePackage.Foreground = new SolidColorBrush(Color.FromRgb(0, 212, 255));
                    LblStrength.Text = "5-Layer Transform";
                    LblSigs.Text = "0 Known";
                    LblSigs.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80));
                    break;
                case ResearchPackage.Neuromancer:
                    LblActivePackage.Text = "NEUROMANCER";
                    LblActivePackage.Foreground = new SolidColorBrush(Color.FromRgb(255, 140, 0));
                    LblStrength.Text = "Env Key + Time Lock";
                    LblSigs.Text = "0 Known";
                    LblSigs.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80));
                    break;
                case ResearchPackage.Darknet:
                    LblActivePackage.Text = "DARKNET CIPHER";
                    LblActivePackage.Foreground = new SolidColorBrush(Color.FromRgb(255, 64, 129));
                    LblStrength.Text = "Feistel + White-Box";
                    LblSigs.Text = "0 Known";
                    LblSigs.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80));
                    break;
                case ResearchPackage.VoidWalker:
                    LblActivePackage.Text = "VOID WALKER";
                    LblActivePackage.Foreground = new SolidColorBrush(Color.FromRgb(138, 43, 226));
                    LblStrength.Text = "Zero-API + MAC";
                    LblSigs.Text = "0 Known";
                    LblSigs.Foreground = new SolidColorBrush(Color.FromRgb(63, 185, 80));
                    break;
                default:
                    LblActivePackage.Text = "None";
                    LblActivePackage.Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158));
                    LblStrength.Text = "—";
                    LblSigs.Text = "—";
                    LblSigs.Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158));
                    break;
            }
        }
    }
}
