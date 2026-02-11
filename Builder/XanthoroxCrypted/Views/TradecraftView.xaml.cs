using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace XanthoroxCrypted.Views
{
    public partial class TradecraftView : UserControl
    {
        public TradecraftView()
        {
            InitializeComponent();
        }

        private void CheckBox_MouseEnter(object sender, MouseEventArgs e)
        {
            if (sender is CheckBox chk && chk.Tag != null)
            {
                TxtInfo.Text = chk.Tag.ToString();
                TxtInfo.FontStyle = FontStyles.Normal;
            }
        }

        private void CheckBox_MouseLeave(object sender, MouseEventArgs e)
        {
            TxtInfo.Text = "Hover over a module to see technical details.";
            TxtInfo.FontStyle = FontStyles.Italic;
        }
    }
}
