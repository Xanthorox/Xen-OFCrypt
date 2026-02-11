using Microsoft.Win32;
using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace XanthoroxCrypted.Views
{
    public partial class ScriptingView : UserControl
    {
        public ScriptingView()
        {
            InitializeComponent();
        }

        private void BtnLoad_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Lua Scripts (*.lua)|*.lua|All files (*.*)|*.*";
            if (openFileDialog.ShowDialog() == true)
            {
                TxtScript.Text = File.ReadAllText(openFileDialog.FileName);
            }
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Lua Scripts (*.lua)|*.lua";
            if (saveFileDialog.ShowDialog() == true)
            {
                File.WriteAllText(saveFileDialog.FileName, TxtScript.Text);
            }
        }
    }
}
