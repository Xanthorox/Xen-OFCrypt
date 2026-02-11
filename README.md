<p align="center">
  <img src="https://img.shields.io/badge/Xanthorox-OFCrypt-00e5ff?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgNyAxMiAxMiAyMiA3eiIvPjxwYXRoIGZpbGw9IndoaXRlIiBvcGFjaXR5PSIuNyIgZD0iTTIgN3YxMGwxMCA1VjEyeiIvPjxwYXRoIGZpbGw9IndoaXRlIiBvcGFjaXR5PSIuNSIgZD0iTTIyIDd2MTBsLTEwIDVWMTJ6Ii8+PC9zdmc+" alt="Xanthorox-OFCrypt"/>
  <br/>
  <img src="https://img.shields.io/badge/version-3.0-blueviolet?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/platform-Windows%20x64-0078D6?style=flat-square&logo=windows" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-Attribution-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/stub-C%2B%2B%20Native-red?style=flat-square" alt="Stub"/>
  <img src="https://img.shields.io/badge/builder-WPF%20.NET%209-purple?style=flat-square" alt="Builder"/>
</p>

<h1 align="center">XANTHOROX-OFCRYPT</h1>
<p align="center"><b>Autonomous Multi-Cipher PE Crypter with Per-Build Cryptographic Metamorphism,<br/>Real-Time AV/EDR Threat Modeling, and 18-Layer Structural Mutation Engine</b></p>
<p align="center"><i>Designed & Engineered by Gary Senderson — Xanthorox Research</i></p>

---

> ⚡ **Ready to use?** The pre-built release is available on **[Releases](../../releases)** — no compilation needed. Source code is provided for educational review and authorized security research.

---

<img width="1331" height="855" alt="image" src="https://github.com/user-attachments/assets/81fe05bb-ad0c-412d-8efe-e3bbcbd9060f" />


## Overview

Xanthorox-OFCrypt is not a standard crypter. It is a **full-spectrum evasion framework** that combines four standard ciphers, four custom-designed research-grade cipher architectures, an 18-mutation PE metamorphism engine, and a real-time AV/EDR threat modeling system into a single cohesive tool.

Every single build produces a **cryptographically and structurally unique binary** — not just different encrypted payloads, but different PE timestamps, section layouts, entropy profiles, code paths, exception handlers, import tables, resource structures, and metadata signatures. Two builds of the same payload with the same key will produce binaries that share **zero static signatures**.

The runtime stub is written entirely in **position-independent native C++** with zero managed dependencies. It implements a multi-stage boot sequence that systematically dismantles every layer of endpoint protection — from userland hooks to kernel telemetry providers — before touching the payload.

---

## Core Architecture

```
╔══════════════════════════════════════════════════════════════════════╗
║                          BUILDER ENGINE                             ║
║                        (C# / WPF / .NET 9)                         ║
║                                                                     ║
║  ┌────────────────────┐  ┌────────────────────┐  ┌──────────────┐  ║
║  │   TARGET MATRIX    │  │   CRYPTO PIPELINE   │  │  PE MUTATOR  │  ║
║  │                    │  │                    │  │              │  ║
║  │ • 25+ AV/EDR       │  │ STANDARD:          │  │ 18 Unique    │  ║
║  │   profiles w/      │  │ • AES-256-CBC      │  │ Structural   │  ║
║  │   detection engine │  │ • ChaCha20-SHA512  │  │ Transforms:  │  ║
║  │   mapping         │  │ • RC4 (KSA+PRGA)   │  │              │  ║
║  │ • Per-engine       │  │ • Rolling XOR      │  │ • Timestamp  │  ║
║  │   threat scoring   │  │                    │  │ • Rich Strip │  ║
║  │   (1-5 scale)      │  │ RESEARCH-GRADE:    │  │ • Sections   │  ║
║  │ • Auto-compute     │  │ • Ghost Protocol   │  │ • Junk Code  │  ║
║  │   optimal counter- │  │   (5-layer SPN)    │  │ • Entropy    │  ║
║  │   measure stack    │  │ • Neuromancer      │  │ • TLS Dir    │  ║
║  │ • Static, Heurist, │  │   (Env-Bound)      │  │ • Debug Dir  │  ║
║  │   Behavioral, Mem, │  │ • Darknet Cipher   │  │ • Imports    │  ║
║  │   Cloud, ML, AMSI  │  │   (16-round SPN)   │  │ • Resources  │  ║
║  │   engine coverage  │  │ • VOID WALKER      │  │ • Dead Code  │  ║
║  │                    │  │   (Anti-Timing)     │  │ • SEH/pdata  │  ║
║  └────────┬───────────┘  └────────┬───────────┘  │ • Metadata   │  ║
║           │    Threat Surface     │    Cipher     │ • Strings    │  ║
║           │    Analysis           │    Selection  │ • Relocs     │  ║
║           └───────────┬───────────┘               │ • Cert Pad   │  ║
║                       ▼                           │ • Alignment  │  ║
║            ┌──────────────────────┐               │ • Code Sign  │  ║
║            │   STUB PATCHER      │               └──────┬───────┘  ║
║            │                     │                      │          ║
║            │ Marker-based binary │◄─────────────────────┘          ║
║            │ patching with       │  Post-patch metamorphism        ║
║            │ save-and-restore    │  with data region protection    ║
║            │ data protection     │                                 ║
║            └──────────┬──────────┘                                 ║
║                       ▼                                            ║
║            ┌──────────────────────┐                                ║
║            │   CODE SIGNER       │                                 ║
║            │                     │                                 ║
║            │ Ephemeral X.509     │                                 ║
║            │ self-signed cert    │                                 ║
║            │ per build           │                                 ║
║            └──────────┬──────────┘                                 ║
╚═══════════════════════╪════════════════════════════════════════════╝
                        ▼
╔══════════════════════════════════════════════════════════════════════╗
║                        NATIVE STUB (C++ x64)                       ║
║                                                                     ║
║  BOOT SEQUENCE (23 individually toggleable protection layers):     ║
║                                                                     ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  PHASE 0: PRE-EXECUTION ENVIRONMENT VALIDATION             │   ║
║  │                                                             │   ║
║  │  L21 MOTW Strip ──► L22 Anti-Emulation ──► L0 Integrity   │   ║
║  │  ──► L23 TLS Callback Verify ──► L1 ntdll Unhook          │   ║
║  │  ──► L11 Syscall SSN Resolution                            │   ║
║  └───────────────────────┬─────────────────────────────────────┘   ║
║                          ▼                                         ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  PHASE 1: TELEMETRY NEUTRALIZATION                         │   ║
║  │                                                             │   ║
║  │  L3 AMSI Patch ──► L4 ETW Patch ──► L4b ETW-TI Disable    │   ║
║  └───────────────────────┬─────────────────────────────────────┘   ║
║                          ▼                                         ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  PHASE 2: ANTI-ANALYSIS GAUNTLET                           │   ║
║  │                                                             │   ║
║  │  L5 Anti-Debug ──► L6 Anti-VM ──► L7 Anti-Sandbox          │   ║
║  │  ──► L8 Encrypted Sleep (payload stays ciphertext)         │   ║
║  └───────────────────────┬─────────────────────────────────────┘   ║
║                          ▼                                         ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  PHASE 3: PAYLOAD RECOVERY                                 │   ║
║  │                                                             │   ║
║  │  L20 Entropy Denormalize ──► L15 HWID Key Derivation       │   ║
║  │  ──► Decrypt (Standard or Research cipher) ──► L39 Staged  │   ║
║  └───────────────────────┬─────────────────────────────────────┘   ║
║                          ▼                                         ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  PHASE 4: PROTECTED EXECUTION                              │   ║
║  │                                                             │   ║
║  │  L14 Guard Page Install ──► Execute via:                   │   ║
║  │    L16  Phantom DLL Hollowing (from signed DLL memory)     │   ║
║  │    L12  Thread Pool (TpAllocWork — legitimate work items)  │   ║
║  │    L16b Callback Diversification (callback proxy chain)    │   ║
║  │    L10  Module Stomping (overwrite loaded DLL .text)       │   ║
║  │    L9   RunPE (NtUnmapViewOfSection hollowing)             │   ║
║  │    L13  Fiber Execution (ConvertThreadToFiber context)     │   ║
║  └───────────────────────┬─────────────────────────────────────┘   ║
║                          ▼                                         ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  PHASE 5: POST-EXECUTION                                   │   ║
║  │                                                             │   ║
║  │  L17 Persistence (HKCU Run) ──► L18 Melt (self-delete)    │   ║
║  └─────────────────────────────────────────────────────────────┘   ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Encryption Pipeline

<img width="517" height="255" alt="image" src="https://github.com/user-attachments/assets/cb2446a3-a7c6-4532-8e77-1a1996d24ed5" />  <img width="572" height="280" alt="image" src="https://github.com/user-attachments/assets/909f3ea0-f55e-45f6-9210-e7675dc6a5b1" />



### Standard Ciphers

| Cipher | Class | Key Schedule | Block/Stream | Self-Inverse | Per-Build Entropy |
|--------|-------|-------------|--------------|--------------|-------------------|
| **AES-256-CBC** | Symmetric Block | 256-bit CSPRNG key | 128-bit blocks, PKCS7 padding | No (IV-dependent) | Random 16-byte IV prepended to ciphertext |
| **ChaCha20** | Stream (SHA-512 Sim) | 256-bit seed → SHA-512 PRNG expansion | Byte-level XOR | Yes (symmetric) | Deterministic from key+counter |
| **RC4** | Stream | KSA over 256-byte S-Box | Byte-level XOR | Yes (symmetric) | Key-dependent permutation |
| **Rolling XOR** | Stream | Bit-rotated key cycling | Byte-level XOR with `(key >> (i%8)) \| (key << (8-i%8))` | Yes (symmetric) | Key rotation pattern |

<img width="1313" height="845" alt="image" src="https://github.com/user-attachments/assets/84440a69-a467-4ca7-9dd9-1820a90593d5" />


### Research-Grade Cipher Architectures

These are **custom-designed cryptographic systems, not wrappers around existing libraries.** Each generates a unique set of cryptographic parameters per build — meaning the cipher itself is different every time, not just the key.

<details>
<summary><b>🔬 GHOST PROTOCOL — Randomized Substitution-Permutation Network</b></summary>

**Parameter Size:** 271 bytes per build

Ghost Protocol implements a **5-layer SPN** where the execution order of layers is randomized per build (120 possible permutations). Each layer applies a different cryptographic primitive:

| Component | Size | Description |
|-----------|------|-------------|
| **S-Box** | 256 bytes | Cryptographically random permutation of all 256 byte values. Verified bijection — every input maps to exactly one output. |
| **Inverse S-Box** | 256 bytes | Pre-computed inverse for decryption. Verified: `InvSBox[SBox[x]] == x` for all x ∈ [0,255]. |
| **Bit Permutation** | 8 bytes | Per-build bit-level transpositions applied after substitution. |
| **Affine Transform** | 2 bytes | `enc(x) = (mul × x + add) mod 256` where `mul` is verified coprime to 256 via `mul × mul_inv ≡ 1 (mod 256)`. |
| **Layer Order** | 1 byte | Encodes the permutation index (0-119) of the 5-layer execution order. |
| **Rolling XOR** | Key-derived | Final mixing layer with rotated key bytes. |

**Why it matters:** Static analysis tools that fingerprint cipher implementations will see a different algorithm every build. The S-Box alone produces `256!` (≈ 8.5 × 10⁵⁰⁶) possible substitution tables.

</details>

<details>
<summary><b>🧠 NEUROMANCER — Machine-Bound Environmental Cipher</b></summary>

**Parameter Size:** 62 bytes per build

Neuromancer binds the decryption process to the **target machine's hardware identity**. The cipher derives its working key from a combination of the master key, a per-build salt, and the machine's environmental fingerprint.

| Component | Size | Description |
|-----------|------|-------------|
| **Environment Hash** | 32 bytes | SHA-256 of `{MachineGUID \|\| MAC \|\| VolumeSerial \|\| ProcessorID}`. Computed at encryption time from target profile. |
| **Time-Lock Rounds** | 2 bytes | Configurable sequential hash iterations (default 4096). Forces O(n) computation — defeats parallel brute-force. |
| **Nonce** | 12 bytes | CSPRNG per-build. Ensures identical payloads produce different ciphertext. |
| **Salt** | 16 bytes | CSPRNG per-build. Mixed into key derivation. |

**Why it matters:** The payload is cryptographically bound to one specific machine. Copying the binary to a different computer produces the wrong derived key → garbage decryption → silent failure. Sandbox environments (which have different HWIDs) cannot recover the payload even with the master key.

</details>

<details>
<summary><b>🌐 DARKNET CIPHER — 16-Round Feistel Network with Per-Round S-Boxes</b></summary>

**Parameter Size:** 4,236 bytes per build

The most parameter-heavy cipher in the system. Darknet implements a **full 16-round Feistel network** where every round has its own unique S-Box, and the diffusion layer uses a randomized P-Box permutation.

| Component | Size | Description |
|-----------|------|-------------|
| **Round S-Boxes** | 4,096 bytes (16 × 256) | Each round uses a unique, independently generated 256-byte bijective substitution table. All 16 verified as valid permutations. |
| **P-Box** | 32 bytes | Bit-level permutation for inter-round diffusion. Verified: 32 unique values covering [0,31]. |
| **Round Keys** | 64 bytes (16 × 4) | Per-round subkeys derived from the master key via cascaded hashing. |
| **Whitening Key** | 32 bytes | Applied before Round 1 and after Round 16 (input/output whitening). |
| **Nonce** | 12 bytes | CSPRNG per-build for CTR mode. |

**Why it matters:** With 4,236 bytes of unique cryptographic state, no two builds share any structural similarity in their cipher. The 16 independent S-Boxes alone represent `(256!)^16` possible configurations — a search space that dwarfs the universe's atomic count.

</details>

<details>
<summary><b>🕳️ VOID WALKER — Anti-Timing Authenticated Stream Cipher</b></summary>

**Parameter Size:** 59 bytes per build

VOID WALKER adds an **active anti-analysis dimension** to encryption. It uses SipHash-2-4 for authenticated encryption and embeds an RDTSC timing threshold that detects single-stepping, breakpoints, and emulated execution.

| Component | Size | Description |
|-----------|------|-------------|
| **Nonce** | 12 bytes | CSPRNG per-build. Stream cipher initialization. |
| **Salt** | 16 bytes | CSPRNG per-build. Key derivation input. |
| **SipKey** | 16 bytes | SipHash-2-4 authentication key. Produces MAC over plaintext. |
| **MAC** | 4 bytes | Truncated SipHash digest. Verified non-zero and non-trivial. |
| **RDTSC Threshold** | 4 bytes | CPU cycle count threshold. If decryption takes longer than expected (indicating single-stepping or debugger intervention), the cipher silently produces incorrect output. |
| **Timing Mode** | 1 byte | Threshold comparison strategy (above/below/windowed). |

**Why it matters:** Analysts who attach a debugger to step through the decryption will unknowingly trigger the timing check. The cipher doesn't crash or exit — it silently produces wrong output, making the analyst believe the payload is corrupted rather than protected.

</details>

---

## PE Metamorphism Engine — 18 Structural Transforms

Every build passes through **all 18 mutations sequentially**. The mutations operate on the raw PE structure after the stub is patched — a save-and-restore mechanism protects embedded data integrity through the entire mutation pipeline.

| # | Mutation | What It Does | Why It Matters |
|---|----------|-------------|----------------|
| 1 | **Timestamp Randomization** | Replaces PE `TimeDateStamp` with a random value from the past 5 years | Defeats compilation date clustering used by threat intel platforms |
| 2 | **Rich Header Eradication** | Zeros out the MSVC Rich header structure between DOS stub and PE header | Removes toolchain fingerprint (compiler version, linker, object counts) |
| 3 | **Section Name Metamorphism** | Renames `.text`/`.rdata`/`.data` sections to randomly selected common names | Breaks YARA rules that match on section names |
| 4 | **Polymorphic Junk Code** | Fills inter-section padding with valid x86_64 instruction sequences (`NOP`, `XCHG`, `LEA`, `MOV`) | Padding no longer looks like null bytes — defeats padding entropy scanners |
| 5 | **PE Checksum Repair** | Recalculates `OptionalHeader.CheckSum` after all modifications | Ensures PE passes integrity validation by loaders and security tools |
| 6 | **Entropy Equalization** | Normalizes per-section entropy to fall within 4.5-6.5 bits/byte range | Evades high-entropy detection (packed/encrypted section heuristics) |
| 7 | **TLS Directory Manipulation** | Modifies TLS callback directory entries | Adds execution paths that run before `main()` — increases complexity for emulators |
| 8 | **Debug Directory Erasure** | Strips `IMAGE_DIRECTORY_ENTRY_DEBUG` and any embedded PDB paths | Removes source file paths, build machine info, and developer fingerprints |
| 9 | **Import Table Augmentation** | Appends legitimate-looking imports from `user32.dll`, `advapi32.dll`, `shell32.dll` | Makes the import table resemble a normal GUI application |
| 10 | **Resource Mimicry** | Injects fake `RT_DIALOG`, `RT_MENU`, `RT_STRING` resource entries | Mimics a legitimate Windows application with UI resources |
| 11 | **Semantic Dead Code** | Injects realistic control flow paths (if/else branches, loops) that compute but never affect output | Increases McCabe complexity — makes automated analysis exponentially harder |
| 12 | **Exception Handler Forgery** | Adds fake `RUNTIME_FUNCTION` entries in `.pdata` | Binary appears to have proper structured exception handling coverage |
| 13 | **Metadata Cloning** | Copies `VS_VERSIONINFO` structures mimicking legitimate Microsoft binaries | File properties dialog shows believable version information |
| 14 | **String Table Obfuscation** | XOR-encrypts suspicious API name strings (`VirtualAlloc`, `WriteProcessMemory`, etc.) | Defeats string-based static detection rules |
| 15 | **Relocation Noise** | Inserts junk entries into the `.reloc` section relocation table | Increases noise for tools that analyze relocation patterns |
| 16 | **Certificate Table Padding** | Adds padding to the Authenticode certificate directory | Modifies file hash without breaking the PE loader |
| 17 | **Section Alignment Jitter** | Varies `VirtualAddress` alignment within valid ranges | No two builds share the same memory layout |
| 18 | **Ephemeral Code Signing** | Signs the final binary with a per-build self-signed X.509 certificate | Binary appears "signed" to quick-glance analysis; cert is unique each time |

---

## Runtime Protection Stack — 23 Layers Deep

The stub executes a **hardcoded 5-phase boot sequence**. Each layer is individually toggleable from the Builder UI. The sequence is designed so that each phase validates the environment at increasing depth before proceeding.

### Phase 0 — Pre-Execution Environment Validation

| Layer | Name | Mechanism | Detail |
|-------|------|-----------|--------|
| **L21** | MOTW Strip | ADS removal + process relaunch | Strips `Zone.Identifier` alternate data stream → relaunches self without Mark-of-the-Web. SmartScreen never fires. |
| **L22** | Anti-Emulation | Multi-vector emulator detection | Timing deltas via `QueryPerformanceCounter`, API behavior probing (emulators often stub `GetModuleHandle` incorrectly), environment artifact scanning. |
| **L0** | Anti-Tamper | Compile-time integrity | Verifies hardcoded author string at runtime. Tampered binary → null-pointer dereference → immediate crash. No error message, no catch block. |
| **L23** | TLS Callback Verify | Pre-main execution check | TLS callback fires before `WinMain()`. Stub verifies the callback executed. Emulators that skip TLS callbacks are detected. |
| **L1** | ntdll Unhook | Full DLL remap from disk | Opens `C:\Windows\System32\ntdll.dll` from disk → maps fresh copy → overwrites `.text` section of loaded `ntdll.dll`. Every EDR userland hook is removed in one operation. |
| **L11** | Direct Syscalls | Runtime SSN resolution | Reads `ntdll.dll` export table → extracts syscall service numbers → builds `syscall` instruction stubs in executable memory. Bypasses userland entirely — calls go directly to kernel. |

### Phase 1 — Telemetry Neutralization

| Layer | Name | Mechanism | Detail |
|-------|------|-----------|--------|
| **L3** | AMSI Bypass | In-memory patching | Patches the first bytes of `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN`. All subsequent AMSI scans pass silently. |
| **L4** | ETW Bypass | Dual-provider disable | Patches `EtwEventWrite` to `ret` — kills standard ETW. Then patches **ETW Threat Intelligence** provider (`Microsoft-Windows-Threat-Intelligence`) — kills kernel-level telemetry forwarding to EDR. |

### Phase 2 — Anti-Analysis Gauntlet

| Layer | Name | Mechanism | Detail |
|-------|------|-----------|--------|
| **L5** | Anti-Debug | 5-vector detection | `IsDebuggerPresent()`, `NtQueryInformationProcess(ProcessDebugPort)`, `GetTickCount64` timing delta, hardware breakpoint register check (`DR0-DR3` via `GetThreadContext`), PEB `BeingDebugged` flag. |
| **L6** | Anti-VM | Hardware fingerprinting | Registry key scan (`VBOX`/`VMWARE` artifacts), `CPUID` hypervisor leaf (`0x40000000`), MAC OUI prefix matching (first 3 bytes identify VM vendors), disk size heuristic (VMs typically have < 80GB). |
| **L7** | Anti-Sandbox | Behavioral analysis | Running process count (sandboxes run < 20 processes), system uptime (`GetTickCount64` < 10 minutes = suspicious), user interaction check (mouse cursor movement), screen resolution validation (800×600 = sandbox). |
| **L8** | Sleep Obfuscation | Encrypted sleep | Payload stays **AES-encrypted in memory** during the delay period. Memory scanners that read the payload region during sleep see only ciphertext. Decrypts when sleep ends. |

### Phase 3 — Payload Recovery

| Layer | Name | Mechanism | Detail |
|-------|------|-----------|--------|
| **L20** | Entropy Denormalize | Affine cipher decode | Reverses Builder's entropy normalization: `dec(y) = (7 × y + 85) mod 256`. Strips the `0xEE` marker byte. One-pass, constant-time. |
| **L15** | HWID Key Derivation | Machine-bound keying | Computes `HMAC-SHA256(masterKey, MachineGUID \|\| MAC \|\| VolumeSerial)` → derived key used for decryption. Wrong machine → wrong key → payload is garbage bytes. Silent failure — no error, no crash. |
| — | Decryption | Standard or Research | Dispatches to the selected cipher (AES/ChaCha20/RC4/XOR or Ghost/Neuro/Darknet/VOID). Research ciphers consume the embedded parameter blob from the `XRESRC` marker region. |
| **L39** | Staged Decryption | Chunked recovery | Decrypts payload in 4KB chunks. At no point is the entire plaintext payload present in memory simultaneously. Each chunk is decrypted, consumed, and zeroed before the next. |

### Phase 4 — Protected Execution

| Layer | Name | Mechanism | Detail |
|-------|------|-----------|--------|
| **L14** | Guard Page Shield | Memory access trap | Installs `PAGE_GUARD` protection on the decrypted payload region. If any external process (memory scanner, EDR agent) reads the memory, the guard page exception fires and the payload **auto-re-encrypts itself**. |
| **L16** | Phantom DLL Hollowing | Signed memory execution | Loads a legitimately signed Windows system DLL → allocates RWX memory in its image space → copies payload into the `.text` section → executes. Process memory analysis sees code "inside" a signed Microsoft DLL. |
| **L12** | Thread Pool Execution | OS-native work items | Creates payload via `TpAllocWork` → `TpPostWork` → `TpReleaseWork`. Execution originates from the Windows thread pool — appears as a legitimate OS work item, not a suspicious remote thread. |
| **L16b** | Callback Diversification | Callback proxy chain | Executes payload through Windows callback mechanisms (`EnumWindows`, `CreateTimerQueueTimer`, etc.) — appears as legitimate callback processing to behavioral analysis. |
| **L10** | Module Stomping | DLL code overwrite | Maps a benign DLL → overwrites its `.text` section with payload → transfers execution. Payload occupies legitimate module memory. |
| **L9** | RunPE | Process hollowing | `NtUnmapViewOfSection` → write payload into hollowed process → resume thread. Classic but still effective against legacy EDR. |
| **L13** | Fiber Execution | Context switching | `ConvertThreadToFiber` → `CreateFiber` with payload → `SwitchToFiber`. Execution context is a fiber, not a thread — invisible to thread enumeration tools. |

### Phase 5 — Post-Execution

| Layer | Name | Mechanism | Detail |
|-------|------|-----------|--------|
| **L17** | Persistence | Registry Run key | Writes to `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — survives reboot. No admin required.  |
| **L18** | Melt | Self-destruction | Spawns `cmd.exe /c ping -n 2 127.0.0.1 > nul & del /q "<self>"` — the delay ensures the process has exited before deletion. Binary is gone from disk. |
| **L19** | Fake Error | Social engineering | Displays a convincing `MSVCP140.dll not found` error dialog before execution. User thinks the program failed to launch. Stack-built strings — no suspicious string literals in the binary. |

---

## Target Matrix — Automated Threat Modeling

The Builder includes profiles for **25+ AV/EDR products**, each mapped with:

- **Detection engines:** Static signatures, heuristic analysis, behavioral monitoring, memory scanning, cloud lookup, ML classification, AMSI integration
- **Threat level:** 1-5 scale based on detection capability and market penetration
- **Engine coverage bars:** Visual breakdown of which detection layers each product uses

Select your targets → the engine computes the **minimum countermeasure stack** required to evade all selected products → one-click apply to Builder settings.

---

## Building

Use your brain to modify and build. You can donate if you want me to help.

---

## Legal

Copyright (c) 2024-2026 **Gary Senderson** / **Xanthorox**. All rights reserved. See [LICENSE](LICENSE).

This software is provided for **educational and authorized security research purposes only**. Unauthorized use of this software to compromise computer systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

---

<p align="center"><b>XANTHOROX</b></p>
<p align="center"><i>"Every build is unique. Every signature is dead on arrival."</i></p>
