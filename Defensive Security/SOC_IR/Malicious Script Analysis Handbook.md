# Malicious Script Analysis Handbook

> A defensive analyst's guide reconstructed from all 14 lessons and 178 slides in the 2026 Practical Cyber Range course, with corrected technical context and contained proof-of-concept labs.

## 0. Purpose, scope, and PoC safety

This handbook explains how to preserve, deobfuscate, investigate, detect, and report suspicious scripts. It is written for defenders, incident responders, malware analysts, detection engineers, and students.

The included proof-of-concept scripts are deliberately constrained:

- They use fixed benign strings, harmless output, temporary files, or loopback-only resources.
- They do not disable AMSI or another security control.
- They do not allocate executable memory, execute shellcode, establish persistence, steal credentials, or contact an external server.
- In-memory loading is demonstrated only with an assembly compiled from visible benign source.
- The AMSI lab reads function bytes for integrity inspection but never modifies them.
- Examples marked Windows-only must still be run in a disposable lab VM, not on a production workstation.

The main operational rule is simple: **decode and inspect first; execute only when necessary, in an isolated and observable lab**.

## 1. Source material and limitations

### 1.1 Archive inventory

| Item | Value |
|---|---|
| Source archive | <code>[2026 실전형 사이버훈련장] 악성 스크립트 분석.zip</code> |
| Archive SHA-256 | <code>839417f453fc581b289854d07f9f537b3e0e868471505690608aecdfabefd25d</code> |
| Lessons | 14 |
| Slides | 178 PNG images |
| Uncompressed size | 32,239,029 bytes |
| Integrity result | ZIP CRC test passed |
| Archive safety result | No path traversal, symbolic links, or encrypted entries |

### 1.2 Evidence limitations

- The archive contains screenshots only. It does not contain the original PowerShell, VBScript, JScript, HTA, AutoIt, PE, or payload files.
- Hashes, signatures, compiler metadata, runtime behavior, and network responses for the course samples therefore cannot be independently verified.
- Code and indicators were reconstructed only to the extent visible in the slides. A real investigation must repeat the analysis against original evidence.
- PAT-like GitLab strings displayed in the course are credentials, regardless of whether they are expired or synthetic. This handbook redacts them.
- The folder name for lesson 12 mentions VBS obfuscation and steganography, but the actual slides teach VBScript debugging and a WScript-to-PowerShell chain. A separate steganography section fills that gap.

## 2. Course coverage

| Lesson | Course subject | Analyst outcome |
|---|---|---|
| 01 | Malicious scripts and attack overview | Understand lure → obfuscated script → payload staging |
| 02 | PowerShell attack fundamentals | Recognize EncodedCommand, IEX, WebClient, and Assembly.Load |
| 03 | PowerShell evasion theory | Analyze XOR, character arrays, ROT, Add-Type, P/Invoke, AMSI, and anti-analysis |
| 04 | ISE and Base64 lab | Decode UTF-16LE Base64 and normalize IEX variants |
| 05 | DownloadString and fileless execution | Distinguish memory execution from file download |
| 06 | Assembly.Load lab | Recover Base64 PE data and inspect .NET types, methods, and entry points |
| 07 | Three obfuscation methods | Reverse single/repeating XOR, numeric character arrays, and ROT |
| 08 | Dynamic execution and shellcode-loading theory | Identify Add-Type, DllImport, memory allocation, copy, and thread APIs |
| 09 | AMSI memory-patching lab | Detect AmsiScanBuffer resolution, protection changes, and code tampering |
| 10 | Information-collection case study | Reconstruct IP/MAC gating, GitLab communication, GZip restoration, and in-memory loading |
| 11 | VBScript/JScript fundamentals | Analyze WSH hosts and high-risk COM ProgIDs |
| 12 | VBScript debugging | Follow WScript.Shell and hidden PowerShell execution |
| 13 | AutoIt fundamentals | Understand directives, variables, macros, strings, and ObjCreate |
| 14 | AutoIt debugging | Trace execution, misleading comments, types, and environment macros |

## 3. Standard analysis workflow

~~~text
Preserve and hash the evidence
          ↓
Identify format, interpreter, and container
          ↓
Parse structure and extract strings without execution
          ↓
Reverse each obfuscation layer
          ↓
Build the process, data, and control-flow graphs
          ↓
Perform contained dynamic analysis only if necessary
          ↓
Extract IoCs and behavioral indicators
          ↓
Map detections, ATT&CK techniques, impact, and response
~~~

### 3.1 Intake and preservation

- Copy the original into a read-only evidence location.
- Calculate SHA-256 before opening or transforming it.
- Record filename, size, timestamps, source host, collector, timezone, and acquisition method.
- Separate delivery containers such as ZIP, ISO, LNK, Office, OneNote, HWP, and HTML from their embedded content. Hash every layer.
- Do not trust an extension; verify magic bytes and MIME.
- Record Alternate Data Streams, Zone.Identifier, digital signatures, and archive encryption.
- Hash every decoded, decompressed, repaired, or extracted derivative.
- Treat discovered passwords, tokens, cookies, or private keys as secrets. Do not paste them into reports or tickets.

### 3.2 Questions that drive the investigation

1. What was the initial execution point: attachment, link, LNK, document, browser, or ClickFix instruction?
2. Which interpreter or signed binary executed the content?
3. What are the complete parent and child process chains?
4. Does the content execute from memory, disk, or both?
5. How are URLs, headers, credentials, filenames, and keys constructed?
6. How many obfuscation and compression layers exist?
7. Does behavior depend on user, IP, MAC, hostname, domain, locale, or time?
8. Does the script establish persistence, escalate privilege, collect data, or exfiltrate?
9. Does the sandbox path differ from the targeted-host path?
10. Which claims are proven by execution evidence, and which are only latent code?

### 3.3 Language and host triage

| Clue | Likely format or host | Immediate focus |
|---|---|---|
| <code>.ps1</code>, powershell.exe, pwsh.exe | PowerShell | Command line, encoding, Script Blocks, .NET and native calls |
| <code>.vbs</code>, <code>.vbe</code> | VBScript/WSH | CreateObject, Execute/Eval, Run/Exec |
| <code>.js</code>, <code>.jse</code> | JScript/WSH | ActiveXObject, eval, fromCharCode |
| <code>.hta</code>, mshta.exe | HTML Application | Remote URL, script blocks, ActiveX, script URI |
| <code>.bat</code>, <code>.cmd</code> | cmd.exe | Variable slicing, delayed expansion, nested LOLBins |
| <code>.au3</code> or an AutoIt-compiled PE | AutoIt | Directives, macros, Chr/StringReverse, ObjCreate |
| Office document | VBA or XLM | Auto-run triggers, shell execution, download APIs |
| <code>MZ</code> or Base64 beginning <code>TVqQ</code> | PE/.NET data | Architecture, CLR metadata, signature, imports |
| <code>1F 8B 08</code> | GZip | Header damage, decompressed type and hash |

## 4. Safe analysis environment

### 4.1 Recommended lab

- Disposable Windows VM with a clean snapshot
- No route to production or the normal Internet
- Shared folders, clipboard, drag-and-drop, and automatic USB attachment disabled
- No corporate credentials, VPN, cloud CLI, browser profile, or password manager
- FakeNet-NG or INetSim when network simulation is necessary
- Sysmon, Procmon, System Informer/Process Explorer, Wireshark, and EDR telemetry enabled
- Sufficient storage for memory dumps and before/after snapshots

### 4.2 Practical sequence

1. Perform hashing, file identification, string extraction, and parsing in a static-analysis VM.
2. Defang URLs and remove or replace credentials in an analysis copy.
3. Transfer only the minimum required sample into a separate dynamic VM.
4. Start event, process, file, registry, memory, and network capture first.
5. Run one controlled test and preserve its artifacts.
6. Revert the VM instead of attempting to clean it manually.

### 4.3 Tool cautions

- PowerShell ISE is a legacy Windows PowerShell 5.1 tool. It is useful for course demonstrations but should not be used to open and run live evidence on an analyst workstation.
- Microsoft Script Debugger is also legacy. Prefer static parsing and modern instrumentation where possible.
- Verify the provenance and signature of debuggers, decompilers, and malware-analysis utilities.
- A decompiler output is an interpretation, not the original source. Correlate it with runtime evidence.

## 5. Infection chain and living-off-the-land view

~~~text
Lure or delivery
  LNK / ZIP / ISO / PDF / HWP / Office / OneNote / ClickFix
       ↓
Signed execution host
  PowerShell / wscript / cscript / mshta / cmd / rundll32
       ↓
Obfuscated script
  Base64 / XOR / character arrays / ROT / split strings / compression
       ↓
Retrieval and restoration
  WebClient / XMLHTTP / WinHTTP / SaaS API / GZip
       ↓
Execution
  IEX / Assembly.Load / Add-Type + P/Invoke / drop and launch
       ↓
Objective
  Discovery / persistence / command and control / theft / ransomware
~~~

A Microsoft signature on powershell.exe, wscript.exe, or mshta.exe authenticates that host binary; it does not authenticate the content supplied to it.

## 6. PowerShell analysis

### 6.1 Platform distinctions

- Windows PowerShell 5.1 is included with supported Windows versions.
- PowerShell 7 uses <code>pwsh.exe</code> and is normally installed separately.
- The <code>.ps1</code> extension does not constrain a script to engine version 1.
- Execution Policy is an administrative safety feature, not a security boundary. A Bypass option is useful context but not proof by itself.

### 6.2 Command-line switches

| Switch or alias | Meaning | Analyst action |
|---|---|---|
| <code>-EncodedCommand</code>, <code>-enc</code> | Base64-encoded command | Decode bytes, usually as UTF-16LE |
| <code>-Command</code>, <code>-c</code> | Inline command | Normalize quoting, escaping, and nested shells |
| <code>-File</code> | Script path | Hash the file and preserve Zone.Identifier |
| <code>-NoProfile</code>, <code>-nop</code> | Skip profiles | Correlate with other evasion signals |
| <code>-WindowStyle Hidden</code> | Hide the console | Raise priority when launched by Office or WSH |
| <code>-ExecutionPolicy Bypass</code> | Ignore policy for this launch | Record but do not treat as a vulnerability exploit |
| <code>-NonInteractive</code> | Disable prompts | Common in both automation and attacks |

### 6.3 PoC 1: create and decode EncodedCommand safely

This lab encodes only <code>Write-Output</code>. It never invokes the encoded command.

~~~powershell
$PlainText = "Write-Output 'LAB_ONLY'"
$Bytes = [Text.Encoding]::Unicode.GetBytes($PlainText)
$Encoded = [Convert]::ToBase64String($Bytes)

"Encoded value: $Encoded"

$DecodedBytes = [Convert]::FromBase64String($Encoded)
$DecodedText = [Text.Encoding]::Unicode.GetString($DecodedBytes)
"Decoded value: $DecodedText"

if ($DecodedText -ne $PlainText) {
    throw "Round-trip validation failed"
}
~~~

Expected artifacts:

- Base64 text with many null-byte patterns because UTF-16LE stores most ASCII characters as two bytes.
- Decoded text equal to the original harmless command.
- No child process, network connection, file, or Script Block execution from the decoded value.

### 6.4 PoC 2: offline multi-encoding Base64 triage

~~~python
import base64
import hashlib

candidate = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEwAQQBCAF8ATwBOAEwAWQAnAA=="
raw = base64.b64decode(candidate, validate=False)

print("byte_length:", len(raw))
print("sha256:", hashlib.sha256(raw).hexdigest())

for encoding in ("utf-16le", "utf-8", "utf-16be", "cp949"):
    try:
        print(f"{encoding}: {raw.decode(encoding)!r}")
    except UnicodeDecodeError:
        pass
~~~

The script decodes data only. Do not add <code>exec</code>, <code>eval</code>, <code>subprocess</code>, or an equivalent execution sink.

### 6.5 IEX and indirect execution

Normalize all of these into the same behavior: **a string flows into the PowerShell parser and is executed**.

- Direct: <code>Invoke-Expression $text</code>
- Alias: <code>IEX $text</code>
- Pipeline: <code>$text | IEX</code>
- Split name: <code>'IE' + 'X'</code>
- Call operator: <code>&amp; ($left + $right) $text</code>
- Alias or command resolution through variables

Do not search for the literal IEX alone. Trace the data flow into any dynamic execution sink.

### 6.6 PoC 3: harmless dynamic-expression observation

Run only in the disposable lab because it intentionally exercises the dynamic parser. The input is a fixed constant and does not accept user or network data.

~~~powershell
$FixedLabString = "Write-Output 'DYNAMIC_PARSER_LAB_ONLY'"

$Tokens = $null
$Errors = $null
$Ast = [Management.Automation.Language.Parser]::ParseInput(
    $FixedLabString,
    [ref]$Tokens,
    [ref]$Errors
)

"AST type: $($Ast.GetType().FullName)"
"Commands found:"
$Ast.FindAll(
    { param($Node) $Node -is [Management.Automation.Language.CommandAst] },
    $true
) | ForEach-Object { $_.GetCommandName() }

# Optional lab-only execution of the fixed constant:
Invoke-Expression $FixedLabString
~~~

Analyst lesson: parse first, inspect commands and strings, then decide whether dynamic execution is necessary.

### 6.7 Retrieval patterns

| Pattern | Result | Evidence |
|---|---|---|
| WebClient.DownloadString + IEX | String executed in memory | Script logs, process, memory, DNS/proxy |
| WebClient.DownloadFile | File written, then launched separately | MFT, USN, AV, file hash |
| Invoke-WebRequest | String, bytes, or file | Content handling and downstream sink |
| Invoke-RestMethod | API/JSON interaction | Method, headers, body, token |
| System.Net.WebRequest | Lower-level request | Proxy, TLS, response handling |

### 6.8 PoC 4: loopback-only download comparison

Create a directory containing a harmless text file named <code>message.txt</code>, then start a server bound only to localhost:

~~~bash
python3 -m http.server 8765 --bind 127.0.0.1
~~~

In a disposable Windows VM with the file available from the same loopback host:

~~~powershell
$Uri = "http://127.0.0.1:8765/message.txt"
$Client = [Net.WebClient]::new()

$InMemoryText = $Client.DownloadString($Uri)
"Memory text: $InMemoryText"

$Destination = Join-Path $env:TEMP "analysis-lab-message.txt"
$Client.DownloadFile($Uri, $Destination)
"Disk path: $Destination"
"Disk SHA256: $((Get-FileHash $Destination -Algorithm SHA256).Hash)"
~~~

This demonstrates memory versus disk acquisition without IEX, executable content, or an external destination.

## 7. Obfuscation analysis

### 7.1 Layer-by-layer discipline

Do not attempt to transform a heavily obfuscated script directly into a final verdict. Preserve every stage.

| Field | Record |
|---|---|
| Input | Name, SHA-256, length, encoding |
| Transform | Base64, XOR, ROT, character array, GZip, reversal, substitution |
| Parameters | Key, shift, range, iteration count |
| Output | SHA-256, type, new strings and IoCs |
| Validation | Magic bytes, syntax, known plaintext, length |
| Confidence | Verified, inferred, or incomplete |

### 7.2 XOR

XOR is reversible: applying the same key twice returns the original bytes.

- Single-byte XOR applies one value to every byte.
- Repeating-key XOR applies <code>key[index % key_length]</code>.
- Validation clues include printable text, URLs, JSON, <code>MZ</code>, <code>PK</code>, and <code>1F 8B</code>.

### 7.3 PoC 5: single-byte and repeating-key XOR

~~~python
def xor_cycle(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(
        value ^ key[index % len(key)]
        for index, value in enumerate(data)
    )

plain = b"ANALYST_LAB_ONLY"

single_key = bytes([0x41])
encoded_single = xor_cycle(plain, single_key)
decoded_single = xor_cycle(encoded_single, single_key)

repeat_key = b"ABC"
encoded_repeat = xor_cycle(plain, repeat_key)
decoded_repeat = xor_cycle(encoded_repeat, repeat_key)

print("single encoded:", encoded_single.hex())
print("single decoded:", decoded_single)
print("repeat encoded:", encoded_repeat.hex())
print("repeat decoded:", decoded_repeat)

assert decoded_single == plain
assert decoded_repeat == plain
~~~

Analyst lesson: recover the key-generation logic from the script before attempting brute force. Hash the encoded and decoded artifacts separately.

### 7.4 Numeric character arrays

Common equivalent forms:

- PowerShell: integer arrays cast through <code>[char]</code> and joined
- VBScript: <code>Chr</code> or <code>ChrW</code>
- JScript: <code>String.fromCharCode</code>
- AutoIt: <code>Chr</code>

Course examples concealed:

- System.Drawing
- System.Windows.Forms
- System.Reflection.Assembly
- Load
- EntryPoint
- 127. and 169.254.
- GitLab API paths

### 7.5 PoC 6: recover character arrays

~~~python
values = [83, 121, 115, 116, 101, 109, 46,
          82, 101, 102, 108, 101, 99, 116, 105, 111, 110]

decoded = "".join(chr(value) for value in values)
print(decoded)

assert decoded == "System.Reflection"
~~~

PowerShell equivalent:

~~~powershell
$Values = 83,121,115,116,101,109,46,82,101,102,108,101,99,116,105,111,110
$Decoded = -join ($Values | ForEach-Object { [char]$_ })
$Decoded
~~~

### 7.6 ROT/Caesar substitution

The course case study uses different alphabetic shifts for different values, including +2, +3, +4, +12, +15, +16, and +21. Digits and punctuation are preserved.

### 7.7 PoC 7: rotate and reverse alphabetic text

~~~python
def rotate_ascii(text: str, shift: int) -> str:
    result = []
    for char in text:
        if "A" <= char <= "Z":
            result.append(chr(65 + (ord(char) - 65 + shift) % 26))
        elif "a" <= char <= "z":
            result.append(chr(97 + (ord(char) - 97 + shift) % 26))
        else:
            result.append(char)
    return "".join(result)

plain = "PRIVATE-TOKEN"
encoded = rotate_ascii(plain, 7)
decoded = rotate_ascii(encoded, -7)

print("encoded:", encoded)
print("decoded:", decoded)
assert decoded == plain
~~~

Use known plaintext such as header names, URL schemes, date formats, or file signatures to verify the direction and shift.

### 7.8 String splitting and indirection

Normalize patterns such as:

- <code>'Am' + 'si' + 'Scan' + 'Buffer'</code>
- Arrays joined at runtime
- PowerShell format operator <code>-f</code>
- Substring extraction and indexing
- Environment-variable slicing
- Reversed strings
- Mixed case and Unicode homoglyphs

Build a value-definition-use graph before renaming variables. A meaningless variable can still control a target gate or provide a decoder key.

### 7.9 GZip and damaged headers

GZip normally begins <code>1F 8B 08</code>. The course case study overwrites the first eight downloaded bytes with a normal GZip header before decompression.

Correct evidence procedure:

1. Preserve and hash the original bytes.
2. Record every replaced offset and byte.
3. Write a repaired copy and hash it.
4. Decompress into a new file and hash the result.
5. Identify the output without loading or executing it.

### 7.10 PoC 8: benign GZip header-restoration lab

~~~python
import gzip
import hashlib

plain = b"COMPRESSED_ANALYST_LAB_ONLY"
original_gzip = gzip.compress(plain, mtime=0)

# Simulate a sample with only the first eight bytes damaged.
damaged = b"BADHDR!!" + original_gzip[8:]

restored = bytes.fromhex("1f8b080000000000") + damaged[8:]
decoded = gzip.decompress(restored)

print("damaged_sha256:", hashlib.sha256(damaged).hexdigest())
print("restored_sha256:", hashlib.sha256(restored).hexdigest())
print("decoded:", decoded)

assert decoded == plain
~~~

The lab reconstructs known benign bytes. Never decompress an untrusted result directly into an executable search path.

## 8. .NET in-memory loading and Reflection

### 8.1 Course execution chain

~~~text
Base64 string
   → FromBase64String
   → PE/.NET byte array
   → Reflection.Assembly.Load(bytes)
   → GetTypes / GetMethod / EntryPoint
   → Invoke
~~~

Important clues:

- Base64 beginning <code>TVqQ</code> often decodes to <code>MZ</code>.
- Decimal bytes 77 and 90 are ASCII M and Z.
- <code>Assembly.Load(byte[])</code> can load a .NET assembly without a corresponding file path.
- An empty <code>Assembly.Location</code> is common for byte-array loads.
- <code>ReflectionTypeLoadException</code> handling may allow partial type enumeration.
- Fallback code may search every type for a static <code>Main</code> when EntryPoint is null.

### 8.2 Required extraction targets

- Encoded or encrypted source blob
- Decoded PE bytes and SHA-256
- Assembly name, version, MVID, and target framework
- Namespace, type, method, and property lists
- EntryPoint and arguments
- Embedded resources, configuration, URLs, and keys
- P/Invoke declarations

An empty Location and Assembly.Load are not independently malicious. Plugins, test frameworks, and legitimate applications also load byte arrays. Correlate source, parent process, network retrieval, obfuscation, and post-load behavior.

### 8.3 PoC 9: benign in-memory assembly load

Windows PowerShell 5.1 lab only. The complete C# source is visible and prints a fixed value. It does not use the network, native APIs, or executable-memory allocation.

~~~powershell
$Source = @"
using System;
public static class BenignLab
{
    public static string Run()
    {
        return "IN_MEMORY_ASSEMBLY_LAB_ONLY";
    }
}
"@

$Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$Options = New-Object System.CodeDom.Compiler.CompilerParameters
$Options.GenerateExecutable = $false
$Options.GenerateInMemory = $false
$Options.OutputAssembly = Join-Path $env:TEMP "BenignLab.dll"

$Result = $Provider.CompileAssemblyFromSource($Options, $Source)
if ($Result.Errors.Count -ne 0) {
    $Result.Errors | ForEach-Object { $_.ToString() }
    throw "Compilation failed"
}

$Bytes = [IO.File]::ReadAllBytes($Options.OutputAssembly)
$Hash = [BitConverter]::ToString(
    [Security.Cryptography.SHA256]::Create().ComputeHash($Bytes)
).Replace("-", "")

$Assembly = [Reflection.Assembly]::Load($Bytes)
$Type = $Assembly.GetType("BenignLab")
$Method = $Type.GetMethod("Run")
$Value = $Method.Invoke($null, $null)

"SHA256: $Hash"
"Assembly: $($Assembly.FullName)"
"Location: '$($Assembly.Location)'"
"Result: $Value"
~~~

Expected observations:

- The temporary DLL exists because the lab compiler emits it for transparent provenance.
- The loaded assembly instance is created from the byte array.
- Its loaded instance normally has an empty Location.
- Reflection identifies the fixed class and method.

The difference between this benign lab and a suspicious sample is provenance and behavior: visible local source versus opaque remote bytes, and harmless output versus hidden payload execution.

## 9. Add-Type, P/Invoke, and memory-loader recognition

### 9.1 High-risk API sequence

| Stage | API or pattern | Meaning |
|---|---|---|
| Runtime compilation | Add-Type, TypeDefinition, Here-String | Create a .NET type |
| Native declaration | DllImport, kernel32, ntdll | P/Invoke |
| Allocation | VirtualAlloc, VirtualAllocEx, NtAllocateVirtualMemory | Obtain memory |
| Protection change | VirtualProtect, VirtualProtectEx, NtProtectVirtualMemory | Add execution or write rights |
| Copy | Marshal.Copy, WriteProcessMemory, RtlMoveMemory | Place payload bytes |
| Transfer control | CreateThread, remote thread, delegate, callback | Begin execution |

Attackers can allocate RW, copy bytes, and then change to RX instead of requesting RWX immediately. Detect the sequence, not only a single protection value.

### 9.2 PoC 10: safe P/Invoke without memory manipulation

This Windows-only lab calls <code>GetCurrentProcessId</code>. It does not allocate, copy, protect, or execute memory.

~~~powershell
$Source = @"
using System;
using System.Runtime.InteropServices;

public static class SafeNativeLab
{
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();
}
"@

Add-Type -TypeDefinition $Source

$ManagedPid = $PID
$NativePid = [SafeNativeLab]::GetCurrentProcessId()

"Managed PID: $ManagedPid"
"Native PID:  $NativePid"

if ($ManagedPid -ne $NativePid) {
    throw "Unexpected PID mismatch"
}
~~~

Analyst lesson: Add-Type plus DllImport is not automatically malicious. The imported function and downstream data flow determine risk.

### 9.3 Memory-analysis checklist

- New private executable regions in powershell.exe or pwsh.exe
- Regions not backed by a signed module
- MZ/PE headers inside private memory
- Headerless position-independent code
- New thread start addresses outside normal image ranges
- Call stacks involving CLR dynamic methods and unbacked memory
- Network-derived buffers followed by copy and execution
- Code-page changes in amsi.dll, ntdll.dll, or kernel32.dll

## 10. AMSI and defensive integrity inspection

### 10.1 Architecture

AMSI connects script/content hosts such as PowerShell, WSH, and Office with antimalware providers. It can inspect content after some decoding and before execution, including content that never exists as a normal file.

The course memory-patching chain is:

1. Construct the strings <code>amsi.dll</code> and <code>AmsiScanBuffer</code>.
2. Resolve the module and function address.
3. Change the code page's protection.
4. Copy a short patch into the function entry.
5. Force an error or immediate return before scanning.

This handbook intentionally does not provide a working bypass or patch sequence.

### 10.2 Detection strategy

- String splitting that reconstructs amsi.dll or AmsiScanBuffer
- LoadLibrary/GetProcAddress followed by VirtualProtect
- A short write into an amsi.dll executable page
- In-memory function bytes that differ from the signed on-disk image
- Loss of AMSI or Script Block visibility immediately before high-risk behavior
- EDR tamper alerts followed by remote retrieval or in-memory loading

Fixed-byte signatures are brittle. Detect function resolution → protection change → code overwrite as a behavioral chain.

### 10.3 PoC 11: read-only AmsiScanBuffer byte inspection

Windows PowerShell lab only. It reads the first bytes from the current process and does not change protection or memory.

~~~powershell
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class ReadOnlyNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);
}
"@

$Module = [ReadOnlyNative]::LoadLibrary("amsi.dll")
if ($Module -eq [IntPtr]::Zero) {
    throw "Could not load amsi.dll"
}

$Address = [ReadOnlyNative]::GetProcAddress($Module, "AmsiScanBuffer")
if ($Address -eq [IntPtr]::Zero) {
    throw "Could not resolve AmsiScanBuffer"
}

$Bytes = New-Object byte[] 16
[Runtime.InteropServices.Marshal]::Copy($Address, $Bytes, 0, $Bytes.Length)

"Address: 0x$($Address.ToInt64().ToString('X'))"
"First 16 bytes: $([BitConverter]::ToString($Bytes))"
~~~

For incident response, compare memory against a trusted image of the exact same Windows build. Different builds and architectures legitimately have different bytes.

## 11. Anti-analysis

| Category | Examples | Defensive response |
|---|---|---|
| Environment checks | CPU, RAM, domain, VM processes | Reconstruct every condition and observed value |
| Time checks | Long sleep, time acceleration tests | Record timers and compare wall/guest time |
| Junk/dead code | Unused functions, impossible branches | Prioritize real data and control flow |
| Target gates | User, IP, MAC, hostname | Analyze both branches statically |

Additional checks include locale, timezone, keyboard, screen resolution, input activity, installed software, files, registry keys, network reachability, and debugger process names.

### 11.1 PoC 12: non-gating environment inventory

The lab prints values but never changes behavior based on them.

~~~powershell
$Inventory = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    ProcessorCount = [Environment]::ProcessorCount
    Is64BitProcess = [Environment]::Is64BitProcess
    OSVersion = [Environment]::OSVersion.VersionString
    Domain = $env:USERDOMAIN
    CurrentDirectory = (Get-Location).Path
}

$Inventory.GetEnumerator() |
    ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }

"LAB_ONLY: no gate and no payload"
~~~

In a real sample, find where each value flows and which comparison selects the next stage.

## 12. Case study: R1.ps1 information collector

### 12.1 Reconstructed behavior

~~~text
Start
  ├─ Junk and unreachable code
  ├─ Numeric arrays reconstruct assembly and API strings
  ├─ Collect IPv4 addresses, excluding loopback and link-local
  ├─ Collect and normalize an active adapter MAC
  └─ Compare against 8 IPs and 36 MACs
       ├─ Match
       │   ├─ Construct GitLab API payload URL
       │   ├─ Decode PAT-like value and PRIVATE-TOKEN header
       │   ├─ Download jka.beep
       │   ├─ Repair GZip header
       │   ├─ Decompress .NET assembly
       │   ├─ Assembly.Load
       │   └─ Invoke EntryPoint or find Main
       └─ No match
           ├─ Collect time, MAC, IP, computer, and user
           ├─ Build access_denied_*.txt record
           ├─ Construct a separate GitLab logging API URL
           └─ Attempt to upload environment data
~~~

### 12.2 Initial obfuscation and discovery

- An impossible condition based on GUID string length acts as junk.
- Numeric arrays reconstruct System.Drawing, System.Windows.Forms, PresentationCore, IP prefixes, and API names.
- Get-NetIPAddress collects IPv4 addresses.
- Reconstructed prefixes 127. and 169.254. exclude loopback and link-local addresses.
- Get-NetAdapter returns an active MAC, which is normalized to uppercase with hyphens.

### 12.3 Target IP list visible in the slides

~~~text
192.168.121.1
192.168.124.57
192.168.121.128
172.21.48.1
192.168.1.195
192.168.56.1
192.168.137.1
192.168.31.208
~~~

### 12.4 Target MAC list visible in the slides

~~~text
EA-E6-A6-A8-CD-0C  28-2E-89-A5-26-EE  00-45-E2-AC-70-8F
38-B1-DB-24-A0-65  E0-D4-E8-B8-CC-9D  18-CC-18-7A-88-B6
3C-9C-0F-BF-E5-AF  6C-3C-8C-1E-34-4C  11-22-33-44-55-66
10-B1-DF-CB-3D-59  F0-4D-A2-42-8B-97  50-76-AF-44-E1-DE
2C-3B-70-68-98-D1  C8-34-8E-4A-1A-03  10-7C-61-44-31-03
B4-69-21-45-BA-55  00-15-5D-7C-DB-8B  5C-FB-3A-DB-4D-91
2C-F0-5D-E4-C0-58  5C-3A-45-82-2A-57  48-51-C5-6A-C4-35
30-89-4A-DF-6D-DA  34-7D-F6-BD-51-7D  50-E0-85-A0-54-47
F8-FE-5E-16-54-22  D8-F2-CA-56-CB-1A  9C-67-D6-2B-C3-F2
BC-24-11-A3-5C-73  C4-03-A8-D1-AB-3C  24-4B-FE-7C-5C-81
00-45-E2-8F-7A-D3  A4-C4-94-96-FE-DD  34-64-A9-2B-94-22
00-15-5D-7A-78-B0  50-3E-AA-B3-4F-74  54-BF-64-6C-9B-C5
~~~

These are training-case conditions, not independently confirmed malicious infrastructure. Do not add them to production blocklists without incident context and asset validation.

### 12.5 Matched branch

- Constructs a GitLab API URL from numeric arrays.
- Appends a path ending in <code>jka.beep/raw?ref=main</code>.
- Applies ROT+3 to recover a PAT-like credential.
- Joins fragments into the header name <code>PRIVATE-TOKEN</code>.
- Retrieves byte content with Invoke-WebRequest.
- Repairs the first eight bytes as a GZip header.
- Decompresses a .NET assembly.
- Resolves Reflection types and loads the byte array.
- Invokes EntryPoint or searches all types for a static Main fallback.

### 12.6 Non-matched branch

- Collects current time, MAC, first IPv4, computer name, and user.
- Creates a name shaped like <code>access_denied_DATE_MAC_IP.txt</code>.
- Constructs an API path for a separate GitLab logging project.
- Decodes a token-like value and HTTP headers through different ROT shifts.
- Attempts to upload the collected environment record as JSON.

The no-match branch is not inactive. It is a reconnaissance and telemetry path.

### 12.7 Indicators from the course

| Type | Indicator or behavior | Handling |
|---|---|---|
| Domain | <code>gitlab[.]com</code> | Correlate path, process, method, and headers; do not block all GitLab |
| Payload path | <code>/api/v4/projects/ekek2-group%2Fekek2-project/repository/files/jka.beep/raw?ref=main</code> | Search proxy, EDR, and memory telemetry |
| Log path | <code>/api/v4/projects/ekek2-group%2Fekek2-log-project/repository/files/log2%2F...</code> | Hunt API writes and generated names |
| Payload name | <code>jka.beep</code> | Inspect content as repaired GZip/.NET rather than trusting extension |
| Log name | <code>access_denied_*.txt</code> | Search hosts, API logs, and proxies |
| Header | <code>PRIVATE-TOKEN</code> | Redact value and rotate exposed credentials |
| Target gate | 8 IPs or 36 MACs | Compare with actual assets |

### 12.8 PoC 13: safe target-gate emulator

The lab uses supplied strings only. It does not enumerate the host, connect to a network, or load a payload.

~~~python
TARGET_IPS = {
    "192.168.121.1",
    "192.168.124.57",
}

TARGET_MACS = {
    "11-22-33-44-55-66",
    "EA-E6-A6-A8-CD-0C",
}

def normalize_mac(value: str) -> str:
    return value.replace(":", "-").upper()

def select_branch(ip_values, mac_value):
    ip_match = any(ip in TARGET_IPS for ip in ip_values)
    mac_match = normalize_mac(mac_value) in TARGET_MACS
    return {
        "ip_match": ip_match,
        "mac_match": mac_match,
        "branch": "MATCHED_LAB_BRANCH" if ip_match or mac_match
                  else "NON_MATCHED_LAB_BRANCH",
    }

tests = [
    (["203.0.113.10"], "AA:BB:CC:DD:EE:FF"),
    (["192.168.121.1"], "AA:BB:CC:DD:EE:FF"),
    (["203.0.113.10"], "11:22:33:44:55:66"),
]

for addresses, mac in tests:
    print(addresses, mac, select_branch(addresses, mac))
~~~

Analyst lesson: evaluate both sides of a target gate without altering or executing the real sample.

## 13. VBScript, JScript, and HTA

### 13.1 Script hosts

| Binary | Role | Focus |
|---|---|---|
| wscript.exe | GUI WSH host | Hidden execution and child processes |
| cscript.exe | Console WSH host | Output collection and command line |
| mshta.exe | HTA/script URI host | Remote URLs, javascript:, vbscript:, ActiveX |

VBScript is deprecated and is moving through a Windows Feature on Demand lifecycle. Verify whether it is installed and enabled on the affected build.

### 13.2 Important COM ProgIDs

| ProgID | Methods or properties | Typical meaning |
|---|---|---|
| WScript.Shell | Run, Exec, RegWrite | Execute commands, read output, modify registry |
| Scripting.FileSystemObject | OpenTextFile, CreateTextFile, DeleteFile | Read, drop, or remove files |
| MSXML2.XMLHTTP | open, send, responseBody | HTTP retrieval or C2 |
| WinHttp.WinHttpRequest.5.1 | Open, Send | Lower-level HTTP |
| ADODB.Stream | Write, SaveToFile | Save binary response data |
| Shell.Application | ShellExecute | Launch files or commands |
| Schedule.Service | Task registration | Persistence |
| WScript.Network | UserName, ComputerName, UserDomain | Discovery |

High-risk chain:

~~~text
XMLHTTP or WinHTTP
  → responseBody
  → ADODB.Stream
  → SaveToFile
  → WScript.Shell or Shell.Application
  → execution
~~~

### 13.3 Course p1.vbs behavior

1. Creates WScript.Shell.
2. Launches a hidden command to collect the current user into a file.
3. Launches hidden PowerShell.
4. Supplies execution-policy and profile options.
5. Attempts a WebClient DownloadString + IEX chain.

Do not reproduce the course's external URL. Use a loopback simulator if dynamic observation is necessary.

### 13.4 PoC 14: benign VBScript COM and file operation

Save as <code>safe_lab.vbs</code> in a disposable Windows VM. It uses FileSystemObject directly and does not launch a child process.

~~~vbscript
Option Explicit

Dim shell, fso, path, file
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

path = shell.ExpandEnvironmentStrings("%TEMP%") & "\vbs_analysis_lab.txt"
Set file = fso.CreateTextFile(path, True)
file.WriteLine "VBS_COM_LAB_ONLY"
file.Close

WScript.Echo "Created: " & path
WScript.Echo "Shell type: " & TypeName(shell)
WScript.Echo "FSO type: " & TypeName(fso)
~~~

Expected evidence: wscript/cscript process and one temporary text file. There is no cmd, PowerShell, network, registry, or persistence activity.

### 13.5 PoC 15: benign JScript ActiveX

~~~javascript
var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var path = shell.ExpandEnvironmentStrings("%TEMP%") +
           "\\jscript_analysis_lab.txt";

var file = fso.CreateTextFile(path, true);
file.WriteLine("JSCRIPT_COM_LAB_ONLY");
file.Close();

WScript.Echo("Created: " + path);
~~~

### 13.6 PoC 16: inert HTA structure

This example performs only local DOM rendering. Do not add ActiveX, command execution, or remote content.

~~~html
<html>
<head>
  <title>HTA Analysis Lab</title>
  <hta:application id="app" border="thin" />
  <script language="javascript">
    function showLabMessage() {
      document.getElementById("output").innerText =
        "HTA_DOM_LAB_ONLY";
    }
  </script>
</head>
<body onload="showLabMessage()">
  <div id="output"></div>
</body>
</html>
~~~

Static-analysis targets in a suspicious HTA include script URIs, remote includes, ActiveXObject/CreateObject, eval, unescape, fromCharCode, and shell-launch methods.

## 14. AutoIt analysis

### 14.1 Source structure

~~~text
Compiler directives
  #RequireAdmin / #NoTrayIcon / #include / #pragma
Global variables
  Global / Dim
Functions
  Func ... EndFunc
Main execution code
~~~

Directives can immediately reveal privilege requests, hidden tray behavior, included libraries, icons, metadata, and compilation options.

### 14.2 Variables, comments, and macros

- Variables begin with <code>$</code>.
- Scope keywords are Global, Local, and Dim.
- A semicolon starts a line comment.
- <code>#cs</code> and <code>#ce</code> delimit block comments.
- Homoglyphs can cause parser errors or visual deception; inspect Unicode code points.

| Macro | Meaning | Analyst relevance |
|---|---|---|
| @TempDir | Temporary folder | Drop path |
| @AppDataDir | Roaming AppData | Configuration or persistence |
| @StartupDir | Startup folder | Persistence |
| @ComputerName | Hostname | Discovery or gating |
| @UserName | User | Discovery or gating |
| @OSVersion | OS build family | Environment check |
| @ScriptDir | Script directory | Locate companion files |
| @HOUR/@MIN/@SEC | Time | Naming or timing gate |

### 14.3 Strings and COM

Important functions:

- Chr
- StringReverse
- BinaryToString
- The <code>&amp;</code> concatenation operator

ObjCreate is the COM object creation point. Follow WScript.Shell, FileSystemObject, XMLHTTP, or WinHTTP methods into process, file, registry, and network behavior.

### 14.4 PoC 17: benign AutoIt strings and macros

~~~autoit
; Safe AutoIt analysis lab: no admin request, hidden icon, network, or process launch.

Local $NumericText = Chr(76) & Chr(65) & Chr(66)
Local $Reversed = StringReverse("YLNO")
Local $Combined = $NumericText & "_" & $Reversed

ConsoleWrite("Value=" & $Combined & @CRLF)
ConsoleWrite("TempDir=" & @TempDir & @CRLF)
ConsoleWrite("ComputerName=" & @ComputerName & @CRLF)
ConsoleWrite("UserName=" & @UserName & @CRLF)

If $Combined <> "LAB_ONLY" Then
    ConsoleWrite("Unexpected decode result" & @CRLF)
    Exit 1
EndIf
~~~

### 14.5 Compiled AutoIt executables

1. Hash the PE and verify its signature.
2. Identify packer, compiler, resources, and overlay.
3. Search for AutoIt runtime and embedded script indicators.
4. Extract source only with a trusted tool and preserve the original hash.
5. Analyze the extracted AU3 separately.
6. Record hashes before and after unpacking.
7. Correlate incomplete decompilation with API, process, file, and network behavior.

## 15. BAT/CMD, Office, and steganography supplements

### 15.1 BAT/CMD patterns

- <code>%VAR:~start,length%</code> slicing
- Delayed expansion with <code>!VAR!</code>
- Caret escaping and line continuation
- <code>for /f</code> command-output parsing
- <code>set /a</code> arithmetic
- Indirect execution through <code>%COMSPEC%</code>
- Calls to PowerShell, mshta, rundll32, regsvr32, certutil, or bitsadmin

### 15.2 PoC 18: benign CMD normalization lab

~~~batch
@echo off
setlocal EnableDelayedExpansion

set "SOURCE=ANALYST_LAB_ONLY"
set "FIRST=!SOURCE:~0,7!"
set "SECOND=!SOURCE:~8,3!"
set "THIRD=!SOURCE:~12,4!"

echo Full=!SOURCE!
echo Pieces=!FIRST! ^| !SECOND! ^| !THIRD!

endlocal
~~~

Analyst lesson: expand variables and remove escaping before interpreting a command line.

### 15.3 Office macros

Focus on:

- AutoOpen, Document_Open, Workbook_Open
- Shell, WScript.Shell, CreateObject
- XMLHTTP, WinHTTP, URLDownloadToFile
- ADODB.Stream
- Chr, StrReverse, split strings, hidden worksheets, UserForms
- Office → cmd/PowerShell/wscript/mshta process lineage

Extract VBA statically from OLE/OOXML. Do not open a suspicious document with macros enabled.

### 15.4 PoC 19: inert VBA structure

~~~vb
Option Explicit

Sub AnalystLab()
    Dim values As Variant
    Dim i As Long
    Dim output As String

    values = Array(76, 65, 66, 95, 79, 78, 76, 89)
    For i = LBound(values) To UBound(values)
        output = output & Chr(values(i))
    Next i

    Debug.Print output
End Sub
~~~

The macro only reconstructs LAB_ONLY and writes it to the VBA Immediate window. It has no auto-run trigger or external side effect.

### 15.5 Steganography triage

- Inspect EXIF, PNG chunks, JPEG APP markers, and trailing data.
- Search beyond the normal image terminator for ZIP, PE, script, or archive signatures.
- Examine color and alpha planes when the sample contains image-decoding logic.
- Compare entropy and size with expected image dimensions.
- Use strings, ExifTool, binwalk, pngcheck, and zsteg in an isolated environment.
- Hash extracted content and identify it before opening.

### 15.6 PoC 20: detect trailing data after a PNG IEND chunk

This script reads only. It does not extract or execute appended content.

~~~python
from pathlib import Path
import hashlib
import sys

PNG_IEND = bytes.fromhex("0000000049454e44ae426082")

path = Path(sys.argv[1])
data = path.read_bytes()

if not data.startswith(bytes.fromhex("89504e470d0a1a0a")):
    raise SystemExit("Not a PNG file")

position = data.rfind(PNG_IEND)
if position < 0:
    raise SystemExit("IEND marker not found")

end = position + len(PNG_IEND)
trailing = data[end:]

print("file_sha256:", hashlib.sha256(data).hexdigest())
print("trailing_length:", len(trailing))
if trailing:
    print("trailing_sha256:", hashlib.sha256(trailing).hexdigest())
    print("first_16_bytes:", trailing[:16].hex())
~~~

Trailing bytes can be legitimate metadata or editor artifacts. They are an investigation lead, not an automatic malicious verdict.

## 16. Windows logs and forensic evidence

### 16.1 PowerShell evidence

| Source or event | Use |
|---|---|
| PowerShell Operational 4103 | Module Logging and pipeline details |
| PowerShell Operational 4104 | Script Block content |
| Windows PowerShell 400/403 | Engine start and stop |
| Security 4688 | Process creation and, when enabled, command line |
| Sysmon 1 | Process creation |
| Sysmon 3 | Network connection |
| Sysmon 7 | Image load, when configured |
| Sysmon 10 | Process access |
| Sysmon 11 | File creation |
| Sysmon 13 | Registry value modification |
| Sysmon 22 | DNS query |
| Defender/EDR | AMSI, behavioral blocking, and tamper events |

Script Block Logging can be absent because of policy, version, collection failure, or evasion. Missing logs do not prove missing activity.

Additional sources:

- PSReadLine history for interactive sessions
- PowerShell transcription when configured
- Prefetch
- Amcache and Shimcache
- SRUM, Windows Firewall, DNS, proxy, and EDR network telemetry
- MFT, USN Journal, and Zone.Identifier
- Memory dumps and loaded CLR assemblies

### 16.2 WSH, HTA, and AutoIt evidence

- Full command lines for wscript, cscript, mshta, and AutoIt executables
- Office, browser, mail client, Explorer, or LNK parent
- cmd, PowerShell, rundll32, or regsvr32 children
- Direct network connections from a script host
- New files in Temp, AppData, Public, or Startup
- Run/RunOnce, scheduled tasks, services, or WMI persistence
- Signature, resources, original filename, and overlay of a compiled AutoIt PE

### 16.3 Evidence in a fileless incident

- Process creation and command lines
- Script Block, AMSI, ETW, and EDR telemetry
- DNS, proxy, TLS, and firewall records
- CLR assemblies and private executable memory
- Process ancestry from browser, Office, or WSH
- URLs, configuration, PE bytes, GZip streams, and keys in memory
- Lure document, email, LNK, browser cache, and download metadata

## 17. Detection engineering

### 17.1 Strong correlation patterns

1. Office, browser, mail client, or LNK → script host
2. wscript/cscript/mshta → PowerShell
3. PowerShell + EncodedCommand + hidden window
4. PowerShell + DownloadString/Invoke-WebRequest + dynamic execution
5. Base64 decode + Assembly.Load + Invoke
6. Add-Type + DllImport + allocation/protection + byte copy
7. amsi.dll/AmsiScanBuffer resolution + code-page write
8. Script host → GitLab API/raw path + authentication header
9. Compiled AutoIt → Temp drop + WSH or PowerShell child
10. Discovery immediately followed by API POST/PUT

### 17.2 Sigma proof of concept

~~~yaml
title: Suspicious PowerShell In-Memory Or Remote Execution
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  suspicious:
    CommandLine|contains:
      - '-EncodedCommand'
      - 'DownloadString'
      - 'Invoke-Expression'
      - 'Assembly]::Load'
      - 'Reflection.Assembly'
      - 'AmsiScanBuffer'
      - 'VirtualProtect'
  condition: image and suspicious
falsepositives:
  - Administrative automation
  - Security testing
level: medium
~~~

This is a triage rule. Improve it with parent process, user, URL, network behavior, signer, allowlisted script, and Script Block context.

### 17.3 Microsoft Defender XDR KQL proof of concept

~~~kusto
DeviceProcessEvents
| where FileName in~ (
    "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe")
| where ProcessCommandLine has_any (
    "-EncodedCommand", "DownloadString", "Invoke-Expression",
    "Assembly]::Load", "Reflection.Assembly",
    "AmsiScanBuffer", "VirtualProtect", "Marshal]::Copy")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, FileName,
          ProcessCommandLine, SHA256
| order by Timestamp desc
~~~

### 17.4 PoC 21: static YARA triage rule

This rule is intentionally broad and should be used for analyst triage, not automatic blocking.

~~~yara
rule Suspicious_PowerShell_Feature_Cluster
{
    meta:
        purpose = "Defensive script triage"
        confidence = "low_to_medium"

    strings:
        $a1 = "FromBase64String" ascii wide nocase
        $a2 = "DownloadString" ascii wide nocase
        $a3 = "Invoke-Expression" ascii wide nocase
        $a4 = "Reflection.Assembly" ascii wide nocase
        $a5 = "Assembly]::Load" ascii wide nocase
        $a6 = "AmsiScanBuffer" ascii wide nocase
        $a7 = "VirtualProtect" ascii wide nocase
        $a8 = "Marshal]::Copy" ascii wide nocase

    condition:
        filesize < 2MB and 2 of ($a*)
}
~~~

### 17.5 GitLab API abuse hunting

Correlate:

- powershell, wscript, mshta, or an AutoIt process
- destination <code>gitlab.com</code>
- URI containing <code>/api/v4/projects/</code> and <code>/repository/files/</code>
- raw repository downloads or file API writes
- PRIVATE-TOKEN header use
- <code>jka.beep</code> or <code>access_denied_</code> naming
- repaired GZip or .NET content
- downstream Assembly.Load

GitLab is a legitimate service. Compare the account, project, CI runner, approved automation, and source control history before containment.

### 17.6 Risk grading

| Priority | Example |
|---|---|
| Low | Base64, IEX, or WScript.Shell alone |
| Medium | Encoding plus remote retrieval or hidden execution |
| High | Remote bytes plus Assembly.Load, WSH→PowerShell, or API token |
| Critical | Security-control tampering, native memory execution, target gate plus exfiltration |

## 18. MITRE ATT&CK mapping

| Technique | ID | Course relationship |
|---|---|---|
| PowerShell | T1059.001 | EncodedCommand, IEX, WebClient |
| Visual Basic | T1059.005 | VBScript and WSH |
| Windows Command Shell | T1059.003 | cmd and BAT |
| Mshta | T1218.005 | HTA and script URI execution |
| Obfuscated/Compressed Files and Information | T1027 | Base64, XOR, arrays, ROT, GZip |
| Deobfuscate/Decode Files or Information | T1140 | Runtime restoration |
| Ingress Tool Transfer | T1105 | WebClient and Invoke-WebRequest |
| Reflective Code Loading | T1620 | Assembly.Load from bytes |
| Native API | T1106 | P/Invoke and Win32 API calls |
| Impair Defenses | T1562.001 | AMSI tampering |
| Virtualization/Sandbox Evasion | T1497 | Environment and time checks |
| System Information Discovery | T1082 | Computer and OS |
| System Network Configuration Discovery | T1016 | IP and MAC |
| System Owner/User Discovery | T1033 | User discovery |
| Application Layer Protocol: Web | T1071.001 | HTTP(S) and GitLab API |
| Web Service | T1102 | SaaS as delivery or collection channel |
| Scheduled Task/Job | T1053.005 | Schedule.Service |
| Registry Run Keys / Startup Folder | T1547.001 | RegWrite and StartupDir |

Map only behavior that is present and supported by evidence. Uncalled dead code is a capability, not proof of execution.

## 19. Tool selection

| Purpose | Tools or capabilities |
|---|---|
| Hash and type | sha256sum/Get-FileHash, file, TrID, Detect It Easy |
| Metadata | ExifTool, PEStudio, sigcheck |
| Strings | strings, FLOSS, ripgrep, Unicode normalization |
| Offline decoding | Python, offline CyberChef |
| PowerShell static analysis | PowerShell AST parser, PSScriptAnalyzer |
| .NET | ILSpy, dnSpy-family tools, de4dot as an aid |
| JavaScript | Beautifier, static AST, contained emulator |
| Office | oletools/olevba, OOXML archive inspection |
| Native PE | Ghidra, IDA, x64dbg, WinDbg |
| Process and file activity | Procmon, System Informer/Process Explorer, Sysmon |
| Network | Wireshark, FakeNet-NG, INetSim, proxy logs |
| Memory | EDR, WinDbg, Volatility-family tools, process dump |
| Image/steganography | ExifTool, binwalk, pngcheck, zsteg |

## 20. Analysis deliverables

### 20.1 Execution-chain table

| Step | Actor | Input | Transform or action | Output | Evidence |
|---|---|---|---|---|---|
| 1 | Lure/user | Attachment or link | Launch script host | PowerShell command | Email, 4688 |
| 2 | PowerShell | EncodedCommand | Base64/UTF-16LE decode | Stage 2 code | Command line, 4104 |
| 3 | Stage 2 | URL and token | HTTP request | GZip bytes | Proxy, memory |
| 4 | Loader | GZip | Repair and decompress | .NET PE | Code, hashes |
| 5 | CLR | PE bytes | Assembly.Load and Invoke | Final behavior | Memory, EDR |

Add timestamps, PIDs, user, host, hashes, and URLs to a real-case table.

### 20.2 Deobfuscation ledger

| Layer | Input SHA-256 | Method | Key or parameter | Output SHA-256 | Validation |
|---|---|---|---|---|---|
| L1 |  | Base64 | UTF-16LE |  | Syntax |
| L2 |  | XOR | Single/repeating key |  | Magic/URL |
| L3 |  | GZip | Header repair |  | MZ/CLR |

### 20.3 IoC fields

- Type: domain, URL, IP, hash, filename, registry, mutex, header
- Raw and defanged values
- First and last observed timestamps
- Source: file, line, log, memory, or network
- Role: delivery, C2, payload, exfiltration, or gate
- Confidence: high, medium, or low
- Status: active, stale, training, or unverified
- Scope and false-positive risk
- Credential exposure and rotation requirement

## 21. Report template

### 21.1 Executive summary

- What the sample is and what it attempts
- Initial execution and final payload
- Affected hosts and users
- Communication, exfiltration, and persistence
- Immediate containment actions

### 21.2 Sample metadata

- Name, path, size, and SHA-256
- Collection source, time, and timezone
- Encoding, language, and execution host
- Signature, Zone.Identifier, and container

### 21.3 Technical findings

1. Delivery
2. Process tree
3. Obfuscation layers
4. Retrieval and restoration
5. Memory loading and execution
6. Environment and target gates
7. Discovery and exfiltration
8. Persistence, privilege, and defense evasion
9. Failure and fallback paths

### 21.4 Detection and response

- IoCs and behavioral indicators
- ATT&CK mapping
- Log searches, queries, and rules
- Blocks, isolation, and credential rotation
- Enterprise-wide hunting scope
- Hardening and telemetry improvements

### 21.5 Confidence and gaps

- Directly verified facts
- Present but unexecuted code
- Damaged, OCR-derived, or missing content
- Additional originals, logs, memory, or network data needed

## 22. Operational checklists

### 22.1 Ten-minute triage

- [ ] Hash the original
- [ ] Identify format, encoding, and interpreter
- [ ] Capture parent and child processes
- [ ] Extract and defang URLs, domains, IPs, and filenames
- [ ] Check Base64, XOR, character arrays, and ROT
- [ ] Check IEX, Execute, Eval, Run, Exec, and ObjCreate
- [ ] Check WebClient, XMLHTTP, and WinHTTP
- [ ] Check Assembly.Load, Add-Type, and DllImport
- [ ] Check AMSI references, memory protection, and byte-copy APIs
- [ ] Check persistence, discovery, collection, and exfiltration

### 22.2 Deep analysis

- [ ] Hash each decode/decompression layer
- [ ] Build data and control-flow graphs
- [ ] Analyze both sides of every gate
- [ ] Collect remote content without execution
- [ ] Extract .NET types, methods, resources, and EntryPoint
- [ ] Inspect memory pages and thread start addresses
- [ ] Correlate PowerShell, WSH, EDR, DNS, and proxy logs
- [ ] Separate IoCs from behavioral indicators
- [ ] Map ATT&CK techniques
- [ ] Record false-positive conditions, confidence, and gaps

### 22.3 Response

- [ ] Isolate host and account
- [ ] Decide whether memory must be captured before termination
- [ ] Revoke and rotate exposed tokens, passwords, and cookies
- [ ] Hunt the same hash, URL, command line, and process ancestry
- [ ] Remove the initial lure and delivery path
- [ ] Remove persistence
- [ ] Apply scoped proxy, DNS, or EDR blocks
- [ ] Verify logging policy and sensor health
- [ ] Monitor after recovery

## 23. Important corrections and context

1. **Text scripts bypass antivirus.** Text is also subject to static scanning, AMSI, reputation, and behavior detection. It has a different attack surface from a PE, not immunity.

2. **Fileless means no evidence.** It may mean no conventional payload file, but process, log, network, memory, cache, and lure artifacts remain.

3. **EncodedCommand is encryption.** Base64 is an easily reversed transport representation.

4. **Execution Policy is a security boundary.** It is not. Bypass is context, not exploitation.

5. **Every Windows host has the same PowerShell.** Distinguish Windows PowerShell 5.1 from separately installed PowerShell 7.

6. **An empty Assembly.Location proves malware.** It indicates a byte-array load but can be legitimate. Provenance and behavior matter.

7. **RWX memory proves malware.** It is suspicious in context, but JIT engines and security tools can use executable memory.

8. **One AMSI patch signature catches bypasses.** Builds, architectures, and implementations vary. Detect the behavior chain.

9. **ISE and Microsoft Script Debugger are current standard tools.** They are legacy teaching tools. Use static parsers, modern instrumentation, and telemetry.

10. **Copy PATs into the report as IoCs.** Tokens are credentials. Redact, revoke, rotate, and reference them by fingerprint where possible.

11. **Block all GitLab traffic.** Correlate project path, API action, process, account, and follow-on execution to avoid broad disruption.

12. **Forcing a gate reproduces the real target behavior exactly.** It is an analysis aid. Server response, timing, and environment can still change execution.

## 24. PoC index

| PoC | Topic | Side effects |
|---|---|---|
| 1 | PowerShell UTF-16LE/Base64 round trip | Console only |
| 2 | Multi-encoding Base64 triage | Console only |
| 3 | PowerShell AST and fixed IEX | Fixed console output |
| 4 | Loopback DownloadString/DownloadFile | Localhost request and one temp file |
| 5 | XOR | Console only |
| 6 | Character arrays | Console only |
| 7 | ROT | Console only |
| 8 | GZip header repair | In-memory benign bytes |
| 9 | Benign Assembly.Load | One transparent temporary DLL |
| 10 | Safe P/Invoke | Reads current PID |
| 11 | AMSI integrity inspection | Reads 16 bytes only |
| 12 | Environment inventory | Console only |
| 13 | Target-gate emulator | Supplied test values only |
| 14 | VBScript COM | One temp text file |
| 15 | JScript COM | One temp text file |
| 16 | Inert HTA | Local DOM text only |
| 17 | AutoIt strings/macros | Console only |
| 18 | CMD variable normalization | Console only |
| 19 | Inert VBA | Immediate window only |
| 20 | PNG trailing-data check | Read-only file inspection |
| 21 | YARA triage | Static matching only |

## 25. Glossary

| Term | Meaning |
|---|---|
| AMSI | Windows antimalware content-scanning interface |
| CLR | Runtime that executes .NET intermediate code |
| IL | .NET intermediate language |
| COM/ProgID | Windows component interface and its string identifier |
| LOLBin | Legitimate signed binary used in an attack chain |
| Fileless | Execution without a conventional on-disk payload |
| Reflection | Runtime inspection and invocation of .NET types and methods |
| P/Invoke | Calling native DLL functions from .NET |
| RWX | Read, write, and execute memory permissions |
| IoC | Compromise indicator such as hash, URL, IP, or filename |
| IoA | Behavioral attack indicator such as an execution or API sequence |
| Anti-analysis | Techniques that delay, detect, or avoid analysis |

## 26. Final analyst summary

The core skill is not keyword recognition. It is reconstruction of **execution, data, and control flow**.

- Identify the delivery item and signed host that started the chain.
- Reverse obfuscation one layer at a time and hash every result.
- Follow remote or embedded bytes into dynamic execution, Reflection, or native APIs.
- Analyze both sides of user, network, environment, and time gates.
- Prove fileless behavior with process, log, network, and memory evidence.
- Manage indicators with source, role, confidence, and false-positive context.
- Never expose credentials in a report.
- Turn technical findings into reproducible detections and scoped response actions.
