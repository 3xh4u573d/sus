package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	oAccMode    = 3
	oCreat      = 0o100
	einprogress = 115

	maxHashSize   = 64 << 20
	maxHashBudget = 1 << 30
)

type fileInfo struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Link   string `json:"link,omitempty"`
	Exec   bool   `json:"executable,omitempty"`
	Setuid bool   `json:"setuid,omitempty"`
	Gone   bool   `json:"gone,omitempty"`
}

type stat struct {
	Count   int       `json:"count"`
	Failed  int       `json:"failed,omitempty"`
	Err     string    `json:"error,omitempty"`
	FirstNs int64     `json:"t_ns"`
	Tag     string    `json:"tag,omitempty"`
	Noise   string    `json:"noise,omitempty"`
	File    *fileInfo `json:"file,omitempty"`
}

type execRec struct {
	Path      string   `json:"path"`
	Args      []string `json:"args"`
	More      bool     `json:"args_truncated,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
	Anomalies []string `json:"anomalies,omitempty"`
}

type proc struct {
	Pid      uint32           `json:"pid"`
	Ppid     uint32           `json:"ppid"`
	Comm     string           `json:"comm"`
	Execs    []execRec        `json:"executed,omitempty"`
	Writes   map[string]*stat `json:"written,omitempty"`
	Deletes  map[string]*stat `json:"deleted,omitempty"`
	Reads    map[string]*stat `json:"read,omitempty"`
	Conns    map[string]*stat `json:"connections,omitempty"`
	Ops      map[string]*stat `json:"operations,omitempty"`
	Children []*proc          `json:"children,omitempty"`
}

type tevent struct {
	T      int64  `json:"t_ns"`
	Pid    uint32 `json:"pid"`
	Proc   string `json:"proc"`
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	Failed bool   `json:"failed,omitempty"`
	Tag    string `json:"tag,omitempty"`
	Noise  string `json:"noise,omitempty"`
}

type finding struct {
	Sev  string `json:"severity"`
	Cat  string `json:"category"`
	Tag  string `json:"tag"`
	Text string `json:"text"`
}

type iocFile struct {
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
}

type iocs struct {
	Domains []string  `json:"domains,omitempty"`
	IPs     []string  `json:"ips,omitempty"`
	Unix    []string  `json:"unix_sockets,omitempty"`
	Files   []iocFile `json:"files,omitempty"`
}

type report struct {
	Command    []string          `json:"command"`
	ExitCode   int               `json:"exit_code"`
	Status     string            `json:"status"`
	DurationMs int64             `json:"duration_ms"`
	Verdict    string            `json:"verdict"`
	Roots      []*proc           `json:"processes"`
	Timeline   []tevent          `json:"timeline"`
	Findings   []finding         `json:"findings"`
	IOCs       iocs              `json:"iocs"`
	Notes      []string          `json:"notes,omitempty"`
	Names      map[string]string `json:"resolved,omitempty"`
	DNS        map[string]string `json:"dns,omitempty"`
	EnvSecrets []string          `json:"env_secret_names,omitempty"`
	Lost       uint64            `json:"lost_events,omitempty"`

	procs       map[uint32]*proc
	fileCache   map[string]*fileInfo
	budget      int64
	maps        []pathMap
	passthrough []string
	infra       bool
	infraDone   bool
	last        *tevent
	minTs       int64
	haveTs      bool
	showAll     bool
	color       bool
	timeline    bool
}

func newReport() *report {
	return &report{
		procs:     map[uint32]*proc{},
		DNS:       map[string]string{},
		fileCache: map[string]*fileInfo{},
		budget:    maxHashBudget,
	}
}

func (r *report) nameFor(host string) string {
	if n := r.DNS[host]; n != "" {
		return n
	}
	if n := r.Names[host]; n != "" {
		return "~" + n
	}
	return ""
}

func ipString(ev *event) string {
	if ev.Family == 10 {
		return net.IP(ev.Addr[:16]).String()
	}
	return net.IP(ev.Addr[:4]).String()
}

var ptraceRequests = map[uint32]string{
	0: "TRACEME", 1: "PEEKTEXT", 2: "PEEKDATA", 3: "PEEKUSER", 4: "POKETEXT",
	5: "POKEDATA", 6: "POKEUSER", 7: "CONT", 8: "KILL", 9: "SINGLESTEP",
	12: "GETREGS", 13: "SETREGS", 16: "ATTACH", 17: "DETACH", 0x4206: "SEIZE",
}

func ptraceName(req uint32) string {
	if n, ok := ptraceRequests[req]; ok {
		return "PTRACE_" + n
	}
	return fmt.Sprintf("request 0x%x", req)
}

func uidString(u uint32) string {
	if u == 0xffffffff {
		return "-1"
	}
	return fmt.Sprint(u)
}

func eaiText(res int32) string {
	switch res {
	case -1:
		return "bad flags"
	case -2:
		return "name or service not known"
	case -3:
		return "temporary failure in name resolution"
	case -4:
		return "non-recoverable failure"
	case -5:
		return "no address for this name"
	case -6:
		return "address family not supported"
	case -8:
		return "service not known"
	case -10:
		return "out of memory"
	case -11:
		return "system error"
	}
	return fmt.Sprintf("resolver error %d", res)
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func splitArgs(b []byte, n uint32) []string {
	if int(n) > len(b) {
		n = uint32(len(b))
	}
	parts := bytes.Split(b[:n], []byte{0})
	var out []string
	for i, p := range parts {
		if i == len(parts)-1 && len(p) == 0 {
			continue
		}
		out = append(out, string(p))
	}
	return out
}

func absPath(pid uint32, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		return filepath.Join(cwd, p)
	}
	return "?/" + p
}

func bump(m *map[string]*stat, key string, res int32, okErrno int32, ts int64) {
	if *m == nil {
		*m = map[string]*stat{}
	}
	s := (*m)[key]
	if s == nil {
		s = &stat{FirstNs: ts}
		(*m)[key] = s
	}
	if ts < s.FirstNs {
		s.FirstNs = ts
	}
	s.Count++
	if res < 0 && res != -okErrno {
		s.Failed++
		s.Err = strings.ToLower(syscall.Errno(-res).Error())
	}
}

func (r *report) abs(pid uint32, p string) string {
	return r.toSandbox(absPath(pid, p))
}

func (r *report) isPassthrough(p string) bool {
	for _, pp := range r.passthrough {
		if p == pp || strings.HasPrefix(p, pp+"/") {
			return true
		}
	}
	return false
}

func (r *report) toSandbox(p string) string {
	if r.isPassthrough(p) {
		return p
	}
	for _, m := range r.maps {
		if p == m.host || strings.HasPrefix(p, m.host+"/") {
			return m.sandbox + strings.TrimPrefix(p, m.host)
		}
	}
	return p
}

func (r *report) toHost(p string) string {
	if r.isPassthrough(p) {
		return p
	}
	for _, m := range r.maps {
		if p == m.sandbox || strings.HasPrefix(p, m.sandbox+"/") {
			return m.host + strings.TrimPrefix(p, m.sandbox)
		}
	}
	return p
}

func isInfraExe(path string) bool {
	b := filepath.Base(path)
	return b == "bwrap" || b == "setpriv"
}

func (r *report) procOf(ev *event) *proc {
	p := r.procs[ev.Pid]
	if p == nil {
		p = &proc{Pid: ev.Pid, Ppid: ev.Ppid, Comm: cstr(ev.Comm[:])}
		r.procs[ev.Pid] = p
	}
	return p
}

func (r *report) note(ts int64, p *proc, kind, text string, failed bool, tag, noise string) {
	r.Timeline = append(r.Timeline, tevent{
		T: ts, Pid: p.Pid, Proc: shortName(p), Kind: kind, Text: text,
		Failed: failed, Tag: tag, Noise: noise,
	})
	r.last = &r.Timeline[len(r.Timeline)-1]
}

func (r *report) op(p *proc, ts int64, ev *event, verb, rest, tag string) {
	key := verb + " " + rest
	bump(&p.Ops, key, ev.Result, 0, ts)
	s := p.Ops[key]
	s.Tag = tag
	if verb == "resolve" && ev.Result < 0 {
		s.Err = eaiText(ev.Result)
	}
	r.note(ts, p, verb, rest, ev.Result < 0, tag, "")
}

func (r *report) add(ev *event) {
	r.last = nil

	if (ev.Type == evSetuid || ev.Type == evSetresuid) && ev.Ppid == uint32(os.Getpid()) {
		if q := r.procs[ev.Pid]; q == nil || len(q.Execs) == 0 {
			return
		}
	}

	if r.infra && !r.infraDone {
		if ev.Type != evExec || isInfraExe(cstr(ev.Path[:])) {
			return
		}
		r.infraDone = true
	}

	p := r.procOf(ev)
	ts := int64(ev.Ts)
	if !r.haveTs || ts < r.minTs {
		r.minTs, r.haveTs = ts, true
	}

	switch ev.Type {
	case evExec:
		rec := execRec{
			Path: r.abs(ev.Pid, cstr(ev.Path[:])),
			Args: splitArgs(ev.Args[:], ev.ArgLen),
			More: ev.Flags&1 != 0,
		}
		p.Comm = cstr(ev.Comm[:])
		p.Execs = append(p.Execs, rec)
		r.note(ts, p, "exec", execLine(rec), false, "", "")
	case evOpen:
		path := r.abs(ev.Pid, cstr(ev.Path[:]))
		failed := ev.Result < 0
		if ev.Flags&oAccMode != 0 || ev.Flags&oCreat != 0 {
			bump(&p.Writes, path, ev.Result, 0, ts)
			r.note(ts, p, "write", path, failed, tagFor(path, true), writeNoiseLabel(path))
		} else {
			bump(&p.Reads, path, ev.Result, 0, ts)
			r.note(ts, p, "read", path, failed, tagFor(path, false), noiseLabel(path))
		}
	case evStat:
		path := r.abs(ev.Pid, cstr(ev.Path[:]))
		if path == "" || path == "." {
			return
		}
		bump(&p.Reads, path, ev.Result, 0, ts)
		r.note(ts, p, "stat", path, ev.Result < 0, tagFor(path, false), noiseLabel(path))
	case evUnlink:
		path := r.abs(ev.Pid, cstr(ev.Path[:]))
		bump(&p.Deletes, path, ev.Result, 0, ts)
		r.note(ts, p, "delete", path, ev.Result < 0, tagFor(path, true), "")
	case evConnect:
		dst := connString(ev)
		bump(&p.Conns, dst, ev.Result, einprogress, ts)
		r.note(ts, p, "net", dst, ev.Result < 0 && ev.Result != -einprogress, connTag(dst), "")
	case evRename:
		oldp := r.abs(ev.Pid, cstr(ev.Path[:]))
		newp := r.abs(ev.Pid, cstr(ev.Args[:]))
		tag := tagFor(newp, true)
		if tag == "" {
			tag = tagFor(oldp, true)
		}
		r.op(p, ts, ev, "rename", oldp+" -> "+newp, tag)
	case evMkdir:
		path := r.abs(ev.Pid, cstr(ev.Path[:]))
		r.op(p, ts, ev, "mkdir", fmt.Sprintf("%s (%04o)", path, ev.Flags&0o7777), tagFor(path, true))
	case evChmod:
		path := r.abs(ev.Pid, cstr(ev.Path[:]))
		mode := ev.Flags & 0o7777
		tag := tagFor(path, true)
		if mode&0o6000 != 0 {
			tag = "SETUID/SETGID"
		}
		r.op(p, ts, ev, "chmod", fmt.Sprintf("%04o %s", mode, path), tag)
	case evSymlink:
		linkPath := r.abs(ev.Pid, cstr(ev.Path[:]))
		target := cstr(ev.Args[:])
		tag := tagFor(linkPath, true)
		if tag == "" {
			tag = tagFor(target, false)
		}
		r.op(p, ts, ev, "symlink", linkPath+" -> "+target, tag)
	case evBind:
		r.op(p, ts, ev, "bind", connString(ev), "")
	case evSendto:
		r.op(p, ts, ev, "send", connString(ev), "")
	case evPtrace:
		r.op(p, ts, ev, "ptrace", fmt.Sprintf("%s pid %d", ptraceName(ev.Flags), ev.Aux), "PTRACE")
	case evSetuid:
		tag := ""
		if ev.Flags == 0 {
			tag = "PRIVILEGE"
		}
		r.op(p, ts, ev, "setuid", fmt.Sprintf("(%s)", uidString(ev.Flags)), tag)
	case evSetresuid:
		tag := ""
		if ev.Flags == 0 || ev.Aux == 0 {
			tag = "PRIVILEGE"
		}
		r.op(p, ts, ev, "setuid", fmt.Sprintf("resuid(%s, %s)", uidString(ev.Flags), uidString(ev.Aux)), tag)
	case evMount:
		fs := cstr(ev.Args[:])
		if fs == "" {
			fs = "bind/remount"
		}
		r.op(p, ts, ev, "mount", fmt.Sprintf("%s on %s (flags 0x%x)", fs, cstr(ev.Path[:]), ev.Flags), "MOUNT")
	case evMemfd:
		r.op(p, ts, ev, "memfd", fmt.Sprintf("%q", cstr(ev.Path[:])), "FILELESS")
	case evModule:
		what := "init_module"
		if ev.Aux == 1 {
			what = fmt.Sprintf("finit_module(fd %d)", ev.Flags)
		}
		r.op(p, ts, ev, "module", what, "KERNEL-MODULE")
	case evDNSQ:
		r.op(p, ts, ev, "resolve", cstr(ev.Path[:]), "")
	case evDNS:
		name, ip := cstr(ev.Path[:]), ipString(ev)
		if _, seen := r.DNS[ip]; !seen {
			r.DNS[ip] = name
			r.note(ts, p, "dns", name+" -> "+ip, false, "", "")
		}
	}
}

func connString(ev *event) string {
	switch ev.Family {
	case 2:
		return fmt.Sprintf("%s:%d", net.IP(ev.Addr[:4]), ev.Port)
	case 10:
		return fmt.Sprintf("[%s]:%d", net.IP(ev.Addr[:16]), ev.Port)
	default:
		return "unix:" + cstr(ev.Path[:])
	}
}

var noisePrefixes = []string{
	"/proc/", "/sys/", "/dev/", "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
	"/usr/share/locale", "/usr/share/zoneinfo", "/etc/ld.so", "/etc/localtime",
	"/etc/nsswitch.conf", "/etc/locale", "/etc/gai.conf", "/etc/host",
	"/etc/resolv.conf", "/etc/ssl/", "/etc/ca-certificates", "/usr/share/ca-certificates",
	"/etc/passwd", "/etc/group", "/run/systemd/resolve", "/usr/share/", "/etc/alternatives/",
}

var writeNoisePrefixes = []string{"/dev/", "/proc/", "/sys/"}

var sensitiveParts = []string{
	"/.ssh/", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/.aws/", "/.kube/", "/.gnupg/",
	"/.docker/config.json", "/.netrc", "/.bash_history", "/.zsh_history", "/.mozilla/",
	"/.config/google-chrome", "/.config/chromium", "/.config/BraveSoftware", "/.config/microsoft-edge",
	"/.thunderbird/", "/.local/share/keyrings/", "/.password-store/", "/.config/Signal",
	"/.config/discord", "/.config/Slack", "/.bitcoin/", "/.electrum", "/.ethereum/", "/.monero",
	"/.git-credentials", "/.npmrc", "/.pypirc", "/.config/gh/", "/.azure/", "/.config/gcloud/",
	"id_rsa", "id_ed25519", "id_ecdsa", "Login Data", "logins.json", "key4.db", "wallet.dat",
}

var persistenceParts = []string{
	"/.bashrc", "/.bash_profile", "/.bash_logout", "/.profile", "/.zshrc", "/.zprofile",
	"/.config/fish/config.fish", "/etc/profile", "/etc/environment", "/etc/rc.local", "/etc/init.d/",
	"/etc/cron", "/var/spool/cron", "/etc/anacrontab", "/var/spool/at",
	"/etc/systemd/", "/.config/systemd/", "/usr/lib/systemd/", "/.config/autostart/", "/etc/xdg/autostart/",
	"/etc/ld.so.preload", "/.ssh/authorized_keys", "/etc/pam.d/", "/etc/ssh/sshd_config",
	"/etc/passwd", "/etc/sudoers", "/etc/udev/rules.d/", "/etc/modules", "/etc/modprobe.d/",
}

var logTamperParts = []string{
	"/var/log/", "/.bash_history", "/.zsh_history", "/var/run/utmp", "/run/utmp",
}

var vmCheckParts = []string{
	"/sys/class/dmi/id/", "/sys/devices/virtual/dmi/", "/sys/hypervisor", "/proc/scsi/scsi",
}

var reconParts = []string{
	"/proc/net/", "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
}

func hasAny(p string, parts []string) bool {
	for _, s := range parts {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

func labelFor(p string, prefixes []string) string {
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			if strings.HasSuffix(pre, "/") {
				return pre + "**"
			}
			return pre + "*"
		}
	}
	return ""
}

func noiseLabel(p string) string {
	if p == "/" {
		return "/"
	}
	return labelFor(p, noisePrefixes)
}
func writeNoiseLabel(p string) string { return labelFor(p, writeNoisePrefixes) }

func tagFor(p string, write bool) string {
	if write {
		if hasAny(p, persistenceParts) {
			return "PERSISTENCE"
		}
		if hasAny(p, logTamperParts) {
			return "LOG-TAMPER"
		}
	}
	if hasAny(p, sensitiveParts) {
		return "SENSITIVE"
	}
	if strings.HasPrefix(p, "/proc/") {
		if strings.HasSuffix(p, "/environ") || strings.HasSuffix(p, "/mem") {
			return "SENSITIVE"
		}
		if p == "/proc/self/status" && !write {
			return "DEBUG-CHECK"
		}
	}
	if !write {
		if hasAny(p, vmCheckParts) {
			return "VM-CHECK"
		}
		if hasAny(p, reconParts) {
			return "RECON"
		}
	}
	return ""
}

func connTag(key string) string {
	if !strings.HasPrefix(key, "unix:") {
		return ""
	}
	p := strings.TrimPrefix(key, "unix:")
	switch {
	case hasAny(p, []string{"docker.sock", "containerd.sock", "podman.sock", "crio.sock"}):
		return "DOCKER-SOCK"
	case strings.Contains(p, "/ssh-") && strings.Contains(p, "agent"),
		strings.HasSuffix(p, "/keyring/ssh"), strings.Contains(p, "S.gpg-agent"):
		return "SSH-AGENT"
	}
	return ""
}

type tagMeta struct{ cat, sev string }

var tagInfo = map[string]tagMeta{
	"PERSISTENCE":   {"persistence", "high"},
	"KERNEL-MODULE": {"persistence", "high"},
	"LOG-TAMPER":    {"defense evasion", "high"},
	"PTRACE":        {"defense evasion", "high"},
	"FILELESS":      {"defense evasion", "high"},
	"VM-CHECK":      {"defense evasion", "medium"},
	"DEBUG-CHECK":   {"defense evasion", "medium"},
	"PRIVILEGE":     {"privilege escalation", "high"},
	"SETUID/SETGID": {"privilege escalation", "high"},
	"DOCKER-SOCK":   {"privilege escalation", "high"},
	"SENSITIVE":     {"credential access", "medium"},
	"SSH-AGENT":     {"credential access", "medium"},
	"ENV":           {"credential access", "low"},
	"RECON":         {"discovery", "low"},
	"EXECUTION":     {"execution", "medium"},
	"EXECUTABLE":    {"execution", "medium"},
	"MOUNT":         {"system change", "medium"},
}

var sevRank = map[string]int{"high": 0, "medium": 1, "low": 2}

func (r *report) addFinding(tag, text string) {
	m, ok := tagInfo[tag]
	if !ok {
		m = tagMeta{"other", "low"}
	}
	r.Findings = append(r.Findings, finding{Sev: m.sev, Cat: m.cat, Tag: tag, Text: text})
}

func sortedKeys(m map[string]*stat) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func failNote(s *stat) string {
	switch {
	case s.Failed == 0:
		return ""
	case s.Failed == s.Count:
		return "failed: " + s.Err
	default:
		return fmt.Sprintf("%d failed: %s", s.Failed, s.Err)
	}
}

func execLine(e execRec) string {
	parts := []string{e.Path}
	if len(e.Args) > 1 {
		parts = append(parts, e.Args[1:]...)
	}
	if e.More {
		parts = append(parts, "...")
	}
	return strings.Join(parts, " ")
}

func shortName(p *proc) string {
	if n := len(p.Execs); n > 0 {
		return filepath.Base(p.Execs[n-1].Path)
	}
	return p.Comm
}

func shorten(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func fmtOffset(ns int64) string {
	if ns < int64(time.Second) {
		return fmt.Sprintf("+%.1fms", float64(ns)/1e6)
	}
	return fmt.Sprintf("+%.3fs", float64(ns)/1e9)
}

var systemPrefixes = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/snap/"}
var tempPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}

func hasPrefixAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func isSystemPath(p string) bool { return hasPrefixAny(p, systemPrefixes) }

func hasHiddenComponent(p string) bool {
	for _, c := range strings.Split(p, "/") {
		if len(c) > 1 && c[0] == '.' && c != ".." {
			return true
		}
	}
	return false
}

func statFile(path string, budget *int64, hash bool) *fileInfo {
	st, err := os.Lstat(path)
	if err != nil {
		return &fileInfo{Gone: true}
	}
	fi := &fileInfo{Size: st.Size(), Mode: st.Mode().String()}
	if st.Mode()&os.ModeSymlink != 0 {
		fi.Kind = "symlink"
		fi.Link, _ = os.Readlink(path)
		return fi
	}
	if !st.Mode().IsRegular() {
		return nil
	}
	fi.Exec = st.Mode()&0o111 != 0
	fi.Setuid = st.Mode()&os.ModeSetuid != 0
	if !hash || st.Size() > maxHashSize || st.Size() > *budget {
		return fi
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fi
	}
	defer f.Close()

	var magic [4]byte
	n, _ := io.ReadFull(f, magic[:])
	switch {
	case n == 4 && string(magic[:]) == "\x7fELF":
		fi.Kind = "elf"
	case n >= 2 && magic[0] == '#' && magic[1] == '!':
		fi.Kind = "script"
	}

	h := sha256.New()
	h.Write(magic[:n])
	m, _ := io.Copy(h, f)
	*budget -= m + int64(n)
	fi.SHA256 = hex.EncodeToString(h.Sum(nil))
	return fi
}

func (r *report) fileOf(path string, hash bool) *fileInfo {
	if fi, ok := r.fileCache[path]; ok && (fi == nil || fi.SHA256 != "" || !hash) {
		return fi
	}
	fi := statFile(r.toHost(path), &r.budget, hash)
	r.fileCache[path] = fi
	return fi
}

func (r *report) sortedPids() []uint32 {
	pids := make([]uint32, 0, len(r.procs))
	for pid := range r.procs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}

func (r *report) fingerprint(hash bool) {
	for _, pid := range r.sortedPids() {
		p := r.procs[pid]
		for _, path := range sortedKeys(p.Writes) {
			s := p.Writes[path]
			if s.Failed == s.Count || s.Noise != "" || !filepath.IsAbs(path) {
				continue
			}
			s.File = r.fileOf(path, hash)
		}
	}
}

func (r *report) analyzeExecs(hash bool) {
	dropped := map[string]bool{}
	for _, p := range r.procs {
		for path, s := range p.Writes {
			if s.Failed < s.Count {
				dropped[path] = true
			}
		}
	}
	isRoot := map[*proc]bool{}
	for _, p := range r.Roots {
		isRoot[p] = true
	}

	for _, pid := range r.sortedPids() {
		p := r.procs[pid]
		for i := range p.Execs {
			e := &p.Execs[i]
			if !filepath.IsAbs(e.Path) {
				continue
			}
			if strings.HasPrefix(e.Path, "/dev/fd/") || (strings.HasPrefix(e.Path, "/proc/") && strings.Contains(e.Path, "/fd/")) {
				e.Anomalies = append(e.Anomalies, "run from a file descriptor (fileless)")
				continue
			}

			sample := isRoot[p] && i == 0
			sys := isSystemPath(e.Path)
			fi := r.fileOf(e.Path, hash && !sys)
			if fi != nil {
				e.SHA256 = fi.SHA256
				if fi.Gone {
					e.Anomalies = append(e.Anomalies, "binary no longer exists (deleted itself?)")
				}
			}
			if sample || sys {
				continue
			}

			if hasPrefixAny(e.Path, tempPrefixes) {
				e.Anomalies = append(e.Anomalies, "runs from a temp directory")
			} else if st, err := os.Stat(filepath.Dir(r.toHost(e.Path))); err == nil &&
				st.Mode().Perm()&0o002 != 0 && st.Mode()&os.ModeSticky == 0 {
				e.Anomalies = append(e.Anomalies, "runs from a world-writable directory")
			}
			if hasHiddenComponent(e.Path) {
				e.Anomalies = append(e.Anomalies, "hidden path")
			}
			if dropped[e.Path] {
				e.Anomalies = append(e.Anomalies, "created by the command itself")
			}
		}
	}
}

func (r *report) collectIOCs() {
	domains := map[string]bool{}
	ips := map[string]bool{}
	unix := map[string]bool{}
	files := map[string]string{}

	for _, name := range r.DNS {
		domains[name] = true
	}

	addHost := func(key string) {
		h, _, err := net.SplitHostPort(key)
		if err != nil {
			return
		}
		if ip := net.ParseIP(h); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			ips[ip.String()] = true
		}
	}

	for _, pid := range r.sortedPids() {
		p := r.procs[pid]
		for k := range p.Conns {
			if strings.HasPrefix(k, "unix:") {
				if connTag(k) != "" {
					unix[strings.TrimPrefix(k, "unix:")] = true
				}
				continue
			}
			addHost(k)
		}
		for k := range p.Ops {
			verb, rest, _ := strings.Cut(k, " ")
			switch verb {
			case "resolve":
				domains[rest] = true
			case "send":
				addHost(rest)
			}
		}
		for i, e := range p.Execs {
			if e.SHA256 != "" && !isSystemPath(e.Path) {
				files[e.Path] = e.SHA256
			}
			_ = i
		}
		for path, s := range p.Writes {
			f := s.File
			if f == nil || f.Gone || f.SHA256 == "" || f.Kind == "symlink" {
				continue
			}
			if f.Kind == "elf" || f.Exec || f.Setuid || s.Tag != "" {
				files[path] = f.SHA256
			}
		}
	}

	r.IOCs = iocs{}
	for d := range domains {
		r.IOCs.Domains = append(r.IOCs.Domains, d)
	}
	for ip := range ips {
		r.IOCs.IPs = append(r.IOCs.IPs, ip)
	}
	for u := range unix {
		r.IOCs.Unix = append(r.IOCs.Unix, u)
	}
	for path, sum := range files {
		r.IOCs.Files = append(r.IOCs.Files, iocFile{SHA256: sum, Path: path})
	}
	sort.Strings(r.IOCs.Domains)
	sort.Strings(r.IOCs.IPs)
	sort.Strings(r.IOCs.Unix)
	sort.Slice(r.IOCs.Files, func(i, j int) bool { return r.IOCs.Files[i].Path < r.IOCs.Files[j].Path })
}

func (i iocs) empty() bool {
	return len(i.Domains)+len(i.IPs)+len(i.Unix)+len(i.Files) == 0
}

func (r *report) finish(cmd []string, exit int, d time.Duration, lost uint64, hash bool) {
	r.Command, r.ExitCode, r.DurationMs = cmd, exit, d.Milliseconds()
	r.Lost = lost

	pids := r.sortedPids()

	for _, pid := range pids {
		p := r.procs[pid]
		if parent := r.procs[p.Ppid]; parent != nil && parent != p {
			parent.Children = append(parent.Children, p)
		} else {
			r.Roots = append(r.Roots, p)
		}

		for _, kind := range []struct {
			m     map[string]*stat
			write bool
			noise func(string) string
		}{
			{p.Writes, true, writeNoiseLabel},
			{p.Deletes, true, nil},
			{p.Reads, false, noiseLabel},
		} {
			for k, s := range kind.m {
				s.Tag = tagFor(k, kind.write)
				if kind.noise != nil {
					s.Noise = kind.noise(k)
				}
				s.FirstNs -= r.minTs
			}
		}
		for k, s := range p.Conns {
			s.Tag = connTag(k)
			s.FirstNs -= r.minTs
		}
		for _, s := range p.Ops {
			s.FirstNs -= r.minTs
		}
	}

	for i := range r.Timeline {
		r.Timeline[i].T -= r.minTs
	}
	sort.SliceStable(r.Timeline, func(i, j int) bool { return r.Timeline[i].T < r.Timeline[j].T })
	r.last = nil

	r.fingerprint(hash)
	r.analyzeExecs(hash)

	r.Findings = nil
	if n := len(r.EnvSecrets); n > 0 {
		r.addFinding("ENV", fmt.Sprintf("command inherited %d secret-like variable(s): %s (names only)",
			n, strings.Join(r.EnvSecrets, ", ")))
	}
	for _, pid := range pids {
		p := r.procs[pid]
		by := fmt.Sprintf("  by %s[%d]", shortName(p), p.Pid)

		for _, e := range p.Execs {
			if len(e.Anomalies) == 0 {
				continue
			}
			tag := "EXECUTION"
			if strings.Contains(strings.Join(e.Anomalies, " "), "fileless") {
				tag = "FILELESS"
			}
			txt := fmt.Sprintf("%s (%s)", e.Path, strings.Join(e.Anomalies, ", "))
			if e.SHA256 != "" {
				txt += "  sha256:" + e.SHA256[:12]
			}
			r.addFinding(tag, txt+by)
		}

		for _, kind := range []struct {
			name string
			m    map[string]*stat
		}{
			{"read", p.Reads}, {"write", p.Writes}, {"delete", p.Deletes},
			{"connect", p.Conns}, {"", p.Ops},
		} {
			for _, k := range sortedKeys(kind.m) {
				s := kind.m[k]
				if s.Tag == "" {
					continue
				}
				f := k
				if kind.name != "" {
					f = kind.name + " " + k
				}
				if n := failNote(s); n != "" {
					f += " (" + n + ")"
				}
				r.addFinding(s.Tag, f+by)
			}
		}

		for _, k := range sortedKeys(p.Writes) {
			f := p.Writes[k].File
			if f == nil || f.Gone {
				continue
			}
			what := ""
			switch {
			case f.Setuid:
				what = "setuid file"
			case f.Kind == "elf":
				what = "ELF binary"
			case f.Kind == "script" && f.Exec:
				what = "executable script"
			}
			if what != "" {
				r.addFinding("EXECUTABLE", fmt.Sprintf("wrote %s %s%s", what, k, by))
			}
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if sevRank[a.Sev] != sevRank[b.Sev] {
			return sevRank[a.Sev] < sevRank[b.Sev]
		}
		return a.Cat < b.Cat
	})

	r.collectIOCs()

	r.Verdict = "none"
	for _, f := range r.Findings {
		switch {
		case f.Sev == "high":
			r.Verdict = "high"
		case f.Sev == "medium" && r.Verdict != "high":
			r.Verdict = "medium"
		case f.Sev == "low" && r.Verdict == "none":
			r.Verdict = "low"
		}
	}
}

func (r *report) resolveNames() {
	hosts := map[string]bool{}
	for _, p := range r.procs {
		for k := range p.Conns {
			if strings.HasPrefix(k, "unix:") {
				continue
			}
			if h, _, err := net.SplitHostPort(k); err == nil && r.DNS[h] == "" {
				hosts[h] = true
			}
		}
	}

	r.Names = map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(ctx, h)
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			r.Names[h] = strings.TrimSuffix(names[0], ".")
			mu.Unlock()
		}(h)
	}
	wg.Wait()
}

func (r *report) writeJSON(w io.Writer) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(r)
}

type painter struct{ on bool }

func (c painter) wrap(code, s string) string {
	if !c.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (c painter) bold(s string) string   { return c.wrap("1", s) }
func (c painter) dim(s string) string    { return c.wrap("2", s) }
func (c painter) red(s string) string    { return c.wrap("1;31", s) }
func (c painter) green(s string) string  { return c.wrap("32", s) }
func (c painter) yellow(s string) string { return c.wrap("33", s) }
func (c painter) cyan(s string) string   { return c.wrap("36", s) }

func (c painter) sev(sev, s string) string {
	switch sev {
	case "high":
		return c.red(s)
	case "medium":
		return c.yellow(s)
	}
	return c.dim(s)
}

func (r *report) label(c painter, p *proc) string {
	var lines []string
	for _, e := range p.Execs {
		line := execLine(e)
		if len(e.Anomalies) > 0 {
			line += " " + c.red("["+strings.Join(e.Anomalies, "; ")+"]")
		}
		if e.SHA256 != "" && !isSystemPath(e.Path) {
			line += " " + c.dim("sha256:"+e.SHA256[:12])
		}
		lines = append(lines, line)
	}
	cmd := strings.Join(lines, " → ")
	if cmd == "" {
		cmd = p.Comm + " (forked)"
	}
	return c.bold(shorten(cmd, 110)) + "  " + c.dim(fmt.Sprintf("[%d]", p.Pid))
}

func fileSummary(c painter, f *fileInfo) string {
	if f == nil {
		return ""
	}
	if f.Gone {
		return "  " + c.dim("(gone afterwards)")
	}
	if f.Kind == "symlink" {
		return "  " + c.dim("-> "+f.Link)
	}
	parts := []string{humanSize(f.Size)}
	if f.SHA256 != "" {
		parts = append(parts, "sha256:"+f.SHA256[:12])
	}
	s := "  " + c.dim(strings.Join(parts, "  "))
	switch {
	case f.Setuid:
		s += " " + c.red("[SETUID]")
	case f.Kind == "elf":
		s += " " + c.red("[ELF binary]")
	case f.Kind == "script" && f.Exec:
		s += " " + c.yellow("[executable script]")
	}
	return s
}

func (r *report) eventLines(w io.Writer, c painter, ind, verb string, paint func(string) string,
	m map[string]*stat, isNet bool) {
	hidden := map[string]int{}
	for _, k := range sortedKeys(m) {
		s := m[k]
		if !r.showAll && s.Noise != "" && s.Tag == "" {
			hidden[s.Noise]++
			continue
		}

		line := ind + paint(fmt.Sprintf("%-6s", verb)) + " " + k
		if isNet {
			if h, _, err := net.SplitHostPort(k); err == nil && r.nameFor(h) != "" {
				line += " " + c.cyan("("+r.nameFor(h)+")")
			}
		}
		if s.Count > 1 {
			line += c.dim(fmt.Sprintf("  x%d", s.Count))
		}
		line += fileSummary(c, s.File)
		if n := failNote(s); n != "" {
			line += "  " + c.yellow("("+n+")")
		}
		if s.Tag != "" {
			line += "  " + c.red("["+s.Tag+"]")
		}
		fmt.Fprintln(w, line)
	}

	if len(hidden) > 0 {
		labels := make([]string, 0, len(hidden))
		for l := range hidden {
			labels = append(labels, l)
		}
		sort.Slice(labels, func(i, j int) bool {
			if hidden[labels[i]] != hidden[labels[j]] {
				return hidden[labels[i]] > hidden[labels[j]]
			}
			return labels[i] < labels[j]
		})
		parts := make([]string, len(labels))
		for i, l := range labels {
			parts[i] = fmt.Sprintf("%s x%d", l, hidden[l])
		}
		fmt.Fprintf(w, "%s%s\n", ind, c.dim("hidden: "+strings.Join(parts, ", ")+"  (-all shows them)"))
	}
}

func (r *report) opLines(w io.Writer, c painter, ind string, m map[string]*stat) {
	for _, k := range sortedKeys(m) {
		s := m[k]
		verb, rest, _ := strings.Cut(k, " ")

		line := ind + c.yellow(fmt.Sprintf("%-6s", verb)) + " " + rest
		if verb == "bind" || verb == "send" {
			if h, _, err := net.SplitHostPort(rest); err == nil && r.nameFor(h) != "" {
				line += " " + c.cyan("("+r.nameFor(h)+")")
			}
		}
		if s.Count > 1 {
			line += c.dim(fmt.Sprintf("  x%d", s.Count))
		}
		if n := failNote(s); n != "" {
			line += "  " + c.yellow("("+n+")")
		}
		if s.Tag != "" {
			line += "  " + c.red("["+s.Tag+"]")
		}
		fmt.Fprintln(w, line)
	}
}

func (r *report) printProc(w io.Writer, c painter, p *proc, prefix, connector string, last bool, depth int) {
	childP := prefix
	if connector != "" {
		if last {
			childP += "   "
		} else {
			childP += "│  "
		}
	}
	fmt.Fprintf(w, "%s%s%s\n", prefix, connector, r.label(c, p))

	vbar := " "
	if len(p.Children) > 0 {
		vbar = "│"
	}
	ind := childP + vbar + "   "
	r.eventLines(w, c, ind, "write", c.green, p.Writes, false)
	r.eventLines(w, c, ind, "delete", c.red, p.Deletes, false)
	r.opLines(w, c, ind, p.Ops)
	r.eventLines(w, c, ind, "read", c.dim, p.Reads, false)
	r.eventLines(w, c, ind, "net", c.cyan, p.Conns, true)

	if depth > 64 {
		return
	}
	for i, ch := range p.Children {
		isLast := i == len(p.Children)-1
		conn := "├─ "
		if isLast {
			conn = "└─ "
		}
		r.printProc(w, c, ch, childP, conn, isLast, depth+1)
	}
}

func (r *report) totals() (procs, written, deleted, read, conns, ops int) {
	for _, p := range r.procs {
		procs++
		written += len(p.Writes)
		deleted += len(p.Deletes)
		read += len(p.Reads)
		conns += len(p.Conns)
		ops += len(p.Ops)
	}
	return
}

func kindPaint(c painter, kind string) func(string) string {
	switch kind {
	case "read", "stat":
		return c.dim
	case "exec":
		return c.bold
	case "write":
		return c.green
	case "delete":
		return c.red
	case "net", "dns", "bind", "send", "resolve":
		return c.cyan
	}
	return c.yellow
}

func timelineLine(c painter, e tevent, t int64) string {
	line := fmt.Sprintf("  %s  %s %s %s", c.dim(fmt.Sprintf("%9s", fmtOffset(t))),
		kindPaint(c, e.Kind)(fmt.Sprintf("%-7s", e.Kind)), shorten(e.Text, 100),
		c.dim(fmt.Sprintf("[%s %d]", e.Proc, e.Pid)))
	if e.Failed {
		line += "  " + c.yellow("(failed)")
	}
	if e.Tag != "" {
		line += "  " + c.red("["+e.Tag+"]")
	}
	return line
}

func (r *report) liveLine(w io.Writer) {
	e := r.last
	if e == nil || (!r.showAll && e.Noise != "" && e.Tag == "") {
		return
	}
	fmt.Fprintln(w, timelineLine(painter{r.color}, *e, e.T-r.minTs))
}

func (r *report) writeTimeline(w io.Writer, c painter) {
	fmt.Fprintf(w, "\n%s\n", c.bold("timeline"))
	skipped := 0
	for _, e := range r.Timeline {
		if !r.showAll && e.Noise != "" && e.Tag == "" {
			skipped++
			continue
		}
		fmt.Fprintln(w, timelineLine(c, e, e.T))
	}
	if skipped > 0 {
		fmt.Fprintf(w, "  %s\n", c.dim(fmt.Sprintf("(%d system events hidden, -all shows them)", skipped)))
	}
}

func (r *report) verdictLine(c painter) string {
	counts := map[string]int{}
	var order []string
	for _, f := range r.Findings {
		if counts[f.Cat] == 0 {
			order = append(order, f.Cat)
		}
		counts[f.Cat]++
	}
	parts := make([]string, len(order))
	for i, cat := range order {
		parts[i] = fmt.Sprintf("%s %d", cat, counts[cat])
	}

	label := strings.ToUpper(r.Verdict)
	switch r.Verdict {
	case "high":
		label = c.red(label)
	case "medium":
		label = c.yellow(label)
	case "none":
		label = c.green(label)
	default:
		label = c.dim(label)
	}
	line := c.bold("verdict ") + label
	if len(parts) > 0 {
		line += c.dim("  (" + strings.Join(parts, ", ") + ")")
	}
	return line
}

func (r *report) writeFindings(w io.Writer, c painter) {
	fmt.Fprintf(w, "\n%s\n", c.bold(fmt.Sprintf("findings: %d", len(r.Findings))))
	cat := ""
	for _, f := range r.Findings {
		if f.Cat != cat {
			cat = f.Cat
			fmt.Fprintf(w, "  %s\n", c.sev(f.Sev, cat))
		}
		fmt.Fprintf(w, "    %s %s\n", c.sev(f.Sev, "["+f.Tag+"]"), f.Text)
	}
}

func (r *report) writeIOCs(w io.Writer, c painter) {
	if r.IOCs.empty() {
		return
	}
	fmt.Fprintf(w, "\n%s\n", c.bold("indicators (IOC)"))
	group := func(name string, items []string) {
		for i, it := range items {
			label := ""
			if i == 0 {
				label = name
			}
			fmt.Fprintf(w, "  %-9s %s\n", c.dim(label), it)
		}
	}
	group("domains", r.IOCs.Domains)
	group("ips", r.IOCs.IPs)
	group("sockets", r.IOCs.Unix)
	files := make([]string, len(r.IOCs.Files))
	for i, f := range r.IOCs.Files {
		files[i] = f.SHA256 + "  " + f.Path
	}
	group("files", files)
}

func (r *report) writeText(w io.Writer) {
	c := painter{r.color}

	status := r.Status
	if r.ExitCode != 0 {
		status = c.red(status)
	} else {
		status = c.green(status)
	}
	fmt.Fprintf(w, "\n%s  %s\n", c.bold("sus"), shorten(strings.Join(r.Command, " "), 110))
	fmt.Fprintf(w, "%s, %s\n", status, time.Duration(r.DurationMs)*time.Millisecond)
	fmt.Fprintln(w, r.verdictLine(c))

	np, nw, nd, nr, nc, no := r.totals()
	fmt.Fprintf(w, "%s\n", c.dim(fmt.Sprintf("%d processes, %d files written, %d deleted, %d read, %d connections, %d other operations",
		np, nw, nd, nr, nc, no)))
	for _, n := range r.Notes {
		fmt.Fprintf(w, "%s\n", c.yellow(n))
	}
	fmt.Fprintln(w)

	for _, root := range r.Roots {
		r.printProc(w, c, root, "", "", true, 0)
	}

	if r.timeline {
		r.writeTimeline(w, c)
	}
	r.writeFindings(w, c)
	r.writeIOCs(w, c)

	if r.Lost > 0 {
		fmt.Fprintf(w, "\n%s\n", c.yellow(fmt.Sprintf("warning: %d events were dropped (ring buffer full)", r.Lost)))
	}
}
