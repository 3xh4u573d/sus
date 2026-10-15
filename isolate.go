package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const sandboxSize = "size=256m"

type pathMap struct{ sandbox, host string }

type isolation struct {
	bwrap       string
	args        []string
	env         []string
	seccomp     *os.File
	maps        []pathMap
	passthrough []string
	stateDir    string
	notes       []string
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

var canaryFiles = map[string]string{
	".ssh/id_rsa":      "-----BEGIN OPENSSH PRIVATE KEY-----\nsus-canary-this-is-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n",
	".ssh/id_ed25519":  "-----BEGIN OPENSSH PRIVATE KEY-----\nsus-canary-this-is-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n",
	".ssh/config":      "Host *\n  ServerAliveInterval 30\n",
	".ssh/known_hosts": "example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsuscanary\n",
	".aws/credentials": "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
	".netrc":           "machine example.com login canary password canary\n",
	".gitconfig":       "[user]\n\tname = analyst\n",
	".bash_history":    "ls\ncd projects\n",

	".config/google-chrome/Default/Login Data": "",
	".mozilla/firefox/sus.default/logins.json": "{}\n",
}

func (iso *isolation) cleanup() {
	if iso.seccomp != nil {
		iso.seccomp.Close()
	}
	if iso.stateDir != "" {
		syscall.Unmount(iso.stateDir, syscall.MNT_DETACH)
		os.RemoveAll(iso.stateDir)
	}
}

func underDir(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

func prepareIsolation(opts options, cmdArgs []string) (*isolation, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, errors.New("-isolate needs bubblewrap: sudo apt install bubblewrap")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		return nil, errors.New("-isolate needs setpriv (package util-linux)")
	}
	if real, err := filepath.EvalSymlinks(setpriv); err == nil {
		setpriv = real
	}

	uidS, gidS := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uidS == "" || gidS == "" || uidS == "0" {
		return nil, errors.New("-isolate runs the command as the user who called sudo, so start it with sudo from a normal user")
	}
	uid, err1 := strconv.Atoi(uidS)
	gid, err2 := strconv.Atoi(gidS)
	u, err3 := user.LookupId(uidS)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("cannot determine the user who called sudo")
	}
	home := u.HomeDir

	state := fmt.Sprintf("/run/sus-%d", os.Getpid())
	if err := os.Mkdir(state, 0o755); err != nil {
		return nil, err
	}
	iso := &isolation{bwrap: bwrap, stateDir: state}
	if err := syscall.Mount("tmpfs", state, "tmpfs", 0, sandboxSize+",mode=0755"); err != nil {
		os.Remove(state)
		iso.stateDir = ""
		return nil, fmt.Errorf("mount sandbox tmpfs: %w", err)
	}

	copyPath := filepath.Join(state, "bwrap")
	if data, err := os.ReadFile(bwrap); err != nil {
		iso.cleanup()
		return nil, err
	} else if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		iso.cleanup()
		return nil, err
	}
	iso.bwrap = copyPath

	mk := func(name string, mode os.FileMode, own bool) (string, error) {
		d := filepath.Join(state, name)
		if err := os.Mkdir(d, mode.Perm()); err != nil {
			return "", err
		}
		if err := os.Chmod(d, mode); err != nil {
			return "", err
		}
		if own {
			os.Chown(d, uid, gid)
		}
		return d, nil
	}
	sticky := os.FileMode(0o777) | os.ModeSticky
	tmpDir, err := mk("tmp", sticky, false)
	if err != nil {
		iso.cleanup()
		return nil, err
	}
	varTmp, err := mk("vartmp", sticky, false)
	if err != nil {
		iso.cleanup()
		return nil, err
	}
	homeDir, err := mk("home", 0o700, true)
	if err != nil {
		iso.cleanup()
		return nil, err
	}
	if !opts.noCanary {
		for rel, content := range canaryFiles {
			p := filepath.Join(homeDir, rel)
			os.MkdirAll(filepath.Dir(p), 0o700)
			if os.WriteFile(p, []byte(content), 0o600) == nil {
				os.Chown(p, uid, gid)
			}
		}
		filepath.Walk(homeDir, func(p string, info os.FileInfo, err error) error {
			if err == nil {
				os.Lchown(p, uid, gid)
			}
			return nil
		})
	}

	iso.maps = []pathMap{{"/tmp", tmpDir}, {"/var/tmp", varTmp}, {home, homeDir}}

	cmd := append([]string(nil), cmdArgs...)
	if strings.Contains(cmd[0], "/") {
		if abs, err := filepath.Abs(cmd[0]); err == nil {
			cmd[0] = abs
		}
	}

	cwd, _ := os.Getwd()
	fakeHome := cwd == home || cwd == "/" || underDir(cwd, "/proc") || underDir(cwd, "/sys")

	var ro []string
	seen := map[string]bool{}
	addRO := func(p string) {
		if p == "" || !filepath.IsAbs(p) || seen[p] || isSystemPath(p) {
			return
		}
		switch p {
		case "/", "/home", "/root", "/etc", "/mnt", "/media", "/run", home:
			return
		}
		if _, err := os.Stat(p); err != nil {
			return
		}
		for done := range seen {
			if underDir(p, done) {
				return
			}
		}
		seen[p] = true
		ro = append(ro, p)
	}
	if strings.Contains(cmd[0], "/") {
		addRO(cmd[0])
	}
	if !fakeHome {
		addRO(cwd)
	}
	for _, a := range cmd[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		abs := a
		if !filepath.IsAbs(a) {
			abs = filepath.Join(cwd, a)
		}
		addRO(filepath.Clean(abs))
	}
	for _, p := range opts.roPaths {
		addRO(filepath.Clean(p))
	}
	iso.passthrough = append(append([]string(nil), ro...), opts.rwPaths...)

	userGroups := map[string]bool{}
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			userGroups[g] = true
		}
	}
	keepGroups := map[string]bool{}
	for _, p := range append(append([]string(nil), ro...), opts.rwPaths...) {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm()&0o004 != 0 {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			g := strconv.Itoa(int(sys.Gid))
			if g != gidS && userGroups[g] {
				keepGroups[g] = true
			}
		}
	}
	groupArgs := []string{"--clear-groups"}
	if len(keepGroups) > 0 {
		var gs []string
		for g := range keepGroups {
			gs = append(gs, g)
		}
		sort.Strings(gs)
		groupArgs = []string{"--groups", strings.Join(gs, ",")}
		iso.notes = append(iso.notes, "groups kept for exposed paths: "+strings.Join(gs, ","))
	}

	sandboxCwd := cwd
	if fakeHome {
		sandboxCwd = home
	}

	args := []string{
		"--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup-try",
		"--hostname", "sus-sandbox",
		"--die-with-parent", "--new-session",
		"--cap-add", "ALL",
		"--seccomp", "3",
	}
	if opts.noNet {
		args = append(args, "--unshare-net")
		iso.notes = append(iso.notes, "network isolated (-no-net): connection attempts are logged but go nowhere")
	} else {
		iso.notes = append(iso.notes,
			"warning: the network is shared, so the sandbox can reach host loopback services and abstract unix sockets; use -no-net for strong isolation")
	}

	args = append(args, "--ro-bind", "/usr", "/usr")
	for _, d := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		hostPath := "/" + d
		if target, err := os.Readlink(hostPath); err == nil {
			args = append(args, "--symlink", target, hostPath)
		} else if st, err := os.Stat(hostPath); err == nil && st.IsDir() {
			args = append(args, "--ro-bind", hostPath, hostPath)
		}
	}
	mounted := map[string]bool{"/usr": true, "/etc": true, "/proc": true, "/dev": true,
		"/tmp": true, "/var/tmp": true, "/run": true, home: true}
	madeDir := map[string]bool{}
	parentDirs := func(targets []string) []string {
		var out []string
		for _, t := range targets {
			var chain []string
			for a := filepath.Dir(t); a != "/" && a != "."; a = filepath.Dir(a) {
				chain = append([]string{a}, chain...)
			}
			for _, a := range chain {
				if !mounted[a] && !madeDir[a] {
					madeDir[a] = true
					out = append(out, "--perms", "0755", "--dir", a)
				}
			}
		}
		return out
	}

	args = append(args, "--ro-bind", "/etc", "/etc", "--proc", "/proc", "--dev", "/dev")
	args = append(args, parentDirs([]string{"/var/tmp", home})...)
	args = append(args,
		"--bind", tmpDir, "/tmp",
		"--bind", varTmp, "/var/tmp",
		"--bind", homeDir, home,
		"--tmpfs", "/run")
	if !opts.noNet {
		args = append(args, "--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve")
	}
	args = append(args, parentDirs(append(append([]string(nil), ro...), opts.rwPaths...))...)
	for _, p := range ro {
		args = append(args, "--ro-bind", p, p)
	}
	for _, p := range opts.rwPaths {
		p = filepath.Clean(p)
		if filepath.IsAbs(p) {
			args = append(args, "--bind", p, p)
			iso.notes = append(iso.notes, "warning: "+p+" is writable from inside the sandbox (-rw)")
		}
	}
	args = append(args, "--chdir", sandboxCwd, "--clearenv")

	iso.env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + home,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"SHELL=/bin/bash",
		"LANG=C.UTF-8",
	}
	if t := os.Getenv("TERM"); t != "" {
		iso.env = append(iso.env, "TERM="+t)
	}
	for _, kv := range iso.env {
		k, v, _ := strings.Cut(kv, "=")
		args = append(args, "--setenv", k, v)
	}

	args = append(args, "--", setpriv, "--reuid", uidS, "--regid", gidS)
	args = append(args, groupArgs...)
	args = append(args,
		"--bounding-set", "-all", "--inh-caps", "-all", "--ambient-caps", "-all",
		"--no-new-privs", "--")
	args = append(args, cmd...)
	iso.args = args

	filter, err := seccompProgram()
	if err != nil {
		iso.cleanup()
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		iso.cleanup()
		return nil, err
	}
	if _, err := w.Write(filter); err != nil {
		r.Close()
		w.Close()
		iso.cleanup()
		return nil, err
	}
	w.Close()
	iso.seccomp = r

	iso.notes = append(iso.notes, fmt.Sprintf(
		"isolated (-isolate): own pid/ipc/uts/cgroup namespaces, read-only system, fake home with canary files, no capabilities, no_new_privs, seccomp (blocks %d syscalls, namespace creation, io_uring, bpf, ...)",
		len(blockedSyscalls)))
	return iso, nil
}

var blockedSyscalls = []uint32{
	321,
	298,
	323,
	425, 426, 427,
	248, 249, 250,
	246, 320,
	304,
	272, 308,
	310, 311, 312, 438,
	212,
	428, 429, 430, 431, 432, 442,
}

const (
	bpfLdAbs = 0x20
	bpfJeq   = 0x15
	bpfJset  = 0x45
	bpfRet   = 0x06

	auditArchX86_64       = 0xc000003e
	seccompRetAllow       = 0x7fff0000
	seccompRetKillProcess = 0x80000000
	seccompRetErrno       = 0x00050000
	eperm                 = 1
	enosys                = 38

	cloneNewFlags = 0x7e020000
)

type insn struct {
	label  string
	code   uint16
	k      uint32
	jt, jf string
}

func assemble(prog []insn) ([]byte, error) {
	at := map[string]int{}
	for i, in := range prog {
		if in.label != "" {
			at[in.label] = i
		}
	}
	jump := func(i int, label string) (uint8, error) {
		if label == "" {
			return 0, nil
		}
		t, ok := at[label]
		if !ok || t <= i || t-i-1 > 255 {
			return 0, fmt.Errorf("seccomp: bad jump to %q from %d", label, i)
		}
		return uint8(t - i - 1), nil
	}

	out := make([]byte, 0, len(prog)*8)
	for i, in := range prog {
		jt, err := jump(i, in.jt)
		if err != nil {
			return nil, err
		}
		jf, err := jump(i, in.jf)
		if err != nil {
			return nil, err
		}
		var b [8]byte
		binary.LittleEndian.PutUint16(b[0:], in.code)
		b[2], b[3] = jt, jf
		binary.LittleEndian.PutUint32(b[4:], in.k)
		out = append(out, b[:]...)
	}
	return out, nil
}

func seccompProgram() ([]byte, error) {
	p := []insn{
		{code: bpfLdAbs, k: 4},
		{code: bpfJeq, k: auditArchX86_64, jt: "ok"},
		{code: bpfRet, k: seccompRetKillProcess},
		{label: "ok", code: bpfLdAbs, k: 0},
		{code: bpfJset, k: 0x40000000, jt: "eperm"},
		{code: bpfJeq, k: 435, jt: "enosys"},
		{code: bpfJeq, k: 56, jt: "clone"},
	}
	for _, nr := range blockedSyscalls {
		p = append(p, insn{code: bpfJeq, k: nr, jt: "eperm"})
	}
	p = append(p,
		insn{code: bpfRet, k: seccompRetAllow},
		insn{label: "clone", code: bpfLdAbs, k: 16},
		insn{code: bpfJset, k: cloneNewFlags, jt: "eperm"},
		insn{code: bpfRet, k: seccompRetAllow},
		insn{label: "eperm", code: bpfRet, k: seccompRetErrno | eperm},
		insn{label: "enosys", code: bpfRet, k: seccompRetErrno | enosys},
	)
	return assemble(p)
}
