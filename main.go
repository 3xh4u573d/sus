package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	evExec = 1 + iota
	evOpen
	evConnect
	evUnlink
	evRename
	evMkdir
	evChmod
	evSymlink
	evBind
	evSendto
	evPtrace
	evSetuid
	evSetresuid
	evMount
	evMemfd
	evModule
	evDNS
	evDNSQ
	evStat
)

type event struct {
	Ts     uint64
	Type   uint32
	Pid    uint32
	Ppid   uint32
	Flags  uint32
	ArgLen uint32
	Result int32
	Aux    uint32
	Family uint16
	Port   uint16
	Addr   [16]byte
	Comm   [16]byte
	Path   [256]byte
	Args   [512]byte
}

var verbose bool

type options struct {
	showAll, asJSON, resolve, color, timeline, noHash bool
	noNet, watch, noPager, isolate, noCanary          bool
	outFile, keepDir, memLimit                        string
	pidsLimit                                         int
	timeout                                           time.Duration
	roPaths, rwPaths                                  multiFlag
}

func init() { runtime.LockOSThread() }

const usageText = `usage: sudo sus [options] [--] command [args...]

Runs the command, traces what it does with eBPF and prints a report: process
tree, files, network, suspicious behaviour, indicators. Meant for looking at
programs you do not trust: run it inside a VM and prefer -no-net.

options:
`

const usageExamples = `
examples:
  sudo sus ./sample
  sudo sus -isolate -no-net -timeout 60s -mem 512M -pids 200 -keep ./loot -o auto ./sample
  sudo sus -w -t curl -s https://example.com
  sudo env "PATH=$PATH" sus npm install
`

func main() {
	var opts options
	flag.BoolVar(&opts.showAll, "all", false, "also list noisy system paths (libraries, /proc, ...)")
	flag.BoolVar(&opts.asJSON, "json", false, "print the report as JSON")
	flag.BoolVar(&opts.resolve, "r", false, "resolve connection IPs to names (reverse DNS, makes DNS queries)")
	flag.BoolVar(&opts.resolve, "resolve", false, "same as -r")
	flag.BoolVar(&opts.timeline, "t", false, "also print a chronological timeline of events")
	flag.BoolVar(&opts.timeline, "timeline", false, "same as -t")
	flag.BoolVar(&opts.watch, "w", false, "show events live while the command runs")
	flag.BoolVar(&opts.watch, "watch", false, "same as -w")
	flag.BoolVar(&opts.noNet, "no-net", false, "run in an empty network namespace: connection attempts are logged but go nowhere")
	flag.BoolVar(&opts.isolate, "isolate", false, "sandbox the command (needs bubblewrap): own namespaces, read-only system, fake home, no capabilities, seccomp")
	flag.Var(&opts.roPaths, "ro", "with -isolate: also expose this `path` read-only (repeatable); files named in the arguments are exposed automatically")
	flag.Var(&opts.rwPaths, "rw", "with -isolate: expose this `path` writable (repeatable; the command can change it)")
	flag.BoolVar(&opts.noCanary, "no-canary", false, "with -isolate: leave the fake home empty instead of filling it with decoy credentials")
	flag.DurationVar(&opts.timeout, "timeout", 0, "kill the command (and everything it started) after this long, e.g. 60s")
	flag.StringVar(&opts.memLimit, "mem", "", "memory limit for the command, e.g. 512M")
	flag.IntVar(&opts.pidsLimit, "pids", 0, "maximum number of processes/threads")
	flag.StringVar(&opts.keepDir, "keep", "", "copy dropped and executed non-system files into this `dir` (named by sha256)")
	flag.StringVar(&opts.outFile, "o", "", "also write a self-contained HTML report to this `file` (\"auto\" picks a name)")
	flag.BoolVar(&opts.noHash, "no-hash", false, "do not hash/stat files the command wrote or ran")
	flag.BoolVar(&opts.noPager, "no-pager", false, "do not pipe long reports through less")
	noColor := flag.Bool("no-color", false, "disable colors (also honours NO_COLOR)")
	completion := flag.String("completion", "", "print a shell completion script (zsh or bash) and exit")
	flag.BoolVar(&verbose, "v", false, "debug: print cgroup id and ring buffer counters")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageText)
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, usageExamples)
	}
	flag.Parse()

	if *completion != "" {
		if !printCompletion(*completion) {
			fmt.Fprintln(os.Stderr, "sus: -completion expects zsh or bash")
			os.Exit(2)
		}
		return
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if opts.memLimit != "" && !regexp.MustCompile(`^[0-9]+[KMGkmg]?$`).MatchString(opts.memLimit) {
		fmt.Fprintln(os.Stderr, "sus: -mem expects a number with optional K, M or G suffix")
		os.Exit(2)
	}
	opts.color = !*noColor && useColor()

	code, err := run(flag.Args(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sus: %+v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func useColor() bool {
	return os.Getenv("NO_COLOR") == "" && isTTY(os.Stderr)
}

func termRows() int {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stderr.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.Row)
}

func showReport(b []byte, opts options) {
	if !opts.noPager && isTTY(os.Stderr) {
		if rows := termRows(); rows > 0 && bytes.Count(b, []byte("\n")) > rows-2 {
			if path, err := exec.LookPath("less"); err == nil {
				cmd := exec.Command(path, "-R", "-F", "-X")
				cmd.Stdin = bytes.NewReader(b)
				cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
				cmd.Env = append(os.Environ(), "LESSSECURE=1")
				if cred, env := sudoIdentity(); cred != nil {
					cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
					cmd.Env = append(cmd.Env, env...)
				}
				if cmd.Run() == nil {
					return
				}
			}
		}
	}
	os.Stderr.Write(b)
}

func autoName(cmd []string) string {
	base := regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(filepath.Base(cmd[0]), "_")
	return fmt.Sprintf("sus-%s-%s.html", base, time.Now().Format("20060102-150405"))
}

var signalNames = map[syscall.Signal]string{
	syscall.SIGHUP: "SIGHUP", syscall.SIGINT: "SIGINT", syscall.SIGQUIT: "SIGQUIT",
	syscall.SIGILL: "SIGILL", syscall.SIGTRAP: "SIGTRAP", syscall.SIGABRT: "SIGABRT",
	syscall.SIGBUS: "SIGBUS", syscall.SIGFPE: "SIGFPE", syscall.SIGKILL: "SIGKILL",
	syscall.SIGSEGV: "SIGSEGV", syscall.SIGPIPE: "SIGPIPE", syscall.SIGTERM: "SIGTERM",
	syscall.SIGSYS: "SIGSYS",
}

func signalName(s syscall.Signal) string {
	if n, ok := signalNames[s]; ok {
		return n
	}
	return fmt.Sprintf("signal %d", int(s))
}

func run(cmdArgs []string, opts options) (int, error) {
	if os.Geteuid() != 0 {
		return 0, errors.New("must run as root (use sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return 0, err
	}

	cg, err := newCgroup()
	if err != nil {
		return 0, err
	}
	defer cg.remove()

	var notes []string
	if opts.memLimit != "" || opts.pidsLimit > 0 {
		notes = append(notes, cg.setLimits(opts.memLimit, opts.pidsLimit)...)
	}

	var iso *isolation
	if opts.isolate {
		iso, err = prepareIsolation(opts, cmdArgs)
		if err != nil {
			return 0, err
		}
		defer iso.cleanup()
		notes = append(notes, iso.notes...)
	}

	var objs susObjects
	if err := loadSusObjects(&objs, nil); err != nil {
		return 0, fmt.Errorf("load BPF: %w", err)
	}
	defer objs.Close()

	if err := objs.Target.Put(uint32(0), cg.id); err != nil {
		return 0, fmt.Errorf("set target cgroup: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "sus: cgroup %s id=%d\n", cg.path, cg.id)
	}

	probes := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sched_process_exec", objs.HandleExec},
		{"openat", objs.HandleOpenat},
		{"openat2", objs.HandleOpenat2},
		{"unlinkat", objs.HandleUnlinkat},
		{"unlink", objs.HandleUnlink},
		{"rmdir", objs.HandleRmdir},
		{"rename", objs.HandleRename},
		{"renameat", objs.HandleRenameat},
		{"renameat2", objs.HandleRenameat2},
		{"mkdir", objs.HandleMkdir},
		{"mkdirat", objs.HandleMkdirat},
		{"chmod", objs.HandleChmod},
		{"fchmodat", objs.HandleFchmodat},
		{"fchmodat2", objs.HandleFchmodat2},
		{"symlink", objs.HandleSymlink},
		{"symlinkat", objs.HandleSymlinkat},
		{"newstat", objs.HandleNewstat},
		{"newlstat", objs.HandleNewlstat},
		{"newfstatat", objs.HandleNewfstatat},
		{"statx", objs.HandleStatx},
		{"access", objs.HandleAccess},
		{"faccessat", objs.HandleFaccessat},
		{"faccessat2", objs.HandleFaccessat2},
		{"connect", objs.HandleConnect},
		{"bind", objs.HandleBind},
		{"sendto", objs.HandleSendto},
		{"ptrace", objs.HandlePtrace},
		{"setuid", objs.HandleSetuid},
		{"setresuid", objs.HandleSetresuid},
		{"mount", objs.HandleMount},
		{"memfd_create", objs.HandleMemfdCreate},
		{"init_module", objs.HandleInitModule},
		{"finit_module", objs.HandleFinitModule},
	}
	for _, p := range probes {
		l, err := link.AttachTracing(link.TracingOptions{Program: p.prog})
		if err != nil {
			return 0, fmt.Errorf("attach %s: %w", p.name, err)
		}
		defer l.Close()
	}

	dnsLinks, err := attachDNS(&objs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sus: DNS names unavailable: %v\n", err)
	}
	defer func() {
		for _, l := range dnsLinks {
			l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return 0, fmt.Errorf("ring buffer: %w", err)
	}
	defer rd.Close()

	rep := newReport()
	rep.showAll, rep.color, rep.timeline = opts.showAll, opts.color, opts.timeline
	if iso != nil {
		rep.maps, rep.passthrough, rep.infra = iso.maps, iso.passthrough, true
	}
	done := make(chan struct{})
	var nrec, nbad int
	go func() {
		defer close(done)
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, ringbuf.ErrFlushed) {
					return
				}
				fmt.Fprintln(os.Stderr, "sus: ring buffer read:", err)
				return
			}
			nrec++
			var ev event
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				nbad++
				continue
			}
			rep.add(&ev)
			if opts.watch {
				rep.liveLine(os.Stderr)
			}
		}
	}()

	var cmd *exec.Cmd
	if iso != nil {
		cmd = exec.Command(iso.bwrap, iso.args...)
		cmd.ExtraFiles = []*os.File{iso.seccomp}
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	} else {
		cmd = exec.Command(cmdArgs[0], cmdArgs[1:]...)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.file.Fd())}
	if iso != nil {
		rep.EnvSecrets = secretEnvNames(iso.env)
	} else {
		if opts.noNet {
			cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWNET
			notes = append(notes, "network isolated (-no-net): connection attempts are logged but go nowhere")
		}
		runAsInvokingUser(cmd)
		env := cmd.Env
		if env == nil {
			env = os.Environ()
		}
		rep.EnvSecrets = secretEnvNames(env)
	}

	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigc {
			if s == syscall.SIGTERM && cmd.Process != nil {
				cmd.Process.Signal(s)
			}
		}
	}()

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start %q: %w", cmdArgs[0], err)
	}
	if iso != nil {
		iso.seccomp.Close()
		iso.seccomp = nil
	}
	if verbose {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", cmd.Process.Pid))
		fmt.Fprintf(os.Stderr, "sus: child pid=%d is in cgroup: %s", cmd.Process.Pid, b)
	}

	var timedOut atomic.Bool
	if opts.timeout > 0 {
		t := time.AfterFunc(opts.timeout, func() {
			timedOut.Store(true)
			cg.kill()
		})
		defer t.Stop()
	}

	waitErr := cmd.Wait()
	dur := time.Since(start)
	signal.Stop(sigc)
	close(sigc)

	exit := 0
	sigName := ""
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			sigName = signalName(ws.Signal())
			exit = 128 + int(ws.Signal())
		} else {
			exit = ee.ExitCode()
		}
	} else if waitErr != nil {
		return 0, waitErr
	}

	if left := cg.waitEmpty(3 * time.Second); left > 0 {
		cg.kill()
		cg.waitEmpty(time.Second)
		notes = append(notes, fmt.Sprintf("killed %d process(es) still running after the command exited", left))
	}
	rd.Flush()
	<-done

	status := fmt.Sprintf("exit %d", exit)
	if sigName != "" {
		status = "killed by " + sigName
	}
	if iso != nil && sigName == "" && exit > 128 && exit < 128+65 {
		status = fmt.Sprintf("exit %d (probably %s)", exit, signalName(syscall.Signal(exit-128)))
	}
	if timedOut.Load() {
		status += " (-timeout reached)"
		notes = append(notes, fmt.Sprintf("stopped after -timeout %s", opts.timeout))
	}
	if n := cg.oomKills(); n > 0 {
		status += " (memory limit hit)"
		notes = append(notes, fmt.Sprintf("-mem limit reached: %d process(es) killed by the OOM killer", n))
	}

	var lost uint64
	objs.Dropped.Lookup(uint32(0), &lost)
	if verbose {
		fmt.Fprintf(os.Stderr, "sus: ring buffer records=%d undecodable=%d dropped=%d\n", nrec, nbad, lost)
	}

	rep.Status = status
	rep.finish(cmdArgs, exit, dur, lost, !opts.noHash)
	if opts.resolve {
		rep.resolveNames()
	}

	if opts.keepDir != "" {
		if n, err := rep.keep(opts.keepDir); err != nil {
			notes = append(notes, fmt.Sprintf("-keep: %v", err))
		} else {
			notes = append(notes, fmt.Sprintf("kept %d file(s) in %s (manifest.txt maps hashes to paths)", n, opts.keepDir))
		}
	}
	rep.Notes = notes

	if opts.asJSON {
		rep.writeJSON(os.Stderr)
	} else {
		var buf bytes.Buffer
		rep.writeText(&buf)
		showReport(buf.Bytes(), opts)
	}

	if opts.outFile != "" {
		name := opts.outFile
		if name == "auto" {
			name = autoName(cmdArgs)
		}
		if err := rep.writeHTML(name); err != nil {
			fmt.Fprintf(os.Stderr, "sus: write %s: %v\n", name, err)
		} else {
			fmt.Fprintf(os.Stderr, "\nHTML report: %s\n", name)
		}
	}
	return exit, nil
}

var libcCandidates = []string{
	"/lib/x86_64-linux-gnu/libc.so.6",
	"/usr/lib/x86_64-linux-gnu/libc.so.6",
	"/lib64/libc.so.6",
	"/usr/lib64/libc.so.6",
}

func attachDNS(objs *susObjects) ([]link.Link, error) {
	var libc string
	for _, c := range libcCandidates {
		if _, err := os.Stat(c); err == nil {
			libc = c
			break
		}
	}
	if libc == "" {
		return nil, errors.New("libc.so.6 not found")
	}

	ex, err := link.OpenExecutable(libc)
	if err != nil {
		return nil, err
	}
	enter, err := ex.Uprobe("getaddrinfo", objs.HandleGaiEnter, nil)
	if err != nil {
		return nil, fmt.Errorf("uprobe getaddrinfo: %w", err)
	}
	exit, err := ex.Uretprobe("getaddrinfo", objs.HandleGaiExit, nil)
	if err != nil {
		enter.Close()
		return nil, fmt.Errorf("uretprobe getaddrinfo: %w", err)
	}
	return []link.Link{enter, exit}, nil
}

func secretEnvNames(env []string) []string {
	parts := []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY",
		"ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL", "COOKIE", "AUTH_SOCK"}
	prefixes := []string{"AWS_", "AZURE_", "GITHUB_", "GH_", "NPM_", "GITLAB_", "DOCKER_", "KUBE"}

	var out []string
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		hit := false
		for _, p := range parts {
			if strings.Contains(up, p) {
				hit = true
			}
		}
		for _, p := range prefixes {
			if strings.HasPrefix(up, p) {
				hit = true
			}
		}
		if hit {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func sudoIdentity() (*syscall.Credential, []string) {
	uidS, gidS := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	uid, err1 := strconv.ParseUint(uidS, 10, 32)
	gid, err2 := strconv.ParseUint(gidS, 10, 32)
	if err1 != nil || err2 != nil {
		return nil, nil
	}

	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	var env []string
	if u, err := user.LookupId(uidS); err == nil {
		if ids, err := u.GroupIds(); err == nil {
			for _, s := range ids {
				if g, err := strconv.ParseUint(s, 10, 32); err == nil {
					cred.Groups = append(cred.Groups, uint32(g))
				}
			}
		}
		env = []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username}
	}
	return cred, env
}

func runAsInvokingUser(cmd *exec.Cmd) {
	cred, env := sudoIdentity()
	if cred == nil {
		return
	}
	cmd.SysProcAttr.Credential = cred
	cmd.Env = append(os.Environ(), env...)
}

type cgroup struct {
	path string
	file *os.File
	id   uint64
}

func newCgroup() (*cgroup, error) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return nil, errors.New("cgroup v2 is not mounted at /sys/fs/cgroup")
	}

	path := fmt.Sprintf("/sys/fs/cgroup/sus-%d", os.Getpid())
	if err := os.Mkdir(path, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		os.Remove(path)
		return nil, err
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	return &cgroup{path: path, file: f, id: st.Ino}, nil
}

func (c *cgroup) write(file, val string) error {
	return os.WriteFile(filepath.Join(c.path, file), []byte(val), 0)
}

func (c *cgroup) setLimits(mem string, pids int) []string {
	var notes []string
	set := func(file, val string) error {
		err := c.write(file, val)
		if err != nil {
			os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory +pids"), 0)
			err = c.write(file, val)
		}
		return err
	}

	if mem != "" {
		if err := set("memory.max", mem); err != nil {
			notes = append(notes, fmt.Sprintf("warning: could not set the memory limit: %v", err))
		} else {
			c.write("memory.swap.max", "0")
			c.write("memory.oom.group", "1")
			notes = append(notes, "memory limit "+mem)
		}
	}
	if pids > 0 {
		if err := set("pids.max", strconv.Itoa(pids)); err != nil {
			notes = append(notes, fmt.Sprintf("warning: could not set the process limit: %v", err))
		} else {
			notes = append(notes, fmt.Sprintf("process limit %d", pids))
		}
	}
	return notes
}

func (c *cgroup) kill() {
	if c.write("cgroup.kill", "1") == nil {
		return
	}
	b, _ := os.ReadFile(filepath.Join(c.path, "cgroup.procs"))
	for _, f := range strings.Fields(string(b)) {
		if pid, err := strconv.Atoi(f); err == nil {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func (c *cgroup) oomKills() int {
	b, err := os.ReadFile(filepath.Join(c.path, "memory.events"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == "oom_kill" {
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return 0
}

func (c *cgroup) waitEmpty(timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		b, _ := os.ReadFile(c.path + "/cgroup.procs")
		n := len(strings.Fields(string(b)))
		if n == 0 || time.Now().After(deadline) {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *cgroup) remove() {
	c.file.Close()
	if err := os.Remove(c.path); err != nil {
		fmt.Fprintf(os.Stderr, "sus: could not remove %s: %v\n", c.path, err)
	}
}

const zshCompletion = `#compdef sus
_arguments -s \
  '-all[also list noisy system paths]' \
  '(-r -resolve)'{-r,-resolve}'[reverse DNS for connection IPs]' \
  '(-t -timeline)'{-t,-timeline}'[print a chronological timeline]' \
  '(-w -watch)'{-w,-watch}'[show events live]' \
  '-o[also write an HTML report (auto picks a name)]:file:_files' \
  '-keep[copy dropped and executed files here]:dir:_directories' \
  '-no-net[run without network, attempts are still logged]' \
  '-isolate[sandbox the command with bubblewrap]' \
  '*-ro[expose a path read-only inside the sandbox]:path:_files' \
  '*-rw[expose a path writable inside the sandbox]:path:_files' \
  '-no-canary[leave the fake home empty]' \
  '-timeout[kill the command after this long]:duration:' \
  '-mem[memory limit, e.g. 512M]:size:' \
  '-pids[maximum number of processes]:n:' \
  '-json[print the report as JSON]' \
  '-no-color[disable colors]' \
  '-no-hash[skip hashing files]' \
  '-no-pager[do not page long reports]' \
  '-v[debug output]' \
  '*::command:_normal'
`

const bashCompletion = `_sus() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "-all -r -resolve -t -timeline -w -watch -o -keep -no-net -isolate -ro -rw -no-canary -timeout -mem -pids -json -no-color -no-hash -no-pager -v" -- "$cur"))
  else
    COMPREPLY=($(compgen -c -- "$cur"))
  fi
}
complete -F _sus sus
`

func printCompletion(shell string) bool {
	switch shell {
	case "zsh":
		fmt.Print(zshCompletion)
	case "bash":
		fmt.Print(bashCompletion)
	default:
		return false
	}
	return true
}
