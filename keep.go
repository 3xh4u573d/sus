package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const maxKeepTotal = 512 << 20

func (r *report) keep(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	chownToSudoUser(dir)

	paths := map[string][]string{}
	var cand []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] && filepath.IsAbs(p) {
			seen[p] = true
			cand = append(cand, p)
		}
	}

	for _, pid := range r.sortedPids() {
		p := r.procs[pid]
		for _, e := range p.Execs {
			if !isSystemPath(e.Path) {
				add(e.Path)
			}
		}
		for path, s := range p.Writes {
			if s.Failed < s.Count && s.Noise == "" && s.File != nil && !s.File.Gone && s.File.Kind != "symlink" {
				add(path)
			}
		}
	}
	sort.Strings(cand)

	var total int64
	copied := 0
	for _, src := range cand {
		sum, n, err := copyArtifact(r.toHost(src), dir, &total)
		if err != nil || sum == "" {
			continue
		}
		if len(paths[sum]) == 0 {
			copied++
		}
		paths[sum] = append(paths[sum], src)
		_ = n
	}

	var lines []string
	for sum, ps := range paths {
		lines = append(lines, sum+"  "+strings.Join(ps, ", "))
	}
	sort.Strings(lines)
	manifest := filepath.Join(dir, "manifest.txt")
	if err := os.WriteFile(manifest, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err == nil {
		chownToSudoUser(manifest)
	}
	return copied, nil
}

func copyArtifact(src, dir string, total *int64) (string, int64, error) {
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxHashSize || *total+st.Size() > maxKeepTotal {
		return "", 0, fmt.Errorf("skipped")
	}

	tmp, err := os.CreateTemp(dir, ".wd-")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), f)
	if err != nil {
		tmp.Close()
		return "", 0, err
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}
	*total += n

	sum := hex.EncodeToString(h.Sum(nil))
	dst := filepath.Join(dir, sum)
	if _, err := os.Lstat(dst); err == nil {
		return sum, n, nil
	}
	if err := os.Chmod(tmp.Name(), 0o444); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", 0, err
	}
	chownToSudoUser(dst)
	return sum, n, nil
}

func chownToSudoUser(path string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 == nil && err2 == nil {
		os.Lchown(path, uid, gid)
	}
}
