OUT ?= sus

PREFIX ?= /usr/local

.PHONY: all deps generate build install uninstall clean

all: deps generate build

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

deps:
	go get github.com/cilium/ebpf@latest

generate: bpf/vmlinux.h
	go generate ./...

build:
	go mod tidy
	go build -buildvcs=false -o $(OUT) .

install:
	install -Dm755 $(OUT) $(DESTDIR)$(PREFIX)/bin/sus
	./$(OUT) -completion zsh | install -Dm644 /dev/stdin $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sus
	./$(OUT) -completion bash | install -Dm644 /dev/stdin $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sus

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/sus \
		$(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sus \
		$(DESTDIR)$(PREFIX)/share/bash-completion/completions/sus

clean:
	rm -f $(OUT) bpf/vmlinux.h *_bpfel.go *_bpfel.o *.o.tmp *.temp-stream-* *.html
