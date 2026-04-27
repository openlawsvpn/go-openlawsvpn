NDK_VERSION      := 30.0.14904198
ANDROID_API      := 31
ANDROID_SDK_HOME ?= $(HOME)/Android/Sdk
MODULE           := github.com/openlawsvpn/go-openvpn3
VERSION          ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GOPATH           ?= $(shell go env GOPATH)

# Prefer the go-installed gomobile over any system package.
export PATH := $(GOPATH)/bin:$(PATH)

# Resolve NDK home: honour explicit override, then try common locations.
ifndef ANDROID_NDK_HOME
  ifdef ANDROID_SDK_ROOT
    ANDROID_NDK_HOME := $(ANDROID_SDK_ROOT)/ndk/$(NDK_VERSION)
  else ifdef ANDROID_HOME
    ANDROID_NDK_HOME := $(ANDROID_HOME)/ndk/$(NDK_VERSION)
  else
    ANDROID_NDK_HOME := $(ANDROID_SDK_HOME)/ndk/$(NDK_VERSION)
  endif
endif

GUI_REPO     ?= $(realpath ../openlawsvpn)
RPM_OUTDIR   ?= $(shell pwd)/rpmbuild
SPEC         := packaging/openlawsvpn.spec

.PHONY: all aar aar-sha256 cli relay-server run-local-relay test lint clean daemon rpm srpm builddep _sources _check-gui-repo

all: aar

## Build the Android .aar
aar: go-openvpn3.aar

go-openvpn3.aar:
	@command -v gomobile >/dev/null 2>&1 || { \
	  echo "gomobile not found — run: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init"; \
	  exit 1; \
	}
	@test -n "$(ANDROID_NDK_HOME)" || { \
	  echo "ANDROID_NDK_HOME is not set and could not be derived from ANDROID_SDK_ROOT/ANDROID_HOME."; \
	  echo "Set it explicitly: make aar ANDROID_NDK_HOME=/path/to/ndk/$(NDK_VERSION)"; \
	  exit 1; \
	}
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) gomobile bind -v \
	  -o go-openvpn3.aar \
	  -target android \
	  -androidapi $(ANDROID_API) \
	  -ldflags "-X $(MODULE).Version=$(VERSION)" \
	  $(MODULE)

## Compute SHA-256 checksum alongside the .aar
aar-sha256: go-openvpn3.aar
	sha256sum go-openvpn3.aar > go-openvpn3.aar.sha256

## Build the Linux CLI binary (CGO_ENABLED=0 → fully static)
cli:
	CGO_ENABLED=0 go build -o ovpn3 ./cmd/ovpn3

## Build the local relay-server test binary
relay-server:
	CGO_ENABLED=0 go build -o relay-server ./cmd/relay-server

## Start the local relay server for testing (default port 18080, override with RELAY_ADDR)
## Agent:  ovpn3 -config tunnel.ovpn -relay <token> -relay-endpoint ws://localhost:18080/ws
## App:    set endpoint to http://<host>:18080/api/v1
RELAY_ADDR ?= :18080
run-local-relay:
	CGO_ENABLED=0 go run ./cmd/relay-server -addr $(RELAY_ADDR)

## Run unit tests
test:
	go test -race ./...

## Run integration tests (starts local mock server, no Docker needed)
integration-test:
	go test -v -tags=integration -timeout 120s .

## Run go vet
lint:
	go vet ./...

## Build the D-Bus daemon binary (Linux, static)
daemon:
	CGO_ENABLED=0 go build -o openlawsvpn-daemon ./cmd/daemon

## Build source tarballs and RPMs (requires GUI_REPO=../openlawsvpn)
srpm: _check-gui-repo _sources
	rpmbuild -bs $(SPEC) \
	    --define "_topdir $(RPM_OUTDIR)" \
	    --define "_sourcedir $(RPM_OUTDIR)/SOURCES"
	@echo "SRPM: $$(find $(RPM_OUTDIR)/SRPMS -name '*.src.rpm')"

rpm: _check-gui-repo _sources
	rpmbuild -bb $(SPEC) \
	    --define "_topdir $(RPM_OUTDIR)" \
	    --define "_sourcedir $(RPM_OUTDIR)/SOURCES"
	@echo ""
	@echo "RPMs built:"
	@find $(RPM_OUTDIR)/RPMS -name '*.rpm'
	@echo ""
	@echo "Install with:"
	@echo "  sudo dnf install $$(find $(RPM_OUTDIR)/RPMS -name '*.rpm' | tr '\n' ' ')"

## Show missing RPM build dependencies
builddep: srpm
	dnf builddep --assumeno $$(find $(RPM_OUTDIR)/SRPMS -name '*.src.rpm' | head -1)

# Internal: pack source tarballs from working trees (not just HEAD, so
# uncommitted edits in gui-gtk/ are included).
_sources: _check-gui-repo
	mkdir -p $(RPM_OUTDIR)/SOURCES
	# go-openvpn3: pack from git HEAD (daemon source is committed)
	git archive --prefix=go-openvpn3/ HEAD | gzip > $(RPM_OUTDIR)/SOURCES/go-openvpn3.tar.gz
	# gui-gtk: pack working tree so uncommitted Cargo.toml changes are included
	tar -C $(GUI_REPO) \
	    --exclude='gui-gtk/target' \
	    --exclude='gui-gtk/.cargo' \
	    --transform='s,^gui-gtk,gui-gtk,' \
	    -czf $(RPM_OUTDIR)/SOURCES/openlawsvpn-gui-gtk.tar.gz \
	    gui-gtk/

_check-gui-repo:
	@test -d "$(GUI_REPO)/gui-gtk" || { \
	    echo "ERROR: GUI_REPO not found at $(GUI_REPO)"; \
	    echo "       Set GUI_REPO=/path/to/openlawsvpn"; \
	    exit 1; \
	}

## Remove build artefacts
clean:
	rm -f go-openvpn3.aar go-openvpn3.aar.sha256 go-openvpn3-sources.jar ovpn3 relay-server openlawsvpn-daemon
	rm -rf rpmbuild
