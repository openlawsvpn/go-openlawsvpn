NDK_VERSION      := 30.0.14904198
ANDROID_API      := 31
ANDROID_SDK_HOME ?= $(HOME)/Android/Sdk
MODULE           := github.com/openlawsvpn/go-openlawsvpn
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

RPM_OUTDIR   ?= $(shell pwd)/rpmbuild
SPEC         := packaging/openlawsvpn.spec

.PHONY: all aar aar-sha256 cli relay-server run-local-relay test lint clean daemon gui gui-release gui-deps rpm srpm builddep

all: aar

## Build the Android .aar
aar: go-openlawsvpn.aar

go-openlawsvpn.aar:
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
	  -o go-openlawsvpn.aar \
	  -target android \
	  -androidapi $(ANDROID_API) \
	  -ldflags "-X $(MODULE).Version=$(VERSION)" \
	  $(MODULE)

## Compute SHA-256 checksum alongside the .aar
aar-sha256: go-openlawsvpn.aar
	sha256sum go-openlawsvpn.aar > go-openlawsvpn.aar.sha256

## Build the Linux CLI binary (CGO_ENABLED=0 → fully static)
cli:
	CGO_ENABLED=0 go build -o openlawsvpn-cli ./cmd/cli

## Build the local relay-server test binary
relay-server:
	CGO_ENABLED=0 go build -o relay-server ./cmd/relay-server

## Start the local relay server for testing (default port 18080, override with RELAY_ADDR)
## Agent:  openlawsvpn-cli -config tunnel.ovpn -relay <token> -relay-endpoint ws://localhost:18080/ws
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

## Install GTK4/libadwaita build dependencies (Fedora)
gui-deps:
	sudo dnf install -y \
	  gtk4-devel libadwaita-devel dbus-devel \
	  rust cargo

## Build the GTK4 GUI binary (debug; use gui-release for optimised)
gui:
	cd gui-gtk && cargo build
	cp gui-gtk/target/debug/openlawsvpn-gui .

gui-release:
	cd gui-gtk && cargo build --release
	cp gui-gtk/target/release/openlawsvpn-gui .

## Build the SRPM
srpm:
	mkdir -p $(RPM_OUTDIR)/SRPMS
	rm -rf $(RPM_OUTDIR)/SRPMS/*.src.rpm
	rpkg srpm --spec $(SPEC) --outdir $(RPM_OUTDIR)/SRPMS
	@echo "SRPM: $$(find $(RPM_OUTDIR)/SRPMS -name '*.src.rpm')"

## Install missing RPM build dependencies (requires sudo), then build binary RPMs.
## Uses dnf builddep which handles %%generate_buildrequires automatically.
rpm: srpm
	#sudo dnf builddep -y $$(find $(RPM_OUTDIR)/SRPMS -name '*.src.rpm' | head -1)
	rpmbuild --rebuild $$(find $(RPM_OUTDIR)/SRPMS -name '*.src.rpm' | head -1) \
	    --define "_topdir $(RPM_OUTDIR)"
	@echo ""
	@echo "RPMs built:"
	@find $(RPM_OUTDIR)/RPMS -name '*.rpm'
	@echo ""
	@echo "Install with:"
	@echo "  sudo dnf install $$(find $(RPM_OUTDIR)/RPMS -name '*.rpm' | tr '\n' ' ')"

## Show missing RPM build dependencies without installing
builddep: srpm
	dnf builddep --assumeno $$(find $(RPM_OUTDIR)/SRPMS -name '*.src.rpm' | head -1)

## Remove build artefacts
clean:
	rm -f go-openlawsvpn.aar go-openlawsvpn.aar.sha256 go-openlawsvpn-sources.jar openlawsvpn-cli relay-server openlawsvpn-daemon openlawsvpn-gui
	rm -rf rpmbuild gui-gtk/target
