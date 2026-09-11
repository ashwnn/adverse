# ADVERSE-Go Makefile — hardened laboratory builds
#
# Targets:
#   build        - Standard stripped build (CI default, reproducible)
#   hardened     - Hardened build: BuildID scrub, PIE, polymorphic seed, padded overlay
#   obfuscated   - Hardened + garble (requires mvdan.cc/garble@v0.14+)
#   windows      - Lab agent: cross-compile registryfil.exe (GOOS=windows GOARCH=amd64)
#   windows-hardened - Lab agent: Windows + hardened flags
#   polymorph    - Append random overlay to bust VT file-hash (post-build)
#   test/lint/clean - as before
#
# Deployable Windows stubs use the embedded-config path, not these targets:
#   adversed gen-stub --secret-file <f> --server-url <url> --out stub.exe
# These `windows*` targets build the --config lab agent only.
#
# Hardening defeats:
#   - Ghidra Go-binary analyzer (BuildID + pclntab minimization via tiny/garble)
#   - VirusTotal YARA string rules (XOR-rotated literals, BuildID scrub)
#   - Well-known Go function matchers (indirect dispatch via internal/obfuscate)
#   - Bytecode/linear-sweep analysis (opaque predicates, CF flattening, junk islands)
#
# Lab safety: hardening does NOT alter guard enforcement or synthetic_only.
# Polymorphic seed is per-invocation; artifact hash changes per build by design.

.PHONY: build hardened obfuscated windows windows-hardened polymorph generate test test-race lint clean verify-hardened

# Version variables for both binaries (overridable via ldflags).
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GITCOMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILDTIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
# Per-build polymorphic seed: random hex per invocation makes every artifact hash unique (VT hash busting).
# Cached via := after ?= so each `make` invocation uses one seed (both binaries share it, echo matches ldflags).
# Override with: make POLY_SEED=deadbeef hardened  or  POLY_SEED=deadbeef make windows-hardened
POLY_SEED ?= $(shell od -An -tx1 -N4 /dev/urandom 2>/dev/null | tr -d ' \n' || echo "5A")
# Explicit seed (command line or environment) — only then does `generate`
# rewrite the tracked string table; the implicit per-invocation random seed
# must not, or every `make hardened` would dirty the worktree. Computed before
# the := caching assignment below, which would otherwise reset origin to file.
POLY_SEED_EXPLICIT := $(filter command line environment,$(origin POLY_SEED))
POLY_SEED := $(POLY_SEED)

# Base stripped flags — BuildID scrubbed (empty) so VT cannot match "Go cmd/go BuildID".
# -trimpath removes filesystem paths from pclntab/DWARF (Ghidra path reduction).
# -buildid= is a LINKER flag (-ldflags) that empties the Go BuildID note; -s -w strip symtab/DWARF.
LDFLAGS := -s -w -buildid=
REGISTRYFIL_LDFLAGS := $(LDFLAGS) \
	-X main.version=$(VERSION) \
	-X main.gitCommit=$(GITCOMMIT) \
	-X main.buildTime=$(BUILDTIME)
ADVERSED_LDFLAGS := $(LDFLAGS) \
	-X main.version=$(VERSION) \
	-X main.gitCommit=$(GITCOMMIT) \
	-X main.buildTime=$(BUILDTIME)

# Hardened adds per-build seed for obfuscate/stealth + PIE and extra linker scrub.
HARDENED_LDFLAGS := $(REGISTRYFIL_LDFLAGS) \
	-X github.com/ashwnn/adverse-go/internal/obfuscate.BuildSeed=$(POLY_SEED) \
	-X github.com/ashwnn/adverse-go/internal/stealth.XorKeyHex=$(POLY_SEED)
# Windows cannot use -buildmode=pie with GOOS=windows cross-compile; use default exe mode there.
HARDENED_BUILD_FLAGS := -trimpath -buildmode=pie -ldflags "$(HARDENED_LDFLAGS)"
HARDENED_BUILD_FLAGS_WINDOWS := -trimpath -ldflags "$(HARDENED_LDFLAGS)"
STANDARD_BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

BIN_DIR := bin

build: $(BIN_DIR)/adversed $(BIN_DIR)/registryfil

$(BIN_DIR)/adversed:
	@mkdir -p $(BIN_DIR)
	go build $(STANDARD_BUILD_FLAGS) -o $@ ./cmd/adversed

# hardened — polymorphic seed + PIE + BuildID scrub (no garble required; works on CI)
hardened: generate $(BIN_DIR)/adversed-hardened $(BIN_DIR)/registryfil-hardened

$(BIN_DIR)/adversed-hardened:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -buildmode=pie -ldflags "$(ADVERSED_LDFLAGS) -X github.com/ashwnn/adverse-go/internal/obfuscate.BuildSeed=$(POLY_SEED) -X github.com/ashwnn/adverse-go/internal/stealth.XorKeyHex=$(POLY_SEED)" -o $@ ./cmd/adversed
	@echo "hardened $(BIN_DIR)/adversed-hardened (seed=$(POLY_SEED))"

$(BIN_DIR)/registryfil:
	@mkdir -p $(BIN_DIR)
	go build $(STANDARD_BUILD_FLAGS) -o $@ ./cmd/registryfil

$(BIN_DIR)/registryfil-hardened:
	@mkdir -p $(BIN_DIR)
	go build $(HARDENED_BUILD_FLAGS) -o $@ ./cmd/registryfil
	@echo "hardened $(BIN_DIR)/registryfil-hardened (seed=$(POLY_SEED))"

# obfuscated — full garble pipeline: -literals (string encrypt), -tiny (pclntab/filename strip), -debug (DWARF strip), seeded.
# Tries a garble on PATH first, then `go run mvdan.cc/garble@v0.14.2`, and
# only falls back to `make hardened` when no garble build produced both outputs.
obfuscated: generate
	@mkdir -p $(BIN_DIR); \
	rm -f $(BIN_DIR)/adversed.obf $(BIN_DIR)/registryfil.obf; \
	if command -v garble >/dev/null 2>&1; then \
		echo ">> garble obfuscation (seed=$(POLY_SEED))"; \
		garble -literals -tiny -debug -seed random build -trimpath -ldflags "$(HARDENED_LDFLAGS)" -o $(BIN_DIR)/adversed.obf ./cmd/adversed && \
		garble -literals -tiny -debug -seed random build -trimpath -ldflags "$(HARDENED_LDFLAGS)" -o $(BIN_DIR)/registryfil.obf ./cmd/registryfil; \
	fi; \
	if [ ! -f $(BIN_DIR)/adversed.obf ] || [ ! -f $(BIN_DIR)/registryfil.obf ]; then \
		echo ">> garble not on PATH or build failed — trying pinned mvdan.cc/garble@v0.14.2"; \
		go run mvdan.cc/garble@v0.14.2 -literals -tiny -debug -seed random build -trimpath -ldflags "$(HARDENED_LDFLAGS)" -o $(BIN_DIR)/adversed.obf ./cmd/adversed && \
		go run mvdan.cc/garble@v0.14.2 -literals -tiny -debug -seed random build -trimpath -ldflags "$(HARDENED_LDFLAGS)" -o $(BIN_DIR)/registryfil.obf ./cmd/registryfil; \
	fi; \
	if [ -f $(BIN_DIR)/adversed.obf ] && [ -f $(BIN_DIR)/registryfil.obf ]; then \
		echo "obfuscated binaries: $(BIN_DIR)/adversed.obf $(BIN_DIR)/registryfil.obf"; \
	else \
		echo "garble pipeline unavailable or failed — falling back to hardened build"; \
		$(MAKE) hardened; \
	fi

windows:
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(REGISTRYFIL_LDFLAGS)" -o $(BIN_DIR)/registryfil.exe ./cmd/registryfil

windows-hardened: generate
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 go build $(HARDENED_BUILD_FLAGS_WINDOWS) -o $(BIN_DIR)/registryfil-hardened.exe ./cmd/registryfil
	@echo "hardened $(BIN_DIR)/registryfil-hardened.exe (seed=$(POLY_SEED))"

# polymorph — append structured overlay to bust MD5/SHA256/TLSH/ssdeep on VirusTotal (no exec change)
polymorph:
	@for f in $(BIN_DIR)/adversed* $(BIN_DIR)/registryfil*; do \
		[ -f "$$f" ] || continue; \
		echo "polymorphing $$f"; \
		go run ./tools/polymorph --in "$$f" --size 4194304; \
	done

verify-hardened:
	@echo "== strings check (hardened vs obfuscated) =="; \
	echo "hardened (no garble): IOC literals in fmt.Errorf still visible — expected residual."; \
	strings $(BIN_DIR)/registryfil-hardened 2>/dev/null | grep -F "NtSaveKey" >/dev/null && echo "info: NtSaveKey in fmt strings (needs garble -literals to hide)" || echo "info: NtSaveKey not found"; \
	strings $(BIN_DIR)/registryfil-hardened 2>/dev/null | grep -F "\\Registry\\Machine" >/dev/null && echo "info: hive path literal present (garble -literals hides)" || echo "info: hive paths hidden"; \
	echo "full VT/YARA evasion: 'make obfuscated' (garble -literals -tiny -debug) encrypts all literals and strips gopclntab"; \
	if strings $(BIN_DIR)/registryfil-hardened.exe 2>/dev/null | head -n1 >/dev/null; then echo "PE ok: bin/registryfil-hardened.exe is valid PE32+"; fi

# generate — re-encrypt the obfuscate string table with a pinned POLY_SEED.
# The generated file embeds genStringSeed next to the ciphertext and Get() uses
# only that value, so the committed table is self-consistent under the implicit
# random seed. Only an explicitly pinned seed rewrites the tracked file,
# avoiding worktree churn on every hardened/obfuscated build.
generate:
ifeq ($(POLY_SEED_EXPLICIT),)
	@echo "generate: POLY_SEED not pinned — keeping committed obfuscate string table (pass POLY_SEED=<hex> to rekey)"
else
	POLY_SEED=$(POLY_SEED) go generate ./internal/obfuscate
endif

test:
	go vet ./...
	go test ./... -count=1

test-race:
	go vet ./...
	go test -race ./... -count=1

lint:
	go vet ./...

clean:
	rm -rf $(BIN_DIR)
