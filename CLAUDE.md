# CLAUDE.md - ldaplookup

Guidance for Claude Code and contributors. Read this first to run, build, and
release the project.

## What this is

`ldaplookup` is a hardened, self-contained Go CLI for LDAP user and group
lookups. Run as `ldaplookup` it looks up users; the `ldaplookupg` symlink looks
up groups (the binary picks mode from its invocation name). Credentials are
handled at build time, never passed on the command line or via the environment.

Two credential modes, chosen when you run `build.sh`:

- **Mode 2 (embedded):** password XOR-obfuscated inside the binary. Single
  artifact, no post-deploy step, weaker against static analysis.
- **Mode 1 (sealed, 2.x only):** password encrypted on the target with
  AES-256-GCM, key derived from `/etc/machine-id` + build salt + deploy path +
  running UID + a hash of the binary. Run `./ldaplookup --seal` once on the
  target; it writes a `.seal.<uid>` file that is useless on any other machine,
  user, or path. Resists static analysis but needs the one-time seal step.

Keep BOTH modes. Do not remove the XOR path.

## Release lines (both are maintained)

- `main` is the **2.x** line: latest stable plus development; has sealed
  credentials. Tag releases `v2.x.y` here. `dev` is the 2.x integration branch.
- `1.x` is the **1.x maintenance** line: embedded mode only, patched as needed,
  to be retired eventually. Tag releases `v1.x.y` on this branch.
- Run `git branch` to see which line you are on. Sealed-credentials code and
  docs exist only on 2.x.

## Build and test

Requires Go 1.25.10 and garble v0.15.0, plus the system packages listed in
`.container-packages` (openssl, util-linux-script). The runtime binary has no
dependencies of its own.

```
# one-time, if `go` is not already on PATH:
./install-go-local.sh        # installs Go 1.25.10 + garble v0.15.0 into ~/myGo
source ~/myGo/env.sh         # activate Go in this shell (run once per session)

./test_build.sh              # CI build test, dummy data, no real creds (use this to verify)
./build.sh                   # interactive real build (prompts for LDAP creds + locks)
```

### Toolchain pin (important)

garble is pinned to **v0.15.0** and must be built with the active Go:
`GOTOOLCHAIN=local go install mvdan.cc/garble@v0.15.0`. Do NOT use
`garble@latest`: it requires Go 1.26+, and a garble built against a different Go
version refuses to run ("built with goX, can't be used with goY"). If you bump
Go, rebuild garble with it. `govulncheck ./...` should report 0 affecting
vulnerabilities.

## Releasing

1. Commit on the correct line (`main` for 2.x, `1.x` for 1.x).
2. Verify: `go vet ./...`, `go build`, `./test_build.sh` green, `govulncheck ./...` clean.
3. Annotated tag `vX.Y.Z`, push the branch and tag, then
   `gh release create vX.Y.Z --notes-file <file>`. GitHub attaches the source
   tar.gz, which is the intended artifact: users build their own binary with
   their own credentials, so no prebuilt binary is shipped. Pass `--latest` for
   the newest release overall.

### Pushing in this environment

SSH to GitHub is blocked in the dev container. Push over HTTPS using the gh
token, which avoids hanging on a prompt:

```
GIT_TERMINAL_PROMPT=0 git push https://github.com/vnegrea/ldaplookup.git <ref>
```

The gh CLI is installed and authenticated. Note the git author identity here
defaults to `Developer <dev@example.com>`, which is not linked to a GitHub
account; set `git config user.email` to the real GitHub email if commit
attribution matters.

## Key files

- `main.go`: all logic (hostname/path locks, anti-debug, `secureExit`,
  sealed and embedded credential handling, the LDAP query).
- `build.sh`: interactive hardened build (garble plus `-ldflags -X`), credential
  mode selection, optional hostname and path locks.
- `test_build.sh`: non-interactive CI build test with dummy values; exercises
  every build path (both modes on 2.x).
- `install-go-local.sh`: installs the pinned Go and garble locally.
- `.claude/plans/`, `.claude/notes/`: design and audit history (gitignored,
  local only).
