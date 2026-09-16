<p align="center">
  <a href="../../CONTRIBUTING.md">Русский</a> · <strong>English</strong> · <a href="../zh-CN/CONTRIBUTING.md">简体中文</a>
</p>

# Contributing to Hydrat

Community contributions are welcome. Please read this guide before submitting changes.

---

## Technology and requirements

- **Go:** 1.26+
- **Network stack:** WireGuard, Xray-core, Tor, nftables
- **Containers:** Docker and Docker Compose
- **Operating system:** Linux 5.10+ with nftables and WireGuard support

---

## Development workflow

### 1. Prepare the environment

Clone the repository and download dependencies:

```bash
git clone https://github.com/only-hydrat/hydrat.git
cd hydrat
go mod download
```

### 2. Run tests

Before changing code, make sure the existing tests pass:

```bash
go test ./...
```

For verbose output:

```bash
go test -v ./...
```

### 3. Format and check code

Code must follow Go formatting and pass static analysis:

```bash
gofmt -s -w .
go vet ./...
```

### 4. Commits

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new functionality
- `fix:` bug fix
- `refactor:` code refactoring without behavior changes
- `docs:` documentation changes
- `test:` adding or fixing tests
- `chore:` maintenance and dependency updates

Example:

```text
feat(routing): add fallback latency threshold for active outbounds
```

---

## Submitting a pull request

1. Create a dedicated branch:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Implement the change and add tests for new behavior.
3. Confirm that `go test ./...` and `go vet ./...` pass.
4. Open a pull request against `main` and complete the provided template.
5. Wait for automated checks and code review.
