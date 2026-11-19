# Contributing to KyGate

The architecture is in [docs/architecture.md](docs/architecture.md); read it before proposing a change.

## Build and test

Go 1.26 or later. No C compiler is needed: the SQLite driver is pure Go.

```sh
go build -o kygate ./cmd/kygate
go vet ./...
go test -count=1 ./...            # includes the end-to-end tests and the eval/ quality gates
node --check web/static/app.js    # the console script
GOOS=linux go vet ./cmd/...       # the background-service code differs per operating system
cd guard && python -m pytest -q   # the Guard, in its own environment (guard/README.md)
```

CI runs the same steps ([.github/workflows/ci.yml](.github/workflows/ci.yml)). To try a change by hand, run `kygate serve --data-dir /tmp/kg` with a provider key in the environment; the data directory is created on the first start, which prints a virtual key and an admin token once. Use a scratch `--data-dir`, and with `kygate service install` also a scratch `--name` and other ports, so that a test never touches a real installation. The commands are described in [docs/deployment.md](docs/deployment.md).

## Editions

This repository is KyGate Community. KyGate Enterprise is built from the same code with `-tags enterprise` and a few private files (`*_ee.go`); the public build never needs them. Community files that stand in for an Enterprise capability end in `_ce.go` and carry `//go:build !enterprise`: keep them answering with `edition.Unavailable`, never with a silent no-op. Contributions go to the Community edition.

## Design rules every change must respect

1. **The Guard detects; the Gateway enforces.** The ML service only reports findings. Masking, blocking, and the placeholder map stay in the gateway.
2. **Security fails closed; optimization fails open.** When detection is unavailable, the request is refused or kept local. When a cache or the router is unavailable, the request goes ahead without that optimization.
3. **Real sensitive values live only in request memory.** They are never written to a cache, a log, a queue, or a database.
4. **The provider sees a stable conversation.** Masking is deterministic and append-only, so an earlier turn looks byte-identical every time it is sent again.
5. **Every stateful dependency is pluggable,** with an embedded implementation for one user and a clustered one for 100,000.
6. **Measure before enforcing.** Detection, the semantic cache, and routing each have a mode that only reports what they would have done.

A change that breaks one of these needs a design discussion first, not a pull request.

## Where things go

| Change | Location |
|---|---|
| Wire format handling (OpenAI, Anthropic) | `internal/ingress/` |
| A pipeline stage or its order | `internal/pipeline/` |
| Fast detectors (patterns, checksums, dictionaries) | `internal/detect/` |
| ML detectors, embeddings, reranking | `guard/kygate_guard/` |
| Gateway ↔ Guard contract | `api/proto/guard/v1/` |
| Masking and rehydration | `internal/mask/` |
| Caches and coalescing | `internal/cache/` |
| Routing and model catalog use | `internal/router/` |
| A new model provider | `internal/provider/<name>/` |
| A new storage back end | `internal/store/<driver>/`, behind the existing interface |
| First-start setup, provider connections | `internal/control/`, `cmd/kygate/` |
| Background service (scheduled task, systemd unit) | `cmd/kygate/service*.go`, one file per operating system |
| A command, a flag, a policy setting, or a response header | The code, and with it `usage()` in `cmd/kygate/main.go`, [docs/deployment.md](docs/deployment.md), and the README |
| Admin and reporting API | `internal/control/`, `api/openapi/` |
| Console pages and reports | `web/` |
| Deployment | `deploy/` |
| Benchmarks | `eval/` |

## Every release must run for real

Every release carries real traffic with real provider keys, and has a console that shows what it did. A change is done when this still works on a clean machine:

1. Add one or several provider keys, through environment variables or the command line.
2. Start KyGate. The first start asks no questions.
3. Send requests from an unmodified OpenAI or Anthropic client. Only the base URL and the key change.
4. Read the result in the console.

Three consequences for contributions:

- **A change must not break an existing installation.** Keys, policy files, and stored data carry over between versions. A new capability arrives switched off or in monitor mode.
- **A capability that produces data comes with its console view,** in the same change.
- **Solo stays light.** A change must not make the Guard, an external store, or a key-management service a requirement of the Solo profile.

## Quality gates

The `eval/` suite runs in CI and tracks:

- detection precision and recall, per data type and per language;
- the semantic-cache false-hit rate;
- routing quality;
- masking stability across turns (byte-identical prefixes);
- load tests.

A missed detection is a leak and a false alarm is a broken prompt, so both numbers count. Changes to detection, masking, caching, or routing should come with eval coverage.

The first-run path is tested end to end in CI against a stand-in provider, and checked with real provider keys before each release.

## Commits and pull requests

- Reference the capability ID from [docs/architecture.md §3.2](docs/architecture.md#32-functional-blocks) (for example `PR-4` or `OP-3`) when a change implements or modifies one.
- Never put real prompts, real personal data, or real credentials in tests, fixtures, logs, or issues. Use synthetic data. This includes provider keys: if one is ever committed, revoke it at the provider at once.
- A change to the design updates [docs/architecture.md](docs/architecture.md) in the same pull request.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
