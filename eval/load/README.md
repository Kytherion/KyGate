# Load tests

Two parts: gates that run in CI with `go test ./...`, and `kyload`, a command that loads a real installation. Both use a stand-in model provider, so no load ever reaches a real provider or costs money. Every answer is checked: each caller must get its own card number back, with no placeholder left, so the numbers count only traffic that was served correctly.

| Part | Path |
|---|---|
| The gates | `load_test.go` |
| The load generator | `run/` |
| The stand-in provider (OpenAI and Anthropic APIs, streamed or not) | `standin/` |
| The command | `kyload/` |

## The gates

A gateway in the test process, with the starter policy (masking, output inspection, the exact cache on disk, the router in shadow mode, the event spool), against a stand-in that answers at once.

| Test | Measures | Target ([architecture.md §5.5](../../docs/architecture.md#55-latency-budget)) | Gate |
|---|---|---|---|
| `TestGatewayOverhead` | KyGate's own time on a model call (every stage but the upstream call, from the events), masking a card number and putting it back | 5 ms at p95 | 20 ms |
| `TestCacheHitTimeToFirstByte` | An exact-cache hit, to the first byte, each caller with its own card number | 15 ms at p95 | 60 ms |
| `TestManyOpenStreams` | 1,000 streams open at once: all correct, and what one open stream costs the gateway (the same streams sent straight to the stand-in are subtracted) | — | 192 KB per stream |
| `TestMixedThroughput` | 4,000 requests: half repeats, a fifth streamed, half with card numbers | — | 300 per second |

The gates fail only well past their targets, because CI machines are shared. Each test logs what it measured (`go test -v ./eval/load/`). `KYGATE_LOAD_HEAPPROFILE=FILE` writes a heap profile while the 1,000 streams are open.

## kyload, against a real installation

```text
go build -o kyload ./eval/load/kyload

kyload standin -listen 127.0.0.1:9100 -first-byte 300ms      # terminal 1: the stand-in provider

OPENAI_API_KEY=standin OPENAI_BASE_URL=http://127.0.0.1:9100 \
ANTHROPIC_API_KEY=standin ANTHROPIC_BASE_URL=http://127.0.0.1:9100 \
kygate serve --data-dir /tmp/kygate-load                     # terminal 2: a KyGate with its own data directory

kyload run -url http://127.0.0.1:4000 -key kg-... -c 64 -n 3000      # terminal 3
kyload run -url http://127.0.0.1:9100 -key x -c 64 -n 3000           # the same load straight to the stand-in: the baseline
```

KyGate's cost is the difference between the two runs. Use a data directory of its own: the load fills the console and the cache. `kyload run` takes `-api anthropic`, `-stream`, `-repeat`, `-sensitive` (shares from 0 to 1), `-d 60s` instead of `-n`, `-ramp`, and `-json`. It exits with status 1 when any request failed. For the Team profile or Helm, start the gateways with the same `*_BASE_URL` variables and point `-url` at the load balancer.

## Measured

On 2026-11-19, one Solo binary (stripped release build) on a laptop (Intel Core i7-11800H, 8 cores, 16 threads, Windows 11), the load generator and the stand-in on the same machine. The stand-in waits 300 ms before answering, then streams 20 pieces 25 ms apart.

| Measure | Result | Target |
|---|---|---|
| KyGate's cost on a model call (through KyGate minus straight to the stand-in) | +1.3 ms at p50, +1.5 ms at p95 | 5 ms at p95 |
| Exact-cache hit, first byte | 0.8 ms at p50, 1.2 ms at p95 | 15 ms at p95 |
| 64 callers, half repeats: requests per second | 288 through KyGate, 154 straight to the stand-in: the cache answered half | — |
| 1,000 streams open at once, 12,000 in all | 0 errors, 0 wrong answers, about 950 streams finished per second | — |
| Memory of an open stream in the gateway | about 128 KB, 5 goroutines (from `TestManyOpenStreams`) | — |
| KyGate's process with 1,000 streams open | about 300 MB working set, including the in-memory cache | — |

**Changed by these measurements:** the stream reader's buffer and the coalescing recorder's buffer went from 64 KB and 32 KB to 4 KB each (an open stream from about 200 KB to about 128 KB), and KyGate keeps up to 1,024 idle connections per provider instead of 64. With 64, 1,000 streams to an HTTP/1.1 server (a local model server) closed and dialled again about 900 connections a second, and 6 of 12,000 requests failed when the server refused a dial; with 1,024, none did.

### The Team profile

Also on 2026-11-19, the same laptop: `deploy/compose/team` (Caddy, two gateways, the control process, PostgreSQL 17, two Valkeys) in Docker Desktop (Linux containers), the stand-in and `kyload` as containers on the same network. Everything shares the laptop's 16 threads.

| Measure | Result |
|---|---|
| KyGate's cost on a model call (through Caddy and a gateway, minus straight to the stand-in) | +5.5 ms at p50, +7 ms at p95: the Caddy hop and the shared counters and cache in Valkey |
| Exact-cache hit from the shared Valkey cache, first byte | 1.8 ms at p50, 2.8 ms at p95 |
| 64 callers, half repeats | 284 requests per second, 0 errors, 0 wrong answers across the two gateways |
| 1,000 streams open at once, 8,000 in all | 0 errors, 0 wrong answers; first byte 366 ms at p50 (the stand-in's own is 300 ms) with the gateways CPU-bound |
| Each gateway with about 500 streams open | about 185 MB of memory, about 4.4 CPU cores |
| Events in PostgreSQL afterwards | 11,020 of 11,020: none lost |

**Finding, fixed the same day:** with streams, output inspection took about 40% of a gateway's CPU. Each streamed piece rescanned up to 8 KB already sent; a 16 KB answer arriving 4 bytes at a time cost 9.7 s of CPU. It now costs 0.18 s (`go test -bench Output ./internal/detect/`), with the same output.

### The Guard

Also on 2026-11-19, the same laptop: one Solo binary, the Python Guard (`kygate-guard`, CPU, ONNX Runtime 1.23) with its default pack, `prompt-injection` (Wolf Defender small, FP16 ONNX), and the policy blocking prompt injection (`kygate policy enable PROMPT_INJECTION --action block`). Short prompts of about 80 characters; every request a model call, so every one is inspected. The stand-in answers after 300 ms. The KyGate process, the Guard, the stand-in, and the load all share the machine.

| Callers | Guard workers | Requests per second | Model call, p50 | Added by the Guard, p50 |
|---|---|---|---|---|
| 4 | 4 (default) | 11 | 339 ms | about 38 ms |
| 16 | 4 | 44 | 355 ms | about 54 ms |
| 64 | 4 | 63 | 1,014 ms | queueing: the Guard is saturated |
| 64 | 16 | 74 | 855 ms | queueing |

An attack was refused with 403 (`X-KyGate-Blocked: PROMPT_INJECTION`) and every harmless request was answered: 0 errors.

**Finding:** the Guard saturates at about 70 inspections per second on this machine, roughly 100 ms of CPU core time per short prompt. The design's sizing rule assumed 30 ms ([architecture.md §5.2](../../docs/architecture.md#52-what-100000-users-means)): measured, 1,000 inspections per second would need on the order of 100 cores, or GPU nodes. The default pack is FP16, which CPUs mostly emulate; an INT8 version of the same model would likely be several times faster. Changing a pack needs a recorded decision and its quality gate (`guard/tests/test_eval_prompt_injection.py`). Raising `--workers` above the default 4 gained about 17%.

**Not measured yet:** Helm, the personal-data pack (not installed here; it is a 343 MB download), long prompts (the Guard's cost grows with the text), a GPU, the semantic cache with a real embeddings model, and a run on a Linux machine rather than in Docker Desktop.
