# KyGate Guard

The Guard is KyGate's ML service, written in Python on ONNX Runtime. It is called by the gateway, over gRPC, and by nothing else. Design: [architecture.md §4.4](../docs/architecture.md#44-the-guard-service).

## Responsibility

The Guard **detects; it never enforces.** It returns findings and threat scores. Masking, blocking, and the placeholder-to-value map stay in the gateway. The Guard holds no state.

| RPC | Purpose |
|---|---|
| `Inspect` | Findings (personal data) and threats (prompt injection) for segments the gateway has not seen before |
| `Embed` | Vectors for the semantic cache and the router. The input is already masked |
| `Rerank` | Second-stage check of semantic-cache candidates |

The contract is [api/proto/guard/v1/guard.proto](../api/proto/guard/v1/guard.proto). Finding offsets are **UTF-8 byte offsets**, end exclusive.

## Layout

| Path | Contents |
|---|---|
| `kygate_guard/server.py` | gRPC server |
| `kygate_guard/detectors/` | `base.py`: findings and the conversion to UTF-8 byte offsets. `personal_data.py`: recognizers now, ML detection next. `prompt_injection.py`: still empty; injection is detected by a model pack (`runtime/onnx_seq.py`) |
| `kygate_guard/pb/` | Code generated from the contract. Do not edit |
| `tests/` | The Guard against its contract, over a real gRPC connection; packs; and the quality gates of the personal-data and prompt-injection packs, each of which runs when its pack is installed |
| `kygate_guard/embeddings/` | Embedding and reranking models. Empty files: not built yet |
| `kygate_guard/runtime/` | `onnx_token.py`: the ONNX token-classifier runtime for personal-data packs. `onnx_seq.py`: the ONNX sequence-classifier runtime for threat packs, such as prompt injection. `batching.py`, `loader.py`, `warmup.py` are empty files for later work |
| `kygate_guard/packs.py` | Model packs: manifests, the catalog, `models list|pull|add|remove`, SHA-256 checks |
| `kygate_guard/catalog/` | The packs this Guard knows by name, as manifests (data, not code) |
| `pyproject.toml` | Package definition |

## Rules

- **Runtime:** quantized models on CPU by default, GPU optional. Requests from different callers are batched for a few milliseconds. Each instance runs several worker processes and reports ready only after its models are loaded and warmed up.
- **Two levels:** the base package finds what its recognizers list, with no model and no download. ML detection is optional and explicit: the `[ml]` extra adds the inference software, and `kygate-guard models pull` downloads a model pack after showing its models, size, and licenses.
- **Models:** pinned by digest, checked before use, and loaded from a local model directory, so air-gapped installs copy the directory and supply-chain checks still work. Nothing is downloaded at start or without the command. Every default model carries a permissive license, and the benchmarks choose which one goes in the default pack.
- **The level is never hidden:** the Guard reports, per data type, whether a list or a model covers it, so the gateway can show it and a policy can require a model.
- **What is scanned:** injection detection runs only on untrusted segments (user turns, tool results, retrieved documents). Prose gets the full ML detectors; source code and tool output get the fast detectors by default.
- **Long inputs:** sliding windows. The gateway sets a deadline on every call; a missed deadline is a Guard failure and follows the fail-closed rule.
- **Extension:** new recognizers (pattern, dictionary, model) are added by configuration.

## Optional by design

KyGate runs without the Guard. An installation needs it only when its policy names a data type or a threat that needs ML detection; from then on, a Guard that is missing or down follows the fail-closed rule (`on_guard_unavailable`). An installation keeps running as it is until its owner adds the Guard.

The semantic cache is an example: it runs without the Guard. It takes its embeddings from any OpenAI-compatible endpoint, such as a local Ollama, and confirms a match with hard checks in Go. A reranking model from the Guard could later join those checks, to let synonyms match and allow wider sharing scopes ([architecture.md §3.4](../docs/architecture.md#34-cache-rules)).

With the Guard, the console shows its state and latency, ML findings by data type and language, and injection attempts.

## Status

Built: the gRPC server, the contract, configurable recognizers, model packs (`kygate-guard models`), the ONNX token classifier (the `personal-data` add-on pack), the ONNX sequence classifier (the default `prompt-injection` pack), and TLS or mutual TLS on its port. Not built: embeddings and reranking; `Embed` and `Rerank` answer `UNIMPLEMENTED`. Third-party credits: [NOTICE](NOTICE).

## Install, run, test

```text
python -m venv .venv                         # in this folder, Python 3.10 or later
.venv/Scripts/pip install -e ".[test]"       # on Linux: .venv/bin/pip
.venv/Scripts/kygate-guard --listen 127.0.0.1:4002 --recognizers names.json
.venv/Scripts/python -m pytest -q            # the Guard against its contract
```

With ML detection (optional):

```text
.venv/Scripts/pip install -e ".[ml]"                     # the inference software
.venv/Scripts/kygate-guard models pull                   # the default pack (prompt-injection); shows models, size, licenses; asks; checks the digest
.venv/Scripts/kygate-guard models pull personal-data     # an add-on: ML detection of personal data
.venv/Scripts/kygate-guard models list                   # installed packs, their digests and licenses
```

| Option of `kygate-guard` | Default | Meaning |
|---|---|---|
| `--listen ADDR` | `127.0.0.1:4002` | Address to listen on. Without TLS, keep it on the loopback or a private network |
| `--tls-cert FILE`, `--tls-key FILE` | none | Serve TLS (also `KYGATE_GUARD_TLS_CERT`, `KYGATE_GUARD_TLS_KEY`) |
| `--tls-client-ca FILE` | none | Require callers to present a certificate this CA signed: mutual TLS (also `KYGATE_GUARD_TLS_CLIENT_CA`). The gateway's side: `KYGATE_GUARD_TLS_CA`, `KYGATE_GUARD_TLS_CERT`, `KYGATE_GUARD_TLS_KEY` |
| `--recognizers FILE` | none | A JSON file of terms and patterns, the base level |
| `--models DIR` | `KYGATE_GUARD_MODELS`, or `~/.kygate/models` | The model directory; every installed pack in it is loaded |
| `--no-models` | off | Load no model pack, even if some are installed: recognizers only |
| `--workers N` | `4` | Requests handled at the same time |

Once the Guard runs, the policy decides which of its types to act on: `kygate policy enable --list`, then `kygate policy enable TYPE...` (or `PROMPT_INJECTION` for the threat). How to connect it to KyGate, the recognizers file format, the data types, and the measured quality: [docs/deployment.md](../docs/deployment.md#the-guard). The container image: `docker build -t kygate-guard:0.1.2 .`, or `--build-arg EXTRAS=ml` for ML detection; packs are mounted on `/models`.

## Adding a model

A token classifier with BIO labels (B-X, I-X, O), exported to ONNX, needs no code. Write a `pack.json` next to nothing at all: the files it needs (the `.onnx` model, `tokenizer.json`, and the `config.json` holding `id2label`), each with an `https` address at a pinned revision and its SHA-256; the license; the languages; and a `label_map` from the model's labels to KyGate's data types. Then `kygate-guard models add pack.json`. Exactly one catalog pack carries `"default": true` (today `prompt-injection`): `models pull` with no name installs it; every other pack is an add-on. The catalog file [kygate_guard/catalog/personal-data.json](kygate_guard/catalog/personal-data.json) is a complete example.

A text classifier for a threat, exported to ONNX, needs no code either: runtime `onnx-sequence-classifier`, a `threat_map` from the model's labels to threats (`{"INJECTION": "PROMPT_INJECTION"}`), and `settings` for the window (`window_tokens`, `overlap_tokens`). The tokenizer's start and end tokens come from `special_tokens_map.json`. Example: [kygate_guard/catalog/prompt-injection.json](kygate_guard/catalog/prompt-injection.json). Another kind of model needs a new runtime in `kygate_guard/runtime/`, registered in `packs.RUNTIMES` and in `server.load_packs`; the gateway does not change.

## Changing the contract

The contract is [api/proto/guard/v1/guard.proto](../api/proto/guard/v1/guard.proto). After a change, regenerate both sides from the repository root, with `protoc-gen-go` and `protoc-gen-go-grpc` on the path:

```text
guard/.venv/Scripts/python -m grpc_tools.protoc -I api/proto --go_out=. --go_opt=module=github.com/Kytherion/KyGate --go-grpc_out=. --go-grpc_opt=module=github.com/Kytherion/KyGate api/proto/guard/v1/guard.proto
guard/.venv/Scripts/python -m grpc_tools.protoc -I api/proto/guard/v1 --python_out=guard/kygate_guard/pb --grpc_python_out=guard/kygate_guard/pb --pyi_out=guard/kygate_guard/pb api/proto/guard/v1/guard.proto
```

Then make the import in `guard/kygate_guard/pb/guard_pb2_grpc.py` relative: `from . import guard_pb2 as guard__pb2`.
