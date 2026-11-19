# Deployment

The operating guide, and a summary of [architecture.md §5](architecture.md#5-scaling-from-1-to-100000-users). Figures marked *target* or *estimate* are design assumptions, not measurements.

**Using KyGate:** [First run](#first-run) · [Ways to run KyGate](#ways-to-run-kygate) · [Keys and tokens](#keys-and-tokens) · [The console](#the-console) · [The Guard](#the-guard) · [People behind a key](#people-behind-an-application-key) · [Data handling](#data-handling-retention-regions-and-purges) · [Audit integrity and SIEM](#audit-integrity-and-siem-export) · [Master key in a KMS](#the-master-key-in-a-key-management-service) · [Kubernetes](#kubernetes-with-helm) · [The Team profile](#the-team-profile) · [Traces and metrics](#traces-and-metrics) · [Reference](#reference) · [Cache settings](#cache-settings)

**The design at every scale:** [Profiles](#profiles) · [Data stores](#data-stores-per-profile) · [Guard placement](#guard-placement) · [Scaling](#how-each-part-scales) · [Failures](#behavior-when-something-fails) · [Latency](#latency-targets) · [Operating notes](#operating-notes)

## First run

The steps are the same in every profile. Details: [architecture.md §3.7](architecture.md#37-first-run-from-a-provider-key-to-a-working-gateway).

```text
go build -o kygate ./cmd/kygate  # once. On Windows: go build -o kygate.exe ./cmd/kygate
export ANTHROPIC_API_KEY=...     # one or several real provider keys (ANTHROPIC_API_KEY_<SUFFIX> for more)
export OPENAI_API_KEY=...        # OPENAI_API_KEY_<SUFFIX> for more
./kygate serve                   # the first start prints a virtual key, an admin token, and the console address
```

In PowerShell, set a key with `$env:ANTHROPIC_API_KEY = "..."` and start KyGate with `.\kygate.exe serve`.

1. **Give KyGate the provider keys.** Use environment variables, the command line, or the admin API and console. One key or many, for one provider or several. A key supplied through the environment stays in memory. A key added from the command line or the console is stored encrypted. A key never goes into a policy file.
2. **Start KyGate.** The first start creates a master key, one organization, a starter policy, one virtual key, and one admin token. The virtual key and the admin token are shown once: copy them then ([Keys and tokens](#keys-and-tokens)).
3. **Point clients at it.** Change the base URL to `http://127.0.0.1:4000` (Anthropic SDKs) or `http://127.0.0.1:4000/v1` (OpenAI SDKs), and use the virtual key in place of the provider key.
4. **Open the console** at `http://127.0.0.1:4001` with the admin token to see usage, cost, savings, and findings ([The console](#the-console)).

With several keys for one provider, a conversation stays on the key that served its first turn. A key that is rate-limited or rejected is skipped before the first byte.

An upgrade keeps an installation working: keys, policy files, and data carry over, and new capabilities arrive switched off or in monitor mode.

## Ways to run KyGate

KyGate is one program, `kygate serve`. There are three ways to keep it running. The first two share the data directory (`~/.kygate` by default), so you can change from one to the other and keep your keys, policy, cache, and reports. Only one KyGate can use a port at a time: stop one before starting another.

| | In a terminal | In the background | In a container |
|---|---|---|---|
| Good for | A first try, development | Daily use on your own machine | A server |
| Start | `kygate serve` | `kygate service install`, once. After that it starts at every logon | `docker compose up -d` in `deploy/compose/solo` |
| Check that it runs | The terminal shows the banner and the log | `kygate service status` | `docker compose ps` |
| Stop | Ctrl+C | `kygate service stop` | `docker compose stop` |
| Start again | `kygate serve` | `kygate service start` | `docker compose start` |
| Restart | Ctrl+C, then `kygate serve` | `kygate service restart` | `docker compose restart` |
| Logs | The terminal | Windows: `<data-dir>/kygate.log`. Linux: `journalctl --user -u kygate` | `docker compose logs kygate` |
| It stops when | You press Ctrl+C or close the terminal | You stop it, or log off. After a crash it starts again by itself | You stop the container. After a crash or a reboot it starts again by itself |
| Remove | Nothing to remove | `kygate service uninstall` | `docker compose down` |

Whatever the way, two addresses tell you whether KyGate answers:

```text
curl http://127.0.0.1:4000/healthz    # {"status":"ok"}: KyGate is running
curl http://127.0.0.1:4000/readyz     # {"status":"ready","connections":1}, or the reason it is not ready, such as no provider key
```

Every stop in the table is graceful: KyGate takes no new requests, gives open streams 30 seconds to finish, and delivers its last events.

### In a terminal

```text
kygate serve [--data-dir DIR] [--listen ADDR] [--console-listen ADDR] [--policy FILE]
```

The start banner shows the data directory, the two addresses, the policy in force, the state of the exact cache and the semantic cache, and each provider key by name with its last four characters. Closing the terminal stops KyGate, and every client then fails until it is started again. For daily use, run it in the background.

### In the background

`kygate service` keeps KyGate running without a terminal, on Windows and Linux, with no administrator rights. It runs under your own account, on the same data directory.

```text
kygate provider add --name anthropic --provider anthropic   # once: store the provider key (it is read from standard input)
kygate service install      # register KyGate and start it now; from then on it starts at every logon
kygate service status       # is it running and ready? where are the console and the logs?
kygate service stop         # stop it; it starts again at the next logon, or with 'start'
kygate service start        # start it now
kygate service restart      # stop, then start: after a new build, for example
kygate service uninstall    # stop it and remove it from the system; the data directory is kept
```

`kygate service status` answers like this:

```text
KyGate service "KyGate"  a Windows scheduled task that starts KyGate when you log on
  State                  running, ready (1 provider connections)
  Model API              http://127.0.0.1:4000/v1  (OpenAI SDKs), http://127.0.0.1:4000 (Anthropic SDKs)
  Console                http://127.0.0.1:4001
  Data directory         C:\Users\you\.kygate
  Logs                   C:\Users\you\.kygate\kygate.log
```

The state is `running, ready`, `running, not ready` with the reason, or `stopped`.

`install` takes the same options as `serve` (`--data-dir`, `--listen`, `--console-listen`, `--policy`), and `--name` for the name of the task or unit (`KyGate` on Windows, `kygate` on Linux). The other commands take `--data-dir` when it is not the default.

| | Windows | Linux |
|---|---|---|
| What install creates | A scheduled task for your user, started at logon | A systemd user unit, `~/.config/systemd/user/kygate.service` |
| Administrator rights | Not needed | Not needed |
| After a crash | A hidden supervisor starts KyGate again: after 1 second, doubling to 1 minute | systemd starts it again (`Restart=on-failure`) |
| Logs | `<data-dir>/kygate.log` (rotated at 10 MB, one earlier file kept), `<data-dir>/service.log` for the supervisor, and `<data-dir>/guard.log` for the Guard | `journalctl --user -u kygate`, and `-u kygate-guard` for the Guard |
| At boot, before logon | No: it starts when you log on | With `loginctl enable-linger $USER` |
| After you log off | It stops, and starts at the next logon | It stops, unless lingering is on |

- **Provider keys:** a key set only in a terminal (`export ANTHROPIC_API_KEY=...`) is not visible to a background KyGate, and KyGate never copies it to disk. `install` refuses it and prints the command that stores it encrypted (`kygate provider add`). A key set for your user account (Windows environment variables, or the systemd user environment) is accepted as it is.
- **Other settings** that are not secrets, such as `KYGATE_LOCAL_<NAME>` addresses, provider base URLs, `KYGATE_CATALOG`, and the `OTEL_*` trace settings except headers, are recorded in `<data-dir>/service.json` and applied at each start. To change them, run `install` again from a terminal where they are set.
- **The first start** happens during `install`, in the terminal, so the virtual key and the admin token are shown there once and never written to a log. On a data directory that `kygate serve` already set up, nothing is shown: the existing keys and token keep working.
- **One KyGate per port:** `install` and `start` refuse to start the service while another KyGate answers on the same port. Stop the one in the terminal first (Ctrl+C).
- **A new build:** run `kygate service stop`, replace the binary, then `kygate service start`. Windows does not let a running binary be replaced. If the binary moves to another folder, run `install` again: the system records its path.
- **On Windows** the task opens a console window for a moment at logon, then KyGate runs hidden.
- **Other systems** (macOS): `kygate service` is not available. Run `kygate serve` under the system's own service manager.

### In a container

```text
cd deploy/compose/solo
export ANTHROPIC_API_KEY=...     # and, or, OPENAI_API_KEY
docker compose up -d             # build and start
docker compose logs kygate       # the first start prints the virtual key and the admin token here, once
docker compose ps                # is it running?
docker compose stop              # stop; 'docker compose start' starts it again
docker compose down              # remove the container; the data volume is kept
```

The data directory is the volume `kygate-data`, so a container does not share the data of a KyGate started on the host. A volume created before 2026-11-17 by the earlier image may belong to root, and the gateway then stops at start with "unable to open database file": remove it with `docker compose down -v`. Both ports are published on the local machine only. The management commands run inside the container, for example `docker compose exec kygate kygate key create alice` and `docker compose exec kygate kygate admin-token reset`.

## Keys and tokens

| Secret | What it is for | How you get it | If you lose it |
|---|---|---|---|
| **Provider key** (`sk-...`) | KyGate calls the provider with it. Clients never see it | From your provider. Give it to KyGate in an environment variable, or store it with `kygate provider add` | Ask your provider for a new one |
| **Virtual key** (`kg-...`) | A client uses it in place of a provider key | The first start prints one, once. Create more with `kygate key create NAME` | Create a new one with `kygate key create NAME`, and revoke the old one with `kygate key revoke NAME` |
| **Admin token** (`kgadmin-...`) | It opens the console | The first start prints it, once | `kygate admin-token reset` prints a new one. The old one stops working at once; no restart is needed |
| **Master key** | It encrypts the stored provider keys and the cache | The first start creates `<data-dir>/master.key`. Or supply your own in `KYGATE_MASTER_KEY`, or, in the Enterprise edition, keep it wrapped by Vault or a cloud KMS ([Master key in a KMS](#the-master-key-in-a-key-management-service)) | Keep a copy. KyGate refuses to start on a data directory with another master key |

- **Where the first start prints the virtual key and the admin token:** in the terminal for `kygate serve`; in the terminal during `kygate service install`, when that is the first start; in `docker compose logs kygate` for a container.
- **KyGate cannot show them again.** It stores only their hashes. `kygate key list` shows the name, the ID, the first characters, and the state of each virtual key, never the key.
- **No restart is needed.** A running KyGate accepts a new virtual key, stops accepting a revoked one, and uses a newly stored provider key within 2 seconds.
- **Another data directory:** add `--data-dir DIR` to any of these commands.

```text
kygate key create alice          # prints a new virtual key, once
kygate key list                  # names, IDs, first characters, state
kygate key revoke alice          # stops working within 2 seconds
kygate admin-token reset         # prints a new admin token, once
kygate provider add --name anthropic --provider anthropic    # stores a provider key, read from standard input
kygate provider list             # stored provider keys by name, and those from this terminal's environment
kygate provider remove anthropic
```

## The console

The console is the same web app in every profile, embedded in the binary. Details: [architecture.md §3.8](architecture.md#38-the-console).

Open `http://127.0.0.1:4001`, or the address shown in the start banner and in `kygate service status`, and paste the admin token. The browser keeps the token for that tab only, so a new tab asks for it again. Lost it? Run `kygate admin-token reset`.

| Page | Shows |
|---|---|
| **Overview** | Requests, money spent, money avoided by the cache, cache hit rate, blocked or refused requests, and errors. Cost per day or per hour. The semantic cache: hits served, and in shadow mode the hits it would have served and how often the answers differed. Top models, and the state of each provider key |
| **Requests** | Recent requests, as metadata: time, virtual key, model, outcome, cache result (`hit`, `semantic hit`, `miss`, `miss · would hit`, `bypass`), findings, tokens, cost or saving, duration. Select a row for its details, such as "served from the cache file" |
| **Usage** (near misses) | "Why the exact cache missed": for misses where the same key asked the same question again, what else had changed in the request, such as `system:date` (a date in the system prompt) or `temperature:value`, with the number of misses, keys, and their cost. A measurement for a future per-client normalization; it changes nothing. A request's detail shows its own near miss |
| **Protection** | The security report: tiles for values found, blocked and refused requests, alerts, injection attempts, and changed answers; a chart over time of requests with protected data, threats, refusals, and changed answers; the main sources, per virtual key. The Guard: whether the policy needs it, its state, the types it finds, its calls, failures, and latency, and what happens while it does not answer. Findings by data type and action, and the policy in force |
| **Usage** | Requests, tokens, money spent and avoided, and hit rate, by virtual key, model, provider key, and API |
| **Setup** | The **fleet**: every KyGate process (the Solo process, Team's control process and gateways, Helm's pods), up or silent, its version, requests in flight, its event spool (what waits, when it last delivered, a failing delivery), and what it sees of the Guard, the counters, the cache, and the providers. Then how to connect a client, the provider keys by name, the virtual keys, and the installation: version, cache, cache file, regenerate rule, semantic cache, Guard, event spool, retention |

- **Time range and refresh:** choose the last 24 hours, 7, 30, or 90 days at the top right, and select Refresh. A request appears about one second after it is served.
- It is served on its own port, apart from the model API, so the model API can be opened to applications without opening administration.
- In Solo it listens on the local machine only, unless configured otherwise, and asks for the admin token.
- The admin token opens it as the administrator: the **Administration** page manages teams, projects, virtual keys, provider keys, policies, and data handling, and every change is recorded. In the Enterprise edition, people also sign in with single sign-on, each limited by their role ([Single sign-on and roles](#single-sign-on-and-roles)).
- It reads its reports from SQLite in Solo, and PostgreSQL in Team and Enterprise.
- It never displays provider keys, real values, or unmasked text.
- **The fleet view** comes from heartbeats: every process writes its own view to the database every 10 seconds, in the background, never on the request path (`GET /api/v1/fleet`, for every role but team lead). A process not heard from for 30 seconds shows as silent: crashed, or cut off from the database. One that stops cleanly leaves the list; the control process forgets a silent one after a day. A heartbeat holds no key, no value, no text, and no provider address.

## The Guard

The Guard is KyGate's ML service, a Python program next to the gateway. It is optional: a policy that names only the types the fast detectors find (`SECRET`, `CREDIT_CARD`, `IBAN`, `EMAIL`, and dictionaries) needs no Guard. A policy that names another type, such as `PERSON`, needs it.

The Guard has two levels:

| Level | What it finds | How to get it |
|---|---|---|
| **Recognizers** | What a recognizers file lists: names, terms, patterns. Nothing else: a name that is not on the list is not found | `pip install ./guard`. Small, no model, no download, works offline |
| **Models** | One default pack, `prompt-injection` (302 MB): it detects prompt injection. Add-on packs add more, such as `personal-data` (327 MB): names, postal addresses, phone numbers, and 30 more types of personal data, in the 24 EU languages, including values it has never seen | `pip install "./guard[ml]"` (81 MB of software), then `kygate-guard models pull personal-data` (a 343 MB pack), which shows the model, its size, and its licenses, asks, and checks every file's SHA-256. Nothing is ever downloaded without this command |

**Install it** once, in its own Python environment (Python 3.10 or later):

```text
python -m venv guard/.venv
guard/.venv/Scripts/pip install ./guard        # on Linux: guard/.venv/bin/pip install ./guard
```

**Add ML detection** (optional), in the same environment:

```text
guard/.venv/Scripts/pip install "./guard[ml]"
guard/.venv/Scripts/kygate-guard models pull                 # the default pack, prompt-injection: shows the model, its size and license; asks; checks the SHA-256
guard/.venv/Scripts/kygate-guard models list                 # installed packs, which one is the default, and the add-ons
guard/.venv/Scripts/kygate-guard models pull personal-data   # an add-on, only if you want ML detection of personal data (327 MB)
```

**One default, the rest add-ons.** A new installation needs one pack: the default, `prompt-injection` ([Prompt injection](#prompt-injection) below). Every other pack is an add-on that you pull by name when you need it. The Guard loads every installed pack, so each one adds memory and start time: install only those your policy uses, and `models remove NAME` the others.

**The personal-data add-on:**

- **Its model** is `bardsai/eu-pii-anonimization-multilang-v3` (Apache-2.0), its INT8 ONNX file, pinned at one revision. It runs on the CPU with ONNX Runtime, without PyTorch. Its credits, including its training datasets, are in [guard/NOTICE](../guard/NOTICE).
- **Its data types**, as KyGate names them: `PERSON`, `ADDRESS`, `LOCATION`, `PHONE`, `EMAIL`, `DATE_OF_BIRTH`, `DATE_TIME`, `NATIONAL_ID`, `ID_DOCUMENT`, `BANK_ACCOUNT`, `CREDIT_CARD`, `CARD_SECURITY_CODE`, `ACCOUNT_ID`, `SECRET`, `ORGANIZATION`, `ORGANIZATION_ID`, `IP_ADDRESS`, `DEVICE_ID`, `URL`, `VEHICLE_ID`, `CONTACT_HANDLE`, `AMOUNT`, `JOB_TITLE`, `PERSON_ATTRIBUTE`, `DOCUMENT_REFERENCE`, `PROPER_NAME`, and the special categories `HEALTH_DATA`, `BIOMETRIC_DATA`, `ETHNIC_ORIGIN`, `POLITICAL_OPINION`, `RELIGION`, `SEXUAL_ORIENTATION`, `TRADE_UNION`, `CRIMINAL_RECORD`. The Guard returns only the types the policy names.
- **Measured** on the English and French corpus in `eval/detection` (55 synthetic texts, a regression gate rather than a certificate): names 14 of 15 in English and 15 of 15 in French; addresses, phone numbers, emails, and IBANs all found; no false alarm on 16 texts without personal data. **Known weakness:** a date of birth written as "14 July 1979" or "22/03/1985" is often taken for a plain date (1 of 2 found in each language).
- **Speed on a CPU:** loading and warming up take about 5 seconds, during which the Guard answers "not ready". Then about 1 ms per token: a short message takes 20 to 60 ms; a pasted document of 1,600 tokens takes about 1.5 s. The findings memo means each piece of text is inspected once per conversation. Keep `--guard-timeout` (default 5 s) above the time your longest messages take, or they are refused.
- **Several packs** can be installed; the Guard loads them all, and combines their findings. A pack of the same kind (an ONNX token classifier with BIO labels) is added with no code: write its manifest (`pack.json`: files with their address and SHA-256, license, label map) and run `kygate-guard models add PATH/pack.json`. `models remove NAME` deletes one.
- **Where packs live:** `~/.kygate/models`, or `--models DIR`, or `KYGATE_GUARD_MODELS`. An air-gapped installation copies the directory; the SHA-256 checks apply when the Guard loads it, and a pack that does not match is not used.

**Describe what it finds** in a recognizers file, JSON. A list of terms matches whole words, without case unless asked; a pattern is a regular expression:

```json
{"recognizers": [
  {"type": "PERSON", "terms": ["Alice Martin", "Hélène Dubois"]},
  {"type": "EMPLOYEE_ID", "pattern": "\\bEMP-[0-9]{6}\\b", "score": 0.99}
]}
```

**Turn the types on in the policy.** Installing the Guard or a model never changes the policy: you choose which types it acts on. The guided way, alert first, then mask:

```text
kygate policy enable --list                        # the types the Guard finds, their level, what the policy does with each
kygate policy enable PERSON ADDRESS PHONE          # action alert: counted in the console, nothing changed in prompts
kygate policy enable PERSON ADDRESS PHONE --action mask    # when the counts look right
kygate policy enable PERSON --action mask --require-model  # also require a model (detection: model)
```

The command shows the exact lines it will add or change and asks before writing; `--yes` skips the question. It keeps your comments and layout, keeps the previous file as `policy.yaml.bak`, refuses an edit that would not load, and warns when the policy will need a Guard that is not configured or not answering. It finds the Guard through `--guard`, `KYGATE_GUARD`, or the background service. A running KyGate uses the new policy within a few seconds.

Or edit the file by hand: name the types, with the action for each, and choose what happens when the Guard does not answer:

```yaml
data:
  on_guard_unavailable: block      # block (the default) | local_only | fast_detectors_only
  entities:
    PERSON:      { action: mask }
    EMPLOYEE_ID: { action: redact }
```

**Require a model where a list is not enough.** A list cannot find a name it has never seen, so a type can demand a model:

```yaml
data:
  entities:
    PERSON:      { action: mask, detection: model }   # without a model for PERSON, on_guard_unavailable applies
    EMPLOYEE_ID: { action: redact }                    # a list or a pattern is enough
```

`detection` is `any` by default: a list or a model. With `model`, a Guard that has no model for the type counts as unavailable for it, and `on_guard_unavailable` decides; KyGate never falls back to the list silently.

### Prompt injection

A prompt injection is text that tries to take over the model: "ignore your previous instructions", a jailbreak, a request to reveal the system prompt, or such orders hidden in a web page or a file that a tool returns. With the `prompt-injection` pack, the Guard scores each untrusted piece of text, and the policy decides.

```text
guard/.venv/Scripts/kygate-guard models pull                    # the default pack, prompt-injection, 302 MB; shows the model and its license; asks; checks the SHA-256
kygate policy enable PROMPT_INJECTION                            # action alert: counted in the console, the request goes on
kygate policy enable PROMPT_INJECTION --action block             # when the counts look right: refused with 403
```

Restart the Guard after a pull (`kygate service restart`, or restart `kygate-guard`) so that it loads the pack. In the policy:

```yaml
threats:
  prompt_injection: { action: block, min_score: 0.5, segments: [user, tool_result] }
```

| Setting | Meaning |
|---|---|
| `action` | `alert`: the request goes on, and is counted on the Protection page and among the alerts. `block`: refused with 403 and the header `X-KyGate-Blocked: PROMPT_INJECTION`, before it reaches the model. `allow`: not looked for |
| `min_score` | From which score, 0 to 1, the text counts as an injection. Default 0.5, the model's threshold. Higher means fewer false alarms and more misses |
| `segments` | Where to look: `user` (user turns) and `tool_result` (tool results). Default both. The system prompt is never scanned: it is yours |

- **A flagged request is never cached,** whatever the action, so an attack cannot plant an answer for others.
- **In monitor mode** a flagged request is recorded and nothing is blocked.
- **No detector, no request:** when the policy names `prompt_injection` and the Guard has no detector for it (the pack is not installed, or was removed), requests follow `on_guard_unavailable`, `block` by default. `kygate policy check --guard`, `kygate service status`, and the console say so. Removing the pack never removes the protection silently.
- **The default pack** is `patronus-studio/wolf-defender-prompt-injection-small` (Apache-2.0), its FP16 ONNX file, pinned at one revision. Its training data is not named on its card; its credits are in [guard/NOTICE](../guard/NOTICE). It can be removed (`models remove prompt-injection`) or replaced by another ONNX text classifier through a manifest; with several, the highest score counts.
- **Measured** on the English and French corpus in `eval/detection` (48 synthetic texts, a regression gate rather than a certificate): English 12 of 12 attacks caught, French 11 of 12; no false alarm on 24 harmless texts, including texts that talk about prompts and instructions. Its authors evaluate it in English and German, not French. A classifier lowers the risk; it does not remove it.
- **Speed on a CPU:** about 0.5 s per window of 512 tokens; a short message takes tens of milliseconds. Long text is read in windows, and the Guard's deadline grows with the text: `--guard-timeout` plus one second per 1,000 characters, up to 60 s.

**Run it with KyGate**, one of three ways:

| | How |
|---|---|
| In two terminals | `guard/.venv/Scripts/kygate-guard --listen 127.0.0.1:4002 --recognizers names.json`, then `kygate serve --guard 127.0.0.1:4002` |
| In the background | `kygate service install --guard-exe guard/.venv/Scripts/kygate-guard.exe --guard-args "--recognizers C:\\path\\names.json"`. The service runs and supervises both; `kygate service status` shows a Guard line. The Guard listens on `127.0.0.1:4002` unless `--guard-listen` says otherwise |
| In a container | `KYGATE_GUARD=guard:4002 docker compose --profile guard up -d` in `deploy/compose/solo`. For ML detection, build with `KYGATE_GUARD_EXTRAS=ml docker compose --profile guard build guard`, then pull the default pack once into the `kygate-models` volume: `docker compose --profile guard run --rm guard models pull` (add `personal-data` for that add-on) |

**What KyGate does with it:**

- **It sends prose only, for personal data.** System prompts, user turns, and assistant turns go to the Guard. Tool results and tool-call arguments get the fast detectors only, because names there raise many false alarms. For prompt injection, when the policy names it, user turns and tool results are sent too, marked as untrusted; the system prompt never is.
- **It asks once per piece of text.** The findings memo remembers what the Guard found in each segment, as positions and types, never text. A conversation's earlier turns are never sent again, and keep the masking they were first sent with.
- **It fails closed.** Every call has a deadline, 5 seconds by default (`--guard-timeout`, `KYGATE_GUARD_TIMEOUT`). A Guard that is down, still loading, too slow, or that answers with positions outside the text counts as unavailable, and `on_guard_unavailable` decides: `block` refuses the request (503); `local_only` lets it go to a local model only; `fast_detectors_only` sends it with the fast detectors' masking alone and flags it in the console.
- **It reconnects by itself.** A Guard started after KyGate, or restarted, is used again without restarting KyGate.

**Where to see it:**

- **A Guard that runs unused:** when the policy names none of the types the Guard finds, the start banner, `kygate service status`, `kygate policy check --guard`, and the console say "not used" and point to `kygate policy enable --list`.
- **Which level covers each type:** the start banner, `kygate service status`, and the console say, for each type the policy acts on, `list` or `model`, for example "PERSON: list only, a name that is not on the list is not found". `kygate policy check --guard ADDR` asks the Guard and warns about a type covered by a list alone, or not at all.

- **The start banner and `kygate service status`:** the Guard's address and state, and the types the policy needs it for.
- **The console's Protection page:** the Guard's state, the types it finds, its calls, failures, average latency, and last error, the findings memo, and what happens while it does not answer. With a threat rule: the injection attempts, and the rule itself. Overview and Setup show a warning when the policy needs a Guard that is not ready.
- **The Requests page:** a request refused because the Guard was unavailable shows the outcome `refused` and the reason.

**Security:** by default the gateway and the Guard talk over plain gRPC. Keep the Guard on the same machine, on the loopback address (the default), or in the same Compose network. For a Guard on another machine, use TLS or mutual TLS: the Guard's `--tls-*` options, and `KYGATE_GUARD_TLS_*` on the gateway ([Reference](#reference)).

## Output inspection

KyGate checks every answer before you get it: fresh or from the cache, streamed or not. It runs inside KyGate, with no Guard and no model, on the answer as the model wrote it, before real values are put back.

| Check | What it finds | Starter policy |
|---|---|---|
| `secrets` | API keys, tokens, and private keys the model writes (the same patterns as for prompts) | `remove` |
| `images` | An image that loads from a site the request did not name: Markdown `![..](..)`, reference images, and HTML `<img>`. A client loads images by itself, so an injected image can carry data out with no click | `remove` |
| `protected_urls` | An image or link whose address carries a masked value of the request, such as `https://x.example/?card=[CREDIT_CARD_1]`, written plainly or percent-encoded. Once the real value is put back, it would go to that site. Checked on every site, known or not, and in tool-call arguments | `remove` |
| `links` | A link to a site the request did not name: Markdown, HTML, or a bare address | `alert` |

```yaml
output:
  secrets:        { action: remove }
  images:         { action: remove }
  protected_urls: { action: remove }
  links:          { action: alert }
  allowed_domains: [docs.example.com, cdn.example.net]   # with their subdomains
```

- **Actions:** `alert` counts it on the Protection page and changes nothing. `remove` replaces the part with a short note, such as `[image removed by KyGate: it loads from an unknown site]`, and the rest of the answer arrives; the header `X-KyGate-Output: removed=OUTPUT_IMAGE` names what was removed (non-streamed answers). `block` refuses the answer: 403 with `X-KyGate-Blocked: OUTPUT_IMAGE`, or, for a stream already started, an error event that ends it; nothing of the part is sent. `allow` does not check.
- **Known sites:** those in `allowed_domains`, with their subdomains, and those that the system prompt or your own messages name. A site named only in a tool result does not count: an injection could plant it there. `localhost` and loopback addresses count as known.
- **Streams** are held back briefly while a link, an image, or a token may still be incomplete, up to 2 KB (16 KB for a private key block). A reference definition (`[r1]: https://...`) to an unknown site, or carrying protected data, is held until an image uses its label or the answer ends, up to 16 KB of text after it, because an image that uses it later must be removed too; reference definitions usually come at the end of an answer. A streamed answer comes out exactly as the same answer sent whole. One exception: a link or image longer than 2 KB cannot be held whole, so its start goes out, and when it turns out to be a finding the rest of it is dropped, which breaks it; nothing it carries reaches the reader.
- **Cost:** inspecting a streamed answer of 16 KB that arrives a few characters at a time takes about 0.2 s of CPU in all (2026-11-19, `BenchmarkOutputStream16KBTokens`), about 0.3% of one core over the minute the model takes to write it.
- **The cache:** an answer that was changed or blocked is never cached. An answer with alerts only is cached, and inspected again on every hit, so a policy change applies to stored answers too.
- **Upgrades:** a policy file without an `output:` section inspects nothing. To turn it on, copy the section above into your policy; KyGate reloads it within a few seconds. The start banner shows the line `Output checks`.
- **In monitor mode** every finding is recorded and nothing is changed.
- **Where to see it:** the console's Protection page (the tile "Answers changed", the findings `OUTPUT_SECRET`, `OUTPUT_IMAGE`, `OUTPUT_PROTECTED_URL`, `OUTPUT_LINK`, and the rules in force), and the metric `kygate_output_findings_total`.
- **Limits:** it checks the answer's text and tool-call arguments, not reasoning blocks. It does not see a value the policy left unmasked (with `alert` or `allow`) inside an address, a value encoded otherwise (base64, for example), or images in CSS or other HTML than `<img>`. It is a filter for the common leak paths, not a guarantee.

## Answer quality

KyGate saves money by answering from caches and, later, by routing to cheaper models. Answer quality (OB-4) shows whether those answers are as good: applications say when an answer was bad, and the console compares answers served from the caches with those from the model.

**Rating an answer.** Every answer carries `X-KyGate-Request-Id`. The application sends, with the virtual key that made the request:

```text
curl -X POST http://127.0.0.1:4000/kygate/v1/feedback \
  -H "Authorization: Bearer kg-..." \
  -d '{"request_id": "REQUEST-ID", "rating": "bad", "reason": "outdated"}'
```

- `rating`: `bad` or `good`. `reason` (optional): `wrong`, `outdated`, `incomplete`, `unsafe`, `off_topic`, or `other`. Free text is refused: a comment could carry personal data. The answer is 202.
- A second rating of the same answer by the same key replaces the first. A rating counts only when the key that sends it made the request; others are kept and never counted.
- Ratings are kept with the events and deleted with them (`audit.retention_days`). The metric `kygate_feedback_total` counts them by rating.

**In the console:** the Usage page's **Answer quality** card shows the ratings and the share of bad ones for answers from the model, from the exact cache, from the semantic cache (a bad rating there is a likely false hit), and for answers the router would have sent to a cheaper model; the reasons given; and the semantic cache's shadow comparisons (how often a shadow hit differed from the real answer). `GET /api/v1/quality` returns the same figures.

**Not here yet:** comparing a cheaper model's answer with the requested one on a sample of requests costs provider calls; it comes with router enforcement.

## Single sign-on and roles

**Enterprise edition.** People sign in to the console with your identity provider (OpenID Connect: Entra ID, Google, Okta, Keycloak…) and act within one of five roles: admin, security, finance, team lead (their team only), and viewer. Groups map to roles; sessions are server-side, with CSRF checks on every change; every sign-in and change is recorded. The Community edition opens the console and the admin API with the admin token, as the admin. To learn more, see [For companies](../README.md#for-companies-kygate-enterprise).

## SCIM provisioning

**Enterprise edition.** Your identity provider (Okta, Entra ID, or another SCIM 2.0 provider) adds, changes, and removes console users and their groups at `/scim/v2` on the console's port, with a token of its own. A person who is deactivated loses access at once. To learn more, see [For companies](../README.md#for-companies-kygate-enterprise).

## Teams, projects, and the admin API

**The hierarchy.** An installation has one organization. Under it, teams; under a team (or directly under the organization), projects; in a project (or in none), virtual keys.

```text
kygate team create finance
kygate project create ledger --team finance
kygate key create ledger-app --project ledger      # shown once
kygate key move old-key --project ledger           # --project "" takes a key out
kygate team list | project list | key list
```

A running KyGate applies a change within a few seconds. A team with projects, or a project with active keys, cannot be deleted.

**Policies per level.** The organization's policy stays `policy.yaml`. Next to it, a `policies/` folder may hold a file per team, project, or key, containing only what that level changes:

```yaml
# policies/team-finance.yaml
data:
  entities:
    EMAIL: { action: block }     # stricter than the organization's: applies
budgets:
  monthly_usd: { soft: 400, hard: 500 }   # the team's own total
```

- Files are named `team-NAME.yaml`, `project-NAME.yaml`, or `key-NAME.yaml`. A request uses the organization's policy merged with its key's team, project, and key files.
- **Security settings: the strictest wins.** The mode, each data type's action and detection, `on_guard_unavailable`, `unreadable_content`, `embeddings`, each threat, each output check. A team can mask what the organization allows, never allow what the organization masks. Known sites for output inspection can only be narrowed.
- **Cache, routing, rate limits: the most specific wins.**
- **Budgets:** a team file's `monthly_usd` and `daily_usd` are the team's own total, a project's the project's, a key's the key's; `per_key` and `at_soft` follow the most specific level.
- **`audit`** is the organization's only.
- An invalid edit keeps that file's last good version in force, as for `policy.yaml`. `kygate policy show --key NAME` prints a key's effective policy and the files it merges.

**The admin API** writes on the console's port: with the admin token (`Authorization: Bearer kgadmin-...`) for scripts, or from a signed-in console session, within its role (see Single sign-on and roles).

| Endpoint | What it does |
|---|---|
| `GET /api/v1/admin/hierarchy` | Teams, projects, and keys (never a key itself) |
| `POST /api/v1/admin/teams` `{"name"}`, `DELETE /api/v1/admin/teams/{name}` | Teams |
| `POST /api/v1/admin/projects` `{"name","team"}`, `DELETE /api/v1/admin/projects/{name}` | Projects |
| `POST /api/v1/admin/keys` `{"name","project"}` | A virtual key, returned once |
| `POST /api/v1/admin/keys/{name}/revoke`, `PUT /api/v1/admin/keys/{name}/project` `{"project"}` | Revoke or move a key |
| `POST`/`DELETE /api/v1/admin/keys/{name}/user-secret`, `PUT /api/v1/admin/keys/{name}/require-user` `{"required"}` | A key's signing secret for user tokens (returned once) and whether it requires one |
| `POST /api/v1/users/pseudonym` `{"id"}` | The pseudonym reports use for a person (any signed-in role); the ID is not stored |
| `POST /api/v1/admin/providers` `{"name","provider","base_url","region","key"}`, `DELETE /api/v1/admin/providers/{name}` | Provider keys: sealed under the master key, never returned |
| `PUT /api/v1/admin/providers/{name}/region` `{"region"}` | A stored connection's region; empty clears it (admin and security) |
| `GET /api/v1/admin/data` | Retention periods, pinned regions, and each connection's region (admin and security) |
| `POST /api/v1/admin/purge/events`, `POST /api/v1/admin/purge/cache` | Purges ([Data handling](#purges)); admin and security |
| `GET /api/v1/admin/audit`, `POST /api/v1/admin/audit/verify` | Enterprise. The audit ledger's head, what waits to be sealed, each SIEM destination's state; a full verification, recorded in the trail ([Audit integrity](#audit-integrity-and-siem-export)); admin and security |
| `GET /api/v1/admin/policies`, `GET`/`PUT`/`DELETE /api/v1/admin/policies/{id}` | Policy files: `org`, `team-NAME`, `project-NAME`, `key-NAME`. A file that would not load is refused (422); the previous version is kept as `.bak`; a deleted file is kept as `.bak` |
| `GET /api/v1/admin/log` | The audit trail of administration: who (a person, the admin token, or the command line), what, when, including sign-ins and refused sign-ins. Never a secret. Admin and security |
| `GET /api/v1/admin/users`, `PUT /api/v1/admin/users/{email}` `{"role","team"}`, `DELETE /api/v1/admin/users/{email}` | Enterprise. People who sign in (admin) |

**Reports:** the Usage page adds "By team" and "By project" when the hierarchy is used, and the budgets card lists teams and projects with their own budgets.

## People behind an application key

An application that serves many people with one virtual key can name the person behind each request, so that usage, budgets, and rate limits count per person (AC-3). It sends a signed **user token** in the `X-KyGate-User` header. KyGate checks it, keeps only a pseudonym of the person, and never forwards the header to a provider.

### Two kinds of user token

| | Application token | Identity-provider token |
|---|---|---|
| Who signs it | The application, with its key's signing secret | The company's OpenID Connect provider (the one single sign-on uses, or another) |
| Algorithm | HS256 | RS256, ES256, and the others the provider publishes |
| Set up | `kygate key user-secret NAME` (or the console's Virtual keys card, or `POST /api/v1/admin/keys/{name}/user-secret`): the secret is shown once, stored sealed, and replaces any earlier one at once | `identity.user_tokens` in the organization's policy (below) |
| Claims | `sub`: the person; `exp`: at most 24 hours ahead | `iss`, an allowed `aud`, `exp`, and the person in `sub` or `email` |

The token's header decides which check applies, and each check accepts only its own algorithms: an application token cannot pass as the provider's, nor the reverse. `alg: none` and other HMAC algorithms are refused. An application signs its own token with any JWT library, for example in Python with PyJWT: `jwt.encode({"sub": "ana@example.com", "exp": now + 3600}, SECRET, algorithm="HS256")`. For tests and scripts, `kygate key user-token NAME --user ID [--ttl 1h]` prints one.

```yaml
identity:                       # the organization's policy only
  user_tokens:
    issuer: https://login.example.com/realms/corp
    audiences: [kygate-apps]    # the audience the provider puts in tokens meant for KyGate
    user_claim: email           # sub (default) or email; an email marked unverified is refused
```

KyGate reads the provider's published keys in the background when the policy names it, and again when the provider rotates them. Until it can, such tokens are refused (503, `user_token_unverifiable`): a token is never accepted unchecked.

### What KyGate does with it

- **A pseudonym, never the ID.** Events, counters, reports, and the audit trail hold `u_` and 20 hex characters: a keyed hash of the person's ID under the organization's key. An email address is compared in lower case, so the same person has one pseudonym from an application and from the provider. To find someone, type their ID in the Usage page's "By user" card, or call `POST /api/v1/users/pseudonym` `{"id"}`; the ID is not stored or recorded.
- **Reports by person:** the Usage page's "By user" card, `GET /api/v1/breakdown?by=user`, and `GET /api/v1/requests?user=u_...`.
- **Budgets per person**, across every key they use: `budgets.per_user`, monthly and daily, soft and hard, as for keys (`X-KyGate-Budget: hard:user:daily`).
- **Rate limits per person**, across keys: `rate_limits.per_user`, requests and tokens per minute.
- **Purge by person:** `kygate purge events --user ID` (or a pseudonym), the API's `"user"`, or the console's Person field ([Purges](#purges)). The trail records "(by ID)", never the ID.

```yaml
budgets:
  per_user: { monthly_usd: { soft: 15, hard: 20 } }
rate_limits:
  per_user: { requests_per_minute: 20 }
```

### Requiring a person

By default a request without a token is accepted, and counts to its key only, so nothing changes when you upgrade. `kygate key require-user NAME` (or the console, or `PUT /api/v1/admin/keys/{name}/require-user` `{"required": true}`) makes a key refuse requests without a valid token (401, `invalid_user_token`); `--off` undoes it. An invalid, expired, or forged token is always refused (401), whatever the setting.

## Coalescing and provider cache markers

**Coalescing.** When identical requests arrive while the first is still waiting for its model, they wait for it and share its answer: one call, one cost. Each caller still gets its own values back (two users whose card numbers differ share the call, because the model saw the same masked request). A follower of a stream gets what was produced so far, then follows live. If the first caller disconnects, the call goes on for the others. Followers show `X-KyGate-Cache: coalesced`, and their cost counts as avoided. Only requests the exact cache could store are shared. It is always on, within one KyGate process.

**Provider cache markers.** Anthropic bills a repeated prompt beginning at about a tenth of the input price, but only up to a cache marker (`cache_control`) placed in the request; writing that beginning costs about a quarter more, once. Most clients place none. KyGate adds them to Anthropic requests that carry none of their own:

```yaml
cache:
  provider_markers: conversation   # off | instructions | conversation
```

- `instructions`: at the end of the tools and of the system prompt, which every request with the same instructions repeats.
- `conversation` (the starter policy): those, and at the end of the latest message, so that the next turn of a conversation reads all of it from Anthropic's cache. A one-off request pays the write premium on its uncached part once.
- Only after a prefix of about 1,024 tokens: a short prompt is left alone. Reasoning blocks are never marked. A request with its own markers is left exactly as it is. OpenAI caches long prefixes by itself.
- The header `X-KyGate-Prompt-Cache: marked system,conversation` says where. The Usage page's cached-input and cache-write tokens show the effect.
- A policy file that does not name `provider_markers` adds none.

## Budgets and rate limits

```yaml
budgets:
  org:     { monthly_usd: { soft: 80, hard: 100 }, daily_usd: { hard: 10 } }
  per_key: { monthly_usd: { soft: 20, hard: 30 } }     # every virtual key
  per_user: { monthly_usd: { hard: 20 } }               # each person named by a user token
  keys:
    build-bot: { daily_usd: { soft: 1, hard: 2 } }      # a named key: its own budget instead
  at_soft: cheaper_tier   # cheaper_tier | alert
  at_hard: reject
  on_counters_unavailable: last_known   # last_known | refuse: when the shared counters are down (Team)
rate_limits:
  per_key: { requests_per_minute: 60, tokens_per_minute: 200000 }
  per_user: { requests_per_minute: 20 }                 # each person, across keys
  keys:
    build-bot: { requests_per_minute: 10 }
```

- **Budgets** are in US dollars per calendar month and per day, in UTC. Each request is checked against the organization's budget, its team's and project's, its key's (a named key's own, or `per_key`), and, when a user token names a person, that person's (`per_user`, [People behind a key](#people-behind-an-application-key)). The starter policy has a commented example; with no `budgets:` section there is no budget.
- **Reserve, then settle.** Before a call, KyGate reserves an estimate: the input size plus the largest answer the request allows (`max_tokens`; 1,024 when the request sets none), priced at the model it names. After the answer it replaces the estimate with the real cost. So a request with a large `max_tokens` can be refused near a limit even if its real answer would have been short.
- **Past a hard limit:** refused with 429, the header `X-KyGate-Budget: hard:key:daily` (which budget), and `Retry-After` until the budget resets. Outcome `over_budget` in the console.
- **Past a soft limit,** with `at_soft: cheaper_tier`: every new conversation goes one tier down within its provider (Opus → Sonnet → Haiku, GPT-5 → o4-mini …). The headers say it: `X-KyGate-Route: budget; claude-sonnet-5-5 instead of claude-opus-5-5 (standard tier): past a soft limit`, `X-KyGate-Budget: soft:key:monthly`, and `X-KyGate-Model` names the model that answered. A conversation under way keeps its model; one that started cheaper stays cheaper; a request with reasoning settings stays. Such an answer is not stored in the cache for the requested model. With `at_soft: alert`, the request is only flagged.
- **Cache hits cost nothing:** they are never counted, and a key past its budget is still answered from the cache.
- **Rate limits** per key: requests per minute, counted for every request, and tokens per minute, estimated before the call and corrected with the real count. Over a limit: 429 with `Retry-After`, outcome `rate_limited`. A key can burst up to a minute's worth.
- **Monitor mode** (`mode: monitor`) counts and records, and refuses or changes nothing.
- **Where to see it:** the start banner's `Budgets` line; the Usage page's budgets card (spend this month and today against each limit, reservations in flight included); `GET /api/v1/budgets`; each request's outcome and route.
- **After a restart** the spend is rebuilt from the recorded events, so limits carry on. With several gateways (Team), the counters live in Valkey and are shared.
- **When the shared counters are down** (Team): with `on_counters_unavailable: last_known` (the default), each gateway goes on from the last figures it saw, adding its own spend, so limits still hold approximately; the event's budget says `approximate` and the request is flagged; `kygate_budget_counters_degraded` counts it. When Valkey answers again, the spend counted meanwhile is added to it. During an outage a gateway tries Valkey again every 2 seconds, so requests do not wait on the network. With `refuse`, a request that has a hard limit in any of its budgets is refused (503, `budget_unavailable`, `X-KyGate-Budget: unavailable`) until the counters are back; a request with no hard limit goes on. Solo keeps its counters in memory, so this never happens there.

## The router (shadow mode)

The router answers one question for each request: is there a cheaper model of the same provider that could answer it well? In shadow mode it only records its answer: every request still goes to the model it names.

```yaml
routing:
  mode: shadow                      # off | shadow
  tiers: [economy, standard, frontier]   # optional: the tiers it may use; all when absent
```

- **The rules are cautious:** one tier down at most (frontier → standard → economy), within the same provider, and only when a conversation starts. The conversation keeps that decision. Only short plain prompts qualify: a last message up to about 400 tokens, a prompt up to about 2,000, an answer allowed up to 4,096 tokens, and no code, tools, images or files, structured output, or extended reasoning.
- **The target** is the cheapest chat model of that provider in the tier below, from the model catalog (tiers are in `internal/router/catalog.yaml`, or your own catalog file). Policies never name a model.
- **What it records:** the header `X-KyGate-Route: shadow; would use claude-sonnet-5-5 (standard tier)` or `shadow; stays`; in the event, the model it would use, the reason, and the saving: the request's real tokens priced at that model.
- **Where to see it:** the Usage page's "Routing (shadow mode)" card (requests decided, the share that would move, the estimated saving, and every requested → cheaper pair with its reason), and each request's detail.
- **The starter policy** turns shadow mode on. A policy without a `routing:` section has no router. `mode: auto` runs in shadow mode, with a warning, until enforcement ships.
- **Limits:** the rules see the shape of a request, not its meaning, so a short but hard question ("prove that…") is counted as one that would move. Enforcement comes only after the shadow figures and a quality check.

## Data handling: retention, regions, and purges

What KyGate keeps, for how long, where requests may go, and how to delete data before its time (GV-4). The console's Administration page has a **Data handling** card for all of it; the admin and security roles can use it.

### Retention

The organization's policy sets a period for each kind of data, under `audit:`. The control process (or the only process, in Solo) applies them once an hour and records what it deleted in the administration trail.

| Setting | Starter policy | Without the setting | What it deletes |
|---|---|---|---|
| `audit.retention_days` | `90` | `90` | Usage and audit events |
| `audit.payload_retention_days` | `30` | the same as `retention_days` | Captured masked payloads (`capture_payloads: masked`); the events stay, so reports stay whole. Never longer than the events |
| `audit.admin_retention_days` | `365` | kept | The administration trail |

Expired console sessions are always deleted. Cache entries have their own lifetime (`cache.exact.ttl`, `cache.semantic.ttl`). An upgrade deletes nothing it did not delete before: a policy file without the new settings keeps payloads as long as events and keeps the trail.

### Region pinning

A policy can send requests only to provider connections in named regions:

```yaml
data:
  regions: [eu]
```

- **Each connection has a region**, where its endpoint processes data: `KYGATE_REGION_<NAME>` for any connection (`KYGATE_REGION_OPENAI=us`, `KYGATE_REGION_OPENAI_TEAM=eu`, `KYGATE_REGION_LOCAL_OLLAMA=on-prem`), or for a stored one `kygate provider add --region eu`, `kygate provider region NAME eu`, the console, or `PUT /api/v1/admin/providers/{name}/region`. The environment variable wins over a stored region. Region names are letters, digits, and dashes, in lower case.
- **A connection without a region is never used** while the policy pins regions: an unknown place is not an allowed one.
- **A request with no allowed connection is refused** (403, `X-KyGate-Blocked: REGION`, code `region_pinned`), before the cache and before any call. Security fails closed.
- **The semantic cache's embeddings** go only to a connection in an allowed region; otherwise the request skips the semantic cache.
- **Levels:** a team, project, or key file can only narrow the regions. Two levels with no region in common leave none, and the request is refused.
- **Monitor mode** sends the request anyway and flags it in the console.
- The start banner shows each connection's region, and says when one is not used.

### Purges

| What | Command | Admin API |
|---|---|---|
| Events, by key, team, project, and time | `kygate purge events [--key K] [--team T] [--project P] [--from DATE] [--to DATE] [--yes]` | `POST /api/v1/admin/purge/events` `{"key","team","project","from","to","dry_run"}` |
| Captured payloads only, the events stay | the same with `--payloads-only` | the same with `"payloads_only": true` |
| Cache entries of one key | `kygate purge cache --key K [--yes]` | `POST /api/v1/admin/purge/cache` `{"key"}` |
| Cache entries with one tag | `kygate purge cache --tag T [--yes]` | `{"tag"}` |
| Every cache entry | `kygate purge cache --all [--yes]` | `{"all": true}` |

- **Every purge says what it will delete and asks first.** The command line counts the events and asks (`--yes` skips the question); the API counts with `"dry_run": true`; the console counts, then asks. A purge that names nothing is refused.
- **Each purge is recorded** in the administration trail, with what it selected and how much it deleted, never a value.
- **Events:** dates are `YYYY-MM-DD` (UTC) or RFC 3339; `from` is included, `to` is not. Deleted events leave the reports. Budget counters keep their current values, but a restart rebuilds them from the events, so a purge of this month's events lowers the spend they count.
- **Cache tags:** an application names tags with the request header `X-KyGate-Cache-Tags: docs-v3, faq` (up to 8 tags of 1 to 64 letters, digits, and `. _ : / -`). The answer it stores carries them; a later request that hits that answer does not add its own. A request with an invalid tag is served but not cached, so that no answer is stored without the tags its application expects to purge by. Every stored answer is also labelled with the key that stored it.
- **The cache store never holds a tag or a key ID in clear:** labels are keyed hashes under the organization's key.
- **Every process applies a cache purge.** The process that purges deletes the entries from the cache store and empties its own memory tier; the purge is recorded in the database, and every other process (the gateways in Team, or a running KyGate when the command line purged) applies it within a few seconds: it empties its memory and purges the store again after the writes it had queued, so an answer written just before the purge does not survive it. The memory tiers refill from the store.
- **Team:** `kygate purge cache` needs `--cache-url` (or `KYGATE_CACHE_URL`) and `--database-url`; in Compose, `docker compose exec control kygate purge cache --tag T`.

## Audit integrity and SIEM export

**Every edition** records each request and each administration action in the audit trail, as metadata only, and each gateway signs the events it writes.

**Enterprise edition:** a tamper-evident ledger seals every event and administration record into a chain of keyed digests; `kygate audit verify` and the console tell recorded retention and purges apart from changes made behind KyGate's back. SIEM export sends events, administration records, and the ledger's head to Splunk, Elastic, syslog, or OpenTelemetry. To learn more, see [For companies](../README.md#for-companies-kygate-enterprise).

## The master key in a key-management service

**Enterprise edition.** The master key is kept wrapped by HashiCorp Vault or OpenBao, AWS KMS, Google Cloud KMS, or Azure Key Vault, and unwrapped once at start, so it is never stored in clear. The Community edition keeps it in `<data-dir>/master.key`, readable only by the account that runs KyGate, or takes it from `KYGATE_MASTER_KEY`. To learn more, see [For companies](../README.md#for-companies-kygate-enterprise).

## The Team profile

Several people, one address, no single gateway to lose. The files are in [deploy/compose/team](../deploy/compose/team): two gateways behind Caddy, one control process, PostgreSQL, and two Valkey instances, one for counters and one for the cache. The Guard is optional, as in Solo.

```text
cd deploy/compose/team
cp .env.example .env          # set KYGATE_MASTER_KEY (openssl rand -base64 32) and POSTGRES_PASSWORD
docker compose up -d
docker compose logs control   # the first start prints a virtual key and an admin token, once
```

Clients use `http://localhost:4000/v1` (OpenAI SDKs) or `http://localhost:4000` (Anthropic SDKs); the console is `http://localhost:4001`. Both ports are published on the loopback interface only: put your own TLS front in place before opening them to a network. Provider keys come from `.env` (or your shell), or are stored, sealed, from the console's Administration page or `kygate provider add --database-url ...`.

**What runs where**

| Process | Role | Serves | Keeps |
|---|---|---|---|
| `control` | `--role=control` | The console, the admin API, `/metrics` (port 4001) | First-start setup, retention, and (Enterprise) the audit ledger, `sso.yaml`, and `siem.yaml` in its volume |
| `gateway1`, `gateway2` | `--role=gateway` | The model API (port 4000 inside the network) | Its own event spool |
| `caddy` | | One address for clients (port 4000), round robin over the gateways that answer `/healthz`, response buffering off | |
| `postgres` | | Configuration, key hashes, sealed provider keys, users and sessions, usage and audit events, the administration trail, the semantic cache (sealed) | |
| `valkey-counters` | | Budget and rate-limit counters: `noeviction`, append-only file | |
| `valkey-cache` | | The exact cache: `allkeys-lru`, `KYGATE_CACHE_MEMORY` (1 GB by default), nothing written to disk | |

A gateway started before the control process waits up to two minutes for the installation to exist. Every process must have the same master key (`KYGATE_MASTER_KEY`, or the same `KYGATE_MASTER_KEY_WRAPPED` with access to its key-management service): it seals provider keys and cache entries. A process with a different one refuses to start.

**What the gateways share, and how fast**

- **Keys, teams, projects, provider keys:** in PostgreSQL. A change made from the console or a command reaches every gateway within 2 seconds.
- **Policies:** in PostgreSQL, with every earlier version kept. A change through the admin API, the console, or `kygate policy enable --database-url ...` reaches every gateway within a few seconds. An invalid policy is refused before it is stored. An installation that kept `policy.yaml` and `policies/` in the control volume has them imported once, at its first start with this version.
- **Exact cache:** an answer stored by one gateway is served by the other about 100 ms later (each gateway writes in the background). Each gateway also keeps its own in-memory tier in front.
- **Budgets:** one set of counters for all gateways, so a budget is spent once, not once per gateway. At start, the first process of each month and day rebuilds the counters from the events; the others find them already built.
- **Rate limits:** one counter per key and calendar minute, shared. With a limit of 4 per minute, the two gateways together let 4 requests through. Unlike Solo's token bucket, a new minute starts fresh, so a key can use its whole limit at the end of one minute and again at the start of the next.
- **Not shared:** the Guard's findings memo stays in each gateway (a turn may be inspected once per gateway), and each gateway coalesces only its own identical requests.

**When a part is down**

| Down | What happens |
|---|---|
| One gateway | Caddy sends every request to the other. Open streams on the stopped gateway get 30 seconds to finish |
| The control process | The gateways keep serving with what they last read. The console, the admin API, and retention stop until it is back |
| PostgreSQL | The gateways keep serving from memory; events wait in each gateway's spool and are delivered when it is back. A process cannot start without it |
| Valkey (counters) | Rate limits fall back to each gateway's own token buckets, so the total can reach the limit times the number of gateways; `kygate_rate_limit_local_fallbacks` counts it. Budgets go on from each gateway's last known figures, approximately, and catch up when Valkey is back; with `budgets.on_counters_unavailable: refuse`, requests with a hard limit are refused until then ([Budgets](#budgets-and-rate-limits)) |
| Valkey (cache) | Each gateway uses its in-memory tier only |

**Commands against a Team installation:** every command takes `--database-url` (or `KYGATE_DATABASE_URL`), for example `kygate key create ci --database-url postgres://...` or `kygate team create finance --database-url ...`. Commands that need the master key (`provider add`, `sso secret`) also need `KYGATE_MASTER_KEY`. In Compose: `docker compose exec control kygate key create ci`.

### Moving from Solo to Team

```text
kygate store copy --to postgres://kygate:PASSWORD@HOST:5432/kygate --data-dir ~/.kygate
```

1. Stop the Solo KyGate (`kygate service stop`, or Ctrl+C).
2. Run `store copy` against an empty PostgreSQL database. It copies the organization, the admin token's hash, keys (as hashes) with their teams and projects, people, the sealed provider keys and SSO secret, every event, and the administration trail, and records the copy in that trail. It refuses a database that already holds an installation.
3. Use the same master key in Team: put the contents of `~/.kygate/master.key` in `KYGATE_MASTER_KEY`. Without it, stored provider keys cannot be opened.
4. Copy `policy.yaml`, the `policies/` folder, `catalog.yaml`, and (Enterprise) `sso.yaml` into the control volume (`docker compose cp`), then start the stack: the control process imports the policies into PostgreSQL at its first start.

Sessions are not copied (people sign in again), and neither are the caches: they refill.

## Kubernetes with Helm

The chart in [deploy/helm/kygate](../deploy/helm/kygate) runs the Enterprise layout: an autoscaled pool of gateways, one control process, and an optional autoscaled Guard pool, on your PostgreSQL and Valkey.

| Part | Kubernetes objects | Notes |
|---|---|---|
| Gateways | Deployment, Service, HorizontalPodAutoscaler (CPU), PodDisruptionBudget, optional Ingress | Spread over zones, then nodes. Rolling updates never take a pod away before its replacement is ready; a stopping pod gives open streams 45 seconds and delivers its event spool |
| Control | Deployment (one replica, replaced, never doubled), Service, optional Ingress, ConfigMap for `sso.yaml` and `siem.yaml` (Enterprise) | It seals the audit ledger and applies retention, so there is always exactly one |
| Guard (`guard.enabled`) | Deployment, headless Service, HorizontalPodAutoscaler, PodDisruptionBudget, a Secret of certificates | Gateways spread each call over every Guard pod, over mutual TLS |
| `dev.enabled` | PostgreSQL StatefulSet, two Valkey Deployments, generated secrets | For trying KyGate only: single instances, no backups |

Pods run as non-root users with a read-only root filesystem, no capabilities, and the runtime's seccomp profile. Probes: `/healthz` and `/readyz` on the gateways, `/healthz` on the console's port; a startup probe gives a starting pod time to wait for PostgreSQL (up to two minutes) and for the control process.

**Try it** (any cluster; kind works):

```text
docker build -t kygate:0.1.0 . && docker build -t kygate-guard:0.1.0 guard/   # then load or push them
kubectl create namespace kygate
kubectl -n kygate create secret generic kygate-providers --from-literal=OPENAI_API_KEY=sk-...
helm install kygate deploy/helm/kygate -n kygate --set dev.enabled=true --set providers.envFromSecrets={kygate-providers}
kubectl -n kygate logs deploy/kygate-control | grep -E 'Virtual key|Admin token'   # shown once
```

**Production:**

1. **Stores:** a Secret with `KYGATE_DATABASE_URL` (PostgreSQL), `KYGATE_COUNTERS_URL` (Valkey, `noeviction`, persistent), and `KYGATE_CACHE_URL` (another Valkey, `allkeys-lru`); `stores.existingSecret` names it.
2. **Master key:** every pod needs the same one. In the Community edition, store 32 random bytes, base64, as `KYGATE_MASTER_KEY` in a Secret (`masterKey.existingSecret`, `masterKey.secretKey: KYGATE_MASTER_KEY`). In the Enterprise edition, make it wrapped, once, from a workstation that can reach the key-management service: `kygate master-key new --kms URI` prints a line to store as `KYGATE_MASTER_KEY_WRAPPED` in a Secret (`masterKey.existingSecret`, `masterKey.secretKey: KYGATE_MASTER_KEY_WRAPPED`). The pods unwrap it with their own identity: set `extraEnv.KYGATE_KMS` to how they log in, for example `hashivault://kygate?auth=kubernetes&role=kygate` with `kms.vaultAddr`, or a cloud's workload identity through `serviceAccount.annotations`. `KYGATE_KMS` at start overrides the login recorded in the wrapped key; it must name the same key.
3. **Provider keys:** Secrets in `providers.envFromSecrets`, or stored from the console.
4. **The Guard:** `guard.enabled: true`. Mutual TLS is on by default, with certificates the chart generates once and keeps across upgrades; or `guard.tls.existingSecret` names a Secret with `ca.crt`, `tls.crt`, `tls.key` (the Guard's, for the service's DNS names) and `client.crt`, `client.key` (the gateways'), from cert-manager for example. Recognizers go in `guard.recognizers` (JSON text); model packs come from a volume where `kygate-guard models pull` put them (`guard.models.existingClaim`). Nothing is downloaded at start.
5. **Autoscaling** uses CPU and needs metrics-server.
6. **Ingress:** `gateway.ingress` with buffering off for streams (the nginx annotations are the defaults); the console on its own host through `control.ingress`, or kept internal.

**Policies live in PostgreSQL**, as with Compose: the admin API, the console, and `kygate policy enable --database-url ...` write them; every gateway reloads within seconds.

## Traces and metrics

**Metrics.** `http://127.0.0.1:4001/metrics` serves Prometheus metrics on the console port: requests, tokens, costs, cache figures, findings by type, and more. It asks for no token, and carries no prompt text and no key.

**Traces.** KyGate sends OpenTelemetry traces when an OTLP endpoint is set, and nothing otherwise. It uses the standard OpenTelemetry variables:

```text
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318      # an OTLP/HTTP collector: Jaeger, Grafana Tempo, an OpenTelemetry Collector
OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer ...    # if the collector needs a token
OTEL_TRACES_SAMPLER=parentbased_traceidratio           # optional: keep a share of the traces
OTEL_TRACES_SAMPLER_ARG=0.1
OTEL_SERVICE_NAME=kygate                                # the default
```

- **What a trace holds:** one span per request, named after the endpoint (`kygate /v1/messages`), with one child span per stage (`kygate.ingress`, `kygate.identity`, `kygate.inspect`, `kygate.enforce`, `kygate.cache`, `kygate.semantic`, `kygate.upstream`, `kygate.respond`, `kygate.after`). The request span carries the request ID, the API, the models requested and served, the provider key's name, the outcome, the cache and semantic-cache results, token counts, cost and cost avoided, and finding types with their actions and counts.
- **What it never holds:** prompt or answer text, a detected value, a provider key, or a virtual key.
- **Linked traces:** a request that carries a W3C `traceparent` header continues the caller's trace. KyGate never forwards trace headers to a provider.
- **The start banner** says where traces go, or that they are off.
- **In the background:** `kygate service install` keeps the `OTEL_*` settings of the terminal it runs in, except `OTEL_EXPORTER_OTLP_HEADERS`, which can hold a token and is never written to disk.

## Reference

| Setting | Default | Meaning |
|---|---|---|
| `--data-dir`, `KYGATE_DATA_DIR` | `~/.kygate` | The data directory: `kygate.db` (configuration, key hashes, events), `master.key`, `policy.yaml`, `spool/` (events waiting for delivery), `cache.db` (both caches). With the background service also `service.json`, and on Windows `kygate.log`, `service.log`, and `guard.log` |
| `--listen`, `KYGATE_LISTEN` | `127.0.0.1:4000` | Model API |
| `--console-listen`, `KYGATE_CONSOLE_LISTEN` | `127.0.0.1:4001` | Console, reporting API, `/metrics` |
| `--policy`, `KYGATE_POLICY` | `<data-dir>/policy.yaml` | Policy file, reloaded within seconds of a change. An invalid edit keeps the last good version in force |
| `--max-concurrency` | `1024` | Requests in flight before new ones are refused |
| `KYGATE_REGION_<NAME>` | none | The region of the connection NAME (`OPENAI`, `OPENAI_TEAM`, `LOCAL_OLLAMA` …), for `data.regions` ([Region pinning](#region-pinning)) |
| `--role`, `KYGATE_ROLE` | `all` | `all`: everything in one process (Solo). `gateway`: the model API only. `control`: the console, the admin API, first-start setup, and retention ([The Team profile](#the-team-profile)) |
| `--database-url`, `KYGATE_DATABASE_URL` | none: SQLite in the data directory | PostgreSQL, `postgres://user:password@host:5432/db`, for configuration, events, and the semantic cache (Team). Every command takes it |
| `--counters-url`, `KYGATE_COUNTERS_URL` | none: in the process | Valkey for budget and rate counters, shared by the gateways. Run it with `noeviction` and append-only persistence |
| `--cache-url`, `KYGATE_CACHE_URL` | none: `cache.db` | Valkey for the exact cache, shared by the gateways. A separate instance, with `allkeys-lru` |
| `KYGATE_CATALOG` | `<data-dir>/catalog.yaml` if present | Model catalog overrides: prices and new models |
| `KYGATE_MASTER_KEY` | `<data-dir>/master.key` | 32 bytes, base64, instead of the key file |
| `KYGATE_KMS` | none | Enterprise. At the first start, wrap the new master key with this key-management service, such as `hashivault://kygate` or `awskms://alias/kygate`; no plain key is written |
| `KYGATE_MASTER_KEY_WRAPPED` | `<data-dir>/master.key.wrapped` | Enterprise. The wrapped master key (that file's content), unwrapped once at start |
| `--guard`, `KYGATE_GUARD` | none | Address of the Guard, such as `127.0.0.1:4002` ([The Guard](#the-guard)) |
| `--guard-timeout`, `KYGATE_GUARD_TIMEOUT` | `5s` | Deadline of one call to the Guard; a slower answer counts as the Guard being unavailable |
| `KYGATE_GUARD_TLS_CA`, `KYGATE_GUARD_TLS_CERT`, `KYGATE_GUARD_TLS_KEY`, `KYGATE_GUARD_TLS_SERVER_NAME` | plain gRPC | TLS to the Guard with this CA, and mutual TLS with this client certificate and key. Calls are spread over every address the Guard's name resolves to |
| `OTEL_EXPORTER_OTLP_ENDPOINT` and the other `OTEL_*` variables | Traces off | Sends OpenTelemetry traces to an OTLP/HTTP collector ([Traces and metrics](#traces-and-metrics)) |
| `OPENAI_API_KEY[_<SUFFIX>]`, `OPENAI_BASE_URL` | | OpenAI keys; an OpenAI-compatible service through the base URL |
| `ANTHROPIC_API_KEY[_<SUFFIX>]`, `ANTHROPIC_BASE_URL` | | Anthropic keys |
| `KYGATE_LOCAL_<NAME>`, `KYGATE_LOCAL_<NAME>_KEY` | | A local OpenAI-compatible model server, such as Ollama or vLLM. The connection is named `local-<name>` in lower case, such as `local-ollama` |

Solo runs every role in one process (`--role=all`). The Team profile runs the gateway and control roles apart ([The Team profile](#the-team-profile)).

| Command | Does |
|---|---|
| `kygate serve` | Starts KyGate in the terminal. The first start sets up the data directory |
| `kygate store copy --to postgres://... [--data-dir D]` | Copies a Solo installation (SQLite) into an empty PostgreSQL database: keys, teams, projects, users, sealed provider keys, events, and the administration trail ([Moving from Solo](#moving-from-solo-to-team)) |
| `kygate service install [--data-dir D] [--listen A] [--console-listen A] [--policy F] [--name N]` | Runs KyGate in the background: started now and at every logon, restarted after a crash |
| `kygate service install ... --guard-exe PATH [--guard-args ARGS] [--guard-listen A]` | The same, with the Guard run and supervised next to the gateway |
| `kygate service status` | Says whether the background KyGate is running and ready, and where its console and logs are |
| `kygate service start`, `stop`, `restart` | Starts, stops gracefully, or restarts the background KyGate |
| `kygate service uninstall` | Stops the background KyGate and removes it from the system. The data is kept |
| `kygate key create NAME [--project P]`, `key list`, `key revoke NAME\|ID`, `key move NAME --project P` | Virtual keys. A running KyGate picks up changes within 2 seconds |
| `kygate key user-secret NAME [--remove]`, `key require-user NAME [--off]`, `key user-token NAME --user ID [--ttl 1h]` | User tokens ([People behind a key](#people-behind-an-application-key)) |
| `kygate team create\|list\|delete`, `kygate project create NAME [--team T]\|list\|delete` | The hierarchy |
| `kygate policy show --key NAME` | A key's effective policy and the files it merges |
| `kygate user add EMAIL --role ROLE [--team T]`, `user list`, `user remove EMAIL` | Enterprise. People who sign in to the console |
| `kygate sso secret` | Enterprise. Stores the single sign-on client secret, sealed under the master key |
| `kygate scim token`, `scim revoke`, `scim status` | Enterprise. SCIM provisioning: a new token, shown once (SCIM on); off; what was provisioned ([SCIM provisioning](#scim-provisioning)) |
| `kygate provider add --name N --provider openai\|anthropic\|local [--base-url U] [--region R]` | Stores a provider key, encrypted, read from standard input |
| `kygate provider list`, `provider remove NAME` | Stored provider keys, with their regions |
| `kygate provider region NAME [REGION]` | A stored connection's region; no REGION clears it ([Region pinning](#region-pinning)) |
| `kygate purge events ...`, `kygate purge cache ...` | Purges, after showing what they delete ([Purges](#purges)) |
| `kygate audit verify [--json]`, `kygate audit status` | Enterprise. The tamper-evident audit ledger ([Audit integrity](#audit-integrity-and-siem-export)) |
| `kygate master-key new --kms URI`, `master-key status`, `master-key wrap --kms URI [--remove-plain]`, `master-key rewrap --kms URI` | Enterprise. The master key in Vault or a cloud KMS ([Master key in a KMS](#the-master-key-in-a-key-management-service)) |
| `kygate admin-token reset` | Replaces the console admin token and prints the new one, once |
| `kygate policy check [FILE] [--guard ADDR]` | Validates a policy file. With `--guard`, also says which level finds each data type the policy needs the Guard for, or that the Guard is not used |
| `kygate policy enable TYPE... [--action A] [--require-model] [--yes]` | Turns data types on in the policy, after showing the lines and asking; `alert` by default. Keeps a `.bak` |
| `kygate policy enable PROMPT_INJECTION [--action alert\|block\|allow] [--yes]` | Turns prompt-injection detection on under `threats:`; `alert` by default. Needs the Guard and its `prompt-injection` pack |
| `kygate policy enable --list [--guard ADDR]` | The types the Guard finds, their level, and what the policy does with each; threats first, then data types |
| `kygate version` | Prints the version |

The management commands work on an existing installation and take `--data-dir`. They never create a data directory: `kygate serve` or `kygate service install` does.

| Model API endpoint | Family |
|---|---|
| `POST /v1/chat/completions` | OpenAI, streaming and tool calls |
| `POST /v1/embeddings` | OpenAI (never masked; see `data.embeddings` in the policy) |
| `GET /v1/models` | Either, by the client's headers |
| `POST /v1/messages` | Anthropic, streaming, tool use, thinking blocks passed through |
| `POST /v1/messages/count_tokens` | Anthropic, masked, not cached |
| `GET /healthz`, `GET /readyz` | Health |
| `POST /kygate/v1/feedback` | KyGate's own: an application's rating of an answer, by its `X-KyGate-Request-Id` ([Answer quality](#answer-quality)) |

| Response header | Meaning |
|---|---|
| `X-KyGate-Request-Id` | The ID of the request, as the console shows it |
| `X-KyGate-Cache` | `hit`, `miss`, `coalesced` (an identical request was in flight and this one shared its answer), `bypass` (the cache was not used for this request), or `off` |
| `X-KyGate-Prompt-Cache` | When KyGate added Anthropic cache markers: `marked` and where, such as `marked system,conversation` |
| `X-KyGate-Cache-Kind` | On a hit: `exact` or `semantic` |
| `X-KyGate-Model` | The model that answered |
| `X-KyGate-Connection` | The name of the provider key that served the request, never the key |
| `X-KyGate-Masked` | How many values were masked |
| `X-KyGate-Blocked` | On a refusal: the data types, threats (`PROMPT_INJECTION`), output checks (`OUTPUT_IMAGE` …), or `REGION` (no connection in the policy's regions) that caused it |
| `X-KyGate-Budget` | When a budget's soft or hard limit is passed: which one, such as `soft:key:monthly` or `hard:org:daily` |
| `Retry-After` | On a 429 for a rate limit or a hard budget limit: seconds to wait |
| `X-KyGate-Route` | Past a soft budget limit: `budget; MODEL instead of REQUESTED (TIER tier): past a soft limit`, and the request went to that model. In routing shadow mode: `shadow; would use MODEL (TIER tier)` or `shadow; stays`. The request still went to the model it names |
| `X-KyGate-Output` | On a non-streamed answer that output inspection changed: `removed=` and the checks, such as `removed=OUTPUT_IMAGE` |
| `X-KyGate-Mode` | `monitor`, when the policy only records what it would have done |

A request names the person behind it with `X-KyGate-User: <signed token>` ([People behind a key](#people-behind-an-application-key)); KyGate never forwards it. A client skips the cache for one request with `X-KyGate-Cache: no-cache` or `Cache-Control: no-cache`, keeps an entry to its own key with `X-KyGate-Cache: scope=key`, and tags the answer it stores for a later purge with `X-KyGate-Cache-Tags: docs-v3, faq` ([Purges](#purges)). The response body is never changed by the cache, so a hit is visible only in the headers and in the console.

### Cache settings

| Cache setting, in the policy file | Default | Meaning |
|---|---|---|
| `cache.exact.enabled` | `true` | The exact cache: the identical request is answered from the stored answer |
| `cache.exact.scope` | `org` | `org`: shared by every virtual key. `key`: each virtual key has its own entries |
| `cache.exact.ttl` | `30d` in the starter policy; `24h` when the policy file does not name it | How long a stored answer is served, counted from when it was stored |
| `cache.exact.repeat_window` | `0s` (off) in the starter policy; `30s` when the policy file does not name it | The same key repeating the same request within this window gets a fresh, paid answer, as a "regenerate" click expects |
| `cache.exact.max_size_mb` | `256` | Memory budget of the in-process cache |
| `cache.exact.persist` | `true` in the starter policy; `false` when the policy file does not name it | Also keeps entries in `<data-dir>/cache.db`, so they survive a restart |
| `cache.exact.max_disk_mb` | `1024` | Size limit of the cache file, both caches together. The least recently used exact entries are removed first |
| `cache.semantic.enabled` | `false` | The semantic cache: a look-alike last message from the same key reuses the stored answer |
| `cache.semantic.mode` | `shadow` | `shadow` records the hits it would serve and changes nothing; `serve` answers from the cache |
| `cache.semantic.embeddings.connection`, `.model` | `local-ollama`, `nomic-embed-text` in the starter policy | A provider connection that serves OpenAI-compatible embeddings, by name, and its model. `KYGATE_LOCAL_OLLAMA=http://localhost:11434/v1` creates the connection `local-ollama`: a connection from `KYGATE_LOCAL_<NAME>` is named `local-<name>`, as the start banner shows |
| `cache.semantic.min_similarity` | `0.95` | Cosine similarity a candidate needs before the hard checks. `0.80` at the lowest |
| `cache.semantic.ttl` | `7d` | How long a semantic entry is served |
| `cache.semantic.max_prompt_tokens` | `256` | Longer last messages use the exact cache only |
| `cache.semantic.max_entries` | `20000` | Semantic entries kept; the oldest go first |
| `cache.semantic.scope` | `key` | The only scope for now. Wider scopes would need a second-check model |
| `cache.provider_markers` | `conversation` in the starter policy; `off` when the policy file does not name it | Anthropic prompt-cache markers for requests that carry none: `off`, `instructions` (system prompt and tools), `conversation` (also the latest message) |

A policy file written by an earlier version keeps its behavior: the settings it does not name take the defaults in the second column, not those of the starter policy. To get the new behavior, add them: `ttl: 30d`, `repeat_window: 0s`, `persist: true`. Check an edit with `kygate policy check`.

What to know about the cache on disk ([architecture.md §3.4](architecture.md#34-cache-rules), [§4.5](architecture.md#45-cache-internals)):

- **Entries on disk have the same form as in memory:** placeholder text, compressed with zstd, then encrypted. The file works the same on Windows and Linux.
- **Nothing is loaded at start.** An entry is read from the file the first time it is asked for, then kept in memory.
- **Editing a comment, a TTL, a size, or the audit settings keeps every stored answer.** Changing the mode, a data rule, or the exact-cache scope starts a new cache, because those can change the masked request. The earlier entries stay until they expire or are evicted.
- **A long TTL serves old answers.** A pinned model name is safe. A model alias keeps receiving the answer of the model it pointed to when the entry was stored.
- **The file belongs to its installation.** Its entries are encrypted under the installation's master key, so a cache file copied to another installation holds only misses there.
- **To empty the cache,** stop KyGate and delete `cache.db`. A damaged file never stops KyGate from starting.

What to know about the semantic cache ([architecture.md §3.4](architecture.md#34-cache-rules)):

- **To turn it on:** run an embeddings model on an OpenAI-compatible server, for example `ollama pull nomic-embed-text`; start KyGate with `KYGATE_LOCAL_OLLAMA=http://localhost:11434/v1`; set `cache.semantic.enabled: true` in the policy. The start banner then says `shadow mode`, or `waiting` when no connection has that name.
- **It is narrow on purpose.** Only the same virtual key, only a short plain-text last message in which nothing was detected, with no tools, and with an identical conversation before it.
- **It matches wording, not synonyms.** Two messages match when they differ only in case, punctuation, word order, filler words, and plurals. Different numbers, names, negations, code identifiers, or language never match. Synonyms need the Guard's second check.
- **Start in shadow mode.** The console's Overview shows the hits it would have served, what they would have saved, and how often they differed from the real answer. Switch to `serve` when that rate is low enough for you. Raising `min_similarity` makes it stricter.
- **Each eligible miss calls the embeddings model once,** and each shadow hit once more, to compare answers. With a local Ollama this costs nothing but a few milliseconds. With a paid embeddings API it costs a little, and the masked text goes to that provider.
- **If the embeddings model is down,** the request is served without the semantic cache, and the event records the skip.

## Profiles

| | Solo | Team | Enterprise |
|---|---|---|---|
| Users | 1 to a few dozen | Up to a few thousand | Tens of thousands to 100,000 and more |
| Packaging | One binary, run in a terminal or in the background (`kygate service`), or one container; the Guard container is optional | Docker Compose or a small Kubernetes install | Helm chart across several availability zones |
| Processes | 1, or 2 with the Guard | 2 gateways, 2 Guards, PostgreSQL, Valkey | Autoscaled gateway and Guard pools, separate control service and workers, clustered stores |
| Storage | Embedded: SQLite, exact and semantic cache in memory and on disk | PostgreSQL, Valkey | The same as Team, replicated; the master key in a key-management service with Enterprise |
| Availability | Single process | Survives the loss of one instance | No single point of failure |
| Provider keys | Environment variables or the command line | The same, or the console | The console or the admin API |
| Console | A local page served by the same process, behind the admin token | Served by the control role; single sign-on and roles with Enterprise | The same, with the fleet view; audit integrity with Enterprise |
| Files | `deploy/compose/solo/` | `deploy/compose/team/` | `deploy/helm/kygate/` |

Enterprise adds operations and governance, not new kinds of store: Kubernetes, high availability, autoscaling, a key-management service, single sign-on with provisioning, and a tamper-evident audit trail exported to your SIEM. For a message bus, an analytics warehouse, a vector database, or several regions, see [Scaling further](#scaling-further-possible-not-a-goal).

Solo works without Python: the fast detectors, the exact cache, the semantic cache, and rule-based routing need only the Go binary. The semantic cache takes its embeddings from any OpenAI-compatible endpoint, such as a local Ollama.

## Data stores per profile

| Data | Solo | Team | Enterprise |
|---|---|---|---|
| Value map | Gateway memory, one request | Same | Same |
| Master key | Local key file or environment variable | Secret file or environment variable | Secret, or a key-management service or Vault with Enterprise |
| Configuration, key hashes, policies, encrypted provider credentials | SQLite | PostgreSQL | PostgreSQL, replicated |
| Counters for limits and budgets | In process | Valkey | Valkey: replicated, persistent, no eviction |
| Exact cache | In process, and a local SQLite file of its own (`cache.db`) when the policy keeps it on disk | Valkey | Valkey cluster with LRU eviction |
| Findings memo | In process | In each gateway | Valkey cluster with LRU eviction |
| Semantic index | In `cache.db` beside the exact cache, sealed; in process when the policy keeps the cache in memory | PostgreSQL, sealed entries compared in each gateway | Same as Team |
| Usage and audit events | SQLite | PostgreSQL | PostgreSQL, bounded by the retention period; longer history through SIEM export (Enterprise) |
| Event transport | In process, with disk spool | Disk spool, direct write | Same as Team |

Counters and caches use separate Valkey instances: a counter must never be evicted, and a cache entry must be. For the same reason the Solo exact cache has its own file, apart from the configuration and event database.

The master key protects the stored provider keys and the cache entries. On a single machine a key file protects a copied database, a copied cache file, or a backup. It does not protect against someone who controls that machine.

## Guard placement

- **Small installations:** the Guard runs next to the gateway; they talk over a Unix socket.
- **Large installations:** a separate autoscaled pool reached over mutually authenticated TLS. Kubernetes balances gRPC per connection, so the gateway must balance per call, with a headless service and client-side balancing or with a service mesh.

**Sizing rule:** cores ≈ peak inspections per second × CPU seconds per inspection ÷ target utilization. *Estimate:* at 30 ms per inspection and 60% utilization, 1,000 requests per second need about 50 cores. *Measured* (2026-11-19, a laptop CPU, the default prompt-injection pack in FP16, short prompts): about 100 ms of core time per inspection; one Guard process saturated near 70 per second. Start `kygate-guard --workers` at about the number of cores, add Guard instances (Helm autoscales them), and size from your own run of `kyload` ([eval/load](../eval/load/README.md)).

## How each part scales

| Part | Scales by | Signal |
|---|---|---|
| Gateway | Stateless instances behind a load balancer | Open streams and CPU |
| Guard | Instances; GPU nodes for large models | Queue wait time and latency |
| Shared store | Replication; cluster mode | Memory and evictions |
| Semantic index | Sealed entries in the database, compared in each gateway, per scope | Entries per scope and lookup latency |
| Relational database | One primary with replicas; holds configuration and events, bounded by retention | Disk size and write latency |
| Event delivery | Disk spool in each gateway, written directly to the database | Spool size and delivery lag |

## Behavior when something fails

| What is down | What KyGate does |
|---|---|
| Guard | Fast detectors still run. Requests that need ML detection follow `on_guard_unavailable`: refuse (default), local-only, or fast detectors only. In Solo, the service starts a Guard it runs again after a crash, and KyGate reconnects by itself |
| Shared store, counters | Approximate per-instance rate limits. Budgets go on from each gateway's last known figures and catch up afterwards; `budgets.on_counters_unavailable: refuse` refuses requests with a hard limit instead |
| Shared store, cache | In-process cache only |
| Cache file (Solo) | In-process cache only. KyGate still starts and serves; entries are not kept across a restart until the file works again |
| Semantic index, or the embeddings model (Solo) | Semantic cache skipped; the exact cache keeps working |
| Control service or database | Gateways serve from the last good snapshot |
| Event delivery (the database) | Events queue in the disk spool; a full spool follows the audit policy |
| A SIEM destination (Enterprise) | Its records wait in the ledger; it is retried with a growing delay and catches up from its cursor. Requests are never slowed |
| One provider | Retry with backoff, then the fallback chain, before the first byte. A mid-stream failure ends the stream with an error event |
| One provider key is rate-limited or rejected | The next key for the same provider is tried, before the first byte. With no key left, the provider's error is returned. The console shows the state of the key |
| Local model pool full | A short queue, then overflow to an external tier. Restricted data waits or is refused |

## Latency targets

| Path | Added time, p95 (*target*) |
|---|---|
| Gateway stages without ML | 5 ms |
| Guard inspection of the new turn | 50 ms |
| Semantic lookup | 40 ms |
| Total before first token when a model is called | Under 100 ms |
| Exact-cache hit, to first byte | 15 ms |

## Operating notes

- **Draining:** an instance being replaced stops taking new requests and lets its open streams finish.
- **Proxies:** response buffering must be off at every proxy in front of the gateway. Write deadlines are set per stream.
- **Regions:** region pinning keeps requests on provider connections in the allowed regions. To run KyGate itself in several regions, see [Scaling further](#scaling-further-possible-not-a-goal).
- **Telemetry:** OpenTelemetry traces and metrics, a Prometheus endpoint, never prompt or answer text. Both ship in the binary ([Traces and metrics](#traces-and-metrics)).
- **Bypass prevention:** provider keys must exist only in KyGate, and network egress rules must block direct access to providers.
- **Load testing your installation:** `kyload` ([eval/load](../eval/load/README.md)) sends load through KyGate to a stand-in provider, so nothing reaches a real provider or costs money, and checks every answer. Give the test KyGate a data directory of its own. Measured in Solo: KyGate adds about 1.5 ms at p95 to a model call; an open stream costs a gateway about 128 KB.
- **Connections to providers:** KyGate keeps up to 1,024 idle connections per provider host, as many as `--max-concurrency` lets calls be in flight, so steady load reuses them. A local model server that speaks HTTP/1.1 sees one connection per call in flight.

## Scaling further: possible, not a goal

KyGate runs on SQLite (Solo), or on PostgreSQL and Valkey (Team and Enterprise). That is the whole list of stores the project builds, tests, and supports. Very large fleets sometimes add more infrastructure. KyGate leaves room for it: every store sits behind a Go interface, so a new back end is a driver and changes nothing on the request path. Building one is not a project goal, and none is planned until load tests or a real installation show the need ([architecture.md §5.7](architecture.md#57-scaling-further-possible-not-a-goal)).

| If you need | What KyGate does instead | How to go further |
|---|---|---|
| **Several regions** (data residency, latency) | Region pinning keeps requests on provider connections in the allowed regions (`data.regions`, [Data handling](#data-handling-retention-regions-and-purges)) | Run one independent installation per region: its own database, caches, keys, and budgets. Budgets are not shared between installations. Combine reports from their SIEM exports |
| **An event bus** (NATS JetStream, Kafka) | Each gateway writes events to its own disk spool first, then to the database; nothing is lost while the database is away | Write a driver for event delivery; the spool stays the first step |
| **An analytics store** (ClickHouse) or a long archive | PostgreSQL keeps events for the retention period you set | Point a SIEM export (Enterprise: webhook, syslog, OpenTelemetry logs) at your warehouse: it receives every event and administration record, with no new driver |
| **A vector database** (Qdrant, pgvector) | The semantic cache keeps sealed entries in the database and compares them in each gateway, per scope | A driver behind the semantic store interface. It needs its own design, because entries are sealed with your organization's key |
