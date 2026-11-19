# Security

KyGate is a security product: it decides what data may leave a company on its way to AI models. This file summarizes its security model. The full version is in [docs/architecture.md §6](docs/architecture.md#6-security-architecture).

## Reporting a vulnerability

Please report vulnerabilities privately, through the repository host's private vulnerability reporting or by email to ayadi.oubaidallah@gmail.com, rather than in a public issue. Do not include real personal data or credentials in a report.

## Data handling rules

1. Real sensitive values exist only in gateway memory, for the life of one request, and in transit to the Guard.
2. Everything stored (cache entries, the findings memo, the semantic index, events) holds masked text or metadata, is encrypted, carries the organization ID, and expires.
3. Traffic between components is mutually authenticated and encrypted whenever it crosses a host boundary.
4. Provider credentials are decrypted only in gateway memory. No API returns them and the console never displays them.

## Provider keys and the console

KyGate holds real provider keys, and shows its reports in a console. Both follow the same rules in every profile.

- **Where a provider key is kept.** A key supplied through an environment variable stays in gateway memory and is not written to disk. A key added from the command line or the console is stored encrypted under the installation's master key. A key never goes into a policy file.
- **The master key.** A local file that only the account running KyGate can read, or an environment variable, in Solo; a secret file or an environment variable in Team; a key-management service or Vault with KyGate Enterprise. On a single machine a key file protects a copied database, a copied cache file, or a backup. It does not protect against someone who controls that machine.
- **Virtual keys and the admin token.** They are created by KyGate, shown once, and stored as hashes, so they cannot be read back from the data directory. A lost one is replaced: `kygate key create`, `kygate admin-token reset`. A revoked key and a replaced token stop working within seconds, with no restart.
- **Running in the background.** `kygate service` runs KyGate under the user's own account, with no administrator rights. It never copies a provider key from the environment to disk: the user stores the key encrypted with `kygate provider add`. The file it writes, `service.json`, holds addresses and paths, no secret. The first start happens in the terminal, so the virtual key and the admin token are never written to a log file.
- **The Guard.** It returns findings, never enforces, and keeps no state. By default the gateway talks to it over plain gRPC, so it must stay on the same machine, on the loopback address (the default), or in the same Compose network; a remote Guard needs TLS or mutual TLS (`KYGATE_GUARD_TLS_*`). When a policy needs the Guard and it does not answer, or answers with positions that do not fit the text, the request follows `on_guard_unavailable`, which refuses it by default.
- **The console.** It is served on its own port, apart from the model API. In Solo it listens on the local machine only, unless configured otherwise. It asks for an admin token created at the first start; with single sign-on (KyGate Enterprise), people sign in (OIDC, PKCE) and act within their role, and the admin token remains for scripts and as a recorded break-glass sign-in. Sessions are server-side, in an HttpOnly, SameSite=Strict cookie, and every change from a browser carries the session's CSRF value. A team lead sees and changes their team only; a role limited to some policy sections cannot change the others. Every change and every sign-in is recorded in the audit trail of administration. The Prometheus endpoint `/metrics` on the same port asks for no token; it carries counts and timings, never text or keys.
- **What the console shows.** Metadata only: types and counts, never values. It never displays a provider key. Prompt and answer text appears only when the policy captures masked payloads, and then only in masked form.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Sensitive data is sent to an external provider | Layered detection (patterns, checksums, dictionaries, ML); an action per data type; restricted data kept local; fail-closed |
| A detector misses a value | Several detector layers; the level that covers each type (list or model) shown everywhere, and a policy can require a model; scan of answers before shared-cache admission; everything stored is encrypted and expires; monitor-mode reports to tune the policy |
| One user receives another user's data through the cache | Entries hold placeholders, not values; an exact entry needs the identical request; semantic sharing is scoped, verified, and scanned on admission; requests that depend on hidden state are not cached |
| Cache poisoning | Prompts flagged for injection are never admitted; verification with hard checks; admission only after several users; purge and feedback; TTL |
| The Solo cache file is copied, or read by someone else on the machine | Entries hold placeholders, not values, and are encrypted under a per-organization key derived from the master key; prompts are stored only as keyed fingerprints; entries expire, and the file has a size limit. The key file sits in the same data directory, so this protects a copied file or a backup, not a machine that someone else controls. A value that a detector missed stays in the file until its entry expires, so a long TTL lengthens that exposure; a policy can keep the cache in memory only |
| Prompt injection, direct or through tool results and documents | A classifier on untrusted segments; output inspection for exfiltration patterns, such as links and images that point to unknown domains |
| Detection evasion with encodings or look-alike characters | Unicode normalization; bounded decoding of encoded blobs before scanning |
| A virtual key is stolen | Keys are hashed at rest, scoped, expiring, and rate-limited; revocation within seconds; optional network allow-list |
| A provider credential is stolen | Envelope encryption under the master key; plaintext only in gateway memory; clients never hold provider keys; keys stay out of policy files, logs, and the console |
| The console or the admin API is reached by the wrong person | Its own port, apart from the model API; local-only by default in Solo; an admin token from the first start, shown once and stored as a hash; single sign-on and roles with KyGate Enterprise; it shows metadata, never values or provider keys |
| Logs and telemetry become the leak | Metadata-only events; optional masked capture; no text in traces or metrics. Traces are off until an endpoint is set, carry no text, value, or key (a test asserts it), and trace headers are never forwarded to a provider |
| Stored embeddings reveal prompts | Embeddings are computed on masked text; the index is encrypted, filtered per organization, and expiring |
| A component or dependency is compromised | Mutual TLS and least privilege between roles; models pinned by digest; dependencies checked for known vulnerabilities in CI; signed releases with a bill of materials are planned |
| Users bypass the gateway | Provider keys exist only in KyGate; network egress rules, described in the deployment guide |
| Overload and abuse | Size limits, concurrency caps, per-key limits, a deadline on every internal call |

## Known limits

- **KyGate sees only the traffic that passes through it.** Enforcement needs provider keys that exist nowhere else and network rules that block direct access to providers.
- **A list finds only what is on it.** With the Guard's base level, a name that is not in the recognizers file is not found. The optional model level finds unlisted values, but it is statistical too: the personal-data pack missed one name in fifteen in English on our corpus, and half of the dates of birth. KyGate shows which level covers each data type, and a policy can require a model (`detection: model`) so that a list never stands in for one silently.
- **Detection is statistical.** It misses some values and flags some harmless text. Both rates are measured per data type and per language, and published.
- **Output inspection covers the common leak paths, not all of them.** It removes images from unknown sites, addresses that carry a masked value, and secrets, in the answer's text and tool-call arguments. It does not see a value the policy left unmasked inside an address, a value encoded another way (base64, for example), or images in CSS.
- **A determined insider can evade it,** by encoding, paraphrasing, or sending a screenshot. KyGate reduces accidental leaks and enforces policy. It is not a barrier against deliberate exfiltration.
- **Masking does not make every provider acceptable for every kind of data.** The policy must still decide which data classes may leave the company at all.
