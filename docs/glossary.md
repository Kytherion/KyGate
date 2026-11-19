# Glossary

Terms as they are used in [architecture.md](architecture.md).

| Term | Meaning |
|---|---|
| **Admin token** | A secret created at the first start and shown once (`kgadmin-...`). It opens the console and the admin API; with single sign-on it remains for scripts and as a recorded break-glass sign-in. It is stored as a hash; `kygate admin-token reset` replaces a lost one |
| **Admission** | The decision to store an answer in a cache. Shared semantic-cache admission requires a clean output scan and no injection flag on the prompt |
| **Affinity** | Keeping a conversation on the same model and, where possible, the same provider credential and region, so provider prompt caches keep working |
| **Background service** | KyGate kept running without a terminal by `kygate service install`: a scheduled task of the user on Windows, a systemd user unit on Linux. It starts at logon and restarts after a crash |
| **Break-glass sign-in** | Enterprise. Opening the console with the admin token when single sign-on is configured: it signs in as an administrator and is recorded in the audit trail |
| **Cache version** | A digest of the policy settings that can change a masked request: mode, data rules, exact-cache scope. Part of every fingerprint, so other policy edits keep the cache |
| **Coalescing** | Identical requests that arrive while the first is still running share one model call |
| **Console** | The web page that shows usage, cost, savings, and findings. The admin token opens it as the administrator, with the Administration page; in the Enterprise edition people also sign in with single sign-on, each within their role |
| **Context fingerprint** | The request fingerprint without the last user message. Used to filter semantic-cache candidates |
| **Control plane** | The control service, its relational database, and the console. Holds configuration; not on the request path |
| **Data plane** | The gateway and the Guard. Stateless; scales horizontally |
| **Exact cache** | A response cache keyed by the request fingerprint. Safe to share across an organization. In Solo it is held in memory and in a local file, so it survives a restart |
| **Effective policy** | A request's policy: the organization's `policy.yaml` merged with its key's team, project, and key files (`policies/`). The strictest wins for security settings, the most specific for cache, routing, and rate limits |
| **Fail closed / fail open** | Security stages refuse or keep the request local when they cannot do their work (fail closed). Optimization stages are skipped (fail open) |
| **Fast detectors** | In-process detectors in the gateway: patterns, checksums, dictionaries. No ML |
| **Finding** | What a detector reports: segment, data type, start and end offsets (UTF-8 bytes, end exclusive), score, and detector name and version |
| **Findings memo** | Findings stored per segment under a keyed hash and reused for the life of a conversation. Gives stable masking and avoids rescanning |
| **Frontier model** | The most capable and most expensive model tier |
| **Guard** | The Python ML service. Detects personal data and injection, computes embeddings, reranks. Called only by the gateway, over gRPC. Two levels: recognizers by default, model packs on request |
| **Hard checks** | Rules that reject a semantic-cache candidate when numbers, negations, code identifiers, or the language differ. Without the Guard they also require the same content words, and the same word order around words such as "to" and "than" |
| **Master key** | One key per installation that protects the stored provider keys and the per-organization keys. A local file in Solo, a key-management service or Vault in Enterprise |
| **Model catalog** | One record per model target: API family, capabilities, context size, prices, tier, hosting, region, data-retention terms. The only place that names models |
| **Model pack** | A set of ML models for one task of the Guard, such as personal data, described by a manifest (`pack.json`): files with pinned addresses and SHA-256, license, languages, and a label map to KyGate's data types. Installed only with `kygate-guard models pull` or `add`, which show its models, size, and licenses; checked again at every load |
| **Monitor mode / shadow mode** | A mode in which a stage records the decision it would have taken and changes nothing |
| **Native mode** | A request goes to the same API family it arrived in. Unknown fields pass through unchanged |
| **Output inspection** | Checks on every answer before the caller gets it: secrets, images from unknown sites, addresses that carry a masked value, links to unknown sites. Each check has its own action: `alert`, `remove`, `block`, or `allow`. A site is *known* when the policy lists it or the request's system prompt or user turns name it |
| **Placeholder** | A typed, numbered stand-in for a masked value, such as `[PERSON_1]` or `[EMAIL_2]` |
| **Provider connection** | A provider or a local model server, a name, and a credential. Supplied through environment variables, the command line, or the admin API and console |
| **Provider cache marker** | A `cache_control` mark in an Anthropic request, up to which the provider caches the prompt. KyGate adds them when the request has none (`cache.provider_markers`) |
| **Provider prompt cache** | A provider's discount on the repeated, byte-identical beginning of a conversation |
| **Regenerate rule** | `cache.exact.repeat_window`: the same key repeating a request within the window gets a fresh answer. Off (`0s`) in the starter policy |
| **Recognizer** | A pattern or a list of terms that the Guard finds as a data type, set in a JSON file. The Guard's base level: it finds only what is listed. A policy can require a model instead (`detection: model`) |
| **Role** | Enterprise. What a person signed in to the console may see and change: admin, security, finance, team_lead (their team only), or viewer |
| **Rate limit** | A limit per virtual key on requests or tokens per minute (`rate_limits:`). Over it: 429 with `Retry-After` |
| **Rehydration** | Putting the real values back in place of placeholders in an answer, including streamed answers and tool calls |
| **Reporting API** | The read-only API behind the console. It sits next to the admin API, on the console port |
| **Request fingerprint** | HMAC-SHA-256, keyed per organization, over the canonical masked request, model, tools, answer-changing settings, scope, and cache version |
| **Reserve, then settle** | Budget handling: reserve an estimate before the call, settle with provider-reported usage afterwards |
| **Segment** | One piece of text in a request: the system prompt, one message, one tool result |
| **Semantic cache** | A response cache that matches the meaning of the last user message, with two-stage verification. Scoped to one key, confirmed with hard checks |
| **Shadow mode (semantic cache)** | The semantic cache records the hits it would have served, and how often they differed from the real answer, without serving them |
| **Snapshot** | A complete, versioned, read-only copy of the configuration the request path needs, held in each gateway's memory |
| **Spool** | An append-only file on local disk where events are written before delivery |
| **Starter policy** | The policy file created at the first start. It enforces only what the fast detectors find with high precision, turns the exact cache on and keeps answers on disk for 30 days, switches the regenerate rule off, and writes out the semantic cache, off until an embeddings model is named |
| **Threat** | Text that tries to take over the model, such as a prompt injection. Named under `threats:` in the policy, scored by a Guard model on untrusted segments, and handled by its action: `alert`, `block`, or `allow`. Its `min_score` is the score from which text counts as the threat |
| **Team, project** | Levels of the hierarchy organization → team → project → key. Each can have its own policy file and budget |
| **Tier** | A model class used by policies and routing: `local`, `economy`, `standard`, `frontier` |
| **Translated mode** | A request crosses API families, for example Anthropic-style to an OpenAI-compatible local model. Allowed only when the catalog shows full feature support |
| **Untrusted segment** | User turns, tool results, and retrieved documents. Injection detection runs on these only |
| **Value map** | The table from placeholders to real values. Lives only in gateway memory, for one request |
| **Virtual key** | A KyGate API key per user, team, or application (`kg-...`). Real provider keys never leave KyGate. Created with `kygate key create`, shown once, stored as a hash, and revoked with `kygate key revoke` |
