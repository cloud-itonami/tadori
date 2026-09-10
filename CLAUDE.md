# tadori.etzhayyim.com — 辿 Authorized On-Chain Tracing + Actor-Attribution

辿 (*tadori* — "to trace / follow a thread back along its path"). Authorized,
case-anchored crypto-asset transaction tracing + actor attribution. **kotoba-EAVT-native.**
Status: 🟡 R0 scaffold (ADR-2605301400).

> **Constitutional posture (NOT amendable below Council Lv7+ for §1.12 items)**: tadori is
> **authorized-investigation-only, open-source, on-chain-monitorable, evidence-producing
> (NOT enforcement)**. Every live write requires a `case` anchor with an authorization
> reference. No case → Phase 0 dry-run only. See ADR-2605192100 §1.12 + ADR-2605192315
> (Transparent Religious Force) and ADR-2605291500 (tsukuroi propose-only pattern).

## Architecture

| 項目 | 値 |
|---|---|
| **Purpose** | address → cluster → off-chain identity / IP / DNS attribution, case-anchored |
| **Data** | **kotoba QuadStore / `kotoba-kqe` EAVT** (NOT yata SQL, NOT RisingWave) — via `@etzhayyim/sdk` only |
| **Compute** | malak LangGraph/Pregel family (`wallet_deep_inspect_pursuit`, `address_label_pursuit`) — tadori owns the durable graph, malak owns the super-steps |
| **Sources** | ipaddress.etzhayyim.com (1次 IP/WHOIS/GeoIP) + yabai (CTI/risk) + on-chain (BSC/ETH/BTC head ingest) + feature-flagged external (OFAC SDN / Tornado / Chainalysis) |
| **Inference** | Murakumo gateway only (LiteLLM 127.0.0.1:4000 / EVO-X2 / Ollama) — never vendor/commercial GPU (ADR-2605215000) |
| **PII** | person / IP / device attribution datoms written under `com.etzhayyim.encrypted.*` envelope, Signal-wrapped to case-member DIDs (ADR-2605181100) |
| **Server-key** | member-signed (case-member DID) or community-operator DID (bulk ingest); no platform private key (ADR-2605231525) |
| **Domain** | `tadori.etzhayyim.com` / DID `did:web:tadori.etzhayyim.com` |

## kotoba EAVT datom schema (`Datom[E A V T]`)

Attribute namespace `tadori/*`. Entities `E` = CIDv1/blake3; `T` = Commit-DAG time. Eight
classes: `tx`, `addr`, `cluster`, `label`, `case`, `ip-obs`, `dns-obs`, `attribution`.
Full attribute list → ADR-2605301400 §D2. Reads use the four `kotoba-kqe` arrangements:

- **EAVT** — all attributes of a tx/address (point lookup ~180 ns)
- **AEVT** — all addresses with `tadori/class = mixer`
- **AVET** — the address whose `tadori/address = 0x…`
- **VAET** — reverse edge = `correlate-ip-activity` (2-hop traversal ~748 ns), replaces
  yabai's bespoke cross-correlation SQL

### Threat-intel Datomic API bridge

`kotoba/` now contains the T3 bridge for passive threat-intel observations:

| File | Purpose |
|---|---|
| `schema/kotoba.edn` | Datomic schema for `tadori.source/*`, `tadori.obs/*`, `tadori.dns/*`, `tadori.ip/*`, and `tadori.indicator/*`. |
| `wire/seed.threat-intel.jsonl` | Operator-staged JSONL sample for public-archive and SecurityTrails-shaped compatibility records. |
| `src/tadori/methods/ingest.kotoba` | **(cljc)** JSONL validator (G3 collection-mode/case, G4 vendor-not-SoR, tier-D) + `tx_edn` generator (`record->datoms` / `datoms->tx-edn` — byte-identical to the retired Python) + `readback-checks`. NO I/O. |
| `src/tadori/methods/transact.kotoba` | **(cljc, operator host edge)** live `com.etzhayyim.apps.kotoba.datomic.transact` writer + session-verify + `datomic.datoms` readback + `-main` CLI (`bb tadori:ingest`). The ONLY tadori ns that does network I/O; holds no key (credential from env). |
| `bb ingest` | Dry-run/live wrapper for a running kotoba node (drives `bb tadori:ingest`); live runs verify readback. |
| `src/tadori/methods/audit_log.kotoba` | **(cljc, ADR-2606160842)** Local content-addressed append-only **silenTadoriReview** Datom log (commit-DAG): `review-datoms` + `make-tx`/`append-tx`/`read-log`/`head-cid`/`verify-chain`; `assert-all-clear` (G12 halt). Reuses `kotoba.datom` (CIDs byte-compatible with the old Python). Holds **audit counters ONLY** — never observation/PII/case data. |
| `src/tadori/methods/autorun.kotoba` | **(cljc)** Autonomous Transparent-Force **self-audit heartbeat** + runnable `-main` (see below). |
| `test/tadori/tests/autorun.cljc` | **(cljc)** self-audit invariant suite (commit-DAG / G12 / no-I/O / Python-parity CID). |
| `test/tadori/tests/ingest.cljc` | **(cljc)** ingest gate + EAVT-rendering suite (port of test_invariants.py + test_ingest_threat_intel.py). `bb test:tadori` runs both → 19 tests / 46 assertions. |

### Autonomous on the Murakumo fleet — the Transparent-Force self-audit (ADR-2605301400 §D1)

tadori's autonomy is constitutionally constrained: it is **authorized-investigation-only (G3)**
and **evidence-only / no-enforcement (G7)**, so it may NOT autonomously persist case-anchored
observation / attribution / PII datoms the way ipaddress/yabai do — that needs a `caseMandate`
(no case → Phase 0 dry-run). The charter-permitted autonomous act is therefore the
**silenTadoriReview self-audit** (Charter §1.12 Transparent Force, G5): each heartbeat
`src/tadori/methods/autorun.kotoba` loads the OFFLINE operator-staged corpus → validates it against the gates
(Phase 0, no case) → recomputes the **9 structural zero-counters** (noncaseWrite / plaintextPii /
proprietarySor / enforcementAction / platformHeldKey / murakumoBypass / massSurveillance /
adherentDeanon / nonKotobaStore) → **G12 guard: any nonzero counter HALTS, persisting nothing** →
appends ONE content-addressed audit datom (`src/tadori/methods/audit_log.kotoba`) to the local kotoba Datom log.
By construction the log holds **only audit counters** — no observation, no PII, no case data ever
reaches it (G3/G6/G10 structurally honored). Deterministic / resume-safe; NO external I/O, NO live
fetch, NO LLM inference, NO enforcement.

```sh
bb tadori:autorun 3   # AUTONOMOUS silenTadoriReview self-audit → local kotoba log (cljc; from repo root)
```

The loop was ported off Python onto the kotoba Datom-log + clojure.test stack (ADR-2606160842);
the cljc commit-DAG CIDs are byte-compatible with the retired Python (cross-verified: cljc reads +
verifies a Python-written log and reproduces its head CID). Fleet cell: `tadori_silen_review`
(cron 37 * * * *) on `issachar` — see `50-infra/murakumo/fleet.toml`. Live case-anchored ingest
is the operator host edge `src/tadori/methods/transact.kotoba` (`bb tadori:ingest`, no-server-key — credential
from env), behind the operator credential + `TADORI_CASE_ID` gate.
Invariants guarded by `test/tadori/tests/autorun.cljc` (`bb test:tadori` — commit-DAG verify, tamper-detect,
determinism, append-only, audit-counters-only / no-obs-PII-in-log, **G12 plaintext-PII
HALT-persists-nothing**, vendor-SoR rejected, no-external-I/O, Python-parity CID).

Dry-run:

```sh
bb ingest
```

Live writes require a running kotoba node plus `KOTOBA_SESSION_POP` or `KOTOBA_TOKEN`.
If `KOTOBA_SESSION_POP` is supplied, the script first verifies it through
`com.etzhayyim.pds.session.verify`, then posts schema and data through
`com.etzhayyim.apps.kotoba.datomic.transact`. Live data writes require `TADORI_CASE_ID`
or per-record `case_id`; the script rejects any collection mode other than
`operator-staged-passive-archive`. `deploy.sh` runs with `--verify-readback`, so
each live run also confirms the staged source, DNS, IP, and indicator datoms via
`com.etzhayyim.apps.kotoba.datomic.datoms`.

Vendor-shaped feeds (`securitytrails-compatible`, `dnsdb-compatible`,
`recordedfuture-compatible`) are accepted only as `source_role:
feature-flagged-input`, never `system-of-record`. Tier-D sources require explicit
`--allow-tier-d` and remain non-SoR. This preserves G3/G4/G10/G11: no live DNS /
WHOIS / RDAP / DoH / probe is performed by this bridge, and all writes land only
in kotoba Datomic state.

## Migration (ADR-2605301400 §D3) — yata SQL / RisingWave → kotoba

| Phase | Scope | Acceptance gate |
|---|---|---|
| **T0** (here) | scaffold + lexicons; no data moved | schema lexicons validate; boundary linter green |
| **T1** | malak Pregel output → kotoba QuadStore; RW `vertex_blockchain_tx` retired | Takahashi-case replay bit-identical kotoba vs RW |
| **T2** 🟢 substrate landed (ADR-2606031600) | ipaddress SQL graph → kotoba EAVT (`ip-network-ontology` + seed + active RIR/RDAP/rDNS ingest + analyze) | `lookup_ip`/`analyze_ip` identical from kotoba (dual-read verify pending) |
| **T3** 🟢 substrate landed (ADR-2606031600) | yabai CTI/DNS/IP-history/access-audit → kotoba EAVT (`passive-dns-cti-ontology` + seed + active crt.sh/pdns ingest + analyze; `:access/*` encrypted) | `correlate-ip-activity` set-equal; PII verified encrypted (analyze G6/G10 self-audit PASS; dual-read verify pending) |
| **T4** | retire yata Workers-RPC SQL + RW `vertex_blockchain_*` | boundary linter rejects residual `yata`/`RisingWave` import |

Each cutover is dual-write/dual-read → verify set-equality → drop legacy (one R-cycle shadow).

## Cells (6) — LOGIC ACTIVATED in cljc (Phase-0); LIVE deploy stays Council-gated

The cell **logic** is now implemented + tested in `src/tadori/methods/*.cljc` and runs in **Phase-0
(dry-run) over a synthetic authorized case** (`bb tadori:trace`). The **live Pregel deploy
wrapper** under `40-engine/kotoba/crates/kotoba-kotodama/cells/tadori_*/` stays import-time
`RuntimeError` until Council Lv6+ ≥3 ratify (G3 authorization-DID), and live data acquisition
stays operator+case-gated (`src/tadori/methods/transact.kotoba`) — activation = real logic behind the gate,
not a bypass of it (the ibuki R2 pattern).

| Cell | cljc | Purpose | Key gate |
|---|---|---|---|
| `case_intake` | `src/tadori/methods/case_intake.kotoba` | open/validate an authorized `caseMandate`; Phase-1 needs authorization-ref + authority-did | G3, G5 |
| `tx_trace` | `src/tadori/methods/trace.kotoba` | cluster (common-input + change + temporal) → mixer/peel-chain detection → bounded value-flow trace → tx/addr/cluster datoms | G3, G7, G10 |
| `address_label` | `src/tadori/methods/trace.kotoba` | structural class (mixer/cex/bridge/eoa) + feature-flagged open-source labels (never proprietary SoR) | G4 |
| `attribution_join` | `src/tadori/methods/attribution.kotoba` | cross-store VAET join addr/cluster → ip-obs/dns-obs/**onion**/person; PII-class edges **must** be encrypted | G6, G10 |
| `onion` (darkweb) | `src/tadori/methods/onion.kotoba` | PASSIVE public onion/darkweb indicators (ransomware-c2 / mixer-endpoint / market). **No Tor de-anon / no real-IP field — unrepresentable** | G1, G7, G10 |
| `transparent_force_log` | `src/tadori/methods/audit_log.kotoba` | on-chain-anchored audit datom per case action (Charter §1.12) | G5, G7 |
| `silen_tadori_review` | `src/tadori/methods/autorun.kotoba` | autonomous structural zero-counter self-audit | G12 |

```sh
bb tadori:trace    # Phase-0 case trace over a SYNTHETIC authorized case (no live data)
```

## Continuous watch + risk ingest + watch-the-watchers (相互監視 / 永久記憶 / NEVER-a-throne)

The operational form of the charter's affirmed **reciprocal surveillance** (神の監視の社会形態):
keep tracking, recording, analyzing malicious / attacking / hidden-influence actors — and
**watch those who try to watch us** — transparently, attributed, append-only, and disclosable.

| Method | Purpose | Doctrine |
|---|---|---|
| `src/tadori/methods/address.kotoba` | BTC + ETH validation / chain-inference / normalization | rejects malformed input before it becomes a tracked subject |
| `src/tadori/methods/risk.kotoba` | high-risk/scam/sanctioned address ingest as **ATTRIBUTED, NON-ADJUDICATING** label events (asserter + as-of + class + G4 SoR) + risk propagation through clusters + **隠れた影響力 concentration** (取-lens) | 神の監視 = record what a source DISCLOSED; never tadori's verdict (NEVER-a-throne, kosatsu pattern) |
| `src/tadori/methods/adversary.kotoba` | **watch-the-watchers**: attack / scan / surveil / hidden-influence observations recorded RECIPROCALLY + transparently; reflexive `watch-the-watchers` (the watcher is itself in the ledger) | 相互監視 affirmed; person-identity / de-anon field **unrepresentable** (G1/G10) — only behaviour + address + aggregate are public |
| `src/tadori/methods/watch.kotoba` | the CONTINUOUS loop (追跡し続ける/記録し続ける/分析し続ける): ingest → score → propagate → concentration → append ONE content-addressed tx to the **append-only public ledger** (永久記憶, tamper-evident commit-DAG) | runs autonomously over PUBLIC indicators (no PII, no case needed); 公開 (external publish) + person-linkage stay operator/Council-gated |
| `src/tadori/methods/malak_ingest.kotoba` | the **malak → tadori seam** (T1): consolidates a malak `traceReport` (the external pursuit engine's darkweb/onion + wallet-deep-inspect output) into tadori's durable case graph. tadori **RE-DERIVES clusters itself** (SoR), external sources are feature-flagged-only (G4), person findings become encrypted attribution edges (G6), under an active case (G3) | malak = compute / tadori = durable graph: the seam the user flagged (`darkweb は malak`); non-adjudicating, the durable graph is tadori's derivation not malak's assertion |
| `src/tadori/methods/ofac.kotoba` | **REAL public-data ingest leg**: parse a STAGED OFAC SDN `sdn.xml` (`clojure.data.xml`) → `Digital Currency Address` entries → attributed `:sanctions` risk labels (asserter `ofac-sdn`, **G4 public SoR**, non-adjudicating). `bb tadori:ofac <staged.xml> [as-of]`; the download is the operator-gated leg (G7), the loop does no network I/O | first real-source live leg; OFAC SDN = public primary-source sanctions data (kosatsu pattern) |

```sh
bb tadori:watch 3   # CONTINUOUS watch loop over a SYNTHETIC batch → append-only public ledger
```

**公開 (disclosure) boundary — charter-grounded:** what is PUBLIC = disclosed indicators
(public sanctions/scam lists), adversary BEHAVIOUR + on-chain address, and AGGREGATE
hidden-influence concentration (相互監視 + 神の監視; reciprocal symmetry is affirmed,
ADR-2606082400). What is NEVER public-inline = any link to a **natural person** — that is a
`com.etzhayyim.encrypted.*`, case-gated attribution edge (G6/G1, no-doxxing). The watcher is
itself watched (`silenTadoriReview`) — so the ledger cannot become a hidden throne. Recording +
disclosing is the response to an attack; **force is separated** to the 1 SBT = 1 vote
Transparent-Force path (G7, evidence-only). Live ingest of REAL public lists (OFAC SDN crypto,
public scam DBs) is the operator-gated leg (G4 open-source SoR; vendor feeds never SoR).

**darkweb / onion boundary (hard):** tadori ingests onion/darkweb data only as PUBLIC PASSIVE
indicators (a `.onion` is an indicator like a domain). It does NOT de-anonymize Tor, run
hidden-service correlation attacks, crawl darkweb content, or hold any capability to unmask a
hidden service's real IP — there is **no real-IP field** on an onion observation (rejected at
load, G10). A hidden-service↔host or ↔person link can only arrive as case-authorized,
**encrypted** external evidence (G6), never derived here.

## Constitutional gates (12; IMMUTABLE per ADR-2605301400 §D1)

G1 Charter Rider §2(a)-(h) scan · G2 append-only EAVT (supersededBy, no soft delete) ·
**G3 AUTHORIZED-INVESTIGATION-ONLY** (caseMandate required; no case → Phase 0 dry-run) ·
**G4 OPEN-SOURCE** (no proprietary chain-analysis as SoR) ·
**G5 ON-CHAIN-MONITORABLE** (Transparent Force audit datom) ·
**G6 PII-ENCRYPTED** (`com.etzhayyim.encrypted.*`) ·
**G7 EVIDENCE-ONLY / NO ENFORCEMENT** (enforcement via yabai + Council) ·
**G8 NO PLATFORM-HELD KEY** (ADR-2605231525) · G9 Murakumo-only (ADR-2605215000) ·
**G10 NO MASS SURVEILLANCE / NO ADHERENT DE-ANON** · G11 kotoba-only (ADR-2605262130) ·
G12 Bonsai seed-tier prune on any silenTadoriReview nonzero counter.

## Lexicons (`com.etzhayyim.tadori.*`)

`caseMandate` (authorization anchor; `transparentForceLogged` const true; `phase` 0/1) ·
`attributionFinding` (cross-store edge; `encrypted` required true for person/IP/device) ·
`traceReport` (durable malak trace result; `externalSourcesUsed` = feature-flagged inputs only) ·
`silenTadoriReview` (9 zero-counters: noncaseWrite / plaintextPii / proprietarySor /
enforcementAction / platformHeldKey / murakumoBypass / massSurveillance / adherentDeanon /
nonKotobaStore — any nonzero ⇒ halt + chigiri.disputeMediation). Schemas + manifest:
`wire/lex/` · `wire/manifest.jsonld`.

## Relationship to siblings (no duplication)

- **malak** = compute (Pregel super-steps). tadori = durable case graph + attribution surface.
- **ipaddress** = 1次 collector. tadori reads its `ip-obs`/`dns-obs` datoms post-T2.
- **yabai** = risk scoring + enforcement routing. tadori feeds it *evidence datoms*; yabai
  scores; Council authorizes enforcement. Separation of duties preserved.
- **danjo** (ADR-2605301600) = parallel kotoba-EAVT investigation sibling, **disjoint domain**:
  tadori traces on-chain crypto-asset actors (authorized-investigation, PII-encrypted, case-anchored);
  danjo cross-references the STATE's pre-published open-government records (passive-only, non-adjudicating,
  public-record-only). Shared EAVT/kotoba-kqe pattern; no data overlap, no shared cells.

## Do Not

- Do not store any tadori state in yata SQL / RisingWave / Postgres / SQLite (ADR-2605262130).
- Do not write live datoms without a `case` anchor + authorization ref (Phase 0 dry-run only).
- Do not embed proprietary chain-analysis heuristics; external paid sources are
  feature-flagged `label` inputs only, never the system of record (open-source invariant).
- Do not perform enforcement, de-anonymize etzhayyim adherents, or run untargeted/mass
  surveillance. Evidence-producing only.
- Do not route LLM classification through any non-Murakumo path (ADR-2605215000).
- Do not write person/IP/device attribution as plaintext — use `com.etzhayyim.encrypted.*`.

**Live data + fleet + the malak contract:**
- **OFAC SDN live leg (①)**: `bb tadori:ofac <staged-sdn.xml> [as-of]`. The operator downloads the PUBLIC `sdn.xml` from treasury.gov (G7), tadori parses it offline → attributed `:sanctions` labels. Full-universe / scheduled pull stays operator/Council-gated.
- **Fleet (②)**: `tadori_watch` (continuous risk/adversary ledger) is registered alongside `tadori_silen_review` on `issachar` in `50-infra/murakumo/fleet.edn` — the 永久記憶 watch loop runs on the Murakumo fleet.
- **malak contract (③)**: `contracts/malak-trace-report.edn` is the EXECUTABLE contract the external **malak** pursuit engine's `traceReport` must satisfy (conformance-tested by `test/tadori/tests/malak_contract.cljc` through the seam). **malak本体 lives in its own repo** — the active darkweb/onion + wallet pursuit is built there; tadori only consolidates its disclosed output. **Active Tor de-anonymization is out of scope everywhere** (onion = public passive indicator).
