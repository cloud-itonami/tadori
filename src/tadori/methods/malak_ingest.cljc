(ns tadori.methods.malak-ingest
  "tadori 辿 — the malak → tadori seam (T1 of ADR-2605301400 §D3, tadori half).
  Lexicon: com.etzhayyim.tadori.traceReport.

  ARCHITECTURE (the user's own point: darkweb/onion *tracking* is malak's; tadori is the
  durable graph). malak 魔来 runs the active pursuit super-steps (wallet_deep_inspect_pursuit /
  address_label_pursuit / onion-ransomware tracking, ADR-2605152000/2605172000) in its OWN
  repo. It emits a `traceReport`. THIS seam consolidates that report into tadori's durable,
  case-anchored kotoba graph — but tadori does NOT blindly trust it:

    - tadori RE-DERIVES clusters from the report's txs itself (trace/trace-case). The durable
      graph is tadori's OWN derivation; malak's clusters are advisory provenance. tadori is the
      system-of-record (G4); malak is the compute source.
    - findings that link to a person/IP/device/onion-host become ENCRYPTED attribution edges
      (G6, via attribution/attribution-datoms — throws on plaintext PII).
    - external sources malak used are recorded as feature-flagged-input ONLY, never SoR (G4).
    - consolidation is LIVE-write ⇒ requires an ACTIVE case (G3); no case → Phase-0 returns the
      derivation but the caller must not persist live.
    - non-adjudicating + evidence-only (G7): a trace-report records a derivation + its evidence,
      never a verdict or an enforcement action.

  Pure (no I/O). The live transact is the operator+case-gated edge (methods/transact)."
  (:require [kotoba.lang.text :as str]
            [kotoba.datom :as kd]
            [tadori.methods.attribution :as attr]
            [tadori.methods.case-intake :as case]
            [tadori.methods.onion :as onion]
            [tadori.methods.risk :as risk]
            [tadori.methods.trace :as trace]))

(defn report-error [m] (ex-info m {:tadori/error :trace-report}))

(defn validate-report
  "A malak traceReport: {:report-id :case-id :chain :seeds [...] :txs [...] :labels [...]
  :onion [...] :findings [...] :external-sources [{:id :role}...] :as-of}. Every external
  source must be :feature-flagged-input (G4 — a paid/vendor pursuit input is never SoR)."
  [{:keys [report-id chain external-sources] :as report}]
  (when (str/blank? (str report-id))
    (throw (report-error "traceReport needs a report-id")))
  (when (str/blank? (str chain))
    (throw (report-error "traceReport needs a chain")))
  (doseq [s external-sources]
    (when (= (keyword (name (or (:role s) :feature-flagged-input))) :system-of-record)
      (throw (report-error (str "G4: malak external source cannot be system-of-record: " (:id s))))))
  report)

(defn report-provenance-datoms
  "Record the trace-report itself: malak is the COMPUTE source, tadori the durable SoR.
  externalSourcesUsed are feature-flagged inputs only (G4)."
  [{:keys [report-id case-id chain external-sources as-of]}]
  (let [e (str "trace-report:" report-id)]
    (cond-> [(kd/add e ":tadori.trace-report/id" report-id)
             (kd/add e ":tadori.trace-report/compute-source" "malak")
             (kd/add e ":tadori.trace-report/chain" (str (name (keyword (name chain)))))
             (kd/add e ":tadori.trace-report/non-adjudicating" true)
             (kd/add e ":tadori.trace-report/system-of-record" "tadori")]   ;; tadori owns the durable graph
      case-id (conj (kd/add e ":tadori.trace-report/case-id" case-id))
      as-of   (conj (kd/add e ":tadori.trace-report/as-of" as-of))
      (seq external-sources)
      (into (map #(kd/add e ":tadori.trace-report/external-source-used" (str (:id %)))) external-sources))))

(defn consolidate
  "Consolidate a malak traceReport into tadori's durable case graph under an ACTIVE case (G3).
  tadori RE-DERIVES clusters from the report txs (its own derivation, not malak's assertion),
  emits tx/cluster/label datoms (trace), onion datoms (onion), encrypted attribution edges
  from findings (attribution, G6), and a provenance record. Returns {:analysis :datoms}.
  With no active case it throws (Phase-0: caller must not persist a live consolidation)."
  [report mandate]
  (validate-report report)
  (let [m (case/require-active-case mandate)                       ;; G3
        {:keys [chain txs seeds labels onion findings]
         :or {txs [] seeds [] labels {} onion [] findings []}} report
        ;; tadori's OWN derivation over malak's txs (SoR = tadori, not malak)
        analysis (trace/trace-case {:chain (name (keyword (name chain)))
                                    :txs txs :seeds seeds :labels labels})
        onion-datoms (mapcat onion/onion-datoms onion)
        ;; malak findings → encrypted attribution edges (G6 enforced inside attribution)
        attr-datoms (if (seq findings) (attr/attribution-datoms findings m) [])]
    {:analysis analysis
     :datoms (vec (concat (report-provenance-datoms report)
                          (:datoms analysis)
                          onion-datoms
                          attr-datoms))}))
