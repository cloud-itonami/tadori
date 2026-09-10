(ns tadori.methods.case-intake
  "tadori 辿 — caseMandate intake + the G3 authorization gate (cell: tadori_case_intake).
  ADR-2605301400 §D1 (G3/G5). Clojure activation of the R0 Pregel scaffold.

  tadori is AUTHORIZED-INVESTIGATION-ONLY (G3): every LIVE write of a case-anchored
  observation/attribution/PII datom requires an active `caseMandate` — an authorization
  anchor carrying an authorization-ref + the signing authority's DID. With no active case
  the actor is in **Phase 0 (dry-run)**: tracing still runs over staged/synthetic evidence,
  but nothing case-anchored is persisted live. This namespace is the gate every other
  tracing cell calls before it may assert a live datom.

  G5 (Transparent Force): transparent-force-logged is a CONSTANT true on every mandate —
  a case cannot be opened without committing to an on-chain-monitorable audit trail.

  Pure (no I/O). The caller supplies as-of (no wall clock)."
  (:require [kotoba.lang.text :as str]
            [kotoba.datom :as kd]))

(def phases #{0 1})   ;; 0 = dry-run (no case), 1 = live (active authorized case)

(defn mandate-error [msg] (ex-info msg {:tadori/error :case-mandate}))
(defn mandate-error? [ex] (= :case-mandate (:tadori/error (ex-data ex))))

(defn validate-mandate
  "G3/G5 gate. A LIVE (phase 1) mandate MUST carry a non-blank case-id + authorization-ref
  + authority-did; transparent-force-logged MUST be true (G5). A phase-0 mandate is the
  dry-run posture (case-id optional). Returns the mandate on success, else throws."
  [{:keys [case-id authorization-ref authority-did phase transparent-force-logged]
    :or {phase 0 transparent-force-logged true} :as mandate}]
  (when-not (phases phase)
    (throw (mandate-error (str "phase must be 0 (dry-run) or 1 (live); got " (pr-str phase)))))
  (when-not (true? transparent-force-logged)
    (throw (mandate-error "G5: transparent-force-logged must be true — a case commits to an on-chain audit trail")))
  (when (= phase 1)
    (doseq [[k v] {:case-id case-id :authorization-ref authorization-ref :authority-did authority-did}]
      (when (str/blank? (str v))
        (throw (mandate-error (str "G3: live (phase 1) case requires " (name k) " — no caseless live write"))))))
  mandate)

(defn active?
  "True iff the mandate authorizes LIVE case-anchored writes (phase 1, gate-clean)."
  [mandate]
  (try (= 1 (:phase (validate-mandate mandate))) (catch #?(:clj Exception :cljs :default) _ false)))

(defn require-active-case
  "Used by the tracing/attribution cells: returns the validated mandate if it authorizes a
  live write, else throws (the caller must fall back to Phase-0 dry-run — never persist live)."
  [mandate]
  (let [m (validate-mandate mandate)]
    (when-not (= 1 (:phase m))
      (throw (mandate-error "G3: no active case (Phase 0 dry-run) — live case-anchored write refused")))
    m))

(defn case-datoms
  "Emit the caseMandate as append-only EAVT (:tadori.case/*). authority-did/authorization-ref
  are the audit anchor; the narrative is operator-supplied free text."
  [{:keys [case-id narrative authorization-ref authority-did phase opened-ts]
    :or {phase 0}}]
  (let [e (str "case:" case-id)]
    (cond-> [(kd/add e ":tadori.case/case-id" case-id)
             (kd/add e ":tadori.case/phase" phase)
             (kd/add e ":tadori.case/transparent-force-logged" true)   ;; G5 const
             (kd/add e ":tadori.case/opened-ts" (or opened-ts 0))]
      narrative         (conj (kd/add e ":tadori.case/narrative" narrative))
      authorization-ref (conj (kd/add e ":tadori.case/authorization-ref" authorization-ref))
      authority-did     (conj (kd/add e ":tadori.case/authority-did" authority-did)))))
