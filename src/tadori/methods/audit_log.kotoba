(ns tadori.methods.audit-log
  "tadori 辿 autonomous self-audit kotoba Datom log (local, content-addressed).
  ADR-2605301400 §D1 (G2/G3/G5/G12) + ADR-2605262130 + ADR-2605312345.
  Clojure port of `kotoba/audit_log.py`.

  Why tadori's autonomous loop is DIFFERENT from ipaddress/yabai/shionome:

    tadori is AUTHORIZED-INVESTIGATION-ONLY (G3): every write of a case-anchored
    OBSERVATION / attribution / PII datom requires a `caseMandate`. No case →
    Phase 0 dry-run only. So tadori must NOT blindly autonomously-persist
    observation datoms the way ipaddress/yabai do — that would violate G3.
    Instead the constitution-permitted autonomous act is the **silenTadoriReview
    self-audit heartbeat** (Charter §1.12 Transparent Force, G5): each cycle the
    actor recomputes its 9 structural zero-counters over the OFFLINE staged corpus
    and persists ONE append-only, on-chain-monitorable AUDIT datom — no
    observation, no PII, no case data ever touches this log. A nonzero counter
    HALTS (G12 Bonsai prune), persisting nothing.

  The content-addressed commit-DAG primitives (tx-cid / make-tx / append / read /
  verify, byte-compatible with Python) are the shared `kotoba.datom` sibling,
  reused verbatim (NOT re-inlined) and re-exposed here under the names the Python
  module defines, so callers depending on either surface work.

  EAVT = [:db/add entity attribute value] — :db/add only (append-only, G2).
  Deterministic: the caller supplies tx-id + as-of (no wall clock)."
  (:require [kotoba.datom :as kd]
            #?(:clj [clojure.java.io :as io])))

#?(:clj
   (def log-default
     "20-actors/tadori/data/persisted/tadori.silen-review.datoms.kotoba.edn (host edge)."
     (-> *file* io/file .getParentFile .getParentFile
         (io/file "data" "persisted" "tadori.silen-review.datoms.kotoba.edn"))))

(def counters
  "The 9 silenTadoriReview structural zero-counters (ADR-2605301400 §D1 / lexicon)."
  ["noncase-write" "plaintext-pii" "proprietary-sor" "enforcement-action"
   "platform-held-key" "murakumo-bypass" "mass-surveillance" "adherent-deanon"
   "non-kotoba-store"])

(defn silen-review-halt
  "G12 halt — an ex-info the autonomous loop raises on any nonzero counter
  (Bonsai seed-tier prune + route to chigiri.disputeMediation; nothing persisted)."
  [msg]
  (ex-info msg {:tadori/error :silen-review-halt}))

(defn silen-review-halt?
  "True iff ex is a G12 halt (so tests can catch it like audit_log.SilenReviewHalt)."
  [ex]
  (= :silen-review-halt (:tadori/error (ex-data ex))))

(defn assert-all-clear
  "G12: any nonzero structural counter HALTS — the autonomous loop persists a passing
  audit ONLY when every counter is zero. A violation raises and writes nothing."
  [review]
  (let [nonzero (into {} (for [k counters
                               :let [v (get review k 0)]
                               :when (not= v 0)]
                           [k v]))]
    (when (seq nonzero)
      (throw (silen-review-halt
              (str "silenTadoriReview HALT (G12): nonzero counter(s) " nonzero
                   " — tadori prunes to Bonsai seed-tier + routes to "
                   "chigiri.disputeMediation; no audit datom persisted."))))))

(defn review-datoms
  "Flatten ONE silenTadoriReview heartbeat into append-only EAVT assertions. Holds only
  the 9 zero-counters + informational audit totals + the Transparent-Force flag (G5).
  NEVER any observation / PII / case-anchored datom."
  [review cycle]
  (let [e (str "silen-tadori-review:cycle-" cycle)]
    (-> (into [(kd/add e ":tadori.review/cycle" cycle)
               (kd/add e ":tadori.review/phase" 0)               ;; Phase 0 — no case, dry-run posture
               (kd/add e ":tadori.review/transparent-force-logged" true)] ;; G5
              (map (fn [k] (kd/add e (str ":tadori.review/" k) (get review k 0))))
              counters)
        (conj (kd/add e ":tadori.review/sources-audited" (get review "sources-audited" 0))
              (kd/add e ":tadori.review/obs-audited" (get review "obs-audited" 0))
              (kd/add e ":tadori.review/obs-without-case" (get review "obs-without-case" 0))
              (kd/add e ":tadori.review/all-clear" true)         ;; only reached if assert-all-clear passed
              (kd/add e ":tadori.review/derived" true)))))

;; ── content-addressed commit-DAG (kotoba.datom verbatim, re-exposed) ──────────

(defn tx-cid
  ([datoms] (kd/tx-cid datoms ""))
  ([datoms prev-cid] (kd/tx-cid datoms prev-cid)))

(defn make-tx
  "Mirror of Python make_tx(datoms, *, tx_id, as_of, prev_cid)."
  [datoms {:keys [tx-id as-of prev-cid] :or {prev-cid ""}}]
  (kd/make-tx datoms {:tx-id tx-id :as-of as-of :prev-cid prev-cid}))

#?(:clj
   (defn append-tx
     "Append ONE audit transaction (the log only ever grows). Returns the CID."
     ([tx] (append-tx tx log-default))
     ([tx log-path] (kd/append-tx! tx log-path))))

#?(:clj
   (defn read-log
     ([] (read-log log-default))
     ([log-path] (kd/read-log log-path))))

#?(:clj
   (defn head-cid
     ([] (head-cid log-default))
     ([log-path] (kd/head-cid log-path))))

#?(:clj
   (defn verify-chain
     ([] (verify-chain log-default))
     ([log-path] (kd/verify-chain log-path))))
