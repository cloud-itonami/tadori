(ns tadori.methods.attribution
  "tadori 辿 — cross-store attribution join (cell tadori_attribution_join). ADR-2605301400 §D1/§D2.

  Joins on-chain subjects (addr/cluster) to off-chain objects (ip-obs / dns-obs / onion / person)
  into attribution edges, under an ACTIVE case. This is the kotoba-kqe VAET reverse-edge join the
  schema reserves (`correlate-ip-activity`), expressed as a pure fold here.

  Constitutional gates (enforced as code, test-bound):
    G3  every edge carries the case-id; built only under an active case (require-active-case).
    G6  any edge whose object is PII-bearing (person / ip / device / onion-real-host) MUST be
        `:encrypted true` — `attribution-datoms` THROWS on a plaintext PII edge (the payload is
        a com.etzhayyim.encrypted.* envelope CID, never plaintext here).
    G7  evidence-only: an edge records a correlation + its evidence CIDs + a confidence; it has
        no enforcement/seize verb (unrepresentable).
    G10 no adherent de-anon / no mass surveillance: edges exist only for case subjects.

  Pure (no I/O)."
  (:require [kotoba.datom :as kd]
            [tadori.methods.case-intake :as case]))

(def pii-object-kinds
  "Object kinds that attribute to a natural person / network locus ⇒ MUST be encrypted (G6)."
  #{:person :ip :device :onion-payment-address :onion-real-host})

(defn attribution-error [msg] (ex-info msg {:tadori/error :attribution}))

(defn- pii-edge? [edge]
  (contains? pii-object-kinds (keyword (name (or (:kind edge) :unknown)))))

(defn build-edges
  "Correlate subjects→objects from the analysis + evidence. Each input edge is
  {:subject :object :kind :evidence [cids] :confidence}; a PII edge is auto-marked
  :encrypted true (the caller must supply the envelope CID in :evidence). Returns edges
  with stable ids + the encrypted flag resolved."
  [edges]
  (mapv (fn [e]
          (let [enc (or (pii-edge? e) (true? (:encrypted e)))]
            (assoc e
                   :id (str "attr:" (kd/tx-cid [[(str (:subject e)) (str (:object e)) (str (:kind e))]] ""))
                   :encrypted enc)))
        edges))

(defn attribution-datoms
  "Emit :tadori.attribution/* under an active case (G3). THROWS on a plaintext PII edge (G6).
  mandate is validated via case/require-active-case before any live edge is produced."
  [edges mandate]
  (let [m (case/require-active-case mandate)
        case-id (:case-id m)
        edges (build-edges edges)]
    (doseq [e edges]
      (when (and (pii-edge? e) (not (true? (:encrypted e))))
        (throw (attribution-error (str "G6: PII attribution edge must be encrypted: " (:id e)))))
      (when (and (pii-edge? e) (empty? (:evidence e)))
        (throw (attribution-error (str "G6: encrypted PII edge requires an evidence envelope CID: " (:id e))))))
    (vec
     (mapcat
      (fn [e]
        (let [eid (:id e)]
          (cond-> [(kd/add eid ":tadori.attribution/id" eid)
                   (kd/add eid ":tadori.attribution/subject" (:subject e))
                   (kd/add eid ":tadori.attribution/object" (:object e))
                   (kd/add eid ":tadori.attribution/kind" (str (keyword (name (:kind e)))))
                   (kd/add eid ":tadori.attribution/confidence" (:confidence e 500))
                   (kd/add eid ":tadori.attribution/encrypted" (true? (:encrypted e)))
                   (kd/add eid ":tadori.attribution/case-id" case-id)]
            (seq (:evidence e))
            (into (map #(kd/add eid ":tadori.attribution/evidence" %) (:evidence e))))))
      edges))))
