(ns tadori.tests.malak-contract-test
  "tadori 辿 — the malak→tadori traceReport CONTRACT is executable: the reference fixture that
  malak (external repo) must emit consolidates cleanly through the seam. ADR-2605301400 §D3.

  NOTE (edn-datomize Phase 4): kotoba/malak-trace-report.contract.edn is now stored as a
  Datomic/Datascript tx-data vector (namespace tadori.malak-contract/*, see
  20-actors/tadori/schema.edn) rather than the bare traceReport map. `contract` reconstitutes
  the original bare map shape here so malak/consolidate + malak/validate-report keep working
  unchanged."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is]]
            [tadori.methods.malak-ingest :as malak]))

(def ^:private mandate
  {:case-id "case:reference" :authorization-ref "warrant:ref"
   :authority-did "did:web:etzhayyim.com:authority:synthetic" :phase 1 :opened-ts 20260617})

(defn- unblob [v]
  (if (string? v)
    (try (let [parsed (edn/read-string v)] (if (coll? parsed) parsed v))
         (catch #?(:clj Exception :cljs :default) _ v))
    v))

(defn- reconstitute-entity [tx-data]
  (into {} (map (fn [[k v]] [(keyword (name k)) (unblob v)]))
        (dissoc (first tx-data) :db/id)))

(defn- contract []
  (reconstitute-entity
   (edn/read-string (slurp (io/resource "contracts/malak-trace-report.edn")))))

(deftest reference-contract-consolidates
  (let [{:keys [analysis datoms]} (malak/consolidate (contract) mandate)]
    (is (= :mixer (get (:classes analysis) "0xfeedface00000000000000000000000000000000"))
        "tadori re-derives the mixer from the contract's txs (SoR)")
    (is (contains? (set (get-in analysis [:flow :exits])) "0x1234567890abcdef1234567890abcdef12345678"))
    (is (pos? (count datoms)))))

(deftest reference-contract-passes-validation
  (is (map? (malak/validate-report (contract))) "the reference traceReport is contract-valid"))
