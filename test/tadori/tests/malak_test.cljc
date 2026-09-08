(ns tadori.tests.malak-test
  "tadori 辿 — malak → tadori traceReport seam invariants. ADR-2605301400 §D3 (T1).
  tadori re-derives (SoR), G3 active-case, G4 external-not-SoR, G6 PII-encrypted, provenance."
  (:require [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [tadori.methods.case-intake :as case]
            [tadori.methods.malak-ingest :as malak]))

(defn- threw? [tag f] (try (f) false (catch clojure.lang.ExceptionInfo e (= tag (:tadori/error (ex-data e))))))

(def ^:private MIX "0xfeedface00000000000000000000000000000000")
(def ^:private CEX "0x1234567890abcdef1234567890abcdef12345678")

(def mandate
  {:case-id "case:malak-demo" :authorization-ref "warrant:synthetic" :authority-did "did:web:etzhayyim.com:authority:synthetic"
   :phase 1 :opened-ts 20260617})

(def report
  "A SYNTHETIC malak traceReport (pursuit output): stolen funds → mixer → CEX, an onion C2,
  a person finding (encrypted), and a feature-flagged external source."
  {:report-id "malak-rpt-001"
   :case-id "case:malak-demo"
   :chain :eth
   :seeds ["0xthief-a"]
   :txs [{:tx-hash "m1" :from "0xthief-a" :to MIX :value 1 :inputs ["0xthief-a" "0xthief-b"] :ts 1}
         {:tx-hash "m2" :from "0xsrc2" :to MIX :value 1 :ts 2}
         {:tx-hash "m3" :from "0xsrc3" :to MIX :value 1 :ts 3}
         {:tx-hash "m4" :from MIX :to CEX :value 1 :ts 4}
         {:tx-hash "m5" :from MIX :to "0xout1" :value 1 :ts 5}
         {:tx-hash "m6" :from MIX :to "0xout2" :value 1 :ts 6}]
   :labels {CEX :cex-hot}
   :onion [{:onion-id "rpt-onion-1" :address "abcdefghijklmnop234567.onion" :class :ransomware-c2
            :source "malak:onion-pursuit" :case-id "case:malak-demo"}]
   :findings [{:subject "cluster:0xthief-a" :object "person:suspect" :kind :person
               :evidence ["bafkrei-encrypted-envelope"] :confidence 700}]
   :external-sources [{:id "chainalysis-compatible" :role :feature-flagged-input}]
   :as-of 20260617})

(deftest g4-external-source-cannot-be-sor
  (is (threw? :trace-report
              #(malak/validate-report (assoc report :external-sources
                                             [{:id "vendor" :role :system-of-record}])))))

(deftest report-needs-id-and-chain
  (is (threw? :trace-report #(malak/validate-report (dissoc report :report-id))))
  (is (threw? :trace-report #(malak/validate-report (dissoc report :chain)))))

(deftest g3-consolidate-requires-active-case
  (is (threw? :case-mandate #(malak/consolidate report {:phase 0 :case-id "c"}))))

(deftest tadori-re-derives-clusters-as-sor
  ;; tadori runs its OWN clustering over malak's txs (the durable graph is tadori's derivation)
  (let [{:keys [analysis]} (malak/consolidate report mandate)]
    (is (= :mixer (get (:classes analysis) MIX)) "tadori re-detects the mixer structurally")
    (is (contains? (set (get-in analysis [:flow :exits])) CEX) "stolen funds traced to the CEX exit")
    (is (= (get (:clusters analysis) "0xthief-a") (get (:clusters analysis) "0xthief-b")))))

(deftest provenance-records-malak-compute-tadori-sor
  (let [{:keys [datoms]} (malak/consolidate report mandate)
        m (into {} (keep (fn [[_ e a v]] (when (str/starts-with? (str e) "trace-report:") [a v])) datoms))]
    (is (= "malak" (get m ":tadori.trace-report/compute-source")))
    (is (= "tadori" (get m ":tadori.trace-report/system-of-record")) "tadori owns the durable graph")
    (is (true? (get m ":tadori.trace-report/non-adjudicating")))
    (let [exts (set (keep (fn [[_ _ a v]] (when (= a ":tadori.trace-report/external-source-used") v)) datoms))]
      (is (contains? exts "chainalysis-compatible") "external source recorded as feature-flagged input"))))

(deftest g6-person-finding-is-encrypted
  (let [{:keys [datoms]} (malak/consolidate report mandate)
        enc (some (fn [[_ _ a v]] (when (= a ":tadori.attribution/encrypted") v)) datoms)]
    (is (true? enc) "the person finding became an ENCRYPTED attribution edge (G6)"))
  ;; a person finding WITHOUT an evidence envelope is refused (G6, via attribution)
  (is (threw? :attribution
              #(malak/consolidate (assoc report :findings
                                         [{:subject "cluster:0xthief-a" :object "person:x" :kind :person}])
                                  mandate))))

(deftest onion-consolidated-from-report
  (let [{:keys [datoms]} (malak/consolidate report mandate)
        attrs (set (map #(nth % 2) datoms))]
    (is (contains? attrs ":tadori.onion/address"))
    ;; no de-anon attr ever appears (onion guard holds through the seam)
    (is (not-any? #(re-find #"(?i)real-?ip|/person\b" %) (remove #{":tadori.attribution/object"} attrs)))))
