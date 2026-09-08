(ns tadori.tests.trace-test
  "tadori 辿 — case-anchored tracing + clustering + onion + attribution invariants.
  ADR-2605301400. Activates cells case_intake / tx_trace / address_label /
  attribution_join (Phase-0, synthetic). Constitutional gates are test-bound."
  (:require [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [tadori.methods.attribution :as attr]
            [tadori.methods.case-intake :as case]
            [tadori.methods.demo-case :as demo]
            [tadori.methods.onion :as onion]
            [tadori.methods.trace :as trace]))

(defn- threw? [pred f] (try (f) false (catch clojure.lang.ExceptionInfo e (pred e))))

;; ── G3 caseMandate gate ───────────────────────────────────────────────────────

(deftest live-case-requires-authorization
  (is (threw? case/mandate-error? #(case/validate-mandate {:phase 1 :case-id "c"})))   ;; no auth-ref/did
  (is (threw? case/mandate-error? #(case/validate-mandate {:phase 1 :case-id "c"
                                                           :authorization-ref "w" :authority-did "did:x"
                                                           :transparent-force-logged false}))) ;; G5
  (is (= 1 (:phase (case/validate-mandate demo/mandate))))
  (is (case/active? demo/mandate))
  (is (not (case/active? {:phase 0 :case-id "c"}))))   ;; phase 0 = dry-run, never live

;; ── clustering + mixer/exchange classification (tx_trace + address_label) ──────

(deftest common-input-clusters-thief-addresses
  (let [a (trace/trace-case {:txs demo/txs :seeds demo/seeds :labels demo/labels})
        c (:clusters a)]
    (is (= (get c "0xthief-a") (get c "0xthief-b")))   ;; H1 co-spend ⇒ one entity
    (is (= "0xthief-a" (get c "0xthief-a")))))         ;; canonical = smallest member

(deftest mixer-detected-structurally
  (let [a (trace/trace-case {:txs demo/txs :seeds demo/seeds :labels demo/labels})]
    (is (= :mixer (get (:classes a) "0xmix-core"))     ;; fan-in≥3 ∧ fan-out≥3 ∧ uniform
        "the tumbler is classified :mixer from structure (open-source heuristic, G4)")))

(deftest flow-trace-surfaces-cex-exit
  (let [a (trace/trace-case {:txs demo/txs :seeds demo/seeds :labels demo/labels})
        exits (set (get-in a [:flow :exits]))]
    (is (contains? exits "0xcex-hot") "stolen funds traced through the mixer to the CEX deposit")
    (is (= :cex-hot (get (:classes a) "0xcex-hot")))))  ;; feature-flagged label (G4)

(deftest trace-bounded-to-seed-set
  ;; G3/G10: an address NOT reachable from the warrant's seed set is never surfaced.
  (let [txs (conj demo/txs {:tx-hash "x" :from "0xunrelated-1" :to "0xunrelated-2" :value 9 :ts 200})
        a (trace/trace-case {:txs txs :seeds demo/seeds :labels demo/labels})]
    (is (not (contains? (get-in a [:flow :reached]) "0xunrelated-2"))
        "unrelated activity outside the seed neighborhood is not traced (no untargeted crawl)")))

;; ── onion / darkweb passive-observation guards ────────────────────────────────

(deftest onion-public-indicator-only
  (is (seq (onion/onion-datoms demo/onion-obs)))
  ;; a de-anonymization field is structurally rejected (G10 — no Tor unmasking)
  (is (threw? #(= :onion (:tadori/error (ex-data %)))
              #(onion/onion-datoms (assoc demo/onion-obs :real-ip "203.0.113.7"))))
  ;; a non-onion address is rejected
  (is (threw? #(= :onion (:tadori/error (ex-data %)))
              #(onion/onion-datoms (assoc demo/onion-obs :address "evil.example.com")))))

(deftest onion-datoms-carry-no-host
  (let [ds (onion/onion-datoms demo/onion-obs)
        attrs (set (map #(nth % 2) ds))]
    (is (every? #(str/starts-with? % ":tadori.onion/") attrs))
    (is (not-any? #(re-find #"(?i)ip|host|real" %) attrs))))  ;; no real-IP/host attr exists

;; ── attribution join: G6 PII-must-be-encrypted, G3 active-case ────────────────

(deftest pii-edge-must-be-encrypted
  (let [person-edge {:subject "cluster:0xthief-a" :object "person:suspect" :kind :person
                     :evidence ["bafkrei-encrypted-envelope"] :confidence 600}]
    ;; auto-marked encrypted, persists under an active case
    (is (seq (attr/attribution-datoms [person-edge] demo/mandate)))
    ;; a PII edge with NO evidence envelope is refused (G6)
    (is (threw? #(= :attribution (:tadori/error (ex-data %)))
                #(attr/attribution-datoms [(dissoc person-edge :evidence)] demo/mandate)))))

(deftest attribution-requires-active-case
  (is (threw? case/mandate-error?
              #(attr/attribution-datoms
                [{:subject "addr:0xa" :object "ip:198.51.100.5" :kind :ip :evidence ["bafEnc"]}]
                {:phase 0 :case-id "c"}))))   ;; Phase-0 dry-run cannot persist a live edge

(deftest attribution-edge-encrypted-flag-emitted
  (let [ds (attr/attribution-datoms
            [{:subject "onion:onion-001" :object "addr:0xthief-a" :kind :onion-payment-address
              :evidence ["bafEnc"] :confidence 700}]
            demo/mandate)
        enc (some (fn [[_ _ a v]] (when (= a ":tadori.attribution/encrypted") v)) ds)]
    (is (true? enc) "onion↔payment-address edge is PII-class ⇒ encrypted (G6)")))

;; ── end-to-end synthetic case ─────────────────────────────────────────────────

(deftest demo-case-runs-phase0
  (let [{:keys [analysis datoms]} (demo/run)]
    (is (= :mixer (get (:classes analysis) "0xmix-core")))
    (is (contains? (set (get-in analysis [:flow :exits])) "0xcex-hot"))
    (is (pos? (count datoms)))
    ;; G7 evidence-only: no enforcement/seize attribute is anywhere in the emitted datoms
    (let [attrs (set (map #(nth % 2) datoms))]
      (is (not-any? #(re-find #"(?i)seize|freeze|enforce|arrest|block-funds" %) attrs)))))
