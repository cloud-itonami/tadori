(ns tadori.tests.ingest-test
  "tadori 辿 threat-intel ingest gates + EAVT rendering. ADR-2605301400 / 2606160842.
  Clojure port of kotoba/test_invariants.py + kotoba/test_ingest_threat_intel.py.

  The load-bearing gates: tadori ingests ONLY operator-staged passive archives (authorized,
  non-probing); Tier-D vendor data is gated and never system-of-record; observations must
  reference a declared source; confidence is bounded; EDN is injection-safe; the encrypted-PII
  flag + case-id (consent/authorization anchor) survive to the Datom log; the live writer
  re-reads every record kind."
  (:require [clojure.java.io :as io]
            [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [tadori.methods.ingest :as ingest]
            [tadori.methods.transact :as transact]))

(defn- seed-records []
  (ingest/load-jsonl (slurp (io/resource "wire/seed.threat-intel.jsonl"))))

(defn- src
  ([] (src "A" "enrichment" "public-archive"))
  ([tier role family]
   {"kind" "intel-source" "id" (str "source:" family ":x") "name" "X"
    "vendor_family" family "source_role" role "license_tier" tier}))

(defn- dns [& {:as over}]
  (merge {"kind" "dns-obs" "id" "dns:sample.invalid:A:2026-06-02" "source" "source:public-archive:x"
          "collection_mode" "operator-staged-passive-archive"
          "domain" "sample.invalid" "rrtype" "A" "rrdata" "192.0.2.10"}
         over))

(defn- v! [records opts]
  (ingest/validate-records records opts))

(defn- threw-validation? [f]
  (try (f) false (catch clojure.lang.ExceptionInfo e (ingest/validation-error? e))))

;; ── gates (port of test_invariants.py) ────────────────────────────────────────

(deftest invalid-kind-rejected
  (is (threw-validation? #(v! [{"kind" "wallet-trace" "id" "x"}] {:allow-tier-d false :live false}))))

(deftest collection-must-be-passive-archive
  ;; the anti-active-probing invariant: only operator-staged passive archives ingest
  (is (threw-validation? #(v! [(src) (dns "collection_mode" "active-scan")]
                              {:allow-tier-d false :live false}))))

(deftest tier-d-requires-explicit-flag-and-stays-non-sor
  (let [recs [(src "D" "enrichment" "public-archive")]]
    (is (threw-validation? #(v! recs {:allow-tier-d false :live false})))
    (is (= recs (v! recs {:allow-tier-d true :live false})))))  ;; with the flag it validates

(deftest observation-must-reference-declared-source
  (is (threw-validation? #(v! [(dns "source" "source:public-archive:undeclared")]
                              {:allow-tier-d false :live false}))))

(deftest confidence-is-bounded
  (is (threw-validation? #(v! [(src) (dns "confidence" 2000)] {:allow-tier-d false :live false})))
  (is (= 2 (count (v! [(src) (dns "confidence" 750)] {:allow-tier-d false :live false})))))

(deftest edn-string-is-injection-safe
  ;; a value with a quote/backslash must be escaped, not break the tx EDN
  (let [s (ingest/edn-string "evil\" :db/add hax \\ end")]
    (is (str/starts-with? s "\""))
    (is (str/ends-with? s "\""))
    (is (str/includes? s "\\\""))
    (is (str/includes? s "\\\\"))))

(deftest encrypted-pii-flag-survives-to-datoms
  (let [datoms (ingest/record->datoms (dns "encrypted" true) {:case-id "case:t"})]
    (is (some #(and (str/includes? % "tadori.obs/encrypted") (str/includes? % "true")) datoms))))

(deftest case-id-binds-observation-for-audit
  ;; every observation carries its case-id (consent/authorization audit anchor)
  (let [datoms (ingest/record->datoms (dns) {:case-id "case:authz-123"})]
    (is (some #(str/includes? % "tadori.obs/case-id \"case:authz-123\"") datoms))))

;; ── seed round-trip + live gates (port of test_ingest_threat_intel.py) ────────

(deftest seed-generates-lookup-ref-for-source-ref
  (let [records (seed-records)
        _ (v! records {:allow-tier-d false :live false})
        tx-edn (ingest/datoms->tx-edn
                (mapcat #(ingest/record->datoms % {:case-id "case:test"}) records))]
    (is (str/includes? tx-edn
                       (str "[:db/add \"dns:sample.invalid:A:2026-06-02\" :tadori.obs/source "
                            "[:tadori.source/id \"source:public-archive:ct-example\"]]")))
    (is (str/includes? tx-edn "[:db/add \"indicator:domain:sample.invalid\" :tadori.obs/source "))
    (is (str/includes? tx-edn "[:db/add \"dns:sample.invalid:A:2026-06-02\" :tadori.obs/case-id \"case:test\"]"))))

(deftest live-write-requires-case-id
  (let [records (mapv #(dissoc % "case_id") (seed-records))]
    (is (threw-validation? #(v! records {:allow-tier-d false :live true})))
    (is (= (count records) (count (v! records {:allow-tier-d false :live true :case-id "case:test"}))))))

(deftest vendor-compatible-source-cannot-be-system-of-record
  (is (threw-validation?
       #(v! [{"kind" "intel-source" "id" "source:vendor-compatible:securitytrails"
              "name" "SecurityTrails-shaped compatibility feed"
              "vendor_family" "securitytrails-compatible" "source_role" "system-of-record"
              "license_tier" "C"}]
            {:allow-tier-d false :live false}))))

(deftest readback-checks-cover-all-record-kinds
  (is (= [["source:public-archive:ct-example" "tadori.source/id"]
          ["source:vendor-compatible:securitytrails" "tadori.source/id"]
          ["dns:sample.invalid:A:2026-06-02" "tadori.dns/domain"]
          ["ip:192.0.2.10:2026-06-02" "tadori.ip/address"]
          ["indicator:domain:sample.invalid" "tadori.indicator/value"]]
         (ingest/readback-checks (seed-records)))))

(deftest live-http-requires-explicit-request-capability
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"explicit HTTP request capability"
                        (transact/http-post nil "http://localhost" {} nil))))

;; ── internal-trust header (ADR-2608124000, "clients first") ──────────────────
;; kotoba-server's require_internal_trust gate returns success while
;; KOTOBA_INTERNAL_SECRET is unset, and it is unset across the fleet — so
;; sending this header today changes nothing on the wire. These tests pin the
;; shape NOW so arming the server later is a one-variable decision rather than a
;; fleet-wide outage. The values below are obviously synthetic; no real secret
;; is read, written, or generated by this suite.
;;
;; NOTE: unlike the actor bridges, tadori has NO host allowlist to act as a
;; positive control — `base-url` is operator-supplied. The Authorization bearer
;; is the only pre-existing header, and it IS asserted here.
(def ^:private synthetic-trust "synthetic-internal-trust-not-a-real-secret")

(defn- capture-headers
  "Run transact/http-post through a stub request-fn, returning the headers sent."
  [token]
  (let [seen (atom nil)]
    (transact/http-post (fn [req] (reset! seen (:headers req)) {:status 200 :body "{}"})
                        "http://127.0.0.1:8077/xrpc/x" {} token)
    @seen))

(deftest internal-trust-header-present-when-configured
  (with-redefs [transact/internal-trust (constantly synthetic-trust)]
    (let [h (capture-headers "operator-token")]
      (is (= synthetic-trust (get h "x-internal-trust"))
          "the configured value is sent verbatim")
      ;; positive control — the pre-existing headers are untouched
      (is (= "Bearer operator-token" (get h "Authorization")))
      (is (= "application/json" (get h "Content-Type"))))))

(deftest internal-trust-header-absent-when-unconfigured
  (with-redefs [transact/internal-trust (constantly nil)]
    (let [h (capture-headers "operator-token")]
      (is (not (contains? h "x-internal-trust"))
          "omitted entirely — never sent as an empty string")
      ;; positive control — omitting trust must not disturb anything else
      (is (= "Bearer operator-token" (get h "Authorization")))
      (is (= "application/json" (get h "Content-Type")))))
  ;; and with no operator token either, the map is exactly what it always was
  (with-redefs [transact/internal-trust (constantly nil)]
    (is (= {"Content-Type" "application/json"} (capture-headers nil)))))

(deftest internal-trust-absence-is-reported-not-silent
  (is (= "x-internal-trust" transact/internal-trust-header))
  (is (= "KOTOBA_INTERNAL_SECRET" transact/internal-trust-env)
      "the same variable the server and the Cloudflare gateway read")
  (with-redefs [transact/internal-trust (constantly nil)]
    (is (= :unconfigured (transact/internal-trust-status))))
  (with-redefs [transact/internal-trust (constantly synthetic-trust)]
    (is (= :configured (transact/internal-trust-status)))))
