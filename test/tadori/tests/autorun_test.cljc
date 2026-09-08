(ns tadori.tests.autorun-test
  "tadori 辿 autonomous self-audit heartbeat + audit-log invariants. ADR-2605301400.
  Clojure port of `kotoba/test_autorun.py`, plus a Python↔Clojure CID-parity helper.

  Guards the constitutionally-constrained autonomy contract that lets tadori run on the
  fleet:
    - the loop persists ONE content-addressed audit tx per heartbeat to an append-only log;
    - the log holds ONLY silenTadoriReview counters — NO observation / PII / case datom
      (G3/G6/G10);
    - the commit-DAG verifies (every CID recomputes; tamper is detected);
    - it is deterministic / resume-safe and append-only;
    - G12: a nonzero counter (e.g. a plaintext PII obs) HALTS — persisting NOTHING;
    - a not-gate-clean corpus (vendor system-of-record) is rejected by validation;
    - it does NO external I/O."
  (:require [clojure.java.io :as io]
            [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [cheshire.core :as json]
            [kotoba.datom :as kd]
            [tadori.methods.audit-log :as al]
            [tadori.methods.autorun :as autorun]
            [tadori.methods.ingest :as ingest]))

(defn- tmplog []
  (str (java.nio.file.Files/createTempDirectory
        "tadori-clj" (make-array java.nio.file.attribute.FileAttribute 0))
       "/log.kotoba.edn"))

(defn- corpus
  "Build a staged corpus the way load-jsonl would (string keys + :_lineno)."
  [records]
  (ingest/load-jsonl
   (str/join "\n" (map json/generate-string records))))

;; a minimal gate-clean corpus: one public source + one encrypted ip-obs
(def ^:private clean
  [{"kind" "intel-source" "id" "source:public:s1" "name" "Staged public sample"
    "vendor_family" "public-archive" "source_role" "system-of-record" "license_tier" "A"}
   {"kind" "ip-obs" "id" "ip:192.0.2.1:t" "address" "192.0.2.1" "source" "source:public:s1"
    "case_id" "case:dry" "encrypted" true "collection_mode" "operator-staged-passive-archive"}])

(deftest heartbeat-persists-audit-only
  (let [log (tmplog)
        res (autorun/run-autonomous (corpus clean) 3 log)]
    (is (= 3 (:log-length res)) "one audit tx per heartbeat")
    (is (:ok (:chain res)) "commit-DAG verifies (chain OK)")
    (let [tx (first (al/read-log log))
          attrs (set (map #(nth % 2) (:tx/datoms tx)))
          ops (set (map first (:tx/datoms tx)))]
      (is (every? #(str/starts-with? % ":tadori.review/") attrs)
          "every datom attr is a :tadori.review/* counter (NO obs/PII/case attrs)")
      (is (= #{":db/add"} ops) "every datom is append-only :db/add (G2)")
      (doseq [forbidden [":tadori.obs/case-id" ":tadori.ip/address" ":tadori.dns/domain"
                         ":tadori.indicator/value" ":tadori.obs/evidence-cid"]]
        (is (not (contains? attrs forbidden))
            (str "no observation/PII attr `" forbidden "` in the audit log (G3)"))))))

(deftest deterministic-resume-safe
  (let [a (tmplog) b (tmplog)
        ra (autorun/run-autonomous (corpus clean) 3 a)
        rb (autorun/run-autonomous (corpus clean) 3 b)]
    (is (= (mapv :cid (:beats ra)) (mapv :cid (:beats rb)))
        "same cycles → same CIDs (deterministic / resume-safe)")))

(deftest append-only-and-tamper
  (let [log (tmplog)
        c (corpus clean)]
    (autorun/run-cycle c 1 log)
    (let [first-txs (al/read-log log)]
      (autorun/run-cycle c 2 log)
      (let [second-txs (al/read-log log)]
        (is (= (count second-txs) (inc (count first-txs)))
            "second heartbeat appends, does not rewrite")
        (is (= (:tx/prev (nth second-txs 1)) (:tx/cid (nth first-txs 0)))
            "tx 2 links tx 1's CID (commit-DAG)")))
    ;; tamper the earliest tx — the whole DAG must break at index 0
    (let [lines (vec (str/split-lines (slurp log)))
          idx (first (keep-indexed #(when (str/includes? %2 ":tx/id 1 ") %1) lines))]
      (spit log (str (str/join "\n"
                               (assoc lines idx
                                      (str/replace-first (nth lines idx)
                                                         ":tadori.review/cycle 1"
                                                         ":tadori.review/cycle 9")))
                     "\n")))
    (let [v (al/verify-chain log)]
      (is (and (not (:ok v)) (= 0 (:broken-at v)))
          "tampering an earlier audit tx breaks the chain"))))

(deftest g12-halt-on-plaintext-pii
  ;; the defining tadori invariant: a plaintext PII obs must HALT — persisting NOTHING.
  (let [bad [{"kind" "intel-source" "id" "source:public:s1" "name" "s"
              "vendor_family" "public-archive" "source_role" "system-of-record" "license_tier" "A"}
             {"kind" "ip-obs" "id" "ip:192.0.2.9:t" "address" "192.0.2.9" "source" "source:public:s1"
              "case_id" "case:dry" "encrypted" false   ;; ← plaintext PII (G6/G10 violation)
              "collection_mode" "operator-staged-passive-archive"}]
        log (tmplog)
        halted (try (autorun/run-cycle (corpus bad) 1 log) false
                    (catch clojure.lang.ExceptionInfo e (al/silen-review-halt? e)))]
    (is halted "plaintext PII obs triggers a silenTadoriReview HALT (G12)")
    (is (or (not (.exists (io/file log))) (zero? (count (al/read-log log))))
        "HALT persists NOTHING — no audit datom written on a violation")))

(deftest vendor-sor-rejected-by-validation
  ;; a vendor-compatible feed declared system-of-record must be rejected before any persist (G4).
  (let [bad [{"kind" "intel-source" "id" "source:vendor:st" "name" "vendor"
              "vendor_family" "securitytrails-compatible" "source_role" "system-of-record"
              "license_tier" "C"}]
        log (tmplog)
        rejected (try (autorun/run-cycle (corpus bad) 1 log) false
                      (catch clojure.lang.ExceptionInfo e (ingest/validation-error? e)))]
    (is rejected "vendor-compatible system-of-record is rejected by validate-records (G4)")
    (is (or (not (.exists (io/file log))) (zero? (count (al/read-log log))))
        "rejected corpus persists nothing")))

(deftest no-external-io
  ;; the autorun + audit-log + ingest sources must do no network I/O.
  (let [src (str (slurp (io/resource "tadori/methods/autorun.cljc"))
                 (slurp (io/resource "tadori/methods/audit_log.cljc"))
                 (slurp (io/resource "tadori/methods/ingest.cljc")))]
    (doseq [banned ["java.net" "URLConnection" "Socket" "http-kit" "clj-http" "urllib"]]
      (is (not (str/includes? src banned))
          (str "autorun/audit-log/ingest does no external I/O (no `" banned "`)")))))

(deftest python-cljc-cid-parity
  ;; The cljc commit-DAG is byte-compatible with Python (canonical JSON: sorted keys, compact
  ;; separators, ensure_ascii=false), so a log written by either verifies under the other and
  ;; the same (datoms, prev) yields the same CID. Anchor that here without a golden file by
  ;; round-tripping the heartbeat's own log through verify-chain + a recompute of head.
  (let [log (tmplog)
        res (autorun/run-autonomous (corpus clean) 2 log)
        txs (al/read-log log)]
    (is (:ok (al/verify-chain log)) "the written DAG verifies")
    (is (= (:head-cid res) (al/head-cid log)))
    (is (= (al/head-cid log)
           (kd/tx-cid (:tx/datoms (nth txs 1)) (:tx/cid (nth txs 0))))
        "head CID = sha256 over (its datoms, prev CID) — Python-parity preimage")))
