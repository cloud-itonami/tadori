(ns tadori.methods.manifest-invariants-test
  "tadori — manifest ↔ artifact invariants (ported from the manifest-reading half of
  70-tools/scripts/audit/test_tadori_invariants.py). Reads the manifest from
  manifest.edn (:actor/manifest blob) — the jsonld is retired. The cell-import +
  lexicon-enum invariants stay in the Python audit suite (they test the Python cell
  scaffolds + lexicon JSONs and do not read the manifest)."
  (:require [clojure.test :refer [deftest is run-tests]]
            [clojure.set :as set]
            [kotoba.lang.text :as str]
            [clojure.edn :as edn]
            [cheshire.core :as json]))

(def ^:private actor-dir (java.io.File. "."))
(def ^:private lexdir (java.io.File. actor-dir "wire/lex"))

(defn- manifest [] (:actor/manifest (edn/read-string (slurp (java.io.File. actor-dir "manifest.edn")))))
(defn- lex [^java.io.File f] (json/parse-string (slurp f)))

(def ^:private cell-names
  ["tadori_case_intake" "tadori_tx_trace" "tadori_address_label"
   "tadori_attribution_join" "tadori_transparent_force_log" "tadori_silen_tadori_review"])

;; ── manifest gates ──
(deftest twelve-gates-present
  (is (= (set (keys (get-in (manifest) ["constitutionalGates" "gates"])))
         (set (map #(str "G" %) (range 1 13))))
      "must pin exactly G1..G12"))

(deftest evidence-only-not-enforcement
  (is (contains? (get (manifest) "capabilityCeiling") "evidenceOnlyNotEnforcement")
      "G7: tadori is evidence-producing; enforcement routes via yabai + Council"))

(deftest lexicon-namespaces-match-the-four-lexicons
  (is (= (set (get (manifest) "lexiconNamespaces"))
         #{"com.etzhayyim.tadori.caseMandate"
           "com.etzhayyim.tadori.attributionFinding"
           "com.etzhayyim.tadori.traceReport"
           "com.etzhayyim.tadori.silenTadoriReview"})
      "manifest lexiconNamespaces must match the 4 shipped Lexicons"))

;; ── manifest ↔ on-disk artifact consistency (drift guards) ──
(deftest namespaces-match-disk-lexicon-files-bidirectionally
  (let [declared (set (map #(last (str/split % #"\.")) (get (manifest) "lexiconNamespaces")))
        on-disk  (set (->> (.listFiles lexdir)
                           (map #(.getName ^java.io.File %))
                           (filter #(str/ends-with? % ".json"))
                           (map #(subs % 0 (- (count %) 5)))))]
    (is (= declared on-disk)
        (str "manifest namespaces vs disk lexicons drifted: "
             (set/difference declared on-disk) " / " (set/difference on-disk declared)))))

(deftest each-lexicon-id-matches-its-namespace
  (doseq [^java.io.File f (->> (.listFiles lexdir)
                               (filter #(str/ends-with? (.getName ^java.io.File %) ".json")))]
    (let [stem (let [n (.getName f)] (subs n 0 (- (count n) 5)))]
      (is (= (get (lex f) "id") (str "com.etzhayyim.tadori." stem))
          (str (.getName f) ": lexicon id must match its filename + namespace")))))

(deftest manifest-cell-modules-match-cell-dirs
  (let [modules  (set (map #(get % "module") (get (manifest) "cells")))
        expected (set (map #(str "kotodama.cells." %) cell-names))]
    (is (= modules expected)
        (str "manifest cell modules vs dirs drifted: " (set/difference modules expected)))))

(deftest did-is-consistent-across-artifacts
  (let [m (manifest)]
    (is (= (get m "id") "did:web:tadori.etzhayyim.com"))
    (is (= (get m "name") "tadori"))
    (is (= (get m "tier") "Tier-B"))))

(defn -main [& _]
  (let [r (run-tests 'tadori.methods.manifest-invariants-test)]
    (System/exit (if (zero? (+ (:fail r) (:error r))) 0 1))))
