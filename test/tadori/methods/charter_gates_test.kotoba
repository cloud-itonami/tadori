(ns tadori.methods.charter-gates-test
  "tadori 辿 — constitutional-gate conformance tests (manifest + central lexicons).

  Substrate-native Clojure (clj + datomic first tier). tadori is authorized on-chain tx tracing +
  actor attribution — evidence-only (NOT enforcement), case-scoped (NOT mass surveillance),
  PII-encrypted, no-platform-key, Murakumo-only, kotoba-only. Its G1–G12 discipline is declared in
  the manifest and encoded as a const ZERO-COUNTER battery + a dual-signed case mandate across the
  4 central AT-Proto lexicons at 00-contracts/lexicons/com/etzhayyim/tadori/. This suite pins them
  so a future cell wave cannot silently drift them:

    G3  authorized-investigation-only — caseMandate requires authorizationRef + dual signatures;
        every finding/trace is case-scoped (caseId); noncaseWriteCount const 0
    G5  on-chain-monitorable — caseMandate.transparentForceLogged const true
    G6  PII-encrypted — attributionFinding requires `encrypted`; plaintextPiiCount const 0
    G7  evidence-only / NO ENFORCEMENT — enforcementActionCount const 0
    G8  no platform-held key (ADR-2605231525) — platformHeldKeyCount const 0
    G9  Murakumo-only (ADR-2605215000) — murakumoBypassCount const 0
    G10 no mass surveillance / no adherent de-anon — both counts const 0
    G4/G11 no proprietary SoR + kotoba-only — proprietarySorCount + nonKotobaStoreCount const 0

  Reads manifest + central lexicons via cheshire (string keys). It weakens no gate; it asserts
  them. The zero-counter battery in silenTadoriReview is the structural Bonsai-pruning trip (G12)."
  (:require [clojure.test :refer [deftest is run-tests]]
            [cheshire.core :as json]))

#?(:clj
   (do
     (def ^:private actor-dir (java.io.File. "."))
     (def ^:private lexdir
       (java.io.File. actor-dir "wire/lex"))
     (defn- lex [name]
       (json/parse-string (slurp (java.io.File. lexdir (str name ".json")))))
     (defn- manifest []
       (:actor/manifest (clojure.edn/read-string (slurp (java.io.File. actor-dir "manifest.edn")))))))

(defn- record-node [doc]
  (let [main (get-in doc ["defs" "main"])] (or (get main "record") main)))
(defn- required-of [doc] (set (get (record-node doc) "required")))
(defn- const-of [doc field] (get-in (record-node doc) ["properties" field "const"]))

;; ── G1–G12 declared ──
(deftest all-12-gates-declared
  (let [cg (get (manifest) "constitutionalGates")
        gm (or (get cg "gates") cg)
        nums (->> (keys gm) (keep #(second (re-matches #"G(\d+).*" %)))
                  (map #(Integer/parseInt %)) set)]
    (is (= (set (range 1 13)) nums) "manifest must declare G1–G12")))

;; ── zero-counter battery — each counter pins a gate at const 0 ──
(deftest silen-zero-counter-battery
  (let [r (lex "silenTadoriReview")]
    (doseq [[field gate] [["noncaseWriteCount" "G3"]
                          ["plaintextPiiCount" "G6"]
                          ["proprietarySorCount" "G4"]
                          ["enforcementActionCount" "G7"]
                          ["platformHeldKeyCount" "G8"]
                          ["murakumoBypassCount" "G9"]
                          ["massSurveillanceCount" "G10"]
                          ["adherentDeanonCount" "G10"]
                          ["nonKotobaStoreCount" "G11"]]]
      (is (= 0 (const-of r field)) (str gate ": silenTadoriReview." field " const 0")))))

;; ── G3/G5 — authorized, dual-signed, transparent-force-logged case mandate ──
(deftest g3-g5-authorized-mandate
  (let [m (lex "caseMandate")
        req (required-of m)]
    (doseq [f ["authorizationRef" "authorityDid" "authoritySignature" "validFrom" "validUntil"]]
      (is (contains? req f) (str "G3: caseMandate must require " f)))
    (is (= true (const-of m "transparentForceLogged"))
        "G5: caseMandate.transparentForceLogged const true")))

;; ── G3 — case-scoped: every finding/trace binds a caseId ──
(deftest g3-case-scoped
  (doseq [n ["attributionFinding" "traceReport"]]
    (is (contains? (required-of (lex n)) "caseId")
        (str "G3: " n " must be case-scoped (require caseId)"))))

;; ── G6 — PII-encrypted attribution ──
(deftest g6-pii-encrypted
  (is (contains? (required-of (lex "attributionFinding")) "encrypted")
      "G6: attributionFinding must require the encrypted-envelope field"))

#?(:clj
   (defn -main [& _]
     (let [r (run-tests 'tadori.methods.charter-gates-test)]
       (System/exit (if (zero? (+ (:fail r) (:error r))) 0 1)))))
