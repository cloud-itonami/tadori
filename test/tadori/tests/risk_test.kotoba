(ns tadori.tests.risk-test
  "tadori 辿 — high-risk/scam ingest + risk propagation + hidden-influence + watch-the-watchers.
  ADR-2605301400. Doctrine test-bound: non-adjudicating (attributed), G4 SoR, G6/G10 no-deanon,
  reciprocal/transparent, append-only 永久記憶."
  (:require [clojure.java.io :as io]
            [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [kotoba.datom :as kd]
            [tadori.methods.address :as addr]
            [tadori.methods.adversary :as adv]
            [tadori.methods.risk :as risk]
            [tadori.methods.watch :as watch]))

(defn- threw? [tag f] (try (f) false (catch clojure.lang.ExceptionInfo e (= tag (:tadori/error (ex-data e))))))
(defn- tmplog [] (str (java.nio.file.Files/createTempDirectory
                       "tadori-risk" (make-array java.nio.file.attribute.FileAttribute 0)) "/log.edn"))

;; ── address validation ────────────────────────────────────────────────────────

(deftest eth-btc-validation
  (is (addr/valid-eth? "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
  (is (not (addr/valid-eth? "0xnothex")))
  (is (not (addr/valid-eth? "0xdead")))                     ;; too short
  (is (addr/valid-btc? "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
  (is (addr/valid-btc? "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"))
  (is (not (addr/valid-btc? "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")))
  (is (= :eth (addr/infer-chain "0xcafebabecafebabecafebabecafebabecafebabe")))
  (is (= :btc (addr/infer-chain "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")))
  (is (= :unknown (addr/infer-chain "garbage"))))

;; ── risk ingest: attributed + non-adjudicating + G4 ───────────────────────────

(deftest risk-label-is-attributed-non-adjudicating
  (let [ds (risk/risk-label-datoms
            {:address "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" :chain :eth :risk-class :scam
             :asserter "source:public:cryptoscamdb" :as-of 20260601 :source-role :system-of-record})
        m (into {} (map (fn [[_ _ a v]] [a v]) ds))]
    (is (= "source:public:cryptoscamdb" (get m ":tadori.risk/asserter")) "records WHO listed it")
    (is (true? (get m ":tadori.risk/non-adjudicating")) "never tadori's own verdict")
    (is (= ":scam" (get m ":tadori.risk/class")))))

(deftest risk-needs-an-asserter
  ;; G7 non-adjudicating: tadori cannot self-assert a risk label
  (is (threw? :risk #(risk/risk-label-datoms
                      {:address "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" :chain :eth
                       :risk-class :scam :asserter ""}))))

(deftest g4-vendor-cannot-be-sor
  (is (threw? :risk #(risk/validate-risk-record
                      {:address "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" :chain :eth :risk-class :scam
                       :asserter "vendor" :vendor-family :chainalysis-compatible :source-role :system-of-record})))
  ;; same vendor as feature-flagged-input is fine
  (is (map? (risk/validate-risk-record
             {:address "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" :chain :eth :risk-class :scam
              :asserter "vendor" :vendor-family :chainalysis-compatible :source-role :feature-flagged-input}))))

(deftest invalid-address-rejected
  (is (threw? :risk #(risk/risk-label-datoms
                      {:address "not-an-address" :chain :eth :risk-class :scam :asserter "x"}))))

;; ── scoring + corroboration + concentration ───────────────────────────────────

(deftest corroboration-raises-score-not-guilt
  (let [one (risk/score-addresses [{:address "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" :chain :eth
                                    :risk-class :scam :asserter "s1"}])
        two (risk/score-addresses [{:address "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" :chain :eth
                                    :risk-class :scam :asserter "s1"}
                                   {:address "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" :chain :eth
                                    :risk-class :scam :asserter "s2"}])
        a "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    (is (> (get-in two [a :score]) (get-in one [a :score])) "more independent asserters ⇒ more corroborated")
    (is (= 2 (count (get-in two [a :asserters]))))))

(deftest hidden-influence-ranks-concentration
  (let [a (watch/analyze watch/demo-batch)
        top (first (:concentration a))]
    (is (pos? (:concentration top)) "a cluster concentrating risk surfaces (取, map-not-target)")
    (is (every? #(>= (:concentration (first (:concentration a))) (:concentration %)) (:concentration a)))))

;; ── adversary / watch-the-watchers: no de-anon, reciprocal ────────────────────

(deftest adversary-observation-is-reciprocal-public
  (let [ds (adv/observation-datoms
            {:adversary-id "adv-1" :behavior :attack :address "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
             :chain :eth :source "operator:incident"})
        m (into {} (map (fn [[_ _ a v]] [a v]) ds))]
    (is (true? (get m ":tadori.adversary/reciprocal")) "the attacker is seen by the same light (相互監視)")
    (is (true? (get m ":tadori.adversary/non-adjudicating")))
    (is (= ":attack" (get m ":tadori.adversary/behavior")))))

(deftest adversary-rejects-identity-and-deanon-fields
  ;; G1/G10: an adversary observation cannot carry an identity / de-anon field inline
  (doseq [k [:real-ip :identity :legal-name :person :home-address :geoloc]]
    (is (threw? :adversary #(adv/observation-datoms
                             {:adversary-id "a" :behavior :attack :source "s" k "X"}))
        (str "rejects inline " k)))
  ;; a retaliation/enforcement "behavior" is not in the enum (response is record, not revenge)
  (is (threw? :adversary #(adv/observation-datoms
                           {:adversary-id "a" :behavior :counterattack :source "s"}))))

(deftest watch-the-watchers-is-reflexive
  (let [ds (adv/watch-the-watchers 1)
        attrs (set (map #(nth % 2) ds))]
    (is (contains? attrs ":tadori.adversary/self-watch") "the watcher writes itself into the ledger")
    (is (contains? attrs ":tadori.adversary/watcher-is-watched"))))

;; ── continuous append-only ledger (永久記憶) ──────────────────────────────────

(deftest watch-loop-appends-and-verifies
  (let [log (tmplog)
        res (watch/run-continuous watch/demo-batch 3 log)]
    (is (= 3 (:cycles res)))
    (is (:ok (:chain res)) "append-only commit-DAG verifies (tamper-evident)")
    (is (= 3 (count (kd/read-log log))))))

(deftest watch-loop-deterministic
  (let [a (tmplog) b (tmplog)]
    (is (= (mapv :cid (:beats (watch/run-continuous watch/demo-batch 2 a)))
           (mapv :cid (:beats (watch/run-continuous watch/demo-batch 2 b))))
        "same batch + cycle ⇒ same CIDs (resume-safe)")))

(deftest ledger-holds-no-identity
  ;; the PUBLIC ledger never contains an identity/de-anon attribute (person-linkage is the
  ;; separate encrypted attribution edge, G6)
  (let [log (tmplog)]
    (watch/run-continuous watch/demo-batch 1 log)
    (let [attrs (set (mapcat (fn [tx] (map #(nth % 2) (:tx/datoms tx))) (kd/read-log log)))]
      (is (not-any? #(re-find #"(?i)real-?ip|identity|legal-name|home-address|geoloc|/person" %) attrs)))))
