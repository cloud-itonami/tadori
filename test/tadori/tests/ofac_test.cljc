(ns tadori.tests.ofac-test
  "tadori 辿 — OFAC SDN digital-currency-address parse + attributed sanctions ingest.
  ADR-2605301400 §D3. Public primary-source (G4 SoR), non-adjudicating (asserter ofac-sdn)."
  (:require [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [tadori.methods.ofac :as ofac]))

;; A FIXTURE in the legacy OFAC sdn.xml shape (default xmlns), synthetic addresses in valid
;; ETH/BTC format + one unparseable-chain entry to exercise the skip path.
(def ^:private sdn-fixture
  (str "<sdnList xmlns=\"http://tempuri.org/sdnList.xsd\">"
       "<sdnEntry><uid>40000</uid>"
       "<programList><program>CYBER2</program><program>DPRK3</program></programList>"
       "<idList>"
       "<id><uid>1</uid><idType>Digital Currency Address - XBT</idType>"
       "<idNumber>1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2</idNumber></id>"
       "<id><uid>2</uid><idType>Digital Currency Address - ETH</idType>"
       "<idNumber>0xcafebabecafebabecafebabecafebabecafebabe</idNumber></id>"
       "<id><uid>3</uid><idType>Name</idType><idNumber>not-a-currency</idNumber></id>"
       "</idList></sdnEntry>"
       "<sdnEntry><uid>40001</uid>"
       "<programList><program>SDGT</program></programList>"
       "<idList>"
       "<id><uid>4</uid><idType>Digital Currency Address - XMR</idType>"
       "<idNumber>4-malformed-monero-not-validatable</idNumber></id>"
       "</idList></sdnEntry>"
       "</sdnList>"))

(deftest parses-only-currency-ids
  (let [es (ofac/parse-sdn sdn-fixture)]
    (is (= 3 (count es)) "3 Digital-Currency-Address ids (the Name id is ignored)")
    (is (= #{:btc :eth :xmr} (set (map :chain es))))
    (is (= ["CYBER2" "DPRK3"] (:programs (first es))) "programs captured per entry")
    (is (= "40000" (:sdn-uid (first es))))))

(deftest maps-to-attributed-sanctions-records
  (let [{:keys [records skipped]} (ofac/ofac->risk-records (ofac/parse-sdn sdn-fixture) {:as-of 20260601})]
    (is (= 2 (count records)) "btc + eth validate; the malformed XMR address is skipped")
    (is (= 1 skipped))
    (is (every? #(= :sanctions (:risk-class %)) records))
    (is (every? #(= "ofac-sdn" (:asserter %)) records) "attributed to OFAC, never tadori's verdict")
    (is (every? #(= :system-of-record (:source-role %)) records) "public primary source = SoR (G4)")
    (let [ev (:evidence (first records))]
      (is (some #(str/starts-with? % "ofac-sdn-uid:") ev))
      (is (some #(str/starts-with? % "ofac-program:") ev)))))

(deftest emits-non-adjudicating-datoms
  (let [{:keys [datoms count skipped]} (ofac/ofac-datoms sdn-fixture {:as-of 20260601})
        attrs (into {} (map (fn [[_ _ a v]] [a v]) datoms))]
    (is (= 2 count))
    (is (= 1 skipped))
    (is (= ":sanctions" (get attrs ":tadori.risk/class")))
    (is (true? (get attrs ":tadori.risk/non-adjudicating")))
    ;; never contains an identity/de-anon attr — addresses + program refs only
    (is (not-any? #(re-find #"(?i)real-?ip|legal-name|/person" %) (map #(nth % 2) datoms)))))

(deftest empty-list-is-safe
  (is (= {:datoms [] :count 0 :skipped 0}
         (ofac/ofac-datoms "<sdnList xmlns=\"http://tempuri.org/sdnList.xsd\"></sdnList>" {}))))
