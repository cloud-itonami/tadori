#!/usr/bin/env bb
;; tadori 辿 — validation of eth-checksummed? (EIP-55 checksum-PRESENCE detection).
;; Run:  bb --classpath 20-actors 20-actors/tadori/methods/test_address_checksum.cljc
(ns tadori.methods.address-checksum-test
  "Validation of eth-checksummed? — the EIP-55 checksum-PRESENCE detector in tadori's address
  parser, which had no test. It is honestly a presence check, NOT full verification: keccak-256
  (the EIP-55 hash) is not in babashka's stdlib, so the function returns truthy iff a structurally
  valid ETH address carries mixed-case hex (a checksum is present), and falsy for all-lower /
  all-upper / malformed. This pins that contract against the four canonical EIP-55 reference
  addresses AND locks the honest limit: a case-corrupted (but still mixed-case) address still reads
  as 'carrying a checksum' — presence ≠ correctness, so nobody mistakes this for verification."
  (:require [tadori.methods.address :as addr]
            [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is run-tests]]))

(def ^:private eip55-canonical
  ;; the four mixed-case checksummed examples from the EIP-55 spec
  ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
   "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
   "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
   "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"])

(deftest canonical-checksummed-addresses-read-as-carrying-a-checksum
  (doseq [a eip55-canonical]
    (is (addr/valid-eth? a) (str a " is a structurally valid ETH address"))
    (is (boolean (addr/eth-checksummed? a)) (str a " carries a (mixed-case) EIP-55 checksum"))))

(deftest all-lower-and-all-upper-carry-no-checksum
  (doseq [a eip55-canonical]
    (is (not (addr/eth-checksummed? (str/lower a)))
        "an all-lowercase address carries no checksum")
    (is (not (addr/eth-checksummed? (str "0x" (str/upper (subs a 2)))))
        "an all-uppercase address carries no checksum"))
  ;; …yet both are still STRUCTURALLY valid — un-checksummed ≠ invalid
  (is (addr/valid-eth? (str/lower (first eip55-canonical)))
      "an all-lowercase address is still a valid address"))

(deftest malformed-inputs-are-not-checksummed
  (doseq [bad ["" "0x" "0xZZ"
               "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"      ;; missing 0x
               "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe"]]   ;; 39 nibbles, too short
    (is (not (addr/eth-checksummed? bad)) (str "not a checksummed address: " (pr-str bad)))))

(deftest presence-is-not-verification-the-honest-limit
  ;; a deliberately case-corrupted address (swapped case in the first byte) is STILL mixed-case, so
  ;; the presence detector accepts it — EIP-55 CORRECTNESS would reject it, but that needs keccak-256
  ;; (the documented live leg). This locks the limitation so the check is never mistaken for verify.
  (let [corrupted "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"]   ;; canonical 5aA… → 5AA…
    (is (not= corrupted (first eip55-canonical)) "the corrupted address differs from the canonical")
    (is (boolean (addr/eth-checksummed? corrupted))
        "presence detector accepts a case-corrupted address (presence ≠ EIP-55 correctness)")))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'tadori.methods.address-checksum-test)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
