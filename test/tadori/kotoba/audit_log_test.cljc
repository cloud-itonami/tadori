(ns tadori.kotoba.audit-log-test
  "Tests for tadori.audit-log (ADR-2605301400 §D1 port). Verifies the silenTadoriReview datom
  flattening, the G12 assert-all-clear halt, the content-address (golden CID pinned to the Python
  output, byte-for-byte verified), make-tx, and the EDN render → read-back → verify-chain round-trip
  (intact + tamper-detected)."
  (:require [clojure.test :refer [deftest is]]
            [kotoba.lang.text :as str]
            [tadori.kotoba.audit-log :as a]))

(defn- clean-review []
  (merge (into {} (map (fn [k] [k 0]) a/counters))
         {"sources-audited" 5 "obs-audited" 12 "obs-without-case" 0}))

(deftest test-review-datoms
  (let [d (a/review-datoms (clean-review) 3)]
    (is (= 17 (count d)))                                        ; 3 head + 9 counters + 5 tail
    (is (= [":db/add" "silen-tadori-review:cycle-3" ":tadori.review/cycle" 3] (first d)))
    (is (every? #(= ":db/add" (first %)) d))                    ; append-only, no :db/retract (G2)
    (is (some #(= % [":db/add" "silen-tadori-review:cycle-3" ":tadori.review/phase" 0]) d))
    (is (some #(= % [":db/add" "silen-tadori-review:cycle-3" ":tadori.review/all-clear" true]) d))
    (is (some #(= % [":db/add" "silen-tadori-review:cycle-3" ":tadori.review/noncase-write" 0]) d))))

(deftest test-assert-all-clear
  (is (nil? (a/assert-all-clear (clean-review))))               ; all zero → passes
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"silenTadoriReview HALT \(G12\)"
                        (a/assert-all-clear (assoc (clean-review) "plaintext-pii" 1)))))

(deftest test-tx-cid-golden-parity
  ;; pinned to the Python tx_cid output (byte-for-byte verified)
  (let [d (a/review-datoms (clean-review) 3)]
    (is (= "b2267accfaf93763c4a3d1f930198e07c5d17b15c1ea702954ea3c919716c0aeb" (a/tx-cid d "")))
    ;; the prev_cid is part of the content address → changing it changes the CID
    (is (not= (a/tx-cid d "") (a/tx-cid d "bdeadbeef")))))

(deftest test-make-tx
  (let [d (a/review-datoms (clean-review) 1)
        tx (a/make-tx d {:tx-id 7 :as-of 1000 :prev-cid "bprev"})]
    (is (= 7 (get tx ":tx/id")))
    (is (= 1000 (get tx ":tx/as-of")))
    (is (= "bprev" (get tx ":tx/prev")))
    (is (= 17 (get tx ":tx/count")))
    (is (= (a/tx-cid d "bprev") (get tx ":tx/cid")))))

(deftest test-edn-roundtrip-and-verify-chain
  (let [d1 (a/review-datoms (clean-review) 1)
        tx1 (a/make-tx d1 {:tx-id 1 :as-of 1000})
        d2 (a/review-datoms (clean-review) 2)
        tx2 (a/make-tx d2 {:tx-id 2 :as-of 2000 :prev-cid (get tx1 ":tx/cid")})
        log-text (str ";; tadori silen-review log — append-only\n"
                      (a/tx-to-edn tx1) "\n" (a/tx-to-edn tx2) "\n")
        txs (a/read-log-string log-text)]
    (is (= 2 (count txs)))
    (is (= (get tx1 ":tx/cid") (get (first txs) ":tx/cid")))    ; EDN round-trips the CID
    (is (= (get tx2 ":tx/cid") (a/head-cid txs)))
    (is (= {"ok" true "length" 2 "broken_at" -1} (a/verify-chain txs)))
    ;; tamper: break the 2nd tx's prev link → verify reports broken at index 1
    (let [tampered (assoc-in txs [1 ":tx/prev"] "bwrong")]
      (is (= {"ok" false "length" 2 "broken_at" 1} (a/verify-chain tampered))))))

(deftest test-edn-roundtrip-preserves-datoms
  (let [d (a/review-datoms (clean-review) 9)
        tx (a/make-tx d {:tx-id 1 :as-of 1})
        txs (a/read-log-string (str (a/tx-to-edn tx) "\n"))]
    ;; datom values survive the EDN round-trip (keywords stay strings, ints stay ints, bool stays bool)
    (is (= d (get (first txs) ":tx/datoms")))))
