(ns tadori.methods.address
  "tadori 辿 — BTC / ETH address validation + chain inference + normalization.
  ADR-2605301400. Pure (no I/O). Used by the risk-ingest + tracing engines to reject
  malformed input before any address becomes a tracked subject.

  Honest limit (R0): cryptographic checksum verification (BTC base58check double-sha256 /
  ETH EIP-55 keccak-256) needs primitives babashka's stdlib does not ship (keccak-256 ≠
  JVM SHA3-256). This module does STRUCTURAL validation (prefix / charset / length) which
  reliably rejects malformed addresses; full checksum verification is the operator/live leg."
  (:require [kotoba.lang.text :as str]))

(def ^:private eth-re #"(?i)0x[0-9a-f]{40}")
(def ^:private btc-base58-re #"[13][1-9A-HJ-NP-Za-km-z]{25,39}")   ;; P2PKH(1) / P2SH(3)
(def ^:private btc-bech32-re #"(?i)bc1[0-9ac-hj-np-z]{11,71}")     ;; segwit v0/v1 (no b,i,o,1)

(defn valid-eth? [a] (boolean (and a (re-matches eth-re (str a)))))
(defn valid-btc? [a]
  (boolean (and a (let [s (str a)] (or (re-matches btc-base58-re s)
                                       (re-matches btc-bech32-re s))))))

(defn eth-checksummed?
  "True iff an ETH address carries EIP-55 mixed-case (a checksum is PRESENT). Note: presence
  is structural; full verification needs keccak-256 (the live leg). All-lower / all-upper = no
  checksum carried (still structurally valid)."
  [a]
  (and (valid-eth? a)
       (let [h (subs (str a) 2)]
         (and (re-find #"[a-f]" h) (re-find #"[A-F]" h)))))

(defn infer-chain
  "Best-effort chain from address shape. :eth | :btc | :unknown."
  [a]
  (cond (valid-eth? a) :eth
        (valid-btc? a) :btc
        :else :unknown))

(defn valid-address?
  "Validate against an asserted chain (or infer). EVM-family chains share the 0x20-byte shape."
  ([a] (not= :unknown (infer-chain a)))
  ([chain a]
   (case (keyword (name (or chain :unknown)))
     (:eth :evm :bsc :polygon :arbitrum :optimism :base) (valid-eth? a)
     :btc (valid-btc? a)
     (not= :unknown (infer-chain a)))))

(defn normalize
  "Canonical form for keying: ETH → lowercase 0x…; BTC → as-is (case-significant)."
  [chain a]
  (let [s (str a)]
    (if (valid-eth? s) (str/lower s) s)))
