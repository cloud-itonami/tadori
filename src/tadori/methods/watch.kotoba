(ns tadori.methods.watch
  "tadori 辿 — the CONTINUOUS watch loop: 追跡し続ける・記録し続ける・分析し続ける.
  ADR-2605301400 + Charter §1.12 (Transparent Force) + Tier-0 永久記憶/相互監視.

  One cycle: ingest high-risk/scam/sanctioned addresses + adversary (attack/surveil/hidden-
  influence) observations → score + cluster-propagate + hidden-influence concentration →
  append ONE content-addressed transaction to the append-only PUBLIC ledger (永久記憶, no
  erasure; commit-DAG, tamper-evident). Reflexively, the watcher writes itself into the ledger
  (watch-the-watchers) so it can never become a hidden throne (NEVER-a-throne).

  Public ledger = disclosed indicators + behaviors + AGGREGATE concentration only. No PII, no
  identity, no de-anon — those live ONLY as encrypted, case-gated attribution edges
  (methods/attribution, G6). So this loop runs autonomously (public-indicator scope, like
  ipaddress/yabai); the 公開 (external publish) + person-linkage stay operator/Council-gated.

  Deterministic / resume-safe (cycle drives tx-id + as-of). Pure analysis; file I/O only at
  the #?(:clj) append edge."
  (:require [kotoba.datom :as kd]
            [tadori.methods.adversary :as adv]
            [tadori.methods.risk :as risk]
            [tadori.methods.trace :as trace]
            #?(:clj [clojure.java.io :as io])))

(def base-as-of 20260617)

(defn analyze
  "Pure analysis over a watch batch: {:risk-labels [...] :adversaries [...] :txs [...]}.
  Returns scores + cluster risk + hidden-influence concentration + adversary tally."
  [{:keys [risk-labels adversaries txs] :or {risk-labels [] adversaries [] txs []}}]
  (let [scored (risk/score-addresses risk-labels)
        addr->cid (trace/cluster txs {})
        cluster-risk (risk/propagate-to-clusters addr->cid scored)
        concentration (risk/hidden-influence cluster-risk)]
    {:scored scored
     :cluster-risk cluster-risk
     :concentration concentration
     :adversary-count (count adversaries)
     :risk-count (count risk-labels)}))

(defn cycle-datoms
  "All append-only datoms for one watch cycle: risk labels + adversary observations +
  hidden-influence concentration summary + the reflexive self-watch (watcher-is-watched)."
  [{:keys [risk-labels adversaries] :or {risk-labels [] adversaries []}} analysis cycle]
  (vec (concat
        (mapcat risk/risk-label-datoms risk-labels)
        (mapcat adv/observation-datoms adversaries)
        ;; aggregate hidden-influence concentration (map-not-target; counts + scores only)
        (mapcat (fn [{:keys [cluster concentration tainted score]}]
                  (let [e (str "concentration:" cluster ":cycle-" cycle)]
                    [(kd/add e ":tadori.concentration/cluster" cluster)
                     (kd/add e ":tadori.concentration/score" concentration)
                     (kd/add e ":tadori.concentration/tainted-count" tainted)
                     (kd/add e ":tadori.concentration/peak-severity" score)]))
                (take 25 (:concentration analysis)))   ;; G5 capped, top-first
        (adv/watch-the-watchers cycle))))

#?(:clj
   (def log-default
     (-> *file* io/file .getParentFile .getParentFile
         (io/file "data" "persisted" "tadori.watch.datoms.kotoba.edn"))))

#?(:clj
   (defn run-cycle
     "One watch heartbeat → append ONE content-addressed tx to the append-only public ledger.
     Returns {:cycle :analysis :datoms :cid}. Deterministic (cycle drives tx-id + as-of)."
     [batch cycle log-path]
     (let [analysis (analyze batch)
           datoms (cycle-datoms batch analysis cycle)
           tx (kd/make-tx datoms {:tx-id cycle :as-of (+ base-as-of cycle)
                                  :prev-cid (kd/head-cid log-path)})
           cid (kd/append-tx! tx log-path)]
       {:cycle cycle :analysis analysis :datoms (count datoms) :cid cid})))

#?(:clj
   (defn run-continuous
     "N watch cycles over one append-only ledger; returns the chain summary."
     [batch cycles log-path]
     (let [beats (mapv #(run-cycle batch % log-path) (range 1 (inc cycles)))]
       {:cycles cycles :beats beats
        :head-cid (kd/head-cid log-path)
        :chain (kd/verify-chain log-path)})))

;; ── SYNTHETIC watch batch (all FICTIONAL documentation-style addresses) ───────
(def ^:private SCAM "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
(def ^:private SANCT "0xcafebabecafebabecafebabecafebabecafebabe")
(def ^:private MIX   "0xfeedface00000000000000000000000000000000")
(def ^:private CEX   "0x1234567890abcdef1234567890abcdef12345678")

(def demo-batch
  {:risk-labels
   [{:address SCAM :chain :eth :risk-class :scam :asserter "source:public-archive:cryptoscamdb"
     :as-of 20260601 :source-role :system-of-record :confidence 800}
    {:address SCAM :chain :eth :risk-class :phishing :asserter "source:public-archive:chainabuse"
     :as-of 20260605 :source-role :system-of-record :confidence 700}      ;; 2nd asserter ⇒ corroborated
    {:address SANCT :chain :eth :risk-class :sanctions :asserter "source:public-archive:ofac-sdn"
     :as-of 20260520 :source-role :system-of-record :confidence 1000}
    {:address MIX :chain :eth :risk-class :mixer :asserter "source:public-archive:tornado-list"
     :as-of 20260510 :source-role :system-of-record :confidence 600}
    {:address "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" :chain :btc :risk-class :ransomware
     :asserter "source:public-archive:ransomwhere" :as-of 20260609 :source-role :system-of-record :confidence 900}]
   :adversaries
   [{:adversary-id "adv-2606170900" :behavior :attack :address SCAM :chain :eth
     :source "operator:incident-2026-06-17" :observed-at 20260617 :target "kotoba-node" :confidence 850}
    {:adversary-id "adv-hidden-001" :behavior :hidden-influence :address SANCT :chain :eth
     :source "tsumugi:concentration-observe" :observed-at 20260617 :confidence 600}]
   ;; on-chain txs that pull the scam + mixer into one traced neighbourhood
   :txs
   [{:tx-hash "w1" :from SCAM :to MIX :value 1 :inputs [SCAM "0x0000000000000000000000000000000000000aaa"] :ts 1}
    {:tx-hash "w2" :from MIX :to CEX :value 1 :ts 2}
    {:tx-hash "w3" :from SANCT :to MIX :value 1 :ts 3}]})

#?(:clj
   (defn -main
     "Run the CONTINUOUS watch loop over the SYNTHETIC batch (no live data). Args: [cycles] [log]."
     [& args]
     (let [cycles (if (first args) (parse-long (first args)) 3)
           log (if (second args) (second args) (str log-default))
           res (run-continuous demo-batch cycles log)
           a (analyze demo-batch)]
       (println "# tadori — CONTINUOUS watch loop (SYNTHETIC; 相互監視 / 永久記憶 / NEVER-a-throne)\n")
       (println (format "  ingested: %d risk labels (attributed, non-adjudicating) · %d adversary observations"
                        (:risk-count a) (:adversary-count a)))
       (println (format "  hidden-influence concentration (取, map-not-target, top 3):"))
       (doseq [c (take 3 (:concentration a))]
         (println (format "    · cluster %s — concentration %d (%d tainted addr, peak severity %d, %s)"
                          (:cluster c) (:concentration c) (:tainted c) (:score c) (vec (:classes c)))))
       (println (format "\n  ledger: %d tx · head %s… · chain %s · watcher-is-watched ✓ (silenTadoriReview)"
                        (:cycles res) (subs (:head-cid res) 0 (min 14 (count (:head-cid res))))
                        (if (:ok (:chain res)) "OK ✓" "BROKEN")))
       (println "  公開 (external publish) + person-linkage stay operator/Council-gated; person data NEVER inline (G1/G6/G10)"))))
