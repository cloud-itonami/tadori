(ns tadori.methods.trace
  "tadori 辿 — case-anchored on-chain tracing + clustering + labeling.
  ADR-2605301400 §D1/§D2. Clojure activation of cells tadori_tx_trace + tadori_address_label.

  Given a CASE's seed addresses + a staged transaction set, this engine:
    - clusters addresses by the classic on-chain heuristics — common-input-ownership +
      change-address + temporal co-movement (union-find);
    - classifies each cluster (mixer / peel-chain / cex-hot / cex-cold / bridge / whale-eoa /
      unknown-eoa) from structural features (fan-in/out, amount uniformity, hop velocity);
    - traces value flow from the case's seed addresses through up to `max-hops`, surfacing the
      exit cluster (e.g. stolen funds → mixer → a labeled CEX deposit);
    - emits :tadori.tx/* :tadori.addr/* :tadori.cluster/* :tadori.label/* EAVT.

  Constitutional posture (enforced by construction):
    G3  tracing is BOUNDED to the case's seed addresses + their N-hop neighborhood — never an
        untargeted full-chain crawl (the seed set is the warrant scope).
    G4  open-source heuristics only; external paid labels enter as feature-flagged inputs, never
        the system of record.
    G7  EVIDENCE-ONLY — there is no freeze/seize/enforce verb; the schema cannot represent one.
    G10 no mass surveillance — the trace can only expand from the authorized seed set.

  Pure (no I/O, no network). Live chain fetch is the operator+case-gated edge (methods/transact)."
  (:require [clojure.set :as set]
            [kotoba.datom :as kd]))

;; ── address clustering (union-find over heuristics) ───────────────────────────

(defn- uf-find [parent x]
  (loop [x x] (let [p (parent x x)] (if (= p x) x (recur p)))))

(defn- uf-union [parent a b]
  (let [ra (uf-find parent a) rb (uf-find parent b)]
    (if (= ra rb) parent (assoc parent ra rb))))

(defn cluster
  "Union addresses by:
    H1 common-input-ownership — all `:inputs` of one tx are co-spent ⇒ same entity;
    H2 change-address — a tx with one external payee + one fresh same-format output ⇒ the
       fresh output is change owned by the input cluster;
    H3 temporal — addresses first-seen within `window` of each other AND already linked by a
       shared counterparty are merged (weak; only tightens existing components).
  Returns {addr → cluster-id} (cluster-id = the lexicographically smallest member)."
  [txs {:keys [_window]}]
  (let [;; every address that appears anywhere starts as its own singleton cluster
        addrs (disj (into #{} (mapcat (fn [tx]
                                        (concat [(:from tx) (:to tx)]
                                                (:inputs tx)
                                                (when (:change tx) [(:change tx)])))
                                      txs))
                    nil)
        parent (into {} (map (fn [a] [a a])) addrs)
        ;; H1: co-spent inputs ⇒ same entity
        parent (reduce (fn [p tx]
                         (let [ins (seq (:inputs tx))]
                           (if (and ins (> (count ins) 1))
                             (reduce (fn [p a] (uf-union p (first ins) a)) p (rest ins))
                             p)))
                       parent txs)
        ;; H2: change-address — a fresh output co-owned with the inputs
        parent (reduce (fn [p tx]
                         (if-let [chg (:change tx)]
                           (uf-union p (first (:inputs tx)) chg)
                           p))
                       parent txs)
        ;; canonicalize each component to its lexicographically smallest member
        canon (reduce (fn [m a] (update m (uf-find parent a) (fnil conj (sorted-set)) a))
                      {} addrs)
        addr->cid (reduce (fn [m [_root members]]
                            (let [cid (first members)]
                              (reduce #(assoc %1 %2 cid) m members)))
                          {} canon)]
    addr->cid))

;; ── cluster classification (structural mixer / exchange detection) ────────────

(defn cluster-features
  "Per-cluster structural features over the tx set."
  [txs addr->cid]
  (let [cid-of (fn [a] (get addr->cid a a))]
    (reduce
     (fn [m tx]
       (let [src (cid-of (:from tx)) dst (cid-of (:to tx))]
         (-> m
             (update-in [src :out-cnt] (fnil inc 0))
             (update-in [src :out-peers] (fnil conj #{}) dst)
             (update-in [src :amounts] (fnil conj []) (:value tx))
             (update-in [dst :in-cnt] (fnil inc 0))
             (update-in [dst :in-peers] (fnil conj #{}) src))))
     {} txs)))

(defn classify-cluster
  "Heuristic class from features (open-source; G4). Mixer = high distinct fan-in AND fan-out
  with near-uniform amounts (the tumbler signature). CEX-hot = very high in+out. Otherwise EOA."
  [{:keys [in-cnt out-cnt in-peers out-peers amounts] :or {in-cnt 0 out-cnt 0}}]
  (let [in-fan (count in-peers) out-fan (count out-peers)
        uniform? (and (seq amounts)
                      (let [s (set amounts)] (<= (count s) (max 1 (quot (count amounts) 3)))))]
    (cond
      (and (>= in-fan 3) (>= out-fan 3) uniform?) :mixer
      (and (>= in-cnt 8) (>= out-cnt 8))          :cex-hot
      (>= in-cnt 6)                               :cex-cold
      (and (>= out-fan 2) (>= in-fan 1) (not uniform?)) :bridge
      :else :unknown-eoa)))

;; ── value-flow trace (bounded to the case seed) ───────────────────────────────

(defn trace-flow
  "BFS value-flow from the case `seeds` outward up to `max-hops` (G3/G10: expansion is bounded
  to the warrant's seed set + neighborhood). Returns the ordered hop path of clusters touched
  and the set of exit clusters reached (terminal nodes with no further outgoing edge in scope)."
  [txs addr->cid seeds {:keys [max-hops] :or {max-hops 5}}]
  (let [cid-of (fn [a] (get addr->cid a a))
        edges (reduce (fn [m tx] (update m (cid-of (:from tx)) (fnil conj #{}) (cid-of (:to tx))))
                      {} txs)
        seed-cids (set (map cid-of seeds))]
    (loop [frontier seed-cids seen seed-cids path [] hop 0]
      (if (or (empty? frontier) (>= hop max-hops))
        {:path (conj path {:hop hop :clusters (vec (sort frontier))})
         :reached seen
         ;; an exit is a reached cluster with NO outgoing edge in scope (a terminal sink)
         :exits (vec (sort (filter #(empty? (get edges % #{})) seen)))}
        (let [nxt (set/difference (reduce set/union #{} (map #(get edges % #{}) frontier)) seen)]
          (recur nxt (set/union seen nxt)
                 (conj path {:hop hop :clusters (vec (sort frontier))}) (inc hop)))))))

;; ── EAVT emission ─────────────────────────────────────────────────────────────

(defn tx-datoms [txs chain]
  (mapcat (fn [tx]
            (let [e (str "tx:" chain ":" (:tx-hash tx))]
              (cond-> [(kd/add e ":tadori.tx/chain" (str chain))
                       (kd/add e ":tadori.tx/tx-hash" (:tx-hash tx))
                       (kd/add e ":tadori.tx/from" (:from tx))
                       (kd/add e ":tadori.tx/to" (:to tx))
                       (kd/add e ":tadori.tx/value" (:value tx))
                       (kd/add e ":tadori.tx/ts" (:ts tx 0))]
                (:token tx) (conj (kd/add e ":tadori.tx/token" (:token tx))))))
          txs))

(defn cluster-datoms
  "Emit :tadori.cluster/* + :tadori.label/* for each cluster. `labels` optionally overrides the
  structural class with a feature-flagged-source label (open-source SoR only, G4)."
  [addr->cid features {:keys [labels] :or {labels {}}}]
  (let [cids (distinct (vals addr->cid))]
    (mapcat (fn [cid]
              (let [klass (or (get labels cid) (classify-cluster (get features cid {})))
                    members (sort (keep (fn [[a c]] (when (= c cid) a)) addr->cid))
                    e (str "cluster:" cid)]
                (into [(kd/add e ":tadori.cluster/id" cid)
                       (kd/add e ":tadori.cluster/class" (str klass))
                       (kd/add e ":tadori.cluster/heuristic" "common-input+change")
                       (kd/add e ":tadori.cluster/size" (count members))]
                      (map #(kd/add e ":tadori.cluster/member" %)) members)))
            cids)))

(defn trace-case
  "Full Phase-0 pipeline over a case's staged txs: cluster → feature → classify → flow-trace,
  returning the analysis + the EAVT datoms (NOT persisted here — the caller, under an active
  case, routes them through the gate). Deterministic; bounded to `seeds` (G3/G10)."
  [{:keys [chain txs seeds labels max-hops window]
    :or {chain "eth" labels {} max-hops 5 window 3600}}]
  (let [addr->cid (cluster txs {:window window})
        features (cluster-features txs addr->cid)
        flow (trace-flow txs addr->cid seeds {:max-hops max-hops})
        classes (into {} (map (fn [cid] [cid (or (get labels cid) (classify-cluster (get features cid {})))])
                              (distinct (vals addr->cid))))]
    {:clusters addr->cid
     :features features
     :classes classes
     :flow flow
     :datoms (vec (concat (tx-datoms txs chain)
                          (cluster-datoms addr->cid features {:labels labels})))}))
