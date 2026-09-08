(ns tadori.methods.risk
  "tadori 辿 — high-risk / scam / sanctioned address ingest + risk propagation + hidden-influence
  concentration. ADR-2605301400 §D1/§D2.

  DOCTRINE (charter-grounded, not just policy):
    NON-ADJUDICATING (G7 + kosatsu pattern). tadori NEVER declares an address a scammer. It
    records an ATTRIBUTED, as-of event: \"asserter X listed this address as :scam\". The risk
    label is a disclosed fact (神の監視 = record what is disclosed), never tadori's verdict
    (NEVER-a-throne — the actor does not sit as judge). Divergence between asserters is itself a
    neutral fact, like kosatsu's competing-claim model.
    OPEN-SOURCE SoR (G4). A vendor/feature-flagged feed may be an input but NEVER the
    system-of-record; public lists (OFAC SDN crypto, public scam DBs) are SoR-eligible.
    EVIDENCE-ONLY (G7). A label has a confidence + evidence CID; it has no freeze/seize verb.
    Address-level only here — person-linkage is the ENCRYPTED, case-gated attribution edge (G6).

  Pure (no I/O). Live ingest of real public lists is the operator-gated leg (methods/transact)."
  (:require [kotoba.lang.text] [kotoba.datom :as kd]
            [tadori.methods.address :as addr]))

(def risk-classes
  "Disclosed risk classes (an asserter's listing category, not a tadori verdict)."
  #{:sanctions :scam :ransomware :mixer :phishing :darknet-market
    :stolen-funds :ponzi :fraud :high-risk :tor-exit :hack})

(def vendor-compat
  "Vendor families accepted only as :feature-flagged-input, never :system-of-record (G4)."
  #{:chainalysis-compatible :trm-compatible :elliptic-compatible})

(defn risk-error [msg] (ex-info msg {:tadori/error :risk}))

(defn validate-risk-record
  "A high-risk label record: {:address :chain :risk-class :asserter :as-of :source-role
  :confidence :evidence}. Enforces address validity, class enum, an asserter (attribution,
  NON-ADJUDICATING), and the G4 SoR rule. Returns the record."
  [{:keys [address chain risk-class asserter source-role vendor-family confidence] :as rec}]
  (when-not (addr/valid-address? (or chain :unknown) address)
    (throw (risk-error (str "invalid " (name (or chain :unknown)) " address: " (pr-str address)))))
  (when-not (contains? risk-classes (keyword (name (or risk-class :high-risk))))
    (throw (risk-error (str "risk-class must be a disclosed class; got " (pr-str risk-class)))))
  (when (kotoba.lang.text/blank? (str asserter))
    (throw (risk-error "G7 non-adjudicating: a risk label needs an ASSERTER (who listed it) — tadori never self-asserts")))
  (when (and (contains? vendor-compat (keyword (str (name (or vendor-family :none)))))
             (= (keyword (name (or source-role :feature-flagged-input))) :system-of-record))
    (throw (risk-error "G4: a vendor-compatible feed cannot be the system-of-record")))
  (when-let [c confidence]
    (when (or (< (long c) 0) (> (long c) 1000))
      (throw (risk-error "confidence must be 0..1000 per-mille"))))
  rec)

(defn risk-label-datoms
  "One ATTRIBUTED risk label → append-only :tadori.risk/* EAVT. The subject is the address; the
  asserter + as-of make it a disclosed event, never tadori's judgment (non-adjudicating)."
  [{:keys [address chain risk-class asserter as-of source-role confidence evidence]
    :or {source-role :feature-flagged-input confidence 500} :as rec}]
  (validate-risk-record rec)
  (let [a (addr/normalize chain address)
        e (str "risk:" (name (keyword (name risk-class))) ":" a ":" asserter)]
    (cond-> [(kd/add e ":tadori.risk/id" e)
             (kd/add e ":tadori.risk/address" a)
             (kd/add e ":tadori.risk/chain" (str (name (or chain (addr/infer-chain address)))))
             (kd/add e ":tadori.risk/class" (str (keyword (name risk-class))))
             (kd/add e ":tadori.risk/asserter" asserter)            ;; WHO listed it (attribution)
             (kd/add e ":tadori.risk/source-role" (str (keyword (name source-role))))
             (kd/add e ":tadori.risk/confidence" confidence)
             (kd/add e ":tadori.risk/non-adjudicating" true)]       ;; const — never a verdict
      as-of (conj (kd/add e ":tadori.risk/as-of" as-of))
      (seq evidence) (into (map #(kd/add e ":tadori.risk/evidence" %) evidence)))))

;; ── risk propagation through the cluster graph ────────────────────────────────

(def ^:private severity
  {:sanctions 1000 :ransomware 950 :stolen-funds 900 :scam 850 :ponzi 850
   :darknet-market 800 :hack 900 :phishing 750 :fraud 750 :mixer 600 :tor-exit 400 :high-risk 500})

(defn score-addresses
  "Fold risk labels → {normalized-address {:classes #{..} :asserters #{..} :score n}}.
  score = max disclosed severity + corroboration bump per extra distinct asserter. Aggregate;
  no verdict (an address with more independent asserters is more corroborated, not more guilty)."
  [risk-labels]
  (let [base (reduce (fn [m {:keys [address chain risk-class asserter]}]
                       (let [a (addr/normalize chain address) k (keyword (name risk-class))]
                         (-> m (update-in [a :classes] (fnil conj #{}) k)
                             (update-in [a :asserters] (fnil conj #{}) asserter))))
                     {} risk-labels)]
    (reduce-kv (fn [m a {:keys [classes asserters] :as v}]
                 (let [sev (apply max (map #(get severity % 500) classes))
                       corroboration (min 1000 (+ sev (* 50 (dec (count asserters)))))]
                   (assoc m a (assoc v :score corroboration))))
               {} base)))

(defn propagate-to-clusters
  "A cluster inherits the MAX risk of any address it contains (aggregate). addr->cid from
  tadori.methods.trace/cluster. Returns {cluster-id {:score :classes :tainted-members}}."
  [addr->cid scored]
  (reduce
   (fn [m [a {:keys [score classes]}]]
     (let [cid (get addr->cid a a)]
       (-> m
           (update-in [cid :score] (fnil max 0) score)
           (update-in [cid :classes] (fnil into #{}) classes)
           (update-in [cid :tainted-members] (fnil conj #{}) a))))
   {} scored))

;; ── hidden-influence concentration (取-lens; map-not-target) ──────────────────

(defn hidden-influence
  "隠れた影響力: rank clusters by how much risk they CONCENTRATE — one controller behind many
  distinct scam/sanctioned addresses or many distinct asserters. Structural + aggregate, a
  RESILIENCE map, never a target-list. Returns clusters sorted by concentration desc."
  [cluster-risk]
  (->> cluster-risk
       (map (fn [[cid v]]
              {:cluster cid
               :score (:score v 0)
               :tainted (count (:tainted-members v))
               :classes (:classes v)
               ;; concentration = breadth of distinct tainted addresses × peak severity
               :concentration (* (count (:tainted-members v)) (:score v 0))}))
       (sort-by :concentration >)
       vec))
