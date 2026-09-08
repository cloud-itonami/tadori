(ns tadori.methods.ofac
  "tadori 辿 — OFAC SDN digital-currency-address ingest leg (ADR-2605301400 §D3, G4 public SoR).

  The US Treasury OFAC SDN list is PUBLIC, primary-source sanctions data. Its crypto entries
  (`<idType>Digital Currency Address - XBT/ETH/…</idType>`) are exactly the disclosed, attributed,
  non-adjudicating risk labels tadori's risk layer is built for: tadori records 'OFAC listed this
  address as sanctioned, as-of T', NEVER its own verdict (kosatsu pattern, G7).

  This module PARSES the public sdn.xml (pure, tested on a fixture) → :sanctions risk-label
  records keyed by SDN uid + program. The actual DOWNLOAD of the live sdn.xml from
  treasury.gov is the operator-gated leg (G4/G7) — `parse-sdn` takes the staged XML text, so
  the loop itself does no network I/O.

  Pure (parse + map). Depends only on clojure.data.xml (babashka built-in) + risk.cljc."
  (:require [clojure.data.xml :as xml]
            [kotoba.lang.text :as str]
            [tadori.methods.address :as addr]
            [tadori.methods.risk :as risk]))

;; ── namespace-agnostic XML helpers (sdn.xml uses a default xmlns) ─────────────

(defn- local-name [tag] (when (keyword? tag) (name tag)))

(defn- child-elems [el name*]
  (when (map? el)
    (filter #(and (map? %) (= name* (local-name (:tag %)))) (:content el))))

(defn- descendants [el name*]
  (when (map? el)
    (mapcat (fn [c]
              (cond
                (not (map? c)) nil
                (= name* (local-name (:tag c))) (cons c (descendants c name*))
                :else (descendants c name*)))
            (:content el))))

(defn- el-text [el]
  (->> (:content el) (filter string?) (apply str) str/trim))

(defn- first-text [el name*]
  (some-> (first (child-elems el name*)) el-text))

;; ── OFAC currency-symbol → chain ──────────────────────────────────────────────

(def ^:private symbol->chain
  {"XBT" :btc "BTC" :btc "ETH" :eth "ETC" :etc "BCH" :bch "LTC" :ltc
   "XMR" :xmr "ZEC" :zec "DASH" :dash "BTG" :btg "BSV" :bsv
   "USDT" :eth "USDC" :eth "ARB" :eth "XVG" :xvg})   ;; best-effort; :unknown otherwise

(def ^:private dca-prefix "Digital Currency Address")

(defn parse-sdn
  "Parse OFAC sdn.xml text → seq of {:address :chain :symbol :sdn-uid :programs [..]} for every
  Digital-Currency-Address id. Namespace-agnostic. No network I/O — caller stages the XML."
  [xml-text]
  (let [root (xml/parse-str xml-text)]
    (mapcat
     (fn [entry]
       (let [uid (first-text entry "uid")
             programs (mapv el-text (descendants entry "program"))]
         (keep
          (fn [id]
            (let [id-type (first-text id "idType")]
              (when (and id-type (str/starts-with? id-type dca-prefix))
                (let [sym (-> id-type (str/split #"-") last str/trim str/upper)]
                  {:address (first-text id "idNumber")
                   :symbol sym
                   :chain (get symbol->chain sym :unknown)
                   :sdn-uid uid
                   :programs programs}))))
          (descendants entry "id"))))
     (descendants root "sdnEntry"))))

(defn ofac->risk-records
  "OFAC digital-currency entries → :sanctions risk-label records (asserter ofac-sdn, G4 SoR).
  Address-validated; an entry whose address does not validate for any known chain is SKIPPED
  (counted), so one malformed entry never kills the batch. as-of = operator-supplied publish date."
  [entries {:keys [as-of] :or {as-of 0}}]
  (reduce
   (fn [acc {:keys [address chain sdn-uid programs symbol]}]
     (if (addr/valid-address? (if (= chain :unknown) :unknown chain) address)
       (update acc :records conj
               {:address address
                :chain (if (= chain :unknown) (addr/infer-chain address) chain)
                :risk-class :sanctions
                :asserter "ofac-sdn"
                :as-of as-of
                :source-role :system-of-record
                :confidence 1000
                :evidence (cond-> []
                            sdn-uid (conj (str "ofac-sdn-uid:" sdn-uid))
                            (seq programs) (into (map #(str "ofac-program:" %) programs)))})
       (-> acc (update :skipped inc)
           (update :skipped-symbols (fnil conj #{}) symbol))))
   {:records [] :skipped 0 :skipped-symbols #{}}
   entries))

(defn ofac-datoms
  "Full leg: parse staged sdn.xml → :sanctions risk-label EAVT datoms (via risk.cljc).
  Returns {:datoms [...] :count n :skipped n}. The risk labels are attributed + non-adjudicating."
  [xml-text {:keys [as-of] :or {as-of 0}}]
  (let [{:keys [records skipped]} (ofac->risk-records (parse-sdn xml-text) {:as-of as-of})]
    {:datoms (vec (mapcat risk/risk-label-datoms records))
     :count (count records)
     :skipped skipped}))
