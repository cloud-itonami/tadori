(ns tadori.methods.ingest
  "tadori 辿 threat-intel → kotoba EAVT bridge (validation + datom conversion).
  ADR-2605301400 §D1/§D2/§D3 (T3) + ADR-2605262130 + ADR-2605312345.
  Clojure port of the PURE core of `kotoba/ingest_threat_intel.py`.

  This module is the gate-clean validator + EAVT-assertion builder that the
  autonomous self-audit loop (tadori.methods.autorun) and the operator-gated
  live ingest both sit on. The HTTP `datomic.transact` / session-verify legs of
  the Python file are deliberately NOT ported here — they are the host/operator
  edge (G7 live-leg, no-server-key), kept out of the pure pywasm-runnable core
  exactly as mimamori/shionome keep their live legs at the edge.

    - load-jsonl        → parse operator-staged JSONL (offline; no fetch)
    - validate-records  → enforce the tadori gates (G3/G4 collection-mode/SoR/tier-D)
    - record->datoms    → one record → append-only EAVT [:db/add e a v] assertions

  Gates enforced here:
    G3  observation needs source + operator-staged collection_mode; live needs case_id
    G4  a vendor-compatible feed may NOT be declared :system-of-record (open-source SoR)
    G2  every emitted datom is :db/add (append-only — no retract)

  ValidationError is an ex-info carrying {:tadori/error :validation}. Stdlib +
  cheshire (babashka built-in) only; deterministic; NO external I/O."
  (:require [kotoba.lang.text :as str]
            [kotoba.datom :as kd]
            #?(:clj [cheshire.core :as json])))

(def vendor-compat
  "Vendor-shaped feeds accepted ONLY as feature-flagged input, never system-of-record (G4)."
  #{"securitytrails-compatible" "dnsdb-compatible" "recordedfuture-compatible"})

(def valid-kinds #{"intel-source" "dns-obs" "ip-obs" "indicator"})
(def valid-license-tiers #{"A" "B" "C" "D"})

(defn validation-error
  "Mirror of the Python ValidationError — an ex-info the loop surfaces as a HALT."
  [msg]
  (ex-info msg {:tadori/error :validation}))

(defn validation-error?
  "True iff ex was raised by validation-error (so callers can catch G3/G4 the way the
  Python tests catch autorun.ValidationError)."
  [ex]
  (= :validation (:tadori/error (ex-data ex))))

;; ── JSONL load (operator-staged corpus; offline) ──────────────────────────────

(defn load-jsonl
  "Parse operator-staged JSONL → records (string-keyed maps + :_lineno). Blank lines
  and `#` comments are skipped, exactly like the Python loader. No fetch — the corpus
  is staged on disk by an operator (G3 offline posture)."
  [^String text]
  (let [parse #?(:clj json/parse-string
                 :cljs (fn [s _] (js->clj (js/JSON.parse s))))]
    (loop [lines (map-indexed vector (str/split-lines text))
           out []]
      (if-let [[i raw] (first lines)]
        (let [line (str/trim raw)
              lineno (inc i)]
          (if (or (str/blank? line) (str/starts-with? line "#"))
            (recur (rest lines) out)
            (let [rec (try (parse line false)
                           (catch #?(:clj Exception :cljs :default) e
                             (throw (validation-error
                                     (str "line " lineno ": JSON parse error: "
                                          #?(:clj (.getMessage ^Exception e) :cljs e))))))]
              (when-not (map? rec)
                (throw (validation-error (str "line " lineno ": expected JSON object"))))
              (recur (rest lines) (conj out (assoc rec "_lineno" lineno))))))
        out))))

(defn- blank-val? [v] (or (nil? v) (= v "")))

(defn- require-fields [rec & fields]
  (let [missing (remove #(not (blank-val? (get rec %))) fields)]
    (when (seq missing)
      (throw (validation-error
              (str "line " (get rec "_lineno") ": missing required fields: "
                   (str/join ", " missing)))))))

(defn validate-records
  "Enforce the tadori gates over the whole corpus (raises on the first violation).
  Mirror of Python validate_records(records, *, allow_tier_d, live, case_id)."
  [records {:keys [allow-tier-d live case-id] :or {allow-tier-d false live false}}]
  (let [source-ids
        (reduce
         (fn [src-ids rec]
           (let [kind (get rec "kind")
                 lineno (get rec "_lineno")]
             (when-not (contains? valid-kinds kind)
               (throw (validation-error (str "line " lineno ": invalid kind " (pr-str kind)))))
             (require-fields rec "id")
             (if (= kind "intel-source")
               (do
                 (require-fields rec "name" "vendor_family" "source_role" "license_tier")
                 (let [tier (str (get rec "license_tier"))]
                   (when-not (contains? valid-license-tiers tier)
                     (throw (validation-error (str "line " lineno ": invalid license_tier " (pr-str tier)))))
                   (when (and (= tier "D") (not allow-tier-d))
                     (throw (validation-error
                             (str "line " lineno ": Tier-D source requires --allow-tier-d and remains non-SoR"))))
                   (when (and (contains? vendor-compat (str (get rec "vendor_family")))
                              (= (get rec "source_role") "system-of-record"))
                     (throw (validation-error
                             (str "line " lineno ": vendor-compatible source cannot be system-of-record")))))
                 (conj src-ids (str (get rec "id"))))
               (do
                 (require-fields rec "source" "collection_mode")
                 (when (and live (not (or case-id (get rec "case_id"))))
                   (throw (validation-error (str "line " lineno ": live write requires case_id"))))
                 (when (not= (get rec "collection_mode") "operator-staged-passive-archive")
                   (throw (validation-error
                           (str "line " lineno ": collection_mode must be operator-staged-passive-archive"))))
                 (when-let [conf (get rec "confidence")]
                   (let [c (long conf)]
                     (when (or (< c 0) (> c 1000))
                       (throw (validation-error (str "line " lineno ": confidence must be 0..1000"))))))
                 (case kind
                   "dns-obs"   (require-fields rec "domain" "rrtype" "rrdata")
                   "ip-obs"    (require-fields rec "address")
                   "indicator" (require-fields rec "indicator_type" "value" "status")
                   nil)
                 src-ids))))
         #{}
         records)
        missing-sources (->> records
                             (remove #(= (get % "kind") "intel-source"))
                             (map #(str (get % "source")))
                             (remove #(contains? source-ids %))
                             distinct sort)]
    (when (seq missing-sources)
      (throw (validation-error
              (str "observation references undeclared source(s): " (str/join ", " missing-sources)))))
    records))

;; ── EAVT assertion builder (T3 kotoba bridge) ─────────────────────────────────
;; Mirror of ingest_threat_intel.py record_to_datoms / datoms_to_tx_edn: each datom is
;; rendered as the FULL `[:db/add "e" :attr v]` STRING the kotoba node's datomic.transact
;; ingests. (The autonomous self-audit loop uses kd vectors instead; this string path is
;; only the live operator ingest, so the two never collide.)

(defn edn-string
  "Python edn_string = json.dumps(v, ensure_ascii=False) — a JSON-escaped \"…\" literal.
  Reuses kotoba.datom's canonical-json string rendering (sorted/compact/ensure_ascii=false)."
  [v]
  (kd/canonical-json (str v)))

(defn- edn-keyword
  "`public_archive` → \":public-archive\" (Python edn_keyword: _→-, prepend :)."
  [v]
  (let [token (-> (str v) str/trim (str/replace "_" "-"))]
    (when (str/blank? token)
      (throw (validation-error "empty keyword value")))
    (if (str/starts-with? token ":") token (str ":" token))))

(defn- edn-value
  "Python edn_value: bool→true/false, int→str, string→edn_string."
  [v]
  (cond
    (boolean? v) (if v "true" "false")
    (integer? v) (str v)
    (string? v)  (edn-string v)
    :else (throw (validation-error (str "unsupported EDN value " (pr-str v))))))

(defn- add!
  "append-only :db/add datom STRINGS; skip nil; explode seqs; optionally keyword-render.
  attr is the bare tail (e.g. \"tadori.obs/kind\"), rendered `:attr`; entity is quoted."
  ([acc entity attr value] (add! acc entity attr value false))
  ([acc entity attr value keyword?]
   (reduce (fn [a* item]
             (if (nil? item)
               a*
               (conj a* (str "[:db/add " (edn-string entity) " :" attr " "
                             (if keyword? (edn-keyword (str item)) (edn-value item)) "]"))))
           acc
           (if (sequential? value) value [value]))))

(defn- add-raw!
  "Python add_raw: a datom whose value is pre-rendered EDN (e.g. a lookup ref)."
  [acc entity attr value-edn]
  (if (nil? value-edn)
    acc
    (conj acc (str "[:db/add " (edn-string entity) " :" attr " " value-edn "]"))))

(defn- source-lookup-ref [source-id]
  (str "[:tadori.source/id " (edn-string source-id) "]"))

(defn record->datoms
  "One staged record → append-only `[:db/add …]` EAVT STRING datoms (G2). case-id, when
  supplied, overrides the per-record case_id (live posture). Mirror of record_to_datoms."
  [rec {:keys [case-id]}]
  (let [kind (str (get rec "kind"))
        e (str (get rec "id"))]
    (if (= kind "intel-source")
      (-> []
          (add! e "tadori.source/id" e)
          (add! e "tadori.source/name" (get rec "name"))
          (add! e "tadori.source/vendor-family" (get rec "vendor_family") true)
          (add! e "tadori.source/source-role" (get rec "source_role") true)
          (add! e "tadori.source/license-tier" (get rec "license_tier") true)
          (add! e "tadori.source/dataset-cid" (get rec "dataset_cid"))
          (add! e "tadori.source/captured-at" (get rec "captured_at"))
          (add! e "tadori.source/notes" (get rec "notes")))
      (cond-> (-> []
                  (add! e "tadori.obs/id" e)
                  (add! e "tadori.obs/kind" kind true)
                  (add-raw! e "tadori.obs/source" (source-lookup-ref (str (get rec "source"))))
                  (add! e "tadori.obs/case-id" (or case-id (get rec "case_id")))
                  (add! e "tadori.obs/observed-at" (get rec "observed_at"))
                  (add! e "tadori.obs/first-seen-at" (get rec "first_seen_at"))
                  (add! e "tadori.obs/last-seen-at" (get rec "last_seen_at"))
                  (add! e "tadori.obs/confidence" (get rec "confidence"))
                  (add! e "tadori.obs/tlp" (get rec "tlp") true)
                  (add! e "tadori.obs/evidence-cid" (get rec "evidence_cid"))
                  (add! e "tadori.obs/encrypted" (get rec "encrypted"))
                  (add! e "tadori.obs/collection-mode" (get rec "collection_mode") true))
        (= kind "dns-obs")
        (-> (add! e "tadori.dns/domain" (get rec "domain"))
            (add! e "tadori.dns/rrtype" (get rec "rrtype") true)
            (add! e "tadori.dns/rrdata" (get rec "rrdata"))
            (add! e "tadori.dns/passive-pivot" (get rec "passive_pivot") true))
        (= kind "ip-obs")
        (-> (add! e "tadori.ip/address" (get rec "address"))
            (add! e "tadori.ip/asn" (get rec "asn"))
            (add! e "tadori.ip/prefix" (get rec "prefix"))
            (add! e "tadori.ip/geo" (get rec "geo"))
            (add! e "tadori.ip/hosting-class" (get rec "hosting_class") true))
        (= kind "indicator")
        (-> (add! e "tadori.indicator/id" e)
            (add! e "tadori.indicator/type" (get rec "indicator_type") true)
            (add! e "tadori.indicator/value" (get rec "value"))
            (add! e "tadori.indicator/status" (get rec "status") true)
            (add! e "tadori.indicator/context" (get rec "context")))))))

(defn datoms->tx-edn
  "Mirror of datoms_to_tx_edn: a tx-data EDN vector literal of the datom strings."
  [datoms]
  (if (empty? datoms)
    "[]"
    (str "[\n  " (str/join "\n  " datoms) "\n]")))

(defn readback-checks
  "Per-record (entity, attr) pairs the live writer re-reads to confirm persistence.
  Mirror of readback_checks (order-preserving)."
  [records]
  (vec (keep (fn [rec]
               (case (get rec "kind")
                 "intel-source" [(str (get rec "id")) "tadori.source/id"]
                 "dns-obs"      [(str (get rec "id")) "tadori.dns/domain"]
                 "ip-obs"       [(str (get rec "id")) "tadori.ip/address"]
                 "indicator"    [(str (get rec "id")) "tadori.indicator/value"]
                 nil))
             records)))
