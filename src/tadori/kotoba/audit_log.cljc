(ns tadori.kotoba.audit-log
  "1:1 port of kotoba/audit_log.py (ADR-2605301400 §D1 + 2605262130 + 2605312345) — tadori's
  autonomous self-audit kotoba Datom log (local, content-addressed commit-DAG). Holds ONLY the 9
  silenTadoriReview zero-counters — never observation / PII / case data (G3). EAVT assertions are
  [op entity attribute value] with op = :db/add (append-only, no :db/retract — G2).

  Ported (pure / deterministic): COUNTERS, assert-all-clear (G12 halt), review-datoms, the
  content-address (tx-cid over a canonical JSON of {prev,datoms} + sha256), make-tx, the EDN value
  renderer (edn-val / tx-to-edn), the subset EDN reader (read-log-string), head-cid + verify-chain
  over an in-memory tx list. OMITTED (IO leg, not ported): append-tx / disk read_log / head_cid /
  LOG_DEFAULT path ops, and autorun.py (the live heartbeat)."
  (:require [kotoba.lang.text :as str]))

(def counters
  "The 9 silenTadoriReview zero-counters (ADR-2605301400 §D1). Python COUNTERS tuple."
  ["noncase-write" "plaintext-pii" "proprietary-sor" "enforcement-action" "platform-held-key"
   "murakumo-bypass" "mass-surveillance" "adherent-deanon" "non-kotoba-store"])

(defn assert-all-clear
  "G12: any nonzero structural counter HALTS (persisting nothing). Port of assert_all_clear —
  Python SilenReviewHalt → (throw (ex-info ...))."
  [review]
  (let [nonzero (into {} (for [k counters :let [v (get review k 0)] :when (not= 0 v)] [k v]))]
    (when (seq nonzero)
      (throw (ex-info (str "silenTadoriReview HALT (G12): nonzero counter(s) " nonzero
                           " — tadori prunes to Bonsai seed-tier + routes to "
                           "chigiri.disputeMediation; no audit datom persisted.")
                      {:tadori/silen-review-halt true :nonzero nonzero})))))

(defn- add* [entity attr value] [":db/add" entity attr value])

(defn review-datoms
  "Flatten ONE silenTadoriReview heartbeat → append-only EAVT assertions. Port of review_datoms.
  Holds only the 9 zero-counters + informational totals + the Transparent-Force flag (G5)."
  [review cycle]
  (let [e (str "silen-tadori-review:cycle-" cycle)]
    (-> [(add* e ":tadori.review/cycle" cycle)
         (add* e ":tadori.review/phase" 0)
         (add* e ":tadori.review/transparent-force-logged" true)]
        (into (map (fn [k] (add* e (str ":tadori.review/" k) (get review k 0))) counters))
        (into [(add* e ":tadori.review/sources-audited" (get review "sources-audited" 0))
               (add* e ":tadori.review/obs-audited" (get review "obs-audited" 0))
               (add* e ":tadori.review/obs-without-case" (get review "obs-without-case" 0))
               (add* e ":tadori.review/all-clear" true)
               (add* e ":tadori.review/derived" true)]))))

;; ── content address: canonical JSON (json.dumps ensure_ascii=False, sort_keys, compact) + sha256 ──
(defn- esc-char [c]
  (let [n (int c)]
    (cond
      (= c \") "\\\""
      (= c \\) "\\\\"
      (= n 0x08) "\\b"
      (= n 0x0c) "\\f"
      (= c \newline) "\\n"
      (= c \return) "\\r"
      (= c \tab) "\\t"
      (< n 0x20) (format "\\u%04x" n)
      :else (str c))))                                  ; ensure_ascii=False → non-ASCII passes through

(defn- canon-json [v]
  (cond
    (nil? v) "null"
    (boolean? v) (if v "true" "false")
    (integer? v) (str v)
    (number? v) (str v)
    (string? v) (str "\"" (apply str (map esc-char v)) "\"")
    (sequential? v) (str "[" (str/join "," (map canon-json v)) "]")
    (map? v) (str "{" (str/join "," (map (fn [k] (str (canon-json k) ":" (canon-json (get v k))))
                                         (sort (keys v)))) "}")
    :else (throw (ex-info (str "canon-json: unsupported " (type v)) {:v v}))))

(defn- sha256-hex [^String s]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")]
    (apply str (map #(format "%02x" (bit-and % 0xff)) (.digest md (.getBytes s "UTF-8"))))))

(defn tx-cid
  "Content address = 'b' + sha256 over canonical {prev, datoms} (commit-DAG, G2 append-only proof).
  Port of tx_cid."
  ([datoms] (tx-cid datoms ""))
  ([datoms prev-cid]
   (str "b" (sha256-hex (canon-json {"prev" prev-cid "datoms" datoms})))))

(defn make-tx
  "Port of make_tx — deterministic (caller supplies tx-id + as-of, no wall clock)."
  [datoms {:keys [tx-id as-of prev-cid] :or {prev-cid ""}}]
  {":tx/id" tx-id
   ":tx/as-of" as-of
   ":tx/prev" prev-cid
   ":tx/cid" (tx-cid datoms prev-cid)
   ":tx/count" (count datoms)
   ":tx/datoms" datoms})

;; ── EDN value rendering (matches _edn_val / _tx_to_edn) ──
(defn- json-str [s] (str "\"" (apply str (map esc-char (str s))) "\""))

(defn- edn-val [v]
  (cond
    (boolean? v) (if v "true" "false")
    (integer? v) (str v)
    (number? v) (str v)
    (string? v) (if (str/starts-with? v ":") v (json-str v))
    (sequential? v) (str "[" (str/join " " (map edn-val v)) "]")
    :else (json-str (str v))))

(defn tx-to-edn
  "Port of _tx_to_edn — render a tx map as an EDN string for the append-only log line."
  [tx]
  (let [datoms (str/join " " (map (fn [d] (str "[" (str/join " " (map edn-val d)) "]"))
                                  (get tx ":tx/datoms")))]
    (str "{:tx/id " (get tx ":tx/id") " :tx/as-of " (get tx ":tx/as-of") " "
         ":tx/prev " (json-str (get tx ":tx/prev")) " :tx/cid " (json-str (get tx ":tx/cid")) " "
         ":tx/count " (get tx ":tx/count") " :tx/datoms [" datoms "]}")))

;; ── minimal EDN reader (subset) for read-back — port of _tokens/_atom/_parse ──
(def ^:private tok-re #"[\s,]+|;[^\n]*|(\[|\]|\{|\}|\"(?:\\.|[^\"\\])*\"|[^\s,\[\]{}]+)")

(defn- tokens [s]
  (->> (re-seq tok-re s) (keep second)))

(defn- atom* [t]
  (cond
    (str/starts-with? t "\"") (-> (subs t 1 (dec (count t)))
                                  (str/replace "\\\"" "\"") (str/replace "\\\\" "\\"))
    (= t "true") true
    (= t "false") false
    (= t "nil") nil
    (str/starts-with? t ":") t
    :else (or (try (Long/parseLong t) (catch Exception _ nil))
              (try (Double/parseDouble t) (catch Exception _ nil))
              t)))

(defn- parse* [state]
  ;; state = atom holding a seq of remaining tokens; returns parsed value or ::end
  (let [t (first @state)]
    (swap! state rest)
    (cond
      (= t "[") (loop [out []] (let [x (parse* state)] (if (= x ::end) out (recur (conj out x)))))
      (= t "{") (loop [out {}] (let [k (parse* state)]
                                 (if (= k ::end) out
                                     (let [v (parse* state)] (recur (assoc out k v))))))
      (or (= t "]") (= t "}")) ::end
      :else (atom* t))))

(defn read-log-string
  "Parse append-only-log TEXT → vector of tx maps (skips blank / ;-comment lines). Pure port of
  read_log's parsing (the disk read is the omitted IO leg)."
  [text]
  (vec (for [line (str/split-lines text)
             :let [l (str/trim line)]
             :when (and (seq l) (not (str/starts-with? l ";")))]
         (parse* (atom (tokens l))))))

(defn head-cid
  "Last tx's :tx/cid (or \"\" if empty). Port of head_cid over an in-memory tx list."
  [txs]
  (if (seq txs) (get (last txs) ":tx/cid") ""))

(defn verify-chain
  "Recompute each tx CID over its predecessor and confirm the commit-DAG is intact. Port of
  verify_chain over an in-memory tx list."
  [txs]
  (loop [i 0 prev "" ts txs]
    (if (empty? ts)
      {"ok" true "length" (count txs) "broken_at" -1}
      (let [tx (first ts)
            expect (tx-cid (get tx ":tx/datoms" []) prev)]
        (if (or (not= (get tx ":tx/cid") expect) (not= (get tx ":tx/prev") prev))
          {"ok" false "length" (count txs) "broken_at" i}
          (recur (inc i) (get tx ":tx/cid") (rest ts)))))))
