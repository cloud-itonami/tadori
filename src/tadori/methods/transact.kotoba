(ns tadori.methods.transact
  "tadori 辿 threat-intel → live kotoba datomic.transact (operator-gated host edge).
  ADR-2605301400 + ADR-2605231525 (no-server-key) + ADR-2605262130.
  Clojure port of the HTTP/CLI leg of `kotoba/ingest_threat_intel.py`.

  This is the ONLY tadori namespace that does network I/O — deliberately split out of the
  pure `tadori.methods.ingest` core so the autonomous self-audit loop stays no-external-I/O
  (G-no-io test) and pywasm-runnable. It is an OPERATOR tool: it transacts an operator-staged
  passive-archive corpus into a running kotoba node and verifies read-back. It holds NO key —
  the credential is supplied at runtime via KOTOBA_SESSION_POP / KOTOBA_TOKEN (the operator's,
  not the platform's). Without a credential it is a DRY RUN (prints the tx_edn summary).

  Live data writes require a `case` anchor (TADORI_CASE_ID / per-record case_id) and reject any
  collection_mode other than operator-staged-passive-archive (G3); vendor-compatible feeds may
  not be system-of-record (G4) — both enforced by tadori.methods.ingest/validate-records.

  Network and codec authority are explicit host dependencies."
  (:require [clojure.java.io :as io]
            [kotoba.lang.text :as str]
            [cheshire.core :as json]
            [tadori.methods.ingest :as ingest]))

(def nsid-session-verify "com.etzhayyim.pds.session.verify")
(def nsid-datomic-transact "com.etzhayyim.apps.kotoba.datomic.transact")
(def nsid-datomic-datoms "com.etzhayyim.apps.kotoba.datomic.datoms")

;; ── internal-trust header (ADR-2608124000) ────────────────────────────────────
;; kotoba-server's `require_internal_trust` gate compares this header against its
;; own KOTOBA_INTERNAL_SECRET. That variable is unset across the murakumo fleet,
;; so the gate returns success and the header is never read — sending it TODAY is
;; a complete no-op. That is precisely why it is safe to ship now: every caller
;; must demonstrably send it BEFORE the server side can be armed, and arming the
;; server first would break every caller at once.
;;
;; We read the SAME variable name the server and the Cloudflare gateway read, so
;; arming the fleet later is one variable rather than one per actor. The value is
;; only ever read from the environment — never minted, never defaulted.
;;
;; When it is unconfigured we OMIT the header, but never SILENTLY: a one-shot
;; stderr warning fires on the live path, and the push result carries
;; :internal-trust so a fleet sweep can see the gap as data instead of as a log
;; line nobody reads. Silent omission is the shape that let an unauthenticated
;; fleet look healthy in the first place.
;;
;; NOTE: this namespace has NO host allowlist -- `base-url` is whatever the
;; operator passes. The trust header is therefore attached to whatever host the
;; operator named, exactly as the Authorization bearer already is. Adding an
;; allowlist is a separate change and is NOT made here.
(def internal-trust-header "x-internal-trust")
(def internal-trust-env "KOTOBA_INTERNAL_SECRET")

#?(:clj
   (defn internal-trust
     "The configured internal-trust secret, or nil when unset/blank. Environment
     only — this function never mints or defaults a value."
     []
     (let [v (System/getenv internal-trust-env)]
       (when-not (str/blank? v) v))))

#?(:clj (def ^:private internal-trust-warned? (atom false)))

#?(:clj
   (defn internal-trust-status
     "`:configured` | `:unconfigured` — the machine-readable half of the warning."
     []
     (if (internal-trust) :configured :unconfigured)))

#?(:clj
   (defn warn-unconfigured-internal-trust!
     "Announce ONCE per process that this push carries no internal-trust header."
     []
     (when (compare-and-set! internal-trust-warned? false true)
       (binding [*out* *err*]
         (println (str "WARN tadori.methods.transact: " internal-trust-env " is unset — requests carry NO "
                       internal-trust-header " header. Harmless while kotoba-server's"
                       " require_internal_trust gate is disabled fleet-wide"
                       " (ADR-2608124000); it becomes a hard rejection the moment"
                       " that gate is armed."))))))

(defn http-post
  "POST JSON through an explicitly granted request capability."
  [request-fn url body token]
  (when-not (fn? request-fn)
    (throw (ex-info "tadori live transact requires an explicit HTTP request capability"
                    {:capability :http-request})))
  (let [trust (internal-trust)
        _ (when-not trust (warn-unconfigured-internal-trust!))
        headers (cond-> {"Content-Type" "application/json"}
                  token (assoc "Authorization" (str "Bearer " token))
                  trust (assoc internal-trust-header trust))
        resp (request-fn {:method :post :uri url :headers headers
                          :body (json/generate-string body) :throw false :timeout 30000})
        raw (or (not-empty (:body resp)) "{}")]
    [(:status resp) (try (json/parse-string raw true) (catch Exception _ {:error raw}))]))

(defn verify-session [request-fn base-url pop-token]
  (let [[status body] (http-post request-fn (str base-url "/xrpc/" nsid-session-verify) {:token pop-token} nil)]
    [(and (= status 200) (boolean (:valid body))) body]))

(defn transact [request-fn base-url graph tx-edn token]
  (http-post request-fn (str base-url "/xrpc/" nsid-datomic-transact) {:graph graph :tx_edn tx-edn} token))

(defn read-datoms [request-fn base-url graph entity attr token]
  (http-post request-fn (str base-url "/xrpc/" nsid-datomic-datoms)
             {:graph graph :index ":eavt"
              :components_edn [(ingest/edn-string entity) (str ":" attr)] :limit 1}
             token))

(def ^:private default-seed (io/file "wire" "seed.threat-intel.jsonl"))

(defn run-cli
  "Operator CLI. Args: [seed-path] [graph] [url]. Reads KOTOBA_SESSION_POP / KOTOBA_TOKEN +
  TADORI_CASE_ID from the env. No credential ⇒ DRY RUN (validate + print tx_edn summary)."
  [request-fn args]
  (let [env (System/getenv)
        seed (if (first args) (io/file (first args)) default-seed)
        graph (or (second args) (.get env "TADORI_GRAPH") "etzhayyim/tadori/threat-intel")
        url (or (nth args 2 nil) (.get env "KOTOBA_URL") "http://127.0.0.1:8077")
        case-id (.get env "TADORI_CASE_ID")
        token (or (.get env "KOTOBA_SESSION_POP") (.get env "KOTOBA_TOKEN"))
        live (boolean token)
        records (ingest/load-jsonl (slurp seed))]
    (ingest/validate-records records {:allow-tier-d false :live live :case-id case-id})
    (let [datoms (mapcat #(ingest/record->datoms % {:case-id case-id}) records)
          tx-edn (ingest/datoms->tx-edn datoms)]
      (println (format "   parsed %d records → %d datoms from %s" (count records) (count datoms) (str seed)))
      (if-not live
        (do (println "   DRY RUN — no writes. Set KOTOBA_SESSION_POP or KOTOBA_TOKEN to transact.")
            (println (format "   tx[data] count~%d bytes=%d" (count datoms) (count (.getBytes ^String tx-edn "UTF-8")))))
        (do
          (when (.get env "KOTOBA_SESSION_POP")
            (let [[ok info] (verify-session request-fn url (.get env "KOTOBA_SESSION_POP"))]
              (when-not ok
                (binding [*out* *err*] (println (str "!! session PoP rejected: " info)))
                (System/exit 1))
              (println (str "   session valid for " (get info :did "?")))))
          (println (format "--> datomic.transact data count~%d graph=%s" (count datoms) graph))
          (let [[status body] (transact request-fn url graph tx-edn token)]
            (when (not= status 200)
              (binding [*out* *err*] (println (str "!! transact failed: " status " " body)))
              (System/exit 1))
            (println (str "    ok tx_cid=" (get body :tx_cid "?") " datom_count=" (get body :datom_count "?"))))
          (doseq [[entity attr] (ingest/readback-checks records)]
            (let [[status body] (read-datoms request-fn url graph entity attr token)]
              (when (or (not= status 200) (< (long (get body :datom_count 0)) 1))
                (binding [*out* *err*] (println (str "!! readback failed for " entity " " attr ": " status " " body)))
                (System/exit 1))))
          (println (format "    readback ok checks=%d graph=%s" (count (ingest/readback-checks records)) graph)))))))

(defn -main [& args]
  (run-cli nil args))
