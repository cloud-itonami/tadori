(ns tadori.methods.autorun
  "tadori 辿 AUTONOMOUS silenTadoriReview self-audit heartbeat. ADR-2605301400 §D1.
  Clojure port of `kotoba/autorun.py`.

  tadori's autonomy is constitutionally constrained (unlike ipaddress/yabai/shionome):
  it is AUTHORIZED-INVESTIGATION-ONLY (G3) and EVIDENCE-PRODUCING-NOT-ENFORCEMENT (G7).
  It may NOT autonomously persist case-anchored observation / attribution / PII datoms —
  that needs a `caseMandate`. So the charter-permitted autonomous act is the
  **Transparent-Force self-audit** (Charter §1.12, G5): each heartbeat the actor

    observe (the OFFLINE operator-staged corpus) → validate against the tadori gates
      (Phase 0, no case → dry-run; raises if the corpus is not gate-clean)
      → recompute the 9 silenTadoriReview structural ZERO-COUNTERS over the corpus
      → G12 guard: any nonzero counter HALTS (Bonsai prune), persisting nothing
      → PERSIST one append-only, content-addressed AUDIT datom (counters + totals +
        the Transparent-Force flag) to the local kotoba Datom log.

  By construction the log holds ONLY audit counters — no observation, no PII, no case
  data ever reaches it (G3/G6/G10 structurally honored). Deterministic / resume-safe
  (cycle drives tx-id + as-of → same CIDs) and append-only. NO external I/O, NO live
  source fetch, NO LLM inference, NO enforcement. Live case-anchored ingest stays at the
  operator-gated edge (tadori.methods.ingest + the Python HTTP leg)."
  (:require [tadori.methods.audit-log :as al]
            [tadori.methods.ingest :as ingest]
            #?(:clj [clojure.java.io :as io])))

(def base-as-of 20260608)

(def pii-kinds
  "PII-bearing observation kinds: person/IP/device attribution MUST be encrypted (G6)."
  #{"ip-obs"})

(defn audit-corpus
  "Recompute the 9 silenTadoriReview structural counters over the staged corpus, in the
  autonomous Phase-0 posture. The autonomous loop writes NO observation/PII/case datoms, so
  the write-side counters (noncase-write / mass-surveillance / adherent-deanon /
  non-kotoba-store / enforcement-action / platform-held-key / murakumo-bypass) are zero by
  construction; the corpus-side counters (plaintext-pii / proprietary-sor) are measured."
  [records]
  (let [obs (filter #(#{"dns-obs" "ip-obs" "indicator"} (get % "kind")) records)
        sources (filter #(= "intel-source" (get % "kind")) records)
        plaintext-pii (count (filter #(and (pii-kinds (get % "kind"))
                                           (not (true? (get % "encrypted"))))
                                     obs))
        proprietary-sor (count (filter #(and (ingest/vendor-compat (str (get % "vendor_family")))
                                             (= (get % "source_role") "system-of-record"))
                                       sources))
        obs-without-case (count (remove #(get % "case_id") obs))]
    {"noncase-write" 0          ;; the loop persists ONLY the audit datom — never a case-write
     "plaintext-pii" plaintext-pii
     "proprietary-sor" proprietary-sor
     "enforcement-action" 0     ;; tadori is evidence-only (G7)
     "platform-held-key" 0      ;; local append, no key (G8)
     "murakumo-bypass" 0        ;; no LLM inference in the loop (G9)
     "mass-surveillance" 0      ;; bounded staged corpus, no untargeted collection (G10)
     "adherent-deanon" 0        ;; no adherent data (G10)
     "non-kotoba-store" 0       ;; kotoba Datom log only (G11)
     "sources-audited" (count sources)
     "obs-audited" (count obs)
     "obs-without-case" obs-without-case}))

#?(:clj
   (defn run-cycle
     "One autonomous self-audit heartbeat: observe → validate → recompute counters → G12
     guard → persist one append-only audit datom. cycle drives tx-id + as-of (deterministic).
     `records` is the already-loaded staged corpus (ingest/load-jsonl)."
     [records cycle log-path]
     ;; Phase 0 (no case): validate raises if the corpus is not gate-clean. Tier-D NOT auto-allowed.
     (ingest/validate-records records {:allow-tier-d false :live false :case-id nil})
     (let [review (audit-corpus records)]
       (al/assert-all-clear review)                      ;; G12 — any nonzero counter HALTS (no persist)
       (let [datoms (al/review-datoms review cycle)
             tx (al/make-tx datoms {:tx-id cycle :as-of (+ base-as-of cycle)
                                    :prev-cid (al/head-cid log-path)})
             cid (al/append-tx tx log-path)]
         {:cycle cycle :review review :datoms (count datoms) :cid cid}))))

#?(:clj
   (defn run-autonomous
     "cycles heartbeats over one append-only log; returns the chain summary."
     [records cycles log-path]
     (let [beats (mapv #(run-cycle records % log-path) (range 1 (inc cycles)))]
       {:cycles cycles
        :beats beats
        :log-length (count (al/read-log log-path))
        :head-cid (al/head-cid log-path)
        :chain (al/verify-chain log-path)})))

#?(:clj
   (def ^:private actor-dir (io/file ".")))

#?(:clj
   (def default-seed (io/file actor-dir "wire" "seed.threat-intel.jsonl")))

#?(:clj
   (defn -main
     "Run the AUTONOMOUS silenTadoriReview self-audit loop over the OFFLINE staged corpus
     (parity with `python3 kotoba/autorun.py`). Args: [cycles] [seed-path] [log-path].
     A HALT / validation failure exits 1 having persisted NOTHING."
     [& args]
     (let [cycles (if (first args) (parse-long (first args)) 3)
           seed (if (second args) (io/file (second args)) default-seed)
           log (if (nth args 2 nil) (nth args 2) (str al/log-default))]
       (try
         (let [res (run-autonomous (ingest/load-jsonl (slurp seed)) cycles log)
               ch (:chain res)]
           (println (str "# tadori — AUTONOMOUS silenTadoriReview self-audit over the kotoba "
                         "Datom log (Phase 0; counters only, NO case/PII/obs data)\n"))
           (doseq [bt (:beats res)]
             (let [r (:review bt)]
               (println (format "  ♥ cycle %d: audited %d sources / %d obs · plaintext-pii %d · proprietary-sor %d · ALL-CLEAR +%d datoms → cid %s…"
                                (:cycle bt) (get r "sources-audited") (get r "obs-audited")
                                (get r "plaintext-pii") (get r "proprietary-sor")
                                (:datoms bt) (subs (:cid bt) 0 (min 14 (count (:cid bt))))))))
           (println (format "\n  log: %d tx · head %s… · chain %s · 9 silenTadoriReview counters = 0 (Transparent-Force audit, G5)"
                            (:log-length res) (subs (:head-cid res) 0 (min 14 (count (:head-cid res))))
                            (if (:ok ch) "OK ✓" (str "BROKEN at " (:broken-at ch))))))
         (catch clojure.lang.ExceptionInfo e
           (binding [*out* *err*] (println (str "!! tadori self-audit HALT: " (.getMessage e))))
           (System/exit 1))))))
