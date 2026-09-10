(ns tadori.methods.adversary
  "tadori 辿 — watch-the-watchers: a transparent, attributed ledger of actors that ATTACK /
  access / surveil etzhayyim, or attempt hidden influence. ADR-2605301400 + Charter §1.12.

  DOCTRINE — this is the operational form of 相互監視 + 神の監視 + NEVER-a-throne:
    監視しようとするものを監視する (watch those who try to watch us) — but RECIPROCALLY and
    TRANSPARENTLY, never as a hidden throne. An adversary observation is appended to the
    public, append-only, on-chain-monitorable ledger (永久記憶 = no erasure): the attacker is
    SEEN, by the same light that sees us. The watcher is itself watched (silenTadoriReview),
    so this cannot degenerate into a panopticon (the 五人組→隣組→Stasi→社会信用 series is
    structurally barred — see G-no-deanon below).

  PUBLISHABLE vs ENCRYPTED (the 公開 boundary, charter-grounded):
    - PUBLIC (公開): the BEHAVIOR (attack/scan/surveil/hidden-influence), the on-chain ADDRESS
      involved, the disclosed source, and AGGREGATE/structural findings. Disclosing that we
      were attacked, from what address, is reciprocal symmetry — affirmed (ADR-2606082400).
    - ENCRYPTED + case-gated (G6/G3): any link to a NATURAL PERSON. Doxxing is forbidden
      (G1/G10). The schema has NO real-IP / identity field on an adversary observation; a
      person-linkage can only exist as a com.etzhayyim.encrypted.* attribution edge.
    - NEVER an enforcement verb (G7): recording + disclosing is the response, not retaliation.
      Force is separated to the 1 SBT = 1 vote Transparent-Force path.

  Pure (no I/O)."
  (:require [kotoba.lang.text :as str]
            [kotoba.datom :as kd]
            [tadori.methods.address :as addr]))

(def behaviors
  "Observable adversary behaviors. NONE denotes a de-anonymization or a retaliation."
  #{:attack :intrusion-attempt :scan :surveil :hidden-influence :scam-targeting-members
    :phishing-our-members :impersonation :sybil :grief})

(def adversary-error (fn [m] (ex-info m {:tadori/error :adversary})))

(defn validate-observation
  "An adversary observation: {:adversary-id :behavior :address :chain :source :observed-at}.
  Behavior must be in the enum. A de-anonymization / identity field anywhere is REJECTED
  (G10) — person-linkage is only ever an encrypted attribution edge, never inline here."
  [{:keys [adversary-id behavior address chain source] :as obs}]
  (when (str/blank? (str adversary-id))
    (throw (adversary-error "adversary observation needs an id")))
  (when-not (contains? behaviors (keyword (name (or behavior :attack))))
    (throw (adversary-error (str "behavior must be observable, non-retaliatory; got " (pr-str behavior)))))
  (when (and address (not (addr/valid-address? (or chain :unknown) address)))
    (throw (adversary-error (str "invalid address: " (pr-str address)))))
  (when (str/blank? (str source))
    (throw (adversary-error "observation requires a source (transparency / attribution)")))
  (doseq [k [:real-ip :host-ip :identity :legal-name :person :home-address :deanon :geoloc]]
    (when (contains? obs k)
      (throw (adversary-error (str "G10/G1: an adversary observation cannot carry an identity/de-anon field (" k
                                   ") — person-linkage is an ENCRYPTED attribution edge only")))))
  obs)

(defn observation-datoms
  "One adversary observation → append-only :tadori.adversary/* EAVT. PUBLIC fields only
  (behavior/address/source/as-of); the attacker is recorded reciprocally. NO identity inline."
  [{:keys [adversary-id behavior address chain source observed-at target confidence]
    :or {confidence 500} :as obs}]
  (validate-observation obs)
  (let [e (str "adversary:" adversary-id)]
    (cond-> [(kd/add e ":tadori.adversary/id" adversary-id)
             (kd/add e ":tadori.adversary/behavior" (str (keyword (name behavior))))
             (kd/add e ":tadori.adversary/source" source)
             (kd/add e ":tadori.adversary/confidence" confidence)
             (kd/add e ":tadori.adversary/reciprocal" true)        ;; const — seen by the same light
             (kd/add e ":tadori.adversary/non-adjudicating" true)] ;; record, not verdict
      address     (conj (kd/add e ":tadori.adversary/address" (addr/normalize chain address)))
      chain       (conj (kd/add e ":tadori.adversary/chain" (str (name chain))))
      observed-at (conj (kd/add e ":tadori.adversary/observed-at" observed-at))
      target      (conj (kd/add e ":tadori.adversary/target" target)))))

(defn watch-the-watchers
  "The reflexive invariant: tadori itself is in the ledger it keeps. Emits the self-audit
  pointer datom so a reader can verify the watcher is watched (links to silenTadoriReview).
  This is the NEVER-a-throne guarantee expressed as data."
  [cycle]
  (let [e (str "adversary.self-watch:cycle-" cycle)]
    [(kd/add e ":tadori.adversary/self-watch" true)
     (kd/add e ":tadori.adversary/watcher-is-watched" "see :tadori.review/* silenTadoriReview")
     (kd/add e ":tadori.adversary/cycle" cycle)]))
