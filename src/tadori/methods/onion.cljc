(ns tadori.methods.onion
  "tadori 辿 — darkweb / onion-service PASSIVE observation model. ADR-2605301400 §D2.

  SCOPE (hard boundary, by construction):
    - tadori ingests PUBLIC, PASSIVE darkweb threat-intel only: a known-malicious `.onion`
      address is itself a public indicator (ransomware C2 / mixer endpoint / market), the same
      way a malicious domain is. These enter as `:tadori.onion/*` observation datoms.
    - tadori does NOT de-anonymize Tor, does NOT run hidden-service correlation attacks, does
      NOT crawl/scrape darkweb content, and holds NO capability to unmask an onion's real IP.
      Those verbs are UNREPRESENTABLE here — there is no real-IP field on an onion observation;
      a hidden-service↔host link can only ever arrive as case-authorized, ENCRYPTED external
      evidence (G6), never derived by this actor.
    - G1 public-source + G7 evidence-only + G10 no-mass-surveillance hold by construction.

  What it DOES do: hold the public onion indicator, and — under an active case — correlate an
  onion service with an on-chain crypto address when the *case evidence* already binds them
  (e.g. a ransom-payment address published on the C2). That correlation is an attribution edge
  (see tadori.methods.attribution), not a de-anonymization.

  Pure (no I/O, no Tor, no network)."
  (:require [kotoba.lang.text :as str]
            [kotoba.datom :as kd]))

(def onion-classes
  "Public-indicator classes only. No member denotes a de-anon capability."
  #{:ransomware-c2 :mixer-endpoint :market :leak-site :phishing :unknown})

(defn onion-error [msg] (ex-info msg {:tadori/error :onion}))

(defn- onion-address? [s]
  ;; v3 onion = 56 base32 chars + ".onion"; accept the documentation/synthetic shape too.
  (boolean (and s (re-matches #"(?i)[a-z2-7]{16,56}\.onion" (str s)))))

(defn validate-onion
  "An onion observation must carry a well-formed .onion address + a public-indicator class +
  a source. It MUST NOT carry a real-IP / host field (de-anon is unrepresentable, G10)."
  [{:keys [onion-id address class source] :as obs}]
  (when-not (onion-address? address)
    (throw (onion-error (str "not a .onion address: " (pr-str address)))))
  (when-not (onion-classes (keyword (name (or class :unknown))))
    (throw (onion-error (str "onion class must be a public-indicator class; got " (pr-str class)))))
  (when (str/blank? (str source))
    (throw (onion-error "onion observation requires a (public) source")))
  (doseq [k [:real-ip :host-ip :deanon :unmasked-ip :node-ip]]
    (when (contains? obs k)
      (throw (onion-error (str "G10: an onion observation cannot carry a de-anonymization field (" k ")")))))
  obs)

(defn onion-datoms
  "Emit :tadori.onion/* for a public onion indicator. case-id binds it to the warrant (G3);
  any sensitive correlation payload stays in encrypted attribution edges, never here.
  The FULL input is validated (a de-anonymization field anywhere in it is rejected, G10)."
  [{:keys [onion-id address class source case-id first-seen last-seen]
    :or {class :unknown} :as obs}]
  (validate-onion (assoc obs :class class))
  (let [e (str "onion:" onion-id)]
    (cond-> [(kd/add e ":tadori.onion/id" onion-id)
             (kd/add e ":tadori.onion/address" address)
             (kd/add e ":tadori.onion/class" (str (keyword (name class))))
             (kd/add e ":tadori.onion/source" source)]
      case-id    (conj (kd/add e ":tadori.onion/case-id" case-id))
      first-seen (conj (kd/add e ":tadori.onion/first-seen" first-seen))
      last-seen  (conj (kd/add e ":tadori.onion/last-seen" last-seen)))))

(defn onion->address-evidence
  "Build the case-evidence link between an onion service and an on-chain payment address that the
  CASE EVIDENCE already binds (e.g. a ransom address posted on the C2). Returns a plain edge spec
  {:subject onion :object addr :evidence [...] :kind :onion-payment-address} for attribution/join
  to encrypt + persist. This is correlation of disclosed evidence, NOT de-anonymization."
  [{:keys [onion-id address evidence-cids confidence]
    :or {evidence-cids [] confidence 500}}]
  {:subject (str "onion:" onion-id)
   :object (str "addr:" address)
   :kind :onion-payment-address
   :evidence evidence-cids
   :confidence confidence})
