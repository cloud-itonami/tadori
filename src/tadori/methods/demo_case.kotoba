(ns tadori.methods.demo-case
  "tadori 辿 — a SYNTHETIC authorized-case fixture + Phase-0 demo runner. ADR-2605301400.

  All entities are FICTIONAL (obviously-fake 0x… addresses + a documentation .onion). This is
  the R0 dry-run corpus the tracing engine runs on; REAL chain/threat-intel acquisition is the
  operator+case-gated live leg (methods/transact), never this file.

  The scenario: an authorized case traces stolen funds from a thief entity (two co-spent
  addresses) → through a tumbler (mixer) → out to a labeled CEX deposit, with a public
  ransomware-C2 .onion indicator whose published payment address binds (by case evidence) to
  the thief — surfaced as an ENCRYPTED attribution edge."
  (:require [tadori.methods.attribution :as attr]
            [tadori.methods.case-intake :as case]
            [tadori.methods.onion :as onion]
            [tadori.methods.trace :as trace]))

(def mandate
  "An ACTIVE (phase 1) authorized case — synthetic authorization anchor."
  {:case-id "case:demo-2606170900"
   :narrative "SYNTHETIC: trace stolen ETH through a tumbler to a CEX deposit (R0 dry-run)"
   :authorization-ref "warrant:synthetic-0001"
   :authority-did "did:web:etzhayyim.com:authority:synthetic"
   :phase 1
   :opened-ts 20260617})

(def txs
  [{:tx-hash "t1" :from "0xthief-a" :to "0xmix-core" :value 1 :inputs ["0xthief-a" "0xthief-b"] :ts 100}
   {:tx-hash "t2" :from "0xsrc2"    :to "0xmix-core" :value 1 :ts 101}
   {:tx-hash "t3" :from "0xsrc3"    :to "0xmix-core" :value 1 :ts 102}
   {:tx-hash "t4" :from "0xmix-core" :to "0xout1"    :value 1 :ts 110}
   {:tx-hash "t5" :from "0xmix-core" :to "0xout2"    :value 1 :ts 111}
   {:tx-hash "t6" :from "0xmix-core" :to "0xcex-hot" :value 1 :ts 112}])

(def seeds ["0xthief-a"])
(def labels {"0xcex-hot" :cex-hot})   ;; feature-flagged open-source CEX label (G4)

(def onion-obs
  {:onion-id "onion-001"
   :address "abcdefghijklmnop234567.onion"   ;; FICTIONAL documentation onion
   :class :ransomware-c2
   :source "source:public-archive:ransomwatch"
   :case-id (:case-id mandate)
   :first-seen 90})

(defn run
  "Phase-0 analysis over the synthetic case. Returns the analysis + all case-anchored datoms
  (case + tx/cluster + onion + the encrypted onion→address attribution edge)."
  []
  (let [m (case/validate-mandate mandate)
        analysis (trace/trace-case {:chain "eth" :txs txs :seeds seeds :labels labels})
        onion-d (onion/onion-datoms onion-obs)
        ;; case evidence binds the C2's published payment address to the thief address
        link (onion/onion->address-evidence
              {:onion-id "onion-001" :address "0xthief-a"
               :evidence-cids ["bafkrei-synthetic-c2-screenshot"] :confidence 700})
        attr-d (attr/attribution-datoms [link] m)]
    {:analysis analysis
     :datoms (vec (concat (case/case-datoms mandate)
                          (:datoms analysis) onion-d attr-d))}))

#?(:clj
   (defn -main [& _]
     (let [{:keys [analysis datoms]} (run)
           classes (:classes analysis)
           exits (get-in analysis [:flow :exits])]
       (println "# tadori — Phase-0 case trace (SYNTHETIC authorized case; no live data)\n")
       (println (str "  case: " (:case-id mandate) " (phase " (:phase mandate) ", transparent-force-logged)"))
       (println (str "  clusters: " (count (distinct (vals (:clusters analysis))))
                     " · mixer(s): " (->> classes (filter #(= :mixer (val %))) (map key) vec)))
       (println (str "  flow exits (funds surfaced at): " exits
                     "  ← includes the labeled CEX deposit"))
       (println (str "  onion indicator: ransomware-c2 (public), payment-addr → thief via ENCRYPTED attribution edge"))
       (println (str "\n  " (count datoms) " case-anchored EAVT datoms (evidence-only; PII encrypted; live persist = operator+case gate)")))))
