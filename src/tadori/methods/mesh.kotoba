;; mesh.clj — tadori 辿 KOTOBA Mesh entry component (Clojure / kotoba-clj).
;;
;; The mesh-hosting face of actor:tadori (authorized on-chain tx tracing + actor
;; attribution). Observatory on-kse pattern (ADR-2606230001 §4): observes
;; address→cluster attribution edges as Datom assertions and derives the trace
;; map via Datalog. The full EAVT-native tracing stays in the actor's methods.
;;
;; Posture: AUTHORIZED tracing only; aggregate attribution, never a private
;; surveillance dragnet; non-adjudicating.
;; host-imports: kqe-assert! / kqe-query → kotoba:kais/kqe (needs cap/kqe)
(ns tadori)

(defn observe []
  ;; observe — authorized on-chain attributions (address → cluster).
  (kqe-assert! "tadori" "address-a" "attributed" "cluster-x")
  (kqe-assert! "tadori" "address-b" "attributed" "cluster-x")
  (kqe-assert! "tadori" "address-c" "attributed" "cluster-y")
  ;; derive — attribution concentration → trace map (Datalog).
  (kqe-query "trace(?c) :- attributed(?c)."))

(defn run [ctx] (observe))
(defn on-kse [topic payload] (observe))
