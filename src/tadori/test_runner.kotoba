(ns tadori.test-runner
  (:require [clojure.test :as test]
            [tadori.kotoba.audit-log-test]
            [tadori.methods.address-checksum-test]
            [tadori.methods.charter-gates-test]
            [tadori.methods.manifest-invariants-test]
            [tadori.tests.autorun-test]
            [tadori.tests.ingest-test]
            [tadori.tests.malak-test]
            [tadori.tests.malak-contract-test]
            [tadori.tests.ofac-test]
            [tadori.tests.risk-test]
            [tadori.tests.trace-test]))

(def suites
  '[tadori.kotoba.audit-log-test
    tadori.methods.address-checksum-test
    tadori.methods.charter-gates-test
    tadori.methods.manifest-invariants-test
    tadori.tests.autorun-test
    tadori.tests.ingest-test
    tadori.tests.malak-test
    tadori.tests.malak-contract-test
    tadori.tests.ofac-test
    tadori.tests.risk-test
    tadori.tests.trace-test])

(defn -main [& _]
  (let [result (apply test/run-tests suites)]
    (when-not (zero? (+ (:fail result) (:error result)))
      (throw (ex-info "tadori tests failed" result)))))
