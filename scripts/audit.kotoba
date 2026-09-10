(require '[clojure.edn :as edn]
         '[clojure.java.io :as io]
         '[kotoba.lang.text :as str])

(def files
  (->> (file-seq (io/file "."))
       (filter #(.isFile %))
       (map #(.getPath %))
       (remove #(str/starts-with? % "./.git/"))))

(doseq [path (filter #(str/ends-with? % ".edn") files)]
  (edn/read-string (slurp path)))

(let [misplaced (filter #(and (re-find #"\.(?:json|jsonld|jsonl|bpmn)$" %)
                              (not (str/starts-with? % "./wire/"))
                              (not= % "./.well-known/did.json")) files)
      forbidden (filter #(re-find #"(?:^|/)(?:go\.mod|go\.sum|.*\.go|run_tests\.sh|deploy\.sh)$" %) files)]
  (when (seq misplaced) (throw (ex-info "external formats must live under wire/" {:files misplaced})))
  (when (seq forbidden) (throw (ex-info "deprecated Go/shell artifacts found" {:files forbidden}))))

(println "EDN and artifact audit passed")
