(ns tadori.host.http
  "Babashka HTTP host adapter. Network authority terminates here."
  (:require [babashka.http-client :as http]
            [tadori.methods.transact :as transact]))

(defn -main [& args]
  (transact/run-cli http/request args))
