(ns onepass.vault
  (:require [cheshire.core             :as json]))

(def BASE_DIR (str (System/getProperty "user.home") "/Dropbox/Apps/1Password/1Password.agilekeychain"))
(def DATA_DIR (str BASE_DIR "/data/default"))

(def type-map {"webforms.WebForm"                 "Logins"
               "wallet.financial.CreditCard"      "Credit cards"
               "passwords.Password"               "Passwords"
               "wallet.financial.BankAccountUS"   "Bank accounts"
               "wallet.membership.Membership"     "Memberships"
               "wallet.government.DriversLicense" "Drivers licenses"
               "system.Tombstone"                 "Dead items"
               "securenotes.SecureNote"           "Secure notes"
               "wallet.government.SsnUS"          "Social Security Numbers"
               "wallet.computer.Router"           "Router passwords"})

(def type-order ["webforms.WebForm"
                 "wallet.financial.CreditCard"
                 "passwords.Password"
                 "wallet.financial.BankAccountUS"
                 "wallet.membership.Membership"
                 "wallet.government.DriversLicense"
                 "wallet.government.SsnUS"
                 "securenotes.SecureNote"
                 "wallet.computer.Router"
                 ;don't show "system.Tombstone"
                 ])


(defonce encryption-keys (atom {}))
(defonce contents (atom {}))

(defn load-json-file
  [filename]
  (-> (format "%s/%s" DATA_DIR filename)
      slurp
      (json/parse-string true)))

(defn load-content-by-uuid
  [uuid]
  (try
    (load-json-file (str uuid ".1password"))
    (catch Exception _)))

;; keys in this guy, not sure if we'll use them all
;; :typeName :updatedAt :createdAt :title :locationKey :securityLevel
;; :openContents :uuid :contentsHash :encrypted :location :faveIndex
(defn content-to-map
  [content]
  (load-content-by-uuid (first content)))

(defn load-data!
  []
  (reset! contents (map content-to-map (load-json-file "contents.js")))
  (reset! encryption-keys (:list (load-json-file "encryptionKeys.js"))))

#_(defn unlock
  [password]
  (let [decrypted  (derive-pbkdf2 password)
        validation (derive-openssl decrypted)]))
