(ns onepass.aes
  (:import [java.security.SecureRandom]
           [javax.crypto.Cipher]
           [javax.crypto.KeyGenerator]
           [javax.crypto.Mac]
           [javax.crypto.spec.SecretKeySpec]
           [javax.crypto.spec.IvParameterSpec]
           [java.util.UUID]))

(def encrypt-defaults
  {:algorithm  "AES"
   :key-size   128
   :mode       "CBC"
   :padding    "NoPadding"})

(defn- make-algorithm
  "Return an algorithm string suitable for JCE from a map of options."
  [options]
  (str "AES/" (options :mode) "/" (options :padding)))

(defn- make-cipher
  "Create an AES Cipher instance."
  [options]
  (Cipher/getInstance (make-algorithm options)))

(defn decrypt-bytes
  "Decrypts a byte array with the given key and encryption options."
  [data k iv & [options]]
  (let [options    (merge encrypt-defaults options)
        cipher     (make-cipher options)
        iv-spec    (IvParameterSpec. iv)
        secret-key (SecretKeySpec. k (options :algorithm))]
    (.init cipher Cipher/DECRYPT_MODE secret-key iv-spec)
    (.doFinal cipher data)))

(defn decrypt
  "Base64 encodes and encrypts a string with the given key and algorithm."
  [options key data]
  (String. (decrypt-bytes options key (b64/decode data))))
