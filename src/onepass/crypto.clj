(ns onepass.crypto
  (:require [buddy.core.crypto         :as crypto]
            [buddy.core.kdf            :as kdf]
            [buddy.core.hash           :as buddyhash]
            [buddy.core.padding        :as padding]
            [buddy.core.bytes          :as b]
            [clojure.data.codec.base64 :as b64]
            [onepass.aes               :as aes]))

(def SALT_PREFIX (.getBytes "Salted__"))
(def SALT_SIZE   (alength SALT_PREFIX))

(defn base64encode
  [s]
  (cond (b/bytes? s) (b64/encode s)
        (string? s)  (b64/encode (.getBytes s))
        :else        (throw (Exception. "cannot encode that my dude"))))

(defn base64decode
  [s]
  (cond (b/bytes? s) (b64/decode s)
        (string? s)  (b64/decode (.getBytes s))
        :else        (throw (Exception. "cannot decode that my dude"))))

(defn get-bytes
  ([a from to]
   (let [len  (alength a)
         from (cond
                (nil? from) 0
                (neg? from) (+ len from)
                :else       from)
         to   (cond
                (nil? to) len
                (neg? to) (+ len to)
                :else     to)
         size (- to from)]
     (byte-array size (take to (drop from a)))))
  ([a from]
   (get-bytes a from nil)))

(defn validate
  [validation k]
  (let [salt     (get-bytes validation SALT_SIZE (* 2 SALT_SIZE))
        vdata    (get-bytes validation (* 2 SALT_SIZE))
        k2       (get-bytes k 0 (* -2 SALT_SIZE))
        k-and-iv (atom (.getBytes ""))
        prev     (atom (.getBytes ""))]
    (while (< (alength @k-and-iv) 32)
      (reset! prev (buddyhash/md5 (b/concat @prev k2 salt)))
      (reset! k-and-iv (b/concat @k-and-iv @prev)))
    (let [derived @k-and-iv
          k3      (get-bytes @k-and-iv 0 (* 2 SALT_SIZE))
          iv      (get-bytes @k-and-iv (* 2 SALT_SIZE))]
      (b/equals? k (aes/decrypt-bytes vdata k3 iv)))))


(defn decrypt-key
  [{:keys [data iterations validation] :as key_obj} password]
  (let [data-bytes    (base64decode data)
        key-size      16
        pw-bytes      (if (b/bytes? password)
                        password
                        (.getBytes password))
        salt          (get-bytes data-bytes SALT_SIZE (* 2 SALT_SIZE))
        data          (get-bytes data-bytes (* 2 SALT_SIZE))
        engine        (kdf/engine {:alg        :pbkdf2
                                   :key        pw-bytes
                                   :salt       salt
                                   :digest     :sha1
                                   :iterations iterations})
        derived       (kdf/get-bytes engine (* 2 key-size))
        k             (get-bytes derived 0 key-size)
        iv            (get-bytes derived key-size nil)
        potential_key (aes/decrypt-bytes data k iv)
        vbytes        (base64decode validation)]
    (validate vbytes potential_key)))
