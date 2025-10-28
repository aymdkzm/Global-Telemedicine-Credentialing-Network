(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-DOCTOR u101)
(define-constant ERR-INVALID-ID u102)
(define-constant ERR-CREDENTIAL-EXISTS u103)
(define-constant ERR-CREDENTIAL-NOT-FOUND u104)
(define-constant ERR-INVALID-HASH u105)
(define-constant ERR-INVALID-EXPIRY u106)
(define-constant ERR-INVALID-TYPE u107)
(define-constant ERR-INVALID-METADATA u108)
(define-constant ERR-INVALID-ISSUER u109)
(define-constant ERR-INVALID-STATUS u110)
(define-constant ERR-INVALID-PROOF u111)
(define-constant ERR-TRANSFER-FAILED u112)
(define-constant ERR-OWNERSHIP-MISMATCH u113)
(define-constant ERR-INVALID-OWNER u114)
(define-constant ERR-INVALID-RECIPIENT u115)
(define-constant ERR-INVALID-UPDATE u116)
(define-constant ERR-INVALID-QUERY u117)
(define-constant ERR-INVALID-CATEGORY u118)
(define-constant ERR-INVALID-LEVEL u119)
(define-constant ERR-INVALID-LOCATION u120)
(define-constant ERR-INVALID-CURRENCY u121)
(define-constant ERR-STORE-FAILED u122)
(define-constant ERR-DELETE-FAILED u123)
(define-constant ERR-ACCESS-DENIED u124)
(define-constant ERR-ROLE-REQUIRED u125)
(define-constant ERR-MAX-CREDENTIALS u126)
(define-constant ERR-INVALID-INDEX u127)
(define-constant ERR-BUFFER-SIZE u128)
(define-constant ERR-STRING-LENGTH u129)

(define-data-var next-credential-id uint u1)
(define-data-var max-credentials-per-doctor uint u50)
(define-data-var authority-contract (optional principal) none)

(define-non-fungible-token credential uint)

(define-map credentials { doctor: principal, id: uint }
  { hash: (buff 32), expiry: uint, issuer: principal, type: (string-utf8 50), status: bool, metadata: (string-utf8 256), owner: principal })

(define-map credential-index principal (list 50 uint))

(define-map credential-types (string-utf8 50) { level: uint, category: (string-utf8 50) })

(define-map doctor-stats principal { total: uint, active: uint, revoked: uint })

(define-read-only (get-credential (doctor principal) (id uint))
  (map-get? credentials { doctor: doctor, id: id }))

(define-read-only (get-credential-nft-owner (id uint))
  (nft-get-owner? credential id))

(define-read-only (get-credential-ids (doctor principal))
  (default-to (list) (map-get? credential-index doctor)))

(define-read-only (get-credential-type (type (string-utf8 50)))
  (map-get? credential-types type))

(define-read-only (get-doctor-stats (doctor principal))
  (default-to { total: u0, active: u0, revoked: u0 } (map-get? doctor-stats doctor)))

(define-read-only (is-credential-owner (id uint) (owner principal))
  (match (nft-get-owner? credential id)
    current (is-eq current owner)
    false))

(define-private (validate-doctor (doctor principal))
  (if (not (is-eq doctor tx-sender)) (err ERR-INVALID-DOCTOR) (ok true)))

(define-private (validate-id (id uint))
  (if (> id u0) (ok true) (err ERR-INVALID-ID)))

(define-private (validate-hash (hash (buff 32)))
  (if (is-eq (len hash) u32) (ok true) (err ERR-INVALID-HASH)))

(define-private (validate-expiry (expiry uint))
  (if (> expiry block-height) (ok true) (err ERR-INVALID-EXPIRY)))

(define-private (validate-type (type (string-utf8 50)))
  (if (is-some (get-credential-type type)) (ok true) (err ERR-INVALID-TYPE)))

(define-private (validate-metadata (metadata (string-utf8 256)))
  (if (<= (len metadata) u256) (ok true) (err ERR-INVALID-METADATA)))

(define-private (validate-issuer (issuer principal))
  (ok true))

(define-private (validate-status (status bool))
  (ok status))

(define-private (validate-owner (owner principal))
  (if (not (is-eq owner tx-sender)) (err ERR-INVALID-OWNER) (ok true)))

(define-private (validate-recipient (recipient principal))
  (if (not (is-eq recipient tx-sender)) (ok true) (err ERR-INVALID-RECIPIENT)))

(define-private (validate-category (cat (string-utf8 50)))
  (if (> (len cat) u0) (ok true) (err ERR-INVALID-CATEGORY)))

(define-private (validate-level (lvl uint))
  (if (<= lvl u10) (ok true) (err ERR-INVALID-LEVEL)))

(define-private (validate-location (loc (string-utf8 100)))
  (if (> (len loc) u0) (ok true) (err ERR-INVALID-LOCATION)))

(define-private (validate-currency (cur (string-utf8 20)))
  (if (or (is-eq cur "STX") (is-eq cur "USD")) (ok true) (err ERR-INVALID-CURRENCY)))

(define-private (validate-index (index uint))
  (if (< index u50) (ok true) (err ERR-INVALID-INDEX)))

(define-private (validate-string-length (s (string-utf8 256)) (max uint))
  (if (<= (len s) max) (ok true) (err ERR-STRING-LENGTH)))

(define-public (set-authority-contract (contract principal))
  (begin
    (try! (validate-owner contract))
    (var-set authority-contract (some contract))
    (ok true)))

(define-public (set-max-credentials (new-max uint))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (asserts! (and (> new-max u0) (<= new-max u100)) (err ERR-INVALID-UPDATE))
    (var-set max-credentials-per-doctor new-max)
    (ok true)))

(define-public (register-credential
  (doctor principal)
  (hash (buff 32))
  (expiry uint)
  (issuer principal)
  (type (string-utf8 50))
  (metadata (string-utf8 256)))
  (let ((id (var-get next-credential-id))
        (existing (get-credential doctor id))
        (ids (get-credential-ids doctor))
        (stats (get-doctor-stats doctor)))
    (try! (validate-doctor doctor))
    (asserts! (is-none existing) (err ERR-CREDENTIAL-EXISTS))
    (asserts! (< (len ids) (var-get max-credentials-per-doctor)) (err ERR-MAX-CREDENTIALS))
    (try! (validate-hash hash))
    (try! (validate-expiry expiry))
    (try! (validate-type type))
    (try! (validate-metadata metadata))
    (try! (validate-issuer issuer))
    (try! (nft-mint? credential id doctor))
    (map-set credentials { doctor: doctor, id: id }
      { hash: hash, expiry: expiry, issuer: issuer, type: type, status: true, metadata: metadata, owner: doctor })
    (map-set credential-index doctor (unwrap! (as-max-len? (append ids id) u50) (err ERR-STORE-FAILED)))
    (map-set doctor-stats doctor
      (merge stats { total: (+ (get total stats) u1), active: (+ (get active stats) u1) }))
    (var-set next-credential-id (+ id u1))
    (print { event: "credential-registered", id: id, doctor: doctor })
    (ok id)))

(define-public (update-credential
  (doctor principal)
  (id uint)
  (metadata (string-utf8 256))
  (status bool))
  (let ((cred (get-credential doctor id)))
    (match cred c
      (begin
        (try! (validate-doctor doctor))
        (try! (validate-id id))
        (try! (validate-metadata metadata))
        (try! (validate-status status))
        (asserts! (is-credential-owner id doctor) (err ERR-OWNERSHIP-MISMATCH))
        (map-set credentials { doctor: doctor, id: id }
          (merge c { metadata: metadata, status: status }))
        (print { event: "credential-updated", id: id, doctor: doctor })
        (ok true))
      (err ERR-CREDENTIAL-NOT-FOUND))))

(define-public (transfer-credential
  (id uint)
  (recipient principal))
  (let ((cred (unwrap! (get-credential-nft-owner id) (err ERR-CREDENTIAL-NOT-FOUND))))
    (try! (validate-recipient recipient))
    (asserts! (is-eq cred tx-sender) (err ERR-NOT-AUTHORIZED))
    (try! (nft-transfer? credential id tx-sender recipient))
    (print { event: "credential-transferred", id: id, from: tx-sender, to: recipient })
    (ok true)))

(define-public (revoke-credential
  (doctor principal)
  (id uint))
  (let ((cred (get-credential doctor id))
        (stats (get-doctor-stats doctor)))
    (match cred c
      (begin
        (try! (validate-doctor doctor))
        (try! (validate-id id))
        (asserts! (get status c) (err ERR-INVALID-STATUS))
        (map-set credentials { doctor: doctor, id: id } (merge c { status: false }))
        (map-set doctor-stats doctor
          (merge stats { active: (- (get active stats) u1), revoked: (+ (get revoked stats) u1) }))
        (print { event: "credential-revoked", id: id, doctor: doctor })
        (ok true))
      (err ERR-CREDENTIAL-NOT-FOUND))))

(define-public (add-credential-type
  (type (string-utf8 50))
  (level uint)
  (category (string-utf8 50)))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (try! (validate-type type))
    (try! (validate-level level))
    (try! (validate-category category))
    (map-set credential-types type { level: level, category: category })
    (ok true)))

(define-public (get-credential-count)
  (ok (var-get next-credential-id)))

(define-public (get-credential-by-index (doctor principal) (index uint))
  (let ((ids (get-credential-ids doctor)))
    (try! (validate-index index))
    (ok (unwrap! (element-at ids index) (err ERR-INVALID-INDEX)))))

(define-public (check-credential-existence (doctor principal) (id uint))
  (ok (is-some (get-credential doctor id))))