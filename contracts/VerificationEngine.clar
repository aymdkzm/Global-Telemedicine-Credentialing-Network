(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-CREDENTIAL-ID u101)
(define-constant ERR-CREDENTIAL-NOT-FOUND u102)
(define-constant ERR-CREDENTIAL-EXPIRED u103)
(define-constant ERR-CREDENTIAL-REVOKED u104)
(define-constant ERR-INVALID-ISSUER u105)
(define-constant ERR-INVALID-PROOF u106)
(define-constant ERR-INVALID-DOCTOR u107)
(define-constant ERR-INVALID-EXPIRY u108)
(define-constant ERR-INVALID-HASH u109)
(define-constant ERR-INVALID-TYPE u110)
(define-constant ERR-INVALID-STATUS u111)
(define-constant ERR-INVALID-THRESHOLD u112)
(define-constant ERR-INVALID-VERIFIER u113)
(define-constant ERR-INVALID-REQUEST u114)
(define-constant ERR-INVALID-RESPONSE u115)
(define-constant ERR-INVALID-SIGNATURE u116)
(define-constant ERR-INVALID-ACCESS u117)
(define-constant ERR-INVALID-ROLE u118)
(define-constant ERR-INVALID-PARAM u119)
(define-constant ERR-INVALID-UPDATE u120)
(define-constant ERR-INVALID-QUERY u121)
(define-constant ERR-INVALID-VERIFICATION u122)
(define-constant ERR-INVALID-CONTEXT u123)
(define-constant ERR-INVALID-METADATA u124)
(define-constant ERR-INVALID-LEVEL u125)
(define-constant ERR-INVALID-CATEGORY u126)
(define-constant ERR-INVALID-LOCATION u127)
(define-constant ERR-INVALID-CURRENCY u128)
(define-constant ERR-VERIFICATION-FAILED u129)
(define-constant ERR-ACCESS-DENIED u130)

(define-data-var verification-fee uint u10)
(define-data-var min-proof-threshold uint u50)
(define-data-var authority-contract (optional principal) none)

(define-map credentials { doctor: principal, id: uint }
  { hash: (buff 32), expiry: uint, issuer: principal, type: (string-utf8 50), status: bool, metadata: (string-utf8 256) })
(define-map revocations uint bool)
(define-map verifiers principal bool)
(define-map verification-history { doctor: principal, verifier: principal, timestamp: uint }
  { credential-id: uint, result: bool, proof: (buff 64) })
(define-map credential-types (string-utf8 50) uint)
(define-map access-roles { principal: principal, role: (string-utf8 20) } bool)

(define-read-only (get-credential (doctor principal) (id uint))
  (map-get? credentials { doctor: doctor, id: id }))

(define-read-only (is-revoked (id uint))
  (default-to false (map-get? revocations id)))

(define-read-only (is-valid-issuer (issuer principal))
  (default-to false (map-get? verifiers issuer)))

(define-read-only (get-verification-history (doctor principal) (verifier principal) (timestamp uint))
  (map-get? verification-history { doctor: doctor, verifier: verifier, timestamp: timestamp }))

(define-read-only (get-credential-type-level (type (string-utf8 50)))
  (map-get? credential-types type))

(define-read-only (has-access-role (p principal) (role (string-utf8 20)))
  (default-to false (map-get? access-roles { principal: p, role: role })))

(define-private (validate-doctor (doctor principal))
  (if (is-eq doctor tx-sender) (ok true) (err ERR-INVALID-DOCTOR)))

(define-private (validate-credential-id (id uint))
  (if (> id u0) (ok true) (err ERR-INVALID-CREDENTIAL-ID)))

(define-private (validate-expiry (expiry uint))
  (if (> expiry block-height) (ok true) (err ERR-INVALID-EXPIRY)))

(define-private (validate-hash (hash (buff 32)))
  (if (is-eq (len hash) u32) (ok true) (err ERR-INVALID-HASH)))

(define-private (validate-type (type (string-utf8 50)))
  (if (is-some (get-credential-type-level type)) (ok true) (err ERR-INVALID-TYPE)))

(define-private (validate-status (status bool))
  (ok status))

(define-private (validate-metadata (metadata (string-utf8 256)))
  (if (<= (len metadata) u256) (ok true) (err ERR-INVALID-METADATA)))

(define-private (validate-proof (proof (buff 64)))
  (if (is-eq (len proof) u64) (ok true) (err ERR-INVALID-PROOF)))

(define-private (validate-verifier (verifier principal))
  (if (is-valid-issuer verifier) (ok true) (err ERR-INVALID-VERIFIER)))

(define-private (validate-threshold (threshold uint))
  (if (>= threshold (var-get min-proof-threshold)) (ok true) (err ERR-INVALID-THRESHOLD)))

(define-private (validate-signature (signature (buff 65)))
  (if (is-eq (len signature) u65) (ok true) (err ERR-INVALID-SIGNATURE)))

(define-private (validate-role (role (string-utf8 20)))
  (if (or (is-eq role "admin") (is-eq role "verifier") (is-eq role "doctor")) (ok true) (err ERR-INVALID-ROLE)))

(define-private (validate-param (param uint))
  (if (> param u0) (ok true) (err ERR-INVALID-PARAM)))

(define-private (validate-update (update bool))
  (ok update))

(define-private (validate-query (query (string-utf8 100)))
  (if (> (len query) u0) (ok true) (err ERR-INVALID-QUERY)))

(define-private (validate-verification (result bool))
  (ok result))

(define-private (validate-context (context uint))
  (if (> context u0) (ok true) (err ERR-INVALID-CONTEXT)))

(define-private (validate-level (level uint))
  (if (<= level u10) (ok true) (err ERR-INVALID-LEVEL)))

(define-private (validate-category (category (string-utf8 50)))
  (if (> (len category) u0) (ok true) (err ERR-INVALID-CATEGORY)))

(define-private (validate-location (loc (string-utf8 100)))
  (if (> (len loc) u0) (ok true) (err ERR-INVALID-LOCATION)))

(define-private (validate-currency (cur (string-utf8 20)))
  (if (or (is-eq cur "STX") (is-eq cur "USD")) (ok true) (err ERR-INVALID-CURRENCY)))

(define-public (set-authority-contract (contract principal))
  (begin
    (asserts! (is-eq tx-sender contract) (err ERR-NOT-AUTHORIZED))
    (var-set authority-contract (some contract))
    (ok true)))

(define-public (set-verification-fee (new-fee uint))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (try! (validate-param new-fee))
    (var-set verification-fee new-fee)
    (ok true)))

(define-public (set-min-proof-threshold (new-threshold uint))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (try! (validate-threshold new-threshold))
    (var-set min-proof-threshold new-threshold)
    (ok true)))

(define-public (add-verifier (verifier principal))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (try! (validate-verifier verifier))
    (map-set verifiers verifier true)
    (ok true)))

(define-public (remove-verifier (verifier principal))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (map-delete verifiers verifier)
    (ok true)))

(define-public (verify-credential (doctor principal) (id uint) (proof (buff 64)))
  (let ((cred (get-credential doctor id)))
    (match cred c
      (begin
        (try! (validate-doctor doctor))
        (try! (validate-credential-id id))
        (try! (validate-proof proof))
        (asserts! (not (is-revoked id)) (err ERR-CREDENTIAL-REVOKED))
        (try! (validate-expiry (get expiry c)))
        (asserts! (is-valid-issuer (get issuer c)) (err ERR-INVALID-ISSUER))
        (try! (validate-type (get type c)))
        (asserts! (get status c) (err ERR-INVALID-STATUS))
        (try! (validate-metadata (get metadata c)))
        (try! (stx-transfer? (var-get verification-fee) tx-sender (unwrap! (var-get authority-contract) (err ERR-NOT-AUTHORIZED))))
        (map-set verification-history { doctor: doctor, verifier: tx-sender, timestamp: block-height }
          { credential-id: id, result: true, proof: proof })
        (print { event: "credential-verified", doctor: doctor, id: id })
        (ok true))
      (err ERR-CREDENTIAL-NOT-FOUND))))

(define-public (batch-verify-credentials (doctors (list 10 principal)) (ids (list 10 uint)) (proofs (list 10 (buff 64))))
  (fold batch-verify-inner (zip doctors ids proofs) (ok true)))

(define-private (batch-verify-inner (entry {d: principal, i: uint, p: (buff 64)}) (acc (response bool uint)))
  (match acc a
    (try! (verify-credential (get d entry) (get i entry) (get p entry)))
    acc))

(define-public (get-verification-status (doctor principal) (id uint))
  (let ((cred (get-credential doctor id)))
    (match cred c
      (ok (and (not (is-revoked id)) (> (get expiry c) block-height) (get status c)))
      (err ERR-CREDENTIAL-NOT-FOUND))))

(define-public (add-credential-type (type (string-utf8 50)) (level uint))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (try! (validate-type type))
    (try! (validate-level level))
    (map-set credential-types type level)
    (ok true)))

(define-public (assign-role (p principal) (role (string-utf8 20)))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (try! (validate-role role))
    (map-set access-roles { principal: p, role: role } true)
    (ok true)))

(define-public (revoke-role (p principal) (role (string-utf8 20)))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (map-delete access-roles { principal: p, role: role })
    (ok true)))

(define-public (check-access (p principal) (role (string-utf8 20)))
  (ok (has-access-role p role)))