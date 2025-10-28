(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-CREDENTIAL-ID u101)
(define-constant ERR-CREDENTIAL-NOT-FOUND u102)
(define-constant ERR-ALREADY-REVOKED u103)
(define-constant ERR-NOT-REVOKED u104)
(define-constant ERR-INVALID-ISSUER u105)
(define-constant ERR-INVALID-PROOF u106)
(define-constant ERR-INVALID-TIMESTAMP u107)
(define-constant ERR-INVALID-REASON u108)
(define-constant ERR-INVALID-SIGNATURE u109)
(define-constant ERR-INVALID-STATUS u110)
(define-constant ERR-INVALID-UPDATE u111)
(define-constant ERR-INVALID-QUERY u112)
(define-constant ERR-INVALID-VERIFIER u113)
(define-constant ERR-INVALID-REQUEST u114)
(define-constant ERR-INVALID-RESPONSE u115)
(define-constant ERR-INVALID-INDEX u116)
(define-constant ERR-INVALID-LEVEL u117)
(define-constant ERR-INVALID-CATEGORY u118)
(define-constant ERR-INVALID-LOCATION u119)
(define-constant ERR-INVALID-CURRENCY u120)
(define-constant ERR-ACCESS-DENIED u121)
(define-constant ERR-ROLE-REQUIRED u122)
(define-constant ERR-MAX-REVOCATIONS u123)
(define-constant ERR-STRING-LENGTH u124)
(define-constant ERR-BUFFER-SIZE u125)
(define-constant ERR-VERIFICATION-FAILED u126)
(define-constant ERR-ISSUER-MISMATCH u127)
(define-constant ERR-EXPIRY-PASSED u128)
(define-constant ERR-REVOCATION-EXISTS u129)

(define-data-var authority-contract (optional principal) none)
(define-data-var max-revocations-per-issuer uint u100)

(define-map revocations uint
  { issuer: principal, reason: (string-utf8 256), timestamp: uint, proof: (buff 64), revoked-by: principal })

(define-map revocation-index principal (list 100 uint))

(define-map issuer-stats principal { total: uint, active: uint })

(define-read-only (is-revoked (credential-id uint))
  (is-some (map-get? revocations credential-id)))

(define-read-only (get-revocation (credential-id uint))
  (map-get? revocations credential-id))

(define-read-only (get-revocation-ids (issuer principal))
  (default-to (list) (map-get? revocation-index issuer)))

(define-read-only (get-issuer-stats (issuer principal))
  (default-to { total: u0, active: u0 } (map-get? issuer-stats issuer)))

(define-read-only (get-revocation-count)
  (ok (fold + (map (lambda (id) u1) (map-get? revocation-index tx-sender)) u0)))

(define-private (validate-credential-id (id uint))
  (if (> id u0) (ok true) (err ERR-INVALID-CREDENTIAL-ID)))

(define-private (validate-issuer (issuer principal))
  (if (not (is-eq issuer tx-sender)) (err ERR-INVALID-ISSUER) (ok true)))

(define-private (validate-reason (reason (string-utf8 256)))
  (if (and (> (len reason) u0) (<= (len reason) u256)) (ok true) (err ERR-INVALID-REASON)))

(define-private (validate-proof (proof (buff 64)))
  (if (is-eq (len proof) u64) (ok true) (err ERR-INVALID-PROOF)))

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height) (ok true) (err ERR-INVALID-TIMESTAMP)))

(define-private (validate-index (index uint))
  (if (< index u100) (ok true) (err ERR-INVALID-INDEX)))

(define-private (validate-string-length (s (string-utf8 256)) (max uint))
  (if (<= (len s) max) (ok true) (err ERR-STRING-LENGTH)))

(define-private (validate-authority)
  (if (is-some (var-get authority-contract)) (ok true) (err ERR-NOT-AUTHORIZED)))

(define-public (set-authority-contract (contract principal))
  (begin
    (try! (validate-issuer contract))
    (var-set authority-contract (some contract))
    (ok true)))

(define-public (set-max-revocations (new-max uint))
  (begin
    (try! (validate-authority))
    (asserts! (and (> new-max u0) (<= new-max u500)) (err ERR-INVALID-UPDATE))
    (var-set max-revocations-per-issuer new-max)
    (ok true)))

(define-public (revoke-credential
  (credential-id uint)
  (reason (string-utf8 256))
  (proof (buff 64)))
  (let ((existing (get-revocation credential-id))
        (ids (get-revocation-ids tx-sender))
        (stats (get-issuer-stats tx-sender)))
    (try! (validate-credential-id credential-id))
    (try! (validate-reason reason))
    (try! (validate-proof proof))
    (asserts! (is-none existing) (err ERR-ALREADY-REVOKED))
    (asserts! (< (len ids) (var-get max-revocations-per-issuer)) (err ERR-MAX-REVOCATIONS))
    (map-set revocations credential-id
      { issuer: tx-sender, reason: reason, timestamp: block-height, proof: proof, revoked-by: tx-sender })
    (map-set revocation-index tx-sender
      (unwrap! (as-max-len? (append ids credential-id) u100) (err ERR-STRING-LENGTH)))
    (map-set issuer-stats tx-sender
      (merge stats { total: (+ (get total stats) u1), active: (+ (get active stats) u1) }))
    (print { event: "credential-revoked", id: credential-id, issuer: tx-sender })
    (ok true)))

(define-public (update-revocation
  (credential-id uint)
  (new-reason (string-utf8 256))
  (new-proof (buff 64)))
  (let ((revocation (unwrap! (get-revocation credential-id) (err ERR-CREDENTIAL-NOT-FOUND))))
    (try! (validate-credential-id credential-id))
    (asserts! (is-eq (get issuer revocation) tx-sender) (err ERR-NOT-AUTHORIZED))
    (try! (validate-reason new-reason))
    (try! (validate-proof new-proof))
    (map-set revocations credential-id
      (merge revocation { reason: new-reason, proof: new-proof }))
    (print { event: "revocation-updated", id: credential-id })
    (ok true)))

(define-public (unrevoke-credential (credential-id uint))
  (let ((revocation (unwrap! (get-revocation credential-id) (err ERR-CREDENTIAL-NOT-FOUND)))
        (stats (get-issuer-stats tx-sender)))
    (try! (validate-credential-id credential-id))
    (asserts! (is-eq (get issuer revocation) tx-sender) (err ERR-NOT-AUTHORIZED))
    (map-delete revocations credential-id)
    (map-set issuer-stats tx-sender
      (merge stats { active: (- (get active stats) u1) }))
    (print { event: "credential-unrevoked", id: credential-id })
    (ok true)))

(define-public (get-revocation-by-index (issuer principal) (index uint))
  (let ((ids (get-revocation-ids issuer)))
    (try! (validate-index index))
    (ok (unwrap! (element-at ids index) (err ERR-INVALID-INDEX)))))

(define-public (check-revocation-existence (credential-id uint))
  (ok (is-some (get-revocation credential-id))))

(define-public (get-total-revocations)
  (let ((total u0))
    (fold (lambda (issuer stats) (+ total (get total stats)))
          (map-get? issuer-stats tx-sender) total)))