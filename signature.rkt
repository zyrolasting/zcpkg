#lang racket/base

(require "contract.rkt")

(provide (struct-out signature-info)
         (contract-out
          [make-signature
           (-> bytes? path-string? bytes?)]
          [well-formed-signature-info/c
           flat-contract?]
          [find-public-key
           (-> bytes? bytes?)]
          [check-signature
           (-> bytes? bytes? bytes? boolean?)]))

(require racket/format
         racket/path
         racket/port
         racket/sequence
         racket/string
         file/sha1
         "encode.rkt"
         "file.rkt"
         "integrity.rkt"
         "rc.rkt"
         "openssl.rkt")


(struct signature-info (pubkey body) #:prefab)


(define (well-formed-signature-info/c info)
  (struct/c signature-info
            bytes?
            bytes?))


(define (make-signature digest private-key-path)
  (run-openssl-command (open-input-bytes digest)
                       "pkeyutl"
                       "-sign"
                       "-inkey" private-key-path))


(define (find-public-key grouped-hex-string)
  (define fingerprint (decode 'colon-separated-hex grouped-hex-string))
  (unless fingerprint
    (raise-user-error 'find-public-key
                      "Expected a 160-bit (20 byte) grouped hex string. Got ~e"
                      grouped-hex-string))
  (hash-ref (XIDEN_PUBLIC_KEYS)
            fingerprint
            (λ () (raise-user-error 'find-public-key
                                    (string-append "Could not find trusted public key using fingerprint ~e.~n"
                                                   "Did you add the key to your configuration?")
                                    grouped-hex-string))))



(define (check-signature digest signature public-key)
  (define tmpsig (make-temporary-file))
  (call-with-output-file tmpsig
    #:exists 'truncate/replace
    (λ (o) (copy-port (open-input-bytes signature) o)))

  (define-values (exit-code msg)
    (run-openssl-command
     (open-input-bytes digest)
     "pkeyutl"
     "-verify"
     "-sigfile" tmpsig
     "-pubin" "-inkey" public-key))

  (eq? exit-code 0))
