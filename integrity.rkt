#lang racket/base

(require "contract.rkt")

; Mirror OpenSSL
(define xiden-hash-algorithms
  '(blake2b512
    blake2s256
    md4
    md5
    rmd160
    sha1
    sha1
    sha224
    sha256
    sha3-224
    sha3-256
    sha3-384
    sha3-512
    sha384
    sha512
    sha512-224
    sha512-256
    shake128
    shake256
    sm3))

(define xiden-hash-source/c
  (or/c path-string? bytes? input-port?))

(define xiden-hash-algorithm/c
  (apply or/c xiden-hash-algorithms))

(provide (struct-out integrity-info)
         (contract-out
          [xiden-hash-algorithms
           (non-empty-listof symbol?)]
          [xiden-hash-algorithm/c
           flat-contract?]
          [well-formed-integrity-info/c
           flat-contract?]
          [make-digest
           (-> xiden-hash-source/c
               xiden-hash-algorithm/c
               bytes?)]
          [make-fingerprint
           (-> path-string? bytes?)]
          [check-integrity
           (-> well-formed-integrity-info/c
               xiden-hash-source/c
               boolean?)]))

(require racket/sequence
         racket/format
         openssl/libcrypto
         (rename-in ffi/unsafe [-> _->])
         "encode.rkt"
         "file.rkt"
         "rc.rkt"
         "openssl.rkt")


(struct integrity-info (algorithm digest) #:prefab)

(define (digest-length-ok? info)
  (equal? (bytes-length (integrity-info-digest info))
          (bytes-length (make-digest #"whatever"
                                     (integrity-info-algorithm info)))))


(define (make-fingerprint path)
  (subbytes (make-digest path 'sha384) 0 20))


(define well-formed-integrity-info/c
  (and/c (struct/c integrity-info
                   xiden-hash-algorithm/c
                   bytes?)
         digest-length-ok?))


(define (make-integrity-info variant algorithm)
  (integrity-info algorithm (make-digest variant algorithm)))


(define (make-digest variant algorithm)
  (cond [(path-string? variant)
         (call-with-input-file variant (λ (i) (make-digest i algorithm)))]
        [(bytes? variant)
         (make-digest (open-input-bytes variant) algorithm)]
        [(input-port? variant)
         (define buffer (make-bytes (* 300 1024)))
         (digest-message algorithm
                         (λ (f)
                           (let loop ()
                             (define res (read-bytes-avail! buffer variant))
                             (if (exact-positive-integer? res)
                                 (begin (f buffer res) (loop))
                                 (void)))))]
        [else (raise-argument-error 'make-digest
                                    "A path, bytes, or an input port"
                                    variant)]))

(define (check-integrity info variant)
  (equal? (integrity-info-digest info)
          (make-digest variant (integrity-info-algorithm info))))

(module+ test
  (require rackunit)

  (test-case "Create integrity information"
    (for ([algorithm (in-list xiden-hash-algorithms)])
      (define bstr (string->bytes/utf-8 (symbol->string algorithm)))
      (define info (make-integrity-info bstr algorithm))
      (check-pred integrity-info? info)
      (check-eq? (integrity-info-algorithm info) algorithm)
      (check-equal? (integrity-info-digest info)
                    (make-digest bstr algorithm)))))
