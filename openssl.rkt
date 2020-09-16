#lang racket/base

(require "contract.rkt")
(provide (struct-out integrity-info)
         (contract-out
          [hash-algorithms
           (non-empty-listof symbol?)]
          [hash-algorithm/c
           flat-contract?]
          [well-formed-integrity-info/c
           flat-contract?]
          [digest-message
           (-> hash-source/c
               hash-algorithm/c
               bytes?)]
          [make-fingerprint
           (-> path-string? bytes?)]))


(require racket/file
         racket/format
         racket/function
         racket/path
         racket/port
         racket/sequence
         openssl/libcrypto
         openssl/libssl
         (rename-in ffi/unsafe [-> _->])
         "contract.rkt"
         "exn.rkt"
         "file.rkt"
         "query.rkt"
         "rc.rkt"
         "string.rkt"
         "url.rkt")


;------------------------------------------------------------------------------
; libcrypto/libssl FFI bindings

(define (cbind sym type)
  (and libcrypto
       (get-ffi-obj sym libcrypto type
                    (λ ()
                      (get-ffi-obj sym libssl type
                                   (error 'cbind "Could not bind ~a" sym))))))


(define _EVP_MD_pointer _pointer)
(define _EVP_MD_CTX_pointer _pointer)
(define _EVP_MD_CTX_new (cbind 'EVP_MD_CTX_new (_fun _-> _EVP_MD_pointer)))
(define _EVP_MD_CTX_free (cbind 'EVP_MD_CTX_free (_fun _EVP_MD_pointer _-> _void)))
(define _EVP_DigestInit_ex (cbind 'EVP_DigestInit_ex (_fun _EVP_MD_CTX_pointer _pointer _pointer _-> _int)))
(define _EVP_DigestUpdate (cbind 'EVP_DigestUpdate (_fun _EVP_MD_CTX_pointer _pointer _int _-> _int)))
(define _EVP_DigestFinal_ex (cbind 'EVP_DigestFinal_ex (_fun _EVP_MD_pointer _pointer _pointer _-> _int)))
(define _EVP_MD_size (cbind 'EVP_MD_size (_fun _pointer _-> _int)))
(define _CRYPTO_malloc (cbind 'CRYPTO_malloc (_fun _int _-> _pointer)))
(define _OPENSSL_malloc _CRYPTO_malloc)
(define _EVP_DigestSignInit (cbind 'EVP_DigestSignInit (_fun _EVP_MD_CTX_pointer _pointer _pointer _pointer _pointer _-> _int)))
(define _EVP_DigestSignUpdate (cbind 'EVP_DigestSign (_fun _EVP_MD_CTX_pointer _pointer _int _-> _int)))
(define _EVP_DigestSignFinal (cbind 'EVP_DigestSignFinal (_fun _EVP_MD_CTX_pointer _pointer _int _-> _int)))
(define _BIO_free (cbind 'BIO_free (_fun _pointer _-> _int)))
(define _BIO_new_mem_buf (cbind 'BIO_new_mem_buf (_fun _pointer _int _-> _pointer)))
(define _PEM_read_bio_PrivateKey (cbind 'PEM_read_bio_PrivateKey (_fun _pointer _pointer _pointer _pointer _-> _pointer)))

;------------------------------------------------------------------------------
; Cryptographic hash function definitions

; Not all of these are available on the system because libcrypto might be compiled
; with a limited selection. Read this as a list of possible functions, not as a
; guarentee for support.
(define hash-algorithms
  '(md2
    md4
    md5
    sha1
    sha224
    sha256
    sha3-224
    sha3-256
    sha3-384
    sha3-512
    sha384
    sha512
    sm3))

(define hash-source/c
  (or/c path-string? bytes? input-port?))

(define hash-algorithm/c
  (apply or/c hash-algorithms))

; Bind each algorithm symbol to the C equivalent
(define md-algorithms
  (make-immutable-hasheq
   (map (λ (sym)
          (cons sym
                (get-ffi-obj (string->symbol (string-replace (~a "EVP_" sym) "-" "_"))
                             libcrypto (_fun _-> _pointer)
                             (λ () #f))))
        hash-algorithms)))


;------------------------------------------------------------------------------
; Message Digests

(define (make-digest algorithm variant)
  (cond [(path-string? variant)
         (call-with-input-file variant (λ (i) (make-digest algorithm i)))]
        [(bytes? variant)
         (make-digest algorithm (open-input-bytes variant))]
        [(input-port? variant)
         (define buffer (make-bytes (* 300 1024)))
         (digest-message algorithm
                         (λ (f)
                           (let loop ()
                             (define res (read-bytes-avail! buffer variant))
                             (if (exact-positive-integer? res)
                                 (begin (f buffer res)
                                        (loop))
                                 (void)))))]
        [else (raise-argument-error 'make-digest
                                    "A path, bytes, or an input port"
                                    variant)]))


(define (digest-length-ok? digest algorithm)
  (equal? (bytes-length digest)
          (bytes-length (make-digest #"whatever" algorithm))))


(define (make-fingerprint path)
  (subbytes (make-digest 'sha384 path) 0 20))


; Based on https://wiki.openssl.org/index.php/EVP_Message_Digests
(define (digest-message algorithm-symbol populate-message)
  (call/cc
   (λ (return)
     (define algorithm (hash-ref md-algorithms algorithm-symbol (λ () (return 'unknown-algorithm))))
     (unless algorithm (return 'algorithm-not-available))

     (define mdctx (_EVP_MD_CTX_new))
     (unless mdctx (return 'cannot-allocate-message-digest-context))

     (unless (= 1 (_EVP_DigestInit_ex mdctx (algorithm) #f))
       (return 'cannot-initialize-digest))

     (populate-message
      (λ (message [len (bytes-length message)])
        (unless (= 1 (_EVP_DigestUpdate mdctx message len))
          (return 'cannot-update-digest))))

     (define pdigest (_OPENSSL_malloc (_EVP_MD_size (algorithm))))
     (define pdigestlen (malloc (_cpointer _int)))

     (unless (= 1 (_EVP_DigestFinal_ex mdctx pdigest pdigestlen))
       (return 'cannot-finalize-digest))

     (define digestlen (ptr-ref pdigestlen _int))
     (define digest (make-bytes digestlen))
     (memcpy digest pdigest digestlen)

     (_EVP_MD_CTX_free mdctx)
     (free pdigest)

     (return digest))))



;------------------------------------------------------------------------------
; Integrity Information

(struct integrity-info (algorithm digest) #:prefab)

(define well-formed-integrity-info/c
  (and/c (struct/c integrity-info
                   hash-algorithm/c
                   bytes?)
         (λ (i) (digest-length-ok? (integrity-info-algorithm i)
                                   (integrity-info-digest i)))))

(define (make-integrity-info variant algorithm)
  (integrity-info algorithm (make-digest variant algorithm)))


#|
Different key types support different digests.
https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestSignInit.html

DSA: SHA1, SHA224, SHA256, SHA384 and SHA512
ECDSA: SHA1, SHA224, SHA256, SHA384, SHA512 and SM3
RSA (X931 padding): SHA1, SHA256, SHA384 and SHA512
RSA (other padding types): SHA1, SHA224, SHA256, SHA384, SHA512, MD5, MD5_SHA1, MD2, MD4, MDC2, SHA3-224, SHA3-256, SHA3-384, SHA3-512
|#


(define (make-signature algorithm digest variant)
  (cond [(path-string? variant)
         (make-signature algorithm digest (open-input-file variant))]
        [(bytes? variant)
         (make-signature algorithm digest (open-input-bytes variant))]
        [(input-port? variant)
         (define bstr (port->bytes variant))
         (close-input-port variant)
         (sign-digest algorithm
                      digest
                      bstr)]
        [else (raise-argument-error 'make-digest
                                    "A path or an input port"
                                    variant)]))


(define (sign-digest algorithm-symbol digest private-key-bytes)
  (call/cc
   (λ (return)
     (define algorithm (hash-ref md-algorithms algorithm-symbol (λ () (return 'unknown-algorithm))))
     (unless algorithm (return 'algorithm-not-available))

     (define pbio (_BIO_new_mem_buf private-key-bytes (bytes-length private-key-bytes)))
     (unless pbio (return 'cannot-allocate-bio))

     (define pkey (_PEM_read_bio_PrivateKey pbio #f #f #f))
     (unless pkey (return 'cannot-read-private-key))

     (define mdctx (_EVP_MD_CTX_new))
     (unless mdctx (return 'cannot-allocate-message-digest-context))

     (unless (= 1 (_EVP_DigestSignInit mdctx #f (algorithm) #f pkey))
       (return 'cannot-initialize-signature))

     (unless (= 1 (_EVP_DigestSignUpdate mdctx digest (bytes-length digest)))
       (return 'cannot-update-signature))

     #;(define plen (malloc _pointer))
     #;(unless (= 1 (_EVP_DigestSignFinal mdctx #f plen))
       (return 'cannot-find-signature-length))

     #;(define siglen (ptr-ref plen _int))

     #;(define psig (malloc siglen))
     #;(unless (= 1 (_EVP_DigestSignFinal mdctx psig plen))
       (return 'cannot-finalize-signature))

     #;(define signature (make-bytes siglen))
     #;(memcpy signature psig siglen)

     (_BIO_free pbio)
     (_EVP_MD_CTX_free mdctx)
     ;(free psig)

     #;signature)))


#;(define (verify-signature algorithm-symbol digest public-key)
  (call/cc
   (λ (return)
     (define mdctx (_EVP_MD_CTX_new))
     (unless mdctx (return 'cannot-allocate-message-digest-context))

     (unless (= 1 (_EVP_DigestVerifyInit mdctx #f EVP_sha256() #f key))
       (return ))

     (unless (= 1 (_EVP_DigestVerifyUpdate mdctx digest (bytes-length digest)))
       (return))

     (define signature-ok? (= 1 (_EVP_DigestVerifyFinal mdctx signature (bytes-length signature))))

     (_EVP_MD_CTX_free mdctx)

     signature-ok?)))


(module+ test
  (require rackunit)

  (test-case "Create integrity information"
    (for ([algorithm (in-list hash-algorithms)])
      (define bstr (string->bytes/utf-8 (symbol->string algorithm)))
      (define info (make-integrity-info bstr algorithm))
      (check-pred integrity-info? info)
      (check-eq? (integrity-info-algorithm info) algorithm)
      (check-equal? (integrity-info-digest info)
                    (make-digest algorithm bstr)))))
