#lang racket/base

(provide run-openssl-command
         digest-message)

(require racket/file
         racket/function
         racket/path
         racket/port
         racket/system
         openssl/libcrypto
         openssl/libssl
         (rename-in ffi/unsafe [-> _->])
         "contract.rkt"
         "exn.rkt"
         "query.rkt"
         "rc.rkt"
         "string.rkt"
         "url.rkt")



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

(require (for-syntax racket/base racket/syntax syntax/stx))
(define-syntax (possible-md-algorithms stx)
  (syntax-case stx ()
    [(_ id ...)
     (with-syntax ([(c-id ...) (stx-map (λ (s) (format-id s "EVP_~a" s)) #'(id ...))])
       #'(make-immutable-hasheq (list (cons 'id
                                            (get-ffi-obj 'c-id libcrypto (_fun _-> _pointer)
                                                         (λ () #f))) ...)))]))

(define md-algorithms
  (possible-md-algorithms
   md2
   md4
   md5
   sha1
   sha224
   sha256
   sha384
   sha512
   blake2b512
   blake2b256
   sha512_224
   sha3_256
   sha3_384
   sha3_512
   shake128
   shake256
   mdc2
   ripemd160
   whirlpool
   sm3))

(define (load-libcrypto!)
  ((cbind 'OPENSSL_config (_fun _pointer _-> _void)) #f))

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

     (return digest))))


(define-exn exn:fail:xiden:openssl exn:fail:xiden (exit-code))

(define openssl (find-executable-path "openssl"))

(define (run-openssl-command stdin-source . args)
  (define-values (sp from-stdout to-stdin from-stderr)
    (apply subprocess #f #f #f (and (subprocess-group-enabled) 'new) openssl args))

  (copy-port stdin-source to-stdin)
  (flush-output to-stdin)
  (close-output-port to-stdin)

  (dynamic-wind void
                (λ ()
                  (define delay-seconds 3)
                  (define maybe-sp (sync/timeout delay-seconds sp))

                  (define exit-code
                    (if maybe-sp
                        (subprocess-status sp)
                        (begin (subprocess-kill sp #t) 1)))

                  (define error-string
                    (if maybe-sp
                        (port->string from-stderr)
                        (format "Command timed out after ~a seconds. xiden terminated the subprocess."
                                delay-seconds)))

                  (unless (eq? exit-code 0)
                    (raise ((exc exn:fail:xiden:openssl exit-code)
                            "OpenSSL failed with exit code ~a: ~a"
                            exit-code
                            error-string)))

                  (define output (port->bytes from-stdout))
                  output)
                (λ ()
                  (close-input-port from-stderr)
                  (close-input-port from-stdout))))
