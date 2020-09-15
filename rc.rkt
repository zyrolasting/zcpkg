#lang racket/base

; Define runtime configuration.

(require "contract.rkt")
(provide
 with-xiden-rcfile
 (contract-out
  [setting-ref
   (-> (or/c string? symbol?)
       (or/c setting? #f))]
  [XIDEN_SETTINGS
   (hash/c symbol? setting? #:immutable #t)]
  [get-xiden-settings-path
   (-> complete-path?)]
  [load-xiden-rcfile
   (-> (-> any/c any))]
  [dump-xiden-settings
   (-> (hash/c symbol? any/c))]
  [save-xiden-settings!
   (-> any)]))


(require racket/function
         racket/match
         racket/pretty
         (only-in racket/tcp listen-port-number?)
         "exn.rkt"
         "message.rkt"
         "sandbox.rkt"
         "setting.rkt"
         "url.rkt"
         "workspace.rkt")

(define+provide-message $setting (name))
(define+provide-message $setting-accepted $setting (value))
(define+provide-message $setting-not-found $setting ())
(define+provide-message $setting-value-unreadable $setting (source-name))
(define+provide-message $setting-value-rejected $setting (value expected))

(define current-xiden-rcfile-cache (make-parameter void))


; The only difference between a vanilla setting an a Xiden setting is how a
; fallback value is computed.
(define-syntax-rule (define-xiden-setting id cnt default-value description)
  (begin (provide (contract-out [id setting?]))
         (define-setting id cnt (xiden-setting-find-value default-value) description)))


; Return a procedure to fetch a value for a setting if it is not already set.
(define (xiden-setting-find-value default-value)
  (λ (id)
    (for/or ([make-value (in-xiden-setting-value-sources id default-value)])
      (define maybe-not-void (make-value))
      (and (not (void? maybe-not-void))
           maybe-not-void))))


; Checks environment variable, then rcfile, then hard-coded value.
(define (in-xiden-setting-value-sources id default-value)
  (in-list (list (λ () (maybe-get-setting-value-from-envvar (symbol->string id)))
                 (λ () ((current-xiden-rcfile-cache) `(#%info-lookup ',id void)))
                 (const default-value))))


(define (maybe-get-setting-value-from-envvar envname)
  (define env (getenv envname))
  (cond [(not env) (void)]
        [(string=? env "") (void)]
        [else (read (open-input-string env))]))


(define (setting-ref name)
  (hash-ref XIDEN_SETTINGS
            (if (string? name)
                (string->symbol name)
                name)
            #f))


(define (get-xiden-settings-path)
  (build-workspace-path "etc/xiden.rkt"))


; Warning: This performs a full file read every time. Use a cache where relevant.
(define (load-xiden-rcfile)
  (let ([path (get-xiden-settings-path)])
    (if (file-exists? path)
        (load-xiden-module path)
        void)))


(define-syntax-rule (with-xiden-rcfile body ...)
  (parameterize ([current-xiden-rcfile-cache (load-xiden-rcfile)])
    body ...))


(define (dump-xiden-settings)
  (for/hash ([(k v) (in-hash XIDEN_SETTINGS)])
    (values k (v))))


; This implementation preserves the reading order of
; any rcfile on disk, as a courtesy to the user.
(define (save-xiden-settings!)
  (define domain-or-void ((load-xiden-rcfile) '(#%info-domain)))
  (save-xiden-module!
   (hash+list->xiden-evaluator (dump-xiden-settings) (if (void? domain-or-void) null domain-or-void))
   (get-xiden-settings-path)))


; For boolean options, since they all use the same help string.
(define (switch-help str)
  (cons str '("#t-or-#f")))


;; Begin runtime configuration space
;; =================================

(define-xiden-setting XIDEN_SANDBOX_MEMORY_LIMIT_MB (>=/c 0) 200 "Total memory quota for a sandbox")

(define-xiden-setting XIDEN_SANDBOX_EVAL_MEMORY_LIMIT_MB (>=/c 0) 200
  "Memory quota for each sandboxed expression")

(define-xiden-setting XIDEN_SANDBOX_EVAL_TIME_LIMIT_SECONDS (>=/c 0) (* 5 60)
  "Time limit for each sandboxed expression")

(define-xiden-setting XIDEN_INSTALL_SOURCES (listof (list/c string? string? string?)) null
  "Add installation to transaction")

(define-xiden-setting XIDEN_MATCH_RACKET_MODULES boolean? #f
  (switch-help "Match .rkt, .ss, .scrbl, and .rktd"))

(define-xiden-setting XIDEN_MATCH_COMPILED_RACKET boolean? #f
  (switch-help "Match .zo and .dep."))

(define-xiden-setting XIDEN_MODS_MODULE (or/c #f path-string?) #f
  "A path to a module that extends Xiden.")

(define-xiden-setting XIDEN_TRUST_UNSIGNED boolean? #f
  "Trust unsigned packages")

(define-xiden-setting XIDEN_TRUST_BAD_SIGNATURE boolean? #f
  "Trust signatures that don't match public key")

(define-xiden-setting XIDEN_TRUST_UNVERIFIED_HOST boolean? #f
  "Download from any server without authenticating")

(define-xiden-setting XIDEN_TRUST_BAD_DIGEST boolean? #f
  "(DANGEROUS) Trust any input.")

(define-xiden-setting XIDEN_FASL_OUTPUT boolean? #f
  "Use FASL program output")

(define-xiden-setting XIDEN_FETCH_TOTAL_SIZE_MB (or/c +inf.0 real?) 100
  "Maximum size, in mibibytes, to read from a source. +inf.0 = no limit")

(define-xiden-setting XIDEN_FETCH_BUFFER_SIZE_MB (real-in 0.1 20) 10
  "Buffer size, in mibibytes, used when reading bytes")

(define-xiden-setting XIDEN_FETCH_PKGDEF_SIZE_MB (real-in 0.1 20) 0.1
  "The maximum expected size, in mibibytes, of a package definition when scoping out work")

(define-xiden-setting XIDEN_FETCH_TIMEOUT_MS (real-in 100 (* 1000 10)) 3000
  "The maximum time, in milliseconds, to wait for a distinct read of bytes from a source")

(define-xiden-setting XIDEN_READER_FRIENDLY_OUTPUT boolean? #f
  "Use (read)able program output")

(define-xiden-setting XIDEN_VERBOSE boolean? #f
  "Show more information in program output")

(define-xiden-setting XIDEN_PUBLIC_KEYS (hash/c bytes? bytes?) (hash)
  "Trusted public keys")

(define-xiden-setting XIDEN_USER_PRIVATE_KEY_PATH (or/c #f path-string?) #f
  "The location of the user's private key")

(define-xiden-setting XIDEN_USER_PUBLIC_KEY_PATH (or/c #f path-string?) #f
  "The location of the user's public key")

(define-xiden-setting XIDEN_DEFINES (hash/c symbol? any/c) (hash)
  "User-defined bindings for a new package definition")

(define-xiden-setting XIDEN_SERVICE_ENDPOINTS (listof url-string?) '("https://zcpkg.com")
  "Services to contact when searching for package definitions")

(define-xiden-setting XIDEN_LINK boolean? #f
  "When installing a package on the filesystem, create a symlink to the source directory.")

(define-xiden-setting XIDEN_DOWNLOAD_MAX_REDIRECTS exact-nonnegative-integer? 2
  "Maximum redirects to follow when downloading an artifact")

(define-xiden-setting XIDEN_ALLOW_UNDECLARED_RACKET_VERSIONS boolean? #f
  "Install packages even if they do not declare supported Racket versions")

(define-xiden-setting XIDEN_ALLOW_UNSUPPORTED_RACKET boolean? #f
  "Install packages even if they declare that they do not support the running version of Racket.")


(define-setting-group XIDEN_SETTINGS
  [XIDEN_ALLOW_UNDECLARED_RACKET_VERSIONS
   XIDEN_ALLOW_UNSUPPORTED_RACKET
   XIDEN_DOWNLOAD_MAX_REDIRECTS
   XIDEN_FASL_OUTPUT
   XIDEN_FETCH_BUFFER_SIZE_MB
   XIDEN_FETCH_PKGDEF_SIZE_MB
   XIDEN_FETCH_TIMEOUT_MS
   XIDEN_FETCH_TOTAL_SIZE_MB
   XIDEN_LINK
   XIDEN_MATCH_COMPILED_RACKET
   XIDEN_MATCH_RACKET_MODULES
   XIDEN_MODS_MODULE
   XIDEN_USER_PUBLIC_KEY_PATH
   XIDEN_USER_PRIVATE_KEY_PATH
   XIDEN_READER_FRIENDLY_OUTPUT
   XIDEN_SANDBOX_EVAL_MEMORY_LIMIT_MB
   XIDEN_SANDBOX_EVAL_TIME_LIMIT_SECONDS
   XIDEN_SANDBOX_MEMORY_LIMIT_MB
   XIDEN_SERVICE_ENDPOINTS
   XIDEN_TRUST_BAD_DIGEST
   XIDEN_TRUST_BAD_SIGNATURE
   XIDEN_TRUST_UNSIGNED
   XIDEN_TRUST_UNVERIFIED_HOST
   XIDEN_VERBOSE])

(module+ test
  (require rackunit
           (submod "file.rkt" test))


  (test-not-exn "Group all runtime configuration in a hash table"
                (λ ()
                  (invariant-assertion
                   (and/c immutable? (hash/c symbol? setting?))
                   XIDEN_SETTINGS)))


  (test-case "Define runtime configuration file path in terms of workspace"
    (define rcfile-/a
      (parameterize ([workspace-directory "/a"])
        (get-xiden-settings-path)))
    (define rcfile-/b
      (parameterize ([workspace-directory "/b"])
        (get-xiden-settings-path)))
    (check-pred complete-path? rcfile-/a)
    (check-pred complete-path? rcfile-/b)
    (check-not-equal? rcfile-/a rcfile-/b))


  (test-case "Dump current runtime configuration to a hash table"
    (check-not-exn
     (λ ()
       (invariant-assertion
        (and/c immutable? (hash/c symbol? (not/c setting?)))
        (dump-xiden-settings))))

    (define dump (dump-xiden-settings))
    (check-equal? (hash-ref dump 'XIDEN_USER_PRIVATE_KEY_PATH)
                  (XIDEN_USER_PRIVATE_KEY_PATH))

    (XIDEN_USER_PRIVATE_KEY_PATH
     "foo"
     (λ ()
       (check-not-equal? (hash-ref dump 'XIDEN_USER_PRIVATE_KEY_PATH)
                         (XIDEN_USER_PRIVATE_KEY_PATH))
       (check-equal? (hash-ref (dump-xiden-settings) 'XIDEN_USER_PRIVATE_KEY_PATH)
                     (XIDEN_USER_PRIVATE_KEY_PATH)))))

  (test-workspace "Find fallback values from several sources"
    (test-false "First use a hard-coded value"
                (XIDEN_USER_PRIVATE_KEY_PATH))

    (test-case "Override hard-coded value with rcfile"
      (XIDEN_USER_PRIVATE_KEY_PATH "foo" save-xiden-settings!)
      (with-xiden-rcfile (check-equal? (XIDEN_USER_PRIVATE_KEY_PATH) "foo")))

    (test-case "Override rcfile value with envvar value"
      (dynamic-wind (λ () (putenv "XIDEN_USER_PRIVATE_KEY_PATH" "\"bar\""))
                    (λ () (check-equal? (XIDEN_USER_PRIVATE_KEY_PATH) "bar"))
                    (λ ()
                      (putenv "XIDEN_USER_PRIVATE_KEY_PATH" "")
                      (with-xiden-rcfile
                        (test-equal? "Do not use empty envvar strings as a source for settings"
                                     (XIDEN_USER_PRIVATE_KEY_PATH)
                                     "foo"))))))

  (test-workspace "Lazily validate fallback values"
    (test-exn "Reject invalid values from ennvar"
              exn:fail:contract?
              (λ ()
                (dynamic-wind void
                              (λ ()
                                (putenv "XIDEN_USER_PRIVATE_KEY_PATH" "123")
                                (XIDEN_USER_PRIVATE_KEY_PATH))
                              (λ ()
                                (putenv "XIDEN_USER_PRIVATE_KEY_PATH" "")))))))
