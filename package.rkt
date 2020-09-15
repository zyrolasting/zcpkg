#lang racket/base

(provide (all-defined-out))

(require racket/function
         racket/list
         racket/path
         racket/pretty
         racket/sequence
         net/head
         version/utils
         "cli-flag.rkt"
         "contract.rkt"
         "encode.rkt"
         "exn.rkt"
         "file.rkt"
         "format.rkt"
         "input-info.rkt"
         "integrity.rkt"
         "localstate.rkt"
         "message.rkt"
         "mod.rkt"
         "monad.rkt"
         "path.rkt"
         "port.rkt"
         "printer.rkt"
         "query.rkt"
         "racket-version.rkt"
         "rc.rkt"
         "sandbox.rkt"
         "setting.rkt"
         "signature.rkt"
         "source.rkt"
         "string.rkt"
         "team.rkt"
         "url.rkt"
         "openssl.rkt"
         "workspace.rkt")

(define+provide-message $consent-note ())
(define+provide-message $no-package-info (source))
(define+provide-message $package (info))
(define+provide-message $package-installed $package ())
(define+provide-message $package-in-use $package ())
(define+provide-message $built-package-output $package (output-name))
(define+provide-message $reused-package-output $package (output-name))
(define+provide-message $package-not-installed $package ())
(define+provide-message $undeclared-racket-version $package ())
(define+provide-message $unsupported-racket-version $package (versions))
(define+provide-message $undefined-package-output $package (output-name))
(define+provide-message $package-malformed $package (errors))


(define (install-package link-path output-name pkg-definition-variant)
  (do pkgeval       <- (make-package-evaluator pkg-definition-variant)
      _             <- (validate-requested-output pkgeval output-name)
      build-output  <- (install-output! pkgeval output-name link-path)
      results       <- (report-installation-results (package-name pkgeval) build-output)
      (return (logged-unit (kill-evaluator pkgeval)))))


(define (configure-evaluator pkgeval)
  (pkgeval `(current-info-lookup
             (let ([h ,(xiden-evaluator->hash pkgeval)])
               (λ (k f) (hash-ref h k f)))))
  pkgeval)


(define (make-package-evaluator source)
  (do sourced-eval    <- (if (string? source)
                             (fetch-package-definition source)
                             (build-package-evaluator source))
      validated-eval  <- (validate-evaluator sourced-eval)
      supported-eval  <- (check-racket-support validated-eval)
      (return (configure-evaluator supported-eval))))


(define (validate-requested-output pkgeval output-name)
  (if (member output-name (cons "default" (xiden-evaluator-ref pkgeval 'outputs null)))
      (logged-unit output-name)
      (logged-failure ($undefined-package-output (package-name pkgeval) output-name))))


(define (validate-evaluator pkgeval)
  (define errors null)
  (define (assert #:optional? [optional? #f] k predicate msg)
    (with-handlers ([values (λ (e) (unless optional? (set! errors (cons (exn-message e) errors))))])
      (define v (pkgeval k))
      (unless (predicate v)
        (set! errors (cons (format "~a: Expected ~a. Got ~e" k msg v)
                           errors)))))

  (assert 'provider string? "a string")
  (assert 'package string? "a string")
  (assert 'edition string? "a string")
  (assert 'revision-number exact-nonnegative-integer? "an exact, nonnegative integer")
  (assert 'inputs (listof well-formed-input-info/c) "a list of inputs")
  (assert 'build
          (λ (p) (and (procedure? p) (= 1 (procedure-arity p))))
          "a unary procedure")

  (assert #:optional? #t 'outputs (listof string?) "a list of strings")
  (assert #:optional? #t 'revision-names (listof string?) "a list of strings")
  (assert #:optional? (XIDEN_ALLOW_UNDECLARED_RACKET_VERSIONS)
          'racket-versions
          racket-version-ranges/c
          "a list of Racket version range pairs, e.g. '((\"7.0\" . \"7.8\") ...) (Use #f to remove bound).")

  (if (null? errors)
      (logged-unit pkgeval)
      (logged-failure ($package-malformed (package-name pkgeval) errors))))


(define (package-name pkgeval)
  (xiden-query->string (package-evaluator->xiden-query pkgeval)))


(define (report-installation-results name build-output)
  (logged-attachment build-output
                     (if (eq? build-output SUCCESS)
                         ($package-installed name)
                         ($package-not-installed name))))


(define (install-output! pkgeval output-name link-path)
  (call-with-reused-output
   (package-evaluator->xiden-query pkgeval)
   output-name
   (λ (variant)
     (cond [(output-record? variant)
            (reuse-package-output! pkgeval output-name variant link-path)]
           [(exn? variant)
            (raise variant)]
           [else
            (build-package-output! pkgeval output-name link-path)]))))


(define (reuse-package-output! pkgeval output-name output-record-inst link-path)
  (logged
   (λ (messages)
     (define directory-record (find-path-record (output-record-path-id output-record-inst)))
     (make-addressable-link directory-record link-path)
     (values SUCCESS
             (cons ($reused-package-output (package-name pkgeval) output-name)
                   messages)))))


(define (open-input-info-as-bytes info)
  (open-input-bytes
    (with-handlers ([values (λ (e) (string->bytes/utf-8 (input-info-name info)))])
      (integrity-info-digest (input-info-integrity info)))))


(define (build-package-output! pkgeval output-name link-path)
  (logged
   (λ (messages)
     (define directory-record
       (make-addressable-directory
        (cons (open-input-string output-name)
              (map open-input-info-as-bytes
                   (xiden-evaluator-ref pkgeval 'inputs null)))
        (λ (build-dir)
          (pkgeval `(cd ,build-dir))
          (pkgeval `(build ,output-name)))))

     (declare-output (xiden-evaluator-ref pkgeval 'provider)
                     (xiden-evaluator-ref pkgeval 'package)
                     (xiden-evaluator-ref pkgeval 'edition "default")
                     (xiden-evaluator-ref pkgeval 'revision-number)
                     (xiden-evaluator-ref pkgeval 'revision-names null)
                     output-name
                     directory-record)

     (make-addressable-link directory-record link-path)

     (values SUCCESS
             (cons ($built-package-output (package-name pkgeval) output-name)
                   messages)))))



; This is the inflection point between restricted and unrestricted
; resources for an evaluator.
(define (call-with-build-sandbox-parameterization proc)
  (parameterize ([sandbox-memory-limit (XIDEN_SANDBOX_MEMORY_LIMIT_MB)]
                 [sandbox-eval-limits (list (XIDEN_SANDBOX_EVAL_TIME_LIMIT_SECONDS)
                                            (XIDEN_SANDBOX_EVAL_MEMORY_LIMIT_MB))]
                 [sandbox-security-guard
                  (make-security-guard
                   (current-security-guard)
                   (make-pkgeval-file-guard (make-bin-path-permissions '("openssl"))
                                            (build-workspace-path "var/xiden"))
                   (make-pkgeval-network-guard)
                   (make-pkgeval-link-guard (workspace-directory)))]
                 [sandbox-make-environment-variables
                  (bind-envvar-subset '(#"PATH"))]
                 [sandbox-namespace-specs
                  (append (sandbox-namespace-specs)
                          '(xiden/rc xiden/package))])
    (proc)))



(define (make-pkgeval-file-guard allowed-executables write-dir)
  (λ (sym path-or-#f ops)
    (when path-or-#f
      (cond [(member 'execute ops)
             (unless (member path-or-#f allowed-executables)
               (raise-user-error 'security
                                 "Unauthorized attempt to execute ~a"
                                 path-or-#f))]

            [(member 'write ops)
             (unless (or (path-prefix? (normalize-path path-or-#f) write-dir)
                         (path-prefix? (normalize-path path-or-#f)
                                       (find-system-path 'temp-dir)))
               (raise-user-error 'security
                                 "Unauthorized attempt to write in ~a"
                                 path-or-#f))]

            [(member 'delete ops)
             (raise-user-error 'security
                               "Unauthorized attempt to delete ~a"
                               path-or-#f)]))))


(define (make-pkgeval-network-guard)
  (λ (sym hostname-or-#f port-or-#f client-or-server)
    (unless hostname-or-#f
      (raise-user-error 'security
                        "Unauthorized attempt to listen for connections"))
    ; TODO: Certificate checks, etc.
    ))


(define (make-pkgeval-link-guard workspace)
  (define (path-ok? p)
    (path-prefix? (simplify-path (if (complete-path? p) p (build-path workspace p)))
                  workspace))

  (λ (op link-path target-path)
    (unless (path-ok? (normalize-path target-path))
      (raise-user-error 'security
                        "Cannot create link. Target must be in ~a~n  target path: ~a"
                        workspace
                        target-path))))


(define (fetch-package-definition source)
  (logged
   (λ (m)
     (define logged/fetch-st
       (fetch source
              (list source)
              (λ (from-source est-size)
                (call-with-build-sandbox-parameterization
                 (λ ()
                   (load-xiden-module
                    (make-limited-input-port from-source
                                             (min (mibibytes->bytes (XIDEN_FETCH_PKGDEF_SIZE_MB))
                                                  est-size)
                                             #t)))))))

     (define-values (fetch-st messages) (run-log logged/fetch-st m))

     (values (or (fetch-state-result fetch-st) FAILURE)
             (cons messages m)))))


(define (build-package-evaluator source)
  (logged-unit (load-xiden-module source)))


(define (check-racket-support pkgeval)
  (let ([racket-support
         (check-racket-version-ranges
          (version)
          (pkgeval 'racket-versions))])
    (case racket-support
      [(supported)
       (logged-unit pkgeval)]
      [(unsupported)
       (if (XIDEN_ALLOW_UNSUPPORTED_RACKET)
           (logged-unit pkgeval)
           (logged-failure ($unsupported-racket-version
                            (package-name pkgeval)
                            (pkgeval 'racket-versions))))]
      [(undeclared)
       (if (or (XIDEN_ALLOW_UNSUPPORTED_RACKET)
               (XIDEN_ALLOW_UNDECLARED_RACKET_VERSIONS))
           (logged-unit pkgeval)
           (logged-failure ($undeclared-racket-version (package-name pkgeval))))])))


(define-message-formatter format-package-message
  [($built-package-output name output-name)
   (format "~a: built ~a" name output-name)]

  [($reused-package-output name output-name)
   (format "~a: reused ~a" name output-name)]

  [($undeclared-racket-version info)
   (join-lines
    (list (format "~a does not declare a supported Racket version."
                  info)
          (format "To install this package anyway, run again with ~a"
                  (shortest-cli-flag --allow-undeclared-racket))))]

  [($package-malformed name errors)
   (format "~a has an invalid definition. Here are the errors for each field:~n~a"
           name
           (join-lines (indent-lines errors)))]

  [($unsupported-racket-version name versions)
   (join-lines
    (list (format "~a does not support this version of Racket (~a)."
                  name
                  (version))
          (format "Supported versions (ranges are inclusive):~n~a~n"
                  (join-lines
                   (map (λ (variant)
                          (format "  ~a"
                                  (if (pair? variant)
                                      (format "~a - ~a"
                                              (or (car variant)
                                                  PRESUMED_MINIMUM_RACKET_VERSION)
                                              (or (cdr variant)
                                                  PRESUMED_MAXIMUM_RACKET_VERSION))
                                      variant)))
                        versions)))
          (format "To install this package anyway, run again with ~a"
                  (format-cli-flags --assume-support))))])


(module+ test
  (require racket/runtime-path
           rackunit
           (submod "file.rkt" test)
           "setting.rkt")

  (test-case "Check Racket version support"
    (define (make-dummy-pkginfo versions)
      (hash+list->xiden-evaluator
       (hash 'racket-versions versions
             'package-name "whatever")))

    (test-case "Detect packages that do not declare a supported Racket version"
      (define pkginfo (make-dummy-pkginfo null))
      (check-equal? (get-log (check-racket-support pkginfo))
                    (list ($undeclared-racket-version (package-name pkginfo)))))

    (test-case "Detect packages that declare an unsupported Racket version"
      (define pkginfo (make-dummy-pkginfo (list "0.0")))
      (check-equal? (get-log (check-racket-support pkginfo))
                    (list ($unsupported-racket-version (package-name pkginfo)
                                                       (pkginfo 'racket-versions)))))))
