#lang racket/base

; This module produces values suitable for `parse-command-line`. The
; flag handlers produce procedures that together bind settings in a
; new parameterization. This prevents oddities that arise when
; maintaining mutable storage for CLI-provided values in addition to a
; set of parameters.
;
; (parse-command-line "prog" (current-command-line-arguments)
;                     (make-cli-flag-table a b c ...)
;                     (λ (flags . args)
;                        (call-with-bound-cli-flags flags (λ () (do-something args)))))
;
; Additionally, each CLI flag specified here always include a canonical flag
; named after its corresponding setting.
;

(require "contract.rkt")

(provide (struct-out cli-flag)
         (struct-out cli-flag-state)
         (contract-out
          [make-cli-flag-table
           (->* () #:rest (listof cli-flag?) list?)]
          [cli-flag-strings
           (-> cli-flag? (non-empty-listof string?))]
          [shortest-cli-flag
           (-> cli-flag? string?)]
          [format-cli-flags
           (-> cli-flag? string?)]
          [call-with-bound-cli-flags
           (-> (listof cli-flag-state?)
               (-> any)
               any)]))

(require racket/cmdline
         "integrity.rkt"
         "rc.rkt"
         "setting.rkt"
         "string.rkt")

(struct cli-flag
  (setting kind additional-flag-strings arity convert help-strings)
  #:transparent)

(struct cli-flag-state
  (flag-string flag-definition bind)
  #:transparent)


;---------------------------------------------------------------------------
; Define procedures for reviewing flag strings. They are necessary for
; generating documentation and contextual help.

(define (cli-flag-strings c)
  (cons (format "--~a" (setting-id (cli-flag-setting c)))
        (cli-flag-additional-flag-strings c)))

(define (shortest-cli-flag c)
  (get-shortest-string (cli-flag-strings c)))

(define (format-cli-flags c)
  (string-join (sort (cli-flag-strings c) < #:key string-length)
               "/"))



;---------------------------------------------------------------------------
; These procedures creates a flag specs suitable for
; parse-command-line. The flag handler returns a procedure that binds
; the given setting in a new parameterization

(define (make-cli-flag-table . cli-flags)
  (for/list ([(kind flags) (in-hash (group-cli-flags-by-kind cli-flags))])
    (cons kind (map cli-flag->flag-spec (reverse flags)))))


(define (group-cli-flags-by-kind cli-flags)
  (for/fold ([grouped (hasheq)])
            ([flag (in-list cli-flags)])
    (hash-set grouped
              (cli-flag-kind flag)
              (cons flag (hash-ref grouped
                                   (cli-flag-kind flag)
                                   null)))))

(define (cli-flag->flag-spec c)
  (list (cli-flag-strings c)
        (procedure-reduce-arity
         (λ formals
           ; This leverages CPS and the prop:procedure property on the setting struct
           ; The idea is that you can compose procedures like these to construct
           ; a parameterization. Composition means that one handler can build on
           ; top of the current value set by another.
           (cli-flag-state (car formals)
                           c
                           (λ (expects-applied-setting)
                             (λ ()
                               ((cli-flag-setting c)
                                (apply (cli-flag-convert c) formals)
                                expects-applied-setting)))))
         (add1 (cli-flag-arity c)))
        (cons (format "~n    ~a" (setting-description (cli-flag-setting c)))
              (cli-flag-help-strings c))))


(define (call-with-bound-cli-flags flags proc)
  (((apply compose (map cli-flag-state-bind flags)) proc)))


;-------------------------------------------------------------------------------
; CLI flag definitions

(define (keep flag a) a)
(define (arg->value flag a) (string->value a))
(define (keep-for s) (λ (flag a) (cons a (s))))

(define (cli-flag/unary setting convert help-str)
  (cli-flag setting 'once-each null 1 convert (list help-str)))

(define (cli-flag/boolean setting)
  (cli-flag/unary setting arg->value "#t-or-#f"))

(define (cli-flag/list setting help-string)
  (cli-flag setting 'multi null 1 (keep-for setting) (list help-string)))


; I use short flags as identifiers below to make Racket stop me if I
; duplicate them across definitions.

;-------------------------------------------------------------------------------
; Unary flags

(require (for-syntax racket/base syntax/stx))
(define-syntax (flag-out stx)
  (syntax-case stx ()
    [(_ [id alts ...] expr)
     (with-syntax ([(strs ...)
                    (stx-map (λ (x) (datum->syntax x (symbol->string (syntax-e x))))
                             #'(id alts ...))])
       #'(begin (provide id (rename-out [id alts] ...))
                (define id
                  (struct-copy cli-flag expr
                               [additional-flag-strings
                                (list strs ...)]))))]))


; Unary flags
(flag-out [-q --my-private-key] (cli-flag/unary XIDEN_USER_PRIVATE_KEY_PATH keep "path"))
(flag-out [-p --my-public-key]  (cli-flag/unary XIDEN_USER_PUBLIC_KEY_PATH keep "path"))

(flag-out [-X --plugin] (cli-flag/unary XIDEN_MODS_MODULE keep "path"))
(flag-out [-M --sandbox-memory-limit] (cli-flag/unary XIDEN_SANDBOX_MEMORY_LIMIT_MB arg->value "mibibytes"))
(flag-out [-e --sandbox-eval-memory-limit] (cli-flag/unary XIDEN_SANDBOX_EVAL_MEMORY_LIMIT_MB arg->value "mibibytes"))
(flag-out [-S --sandbox-eval-time-limit] (cli-flag/unary XIDEN_SANDBOX_EVAL_TIME_LIMIT_SECONDS arg->value "seconds"))
(flag-out [-m] (cli-flag/unary XIDEN_FETCH_TOTAL_SIZE_MB arg->value "mibibytes-or-+inf.0"))
(flag-out [-n] (cli-flag/unary XIDEN_FETCH_BUFFER_SIZE_MB arg->value "mibibytes"))
(flag-out [-l] (cli-flag/unary XIDEN_FETCH_PKGDEF_SIZE_MB arg->value "mibibytes"))
(flag-out [-d] (cli-flag/unary XIDEN_FETCH_TIMEOUT_MS arg->value "milliseconds"))
(flag-out [-o --max-redirects] (cli-flag/unary XIDEN_DOWNLOAD_MAX_REDIRECTS arg->value "exact-nonnegative-integer"))
(flag-out [+h ++host] (cli-flag/list XIDEN_SERVICE_ENDPOINTS "url-string"))

(flag-out [+k ++public-key]
          (cli-flag/unary XIDEN_PUBLIC_KEYS
                          (λ (flag path)
                            (hash-set (XIDEN_PUBLIC_KEYS)
                                      (make-fingerprint path)
                                      path))
                          "path"))


; Unary boolean flags
(flag-out [-r] (cli-flag/boolean XIDEN_MATCH_RACKET_MODULES))
(flag-out [-b --match-compiled-racket] (cli-flag/boolean XIDEN_MATCH_COMPILED_RACKET))
(flag-out [-U --trust-unsigned] (cli-flag/boolean XIDEN_TRUST_UNSIGNED))
(flag-out [-T --trust-bad-signature] (cli-flag/boolean XIDEN_TRUST_BAD_SIGNATURE))
(flag-out [-H --trust-any-host] (cli-flag/boolean XIDEN_TRUST_UNVERIFIED_HOST))
(flag-out [-Y --trust-any-digest] (cli-flag/boolean XIDEN_TRUST_BAD_DIGEST))
(flag-out [-F --fasl-output] (cli-flag/boolean XIDEN_FASL_OUTPUT))
(flag-out [-R --reader-friendly-output] (cli-flag/boolean XIDEN_READER_FRIENDLY_OUTPUT))
(flag-out [-v --verbose] (cli-flag/boolean XIDEN_VERBOSE))
(flag-out [-A --allow-undeclared-racket] (cli-flag/boolean XIDEN_ALLOW_UNDECLARED_RACKET_VERSIONS))
(flag-out [-G --assume-support] (cli-flag/boolean XIDEN_ALLOW_UNSUPPORTED_RACKET))

; Transaction flags
(flag-out [+s ++install-source]
          (cli-flag XIDEN_INSTALL_SOURCES
                    'multi null 3 (λ (flag link-name output-name source)
                                    (cons (list link-name output-name source)
                                          (XIDEN_INSTALL_SOURCES)))
                    '("link-name" "output-name" "source")))

(flag-out [+d ++define]
          (cli-flag XIDEN_DEFINES
                    'multi null 2
                    (λ (flag id val)
                      (hash-set (XIDEN_DEFINES)
                                (string->symbol id)
                                (arg->value val)))
                    '("identifier" "racket-literal")))


; For use in REPL and tests. Provides a quick way to preview the effect of command
; line flags, and generated help strings shown.
(define (try-flags . args)
  (call/cc (λ (halt)
             (parse-command-line "test" (list->vector args)
                                 (make-cli-flag-table -X -M -e -S -m -n -p -d -q -o
                                                      +h -r -b -U -T -H -Y -F -R -v
                                                      -A -G +s)
                                 (λ (flags)
                                   (call-with-bound-cli-flags
                                    flags
                                    (λ () (for/fold ([dump (hash)])
                                                    ([st (in-list flags)])
                                            (define setting (cli-flag-setting (cli-flag-state-flag-definition st)))
                                            (hash-set dump (setting-id setting) (setting))))))
                                 null
                                 (λ (h) (displayln h) (halt (void)))))))



(module+ test
  (require racket/contract
           racket/function
           racket/match
           rackunit)

  (define-setting TEST_SETTING real? 10 "Test")

  (define TEST_SETTING/flag (cli-flag TEST_SETTING
                                      'once-each
                                      '("-t" "--test")
                                      1
                                      (λ (flag a) (string->value a))
                                      '("value")))

  (test-equal? "Always include setting name as a CLI flag"
               (cli-flag-strings TEST_SETTING/flag)
               '("--TEST_SETTING" "-t" "--test"))

  (test-equal? "Find the shortest CLI flag to help abbreviate messages to the user"
               (shortest-cli-flag TEST_SETTING/flag)
               "-t")

  (test-equal? "Show all flags in order of increasing length when total message length is a non-issue"
               (format-cli-flags TEST_SETTING/flag)
               "-t/--test/--TEST_SETTING")

  (test-case "Convert CLI flag to deferred setting binding"
    (match-define (list flag-strings handler help-strings) (cli-flag->flag-spec TEST_SETTING/flag))
    (check-equal? (cli-flag-strings TEST_SETTING/flag) flag-strings)
    (check-equal? (procedure-arity handler) (add1 (cli-flag-arity TEST_SETTING/flag)))
    (check-equal? help-strings '("Test" "value"))

    (match-define (cli-flag-state flag-string cli-flag-inst args-bound) (handler "-t" "+inf.0"))
    (check-equal? flag-string "-t")
    (check-eq? cli-flag-inst TEST_SETTING/flag)
    (define callback-bound (args-bound (λ () (check-eq? (TEST_SETTING) +inf.0))))

    (callback-bound))

  (test-case "Group CLI flags"
    (define (of-kind k) (cli-flag #f k #f #f #f #f))

    (define-values (oe1 oe2 oa1 oa2 oa3 m1 m2 m3)
      (values (of-kind 'once-each)
              (of-kind 'once-each)
              (of-kind 'once-any)
              (of-kind 'once-any)
              (of-kind 'once-any)
              (of-kind 'multi)
              (of-kind 'multi)
              (of-kind 'multi)))

    (check-equal? (group-cli-flags-by-kind (list oe1 oe2 oa1 oa2 oa3 m1 m2 m3))
                  (hasheq 'once-each (list oe2 oe1)
                          'once-any (list oa3 oa2 oa1)
                          'multi (list m3 m2 m1))))

  (test-case "Ease use of parse-command-line"
    (define-setting TEST_MULTI     list? null "Accepts the numbers 1, 2, or 3.")
    (define-setting TEST_ONCE_EACH (or/c #f string?) #f "Accepts two arguments")
    (define-setting TEST_ONCE_ANY  string? "" "Accepts a string")

    (define (get-current-values)
      (list (TEST_MULTI)
            (TEST_ONCE_EACH)
            (TEST_ONCE_ANY)))

    (define multi-flag
      (cli-flag TEST_MULTI 'multi
                '("-m" "--multi")
                2
                (λ (flag a b)
                  (cons (string->value a) (cons (string->value b) (TEST_MULTI))))
                '("num" "num")))

    (define once-each-flag
      (cli-flag TEST_ONCE_EACH
                'once-each
                '("--quad")
                4
                (λ (flag a b c d)
                  (string-join (list a b c d) " "))
                '("str" "str" "str" "str")))


    (define once-any-flag
      (cli-flag TEST_ONCE_ANY
                'once-any
                '("-a")
                1
                (λ (flag a) a)
                '("str")))


    (test-case "Can compose multiple flag handlers"
      (match-define (list _ handler _) (cli-flag->flag-spec multi-flag))
      (define bind-a (handler "--multi" "1" "2"))
      (define bind-b (handler "--multi" "3" "4"))
      (check-equal? (call-with-bound-cli-flags (list bind-a bind-b) (λ () (TEST_MULTI)))
                    '(3 4 1 2)))


    (define-values (outside-parameterization inside-parameterization positional)
      (parse-command-line "test" #("-m" "1" "2"
                                   "--multi" "3" "4"
                                   "--TEST_MULTI" "5" "6"
                                   "-a" "once"
                                   "--quad" "what" "else" "you" "got?"
                                   "positional" "arguments")
                          (make-cli-flag-table multi-flag once-each-flag once-any-flag)
                          (λ (flags formal1 formal2)
                            (check-equal? (map cli-flag-state-flag-string flags)
                                          '("-m"
                                            "--multi"
                                            "--TEST_MULTI"
                                            "-a"
                                            "--quad"))

                            (values (get-current-values)
                                    (call-with-bound-cli-flags flags get-current-values)
                                    (list formal1 formal2)))
                          '("arg" "arg")))

    (check-equal? outside-parameterization
                  '(() #f ""))

    (check-equal? inside-parameterization
                  '((5 6 3 4 1 2)
                    "what else you got?"
                    "once"))

    (check-equal? positional
                  '("positional" "arguments"))))
