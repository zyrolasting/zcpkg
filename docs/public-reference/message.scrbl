#lang scribble/manual

@require[@for-label[racket/base
                    racket/contract
                    racket/fasl
                    racket/match
                    racket/pretty
                    racket/serialize
                    xiden/l10n
                    xiden/message
                    xiden/printer]
         "../shared.rkt"]

@title{Messages}

@defmodule[xiden/message]

A @deftech{message} is an instance of the @racket[$message]
@tech/reference{structure} used to share data in the @project-name
runtime and between Racket processes. @racket[$message] and all of its
subtypes are @tech/reference{prefab} @tech/reference{structures}.
When the term “@tech{message}” is ambiguous, then @deftech{@project-name message}
applies the context of this section.

All @tech{message} types form a heirarchy using colon-separated
identifiers that start with @racket[$]. @racket[$message] itself has
no semantics beyond serving as the root type, and its identifier does
not appear in other structure type identifiers like @racket[exn]'s
does. For example, identifiers pertaining to command line messages
start with @tt{$cli}, not @tt{$message:cli}.

@defstruct*[$message () #:prefab]{
The base type for all @tech{messages}.
}

@defform*[((define-message id [field-expr ...])
           (define-message id super-id [field-expr ...]))]{
Like @racket[struct], in that @racket[(define-message foo (a b c))] is
equivalent to @racket[(struct foo $message (a b c) #:prefab)].

The second form allows declaration of a supertype, but that supertype
must be a subtype of @racket[$message].
}

@defform[(define+provide-message id form ...)]{
Like @racket[define-message], with an included @racket[(provide (struct-out id))].
}

@defstruct*[($show-datum $message) ([value any/c]) #:prefab]{
Represents a request to show the user the given Racket value.
}

@defstruct*[($show-string $message) ([message any/c]) #:prefab]{
Represents a request to show the user the given string.
}

@defstruct*[($regarding $message) ([subject $message?] [body $message?]) #:prefab]{
Represents a request to show one message in the context of another.
}


@section{Printing Messages}

@defmodule[xiden/printer]

@defstruct*[($verbose $message) ([message $message?]) #:prefab]{
A wrapper for a message that only appears to a user if
@racket[(XIDEN_VERBOSE)] is @racket[#t].
}

@defthing[message-formatter/c chaperone-contract? #:value (-> $message? string?)]{
A @deftech{message formatter} is a procedure that translates a
@tech{message} to a human-readable string.
}

@defform[(message-formatter patts ...)]{
Expands to @racket[(λ (m) (match m patts ...))]
}


@defform[(define-message-formatter id patts ...)]{
Expands to @racket[(define id (message-formatter patts ...))]
}

@defform[(define+provide-message-formatter id patts ...)]{
Expands to

@racketblock[
(begin (provide (contract-out [id message-formatter/c]))
       (define-message-formatter id patts ...))]
}

@defproc[(combine-message-formatters [formatter message-formatter/c] ...) message-formatter/c]{
Returns a @tech{message formatter} that uses each @racket[formatter]
in the order passed.
}

@defthing[default-message-formatter message-formatter/c]{
A @tech{message formatter} useful only for producing locale-independent fallback strings.
}

@defthing[current-message-formatter (parameter/c message-formatter/c) #:value default-message-formatter]{
A @tech/reference{parameter} holding the @tech{message formatter} for
use with @racket[format-message].
}

@defproc[(format-message [m $message?]) string?]{
Equivalent to @racket[((current-message-formatter) m)].
}

@defproc[(write-message [m $message?] [format-message message-formatter/c] [out output-port? (current-output-port)]) void?]{
Writes a @tech{message} to @racket[out] according to the values of
@racket[(XIDEN_READER_FRIENDLY_OUTPUT)], @racket[(XIDEN_FASL_OUTPUT)],
and @racket[(XIDEN_VERBOSE)].

Given @racket[(and (not (XIDEN_VERBOSE)) ($verbose? m))],
@racket[write-message] does nothing.

Otherwise, @racket[write-message] does the following:

@racketblock[
(let ([to-send (if (XIDEN_READER_FRIENDLY_OUTPUT) m (format-message m))])
  (if (XIDEN_FASL_OUTPUT)
      (s-exp->fasl (serialize to-send) out)
      (if (XIDEN_READER_FRIENDLY_OUTPUT)
          (pretty-write #:newline? #t to-send out)
          (displayln to-send out))))]

}


@section{High-level Messages}

@defstruct*[($fail $message) ([v any/c]) #:prefab]{
Represents a general failure. When
@racket[XIDEN_READER_FRIENDLY_OUTPUT] is @racket[#f], this message is
presented differently depending value of @racket[v]:

If @racket[(exn? v)], then @racket[($fail v)] is shown as @racket[(exn->string v)].

If @racket[(string? v)], then @racket[($fail v)] is shown as @racket[v].

Otherwise, @racket[($fail v)] is shown as @racket[(~s v)].
}


@section{Localization}

@defmodule[xiden/l10n]

@racketmodname[xiden/l10n] uses @tech{messages} to communicate with
the user according to the value of @racket[(system-language+country)].
Currently, the only supported locale is @tt{en-US}.

@defproc[(get-message-formatter) message-formatter/c]{
Returns a @tech{message formatter} for translating @tech{messages}
to strings in the user's locale.
}

@defproc[(run+print-log [l logged?]) any/c]{
Returns the first value from @racket[(run-log l)].

Before returning control, each @tech{message} @racketid[M] from
@racket[run-log] is printed using

@racketblock[(write-message M (get-message-formatter) (current-output-port))]
}