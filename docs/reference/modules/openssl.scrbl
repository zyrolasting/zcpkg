#lang scribble/manual

@title{OpenSSL}

@require[@for-label[racket/base
                    racket/contract
                    racket/pretty
                    xiden/openssl]
         racket/pretty
         xiden/openssl
         "../../shared.rkt"]

@defmodule[xiden/openssl]

OpenSSL is an implicitly-trusted dependency that Xiden invokes as a
subprocess.

@defthing[md-algorithm/c flat-contract? #:value (apply or/c md-algorithms)]{
A contract that accepts one of the symbols in @racket[md-algorithms].
}

@defthing[md-bytes-source/c flat-contract? #:value (or/c path-string? bytes? input-port?)]{
This contract matches a value @racket[V] suitable for use in @racket[make-digest].

Given @racket[(path-string? V)], the bytes are drawn from the file located at @racket[V].
Given @racket[(bytes? V)] or @racket[(input-port? V)], the bytes are drawn directly from @racket[V].
}

@defthing[md-algorithms (listof symbol?)]{
A list of symbols that represent supported message digest algorithms.

Bound to @typeset-code[(pretty-format #:mode 'print md-algorithms)]
}

@defproc[(make-digest [variant md-bytes-source/c] [algorithm md-algorithm/c]) bytes?]{
Returns the raw byte content of @racket[algorithm] applied to bytes from @racket[variant].
}
