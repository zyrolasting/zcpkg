#lang scribble/manual

@require[@for-label[racket/base
                    racket/contract
                    racket/string
                    xiden/input-info
                    xiden/logged
                    xiden/package
                    xiden/rc
                    xiden/string
                    xiden/url
                    xiden/version]
         "../../shared.rkt"]

@title{Packages}

@defmodule[xiden/package]

@defstruct*[package ([description string?]
                     [tags (listof non-empty-string?)]
                     [url url-string?]
                     [provider non-empty-string?]
                     [name non-empty-string?]
                     [edition non-empty-string?]
                     [revision-number revision-number?]
                     [revision-names (listof non-empty-string?)]
                     [os-support (listof symbol?)]
                     [racket-versions (listof (list/c non-empty-string?))]
                     [metadata (hash/c symbol? string?)]
                     [inputs (listof input-info?)]
                     [output-names (listof non-empty-string?)]
                     [build (-> non-empty-string? (logged/c void?))])]{
A @deftech{package} is an instance of @racket[package].

@racket[description] is a human-readable summary of the package's purpose.

@racket[tags] is a list of human-readable topics used for discovery.

@racketid[url] is the primary, or canonical URL used to guide a user
towards more information (as opposed to secondary URLs that may appear
in @racket[metadata]).

@racket[provider] is the name of the allegedly responsible
distributor.

@racket[name] is the name of the package.

@racket[edition], @racket[revision-number], and
@racket[revision-names] are the package's @tech{edition},
@tech{revision number}, and @tech{revision names}.

@racket[os-support] is a list of possible values from
@racket[(system-type 'os)].  If @racket[(system-type 'os)] is not an
element of @racket[os-support], then either calls to @racket[build]
will fail, or the software created with @racket[build] will not
function.

@racket[racket-versions] is a list of Racket version ranges that
should be interpreted as a set of supported Racket versions. If
@racket[(version)] is not an element of any version interval, then
assume that the software created with @racket[build] will not
function with the running version of Racket.

@racket[metadata] is a hash table of user-defined metadata.  In the
event entries of this table appear redundant with other structure
fields, prefer the values in the structure fields.

@racket[inputs] is a list of @tech{package inputs}.

@racket[output-names] is a list of defined @tech{package outputs}.

@margin-note{@racket[build] procedures created using
@racketmodname[xiden/pkgdef] are always surjective, but might not be
injective.}
@racket[build] is function that maps the elements of
@racket[output-names] to @tech{logged procedures}. Each logged
procedure installs software into @racket[current-directory] assuming
@racket[current-inputs] is bound to @racket[inputs]. The behavior of
@racket[build] is impacted by the @tech{runtime configuration}.

Xiden will not verify if @racket[build] procedures are bijective.  If
@racket[build] is not bijective, then @racket[build]'s relationship
with the host system varies slightly. If @racket[build] is not
injective, then it may create redundant data on disk because Xiden
assumes that different output names imply different file
distributions. If @racket[build] is not surjective, then a
@tech{logged procedure} might be inaccessible.  This can happen if a
@racket[package] instance is manually created with faulty data.
Bijective @racket[build] procedures do not have these problems.
}

@defthing[empty-package package?]{
The @tech{package} with no inputs, no outputs, and all default values.
The empty package claims to support all operating systems and versions
of Racket.
}

@defthing[output-not-found (-> non-empty-string? logged?)]{
The build procedure for the empty package.

Returns a @tech{logged procedure} that always fails and adds
@racket[$package:output:undefined] to the program log.
}

@defproc[(install [link-path (or/c #f path-string?)]
                  [output-name (or/c #f string?)]
                  [package-definition-variant any/c])
                  logged?]{
Returns a @tech{logged procedure} called for its effect.  The effect
being that a symbolic link gets created at @racket[link-path],
pointing to a directory. That directory contains the files
corresponding to the @racket[output-name] defined in
@racket[package-definition-variant]).

If @racket[link-path] is @racket[#f], then the name of the symbolic
link will match the name of the package.

If @racket[output-name] is @racket[#f], then @racket[install] will use
@racket[DEFAULT_STRING].

The @tech{logged procedure} is not atomic, so failure may result in
a broken intermediate state on disk. This procedure should be used
in the context of a transaction to avoid this problem.

All @racket[install] @tech{messages} are instances of @racket[$package].
}


@section{Package Messages}

@defstruct*[($package $message) () #:prefab]{
A @tech{message} from a package's runtime.
}

@defstruct*[($package:log $package) ([query package-query?]
                                     [output-name string?]
                                     [messages messy-log/c]) #:prefab]{
A @tech{message} containing other messages relevant to building a particular package output.
}

@defstruct*[($package:output $package) () #:prefab]{
A @tech{message} pertaining to a package output.
}

@defstruct*[($package:output:built $package:output) () #:prefab]{
Xiden successfully built a package output.
}

@defstruct*[($package:output:reused $package:output) () #:prefab]{
Xiden reused a previously-built package output.
}

@defstruct*[($package:output:undefined $package:output) () #:prefab]{
A requested output is not defined in a corresponding @tech{package
definition}.
}

@defstruct*[($package:unsupported-racket-version $package)
            ([versions racket-version-ranges/c]) #:prefab]{
A @tech{package} claims that the software it builds does not support
the running version of Racket.
}

@defstruct*[($package:unsupported-os $package)
            ([supported (listof symbol?)]) #:prefab]{
A @tech{package} claims that it, or the software it builds, does not support
the current operating system. Supported systems in @racket[supported]
are possible values from @racket[(system-type 'os)].
}

@defstruct*[($package:unavailable-output $package)
            ([available (listof string?)]) #:prefab]{
The @racket[requested] output for a package is not among the @racket[available] outputs.
}
