A flexible package manager for Racket.


## Benefits

* You can install the _exact_ code you asked for.
* You can make links to the _exact_ versions of packages you need in your projects.
* You can use packages that would otherwise conflict in the same Racket installation.
* You can introduce package code starting from _zero trust_.
* You can publish breaking changes whenever you want.
* You can organize your files however you want.
* You can use your own package namespace.
* You can define deliverables with more creative freedom, outside of PLT's recipes.
* You can strictly separate third-party code from your Racket installation.


## Tradeoffs

* Dependencies are installed side-by-side ("SxS", for the hopelessly curt). This means added disk usage.
* Dependency management is less opinionated, hence more involved if you have highly-specific needs.
* Package development does not involve `raco setup` or `raco pkg`. The workflow is different.


## Wait, we already have `raco pkg`

Yes, and it's fine. `zcpkg` complements `raco pkg`, and is not meant
to provide redundant functionality.

To borrow [Sam Boyer's terms][boyer], `raco pkg` is a **Language
Package Manager**, or LPM.  It fetches and builds packages of Racket
source code. `raco pkg` further presumes that Racket packages define
at least one collection to include in a Racket installation. This
creates scenarios specific to Racket. For example, if two packages
define conflicting collection paths, users may need to create a custom
Racket configuration if they want to use both packages at once. These
configurations can be painful to maintain on a case-by-case basis.

The command `zcpkg` is short for "Zero-Collection Package," which
means it manages packages that define no collections.  Removing
collections from the equation severs the relationship between an
arbitrary group of files and a Racket installation. Meaning, you
cannot directly target these files using `raco setup` or collection
paths. The benefit is that you are free to integrate the files as you
wish. For that reason, `zcpkg` concerns itself with (re)producing
files as a **Project/Application Dependency Manager**, or
PDM. System-level dependencies matter too, but they are out of scope
for this section.


[boyer]: https://medium.com/@sdboyer/so-you-want-to-write-a-package-manager-4ae9c17d9527


## Setup

First, make sure the following programs are available in your search paths.

* Racket 7.0+. Verify with `racket -v`.
* OpenSSL 0.9.8+. Verify with `openssl version`.

Next, build the project using `make`.

```console
git clone ...
cd zcpkg
make
```

If everything worked, you should have HTML documentation in a `doc`
subdirectory and a new executable called `zcpkg`. If you see an error
relating to a missing Racket dependency, then you might be using a
trimmed down Racket installation. In that case, try `make racket-deps
&& make`.


## Release Status

### Alpha

At minimum, `zcpkg` must function offline. The alpha service offers
read-only access to manually-maintained files. There are no marketing
materials, onboarding features, or databases.

Package updates are defined in terms of installation and uninstallation.
For that reason, an update command is not necessary right now.

- [x] Define a namespace-specific string format for packages
- [x] Use SHA-384 for subresource integrity checking
- [x] Verify digital signatures (No restrictions on asymmetric crypto yet. Just bring your own keys).
- [x] Capture digests, installed packages, and `zcpkg` configuration for collaborators.
- [x] Create a new package from a template
- [x] Start a sandboxed REPL inside of a package
- [x] Show a diff between a capture and a workspace
- [x] Reproduce a workspace from a capture
    - [x] Apply stored configuration
    - [x] Run install commands
- [ ] Create a direct link to a package
- [x] Bundle a package for use on a server
- [x] Print informative output on demand
- [x] Basic operations
    - [x] Install a package (as a link) from a directory
    - [x] Install a package from a service
    - [x] Uninstall a package
- [x] Serve package artifacts
    - [x] Run server
    - [x] GET file
    - [x] GET directory listing
    - [x] GET file from URN's NSS


### Beta

The beta release introduces onboarding so that others can share their
work. Since hosting packages is a potentially expensive job, I will
need to fundraise before exposing the service to a wider audience.

- [ ] Let packages define supported Racket version ranges
    - [ ] Cap lower bound to `zcpkg`'s own minimum supported version
    - [ ] Cap upper bound to running Racket version
- [ ] Define onboarding process for new users
    - [ ] Implement password authentication
- [ ] Define fundraising goals and options
- [ ] Update command
    - [ ] Predicate update on if any dependents insist on keeping an existing version.
- [ ] Document critical bindings and commands
- [ ] 80%+ test coverage


### Production

This assumes the project is funded and able to operate on an
ongoing basis.

- [ ] Extend authentication with second-factor (Client certs or TOTP)
- [ ] Define database
    - [ ] Define table for provider
    - [ ] Define table for packages
    - [ ] Define table for revision names
    - [ ] Define table for sessions
    - [ ] Generate initial content based on flat files
    - [ ] Incrementally add records
- [ ] Enhance webpage to promotional website
    - [ ] Home
        - [ ] Summary
        - [ ] Search
    - [ ] Register
    - [ ] Login
    - [ ] Search results
- [ ] 98%+ test coverage
