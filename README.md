[![](https://img.shields.io/badge/%E2%99%A5-Support%20Ethical%20Software-red)](https://sagegerard.com/subscribe.html)

A functional dependency manager for Racket.


## Benefits

* You can install the _exact_ code you asked for.
* You can make links to the _exact_ files you need in your projects.
* You can use packages that would otherwise conflict in the same Racket installation.
* You can introduce package code starting from _zero trust_.
* You can publish breaking changes whenever you want.
* You can organize your files however you want.
* You can use your own package namespace.
* You can define deliverables with more creative freedom, outside of the PLT's recipes.
* You can strictly separate third-party code from your Racket installation.


## Tradeoffs

* Higher storage requirements
* Different learning curve


## But we already have `raco pkg`

Yes, and it's fine. So what's different? `raco pkg` has side-effects
on the Racket installation that runs it. `xiden` does not. This means
`xiden` does not create collections in the running Racket
installation. You cannot directly target Racket modules using `raco
setup` or collection paths, but you can incorporate dependencies as if
they were parts of your project.

`xiden` behaves like [Guix][], in that packages are built
deterministically and atomically. When you want to use a dependency,
you can request links to it. Delete every link to make that dependency
eligible for garbage collection.

[Guix]: https://guix.gnu.org/

## Setup

First, make sure the following programs are available in your search paths.

* SQLite 3.24.0+. Verify with `sqlite3 -version`.
* Racket 7.0+. Verify with `racket -v`.
* OpenSSL 1.0.0+. Verify with `openssl version`.

Next, build the project using `make`.

```console
git clone ...
cd xiden
make
```

If everything worked, you should have HTML documentation in an `html`
subdirectory and a new executable called `xiden` in the working
directory.


## Release Status

| Milestone   | Status                                                                |
| ----------- | --------------------------------------------------------------------- |
| Alpha       | [Released](https://github.com/zyrolasting/xiden/releases/tag/alpha)   |
| Closed Beta | [Ongoing](https://github.com/zyrolasting/xiden/milestone/1)           |
| Open Beta   | [Not started](https://github.com/zyrolasting/xiden/milestone/2)       |
| Production  | [Not started](https://github.com/zyrolasting/xiden/milestone/3)       |
