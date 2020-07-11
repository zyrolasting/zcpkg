all: exe docs
.PHONY: all

setup:
	raco pkg install web-server-lib rackunit-lib

compile:
	raco make client/*.rkt service/*.rkt *.rkt

exe: compile
	raco exe -o zcpkg client/main.rkt

doc:
	raco make *.scrbl
	raco scribble --dest doc +m manual.scrbl

clean:
	git clean -fdX
