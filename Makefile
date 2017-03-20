prefix = /usr/local
target = $(shell pwd)/target/release/ethrun
bin = $(prefix)/bin/

all:; cargo build --release
link: all; ln -s $(program) $(bin)
install: all; cp $(target) $(bin)
