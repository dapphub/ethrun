prefix = /usr/local
target = $(shell pwd)/target/release/ethrun
bin = $(prefix)/bin/

all:; cargo build --release
link: all; ln -s $(target) $(bin)
install: all; cp $(target) $(bin)
