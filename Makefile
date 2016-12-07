prefix = /usr/local

all:; cargo build --release
link: all; ln -s $(shell pwd)/target/release/ethrun $(prefix)/bin/
