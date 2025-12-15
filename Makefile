.PHONY: build install uninstall test

build:
	cargo build --release

install: build
	install -Dm755 target/release/torc $(DESTDIR)/usr/bin/torc
	install -Dm644 README.md $(DESTDIR)/usr/share/doc/torc/README.md
	install -Dm644 LICENSE $(DESTDIR)/usr/share/licenses/torc/LICENSE

uninstall:
	rm -f $(DESTDIR)/usr/bin/torc
	rm -rf $(DESTDIR)/usr/share/doc/torc
	rm -rf $(DESTDIR)/usr/share/licenses/torc

test:
	cargo test
