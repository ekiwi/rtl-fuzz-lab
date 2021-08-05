all: afl-proxy

afl-proxy: afl-proxy.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f afl-proxy
