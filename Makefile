.PHONY: dynamic static clean

CFLAGS = -Wall -O3 -Os
LDFLAGS = -s

dynamic: LDLIBS += -lpcap -lcrypto
dynamic: uthash.h mysql-unsha1-sniff

static: LDLIBS += -Wl,-Bstatic -lpcap -lcrypto -Wl,-Bdynamic
static: uthash.h mysql-unsha1-sniff

uthash.h:
	wget https://raw.githubusercontent.com/troydhanson/uthash/master/src/uthash.h

clean:
	$(RM) uthash.h

cleanall: clean
	$(RM) mysql-unsha1-sniff
