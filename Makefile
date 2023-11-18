PROJECT=switch
SOURCES=lib/queue.c lib/list.c lib/lib.c
LIBRARY=nope
INCPATHS=include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -Wall -Werror -Wno-error=unused-variable
CC=gcc

SWITCH_ID ?= 1

# Automatic generation of some important lists
OBJECTS=$(SOURCES:.c=.o)
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(PROJECT)

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(LIBFLAGS) -shared $(OBJECTS) $(LDFLAGS) -o dlink.so

.c.o:
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

clean:
	rm -rf $(OBJECTS)  hosts_output router_* dlink.so

run_switch: all
	python3 switch.py $(SWITCH_ID) $$(ifconfig -a | grep -o '^[^ :]*' | grep -v 'lo' | tr '\n' ' ')
