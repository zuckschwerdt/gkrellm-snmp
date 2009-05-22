# Makefile for a GKrellM SNMP monitor plugin

# Linux
GKRELLM_CONFIG ?=pkg-config gkrellm
SNMPLIB = -lnetsnmp
SYSLIB ?= $(SNMPLIB)
# older systems need lib crypto if libsnmp has privacy support.
# SYSLIB += -L/usr/local/ssl/lib -L/usr/ssl/lib -lcrypto

USER_PLUGIN_DIR ?= $(HOME)/.gkrellm2/plugins
PLUGIN_DIR ?= /usr/lib/gkrellm2/plugins
GKRELLM_INCLUDE ?= `$(GKRELLM_CONFIG) --cflags`
GKRELLM_LIB ?= `$(GKRELLM_CONFIG) --libs`

CFLAGS += -Wall -fPIC -I. $(GKRELLM_INCLUDE)
LIBS = $(GKRELLM_LIB) $(SYSLIB)
LFLAGS ?= -shared -Wl,-Bsymbolic

INSTALL ?= install -c
STRIP ?= strip -x

OBJS = simpleSNMP.o gkrellm_snmp.o

all:	gkrellm_snmp.so

osx:
	make LFLAGS="-bundle -undefined suppress -flat_namespace"

freebsd:
	make GTK_CONFIG=gtk12-config SYSLIB=-lsnmp PLUGIN_DIR=/usr/X11R6/libexec/gkrellm/plugins

ucdsnmp:
	make CFLAGS="-DUCDSNMP" SNMPLIB="-lsnmp"

gkrellm_snmp.so:	$(OBJS)
	$(CC) $(OBJS) -o gkrellm_snmp.so $(LFLAGS) $(LIBS)

clean:
	rm -f *.o core *.so* *.bak *~

install-user:	gkrellm_snmp.so
	make PLUGIN_DIR=$(USER_PLUGIN_DIR) install

install:	gkrellm_snmp.so
	$(INSTALL) -m 755 -d $(DESTDIR)$(PLUGIN_DIR)
	$(INSTALL) -m 755 gkrellm_snmp.so $(DESTDIR)$(PLUGIN_DIR)
	$(STRIP) $(DESTDIR)$(PLUGIN_DIR)/gkrellm_snmp.so

gkrellm_snmp.o:	gkrellm_snmp.c

