# Makefile for a GKrellM SNMP monitor plugin

# Linux
GTK_CONFIG = gtk-config
IMLIB_CONFIG = imlib-config
SYSLIB = -lsnmp
# we need lib crypto if libsnmp has privacy support.
SYSLIB += -lcrypto -L/usr/local/ssl/lib -L/usr/ssl/lib

# FreeBSD
#GTK_CONFIG = gtk12-config
#IMLIB_CONFIG = imlib-config
#SYSLIB = -lsnmp
#PLUGIN_DIR = /usr/X11R6/libexec/gkrellm/plugins/

USER_PLUGIN_DIR = $(HOME)/.gkrellm/plugins
PLUGIN_DIR = /usr/share/gkrellm/plugins
GKRELLM_INCLUDE = -I/usr/local/include

GTK_INCLUDE = `$(GTK_CONFIG) --cflags`
GTK_LIB = `$(GTK_CONFIG) --libs`

IMLIB_INCLUDE = `$(IMLIB_CONFIG) --cflags-gdk`
IMLIB_LIB = `$(IMLIB_CONFIG) --libs-gdk`


FLAGS = -Wall -fPIC $(GTK_INCLUDE) $(IMLIB_INCLUDE) $(GKRELLM_INCLUDE)
LIBS = $(GTK_LIB) $(IMLIB_LIB) $(SYSLIB)
LFLAGS = -shared

CC = gcc $(CFLAGS) $(FLAGS)

INSTALL = install -c
INSTALL_PROGRAM = $(INSTALL) -s

OBJS = gkrellm_snmp.o

all:	gkrellm_snmp.so

freebsd:
	make GTK_CONFIG=gtk12-config SYSLIB=-lsnmp PLUGIN_DIR=/usr/X11R6/libexec/gkrellm/plugins

gkrellm_snmp.so:	$(OBJS)
	$(CC) $(OBJS) -o gkrellm_snmp.so $(LFLAGS) $(LIBS)

clean:
	rm -f *.o core *.so* *.bak *~

install-user:	gkrellm_snmp.so
	make PLUGIN_DIR=$(USER_PLUGIN_DIR) install

install:	gkrellm_snmp.so
	$(INSTALL) -m 755 -d $(PLUGIN_DIR)
	$(INSTALL_PROGRAM) -m 755 gkrellm_snmp.so $(PLUGIN_DIR)

gkrellm_snmp.o:	gkrellm_snmp.c

