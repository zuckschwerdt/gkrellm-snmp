# Sample Makefile for a GKrellM plugin, edited for gkrellm_snmp

GTK_INCLUDE = `gtk-config --cflags`
GTK_LIB = `gtk-config --libs`

IMLIB_INCLUDE = `imlib-config --cflags-gdk`
IMLIB_LIB = `imlib-config --libs-gdk`


FLAGS = -O2 -Wall -fPIC $(GTK_INCLUDE) $(IMLIB_INCLUDE)
LIBS = $(GTK_LIB) $(IMLIB_LIB) -lsnmp -lcrypto
LFLAGS = -shared

CC = gcc $(CFLAGS) $(FLAGS)

OBJS = gkrellm_snmp.o

gkrellm_snmp.so: $(OBJS)
	$(CC) $(OBJS) -o gkrellm_snmp.so $(LFLAGS) $(LIBS)

clean:
	rm -f *.o core *.so* *.bak *~

install: 
	install -c -s -m 755 gkrellm_snmp.so /usr/share/gkrellm/plugins

# gkrellm_snmp.o: gkrellm_snmp.c
