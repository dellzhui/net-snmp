#
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#

NET_SNMP_BIN_PATH=/home/work/opensource/net-snmp-5.7.3/out/bin
CC=gcc
OBJS_DIR = objs

OBJS1=snmpdemoapp.o
OBJS2=example-demon.o nstAgentSubagentObject.o
OBJS3=$(OBJS_DIR)/asyncapp.o
#TARGETS=example-demon snmpdemoapp asyncapp
TARGETS=asyncapp

CFLAGS=-I. -Wall -g `${NET_SNMP_BIN_PATH}/net-snmp-config --cflags`
#CFLAGS += `${NET_SNMP_BIN_PATH}/net-snmp-config --cflags`/local
BUILDLIBS=`${NET_SNMP_BIN_PATH}/net-snmp-config --libs`
BUILDAGENTLIBS=`${NET_SNMP_BIN_PATH}/net-snmp-config --agent-libs`

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: $(TARGETS)

snmpdemoapp: $(OBJS1)
	$(CC) -o snmpdemoapp $(OBJS1) $(BUILDLIBS)

asyncapp: $(OBJS3)
	$(CC) -o asyncapp $(OBJS3) $(BUILDLIBS)

example-demon: $(OBJS2)
	$(CC) -o example-demon $(OBJS2)  $(BUILDAGENTLIBS)

$(OBJS3): aaa.c
	$(CC) -c $< -o $@ $(CFLAGS)


clean:
	rm -rf $(OBJS2) $(OBJS3) $(TARGETS)

nstAgentPluginObject.so: nstAgentPluginObject.c Makefile
	$(CC) $(CFLAGS) $(DLFLAGS) -c -o nstAgentPluginObject.o nstAgentPluginObject.c
	$(CC) $(CFLAGS) $(DLFLAGS) -o nstAgentPluginObject.so nstAgentPluginObject.o
