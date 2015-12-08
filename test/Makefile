#
# Warning: you may need more libraries than are included here on the
# build line.  The agent frequently needs various libraries in order
# to compile pieces of it, but is OS dependent and we can't list all
# the combinations here.  Instead, look at the libraries that were
# used when linking the snmpd master agent and copy those to this
# file.
#
CURDIR = $(shell pwd)
NET_SNMP_BIN_PATH=${CURDIR}/../out/bin
CC=gcc
SRCS_DIR = src
OBJS_DIR = objs

SRCS0 = $(wildcard $(SRCS_DIR)/*.c)
SRCS = $(notdir $(SRCS0))
OBJS0 = $(SRCS:.c=.o)
OBJS = $(addprefix $(OBJS_DIR)/,$(OBJS0))

vpath %.c $(SRCS_DIR)

TARGETS=asyncapp

CFLAGS=-I./include -Wall -g `${NET_SNMP_BIN_PATH}/net-snmp-config --cflags`
BUILDLIBS=`${NET_SNMP_BIN_PATH}/net-snmp-config --libs`
BUILDAGENTLIBS=`${NET_SNMP_BIN_PATH}/net-snmp-config --agent-libs`

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: $(TARGETS)

asyncapp: $(OBJS_DIR) $(OBJS)
	$(CC) -o $@ $(OBJS) $(BUILDLIBS)


$(OBJS_DIR)/%.o: %.c
	$(CC) -o $(OBJS_DIR)/$(notdir $@) -c $^ $(CFLAGS)

$(OBJS_DIR): 
	if [ ! -d $@ ];then\
		mkdir $@;\
	fi

clean:
	rm -rf $(OBJS) $(TARGETS)

nstAgentPluginObject.so: nstAgentPluginObject.c Makefile
	$(CC) $(CFLAGS) $(DLFLAGS) -c -o nstAgentPluginObject.o nstAgentPluginObject.c
	$(CC) $(CFLAGS) $(DLFLAGS) -o nstAgentPluginObject.so nstAgentPluginObject.o
