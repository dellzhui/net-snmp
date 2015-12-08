

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

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: clean $(TARGETS)

asyncapp: $(OBJS_DIR) $(OBJS)
	@$(CC) -o $@ $(OBJS) $(BUILDLIBS)


$(OBJS_DIR)/%.o: %.c
	@echo "compiling $(notdir $@)"
	@$(CC) -o $(OBJS_DIR)/$(notdir $@) -c $^ $(CFLAGS)

$(OBJS_DIR): 
	@if [ ! -d $@ ];then\
		mkdir $@;\
	fi

clean:
	rm -rf $(OBJS) $(TARGETS)

