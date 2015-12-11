

CURDIR = $(shell pwd)
NET_SNMP_BIN_PATH=${CURDIR}/../out/bin

CC=gcc

SRCS_ROOT_DIR = $(CURDIR)/src
SRCS_DIR = $(shell find $(SRCS_ROOT_DIR) -type d)
OBJS_DIR = objs

SRCS0 = $(shell find $(SRCS_ROOT_DIR) -name *.c -type f)
SRCS = $(notdir $(SRCS0))
OBJS0 = $(SRCS:.c=.o)
OBJS = $(addprefix $(OBJS_DIR)/,$(OBJS0))

vpath %.c $(SRCS_DIR)

TARGETS=asyncapp

CFLAGS=-I./include -Wall -g `${NET_SNMP_BIN_PATH}/net-snmp-config --cflags`
BUILDLIBS=`${NET_SNMP_BIN_PATH}/net-snmp-config --libs`
DLFLAGS=-fPIC -shared

all: clean $(TARGETS)

asyncapp: $(OBJS_DIR) $(OBJS)
	@$(CC) -o $@ $(OBJS) $(BUILDLIBS)

$(OBJS_DIR)/%.o: %.c
	@echo "compiling $(notdir $^)"
	@$(CC) -o $(OBJS_DIR)/$(notdir $@) -c $^ $(CFLAGS)

$(OBJS_DIR): 
	@if [ ! -d $@ ];then\
		mkdir $@;\
	fi

clean:
	@rm -rf $(OBJS) $(TARGETS)

