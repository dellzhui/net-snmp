CURDIR = $(shell pwd)

CC = arm-linux-androideabi-gcc

SRCS_ROOT_DIR = $(CURDIR)/src
SRCS_ALL_DIR = $(shell find $(SRCS_ROOT_DIR) -type d)
SRCS_LIBSNMP_DIR = $(SRCS_ROOT_DIR)/snmp
OBJS_DIR = objs
LIBS_DIR = lib
DEPS_DIR = deps

SRCS_ALL = $(notdir $(shell find $(SRCS_ROOT_DIR) -name *.c -type f))
SRCS_TEST = test_main.c
SRCS_ISTC_CLI = istc_cli.c
SRCS_LIBISTC_7251S = istc_7251s.c istc_error.c
SRCS_LIBSNMP = $(notdir $(shell find $(SRCS_LIBSNMP_DIR) -name *.c -type f))

OBJS_TEST = $(addprefix $(OBJS_DIR)/,$(SRCS_TEST:.c=.o))
OBJS_LIBSNMP = $(addprefix $(OBJS_DIR)/,$(SRCS_LIBSNMP:.c=.o))
OBJS_LIBISTC_7251S = $(addprefix $(OBJS_DIR)/,$(SRCS_LIBISTC_7251S:.c=.o))
OBJS_ISTC_CLI = $(addprefix $(OBJS_DIR)/,$(SRCS_ISTC_CLI:.c=.o))

TEST = test
ISTC_CLI = istc_cli
LIBISTC_7251S = $(LIBS_DIR)/libistc_7251s.so
LIBSNMP = $(LIBS_DIR)/libsnmp.so
TARGETS = $(LIBSNMP) $(LIBISTC_7251S) $(TEST) $(ISTC_CLI) 

CFLAGS = -fPIC -I./include -Wall -g -fno-strict-aliasing -O2 -Ulinux -Dlinux=linux -I. -I/home/work/opensource/Git/net-snmp/out/include
BUILDLIBS = -lpthread -L/home/work/opensource/Git/net-snmp/out/lib -lnetsnmp -lm
DLFLAGS = -shared

vpath %.c $(SRCS_ALL_DIR)

all: $(TARGETS)

$(TEST): $(OBJS_TEST)
	@echo "building test"
	@$(CC) -o $@ $(OBJS_TEST) $(BUILDLIBS) -L$(LIBS_DIR) -lsnmp

$(ISTC_CLI): $(OBJS_ISTC_CLI)
	@echo "building istc_cli"
	@$(CC) -o $@ $(OBJS_ISTC_CLI) $(BUILDLIBS) -L$(LIBS_DIR) -listc_7251s -lsnmp

$(LIBISTC_7251S): $(OBJS_LIBISTC_7251S)
	@echo "building libistc_7251s.so"
	@$(CC) -o $@ $(OBJS_LIBISTC_7251S) $(DLFLAGS)

$(LIBSNMP): $(OBJS_LIBSNMP)
	@echo "building libsnmp.so"
	@$(CC) -o $@ $(OBJS_LIBSNMP) $(DLFLAGS)


ifneq ($(MAKECMDGOALS), clean)
sinclude $(addprefix $(DEPS_DIR)/,$(SRCS_ALL:.c=.d))
endif

$(OBJS_DIR)/%.o: %.c
	@echo "compiling $(notdir $(filter %.c, $^))"
	@$(CC) -o $@ -c $(filter %.c, $^) $(CFLAGS)
	
$(DEPS_DIR)/%.d: %.c
	@set -e; \
	rm -f $@; \
	$(CC) -E -MM $(CFLAGS) $(filter %.c, $^) > $@.$$$$; \
	sed 's,\(.*\)\.o[ :]*,$(OBJS_DIR)/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

clean:
	@rm -rf $(TARGETS) $(LIBS_DIR)/* $(OBJS_DIR)/* $(DEPS_DIR)/*
