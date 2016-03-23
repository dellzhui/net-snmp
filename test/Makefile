.PHONY: all clean
CURDIR = $(shell pwd)
S = $(CURDIR)/../../../
#include $(S)/make/tools.mk

CC=gcc

SRCS_ROOT_DIR = $(CURDIR)/src
SRCS_ALL_DIR = $(shell find $(SRCS_ROOT_DIR) -type d)
SRCS_LIBSNMP_DIR = $(SRCS_ROOT_DIR)/snmp
OBJS_DIR = objs
LIBS_DIR = lib
DEPS_DIR = deps
ADB_LIBS_DIR = /system/adb/lib/
ADB_BIN_DIR = /system/adb/

SRCS_ALL = $(notdir $(shell find $(SRCS_ROOT_DIR) -name *.c -type f))
SRCS_TEST = test_main.c
SRCS_ISTC_CLI = istc_cli.c
SRCS_LIBISTC_7251S = istc_7251s.c 
SRCS_LIBSNMP = $(notdir $(shell find $(SRCS_LIBSNMP_DIR) -name *.c -type f))

OBJS_TEST = $(addprefix $(OBJS_DIR)/,$(SRCS_TEST:.c=.o))
OBJS_LIBSNMP = $(addprefix $(OBJS_DIR)/,$(SRCS_LIBSNMP:.c=.o))
OBJS_LIBISTC_7251S = $(addprefix $(OBJS_DIR)/,$(SRCS_LIBISTC_7251S:.c=.o))
OBJS_ISTC_CLI = $(addprefix $(OBJS_DIR)/,$(SRCS_ISTC_CLI:.c=.o))

TEST = istc_test
ISTC_CLI = istc_cli
LIBISTC_7251S = $(LIBS_DIR)/libistc_7251s.so
LIBSNMP = $(LIBS_DIR)/libsnmp.so
TARGETS = $(LIBSNMP) $(LIBISTC_7251S) $(TEST) $(ISTC_CLI)

CFLAGS += -fPIC -I./include  -Wall  -g -fno-strict-aliasing -O2 -Ulinux -Dlinux=linux -I.
LDFLAGS += -L./lib/netsnmp -lnetsnmp -lm 
OFLAGS = $(S)/install/brcmSDK/lib/crtbegin_dynamic.o $(S)/install/brcmSDK/lib/crtend_android.o

vpath %.c $(SRCS_ALL_DIR)
$(shell if [ ! -d $(OBJS_DIR) ]; then mkdir $(OBJS_DIR); fi)
$(shell if [ ! -d $(DEPS_DIR) ]; then mkdir $(DEPS_DIR); fi)
ADBENABLE = no
ifeq ("x$(ADBENABLE)", "xyes")
ADBPATH = $(shell whereis adb | grep "adb:.*adb")
ifneq ("x$(ADBPATH)", "x")
ADBIP = $(shell adb devices | grep :5555 | sed 's/:.*$$//g')
ifneq ("x$(ADBIP)", "x")
ADBNOTSUPPORT = $(shell ping -c 1 -w 1 $(ADBIP) | grep "100% packet loss")
else
ADBNOTSUPPORT = not support
endif
else
ADBNOTSUPPORT = not support
endif
else
ADBNOTSUPPORT = not support
endif

default: $(LIBISTC_7251S)

all: $(TARGETS)

$(TEST): $(OBJS_TEST) $(LIBSNMP)
	@echo "building istc_test"
	@$(CC) -o $@ $(OBJS_TEST) $(OFLAGS) $(LDFLAGS) -L$(LIBS_DIR) -lsnmp
	@if [ "x$(ADBNOTSUPPORT)" = "x" ];then \
		adb push $@ $(ADB_BIN_DIR); \
	fi

$(ISTC_CLI): $(OBJS_ISTC_CLI) $(LIBSNMP) $(LIBISTC_7251S)
	@echo "building istc_cli"
	@$(CC) -o $@ $(OBJS_ISTC_CLI) $(LDFLAGS) $(OFLAGS) -L$(LIBS_DIR) -listc_7251s -lsnmp
	@if [ "x$(ADBNOTSUPPORT)" = "x" ];then \
		adb push $@ $(ADB_BIN_DIR); \
	fi

$(LIBISTC_7251S): $(OBJS_LIBISTC_7251S) $(LIBSNMP) 
	@echo "building libistc_7251s.so"
	@$(CC) -o $@ $(OBJS_LIBISTC_7251S) $(LDFLAGS) -L$(LIBS_DIR) -lsnmp -shared
	@if [ "x$(ADBNOTSUPPORT)" = "x" ];then \
                adb push $@ $(ADB_LIBS_DIR); \
        fi

$(LIBSNMP): $(OBJS_LIBSNMP)
	@echo "building libsnmp.so"
	@$(CC) -o $@ $(OBJS_LIBSNMP) $(LDFLAGS) -shared
	@if [ "x$(ADBNOTSUPPORT)" = "x" ];then \
                adb push $@ $(ADB_LIBS_DIR); \
        fi

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
	@rm -rf $(TARGETS) $(OBJS_DIR) $(DEPS_DIR)
