CURDIR = $(shell pwd)
NET_SNMP_BIN_PATH=${CURDIR}/../out/bin

CC=gcc

SRCS_ROOT_DIR = $(CURDIR)/src
SRCS_ALL_DIR = $(shell find $(SRCS_ROOT_DIR) -type d)
SRCS_LIBSNMP_DIR = $(SRCS_ROOT_DIR)/snmp
OBJS_DIR = objs
LIBS_DIR = lib

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

CFLAGS = -I./include -Werror -Wall -g `${NET_SNMP_BIN_PATH}/net-snmp-config --cflags`
BUILDLIBS = -lpthread `${NET_SNMP_BIN_PATH}/net-snmp-config --libs`
DLFLAGS = -fPIC -shared

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

sinclude $(addprefix $(OBJS_DIR)/,$(SRCS_ALL:.c=.d))

$(OBJS_DIR)/%.d: %.c
	@set -e; \
	rm -f $(OBJS_DIR)/$(notdir $@); \
	$(CC) -MM $(CFLAGS) $< > $(OBJS_DIR)/$(notdir $@).$$$$; \
	sed 's,\($*\)\.o[ :]*,$(OBJS_DIR)/\1.o $@ : ,g' < $(OBJS_DIR)/$(notdir $@).$$$$ > $(OBJS_DIR)/$(notdir $@); \
	echo -e "\t@echo \"compiling $(notdir $^)\"" >> $(OBJS_DIR)/$(notdir $@); \
	echo -e "\t@$(CC) -o $(OBJS_DIR)/$(notdir $@) -c $^ $(CFLAGS)" | sed 's/.d -c /.o -c /g' >> $(OBJS_DIR)/$(notdir $@); \
	echo -e "\t@touch $(OBJS_DIR)/$(notdir $@)" >> $(OBJS_DIR)/$(notdir $@); \
	rm -f $(OBJS_DIR)/$(notdir $@).$$$$

clean:
	@rm -rf $(LIBS_DIR)/* $(OBJS_DIR)/*.o $(TARGETS)
	
dclean:
	@rm -rf $(LIBS_DIR)/* $(OBJS_DIR)/* $(TARGETS)

