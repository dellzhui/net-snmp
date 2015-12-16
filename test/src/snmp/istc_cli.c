
/**
 ** Copyright (c) Inspur Group Co., Ltd. Unpublished
 **
 ** Inspur Group Co., Ltd.
 ** Proprietary & Confidential
 **
 ** This source code and the algorithms implemented therein constitute
 ** confidential information and may comprise trade secrets of Inspur
 ** or its associates, and any use thereof is subject to the terms and
 ** conditions of the Non-Disclosure Agreement pursuant to which this
 ** source code was originally received.
 **/

/******************************************************************************
DESCRIPTION:
  iSTC(Inspur Safe Token Center) client routine definition

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
01a,19Jun2014,xiongdb@inspur.com           written
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <ctype.h>



#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "istc.h"
#include "istc_version.h"
#include "istc_protocol.h"
#include "istc_snmp_interface.h"


#define CMD_ARGC_MAX	48
#define CMD_ARGV_LEN	128

#define CMD_QUIT		0xf0000000
#define CMD_EXIT		0xf1000000
#define CMD_SIGNAL		0xf2000000


#define CMD_SCRIPT_BUFF_SIZE	1024


jmp_buf env;

typedef struct cmd_s {
    char *prompt;
    char *name;
    int length;
    char *help;
    char *args;
    char *desc;
    int (*handle) (struct cmd_s * this, int argc, char **argv);
    struct cmd_s *parent;
    struct cmd_s *child;
    struct cmd_s *prev;
    struct cmd_s *next;
} cmd_t;


typedef struct cmd_args_s {
    int argc;
    char *argv[CMD_ARGC_MAX];
    char buff[CMD_ARGC_MAX][CMD_ARGV_LEN];
} cmd_args_t;


typedef struct cmd_log_lv_s {
    int level;
    char *str;
} cmd_log_lv_t;


const static cmd_log_lv_t cmd_log_lv[] = {
    {0, "EMERG"},
    {1, "Alert"},
    {2, "Critical"},
    {3, "Error"},
    {4, "Warrning"},
    {5, "Notice"},
    {6, "Information"},
    {7, "Debug"},
};

static FILE *cmd_script_fp = NULL;

typedef int (*read_args_func_t) (char *prompt, int *argc, char **argv);

static read_args_func_t read_args_func = NULL;

char *cmd_htoa(unsigned int ip);



int cmd_handle_help(cmd_t * this, int argc, char **argv);
int cmd_handle_quit(cmd_t * this, int argc, char **argv);
int cmd_handle_exit(cmd_t * this, int argc, char **argv);
int cmd_handle_list(cmd_t * this, int argc, char **argv);
int cmd_handle_sleep(cmd_t * this, int argc, char **argv);

cmd_t *cmd_match(cmd_t * this, char *name);
int cmd_handle_cli(cmd_t * this, int argc, char **argv);




int cmd_handle_ip_get_addr(cmd_t * this, int argc, char **argv);
int cmd_handle_ip_set_addr(cmd_t * this, int argc, char **argv);

int cmd_handle_ip_get_mask(cmd_t * this, int argc, char **argv);
int cmd_handle_ip_set_mask(cmd_t * this, int argc, char **argv);

int cmd_handle_ip_get_addr_mode(cmd_t * this, int argc, char **argv);
int cmd_handle_ip_set_addr_mode(cmd_t * this, int argc, char **argv);


int cmd_handle_mac_get_mac(cmd_t * this, int argc, char **argv);
int cmd_handle_mac_set_mac(cmd_t * this, int argc, char **argv);



int cmd_handle_link_get_state(cmd_t * this, int argc, char **argv);
int cmd_handle_link_get_admin(cmd_t * this, int argc, char **argv);
int cmd_handle_link_get_mtu(cmd_t * this, int argc, char **argv);
int cmd_handle_link_set_admin(cmd_t * this, int argc, char **argv);



int cmd_handle_sta_scan(cmd_t * this, int argc, char **argv);
int cmd_handle_sta_state(cmd_t * this, int argc, char **argv);
int cmd_handle_sta_get_scan_result(cmd_t * this, int argc, char **argv);
int cmd_handle_sta_add_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_sta_add2_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_sta_remove_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_sta_enable_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_sta_disable_ssid(cmd_t * this, int argc, char **argv);


int cmd_handle_ap_get_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_get_sta(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_add_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_remove_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_enable_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_disable_ssid(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_get_acl_mac(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_add_accept_mac(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_rm_accept_mac(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_add_deny_mac(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_rm_deny_mac(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_get_mac_acl(cmd_t * this, int argc, char **argv);
int cmd_handle_ap_set_mac_acl(cmd_t * this, int argc, char **argv);



int cmd_handle_dhcp_get_pool(cmd_t * this, int argc, char **argv);
int cmd_handle_dhcp_get_lease(cmd_t * this, int argc, char **argv);
int cmd_handle_dhcp_add_pool(cmd_t * this, int argc, char **argv);
int cmd_handle_dhcp_remove_pool(cmd_t * this, int argc, char **argv);
int cmd_handle_dhcp_add_opt60(cmd_t * this, int argc, char **argv);
int cmd_handle_dhcp_remove_opt60(cmd_t * this, int argc, char **argv);
int cmd_handle_dhcp_add_opt60_s(cmd_t * this, int argc, char **argv);
int cmd_handle_dhcp_remove_opt60_s(cmd_t * this, int argc, char **argv);








int cmd_handle_route_get_state(cmd_t * this, int argc, char **argv);
int cmd_handle_route_set_state(cmd_t * this, int argc, char **argv);
int cmd_handle_route_get_default(cmd_t * this, int argc, char **argv);
int cmd_handle_route_set_default(cmd_t * this, int argc, char **argv);


int cmd_handle_dns_get_dns(cmd_t * this, int argc, char **argv);
int cmd_handle_dns_set_dns(cmd_t * this, int argc, char **argv);


int cmd_handle_misc_save_config(cmd_t * this, int argc, char **argv);

int cmd_handle_pppoe_get_config(cmd_t * this, int argc, char **argv);
int cmd_handle_pppoe_set_config(cmd_t * this, int argc, char **argv);
int cmd_handle_pppoe_state(cmd_t * this, int argc, char **argv);
int cmd_handle_pppoe_connect(cmd_t * this, int argc, char **argv);
int cmd_handle_pppoe_disconnect(cmd_t * this, int argc, char **argv);
int cmd_handle_pppoe_async_connect(cmd_t * this, int argc, char **argv);


int cmd_handle_misc_ping(cmd_t * this, int argc, char **argv);

int cmd_handle_misc_get_iflist(cmd_t * this, int argc, char **argv);
int cmd_handle_misc_get_iftype(cmd_t * this, int argc, char **argv);
int cmd_handle_misc_get_if(cmd_t * this, int argc, char **argv);

int cmd_handle_misc_get_log_lv(cmd_t * this, int argc, char **argv);
int cmd_handle_misc_set_log_lv(cmd_t * this, int argc, char **argv);


int cmd_handle_misc_async_sta_connect(cmd_t * this, int argc, char **argv);
int cmd_handle_misc_async_sta_disconnect(cmd_t * this, int argc, char **argv);


int cmd_handle_misc_async_ap_start(cmd_t * this, int argc, char **argv);
int cmd_handle_misc_async_ap_stop(cmd_t * this, int argc, char **argv);

int cmd_handle_misc_async_ping(cmd_t * this, int argc, char **argv);

int cmd_handle_misc_async_sta_scan(cmd_t * this, int argc, char **argv);


int cmd_handle_qos_set_mode(cmd_t * this, int argc, char **argv);
int cmd_handle_qos_get_mode(cmd_t * this, int argc, char **argv);
int cmd_handle_qos_set_device_bandwidth(cmd_t * this, int argc, char **argv);
int cmd_handle_qos_get_device_bandwidth(cmd_t * this, int argc, char **argv);
int cmd_handle_qos_get_device_bandwidth_list(cmd_t * this, int argc, char **argv);

int cmd_handle_lan_set_addr_info(cmd_t * this, int argc, char **argv);
int cmd_handle_lan_get_addr_info(cmd_t * this, int argc, char **argv);

#define CMD_DEFINE(name, args, desc, help) \
	int cmd_handle_##name (cmd_t *this, int argc, char **argv); \
	static cmd_t cmd_ ## name = { 			\
		NULL, #name, 0, help, args, desc, cmd_handle_ ## name , NULL, NULL, NULL, NULL \
	}; 										\
	int cmd_handle_##name (cmd_t *this, int argc, char **argv)


#define CMD_NODE(name, prompt, help)	\
	static cmd_t cmd_ ## name = {			\
		prompt, #name, 0, help, NULL, NULL, cmd_handle_cli, NULL, NULL, NULL, NULL \
	}


/*
 * CMD_NODE and CMD_DEFINE macro usage
 * a demo for marco definition command :
 * use CMD_NODE to define a node, it take 3 arguments, the first is the command 
 * node name, which will auto add 'cmd_' prefix, second is the command line 
 * prompt, the last is the helpful message, e.g. 
 * CMD_NODE(test, "test> ", "this is test!");
 * the real node defined is cmd_test
 *
 * use CMD_DEFINE to define a command, it take 4 arguments, the first is the
 * command name, which will auto add 'cmd_' prefix, the second is the arguments
 * list used by handle function, the third is the description for 3rd, and the
 * last is helpful message, e.g.
 * CMD_DEFINE(foo, NULL, NULL, "foo bar ...") { ..... }
 * the real command defined is cmd_foo, and the function name is cmd_handle_foo,
 * so the definition of function is like below :
 * int cmd_hanle_foo(cmd_t *this, int argc, char **argv)
 * {
 *
 *     //do anything you want to hanle the command
 *
 *     //and do not remenber to return a integer value
 *     return 0;
 * }
 *
 */

#if 0
/* CMD_NODE(node_name, const char *prompt, const char *help_message) */
CMD_NODE(test, "test> ", "this is test!");

/* CMD_DEFINE(cmd_name, const char *arguments_list, const char *arguments_description, const char *help_message) */
CMD_DEFINE(foo, NULL, NULL, "foo bar ...")
{
    printf("this is foo bar test by macro defined\n");

    return 0;
}
#endif

static cmd_t cmd_root = {
    .prompt = "cli> ",
    .name = "root",
    .length = 4,
    .handle = cmd_handle_cli,
    .parent = NULL,
    .child = NULL,
    .prev = &cmd_root,
    .next = &cmd_root,
    .help = "command line",
};

static cmd_t cmd_quit = {
    .name = "quit",
    .length = 4,
    .handle = cmd_handle_quit,
    .help = "quit this level and back to up",
};

static cmd_t cmd_exit = {
    .name = "exit",
    .length = 4,
    .handle = cmd_handle_exit,
    .help = "exit all level and goto the top",
};

static cmd_t cmd_help = {
    .name = "help",
    .length = 4,
    .handle = cmd_handle_help,
    .help = "use list to display all command(s)",
};

static cmd_t cmd_help2 = {
    .name = "?",
    .length = 1,
    .handle = cmd_handle_list,
    .help = "list all available command under this node",
};


static cmd_t cmd_list_cmd = {
    .name = "list",
    .length = 4,
    .handle = cmd_handle_list,
    .help = "list all available command under this node",
};

static cmd_t cmd_list_sleep = {
    .name = "sleep",
    .length = 5,
    .handle = cmd_handle_sleep,
    .help = "sleep in second",
};



static cmd_t cmd_class_ip = {
    .prompt = "ip> ",
    .name = "ip",
    .length = 2,
    .handle = cmd_handle_cli,
    .help = "class ip configuration",
};


static cmd_t cmd_class_ip_get_addr = {
    .name = "getaddr",
    .args = "IFNAME",
    .handle = cmd_handle_ip_get_addr,
    .help = "get interface ip address",
};

static cmd_t cmd_class_ip_set_addr = {
    .name = "setaddr",
    .args = "IFNAME IP",
    .handle = cmd_handle_ip_set_addr,
    .help = "set interface ip address",
};

static cmd_t cmd_class_ip_get_mask = {
    .name = "getmask",
    .args = "IFNAME",
    .handle = cmd_handle_ip_get_mask,
    .help = "get interface netmask address",
};

static cmd_t cmd_class_ip_set_mask = {
    .name = "setmask",
    .args = "IFNAME NETMASK",
    .handle = cmd_handle_ip_set_mask,
    .help = "set interface netmask address",
};

static cmd_t cmd_class_ip_get_addr_mode = {
    .name = "getmode",
    .args = "IFNAME",
    .handle = cmd_handle_ip_get_addr_mode,
    .help = "get interface IP address alloc mode(static, dynamic etc)",
};

static cmd_t cmd_class_ip_set_addr_mode = {
    .name = "setmode",
    .args = "IFNAME <static | dhcp | pppoe>",
    .desc = "\tIFNAME           the interface name\n"
        "\tstatic           static and manual config the interface IP\n"
        "\tdhcp             use DHCP to alloc IP address from DHCP server\n"
        "\tpppoe            use PPPoE to alloc IP address",
    .handle = cmd_handle_ip_set_addr_mode,
    .help = "set interface IP address alloc mode(static, dynamic etc)",
};


/* ---------- MAC CLASS--------------- */

static cmd_t cmd_class_mac = {
    .prompt = "mac> ",
    .name = "mac",
    .length = 3,
    .handle = cmd_handle_cli,
    .help = "class MAC configuration",
};

static cmd_t cmd_class_mac_get_mac = {
    .name = "getmac",
    .args = "IFNAME",
    .desc = "\tIFNAME       the interface name",
    .handle = cmd_handle_mac_get_mac,
    .help = "get interface MAC address",
};

static cmd_t cmd_class_mac_set_mac = {
    .name = "setmac",
    .args = "IFNAME MAC",
    .desc = "\tIFNAME       the interface name\n"
        "\tMAC          the interface MAC address",
    .handle = cmd_handle_mac_set_mac,
    .help = "set interface MAC address",
};



/* ---------- LINK CLASS -------------- */
static cmd_t cmd_class_link = {
    .prompt = "link> ",
    .name = "link",
    .length = 4,
    .handle = cmd_handle_cli,
    .help = "class link configuration",
};

static cmd_t cmd_class_link_get_state = {
    .name = "getlink",
    .args = "IFNAME",
    .desc = "\tIFNAME       the interface name",
    .handle = cmd_handle_link_get_state,
    .help = "get interface link state",
};

static cmd_t cmd_class_link_get_admin = {
    .name = "getadmin",
    .args = "IFNAME",
    .desc = "\tIFNAME       the interface name",
    .handle = cmd_handle_link_get_admin,
    .help = "get interface admin state",
};

static cmd_t cmd_class_link_get_mtu = {
    .name = "getmtu",
    .args = "IFNAME",
    .desc = "\tIFNAME       the interface name",
    .handle = cmd_handle_link_get_mtu,
    .help = "get interface MTU",
};

static cmd_t cmd_class_link_set_admin = {
    .name = "setadmin",
    .args = "IFNAME <up | down>",
    .desc = "\tIFNAME       the interface name\n"
        "\t<up | down>  up/UP to enable the traffic on interface\n"
        "\t             down/DOWN to disable the traffic on interface",
    .handle = cmd_handle_link_set_admin,
    .help = "set interface admin state(enable or disable the traffic)",
};





/* ----------- STA CLASS -------------- */
static cmd_t cmd_class_sta = {
    .prompt = "sta> ",
    .name = "sta",
    .length = 3,
    .handle = cmd_handle_cli,
    .help = "class station configuration",
};


static cmd_t cmd_class_sta_scan = {
    .name = "scan",
    .length = 4,
    .args = "IFNAME",
    .handle = cmd_handle_sta_scan,
    .help = "start station wifi scanning",
};

static cmd_t cmd_class_sta_state = {
    .name = "state",
    .args = "IFNAME",
    .handle = cmd_handle_sta_state,
    .help = "query station state",
};

static cmd_t cmd_class_sta_get_scan_result = {
    .name = "scanresult",
    .args = "IFNAME",
    .handle = cmd_handle_sta_get_scan_result,
    .help = "get ssid scan result list",
};

static cmd_t cmd_class_sta_add_ssid = {
    .name = "addssid",
    .args = "IFNAME SSID [PASSWORD]",
    .handle = cmd_handle_sta_add_ssid,
    .help =
        "add a ssid configuration, include SSID name and password(if not open)",
};

static cmd_t cmd_class_sta_add2_ssid = {
    .name = "add2ssid",
    .args = "IFNAME SSID ENCRYPTION [PASSWORD]",
    .handle = cmd_handle_sta_add2_ssid,
    .help =
        "add a ssid configuration, include SSID name, encryption and password(if not open)\n"
        "support encryption type are: WPA, WPA2, WPAWPA2, OPEN",
};


static cmd_t cmd_class_sta_remove_ssid = {
    .name = "rmssid",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME             the interface name\n"
        "\tSSID               the SSID name",
    .handle = cmd_handle_sta_remove_ssid,
    .help = "remove the preconfigurated SSID",
};


static cmd_t cmd_class_sta_enable_ssid = {
    .name = "enssid",
    .args = "IFNAME SSID",
    .handle = cmd_handle_sta_enable_ssid,
    .help =
        "enable the preconfigurated SSID, and try to connect this SSID, you can use state command to query result",
};


static cmd_t cmd_class_sta_disable_ssid = {
    .name = "dissid",
    .args = "IFNAME SSID",
    .handle = cmd_handle_sta_disable_ssid,
    .help =
        "disable the preconfigurated SSID, you can use enssid to reuse this SSID",
};



/* ---------------- AP CLASS ---------------- */

static cmd_t cmd_class_ap = {
    .prompt = "ap> ",
    .name = "ap",
    .length = 2,
    .handle = cmd_handle_cli,
    .help = "class ap configuration",
};

static cmd_t cmd_class_ap_get_ssid = {
    .name = "getssid",
    .args = "IFNAME",
    .desc = "\tIFNAME       the wireless interface name",
    .handle = cmd_handle_ap_get_ssid,
    .help = "get SSID info with the AP interface",
};

static cmd_t cmd_class_ap_get_sta = {
    .name = "getsta",
    .args = "IFNAME",
    .desc = "\tIFNAME       the wireless interface name",
    .handle = cmd_handle_ap_get_sta,
    .help = "get station assoicate with the AP interface",
};

static cmd_t cmd_class_ap_add_ssid = {
    .name = "addssid",
    .args = "IFNAME SSID CHANNEL [ENCRYPTION PASSWORD] [HIDDEN]",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the SSID name to add\n"
        "\tCHANNLE      the radio channel 0 -- 13 of SSID to use, 0 means auto select\n"
        "\tENCRYPTION   the encryption method to use, open, wpa, wpa2, wap|wap2 are allowed,\n"
        "\t             if open, then password is ignored. and default is wpa2\n"
        "\tPASSWORD     the password to use, must more than 8 characters\n"
        "\tHIDDEN       not broadcast the SSID, default broadcast",
    .handle = cmd_handle_ap_add_ssid,
    .help = "add a SSID to ap configuration, the ssid is auto enabled",
};

static cmd_t cmd_class_ap_remove_ssid = {
    .name = "rmssid",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name",
    .handle = cmd_handle_ap_remove_ssid,
    .help = "remove the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_enable_ssid = {
    .name = "enssid",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name",
    .handle = cmd_handle_ap_enable_ssid,
    .help = "enable the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_disable_ssid = {
    .name = "dissid",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name",
    .handle = cmd_handle_ap_disable_ssid,
    .help = "disable the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_get_acl_mac = {
    .name = "getaclmac",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name",
    .handle = cmd_handle_ap_get_acl_mac,
    .help = "get acl mac list in the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_add_accept_mac = {
    .name = "addacceptmac",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name\n" "\tMAC          the mac address",
    .handle = cmd_handle_ap_add_accept_mac,
    .help = "add accept mac in the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_remove_accept_mac = {
    .name = "rmacceptmac",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name\n" "\tMAC          the mac address",
    .handle = cmd_handle_ap_rm_accept_mac,
    .help = "remove accept mac in the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_add_deny_mac = {
    .name = "adddenymac",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name\n" "\tMAC          the mac address",
    .handle = cmd_handle_ap_add_deny_mac,
    .help = "add deny mac in the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_remove_deny_mac = {
    .name = "rmdenymac",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name\n" "\tMAC          the mac address",
    .handle = cmd_handle_ap_rm_deny_mac,
    .help = "remove deny mac in the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_get_mac_acl = {
    .name = "getmacacl",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name",
    .handle = cmd_handle_ap_get_mac_acl,
    .help =
        "get the current mac acl mode in the ssid configurated on the interface",
};

static cmd_t cmd_class_ap_set_mac_acl = {
    .name = "setmacacl",
    .args = "IFNAME SSID",
    .desc = "\tIFNAME       the wireless interface name\n"
        "\tSSID         the ssid name\n"
        "\tMAC          the mac address\n"
        "\ttype         the type to set, valid below:\n"
        "\t                 disable to disable the acl\n"
        "\t                 accept  to enable the accept list\n"
        "\t                 deny    to enable the deny list",
    .handle = cmd_handle_ap_set_mac_acl,
    .help =
        "set the current mac acl mode in the ssid configurated on the interface",
};




/* ---------------- DHCP CLASS ---------------- */

static cmd_t cmd_class_dhcp = {
    .prompt = "dhcp> ",
    .name = "dhcp",
    .length = 4,
    .handle = cmd_handle_cli,
    .help = "class DHCP configuration",
};


static cmd_t cmd_class_dhcp_get_pool = {
    .name = "getpool",
    .handle = cmd_handle_dhcp_get_pool,
    .help = "get all DHCP pool configed",
};

static cmd_t cmd_class_dhcp_get_lease = {
    .name = "getlease",
    .handle = cmd_handle_dhcp_get_lease,
    .help = "get all DHCP lease info",
};



static cmd_t cmd_class_dhcp_add_pool = {
    .name = "addpool",
    .args =
        "[name NAME] [interface INTERFACE] START END [netmask NETMASK] [gateway GATEWAY] [primary-dns DNS] [secondary-dns DNS] [lease TIME]",
    .desc =
        "\tname NAME             the DHCP address pool name\n"
        "\tinterface INTERFACE   the interface of address pool to bind to\n"
        "\tSTART                 the start address\n"
        "\tEND                   the end address\n"
        "\tnetmask NETMASK       the netmask address\n"
        "\tgateway GATEWAY       the gateway address\n"
        "\tprimary-dns DNS       the primary dns server address\n"
        "\tsecondary-dns DNS     the secondary dns server address\n"
        "\tlease TIME            the DHCP lease time(in hour, default 24 hours)",
    .handle = cmd_handle_dhcp_add_pool,
    .help = "add a DHCP address pool",
};

static cmd_t cmd_class_dhcp_remove_pool = {
    .name = "rmpool",
    .args = "START END",
    .desc = "\tEND                   the end address\n"
        "\tnetmask NETMASK       the netmask address\n",
    .handle = cmd_handle_dhcp_remove_pool,
    .help = "remove a DHCP address pool",
};

static cmd_t cmd_class_dhcp_add_opt60 = {
    .name = "addopt60",
    .args = "IFNAME OPTION",
    .desc = "\tIFNAME                 the interface name\n"
        "\tOPTION                 the option 60 string\n",
    .handle = cmd_handle_dhcp_add_opt60,
    .help = "add option 60 to dhcp client",
};

static cmd_t cmd_class_dhcp_remove_opt60 = {
    .name = "rmopt60",
    .args = "IFNAME OPTION",
    .desc = "\tIFNAME                 the interface name\n",
    .handle = cmd_handle_dhcp_remove_opt60,
    .help = "remove option 60 from dhcp client",
};

static cmd_t cmd_class_dhcp_add_opt60_s = {
    .name = "addopt60_s",
    .args = "IFNAME OPTION",
    .desc = "\tIFNAME                 the interface name\n"
        "\tOPTION                 the option 60 string\n",
    .handle = cmd_handle_dhcp_add_opt60_s,
    .help = "add option 60_s to dhcp client",
};

static cmd_t cmd_class_dhcp_remove_opt60_s = {
    .name = "rmopt60_s",
    .args = "IFNAME OPTION",
    .desc = "\tIFNAME                 the interface name\n",
    .handle = cmd_handle_dhcp_remove_opt60_s,
    .help = "remove option 60_s from dhcp client",
};

/* CMD_DEFINE(cmd_name, const char *arguments_list, const char *arguments_description, const char *help_message) */
CMD_DEFINE(rmpoolname, 
    "NAME", 
    "\tNAME         the DHCP pool name\n", 
    "remove a DHCP pool by pool name")
{
   int ret;

    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;        
    }

   if ((ret = istc_dhcp_pool_remove_by_name(argv[0])) != 0) {
       printf("remove dhcp pool failed\n");
   }

    return 0;
}



/* ---------------- ROUTE CLASS ---------------- */

static cmd_t cmd_class_route = {
    .prompt = "route> ",
    .name = "route",
    .length = 5,
    .handle = cmd_handle_cli,
    .help = "class route configuration",
};


static cmd_t cmd_class_route_get_state = {
    .name = "getstate",
    .handle = cmd_handle_route_get_state,
    .help = "get route state info (enable or disable)",
};


static cmd_t cmd_class_route_set_state = {
    .name = "setstate",
    .args = " <enable | disable>",
    .desc = "\tenable                  enable the IP routing\n"
        "\tdisable                 disable the IP routing",
    .handle = cmd_handle_route_set_state,
    .help = "set route state (enable or disable)",
};

static cmd_t cmd_class_route_get_default = {
    .name = "getdefault",
    .handle = cmd_handle_route_get_default,
    .help = "get route default gateway",
};


static cmd_t cmd_class_route_set_default = {
    .name = "setdefault",
    .args = "IFNAME GATEWAY",
    .desc = "\tIFNAME                  the interface\n"
        "\tGATEWAY                 the gateway",
    .handle = cmd_handle_route_set_default,
    .help = "set route gateway",
};



/* ---------------- DNS CLASS ---------------- */

static cmd_t cmd_class_dns = {
    .prompt = "dns> ",
    .name = "dns",
    .length = 3,
    .handle = cmd_handle_cli,
    .help = "class DNS configuration",
};


static cmd_t cmd_class_dns_get_dns = {
    .name = "getdns",
    .handle = cmd_handle_dns_get_dns,
    .help = "get DNS server address",
};


static cmd_t cmd_class_dns_set_dns = {
    .name = "setdns",
    .args = "PRIMARY SECONDARY",
    .desc = "\tPRIMARY                 the primary DNS server address\n"
        "\tSECONDARY               the secondary DNS server address",
    .handle = cmd_handle_dns_set_dns,
    .help = "set DNS server address",
};


/* ---------------- PPPOE MISC ---------------- */

static cmd_t cmd_class_pppoe = {
    .prompt = "pppoe> ",
    .name = "pppoe",
    .length = 5,
    .handle = cmd_handle_cli,
    .help = "class PPPoE configuration",
};



static cmd_t cmd_class_pppoe_get_config = {
    .name = "getconfig",
    .args = "IFNAME",
    .desc = "\tIFNAME                   the interface ppp run on",
    .handle = cmd_handle_pppoe_get_config,
    .help = "get PPPoE configuration information: username and password",
};

static cmd_t cmd_class_pppoe_state = {
    .name = "state",
    .args = "IFNAME",
    .desc = "\tIFNAME                   the interface ppp run on",
    .handle = cmd_handle_pppoe_state,
    .help = "get PPPoE connection state",
};


static cmd_t cmd_class_pppoe_set_config = {
    .name = "setconfig",
    .args = "IFNAME USERNAME PASSWORD",
    .desc = "\tIFNAME                   the interface ppp run on\n"
        "\tUSERNAME      the PPPoE username\n"
        "\tPASSWORD      the PPPoE password",
    .handle = cmd_handle_pppoe_set_config,
    .help = "set PPPoE configuration information: username and password",
};

static cmd_t cmd_class_pppoe_connect = {
    .name = "connect",
    .args = "IFNAME",
    .desc = "\tIFNAME                   the interface ppp run on",
    .handle = cmd_handle_pppoe_connect,
    .help = "try to connect the PPPoE server with username and password",
};

static cmd_t cmd_class_pppoe_async_connect = {
    .name = "async-connect",
	.args = "IFNAME",
	.desc = "\tIFNAME                   the interface ppp run on",
	.handle = cmd_handle_pppoe_async_connect,
	.help = "try to async connect the PPPoE server with username and password",
};

static cmd_t cmd_class_pppoe_disconnect = {
    .name = "disconnect",
    .args = "IFNAME",
    .desc = "\tIFNAME                   the interface ppp run on",
    .handle = cmd_handle_pppoe_disconnect,
    .help = "disconnect from the PPPoE server",
};


/* ---------------- DNS MISC ---------------- */

static cmd_t cmd_class_misc = {
    .prompt = "misc> ",
    .name = "misc",
    .length = 4,
    .handle = cmd_handle_cli,
    .help = "class misc configuration",
};


static cmd_t cmd_class_misc_save_config = {
    .name = "saveconfig",
    .handle = cmd_handle_misc_save_config,
    .help = "save the running config",
};


static cmd_t cmd_class_misc_ping = {
    .name = "ping",
    .args = "HOST [count COUNT] [interval INTERVAL] [size SIZE] [ttl TTL] "
        "[timeout TIMEOUT] [fragment <enable|disable>] [interface INTERFACE] [srcip IP]",
    .desc = "\tHOST             the host name or IP to ping\n"
        "\tcount            total icmp echo request packets to send\n"
        "\tinterval         the interval between each ping packet\n"
        "\tsize             the icmp echo request packet payload size\n"
        "\tttl              the icmp echo request message IP ttl number\n"
        "\ttimeout          wait 'timeout' second to receive the ping response\n"
        "\tfragment         to enable or disable the IP fragment\n"
        "\tinterface        the source interface to send ping from\n"
        "\tsrcip            the src ip address to send ping from",
    .handle = cmd_handle_misc_ping,
    .help =
        "ping the host, the interface and srcip must not use at the same time",
};


static cmd_t cmd_class_misc_get_iflist = {
    .name = "getiflist",
    .handle = cmd_handle_misc_get_iflist,
    .help = "get all interface list",
};


static cmd_t cmd_class_misc_get_iftype = {
    .name = "getiftype",
    .args = "IFNAME",
    .desc = "\tIFNAME            the interface name",
    .handle = cmd_handle_misc_get_iftype,
    .help = "get interface type (wired or wireless)",
};

static cmd_t cmd_class_misc_get_if = {
    .name = "getif",
    .handle = cmd_handle_misc_get_if,
    .help = "get all interface list and each type",
};


static cmd_t cmd_class_misc_get_log_lv = {
    .name = "getloglv",
    .handle = cmd_handle_misc_get_log_lv,
    .help = "get istcd log level",
};

static cmd_t cmd_class_misc_set_log_lv = {
    .name = "setloglv",
    .args = "LEVEL",
    .desc = "LEVEL                int log level (integer)",
    .handle = cmd_handle_misc_set_log_lv,
    .help = "set istcd log level",
};


static cmd_t cmd_class_misc_async_sta_connect = {
    .name = "asyncstaconn",
    .args = "IFNAME SSID PASSWORD ENCRYPTION",
    .desc = "IFNAME                the interface name\n"
            "SSID                  the SSID NAME\n"
            "PASSWORD              the password\n"
            "ENCRYPTION            the encryption, e.g. WPA WPA2",
    .handle = cmd_handle_misc_async_sta_connect,
    .help = "use async to connect a ssid",
};

static cmd_t cmd_class_misc_async_sta_disconnect = {
    .name = "asyncstasdisc",
    .args = "IFNAME SSID",
    .desc = "IFNAME                the interface name\n"
            "SSID                  the SSID NAME",
    .handle = cmd_handle_misc_async_sta_disconnect,
    .help = "use async to disconnect a ssid",
};

static cmd_t cmd_class_misc_async_ap_start = {
    .name = "asyncsapstart",
    .args = "IFNAME SSID PASSWORD ENCRYPTION CHANNEL",
    .desc = "IFNAME                the interface name\n"
            "SSID                  the SSID NAME\n"
            "PASSWORD              the password\n"
            "ENCRYPTION            the encryption type, e.g. WPA WPA2 OPEN"
            "CHANNEL               the channel to use, e.g. 11",
    .handle = cmd_handle_misc_async_ap_start,
    .help = "use async to start a ap ssid",
};

static cmd_t cmd_class_misc_async_ap_stop = {
    .name = "asyncsapstop",
    .args = "IFNAME SSID PASSWORD ENCRYPTION CHANNEL",
    .desc = "IFNAME                the interface name\n"
            "SSID                  the SSID NAME",
    .handle = cmd_handle_misc_async_ap_stop,
    .help = "use async to stop a ap ssid",
};

static cmd_t cmd_class_misc_async_ping = {
    .name = "asyncping",
    .args = "HOST [count COUNT] [interval INTERVAL] [size SIZE] [ttl TTL] "
        "[timeout TIMEOUT] [fragment <enable|disable>] [interface INTERFACE] [srcip IP]",
    .desc = "\tHOST             the host name or IP to ping\n"
        "\tcount            total icmp echo request packets to send\n"
        "\tinterval         the interval between each ping packet\n"
        "\tsize             the icmp echo request packet payload size\n"
        "\tttl              the icmp echo request message IP ttl number\n"
        "\ttimeout          wait 'timeout' second to receive the ping response\n"
        "\tfragment         to enable or disable the IP fragment\n"
        "\tinterface        the source interface to send ping from\n"
        "\tsrcip            the src ip address to send ping from",
    .handle = cmd_handle_misc_async_ping,
    .help =
        "ping the host, the interface and srcip must not use at the same time",
};

static cmd_t cmd_class_misc_async_sta_scan = {
    .name = "asyncstascan",
    .args = "IFNAME            the interface to scan by",
    .handle = cmd_handle_misc_async_sta_scan,
    .help = "scan the SSID",
};



/* ---------------- QOS ---------------- */

static cmd_t cmd_class_qos = {
    .prompt = "qos> ",
	.name = "qos",
	.length = 3,
	.handle = cmd_handle_cli,
	.help = "class qos configuration",
};


static cmd_t cmd_class_qos_set_mode = {
    .name = "setmode",
	.args = "MODE",
	.desc = "\tMODE                 1:disable 2:enable",
	.handle = cmd_handle_qos_set_mode,
	.help = "set mode",
};

static cmd_t cmd_class_qos_get_mode = {
    .name = "getmode",
	.handle = cmd_handle_qos_get_mode,
	.help = "get mode",
};

static cmd_t cmd_class_qos_set_device_bandwidth = {
    .name = "set_device_bandwidth",
	.args = "MAC DOWNLOAD UPLOAD",
	.desc = "\tMAC						device mac\n"
			"\tDOWNLOAD					download ceil kbyte\n"
			"\tUPLOAD					upload ceil kbyte",
	.handle = cmd_handle_qos_set_device_bandwidth,
	.help = "set device bandwidth",
};

static cmd_t cmd_class_qos_get_device_bandwidth = {
    .name = "get_device_bandwidth",
	.handle = cmd_handle_qos_get_device_bandwidth,
	.help = "get device bandwidth",
};

static cmd_t cmd_class_qos_get_device_bandwidth_list = {
    .name = "get_device_bandwidth_list",
	.handle = cmd_handle_qos_get_device_bandwidth_list,
	.help = "get device bandwidth list",
};


/* ---------------- LAN ---------------- */

static cmd_t cmd_class_lan = {
    .prompt = "lan> ",
	.name = "lan",
	.length = 3,
	.handle = cmd_handle_cli,
	.help = "class lan configuration",
};

static cmd_t cmd_class_lan_set_addr_info = {
    .name = "set_addr_info",
	.args = "GATEWAY START END",
	.handle = cmd_handle_lan_set_addr_info,
	.help = "set addr info",
};

static cmd_t cmd_class_lan_get_addr_info = {
    .name = "get_addr_info",
	.handle = cmd_handle_lan_get_addr_info,
	.help = "get addr info",
};




/* signal handler */
void cmd_signal_handler(int signo)
{
    int jmpno = CMD_SIGNAL;
    printf("Receive signal %d\n", signo);

    longjmp(env, jmpno);
}










int read_args(char *prompt, int *argc, char **argv);


#define ISTC_LINE_SIZE		1024

static char *read_line(const char *prompt, FILE * fp)
{
    char buff[ISTC_LINE_SIZE];
    char *ptr = NULL;
    char *line = NULL;
    int len;

    fflush(NULL);

    if (prompt) {
        printf("%s", prompt);
        fflush(NULL);
    }

    ptr = fgets(buff, sizeof (buff), fp);
    if (ptr) {
        len = strlen(ptr);
        if ((line = malloc(len + 1)) == NULL) {
            fprintf(stderr, "malloc failed\n");
            return NULL;
        }
        strncpy(line, buff, len + 1);
    }

    fflush(NULL);

    return line;
}


int read_args_std(char *prompt, int *argc, char **argv)
{
    char *line = read_line(prompt, stdin);
    int len;
    int ac = 0;

    if (!line) {
        return -1;
    }

    len = strlen(line);

    //printf("line = [%s]\n", line);

    char *ptr;
    char *start;
    char *end;
    char *last = line + len;

    ptr = line;
    /* ignore space at head */
    while ((ptr < last) && (*ptr == ' ' || *ptr == '\t'))
        ptr++;

    while ((ptr < last && *ptr != '\n') && ac < CMD_ARGC_MAX) {
        start = ptr;
        while ((ptr < last && *ptr != '\n') && (*ptr != ' ' && *ptr != '\t'))
            ptr++;

        /* got one arg */
        end = ptr++;
        *end = '\0';
        strncpy(argv[ac++], start, CMD_ARGV_LEN);

        /* ingore space */
        while ((ptr < last) && (*ptr == ' ' || *ptr == '\t'))
            ptr++;
    }

    *argc = ac;

    free(line);


    return 0;
}

cmd_t *cmd_match(cmd_t * this, char *name)
{
    //printf("name = [%s], this = %s\n", name, this->name);

    cmd_t *child = this->child;
    if (!child) {
        return NULL;
    }

    int length = strlen(name);
    //printf("child->name = [%s]\n", child->name);
    if (child->length == length && strncmp(name, child->name, length) == 0) {
        return child;
    }

    cmd_t *ptr = child->next;
    while (ptr != child) {
        //printf("child->name = [%s]\n", ptr->name);
        if (ptr->length == length && strncmp(name, ptr->name, length) == 0) {
            return ptr;
        }
        ptr = ptr->next;
    }

    return NULL;
}

/* this function is a recursion function */
int cmd_handle_cli(cmd_t * this, int argc, char **argv)
{
    int ret = -1;
    cmd_t *cmd;
    char *prompt = this->prompt;

    while (1) {
        ret = read_args_func(prompt, &argc, argv);
        if (ret == -1) {
            //printf("read_args failed\n");
            return -1;
        }

        if (argc <= 0) {
            continue;
        }

        cmd = cmd_match(this, argv[0]);
        if (cmd == NULL) {
            printf("@@@unknown command %s\n", argv[0]);
            continue;
        }

        ret = cmd->handle(cmd, argc - 1, argv + 1);
        if (ret == CMD_QUIT) {
            /* quit */
            return 0;
        } else if (ret == CMD_EXIT) {
            int val = CMD_EXIT;
            printf("start jump %d\n", val);
            longjmp(env, val);
            //exit(0);
        }

    }

    return 0;
}

int cmd_handle_quit(cmd_t * this, int argc, char **argv)
{
    this = this;
    argc = argc;
    argv = argv;

    return CMD_QUIT;
}

int cmd_handle_exit(cmd_t * this, int argc, char **argv)
{
    this = this;
    argc = argc;
    argv = argv;

    return CMD_EXIT;
}


int cmd_handle_ip_get_addr(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    unsigned int addr;

    if (istc_interface_ipaddr_get(argv[0], &addr) != 0) {
        printf("get interface %s addr failed\n", argv[0]);
        return -1;
    }

    addr = ntohl(addr);

    printf("interface %s addr is %s\n", argv[0],
           inet_ntoa(*(struct in_addr *) &addr));

    return 0;
}


int cmd_handle_ip_set_addr(cmd_t * this, int argc, char **argv)
{
    unsigned int addr;

    if (argc != 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (inet_aton(argv[1], (struct in_addr *) &addr) == 0) {
        printf("IP address %s format is invalid\n", argv[1]);
        return -1;
    }

    addr = ntohl(addr);

    if (istc_interface_ipaddr_set(argv[0], addr) != 0) {
        printf("set interface %s addr failed\n", argv[0]);
        return -1;
    }

    return 0;
}


int cmd_handle_ip_get_mask(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    unsigned int addr;

    if (istc_interface_netmask_get(argv[0], &addr) != 0) {
        printf("get interface %s addr failed\n", argv[0]);
        return -1;
    }

    addr = ntohl(addr);

    printf("interface %s netmask is %s\n", argv[0],
           inet_ntoa(*(struct in_addr *) &addr));

    return 0;
}


int cmd_handle_ip_set_mask(cmd_t * this, int argc, char **argv)
{
    unsigned int addr;

    if (argc != 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (inet_aton(argv[1], (struct in_addr *) &addr) == 0) {
        printf("netmask address %s format is invalid\n", argv[1]);
        return -1;
    }

    addr = ntohl(addr);

    if (istc_interface_netmask_set(argv[0], addr) != 0) {
        printf("set interface %s netmask failed\n", argv[0]);
        return -1;
    }

    return 0;
}


int cmd_handle_ip_get_addr_mode(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    int mode;

    if (istc_interface_addr_mode_get(argv[0], &mode) != 0) {
        printf("get interface %s address alloc mode failed\n", argv[0]);
        return -1;
    }

    char *str;

    if (mode == ISTC_INTERFACE_ADDR_MODE_STATIC) {
        str = "static";
    } else if (mode == ISTC_INTERFACE_ADDR_MODE_DHCP) {
        str = "dhcp";
    } else if (mode == ISTC_INTERFACE_ADDR_MODE_PPPOE) {
        str = "pppoe";
    } else {
        str = "unknown";
    }

    printf("interface %s address alloc mode is %s\n", argv[0], str);

    return 0;
}


int cmd_handle_ip_set_addr_mode(cmd_t * this, int argc, char **argv)
{
    unsigned int mode;
    int len;

    if (argc != 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    len = strlen(argv[1]);

    if (len == 6 && strncmp(argv[1], "static", len) == 0) {
        mode = ISTC_INTERFACE_ADDR_MODE_STATIC;
    } else if (len == 4 && strncmp(argv[1], "dhcp", len) == 0) {
        mode = ISTC_INTERFACE_ADDR_MODE_DHCP;
    } else if (len == 5 && strncmp(argv[1], "pppoe", len) == 0) {
        mode = ISTC_INTERFACE_ADDR_MODE_PPPOE;
    }else if(len == 3 && strncmp(argv[1], "lan", len) == 0){
        mode = ISTC_INTERFACE_ADDR_MODE_LAN;
    }else {
        printf("unknown IP address alloc mode %s\n", argv[1]);
        return -1;
    }

    if (istc_interface_addr_mode_set(argv[0], mode) != 0) {
        printf("set interface %s netmask failed\n", argv[0]);
        return -1;
    }

    return 0;
}



int cmd_handle_mac_get_mac(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    unsigned char mac[8] = { 0 };

    if (istc_interface_mac_get(argv[0], mac) != 0) {
        printf("get interface %s mac failed\n", argv[0]);
        return -1;
    }

    printf("interface %s mac is %02x:%02x:%02x:%02x:%02x:%02x\n", argv[0],
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return 0;
}

static int cmd_str2mac(const char *str, unsigned char *mac)
{
    char buff[24] = { 0 };
    char *end;
    int ret;

    strncpy(buff, str, 24);

    if (buff[2] == buff[5] &&
        buff[2] == buff[8] && buff[2] == buff[11] && buff[2] == buff[14]) {
        if (buff[2] != ':' && buff[2] != '-') {
            //printf("mac string error format\n");
            return -1;
        }
    }

    int i;
    for (i = 0; i <= 15; i += 3) {
        ret = strtol(buff + i, &end, 16);
        if (end == buff + i) {
            return -1;
        }
        if (ret < 0 || ret > 255) {
            return -1;
        }

        *mac++ = (unsigned char) ret;
    }


    return 0;
}

int cmd_handle_mac_set_mac(cmd_t * this, int argc, char **argv)
{
    if (argc != 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    unsigned char mac[8] = { 0 };

    if (cmd_str2mac(argv[1], mac) != 0) {
        printf("mac string %s format error\n", argv[1]);
        return -1;
    }

    if (istc_interface_mac_set(argv[0], mac) != 0) {
        printf("set interface %s mac failed\n", argv[0]);
        return -1;
    }

    return 0;
}



int cmd_handle_link_get_state(cmd_t * this, int argc, char **argv)
{
    int state;

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_link_state_get(argv[0], &state) != 0) {
        printf("get interface %s state failed\n", argv[0]);
        return -1;
    }

    if (state == ISTC_LINK_STATE_UP) {
        printf("interface %s link is UP\n", argv[0]);
        return 0;
    } else if (state == ISTC_LINK_STATE_DOWN) {
        printf("interface %s link is DOWN\n", argv[0]);
    } else {
        printf("interface %s link is unknown\n", argv[0]);
    }

    return 0;
}

int cmd_handle_link_get_admin(cmd_t * this, int argc, char **argv)
{
    int state;

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_link_admin_state_get(argv[0], &state) != 0) {
        printf("get interface %s admin state failed\n", argv[0]);
        return -1;
    }

    if (state == ISTC_LINK_ADMIN_STATE_UP) {
        printf("interface %s admin is UP\n", argv[0]);
        return 0;
    } else if (state == ISTC_LINK_ADMIN_STATE_DOWN) {
        printf("interface %s admin is DOWN\n", argv[0]);
    } else {
        printf("interface %s admin is unknown\n", argv[0]);
    }

    return 0;
}


int cmd_handle_link_get_mtu(cmd_t * this, int argc, char **argv)
{
    int mtu;

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_link_mtu_get(argv[0], &mtu) != 0) {
        printf("get interface %s mtu failed\n", argv[0]);
        return -1;
    }

    printf("interface MTU is %d\n", mtu);

    return 0;
}


int cmd_handle_link_set_admin(cmd_t * this, int argc, char **argv)
{
    int state;
    int len;

    if (argc != 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    len = strlen(argv[1]);
    if (len == 2
        && (strncmp(argv[1], "up", 2) == 0 || strncmp(argv[1], "UP", 2) == 0)) {
        state = ISTC_LINK_ADMIN_STATE_UP;
    } else if (len == 4
               && (strncmp(argv[1], "down", 4) == 0
                   || strncmp(argv[1], "DOWN", 4) == 0)) {
        state = ISTC_LINK_ADMIN_STATE_DOWN;
    } else {
        printf("admin state %s is invalid\n", argv[1]);
        return -1;
    }

    if (istc_link_admin_state_set(argv[0], state) != 0) {
        printf("get interface %s admin state failed\n", argv[0]);
        return -1;
    }

    return 0;
}




int cmd_handle_help(cmd_t * this, int argc, char **argv)
{

    argc = argc;
    argv = argv;

    printf("Command Format : %s %s\n", this->name,
           (this->args ? this->args : ""));
    printf("Descriptions   : %s", this->help);
    if (this->desc) {
        printf(", argument(s) description :\n");
        printf
            ("------------------------------------------------------------------------\n");
        printf("%s", this->desc);
    }

    printf("\n");

    return 0;
}

int cmd_handle_list(cmd_t * this, int argc, char **argv)
{
    this = this->parent;

    cmd_t *cmd = this->child;

    printf("all avaiable command(s) list below:\n");
    printf
        ("-------- ----------------------------------------------------------\n");
    if (cmd) {
        printf("%-12s %s\n", cmd->name, cmd->help);
    }

    cmd = cmd->next;
    while (cmd != this->child) {
        printf("%-12s %s\n", cmd->name, cmd->help);
        cmd = cmd->next;
    }

    return 0;
}

int cmd_handle_sleep(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    int time = atoi(argv[0]);
    sleep(time);

    return 0;
}


int cmd_handle_sta_scan(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_wireless_sta_ssid_scan(argv[0]) != 0) {
        printf("istc_wireless_sta_ssid_scan %s failed\n", argv[0]);
        return -1;
    }

    printf("interface %s start scanning, please wait...\n", argv[0]);

    return 0;
}



int cmd_handle_sta_state(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    int state;
    istc_sta_ssid_t ssid;
    if (istc_wireless_sta_state_get(argv[0], &state, &ssid) != 0) {
        printf("istc_wireless_sta_state_get %s failed\n", argv[0]);
        return -1;
    }

    char *ptr;
    int show_ssid = 0;
    switch (state) {
        case ISTC_WIRELESS_STA_STATE_INACTIVE:
            ptr = "inactive";
            break;
        case ISTC_WIRELESS_STA_STATE_SCANNING:
            ptr = "scanning";
            break;
        case ISTC_WIRELESS_STA_STATE_CONNECTING:
            ptr = "connecting";
            show_ssid = 1;
            break;
        case ISTC_WIRELESS_STA_STATE_CONNECTED:
            ptr = "connected";
            show_ssid = 1;
            break;
        case ISTC_WIRELESS_STA_STATE_DISCONNECTED:
            ptr = "disconnected";
            break;
        case ISTC_WIRELESS_STA_STATE_DISABLED:
            ptr = "interface disabled";
            break;
        default:
            ptr = "unknown";
            break;
    }
    printf("interface %s state = %s\n", argv[0], ptr);

    if (show_ssid == 1) {
        char *encry;
        if (ssid.encryption == ISTC_WIRELESS_ENCRYPTION_OPEN) {
            encry = "OPEN";
        } else if (ssid.encryption == ISTC_WIRELESS_ENCRYPTION_WPA) {
            encry = "WPA";
        } else if (ssid.encryption == ISTC_WIRELESS_ENCRYPTION_WPA2) {
            encry = "WPA2";
        } else if (ssid.encryption == ISTC_WIRELESS_ENCRYPTION_WPA_WPA2) {
            encry = "WPA | WPA2";
        } else {
            encry = "???";
        }

        printf("SSID         : %s\n", ssid.ssid);
        printf("BSSID        : %s\n", ssid.mac);
        printf("Channel      : %d\n", ssid.channel);
        printf("RSSI         : %d dbm\n", ssid.signal);
        printf("encryption   : %s\n", encry);
    }

    return 0;
}


int cmd_handle_sta_get_scan_result(cmd_t * this, int argc, char **argv)
{
    istc_sta_ssid_t ssidlist[32];
    int cnt = 32;
    int i;
    char ssid[32];
    char *encry;


    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_wireless_sta_scan_result_get(argv[0], ssidlist, &cnt) != 0) {
        printf("istc_wireless_sta_ssid_get %s failed\n", argv[0]);
        return -1;
    }



    printf("%3s  %-32s  %-17s  %-4s  %-4s  %s\n", "idx", "SSID", "MAC", "chnl",
           "sgnl", "encryption");
    printf
        ("---  --------------------------------  -----------------  ----  ----  ----------\n");
    for (i = 0; i < cnt; i++) {
        if (ssidlist[i].ssid[0]) {
            int len = strlen(ssidlist[i].ssid);
            if (len >= 31) {
                memcpy(ssid, ssidlist[i].ssid, 28);
                strcpy(ssid + 28, "...");
            } else {
                strncpy(ssid, ssidlist[i].ssid, 32);
            }

        } else {
            strcpy(ssid, " ");
        }

        if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_OPEN) {
            encry = "OPEN";
        } else if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA) {
            encry = "WPA";
        } else if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA2) {
            encry = "WPA2";
        } else if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA_WPA2) {
            encry = "WPA | WPA2";
        } else {
            encry = "???";
        }

        printf("%3d  %-32s  %-17s  %-4d  %-4d  %s\n",
               (i + 1),
               ssid,
               ssidlist[i].mac, ssidlist[i].channel, ssidlist[i].signal, encry);

    }

#if 0
    int j;
    printf
        ("    0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f\n");
    for (i = 0; i < cnt; i++) {
        //if (! isprint(ssidlist[i].ssid[0])) {
        printf("%02d ", i + 1);
        for (j = 0; j < 32; j++) {
            printf("%02x ", ((unsigned char) (ssidlist[i].ssid[j])) & 0xff);
        }
        printf("\n");
        //}
    }
#endif

    return 0;
}

int cmd_handle_sta_add_ssid(cmd_t * this, int argc, char **argv)
{
    char *ssid = NULL;
    char *password = NULL;

    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    ssid = argv[1];
    if (argc > 2) {
        password = argv[2];
    }
    //printf("ssid = %s, password = %s\n", ssid, (password ? password : "null"));

    if (istc_wireless_sta_ssid_add(argv[0], ssid, password) != 0) {
        printf("istc_wireless_sta_ssid_add %s ssid %s failed\n", argv[0], ssid);
        return -1;
    }

    return 0;
}

int cmd_handle_sta_add2_ssid(cmd_t * this, int argc, char **argv)
{
    char *ssid = NULL;
    char *password = NULL;
    char *encry = NULL;
    int encryption = -1;

    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    ssid = argv[1];
    encry = argv[2];

    if (strcmp(encry, "WPA") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_WPA;
    } else if (strcmp(encry, "WPA2") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_WPA2;
    } else if (strcmp(encry, "WPAWPA2") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_WPA_WPA2;
    } else if (strcmp(encry, "OPEN") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_OPEN;
    } else {
        printf("not support encryption : %s\n", encry);
        return -1;
    }

    if (argc > 3) {
        password = argv[3];
    }
    //printf("ssid = %s, password = %s\n", ssid, (password ? password : "null"));

    if (istc_wireless_sta_ssid_add2(argv[0], ssid, password, encryption) != 0) {
        printf("istc_wireless_sta_ssid_add2 %s ssid %s failed\n", argv[0],
               ssid);
        return -1;
    }

    return 0;
}


int cmd_handle_sta_remove_ssid(cmd_t * this, int argc, char **argv)
{
    char *ssid = NULL;

    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    ssid = argv[1];

    if (istc_wireless_sta_ssid_remove(argv[0], ssid) != 0) {
        printf("istc_wireless_sta_ssid_remove %s ssid %s failed\n", argv[0],
               ssid);
        return -1;
    }

    return 0;
}


int cmd_handle_sta_enable_ssid(cmd_t * this, int argc, char **argv)
{
    char *ssid = NULL;

    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    ssid = argv[1];

    if (istc_wireless_sta_ssid_enable(argv[0], ssid) != 0) {
        printf("istc_wireless_sta_ssid_enable %s ssid %s failed\n", argv[0],
               ssid);
        return -1;
    }

    return 0;
}

int cmd_handle_sta_disable_ssid(cmd_t * this, int argc, char **argv)
{
    char *ssid = NULL;

    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    ssid = argv[1];

    if (istc_wireless_sta_ssid_disable(argv[0], ssid) != 0) {
        printf("istc_wireless_sta_ssid_disable %s ssid %s failed\n", argv[0],
               ssid);
        return -1;
    }

    return 0;
}

/* ----------------------- AP CLASS------------------------- */

int cmd_handle_ap_get_ssid(cmd_t * this, int argc, char **argv)
{
    istc_ap_ssid_t ssid[ISTC_AP_SSID_LIST_MAX];
    int count = ISTC_AP_SSID_LIST_MAX;
    char *encryption;

    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_wireless_ap_ssid_get(argv[0], ssid, &count) != 0) {
        printf("istc_wireless_ap_ssid_get %s failed\n", argv[0]);
        return -1;
    }
    

    int i;
    printf("interface %s configurated SSID list (count %d):\n", argv[0], count);
    if (count <= 0) {
        return 0;
    }

    printf("%3s %-32s %-9s %-4s %s\n", "idx", "SSID", "encyption", "chnl",
           "flag");
    printf
        ("--- -------------------------------- --------- ---- -------------------\n");
    for (i = 0; i < count; i++) {
        if (ssid[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA) {
            encryption = "wpa";
        } else if (ssid[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA2) {
            encryption = "wpa2";
        } else if (ssid[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA_WPA2) {
            encryption = "wpa|wpa2";
        } else if (ssid[i].encryption == ISTC_WIRELESS_ENCRYPTION_OPEN) {
            encryption = "open";
        } else if (ssid[i].encryption == ISTC_WIRELESS_ENCRYPTION_WEP) {
            encryption = "wep";
        } else {
            encryption = "?";
        }

        printf("%-3d %-32s %-9s %-4d ",
               (i + 1), ssid[i].ssid, encryption, ssid[i].channel);

        if (1 == ssid[i].b_hidden) {
            printf("hidden ");
        }
        printf("\n");
    }

    return 0;

}

/* IFNAME SSID */
int cmd_handle_ap_get_sta(cmd_t * this, int argc, char **argv)
{
    istc_ap_sta_t list[128];
    int i;
    int cnt = 128;
    unsigned char *m;

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    memset(list, 0, sizeof (list));

    if (istc_wireless_ap_ssid_sta_get(argv[0], argv[1], list, &cnt) != 0) {
        printf("get interface %s SSID %s station failed\n", argv[0], argv[1]);
        return -1;
    }

    printf("All Station associate on interface %s SSID %s ", argv[0], argv[1]);

    if (cnt == 0) {
        printf("(total 0)\n");
        return 0;
    }

    printf("(total %d) :\n", cnt);
    printf("%3s %-32s %-16s %-18s\n", "idx", "Name", "IP", "MAC");
    printf
        ("--- -------------------------------- ---------------- ------------------\n");
    for (i = 0; i < cnt; i++) {
        m = list[i].sta_mac;
        printf("%3d %-32s %-16s %02x:%02x:%02x:%02x:%02x:%02x\n",
               (i + 1),
               list[i].sta_name,
               cmd_htoa(list[i].sta_ip), m[0], m[1], m[2], m[3], m[4], m[5]);
    }

    return 0;
}


/* IFNAME SSID CHANNEL [ENCRYPTION PASSWORD] [HIDDEN] */
int cmd_handle_ap_add_ssid(cmd_t * this, int argc, char **argv)
{
    int len;
    istc_ap_ssid_t ssid;

    if (argc < 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    memset(&ssid, 0, sizeof (istc_ap_ssid_t));

    /* parse cmdline args */
    strncpy(ssid.ssid, argv[1], ISTC_SSID_NAME_SIZE);
    ssid.channel = atoi(argv[2]);
    if (ssid.channel < 0 || ssid.channel > 13) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (argc >= 4) {
        /* get encryption */
        len = strlen(argv[3]);
        if (len == 4 && strncmp(argv[3], "open", 4) == 0) {
            printf("pass\n");
            ssid.encryption = ISTC_WIRELESS_ENCRYPTION_OPEN;
        } else if (len == 3 && strncmp(argv[3], "wpa", 3) == 0) {
            ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA;
        } else if (len == 4 && strncmp(argv[3], "wpa2", 4) == 0) {
            ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA2;
        } else if (len == 8 && strncmp(argv[3], "wpa|wpa2", 8) == 0) {
            ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA_WPA2;
        } else {
            cmd_handle_help(this, argc, argv);
            return -1;
        }
    }

    if (ssid.encryption != ISTC_WIRELESS_ENCRYPTION_OPEN) {
        /* check password */
        if (argc >= 5) {
            len = strlen(argv[4]);
            if (len < 8) {
                printf("password %s format error!\n", argv[4]);
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            strncpy(ssid.password, argv[4], ISTC_SSID_PSWD_SIZE);
        }

        if (argc >= 6) {
            len = strlen(argv[5]);
            if (len == 6 && strncmp(argv[5], "hidden", 6) == 0) {
                ssid.b_hidden = 1;
            } else {
                printf("flag %s format error\n", argv[5]);
                cmd_handle_help(this, argc, argv);
                return -1;
            }
        }
    } else {
        ssid.password[0] = '\0';    /* ignore password */
        if (argc >= 5) {
            len = strlen(argv[4]);
            if (len == 6 && strncmp(argv[4], "hidden", 6) == 0) {
                ssid.b_hidden = 1;
            } else {
                printf("flag %s format error\n", argv[4]);
                cmd_handle_help(this, argc, argv);
                return -1;
            }
        }
    }

    printf("ssid name : [%s]\n", ssid.ssid);
    printf("ssid password : [%s]\n", ssid.password);
    printf("ssid encryption : %d\n", ssid.encryption);
    printf("ssid channel : %d\n", ssid.channel);
    printf("ssid b_hidden : %u\n", ssid.b_hidden);

    if (istc_wireless_ap_ssid_add(argv[0], &ssid) != 0) {
        printf("istc_wireless_ap_ssid_add %s ssid %s failed\n", argv[0],
               ssid.ssid);
        return -1;
    }

    return 0;
}


int cmd_handle_ap_remove_ssid(cmd_t * this, int argc, char **argv)
{
    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_wireless_ap_ssid_remove(argv[0], argv[1]) != 0) {
        printf("istc_wireless_ap_ssid_remove ssid %s on interface %s failed\n",
               argv[1], argv[0]);
        return -1;
    }

    return 0;
}

int cmd_handle_ap_enable_ssid(cmd_t * this, int argc, char **argv)
{
    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if(istc_wireless_ap_ssid_enable(argv[0], argv[1]) != 0)
    {
        printf("istc_wireless_ap_ssid_enable ssid %s on interface %s failed\n", argv[1], argv[0]);
        return -1;
    }
    return 0;
}

int cmd_handle_ap_disable_ssid(cmd_t * this, int argc, char **argv)
{
    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if(istc_wireless_ap_ssid_disable(argv[0], argv[1]) != 0)
    {
        printf("istc_wireless_ap_ssid_disable ssid %s on interface %s failed\n", argv[1], argv[0]);
        return -1;
    }
    return 0;
}

int cmd_handle_ap_get_acl_mac(cmd_t * this, int argc, char **argv)
{
    unsigned char list1[ISTC_WIRELESS_MAC_ACCEPT_MAX][6];
    int count1 = ISTC_WIRELESS_MAC_ACCEPT_MAX;
    unsigned char list2[ISTC_WIRELESS_MAC_DENY_MAX][6];
    int count2 = ISTC_WIRELESS_MAC_DENY_MAX;
    int i;
    unsigned char *m;

    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_wireless_ap_ssid_mac_accept_get(argv[0], argv[1], list1, &count1)
        != 0) {
        count1 = 0;
    }

    if (istc_wireless_ap_ssid_mac_deny_get(argv[0], argv[1], list2, &count2) !=
        0) {
        count2 = 0;
    }

    if ((count1 + count2) > 0) {
        printf("%-17s  %-s\n", "MAC Address", "Type");
        printf("-----------------  -------\n");
    } else {
        printf("AP ACL MAC Address is not configed\n");
    }

    for (i = 0; i < count1; i++) {
        m = list1[i];
        printf("%02x:%02x:%02x:%02x:%02x:%02x  Accept\n",
               m[0], m[1], m[2], m[3], m[4], m[5]);
    }

    for (i = 0; i < count2; i++) {
        m = list2[i];
        printf("%02x:%02x:%02x:%02x:%02x:%02x  Deny\n",
               m[0], m[1], m[2], m[3], m[4], m[5]);
    }

    return 0;
}



int cmd_handle_ap_add_accept_mac(cmd_t * this, int argc, char **argv)
{
    unsigned char mac[6] = { 0 };

    if (argc < 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (cmd_str2mac(argv[2], mac) != 0) {
        printf
            ("mac format error, need xx:xx:xx:xx:xx:xx (xx is 0-9 a-f A-F)\n");
        return -1;
    }

    if (istc_wireless_ap_ssid_mac_accept_add(argv[0], argv[1], mac) != 0) {
        printf("add accept mac failed\n");
        return -1;
    }

    return 0;
}

int cmd_handle_ap_rm_accept_mac(cmd_t * this, int argc, char **argv)
{
    unsigned char mac[6] = { 0 };

    if (argc < 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (cmd_str2mac(argv[2], mac) != 0) {
        printf
            ("mac format error, need xx:xx:xx:xx:xx:xx (xx is 0-9 a-f A-F)\n");
        return -1;
    }

    if (istc_wireless_ap_ssid_mac_accept_remove(argv[0], argv[1], mac) != 0) {
        printf("remove accept mac failed\n");
        return -1;
    }

    return 0;
}

int cmd_handle_ap_add_deny_mac(cmd_t * this, int argc, char **argv)
{
    unsigned char mac[6] = { 0 };

    if (argc < 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (cmd_str2mac(argv[2], mac) != 0) {
        printf
            ("mac format error, need xx:xx:xx:xx:xx:xx (xx is 0-9 a-f A-F)\n");
        return -1;
    }

    if (istc_wireless_ap_ssid_mac_deny_add(argv[0], argv[1], mac) != 0) {
        printf("add deny mac failed\n");
        return -1;
    }

    return 0;
}

int cmd_handle_ap_rm_deny_mac(cmd_t * this, int argc, char **argv)
{
    unsigned char mac[6] = { 0 };

    if (argc < 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (cmd_str2mac(argv[2], mac) != 0) {
        printf
            ("mac format error, need xx:xx:xx:xx:xx:xx (xx is 0-9 a-f A-F)\n");
        return -1;
    }

    if (istc_wireless_ap_ssid_mac_deny_remove(argv[0], argv[1], mac) != 0) {
        printf("remove deny mac failed\n");
        return -1;
    }

    return 0;
}


int cmd_handle_ap_get_mac_acl(cmd_t * this, int argc, char **argv)
{
    int mode;

    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_wireless_ap_ssid_mac_acl_get(argv[0], argv[1], &mode) != 0) {
        printf("get ap mac acl mode failed\n");
        return -1;
    }

    printf("AP MAC ACL mode is : ");
    if (mode == ISTC_ACL_MAC_MODE_ACCEPT) {
        printf("accept\n");
    } else if (mode == ISTC_ACL_MAC_MODE_DENY) {
        printf("deny\n");
    } else if (mode == ISTC_ACL_MAC_MODE_DISABLE) {
        printf("disable\n");
    } else {
        printf("unknown\n");
    }

    return 0;
}

int cmd_handle_ap_set_mac_acl(cmd_t * this, int argc, char **argv)
{
    int mode = 0;
    int len;

    if (argc < 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    len = strlen(argv[2]);
    if (len == 6 && strcmp(argv[2], "accept") == 0) {
        mode = ISTC_ACL_MAC_MODE_ACCEPT;
    } else if (len == 4 && strcmp(argv[2], "deny") == 0) {
        mode = ISTC_ACL_MAC_MODE_DENY;
    } else if (len == 7 && strcmp(argv[2], "disable") == 0) {
        mode = ISTC_ACL_MAC_MODE_DISABLE;
    } else {
        printf("type is invalid, must be accept, deny or disable\n");
    }

    if (istc_wireless_ap_ssid_mac_acl_set(argv[0], argv[1], mode) != 0) {
        printf("set ap mac acl mode failed\n");
        return -1;
    }

    return 0;
}





/********************** DCHP *************************/

/* NOTE: not thread-safe */
char *cmd_htoa(unsigned int ip)
{
    if (!ip) {
        return "";
    }

    ip = htonl(ip);

    return (inet_ntoa(*(struct in_addr *) &ip));
}

int cmd_handle_dhcp_get_pool(cmd_t * this, int argc, char **argv)
{
    istc_dhcp_pool_t pool[ISTC_DHCP_POOL_MAX];
    int cnt = ISTC_DHCP_POOL_MAX;
    int i;

    memset(pool, 0, sizeof (pool));

    if (istc_dhcp_pool_get(pool, &cnt) != 0) {
        printf("get dhcp pool failed\n");
        return -1;
    }

    printf("DHCP pool list below : ");
    if (cnt == 0) {
        printf("(0 total)\n");
        return 0;
    } else {
        printf("(%d total)\n", cnt);
    }

    printf("%3s %-16s %-16s %-16s %-16s %-16s %-16s %-16s %s\n",
           "idx", "pool name", "interface", "start address", "end address",
           "netmask", "primary dns", "secondary dns", "lease(h)");
    printf
        ("--- ---------------- ---------------- ---------------- ---------------- "
         "---------------- ---------------- ---------------- --------\n");
    for (i = 0; i < cnt; i++) {
        printf("%3d %-16s %-16s ", (i + 1), pool[i].name, pool[i].interface);
        printf("%-16s ", cmd_htoa(pool[i].start));
        printf("%-16s ", cmd_htoa(pool[i].end));
        printf("%-16s ", cmd_htoa(pool[i].mask));
        printf("%-16s ", cmd_htoa(pool[i].primary_dns));
        printf("%-16s ", cmd_htoa(pool[i].secondary_dns));
        printf("%u\n", pool[i].lease);
    }


    return 0;
}

int cmd_handle_dhcp_get_lease(cmd_t * this, int argc, char **argv)
{
    istc_dhcp_lease_t lease[512];
    int cnt = 512;
    int i;
    unsigned char *m;

    memset(lease, 0, sizeof (lease));

    if (istc_dhcp_lease_get(lease, &cnt) != 0) {
        printf("get dhcp lease failed\n");
        return -1;
    }

    printf("DHCP lease below : ");
    if (cnt == 0) {
        printf("(0 total)\n");
        return 0;
    } else {
        printf("(%d total)\n", cnt);
    }

    printf("%3s %-32s %-16s %-18s %s\n", "idx", "Name", "IP", "MAC",
           "lease(sec)");
    printf
        ("--- -------------------------------- ---------------- ------------------ ------------\n");
    for (i = 0; i < cnt; i++) {
        m = lease[i].host_mac;
        printf("%3d %-32s %-16s %02x:%02x:%02x:%02x:%02x:%02x %-u\n",
               (i + 1),
               lease[i].host_name,
               cmd_htoa(lease[i].host_ip),
               m[0], m[1], m[2], m[3], m[4], m[5], lease[i].host_lease);
    }

    return 0;
}



/* [NAME] [INTERFACE] START END [netmask NETMASK] [gateway GATEWAY] [primary-dns DNS] [secondary-dns DNS] [lease TIME] */
int cmd_handle_dhcp_add_pool(cmd_t * this, int argc, char **argv)
{
    int need_argc = 2;
    int index = 0;
    istc_dhcp_pool_t pool;

    if (argc < need_argc) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    memset(&pool, 0, sizeof (pool));

    if (strlen(argv[index]) == 4 && strncmp(argv[index], "name", 4) == 0) {
        index++;
        strncpy(pool.name, argv[index], ISTC_DHCP_POOL_NAME_SIZE);
        need_argc += 2;
        index++;
    }

    if (argc < need_argc) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (strlen(argv[index]) == 9 && strncmp(argv[index], "interface", 9) == 0) {
        index++;
        strncpy(pool.interface, argv[index], ISTC_IFNAME_SIZE);
        need_argc += 2;
        index++;
    }

    if (argc < need_argc) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    /* now the start address and end address */
    if (inet_pton(AF_INET, argv[index], &(pool.start)) != 1) {
        printf("start address %s format error\n", argv[index]);
        cmd_handle_help(this, argc, argv);
        return -1;
    } else {
        pool.start = ntohl(pool.start);
        index++;
    }

    if (inet_pton(AF_INET, argv[index], &(pool.end)) != 1) {
        printf("end address %s format error\n", argv[index]);
        cmd_handle_help(this, argc, argv);
        return -1;
    } else {
        pool.end = ntohl(pool.end);
        index++;
        need_argc += 2;
    }

    do {

        /* netmask */
        if (argc < need_argc) {
            break;
        }
        if (strlen(argv[index]) == 7 && strncmp(argv[index], "netmask", 7) == 0) {
            index++;
            if (inet_pton(AF_INET, argv[index], &(pool.mask)) != 1) {
                pool.mask = 0;
                break;
            }
            pool.mask = ntohl(pool.mask);
            need_argc += 2;
            index++;
        }

        /* gateway */
        if (argc < need_argc) {
            break;
        }
        if (strlen(argv[index]) == 7 && strncmp(argv[index], "gateway", 7) == 0) {
            index++;
            if (inet_pton(AF_INET, argv[index], &(pool.gateway)) != 1) {
                pool.mask = 0;
                break;
            }
            pool.gateway = ntohl(pool.gateway);
            need_argc += 2;
            index++;
        }


        /* primary dns */
        if (argc < need_argc) {
            break;
        }
        if (strlen(argv[index]) == 11
            && strncmp(argv[index], "primary-dns", 11) == 0) {
            index++;
            if (inet_pton(AF_INET, argv[index], &(pool.primary_dns)) != 1) {
                pool.primary_dns = 0;
                break;
            }
            pool.primary_dns = ntohl(pool.primary_dns);
            need_argc += 2;
            index++;
        }

        /* secondary dns */
        if (argc < need_argc) {
            break;
        }
        if (strlen(argv[index]) == 13
            && strncmp(argv[index], "secondary-dns", 13) == 0) {
            index++;
            if (inet_pton(AF_INET, argv[index], &(pool.secondary_dns)) != 1) {
                pool.secondary_dns = 0;
                break;
            }
            pool.secondary_dns = ntohl(pool.secondary_dns);
            need_argc += 2;
            index++;
        }

        /* lease */
        if (argc < need_argc) {
            break;
        }
        if (strlen(argv[index]) == 5 && strncmp(argv[index], "lease", 5) == 0) {
            index++;

            pool.lease = atoi(argv[index]);
            if (pool.lease < ISTC_DHCP_LEASE_MIN) {
                pool.lease = ISTC_DHCP_LEASE_DEFAULT;
            }
            need_argc += 2;
            index++;
        }

    } while (0);

#if 1
    printf("name [%s]\n", pool.name);
    printf("interface [%s]\n", pool.interface);
    printf("start 0x%x\n", pool.start);
    printf("end 0x%x\n", pool.end);
    printf("netmask 0x%x\n", pool.mask);
    printf("gateway 0x%x\n", pool.gateway);
    printf("primary dns 0x%x\n", pool.primary_dns);
    printf("secondary dns 0x%x\n", pool.secondary_dns);
    printf("lease %u hour(s)\n", pool.lease);
#endif

    if (istc_dhcp_pool_add(&pool) != 0) {
        printf("add dhcp pool failed\n");
        return -1;
    }

    return 0;
}


int cmd_handle_dhcp_remove_pool(cmd_t * this, int argc, char **argv)
{
    unsigned int start;
    unsigned int end;

    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    /* now the start address and end address */
    if (inet_pton(AF_INET, argv[0], &(start)) != 1) {
        printf("start address %s format error\n", argv[0]);
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (inet_pton(AF_INET, argv[1], &(end)) != 1) {
        printf("end address %s format error\n", argv[1]);
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    start = ntohl(start);
    end = ntohl(end);

    if (istc_dhcp_pool_remove(start, end) != 0) {
        printf("remove dhcp pool failed\n");
        return -1;
    }

    return 0;
}


int cmd_handle_dhcp_add_opt60(cmd_t * this, int argc, char **argv)
{
    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_dhcpc_option60_add(argv[0], argv[1]) != 0) {
        printf("add option 60 %s to interface %s failed\n", argv[1], argv[0]);
        return -1;
    }

    return 0;
}

int cmd_handle_dhcp_remove_opt60(cmd_t * this, int argc, char **argv)
{
    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_dhcpc_option60_remove(argv[0]) != 0) {
        printf("remove option 60 from interface %s failed\n", argv[0]);
        return -1;
    }

    return 0;
}

int cmd_handle_dhcp_add_opt60_s(cmd_t * this, int argc, char **argv)
{
    if (argc < 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_dhcpc_option60_s_add(argv[0], argv[1]) != 0) {
        printf("add option 60 %s to interface %s failed\n", argv[1], argv[0]);
        return -1;
    }

    return 0;
}

int cmd_handle_dhcp_remove_opt60_s(cmd_t * this, int argc, char **argv)
{
    if (argc < 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_dhcpc_option60_s_remove(argv[0]) != 0) {
        printf("remove option 60 from interface %s failed\n", argv[0]);
        return -1;
    }

    return 0;
}


int cmd_handle_route_get_state(cmd_t * this, int argc, char **argv)
{
    int state;

    if (istc_route_state_get(&state) != 0) {
        printf("get route state failed\n");
        return -1;
    }

    if (state) {
        printf("IP routing is enabled!\n");
    } else {
        printf("IP routing is disabled!\n");
    }

    return 0;
}

int cmd_handle_route_set_state(cmd_t * this, int argc, char **argv)
{
    int state;
    int len;

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    len = strlen(argv[0]);

    if (len == 6 && strncmp(argv[0], "enable", 6) == 0) {
        state = 1;
    } else if (len == 7 && strncmp(argv[0], "disable", 7) == 0) {
        state = 0;
    } else {
        printf("state format is invalid\n");
        //cmd_handle_help(this, argc, argv);
        return -1;
    }


    if (istc_route_state_set(state) != 0) {
        printf("set route state failed\n");
        return -1;
    }

    return 0;
}



int cmd_handle_route_get_default(cmd_t * this, int argc, char **argv)
{
    unsigned int gateway;
    char str[32] = { 0 };

    char iflist[ISTC_INTERFACE_MAX][ISTC_IFNAME_SIZE];
    int count = ISTC_INTERFACE_MAX;
    int i;

    if (istc_interface_list_get(iflist, &count) != 0) {
        printf("get interface list failed\n");
        return -1;
    }

    printf("%-16s  %s\n", "Gateway", "Interface");
    printf("----------------  --------\n");
    for (i = 0; i < count; i++) {
        if (istc_route_default_get(iflist[i], &gateway) == 0) {
            if (gateway != 0) {
                istc_inet_htoa(gateway, str, sizeof (str));
                printf("%-16s  %s\n", str, iflist[i]);
            }

        }
    }

    return 0;
}

int cmd_handle_route_set_default(cmd_t * this, int argc, char **argv)
{
    unsigned int gateway;

    if (argc != 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_inet_atoh(argv[1], &gateway) != 0) {
        printf("gateway address %s format is invalid\n", argv[1]);
        return -1;
    }


    if (istc_route_default_set(argv[0], gateway) != 0) {
        printf("set route default gateway failed\n");
        return -1;
    }

    return 0;
}




int cmd_handle_dns_get_dns(cmd_t * this, int argc, char **argv)
{
    unsigned int primary;
    unsigned int secondary;

    if (istc_dns_address_get(&primary, &secondary) != 0) {
        printf("get dns failed\n");
        return -1;
    }

    printf("primary   DNS %s\n", cmd_htoa(primary));
    printf("secondary DNS %s\n", cmd_htoa(secondary));

    return 0;
}

int cmd_handle_dns_set_dns(cmd_t * this, int argc, char **argv)
{
    unsigned int primary;
    unsigned int secondary;

    if (argc != 2) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (inet_aton(argv[0], (struct in_addr *) &primary) == 0) {
        printf("primary DNS IP address %s format is invalid\n", argv[1]);
        return -1;
    }

    primary = ntohl(primary);

    if (inet_aton(argv[1], (struct in_addr *) &secondary) == 0) {
        printf("secondary DNS IP address %s format is invalid\n", argv[1]);
        return -1;
    }

    secondary = ntohl(secondary);


    if (istc_dns_address_set(primary, secondary) != 0) {
        printf("set dns failed\n");
        return -1;
    }

    return 0;
}



int cmd_handle_misc_save_config(cmd_t * this, int argc, char **argv)
{
    if (istc_misc_config_save() != 0) {
        printf("save config failed\n");
        return -1;
    } else {
        printf("running config was saved\n");
    }

    return 0;
}


int cmd_handle_pppoe_get_config(cmd_t * this, int argc, char **argv)
{
    char username[64];
    char password[64];

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }


    if (istc_pppoe_config_get(argv[0], username, password) != 0) {
        printf("get pppoe config on interface %s failed\n", argv[0]);
        return -1;
    } else {
        printf("PPPoE configuration information on interface %s:\n", argv[0]);
        printf("username : %s\n", username);
        printf("password : %s\n", password);
    }

    return 0;
}

int cmd_handle_pppoe_set_config(cmd_t * this, int argc, char **argv)
{
    if (argc != 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_pppoe_config_set(argv[0], argv[1], argv[2]) != 0) {
        printf("set pppoe config failed\n");
        return -1;
    }

    return 0;
}


int cmd_handle_pppoe_state(cmd_t * this, int argc, char **argv)
{
    int state;
    char *str;

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_pppoe_state(argv[0], &state) != 0) {
        printf("get pppoe state failed\n");
        return 0;
    }

    if (state == ISTC_PPPOE_STATE_CONNECTED) {
        str = "connected";
    } else if (state == ISTC_PPPOE_STATE_DISCONNECTED) {
        str = "disconnected";
    } else if (state == ISTC_PPPOE_STATE_CONNECTING) {
        str = "connecting";
    } else if (state == ISTC_PPPOE_STATE_NOTINIT) {
        str = "device not init";
    } else if (state == ISTC_PPPOE_STATE_ETHDOWN) {
        str = "ethernet is down";
    } else {
        str = "unknown";
    }

    printf("PPPoE state on interface %s : %s\n", str, argv[0]);

    return 0;
}

int cmd_handle_pppoe_connect(cmd_t * this, int argc, char **argv)
{

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }


    if (istc_pppoe_connect(argv[0]) != 0) {
        printf("PPPoE connect failed\n");
        return -1;
    }

    return 0;
}

int cmd_handle_pppoe_async_connect(cmd_t * this, int argc, char **argv)
{
	
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }
	
	
    if (istc_async_pppoe_connect(argv[0]) != 0) {
        printf("PPPoE async connect failed\n");
        return -1;
    }
	
    return 0;
}

int cmd_handle_pppoe_disconnect(cmd_t * this, int argc, char **argv)
{

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }


    if (istc_pppoe_disconnect(argv[0]) != 0) {
        printf("PPPoE disconnect failed\n");
        return -1;
    }

    return 0;
}


int cmd_handle_misc_ping(cmd_t * this, int argc, char **argv)
{
    istc_ping_para_t para;
    istc_ping_result_t result;
    int i;
    int num;
    struct in_addr in_addr;

    if (argc < 1 || ((argc & 1) != 1)) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    memset(&para, 0, sizeof (para));
    memset(&result, 0, sizeof (result));

    strncpy(para.host, argv[0], ISTC_HOST_NAME_SIZE);

    /* parse the args */
    for (i = 1; i < argc; i += 2) {
        num = 0;
        if (strcmp(argv[i], "count") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.count = num;
        } else if (strcmp(argv[i], "interval") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.interval = num;
        } else if (strcmp(argv[i], "size") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.pkt_size = num;
        } else if (strcmp(argv[i], "ttl") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.ip_ttl = num;
        } else if (strcmp(argv[i], "timeout") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.timeout = num;
        } else if (strcmp(argv[i], "fragment") == 0) {
            if (strcmp(argv[i + 1], "enable") == 0) {
                para.fragment = 0;
            } else if (strcmp(argv[i + 1], "disable") == 0) {
                para.fragment = 1;
            } else {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
        } else if (strcmp(argv[i], "interface") == 0) {
            strncpy(para.interface, argv[i + 1], ISTC_IFNAME_SIZE);
        } else if (strcmp(argv[i], "srcip") == 0) {

            if (inet_aton(argv[i + 1], &in_addr) == 0) {
                printf("address %s is valid\n", argv[i + 1]);
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.src_addr = in_addr.s_addr;
        } else {
            cmd_handle_help(this, argc, argv);
            return -1;
        }
    }

    //printf("host %s\n", para.host);

    if (istc_ping(&para, &result) != 0) {
        printf("ping failed\n");
        return -1;
    }

    /* show the ping result */
    if (para.interface[0]) {
        printf("--- %s ping statistics from interface %s ---\n", argv[0],
               para.interface);
    } else if (para.src_addr) {
        printf("--- %s ping statistics from %s ---\n", argv[0],
               inet_ntoa(in_addr));
    } else {
        printf("--- %s ping statistics ---\n", argv[0]);
    }
    printf
        ("%d packet transmitted, %d packet received, %d%% packet loss, time %dms\n",
         result.send, result.recv,
         (100 - ((result.recv * 100) / (result.send))), result.time);
    printf("rtt min/avg/max = %d/%d/%d ms\n", result.rtt_min, result.rtt_avg,
           result.rtt_max);

    return 0;
}



int cmd_handle_misc_async_ping(cmd_t * this, int argc, char **argv)
{
    istc_ping_para_t para;
    istc_ping_result_t result;
    int i;
    int num;
    struct in_addr in_addr;

    if (argc < 1 || ((argc & 1) != 1)) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    memset(&para, 0, sizeof (para));
    memset(&result, 0, sizeof (result));

    strncpy(para.host, argv[0], ISTC_HOST_NAME_SIZE);

    /* parse the args */
    for (i = 1; i < argc; i += 2) {
        num = 0;
        if (strcmp(argv[i], "count") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.count = num;
        } else if (strcmp(argv[i], "interval") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.interval = num;
        } else if (strcmp(argv[i], "size") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.pkt_size = num;
        } else if (strcmp(argv[i], "ttl") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.ip_ttl = num;
        } else if (strcmp(argv[i], "timeout") == 0) {
            num = atoi(argv[i + 1]);
            if (num == 0) {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.timeout = num;
        } else if (strcmp(argv[i], "fragment") == 0) {
            if (strcmp(argv[i + 1], "enable") == 0) {
                para.fragment = 0;
            } else if (strcmp(argv[i + 1], "disable") == 0) {
                para.fragment = 1;
            } else {
                cmd_handle_help(this, argc, argv);
                return -1;
            }
        } else if (strcmp(argv[i], "interface") == 0) {
            strncpy(para.interface, argv[i + 1], ISTC_IFNAME_SIZE);
        } else if (strcmp(argv[i], "srcip") == 0) {

            if (inet_aton(argv[i + 1], &in_addr) == 0) {
                printf("address %s is valid\n", argv[i + 1]);
                cmd_handle_help(this, argc, argv);
                return -1;
            }
            para.src_addr = in_addr.s_addr;
        } else {
            cmd_handle_help(this, argc, argv);
            return -1;
        }
    }

    //printf("host %s\n", para.host);

    if (istc_async_ping(&para) != 0) {
        printf("ping failed\n");
        return -1;
    }

    return 0;
}


int cmd_handle_misc_async_sta_scan(cmd_t * this, int argc, char **argv)
{
    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;       
    }

    if (istc_async_wireless_sta_ssid_scan(argv[0]) != 0) {
        printf("async sta scan failed\n");
        return -1;
    }

    return 0;
}




int cmd_handle_misc_get_iflist(cmd_t * this, int argc, char **argv)
{
    char iflist[ISTC_INTERFACE_MAX][ISTC_IFNAME_SIZE];
    int count = ISTC_INTERFACE_MAX;
    int i;

    if (istc_interface_list_get(iflist, &count) != 0) {
        printf("get interface list failed\n");
        return -1;
    }

    printf("All interface list (total %d) : \n", count);
    if (count > 0) {
        printf("%5s  %s\n", "index", "interface name");
        printf("-----  ----------------\n");

        for (i = 0; i < count; i++) {
            printf("%5d  %s\n", i + 1, iflist[i]);
        }
    }


    return 0;
}


int cmd_handle_misc_get_iftype(cmd_t * this, int argc, char **argv)
{
    int type;
    char *str = "unknown";

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    if (istc_interface_type_get(argv[0], &type) != 0) {
        printf("get interface %s type failed\n", argv[0]);
        return -1;
    }

    if (type == ISTC_INTERFACE_TYPE_WIRED) {
        str = "wired";
    } else if (type == ISTC_INTERFACE_TYPE_WIRELESS) {
        str = "wireless";
    }

    printf("interface %s is a %s interface\n", argv[0], str);

    return 0;
}



int cmd_handle_misc_get_if(cmd_t * this, int argc, char **argv)
{
    char iflist[ISTC_INTERFACE_MAX][ISTC_IFNAME_SIZE];
    int count = ISTC_INTERFACE_MAX;
    int i;
    int type;
    char *str;

    if (istc_interface_list_get(iflist, &count) != 0) {
        printf("get interface list failed\n");
        return -1;
    }

    printf("All interface list (total %d) : \n", count);
    if (count > 0) {
        printf("%5s  %-16s  %-s\n", "index", "interface name", "type");
        printf("-----  ----------------  --------\n");

        for (i = 0; i < count; i++) {
            type = ISTC_INTERFACE_TYPE_NONE;
            istc_interface_type_get(iflist[i], &type);

            if (type == ISTC_INTERFACE_TYPE_WIRED) {
                str = "wired";
            } else if (type == ISTC_INTERFACE_TYPE_WIRELESS) {
                str = "wireless";
            } else {
                str = "unknown";
            }

            printf("%5d  %-16s  %-s\n", i + 1, iflist[i], str);
        }
    }


    return 0;
}


int cmd_handle_misc_get_log_lv(cmd_t * this, int argc, char **argv)
{
    int level = 0;

    if (istc_log_level_get(&level) != 0) {
        printf("get log level failed\n");
        return -1;
    }

    if (level >= 0 && level <= 7) {
        printf("istcd log level is %d <%s>\n", cmd_log_lv[level].level,
               cmd_log_lv[level].str);
    } else if (level == -1) {
        printf("istcd log is disabled\n");
    } else {
        printf("istcd log level is unkown\n");
    }

    return 0;
}


int cmd_handle_misc_set_log_lv(cmd_t * this, int argc, char **argv)
{
    int i;
    int num = -2;

    if (argc != 1) {
        cmd_handle_help(this, argc, argv);

        printf("%-5s  %s\n", "Level", "Description");
        printf("-----  -----------\n");
        for (i = 0; i <= 7; i++) {
            printf("%5d  %s\n", cmd_log_lv[i].level, cmd_log_lv[i].str);
        }
        printf("%5s  %s\n", "-1", "disable");
    }

    num = atoi(argv[0]);

    if ((num >= 0 && num <= 7) || (num == -1)) {
        if (istc_log_level_set(num) != 0) {
            printf("set log level failed\n");
        }
    } else {
        printf("invalid log level %s\n", argv[0]);
    }

    return 0;
}


void cmd_show_sta_ssid(istc_sta_ssid_t *ssidlist, int cnt)
{
    int i;
    char ssid[32];
    char *encry;


    printf("%3s  %-32s  %-17s  %-4s  %-4s  %s\n", "idx", "SSID", "MAC", "chnl",
           "sgnl", "encryption");
    printf
        ("---  --------------------------------  -----------------  ----  ----  ----------\n");
    for (i = 0; i < cnt; i++) {
        if (ssidlist[i].ssid[0]) {
            int len = strlen(ssidlist[i].ssid);
            if (len >= 31) {
                memcpy(ssid, ssidlist[i].ssid, 28);
                strcpy(ssid + 28, "...");
            } else {
                strncpy(ssid, ssidlist[i].ssid, 32);
            }

        } else {
            strcpy(ssid, " ");
        }

        if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_OPEN) {
            encry = "OPEN";
        } else if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA) {
            encry = "WPA";
        } else if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA2) {
            encry = "WPA2";
        } else if (ssidlist[i].encryption == ISTC_WIRELESS_ENCRYPTION_WPA_WPA2) {
            encry = "WPA | WPA2";
        } else {
            encry = "???";
        }

        printf("%3d  %-32s  %-17s  %-4d  %-4d  %s\n",
               (i + 1),
               ssid,
               ssidlist[i].mac, ssidlist[i].channel, ssidlist[i].signal, encry);

    }

}

static void cmd_async_callback(int command, const void *data, int size)
{
    if (!data) {
        printf("data is null\n");
        return;
    }

    if (size <= 0) {
        printf("size <= 0\n");
        return;
    }

    istc_class_async_sta_ssid_enable_t *en_ssid = (istc_class_async_sta_ssid_enable_t *)data;
    istc_class_async_sta_ssid_disable_t *di_ssid = (istc_class_async_sta_ssid_disable_t *)data;
    istc_class_async_ap_ssid_enable_t *ap_en_ssid = (istc_class_async_ap_ssid_enable_t *)data;
    istc_class_async_ap_ssid_disable_t *ap_di_ssid = (istc_class_async_ap_ssid_disable_t *)data;
	istc_class_async_pppoe_t *pppoe = (istc_class_async_pppoe_t *)data;
    
    istc_class_async_ping_t *ping = (istc_class_async_ping_t *)data;
    istc_class_async_sta_scan_t *sta_scan = (istc_class_async_sta_scan_t *)data;

    switch (command) {
        case ISTC_CLASS_ASYNC_CMD_STA_ENABLE:
            en_ssid->result = ntohl(en_ssid->result);
            printf("connect to %s %s\n", en_ssid->ssid, istc_errstr(en_ssid->result));
            break;
        case ISTC_CLASS_ASYNC_CMD_STA_DISABLE:
            di_ssid->result = ntohl(di_ssid->result);
            printf("disconnect from %s %s\n", di_ssid->ssid, istc_errstr(di_ssid->result));
            break;  
        case ISTC_CLASS_ASYNC_CMD_AP_ENABLE:
            ap_en_ssid->result = ntohl(ap_en_ssid->result);
            printf("start AP %s %s\n", ap_en_ssid->ssid, istc_errstr(ap_en_ssid->result));
            break;
        case ISTC_CLASS_ASYNC_CMD_AP_DISABLE:
            ap_di_ssid->result = ntohl(ap_di_ssid->result);
            printf("stop AP %s %s\n", ap_di_ssid->ssid, istc_errstr(ap_di_ssid->result));
            break;
        case ISTC_CLASS_ASYNC_CMD_PING:
            /* convert to host byteorder */
            ping->result.send = ntohl(ping->result.send);
            ping->result.recv = ntohl(ping->result.recv);
            ping->result.rtt_min = ntohl(ping->result.rtt_min);
            ping->result.rtt_avg = ntohl(ping->result.rtt_avg);
            ping->result.rtt_max = ntohl(ping->result.rtt_max);
            ping->result.time = ntohl(ping->result.time);
            printf("ping %s result:\n", ping->para.host);
            printf("send %d, recv %d, lost %d\n", ping->result.send, 
                ping->result.recv, (ping->result.send - ping->result.recv));
            printf("rtt(ms) min %d avg %d max %d, cost %d ms\n", 
                ping->result.rtt_min, ping->result.rtt_avg, ping->result.rtt_max,
                ping->result.time);
            break;
        case ISTC_CLASS_ASYNC_CMD_STA_SCAN:
        {
            int i;
            sta_scan->result = ntohl(sta_scan->result);
            if (sta_scan->result != 0) {
                printf("interface %s scan SSID failed %s\n", sta_scan->ifname,
                    istc_errstr(sta_scan->result));
            }
            sta_scan->cnt = ntohl(sta_scan->cnt);
            istc_sta_ssid_t *ssidlist = (istc_sta_ssid_t *)(sta_scan + 1);
            
            for (i = 0; i < sta_scan->cnt; i++) {
                ssidlist[i].channel = htonl(ssidlist[i].channel);
                ssidlist[i].encryption = htonl(ssidlist[i].encryption);
                ssidlist[i].signal = htonl(ssidlist[i].signal);
            }

            cmd_show_sta_ssid(ssidlist, sta_scan->cnt);

        }
            break;  
		case ISTC_CLASS_ASYNC_CMD_PPPOE:
            pppoe->result = ntohl(pppoe->result);
            printf("pppoe async connect %s\n", istc_errstr(pppoe->result));
            break;
        default:
            printf("unknown command %d\n", command);
            break;
    }
}

int cmd_handle_misc_async_sta_connect(cmd_t * this, int argc, char **argv)
{
    //int ret;
    
    if (argc != 4) {
        /* IFNAME SSID PASSWORD ENCRYPTION */
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    char *ssid = NULL;
    char *password = NULL;
    char *encry = NULL;
    int encryption = -1;


    ssid = argv[1];
    password = argv[2];
    encry = argv[3];

    if (strcmp(encry, "WPA") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_WPA;
    } else if (strcmp(encry, "WPA2") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_WPA2;
    } else if (strcmp(encry, "WPAWPA2") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_WPA_WPA2;
    } else if (strcmp(encry, "OPEN") == 0) {
        encryption = ISTC_WIRELESS_ENCRYPTION_OPEN;
    } else {
        printf("not support encryption : %s\n", encry);
        return -1;
    }

    if (istc_wireless_sta_ssid_add2(argv[0], ssid, password, encryption) != 0) {
        printf("istc_wireless_sta_ssid_add2 %s ssid %s failed\n", argv[0],
               ssid);
        return -1;
    }

    /* async connect */
    if (istc_async_wireless_sta_ssid_enable(argv[0], ssid) != 0) {
        printf("istc_async_wireless_sta_ssid_enable failed\n");
        return -1;
    }
    
    return 0;
}


int cmd_handle_misc_async_sta_disconnect(cmd_t * this, int argc, char **argv)
{
    //int ret;
    
    if (argc != 2) {
        /* IFNAME SSID */
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    char *ssid = NULL;

    ssid = argv[1];

    /* async connect */
    if (istc_async_wireless_sta_ssid_disable(argv[0], ssid) != 0) {
        printf("istc_async_wireless_sta_ssid_disable failed\n");
        return -1;
    }
    
    return 0;
}



int cmd_handle_misc_async_ap_start(cmd_t * this, int argc, char **argv)
{
    //int ret;
    
    if (argc != 5) {
        /* IFNAME SSID PASSWORD ENCRYPTION CHANNEL */
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    istc_ap_ssid_t ap;

    memset(&ap, 0, sizeof(istc_ap_ssid_t));

    strncpy(ap.ssid, argv[1], ISTC_SSID_NAME_SIZE);
    strncpy(ap.password, argv[2], ISTC_SSID_PSWD_SIZE);
    

    if (strcmp(argv[3], "WPA") == 0) {
        ap.encryption = ISTC_WIRELESS_ENCRYPTION_WPA;
    } else if (strcmp(argv[3], "WPA2") == 0) {
        ap.encryption = ISTC_WIRELESS_ENCRYPTION_WPA2;
    } else if (strcmp(argv[3], "WPAWPA2") == 0) {
        ap.encryption = ISTC_WIRELESS_ENCRYPTION_WPA_WPA2;
    } else if (strcmp(argv[3], "OPEN") == 0) {
        ap.encryption = ISTC_WIRELESS_ENCRYPTION_OPEN;
    } else {
        printf("not support encryption : %s\n", argv[3]);
        return -1;
    }

    ap.channel = atoi(argv[4]);
    if (ap.channel < 0) {
        printf("channel %s is not support\n", argv[4]);
        return -1;
    }

    if (istc_wireless_ap_ssid_add(argv[0], &ap) != 0) {
        printf("istc_wireless_ap_ssid_add %s ssid %s failed\n", argv[0],
               ap.ssid);
        return -1;
    }

    /* async connect */
    if (istc_async_wireless_ap_ssid_enable(argv[0], ap.ssid) != 0) {
        printf("istc_async_wireless_ap_ssid_enable failed\n");
        return -1;
    }
    
    return 0;
}


int cmd_handle_misc_async_ap_stop(cmd_t * this, int argc, char **argv)
{
    //int ret;
    
    if (argc != 2) {
        /* IFNAME SSID */
        cmd_handle_help(this, argc, argv);
        return -1;
    }

    char *ssid = NULL;

    ssid = argv[1];

    /* async connect */
    if (istc_async_wireless_ap_ssid_disable(argv[0], ssid) != 0) {
        printf("istc_async_wireless_ap_ssid_disable failed\n");
        return -1;
    }
    
    return 0;
}




static int cmd_add(cmd_t * parent, cmd_t * this)
{
    cmd_t *child;

    if (this->length == 0) {
        this->length = strlen(this->name);
    }

    this->parent = parent;
    child = parent->child;
    this->child = NULL;

    if (child) {
        /* insert at tail */
        //printf("insert %s at %s tail\n", this->name, parent->name);
        this->prev = child->prev;
        this->next = child;
        child->prev->next = this;
        child->prev = this;
    } else {
        //printf("insert %s at %s head\n", this->name, parent->name);
        parent->child = this;

        this->prev = this;
        this->next = this;
    }

    return 0;
}



int cmd_add_default(cmd_t * this)
{
    /* add quit, help, help2, list etc commands */
    cmd_t *cmd;

    if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(cmd, &cmd_quit, sizeof (cmd_t));
    cmd_add(this, cmd);

#if 1
    if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(cmd, &cmd_exit, sizeof (cmd_t));
    cmd_add(this, cmd);
#endif

    if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(cmd, &cmd_help, sizeof (cmd_t));
    cmd_add(this, cmd);

    if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(cmd, &cmd_help2, sizeof (cmd_t));
    cmd_add(this, cmd);

    if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(cmd, &cmd_list_cmd, sizeof (cmd_t));
    cmd_add(this, cmd);

    if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(cmd, &cmd_list_sleep, sizeof (cmd_t));
    cmd_add(this, cmd);
    
    return 0;
}


int cmd_remove_default(cmd_t * this)
{
    /* remove quit, help, help2, list etc commands */
    cmd_t *cmd = this->child;
    cmd_t *next;

    while (cmd) {
        next = cmd->next;
        if ((cmd->length == 4) && (strncmp(cmd->name, "quit", 4) == 0)) {
            //printf("in cmd [%s]\n", this->name);
            /* find the 'quit', remove the next nodes */
            /* free 'quit' */
            free(cmd);
            cmd = next;
            next = cmd->next;
            /* free exit */
            free(cmd);
            cmd = next;
            next = cmd->next;
            /* free help */
            free(cmd);
            cmd = next;
            next = cmd->next;
            /* free help2 */
            free(cmd);
            cmd = next;
            next = cmd->next;
            /* free list */
            free(cmd);
            cmd = next;
            next = cmd->next;

            return 0;
        }

        cmd = next;
    }

    return 0;
}


#if 0
static void cmd_show_all(cmd_t * root, char *prefix)
{
    cmd_t *cmd;

    //printf("in cmd_show_all\n");

    cmd_t *child1 = root->child;

    printf("%s%s\n", prefix, root->name);

    if (child1) {
        printf("%s\t%s\n", prefix, child1->name);
        cmd = child1;
        child1 = child1->next;
        while (child1 != cmd) {
            printf("%s\t%s\n", prefix, child1->name);
            child1 = child1->next;
        }
    }

}
#endif

static int cmd_init()
{
    /* TOP level commands */
    cmd_add(&cmd_root, &cmd_class_ip);
    cmd_add(&cmd_root, &cmd_class_mac);
    cmd_add(&cmd_root, &cmd_class_link);
    cmd_add(&cmd_root, &cmd_class_sta);
    cmd_add(&cmd_root, &cmd_class_ap);
    cmd_add(&cmd_root, &cmd_class_dhcp);
    cmd_add(&cmd_root, &cmd_class_route);
    cmd_add(&cmd_root, &cmd_class_dns);
    cmd_add(&cmd_root, &cmd_class_pppoe);
    cmd_add(&cmd_root, &cmd_class_misc);
    cmd_add(&cmd_root, &cmd_class_qos);
    cmd_add(&cmd_root, &cmd_class_lan);

    cmd_add_default(&cmd_root);



    /* IP commands */
    cmd_add(&cmd_class_ip, &cmd_class_ip_get_addr);
    cmd_add(&cmd_class_ip, &cmd_class_ip_get_mask);
    cmd_add(&cmd_class_ip, &cmd_class_ip_get_addr_mode);
    cmd_add(&cmd_class_ip, &cmd_class_ip_set_addr);
    cmd_add(&cmd_class_ip, &cmd_class_ip_set_mask);
    cmd_add(&cmd_class_ip, &cmd_class_ip_set_addr_mode);

    cmd_add_default(&cmd_class_ip);


    /* MAC commands */
    cmd_add(&cmd_class_mac, &cmd_class_mac_get_mac);
    cmd_add(&cmd_class_mac, &cmd_class_mac_set_mac);

    cmd_add_default(&cmd_class_mac);


    /* LINK commands */
    cmd_add(&cmd_class_link, &cmd_class_link_get_state);
    cmd_add(&cmd_class_link, &cmd_class_link_get_admin);
    cmd_add(&cmd_class_link, &cmd_class_link_get_mtu);
    cmd_add(&cmd_class_link, &cmd_class_link_set_admin);

    cmd_add_default(&cmd_class_link);


    /* station commands */
    cmd_add(&cmd_class_sta, &cmd_class_sta_scan);
    cmd_add(&cmd_class_sta, &cmd_class_sta_state);
    cmd_add(&cmd_class_sta, &cmd_class_sta_get_scan_result);
    cmd_add(&cmd_class_sta, &cmd_class_sta_add_ssid);
    cmd_add(&cmd_class_sta, &cmd_class_sta_add2_ssid);
    cmd_add(&cmd_class_sta, &cmd_class_sta_remove_ssid);
    cmd_add(&cmd_class_sta, &cmd_class_sta_enable_ssid);
    cmd_add(&cmd_class_sta, &cmd_class_sta_disable_ssid);

    cmd_add_default(&cmd_class_sta);


    /* ap commands */
    cmd_add(&cmd_class_ap, &cmd_class_ap_get_ssid);
    cmd_add(&cmd_class_ap, &cmd_class_ap_get_sta);
    cmd_add(&cmd_class_ap, &cmd_class_ap_add_ssid);
    cmd_add(&cmd_class_ap, &cmd_class_ap_remove_ssid);
    cmd_add(&cmd_class_ap, &cmd_class_ap_enable_ssid);
    cmd_add(&cmd_class_ap, &cmd_class_ap_disable_ssid);
    cmd_add(&cmd_class_ap, &cmd_class_ap_get_acl_mac);
    cmd_add(&cmd_class_ap, &cmd_class_ap_add_accept_mac);
    cmd_add(&cmd_class_ap, &cmd_class_ap_remove_accept_mac);
    cmd_add(&cmd_class_ap, &cmd_class_ap_add_deny_mac);
    cmd_add(&cmd_class_ap, &cmd_class_ap_remove_deny_mac);
    cmd_add(&cmd_class_ap, &cmd_class_ap_get_mac_acl);
    cmd_add(&cmd_class_ap, &cmd_class_ap_set_mac_acl);



    cmd_add_default(&cmd_class_ap);


    /* dhcp commands */
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_get_pool);
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_get_lease);
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_add_pool);
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_remove_pool);
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_add_opt60);
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_remove_opt60);
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_add_opt60_s);
    cmd_add(&cmd_class_dhcp, &cmd_class_dhcp_remove_opt60_s);
    cmd_add(&cmd_class_dhcp, &cmd_rmpoolname);
    

    cmd_add_default(&cmd_class_dhcp);


    /* route commands */
    cmd_add(&cmd_class_route, &cmd_class_route_get_state);
    cmd_add(&cmd_class_route, &cmd_class_route_set_state);
    cmd_add(&cmd_class_route, &cmd_class_route_get_default);
    cmd_add(&cmd_class_route, &cmd_class_route_set_default);

    cmd_add_default(&cmd_class_route);

    /* dns commands */
    cmd_add(&cmd_class_dns, &cmd_class_dns_get_dns);
    cmd_add(&cmd_class_dns, &cmd_class_dns_set_dns);

    cmd_add_default(&cmd_class_dns);

    /* pppoe commands */
    cmd_add(&cmd_class_pppoe, &cmd_class_pppoe_get_config);
    cmd_add(&cmd_class_pppoe, &cmd_class_pppoe_set_config);
    cmd_add(&cmd_class_pppoe, &cmd_class_pppoe_state);
    cmd_add(&cmd_class_pppoe, &cmd_class_pppoe_connect);
    cmd_add(&cmd_class_pppoe, &cmd_class_pppoe_disconnect);
	cmd_add(&cmd_class_pppoe, &cmd_class_pppoe_async_connect);

    cmd_add_default(&cmd_class_pppoe);

    /* QOS commands */
    cmd_add(&cmd_class_qos, &cmd_class_qos_set_mode);
    cmd_add(&cmd_class_qos, &cmd_class_qos_get_mode);
    cmd_add(&cmd_class_qos, &cmd_class_qos_set_device_bandwidth);
    cmd_add(&cmd_class_qos, &cmd_class_qos_get_device_bandwidth);
    cmd_add(&cmd_class_qos, &cmd_class_qos_get_device_bandwidth_list);

    cmd_add_default(&cmd_class_qos);

    /* LAN commands */
    cmd_add(&cmd_class_lan, &cmd_class_lan_set_addr_info);
    cmd_add(&cmd_class_lan, &cmd_class_lan_get_addr_info);
    cmd_add_default(&cmd_class_lan);

    /* misc commands */
    cmd_add(&cmd_class_misc, &cmd_class_misc_save_config);
    cmd_add(&cmd_class_misc, &cmd_class_misc_ping);
    cmd_add(&cmd_class_misc, &cmd_class_misc_get_iflist);
    cmd_add(&cmd_class_misc, &cmd_class_misc_get_iftype);
    cmd_add(&cmd_class_misc, &cmd_class_misc_get_if);
    cmd_add(&cmd_class_misc, &cmd_class_misc_get_log_lv);
    cmd_add(&cmd_class_misc, &cmd_class_misc_set_log_lv);

    cmd_add(&cmd_class_misc, &cmd_class_misc_async_sta_connect);
    cmd_add(&cmd_class_misc, &cmd_class_misc_async_sta_disconnect);
    cmd_add(&cmd_class_misc, &cmd_class_misc_async_ap_start);
    cmd_add(&cmd_class_misc, &cmd_class_misc_async_ap_stop);
    cmd_add(&cmd_class_misc, &cmd_class_misc_async_ping);
    cmd_add(&cmd_class_misc, &cmd_class_misc_async_sta_scan);


    cmd_add_default(&cmd_class_misc);


#if 0
    /*  */
    cmd_add(&cmd_root, &cmd_test);
    cmd_add(&cmd_test, &cmd_foo);
#endif

    return 0;
}


int cmd_deinit()
{
    cmd_remove_default(&cmd_root);
    cmd_remove_default(&cmd_class_ip);
    cmd_remove_default(&cmd_class_mac);
    cmd_remove_default(&cmd_class_link);
    cmd_remove_default(&cmd_class_sta);
    cmd_remove_default(&cmd_class_ap);
    cmd_remove_default(&cmd_class_dhcp);
    cmd_remove_default(&cmd_class_route);
    cmd_remove_default(&cmd_class_dns);
    cmd_remove_default(&cmd_class_pppoe);
    cmd_remove_default(&cmd_class_misc);
    cmd_remove_default(&cmd_class_qos);
    cmd_remove_default(&cmd_class_lan);

    return 0;
}

void link_change_callback(const istc_link_change_t * link)
{
    if (!link) {
        printf("link is NULL\n");
        return;
    }
    //printf("link_change_callback ...\n");

	if (ISTC_DATA_LINK_VALID == link->change_to) {
		printf("istc_cli: interface %s data link valid.\n", link->ifname);
		return;
	}

    if (strncmp(link->ifname, "eth", 3) == 0) {
        printf("istc_cli: interface %s is %s\n",
               link->ifname,
               link->change_to == ISTC_LINK_STATE_DOWN ? "DOWN" : "UP");
    } else if (strncmp(link->ifname, "wlan", 4) == 0) {
        printf("istc_cli: interface %s is %s\n", link->ifname,
               link->change_to ==
               ISTC_WIRELESS_STA_STATE_CONNECTED ? "connected" :
               "disconnected");
    } else {
        printf("istc_cli: interface %s is %d\n", link->ifname, link->change_to);
    }

}

int read_args_script(char *prompt, int *argc, char **argv)
{
    prompt = "";
    char *line = read_line(prompt, cmd_script_fp);
    int len;
    int ac = 0;

    if (!line) {
        return -1;
    }

    len = strlen(line);

    //printf("line = [%s]\n", line);

    char *ptr;
    char *start;
    char *end;
    char *last = line + len;

    ptr = line;
    /* ignore space at head */
    while ((ptr < last) && (*ptr == ' ' || *ptr == '\t'))
        ptr++;

    while ((ptr < last && *ptr != '\n') && ac < CMD_ARGC_MAX) {
        start = ptr;
        while ((ptr < last && *ptr != '\n') && (*ptr != ' ' && *ptr != '\t'))
            ptr++;

        /* got one arg */
        end = ptr++;
        *end = '\0';
        strncpy(argv[ac++], start, CMD_ARGV_LEN);

        /* ingore space */
        while ((ptr < last) && (*ptr == ' ' || *ptr == '\t'))
            ptr++;
    }

    *argc = ac;

    free(line);

    return 0;
}

int cmd_load_script(cmd_t * this, int argc, char *argv[], const char *name)
{
    FILE *fp = NULL;

    if (!name || !*name) {
        printf("name is null\n");
        return -1;
    }

    if ((fp = fopen(name, "r")) == NULL) {
        printf("open %s failed\n", name);
        return -1;
    }

    cmd_script_fp = fp;
    read_args_func = read_args_script;
    cmd_handle_cli(this, argc, argv);

    fclose(fp);

    return 0;
}

void usage()
{
    printf("istcd command line util, version %s protocol %d commit %s\n", 
        ISTC_VERSION, ISTC_PROTOCOL_VERSION, ISTC_VERSION_COMMIT);
    printf("usage : istc_cli [-s ADDR] [-S script] [-h]\n");
    printf
        ("  -s ADDR      set the istcd server address, default is 127.0.0.1\n");
    printf("  -p PORT      set the istcd server port, default is 55555\n");
    printf("  -S script    load the script and exit\n");
    printf("  -h           show this message\n");
}


int main(int argc, char *argv[])
{
    unsigned int addr = 0;
    int opt;
    unsigned short port = -1;
    char *script_name = NULL;
    cmd_args_t *cmd_args = NULL;
    int ret;
#ifndef ISTC_USE_SNMP
    char *msg = "hello world!";
#endif    

    int i;

    istc_snmp_init();
    
    while ((opt = getopt(argc, argv, "s:p:S:h")) != -1) {
        switch (opt) {
            case 's':
                inet_aton(optarg, (struct in_addr *) &addr);
                if (addr == 0) {
                    usage();
                    return -1;
                }
                /* get a valid address */
                addr = ntohl(addr);
                istc_server_addr_set(addr);
                break;
            case 'p':
                port = atoi(optarg);
                if (port == -1) {
                    usage();
                    return -1;
                }
                istc_server_port_set(port);
                break;
            case 'S':
                script_name = optarg;
                break;
            case 'h':
                usage();
                return 0;
                break;
            default:
                usage();
                return 0;
                break;
        }
    }


    signal(SIGINT, cmd_signal_handler);
    signal(SIGQUIT, cmd_signal_handler);
    signal(SIGTERM, cmd_signal_handler);

    printf("istc_cli start ...\n");
#ifndef ISTC_USE_SNMP
	if (istc_link_change_register(ISTC_IFNAME_ALL, link_change_callback, msg) !=
		0) {
		printf("register %s link notification failed\n", ISTC_IFNAME_ALL);
	} else {
		printf("register %s link notification success\n", ISTC_IFNAME_ALL);
    }
#endif

    cmd_init();

#ifndef ISTC_USE_SNMP
    if ((ret = istc_async_callback_register(cmd_async_callback)) != 0) {
        printf("register async callback failed\n");
        return -1;
    }
#endif    

    //cmd_show_all(&cmd_root, "");

    //printf("\n--------------- \n");
    //cmd_show_all(&cmd_class_ip, "");

    if ((cmd_args = malloc(sizeof (cmd_args_t))) == NULL) {
        printf("malloc failed\n");
        return -1;
    }

    for (i = 0; i < CMD_ARGC_MAX; i++) {
        cmd_args->argv[i] = cmd_args->buff[i];
    }



    ret = setjmp(env);

    if (ret == 0) {
        /* set jump success (the first time run to here) */
        if (script_name) {
            printf("load script %s ...\n", script_name);
            cmd_load_script(&cmd_root, cmd_args->argc, cmd_args->argv,
                            script_name);
        } else {
            cmd_script_fp = stdin;
            read_args_func = read_args_std;
            cmd_handle_cli(&cmd_root, cmd_args->argc, cmd_args->argv);
        }
    } else {
        printf("jump no %d(0x%x)\n", ret, ret);
        goto __cmd_exit_now;
    }

  __cmd_exit_now:

    if (cmd_args) {
        free(cmd_args);
        cmd_args = NULL;
    }

    cmd_deinit();

	if (istc_link_change_unregister(ISTC_IFNAME_ALL, link_change_callback) != 0) {
		printf("unregister %s link notification failed\n", ISTC_IFNAME_ALL);
	} else {
		printf("unregister %s link notification success\n", ISTC_IFNAME_ALL);
    }

    if ((ret = istc_async_callback_unregister(cmd_async_callback)) != 0) {
        printf("register async callback failed\n");
        return -1;
    }    

    return 0;
}

int cmd_handle_qos_set_mode( cmd_t * this, int argc, char **argv )
{
	int mode = -1;
	
	if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }
	
	mode = atoi(argv[0]);
	
    if (istc_qos_set_mode(mode) != 0) {
        printf("qos set mode failed\n");
        return -1;
    }
	
    return 0;	
}

int cmd_handle_qos_get_mode( cmd_t * this, int argc, char **argv )
{
	int mode = -1;
	
	if (istc_qos_get_mode(&mode) != 0) {
        printf("qos get mode failed\n");
        return -1;
    }
	
	printf("cli: get_mode %d\n", mode);
	
    return 0;	
}

int cmd_handle_qos_set_device_bandwidth( cmd_t * this, int argc, char **argv )
{
	int download = -1;
	int upload = -1;

	if (argc != 3) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }
	
    unsigned char mac[8] = { 0 };
	
    if (cmd_str2mac(argv[0], mac) != 0) {
        printf("mac string %s format error\n", argv[1]);
        return -1;
    }
	
	download = atoi(argv[1]);
	upload = atoi(argv[2]);

    if (istc_qos_set_device_bandwidth(mac, download, upload) != 0) {
        printf("qos set device bandwidth failed\n");
        return -1;
    }
	
    return 0;	
}

int cmd_handle_qos_get_device_bandwidth( cmd_t * this, int argc, char **argv )
{
	int download = -1;
	int upload = -1;

	if (argc != 1) {
        cmd_handle_help(this, argc, argv);
        return -1;
    }
	
    unsigned char mac[8] = { 0 };
	
    if (cmd_str2mac(argv[0], mac) != 0) {
        printf("mac string %s format error\n", argv[1]);
        return -1;
    }

	if (istc_qos_get_device_bandwidth(mac, &download, &upload) != 0) {
        printf("qos get device bandwidth failed\n");
        return -1;
    }

	printf("cli: get_device_bandwidth %s %d %d\n", argv[0], download, upload);
	
    return 0;	
}

int cmd_handle_qos_get_device_bandwidth_list( cmd_t * this, int argc, char **argv )
{
	istc_conf_qos_device_bandwidth_t list[ISTC_QOS_DEVICE_LIST_MAX];
	int count = ISTC_QOS_DEVICE_LIST_MAX;
	int i;
		
	if (istc_qos_get_device_bandwidth_list(list, &count) != 0) {
        printf("qos get device bandwidth list failed\n");
        return -1;
    }

	printf("cli: get_device_bandwidth_list, count %d\n", count);

	for (i=0; i<count; i++) {
		printf("cli: %02x:%02x:%02x:%02x:%02x:%02x %d %d\n",
			list[i].mac[0], list[i].mac[1], list[i].mac[2], list[i].mac[3], list[i].mac[4], list[i].mac[5],
			list[i].download_kbyte, list[i].upload_kbyte);
	}

    return 0;	
}


int cmd_handle_lan_set_addr_info(cmd_t * this, int argc, char **argv)
{
    int ret = -1;
    unsigned int gateway, start, end;
    
    if(argc < 3)
    {
        printf("%s %d:input set_addr_info gateway start end\n", __FUNCTION__, __LINE__);
        return -1;
    }

    istc_inet_atoh(argv[0], &gateway);
    istc_inet_atoh(argv[1], &start);
    istc_inet_atoh(argv[2], &end);

    ret = istc_lan_set_addr_info(gateway, start, end);
    printf("%s %d:ret = %d\n", __FUNCTION__, __LINE__, ret);
    
    return ret;
}

int cmd_handle_lan_get_addr_info(cmd_t * this, int argc, char **argv)
{
    int ret = -1;
    unsigned int Gateway, Start, End;
    char gateway[32] = {0}, start[32] = {0}, end[32] = {0};

    if((ret = istc_lan_get_addr_info(&Gateway, &Start, &End)) != 0)
    {
        printf("%s %d:can not get lan addr info\n", __FUNCTION__, __LINE__);
        return -1;
    }
    
    istc_inet_htoa(Gateway, gateway, sizeof(gateway));
    istc_inet_htoa(Start, start, sizeof(start));
    istc_inet_htoa(End, end, sizeof(end));
    printf("%s %d:gateway:%s, start:%s, end:%s\n", __FUNCTION__, __LINE__, gateway, start, end);
    
    return ret;
}
