
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
  iSTC(Inspur Safe Token Center) istc type definition and function prototype

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
01a,18Jun2014,xiongdb@inspur.com           written
*/

#ifndef __ISTC_H
#define __ISTC_H

#define ISTC_USE_SNMP
/* the interface name (e.g. eth0, wlan0 etc) max size */
#define ISTC_IFNAME_SIZE		16  /*(IF_NAMESIZE) */

#define ISTC_IFNAME_ALL			"all"

/* the max ssid allowed to config per station */
#define ISTC_STA_SSID_LIST_MAX	16

/* the max ssid allowed to config per access point */
#define ISTC_AP_SSID_LIST_MAX	(8) /*the max ssid num than ui need*/
#define ISTC_AP_INTERFACE_SSID_MAX (8) /*the max ssid numbrs on one interface*/

/* the max  count of interfaces supported */
#define ISTC_INTERFACE_MAX		16

/* the max count of dhcp address pools supported */
#define ISTC_DHCP_POOL_MAX		ISTC_INTERFACE_MAX

/* the ssid name max size (bytes) */
#define ISTC_SSID_NAME_SIZE			32
#define ISTC_SSID_NAME_STRLEN_MAX	31

/* the password max size (bytes) */
#define ISTC_SSID_PSWD_SIZE		32

/* the host name max size (bytes) used in DHCP */
#define ISTC_HOST_NAME_SIZE		32


#define ISTC_DHCP_LEASE_MIN			1
#define ISTC_DHCP_LEASE_DEFAULT		24

/* the DHCP address pool name max size (bytes) */
#define ISTC_DHCP_POOL_NAME_SIZE	16


#define ISTC_WIRELESS_MAC_ACCEPT_MAX	16
#define ISTC_WIRELESS_MAC_DENY_MAX		16

#define ISTC_PPPOE_USERNAME_SIZE	32
#define ISTC_PPPOE_PASSWORD_SIZE	32


#define ISTC_PING_SIZE_DEFAULT		64
#define ISTC_PING_SIZE_MAX			4096

#define ISTC_PING_COUNT_MAX			20000
#define ISTC_PING_COUNT_DEFAULT		4
#define ISTC_PING_PKT_SIZE_MAX		(ISTC_PING_SIZE_MAX - 8 - 20)
#define ISTC_PING_PKT_SIZE_DEFAULT	64
#define ISTC_PING_IP_TTL_MAX		255
#define ISTC_PING_IP_TTL_MIN		1
#define ISTC_PING_IP_TTL_DEFAULT	64
#define ISTC_PING_INTERVAL_MAX		60
#define ISTC_PING_INTERVAL_MIN		1
#define ISTC_PING_INTERVAL_DEFAULT	2
#define ISTC_PING_TIMEOUT_MAX		60
#define ISTC_PING_TIMEOUT_MIN		ISTC_PING_INTERVAL_MIN
#define ISTC_PING_TIMEOUT_DEFAULT	8
#define ISTC_PING_FLAG_ASYNC        (1)

#define ISTC_DHCP_OPTION60_SIZE		32

#define ISTC_WIRELESS_CHANNEL_DEFAULT   11

#define ISTC_QOS_DEVICE_LIST_MAX		24

enum {
    __ISTC_ERR_NONE = 0,
    __ISTC_SUCCESS = __ISTC_ERR_NONE,
    __ISTC_FAILED,
    __ISTC_ERR_ARGUMENT,
    __ISTC_ERR_MEMORY,
    __ISTC_ERR_ACCESS,
    __ISTC_ERR_UNSUPPORT,
    __ISTC_ERR_EXIST,
    __ISTC_ERR_TIMEOUT,
    __ISTC_ERR_BUSY,
    __ISTC_ERR_INPROGRESS,
    __ISTC_ERR_LOCK_FAIL,
    __ISTC_ERR_UNLOCK_FAIL,
    __ISTC_ERR_NOT_INSTANCE,
    __ISTC_ERR_NOT_FOUND,
    __ISTC_ERR_FULL,

    __ISTC_ERR_UNKNOWN,
};

typedef enum istc_error_code_e {
    ISTC_ERR_NONE = -__ISTC_ERR_NONE,
    ISTC_SUCCESS = -__ISTC_SUCCESS,
    ISTC_FAILED = -__ISTC_FAILED,
    ISTC_ERR_ARGUMENT = -__ISTC_ERR_ARGUMENT,
    ISTC_ERR_MEMORY = -__ISTC_ERR_MEMORY,
    ISTC_ERR_ACCESS = -__ISTC_ERR_ACCESS,
    ISTC_ERR_UNSUPPORT = -__ISTC_ERR_UNSUPPORT,
    ISTC_ERR_EXIST = -__ISTC_ERR_EXIST,
    ISTC_ERR_TIMEOUT = -__ISTC_ERR_TIMEOUT,
    ISTC_ERR_BUSY = -__ISTC_ERR_BUSY,
    ISTC_ERR_INPROGRESS = -__ISTC_ERR_INPROGRESS,
    ISTC_ERR_LOCK_FAIL = -__ISTC_ERR_LOCK_FAIL,
    ISTC_ERR_UNLOCK_FAIL = -__ISTC_ERR_UNLOCK_FAIL,
    ISTC_ERR_NOT_INSTANCE = -__ISTC_ERR_NOT_INSTANCE,
    ISTC_ERR_NOT_FOUND = -__ISTC_ERR_NOT_FOUND,
    ISTC_ERR_FULL = - __ISTC_ERR_FULL,


    ISTC_ERR_UNKNOWN = -__ISTC_ERR_UNKNOWN,
} istc_error_code_t;

enum {
    ISTC_WIRELESS_MODE_NONE = 0,
    ISTC_WIRELESS_MODE_STA,
    ISTC_WIRELESS_MODE_AP,

    ISTC_WIRELESS_MODE_MAX
};
enum {
    ISTC_INTERFACE_ADDR_MODE_UNKNOWN = 0,   /* space holder and error check */
    ISTC_INTERFACE_ADDR_MODE_STATIC,    /* static and manual config */
    ISTC_INTERFACE_ADDR_MODE_DHCP,  /* use DHCP to dynamic alloc address */
    ISTC_INTERFACE_ADDR_MODE_PPPOE, /* use PPPoE to alloc address */
	ISTC_INTERFACE_ADDR_MODE_LAN, /* LAN mode for network share */

    ISTC_INTERFACE_ADDR_MODE_MAX    /* space holder and error check */
};


enum {
    ISTC_LINK_ADMIN_STATE_DOWN = 0, /* interface admin down */
    ISTC_LINK_ADMIN_STATE_UP,   /* interface admin up */

    ISTC_LINK_STATE_DOWN,       /* link is DOWN now */
    ISTC_LINK_STATE_UP,         /* link is DOWN now */

    ISTC_LINK_STATE_MAX         /* space holder and error check */
};



typedef struct istc_sta_ssid_s {
    char ssid[ISTC_SSID_NAME_SIZE]; /* SSID name also known as ESSID */
    char mac[24];               /* AP MAC address also known as BSSID (in text and with '\0' terminated) */
    int channel;                /* channel */
    int signal;                 /* signal level or RSSI */
    int encryption;             /* encryption type */
} istc_sta_ssid_t;

enum {
    ISTC_WIRELESS_ENCRYPTION_NONE = 0,  /* space holder and error check */
    ISTC_WIRELESS_ENCRYPTION_OPEN,  /* open */
    ISTC_WIRELESS_ENCRYPTION_WEP,   /* wep (not supported) */
    ISTC_WIRELESS_ENCRYPTION_WPA,   /* wpa version 1 */
    ISTC_WIRELESS_ENCRYPTION_WPA2,  /* wpa version 2 */
    ISTC_WIRELESS_ENCRYPTION_WPA_WPA2,  /* both wpa version 1 and version 2 */

    ISTC_WIRELESS_ENCRYPTION_MAX    /* space holder and error check */
};

enum {
    ISTC_WIRELESS_STA_STATE_UNKNOWN = ISTC_LINK_STATE_MAX + 1,  /* == 5 space holder and error check */
    ISTC_WIRELESS_STA_STATE_INACTIVE,   /* inactive */
    ISTC_WIRELESS_STA_STATE_SCANNING,   /* scanning */
    ISTC_WIRELESS_STA_STATE_CONNECTING, /* connecting (authentication and association) */
    ISTC_WIRELESS_STA_STATE_CONNECTED,  /* connected */
    ISTC_WIRELESS_STA_STATE_DISCONNECTED,   /* disconnected */
    ISTC_WIRELESS_STA_STATE_DISABLED,   /* interface was disabled */

    ISTC_WIRELESS_STA_STATE_MAX /* space holder and error check */
};


enum {
	ISTC_DATA_LINK_VALID = ISTC_WIRELESS_STA_STATE_MAX + 1,
	ISTC_DATA_LINK_INVALID,
	ISTC_DATA_LINK_IN_USE,

	ISTC_DATA_LINK_MAX
};

enum {
    ISTC_AP_SSID_2DOT4G = 0,
    ISTC_AP_SSID_5G,
    ISTC_AP_GUEST_SSID_2DOT4G,
    ISTC_AP_GUEST_SSID_5G,
    ISTC_AP_SSID_TYPE_MAX
};

typedef struct istc_ap_ssid_s {
    int index;
    int b_disable;
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE]; /* SSID name, also known as ESSID */
    char password[ISTC_SSID_PSWD_SIZE]; /* password */
    int encryption;             /* entryption type */
    int channel;                /* radio channel */
    int b_hidden;
    int band;
    int b_visitor;
} istc_ap_ssid_t;



typedef struct istc_ap_sta_s {
    char sta_name[ISTC_HOST_NAME_SIZE]; /* station host name */
    unsigned int sta_ip;        /* station ip address */
    unsigned char sta_mac[6];   /* station mac address */
    unsigned char padding[2];   /* not used just for alignment now */
    unsigned int up_ceil_rate_kbyte;
    unsigned int up_flow_kbyte;
    unsigned int down_ceil_rate_kbyte;
    unsigned int down_flow_kbyte;
    unsigned int up_nowtime_ms;
    unsigned int down_nowtime_ms;
} istc_ap_sta_t;




typedef struct istc_dhcp_pool_s {
    char name[ISTC_DHCP_POOL_NAME_SIZE];    /* optional pool name */
    char interface[ISTC_IFNAME_SIZE];   /* optional interface name */
    unsigned int start;         /* pool start address */
    unsigned int end;           /* pool end address */
    unsigned int mask;          /* pool net mask */
    unsigned int lease;         /* pool lease duration */
    unsigned int gateway;       /* pool gateway address */
    unsigned int primary_dns;   /* primary dns address */
    unsigned int secondary_dns; /* secondary dns address */
} istc_dhcp_pool_t;

typedef struct istc_dhcp_lease_s {
    char host_name[ISTC_HOST_NAME_SIZE];    /*optional host readable name */
    unsigned int host_ip;       /* host allocated ip address */
    unsigned char host_mac[6];  /* host mac address */
    unsigned short resv;        /* reserved, just for alignment now */
    unsigned int host_lease;    /* lease */
} istc_dhcp_lease_t;




typedef struct istc_link_change_s {
    char ifname[ISTC_IFNAME_SIZE];  /* changed interface */
    int change_to;              /* changed state */
    void *data;                 /* user data */
} istc_link_change_t;


enum {
    ISTC_ACL_MAC_MODE_DISABLE,  /* the mac acl is disabled */
    ISTC_ACL_MAC_MODE_DENY,     /* the mac(s) in list will be forbid(deny) access to this AP */
    ISTC_ACL_MAC_MODE_ACCEPT,   /* only mac(s) in the list are permit(accept) to access to this AP */

    ISTC_ACL_MAC_MODE_MAX
};


enum {
    ISTC_PPPOE_STATE_ETHDOWN = ISTC_WIRELESS_STA_STATE_MAX + 1,
    ISTC_PPPOE_STATE_NOTINIT,
    ISTC_PPPOE_STATE_DISCONNECTED,
    ISTC_PPPOE_STATE_CONNECTED,
    ISTC_PPPOE_STATE_CONNECTING,

    ISTC_PPPOE_STATE_MAX
};


typedef struct istc_ping_para_s {
    char host[ISTC_HOST_NAME_SIZE]; /* the ping target host name or IPv4 address */
    int count;                  /* total icmp echo request packets to send */
    int interval;               /* the interval of each packet to send */
    int pkt_size;               /* each request packet size (icmp payload size) */
    int ip_ttl;                 /* each request packet IP TTL */
    int timeout;                /* the max time to wait ICMP response */
    int fragment;               /* allow to fragment the packet, (0 to enable, 1 disable) */
    char interface[ISTC_IFNAME_SIZE];   /* the source interface to send packet from */
    unsigned int src_addr;      /* the source IPv4 address to send packet from */
} istc_ping_para_t;

typedef struct istc_ping_result_s {
    int rtt_min;                /* the min rtt (ms) */
    int rtt_max;                /* the max rtt (ms) */
    int rtt_avg;                /* the average rtt (ms) */
    int time;                   /* total time cost by ping (ms) */
    int send;                   /* total ping request packet sent */
    int recv;                   /* total ping  response packet received */
} istc_ping_result_t;


enum {
    ISTC_INTERFACE_TYPE_NONE = 0,

    ISTC_INTERFACE_TYPE_WIRED,
    ISTC_INTERFACE_TYPE_WIRELESS,

    ISTC_INTERFACE_TYPE_MAX
};


enum {
	ISTC_QOS_MODE_NONE = 0,
    ISTC_QOS_MODE_DISABLE,
	ISTC_QOS_MODE_ENABLE,

	ISTC_QOS_MODE_MAX
};


typedef struct istc_conf_qos_device_bandwidth_s {
	int download_kbyte;
	int upload_kbyte;
	unsigned char mac[6];
	short b_used;
} istc_conf_qos_device_bandwidth_t;


/* the istc protocol definition move to here, because all module need the command value */
enum {
    ISTC_CLASS_ASYNC_CMD_NONE = 0,

    ISTC_CLASS_ASYNC_CMD_REGISTER,
    ISTC_CLASS_ASYNC_CMD_UNREGISTER,
    
    ISTC_CLASS_ASYNC_CMD_DHCP,
    ISTC_CLASS_ASYNC_CMD_PPPOE,
    ISTC_CLASS_ASYNC_CMD_STATIC,

    ISTC_CLASS_ASYNC_CMD_PING,

    ISTC_CLASS_ASYNC_CMD_STA_SCAN,
    ISTC_CLASS_ASYNC_CMD_STA_ENABLE,
    ISTC_CLASS_ASYNC_CMD_STA_DISABLE,
    
    ISTC_CLASS_ASYNC_CMD_AP_ENABLE,
    ISTC_CLASS_ASYNC_CMD_AP_DISABLE,

    ISTC_CLASS_ASYNC_CMD_MAX
};

typedef struct istc_class_async_dhcp_s {
    char ifname[ISTC_IFNAME_SIZE];
    int result;
} istc_class_async_dhcp_t;

typedef struct istc_class_async_pppoe_s {
    char ifname[ISTC_IFNAME_SIZE];
    int result;
} istc_class_async_pppoe_t;

typedef struct istc_class_async_static_s {
    char ifname[ISTC_IFNAME_SIZE];
    int result;
} istc_class_async_static_t;

typedef struct istc_class_async_ping_s {
    istc_ping_para_t para;
    istc_ping_result_t result;
} istc_class_async_ping_t;


typedef struct istc_class_async_sta_scan_s {
    char ifname[ISTC_IFNAME_SIZE];
    int result;
    int cnt;
    //istc_sta_ssid_t list[0];    /* NOTE : the ISO C++, not support zero size array */
} istc_class_async_sta_scan_t;

typedef struct istc_class_async_sta_ssid_enable_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    int result;
} istc_class_async_sta_ssid_enable_t;

typedef istc_class_async_sta_ssid_enable_t istc_class_async_sta_ssid_disable_t;

typedef struct istc_class_async_ap_ssid_enable_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    int result;
} istc_class_async_ap_ssid_enable_t;

typedef istc_class_async_ap_ssid_enable_t istc_class_async_ap_ssid_disable_t;






/* end ISTC protocol definitions */


typedef void (*istc_async_callback_t)(int command, const void *data, int size);


unsigned int istc_now_time_ms(void);


/* start istc prototype */

/* IP address class */
int istc_interface_ipaddr_get(const char *ifname, unsigned int *ipaddr);

int istc_interface_netmask_get(const char *ifname, unsigned int *netmask);

int istc_interface_addr_mode_get(const char *ifname, int *mode);

int istc_interface_ipaddr_set(const char *ifname, unsigned int ipaddr);

int istc_interface_netmask_set(const char *ifname, unsigned int netmask);

int istc_interface_addr_mode_set(const char *ifname, int mode);


/* MAC address class */
int istc_interface_mac_get(const char *ifname, unsigned char *mac);

int istc_interface_mac_set(const char *ifname, const unsigned char *mac);

int istc_interface_totalflow_get(const char *ifname, unsigned int *up_flow, unsigned int *down_flow);



/* link class */
int istc_link_state_get(const char *ifname, int *state);

int istc_link_speed_get(const char *ifname, int *speed);

int istc_link_admin_state_get(const char *ifname, int *state);

int istc_link_mode_get(const char *ifname, int *mode);

int istc_link_mtu_get(const char *ifname, int *mtu);

int istc_link_admin_state_set(const char *ifname, int state);

int istc_link_change_register(const char *ifname,
                              void (*callback) (const istc_link_change_t *
                                                link), void *data);

int istc_link_change_unregister(const char *ifname,
                                void (*callback) (const istc_link_change_t *
                                                  link));

int istc_async_callback_register(istc_async_callback_t callback);

int istc_async_callback_unregister(istc_async_callback_t callback);



/* WIFI STAtion class */
int istc_wireless_sta_ssid_scan(const char *ifname);

int istc_wireless_sta_scan_result_get(const char *ifname,
                                      istc_sta_ssid_t * result, int *pcnt);

int istc_wireless_sta_state_get(const char *ifname, int *state,
                                istc_sta_ssid_t * ssid);

int istc_wireless_sta_ssid_add(const char *ifname, const char *ssid,
                               const char *password);

int istc_wireless_sta_ssid_add2(const char *ifname, const char *ssid,
                                const char *password, int encryption);

int istc_wireless_sta_ssid_remove(const char *ifname, const char *ssid);

int istc_wireless_sta_ssid_disable(const char *ifname, const char *ssid);

int istc_wireless_sta_ssid_enable(const char *ifname, const char *ssid);

int istc_async_wireless_sta_ssid_enable(const char *ifname, const char *ssid);

int istc_async_wireless_sta_ssid_disable(const char *ifname, const char *ssid);

int istc_async_wireless_sta_ssid_scan(const char *ifname);



/* WIFI AP class */
int istc_init_snmp_wifissid(void);

int istc_init(void);

int istc_wireless_ap_ssid_add_by_index(const char *ifname, int index, const istc_ap_ssid_t * ssid);//todo

int istc_wireless_ap_ssid_get_by_index(const char *ifname, int index, istc_ap_ssid_t * ssid);//todo

int istc_wireless_ap_ssid_set_by_index(const char *ifname, int index, const istc_ap_ssid_t * ssid);//todo

int istc_wireless_ap_ssid_remove_by_index(const char *ifname, int index);//todo

int istc_wireless_ap_get_ssids_num(int *num);

int istc_wireless_ap_ssid_get(const char *ifname, istc_ap_ssid_t * ssid,
                              int *count);


//todo, old interface, need remove!
int istc_wireless_ap_ssid_add(const char *ifname, const istc_ap_ssid_t * ssid);
int istc_wireless_ap_ssid_remove(const char *ifname, const char *ssid);
int istc_wireless_ap_ssid_enable(const char *ifname, const char *ssid);
int istc_wireless_ap_ssid_disable(const char *ifname, const char *ssid);
int istc_async_wireless_ap_ssid_enable(const char *ifname, const char *ssid);
int istc_async_wireless_ap_ssid_disable(const char *ifname, const char *ssid);


int istc_wireless_ap_ssid_sta_get(const char *ifname, const char *ssid,
                                  istc_ap_sta_t * sta, int *count);

int istc_wireless_ap_ssid_mac_accept_get(const char *ifname, const char *ssid,
                                         unsigned char list[][6], int *count);

int istc_wireless_ap_ssid_mac_accept_add(const char *ifname, const char *ssid,
                                         unsigned char *mac);

int istc_wireless_ap_ssid_mac_accept_remove(const char *ifname,
                                            const char *ssid,
                                            unsigned char *mac);

int istc_wireless_ap_ssid_mac_deny_get(const char *ifname, const char *ssid,
                                       unsigned char list[][6], int *count);

int istc_wireless_ap_ssid_mac_deny_add(const char *ifname, const char *ssid,
                                       unsigned char *mac);

int istc_wireless_ap_ssid_mac_deny_remove(const char *ifname, const char *ssid,
                                          unsigned char *mac);

int istc_wireless_ap_ssid_mac_acl_get(const char *ifname, const char *ssid,
                                      int *mode);

int istc_wireless_ap_ssid_mac_acl_set(const char *ifname, const char *ssid,
                                      int mode);



/* DHCP class */

int istc_dhcpc_option60_add(const char *ifname, const char *data);
int istc_dhcpc_option60_remove(const char *ifname);
int istc_dhcpc_option60_s_add(const char *ifname, const char *data);
int istc_dhcpc_option60_s_remove(const char *ifname);


//todo, user do not care, need remove! 
int istc_dhcp_pool_get(istc_dhcp_pool_t * pool, int *count);
int istc_dhcp_lease_get(istc_dhcp_lease_t * lease, int *count);
int istc_dhcp_pool_add(const istc_dhcp_pool_t * pool);
int istc_dhcp_pool_remove(unsigned int start, unsigned int end);
int istc_dhcp_pool_remove_by_name(const char *name);
int istc_dhcpc_start(const char *ifname);
int istc_dhcpc_stop(const char *ifname);
int istc_dhcpc_restart(const char *ifname);



/* ROUTE class */

int istc_route_state_get(int *state);
int istc_route_state_set(int state);
int istc_route_default_get(const char *ifname, unsigned int *gateway);
int istc_route_default_set(const char *ifname, unsigned int gateway);




/* DNS class */
int istc_dns_address_get(unsigned int *primary, unsigned int *secondary);
int istc_dns_address_set(unsigned int primary, unsigned int secondary);


/* PPPoE class */
int istc_pppoe_config_get(const char *ifname, char *username, char *password);
int istc_pppoe_state(const char *ifname, int *state);
int istc_pppoe_config_set(const char *ifname, char *username, char *password);
int istc_pppoe_connect(const char *ifname);
int istc_pppoe_disconnect(const char *ifname);

int istc_async_pppoe_connect(const char *ifname);


/* QOS class */
int istc_qos_set_mode(int mode);
int istc_qos_get_mode(int *mode);
int istc_qos_set_device_bandwidth(const unsigned char *mac, int download_kbyte, int upload_kbyte);
int istc_qos_get_device_bandwidth(const unsigned char *mac, int *download_kbyte, int *upload_kbyte);
int istc_qos_get_device_bandwidth_list(istc_conf_qos_device_bandwidth_t *list, int *count);


/* LAN class */
//todo
int istc_lan_set_addr_info(unsigned int gateway, unsigned int addr_begin, unsigned int addr_end);
int istc_lan_get_addr_info(unsigned int *gateway, unsigned int *addr_begin, unsigned int *addr_end);


/* others */
int istc_server_addr_set(unsigned int addr);
int istc_server_addr_get(unsigned int *addr);
int istc_server_port_set(unsigned short port);



int istc_misc_config_save(void);

/* NOTE: this function may blocked long time */
int istc_ping(const istc_ping_para_t * para, istc_ping_result_t * result);
/* async ping */
int istc_async_ping(const istc_ping_para_t * para);


int istc_interface_list_get(char list[][ISTC_IFNAME_SIZE], int *count);

int istc_interface_type_get(const char *ifname, int *type);

int istc_log_level_get(int *level);

int istc_log_level_set(int level);

int istc_wireless_mode_get(const char *ifname, int *mode);


/* end istc prototype */

const char *istc_inet_ntoa(unsigned int ip, char *buff, int size);
const char *istc_inet_htoa(unsigned int host, char *buff, int size);
int istc_inet_aton(const char *str, unsigned int *ip);
int istc_inet_atoh(const char *str, unsigned int *ip);

int istc_str2mac(const char *str, unsigned char *mac);

const char *istc_errstr(int err);


/* the following pragma instruction to avoid marco varargs when compile by g++ */
#define DERROR(fmt, ...) \
	do { fprintf(stderr, "[istcc] @error %s %d %s [%s] :" fmt, __FILE__, __LINE__, __FUNCTION__, (strerror(errno)), ##__VA_ARGS__); } while (0)


#define DPRINT(fmt, ...) \
	do { fprintf(stderr, "[istcc] @debug %s %d %s :" fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); } while (0)

#define DPRINT0(str) \
	do { fprintf(stderr, "[istcc] @debug %s %d %s :" str, __FILE__, __LINE__, __FUNCTION__); } while (0)

#define SURE_STR(str) \
		if (!(str) || !(*(str))) { DPRINT("%s == NULL, return\n", #str); return -1; }

#define SURE_PTR(ptr) \
		if (!(ptr)) { DPRINT("%s is NULL, return\n", #ptr); return -1; }


#endif
