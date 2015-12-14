
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
  iSTC(Inspur Safe Token Center) istc protocol definition

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
01a,04Jul2014,xiongdb@inspur.com           written
*/

#ifndef __ISTC_PROTOCOL_H
#define __ISTC_PROTOCOL_H

#include "istc.h"

/* ISTC protocol definitions */
#define ISTC_DEFAULT_PORT		55555

#define ISTC_PROTOCOL_VERSION            1

#define ISTC_MSG_TYPE_REQUEST		0
#define ISTC_MSG_TYPE_RESPONSE		1
#define ISTC_MSG_TYPE_NOTIFY		2
#define ISTC_MSG_TYPE_ASYNC		    3


/* istc protocol head, make it 4 bytes aligned */
typedef struct istc_head_s {
    unsigned char version;
    unsigned char type;
    unsigned short length;

    int rc;                     /* response code */

    unsigned int seq;
    unsigned short class;
    unsigned short command;
    unsigned int checksum;

    unsigned char data[0];
} istc_head_t;




enum {
    ISTC_CLASS_NONE = 0,        /* class 0 */
    ISTC_CLASS_IP,              /* class 1 */
    ISTC_CLASS_MAC,             /* class 2 */
    ISTC_CLASS_LINK,            /* class 3 */
    ISTC_CLASS_STA,             /* class 4 */
    ISTC_CLASS_AP,              /* class 5 */
    ISTC_CLASS_DNS,             /* class 6 */
    ISTC_CLASS_DNSS,            /* class 7 */
    ISTC_CLASS_DHCPS,           /* class 8 */
    ISTC_CLASS_PPPOE,           /* class 9 */
    ISTC_CLASS_ARP,             /* class 10 */
    ISTC_CLASS_ROUTE,           /* class 11 */
    ISTC_CLASS_NAT,             /* class 12 */
    ISTC_CLASS_FIREWALL,        /* class 13 */
    ISTC_CLASS_MISC,            /* class 14 */

    ISTC_CLASS_NOTIFY,          /* class 15 */

    ISTC_CLASS_ASYNC,           /* class 16 */
	ISTC_CLASS_QOS,				/* class 17 */
	
    ISTC_CLASS_LAN,                 /* class 18 */

    ISTC_CLASS_MAX
};


enum {
    ISTC_CLASS_IP_CMD_NONE = 0,
    ISTC_CLASS_IP_CMD_GET_IPADDR,
    ISTC_CLASS_IP_CMD_GET_NETMASK,
    ISTC_CLASS_IP_CMD_GET_ADDR_MODE,
    ISTC_CLASS_IP_CMD_SET_IPADDR,
    ISTC_CLASS_IP_CMD_SET_NETMASK,
    ISTC_CLASS_IP_CMD_SET_ADDR_MODE,

    ISTC_CLASS_IP_CMD_MAX
};

typedef struct istc_class_ip_cmd_data_s {
    char ifname[ISTC_IFNAME_SIZE];
    union {
        unsigned int ipaddr;
        unsigned int netmask;
        int addr_mode;
    } u;
} istc_class_ip_cmd_data_t;


enum {
    ISTC_CLASS_MAC_CMD_NONE = 0,
    ISTC_CLASS_MAC_CMD_GET_MAC,
    ISTC_CLASS_MAC_CMD_SET_MAC,

    ISTC_CLASS_MAC_CMD_MAX
};


typedef struct istc_class_mac_cmd_data_s {
    char ifname[ISTC_IFNAME_SIZE];
    union {
        unsigned char mac[8];
    } u;
} istc_class_mac_cmd_data_t;


typedef struct istc_class_link_cmd_data_s {
    char ifname[ISTC_IFNAME_SIZE];
    int data;
} istc_class_link_cmd_data_t;



enum {
    ISTC_CLASS_LINK_CMD_NONE = 0,
    ISTC_CLASS_LINK_CMD_GET_LINK_STATE,
    ISTC_CLASS_LINK_CMD_GET_LINK_SPEED,
    ISTC_CLASS_LINK_CMD_GET_ADMIN_STATE,
    ISTC_CLASS_LINK_CMD_GET_LINK_MODE,
    ISTC_CLASS_LINK_CMD_GET_LINK_MTU,
    ISTC_CLASS_LINK_CMD_SET_ADMIN_STATE,

    ISTC_CLASS_LINK_CMD_MAX
};





enum {
    ISTC_CLASS_STA_CMD_NONE = 0,
    ISTC_CLASS_STA_CMD_SCAN,
    ISTC_CLASS_STA_CMD_GET_SCAN_RESULT,
    ISTC_CLASS_STA_CMD_GET_STATE,
    ISTC_CLASS_STA_CMD_ADD_SSID,
    ISTC_CLASS_STA_CMD_ADD2_SSID,
    ISTC_CLASS_STA_CMD_REMOVE_SSID,
    ISTC_CLASS_STA_CMD_ENABLE_SSID,
    ISTC_CLASS_STA_CMD_DISABLE_SSID,

    ISTC_CLASS_STA_CMD_SCAN_ASYNC,
    ISTC_CLASS_STA_CMD_ENABLE_SSID_ASYNC,
    ISTC_CLASS_STA_CMD_DISABLE_SSID_ASYNC,    

    ISTC_CLASS_STA_CMD_MAX
};



typedef struct istc_class_sta_scan_s {
    char ifname[ISTC_IFNAME_SIZE];
} istc_class_sta_scan_t;

typedef struct istc_class_sta_get_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    int cnt;
    istc_sta_ssid_t ssid[0];
} istc_class_sta_get_ssid_t;

typedef struct istc_class_sta_state_s {
    char ifname[ISTC_IFNAME_SIZE];
    int state;
    istc_sta_ssid_t ssid;
} istc_class_sta_state_t;

typedef struct istc_class_sta_add_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    char pswd[ISTC_SSID_PSWD_SIZE];
} istc_class_sta_add_ssid_t;

typedef struct istc_class_sta_add2_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    char pswd[ISTC_SSID_PSWD_SIZE];
    int encryption;
} istc_class_sta_add2_ssid_t;


typedef struct istc_class_sta_del_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
} istc_class_sta_del_ssid_t;



typedef struct istc_class_sta_enable_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
} istc_class_sta_enable_ssid_t;

typedef istc_class_sta_enable_ssid_t istc_class_sta_disable_ssid_t;


enum {
    ISTC_CLASS_AP_CMD_NONE = 0, /* 0 */
    ISTC_CLASS_AP_CMD_GET_SSID, /* 1 */
    ISTC_CLASS_AP_CMD_GET_SSID_STA, /* 2 */
    ISTC_CLASS_AP_CMD_ADD_SSID, /* 3 */
    ISTC_CLASS_AP_CMD_REMOVE_SSID,  /* 4 */
    ISTC_CLASS_AP_CMD_ENABLE_SSID,  /* 5 */
    ISTC_CLASS_AP_CMD_DISABLE_SSID, /* 6 */
    ISTC_CLASS_AP_CMD_GET_MAC_ACCEPT,   /* 7 */
    ISTC_CLASS_AP_CMD_ADD_MAC_ACCEPT,   /* 8 */
    ISTC_CLASS_AP_CMD_REMOVE_MAC_ACCEPT,    /* 9 */
    ISTC_CLASS_AP_CMD_GET_MAC_DENY, /* 10 */
    ISTC_CLASS_AP_CMD_ADD_MAC_DENY, /* 11 */
    ISTC_CLASS_AP_CMD_REMOVE_MAC_DENY,  /* 12 */
    ISTC_CLASS_AP_CMD_GET_MAC_ACL,  /* 13 */
    ISTC_CLASS_AP_CMD_SET_MAC_ACL,  /* 14 */

    ISTC_CLASS_AP_CMD_ENABLE_SSID_ASYNC,  /* 15 */
    ISTC_CLASS_AP_CMD_DISABLE_SSID_ASYNC, /* 16 */

	ISTC_CLASS_AP_CMD_REMOVE_SSID_BY_INDEX,

    ISTC_CLASS_AP_CMD_MAX
};

enum {
    ISTC_CLASS_DNS_CMD_NONE = 0,
    ISTC_CLASS_DNS_CMD_GET_DNS,
    ISTC_CLASS_DNS_CMD_SET_DNS,

    ISTC_CLASS_DNS_CMD_MAX
};




typedef struct istc_class_ap_get_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    int cnt;
    istc_ap_ssid_t ssid[0];
} istc_class_ap_get_ssid_t;

typedef struct istc_class_ap_get_sta_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    int cnt;
    istc_ap_sta_t sta[0];
} istc_class_ap_get_sta_t;


typedef struct istc_class_ap_add_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    istc_ap_ssid_t ssid;
} istc_class_ap_add_ssid_t;


typedef struct istc_class_ap_remove_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
} istc_class_ap_remove_ssid_t;

typedef struct istc_class_ap_remove_ssid_by_index_s {
    char ifname[ISTC_IFNAME_SIZE];
    int index;
} istc_class_ap_remove_ssid_by_index_t;

typedef struct istc_class_ap_enable_ssid_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
} istc_class_ap_enable_ssid_t;

typedef istc_class_ap_enable_ssid_t istc_class_ap_disable_ssid_t;

struct istc_class_ap_get_mac_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    int cnt;
    unsigned char list[0][6];
} __attribute__ ((aligned(1)));

typedef struct istc_class_ap_get_mac_s istc_class_ap_get_mac_t;

typedef struct istc_class_ap_mac_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    unsigned char mac[8];
} istc_class_ap_mac_t;

typedef struct istc_class_ap_mac_acl_s {
    char ifname[ISTC_IFNAME_SIZE];
    char ssid[ISTC_SSID_NAME_SIZE];
    int mode;
} istc_class_ap_mac_acl_t;


enum {
    ISTC_CLASS_DHCPS_CMD_NONE = 0,
    ISTC_CLASS_DHCPS_CMD_GET_POOL,
    ISTC_CLASS_DHCPS_CMD_GET_LEASE,
    ISTC_CLASS_DHCPS_CMD_ADD_POOL,
    ISTC_CLASS_DHCPS_CMD_REMOVE_POOL,
    ISTC_CLASS_DHCPC_CMD_ADD_OPT60,
    ISTC_CLASS_DHCPC_CMD_REMOVE_OPT60,
    ISTC_CLASS_DHCPC_CMD_ADD_OPT60_S,
    ISTC_CLASS_DHCPC_CMD_REMOVE_OPT60_S,
    ISTC_CLASS_DHCPS_CMD_REMOVE_POOL_BY_NAME,
    
    ISTC_CLASS_DHCPS_CMD_MAX
};



typedef struct istc_class_dhcp_get_lease_s {
    int cnt;
    istc_dhcp_lease_t lease[0];
} istc_class_dhcp_get_lease_t;


typedef struct istc_class_dhcp_get_pool_s {
    int cnt;
    istc_dhcp_pool_t pool[0];
} istc_class_dhcp_get_pool_t;

typedef struct istc_class_dhcp_remove_pool_s {
    unsigned int start;
    unsigned int end;
} istc_class_dhcp_remove_pool_t;

typedef struct istc_class_dhcp_remove_pool_by_name_s {
    char name[ISTC_DHCP_POOL_NAME_SIZE];
} istc_class_dhcp_remove_pool_by_name_t;


typedef struct istc_class_dhcp_add_opt60_s {
    char ifname[ISTC_IFNAME_SIZE];
    char data[ISTC_DHCP_OPTION60_SIZE];
} istc_class_dhcp_add_opt60_t;

typedef struct istc_class_dhcp_remove_opt60_s {
    char ifname[ISTC_IFNAME_SIZE];
} istc_class_dhcp_remove_opt60_t;

typedef istc_class_dhcp_add_opt60_t istc_class_dhcp_add_opt60_s_t;

typedef istc_class_dhcp_remove_opt60_t istc_class_dhcp_remove_opt60_s_t;

enum {
    ISTC_CLASS_NOTIFY_CMD_NONE = 0,
    ISTC_CLASS_NOTIFY_CMD_REGISTER_LINK_CHANGE,
    ISTC_CLASS_NOTIFY_CMD_UNREGISTER_LINK_CHANGE,

    ISTC_CLASS_NOTIFY_CMD_LINK_CHANGED,

    ISTC_CLASS_NOTIFY_CMD_MAX
};


typedef struct istc_link_notification_s {
    char ifname[ISTC_IFNAME_SIZE];
    int change_to;
} istc_link_notification_t;


enum {
    ISTC_CLASS_ROUTE_CMD_GET_NONE,
    ISTC_CLASS_ROUTE_CMD_GET_STATE,
    ISTC_CLASS_ROUTE_CMD_SET_STATE,
    ISTC_CLASS_ROUTE_CMD_GET_DEFAULT,
    ISTC_CLASS_ROUTE_CMD_SET_DEFAULT,

    ISTC_CLASS_ROUTE_CMD_MAX
};

typedef struct istc_class_route_get_state_s {
    int state;
} istc_class_route_get_state_t;

typedef istc_class_route_get_state_t istc_class_route_set_state_t;

typedef struct istc_class_route_get_default_s {
    char ifname[ISTC_IFNAME_SIZE];
    unsigned int gateway;
} istc_class_route_get_default_t;

typedef istc_class_route_get_default_t istc_class_route_set_default_t;


typedef struct istc_class_dns_get_dns_s {
    unsigned int primary;
    unsigned int secondary;
} istc_class_dns_get_dns_t;

typedef istc_class_dns_get_dns_t istc_class_dns_set_dns_t;


enum {
    ISTC_CLASS_MISC_CMD_NONE = 0,
    ISTC_CLASS_MISC_CMD_SAVE_CONFIG,
    ISTC_CLASS_MISC_CMD_PING,
    ISTC_CLASS_MISC_CMD_INTERFACE_LIST_GET,
    ISTC_CLASS_MISC_CMD_INTERFACE_TYPE_GET,
    ISTC_CLASS_MISC_CMD_GET_CONFIG,
    ISTC_CLASS_MISC_CMD_SET_CONFIG,
    ISTC_CLASS_MISC_CMD_GET_LOG_LV,
    ISTC_CLASS_MISC_CMD_SET_LOG_LV,
    ISTC_CLASS_MISC_CMD_PING_ASYNC,
    ISTC_CLASS_MISC_CMD_WIRELESS_MODE_GET,

    ISTC_CLASS_MISC_CMD_MAX
};

typedef struct istc_class_misc_cmd_wireless_mode_get_s {
    char ifname[ISTC_IFNAME_SIZE];
    int mode;
} istc_class_misc_cmd_wireless_mode_get_t ;

typedef struct istc_class_misc_cmd_interface_list_get_s {
    int cnt;
    char list[0][ISTC_IFNAME_SIZE];
} istc_class_misc_cmd_interface_list_get_t;

typedef struct istc_class_misc_cmd_interface_type_get_s {
    char ifname[ISTC_IFNAME_SIZE];
    int type;
} istc_class_misc_cmd_interface_type_get_t;


typedef struct istc_class_misc_cmd_log_lv_get_s {
    int level;
} istc_class_misc_cmd_log_lv_get_t;

typedef istc_class_misc_cmd_log_lv_get_t istc_class_misc_cmd_log_lv_set_t;

enum {
    ISTC_CLASS_PPPOE_CMD_NONE = 0,
    ISTC_CLASS_PPPOE_CMD_GET_CONFIG,
    ISTC_CLASS_PPPOE_CMD_GET_STATE,
    ISTC_CLASS_PPPOE_CMD_SET_CONFIG,
    ISTC_CLASS_PPPOE_CMD_CONNECT,
    ISTC_CLASS_PPPOE_CMD_DISCONNECT,
	ISTC_CLASS_PPPOE_CMD_ASYNC_CONNECT,

    ISTC_CLASS_PPPOE_CMD_MAX
};

typedef struct istc_class_pppoe_config_s {
    char ifname[ISTC_IFNAME_SIZE];
    char username[ISTC_PPPOE_USERNAME_SIZE];
    char password[ISTC_PPPOE_PASSWORD_SIZE];
} istc_class_pppoe_config_t;

typedef struct istc_class_pppoe_state_s {
    char ifname[ISTC_IFNAME_SIZE];
    int state;
} istc_class_pppoe_state_t;

typedef struct istc_class_pppoe_connect_s {
    char ifname[ISTC_IFNAME_SIZE];
} istc_class_pppoe_connect_t;

typedef struct istc_class_pppoe_disconnect_s {
    char ifname[ISTC_IFNAME_SIZE];
} istc_class_pppoe_disconnect_t;


enum {
    ISTC_CLASS_QOS_CMD_NONE = 0,
	ISTC_CLASS_QOS_CMD_SET_MODE,
	ISTC_CLASS_QOS_CMD_GET_MODE,
	ISTC_CLASS_QOS_CMD_SET_DEVICE_BANDWIDTH,
	ISTC_CLASS_QOS_CMD_GET_DEVICE_BANDWIDTH,
	ISTC_CLASS_QOS_CMD_GET_DEVICE_BANDWIDTH_LIST,

	ISTC_CLASS_QOS_CMD_MAX
};

typedef struct istc_class_qos_mode_s {
    int mode;
} istc_class_qos_mode_t;

typedef struct istc_class_qos_device_bandwidth_list_s {
    int cnt;
    istc_conf_qos_device_bandwidth_t list[0];
} istc_class_qos_device_bandwidth_list_t;


enum {
    ISTC_CLASS_LAN_CMD_NONE = 0,
    ISTC_CLASS_LAN_CMD_SET_ADDR_INFO,
    ISTC_CLASS_LAN_CMD_GET_ADDR_INFO,

    ISTC_CLASS_LAN_CMD_MAX
};

typedef struct istc_class_lan_addr_info_s
{
    unsigned int gateway;
    unsigned int addr_begin;
    unsigned int addr_end;
}istc_class_lan_addr_info_t;

#endif
