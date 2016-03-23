
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
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "istc.h"
#include "istc_protocol.h"
#include "istc_log.h"

#include "snmp_interface.h"


#define BUSYBOX_FILE "/tmp/busybox"
#define DNSINFO_SCRIPT "/system/bin/dnsinfo.script"
#define DNSINFO_FILE "/tmp/dnsinfo.txt"
#define ISTC_NOTSUPPORT istc_log("not support now\n");
#define ISTC_WIRELESS_AP_STA_COUNT_MAX 64

static istc_ap_ssid_t gSNMPWIFISSID[ISTC_AP_SSID_TYPE_MAX];
static int gSNMPWifiInterfaceCount = 0;

unsigned int istc_now_time_ms(void)
{
    struct timeval tv;
    struct  timezone   tz;
    unsigned int nowtime = 0;

    gettimeofday(&tv,&tz);
    nowtime = tv.tv_sec * 1000 + tv.tv_usec / 1000000;
    return nowtime;
}

int istc_inet_itoa(int value, char *str, int len)
{
    char *buf = NULL;
    int index = 0, num_len = 0;

    SNMP_ASSERT(value >= 0 && str != NULL && len > 0);

    memset(str, 0, len);
    if(value == 0)
    {
        strcpy(str, "0");
        return 0;
    }

    if((buf = (char *)calloc(1, len + 1)) == NULL)
    {
        istc_log("can not calloc\n");
        return -1;
    }

    while(value > 0)
    {
        *(buf + index) = value % 10 + '0';
        value /= 10;
        if(++index > len)
        {
            istc_log("%d is too short\n", len);
            free(buf);
            return -1;
        }
    }
    num_len = index;
    index = 0;
    while(index < num_len)
    {
        *(str + index) = buf[num_len - index - 1];
        index++;
    }
    free(buf);
    return 0;
}


const char *istc_inet_ntoa(unsigned int ip, char *buff, int size)
{
    *buff = '\0';

    return (inet_ntop(AF_INET, &ip, buff, size));
}

const char *istc_inet_htoa(unsigned int host, char *buff, int size)
{

    *buff = '\0';

    return inet_ntop(AF_INET, &host, buff, size);
}

int istc_inet_aton(const char *str, unsigned int *ip)
{
    if (inet_pton(AF_INET, str, ip) == 1) {
        return 0;
    } else {
        return -1;
    }
}

int istc_inet_atoh(const char *str, unsigned int *ip)
{
    unsigned int u4;
    if (inet_pton(AF_INET, str, &u4) == 1) {
        u4 = ntohl(u4);
        *ip = u4;
        return 0;
    } else {
        return -1;
    }
}


int istc_interface_ipaddr_get(const char *ifname, unsigned int *ipaddr)
{
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT status = ISTC_SNMP_ERR_UNKNOWN;
    int index = 0, ifindex = 0;
    int getflag = 0;

    oid ipAdEntAddr[] = {IPADDRTABLE_OID, IPADDRENTRY_OID, COLUMN_IPADENTADDR};
    size_t ipAdEntAddr_len = OID_LENGTH(ipAdEntAddr);
    oid ipAdEntIfIndex[] = {IPADDRTABLE_OID, IPADDRENTRY_OID, COLUMN_IPADENTIFINDEX};
    size_t ipAdEntIfIndex_len = OID_LENGTH(ipAdEntIfIndex);

    SNMP_ASSERT(ipaddr != NULL);
    
    if(istc_snmp_walk(ipAdEntIfIndex, ipAdEntIfIndex_len, &pdu_head, &status) != ISTC_SNMP_SUCCESS)
    {
        istc_log("can not get ipaddr\n");
        return -1;
    }
    istc_snmp_print_pdulist(pdu_head, ipAdEntIfIndex, ipAdEntIfIndex_len);
    pdu_list = pdu_head;
    while(pdu_list != NULL && getflag == 0)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, ipAdEntIfIndex, ipAdEntIfIndex_len * sizeof(oid)) != 0)
            {
                break;
            }
            index++;
            if(*(vars->val.integer) == WAN_INTERFACE_INDEX)
            {
                istc_log("get index success\n");
                getflag = 1;
                break;
            }
        }
        pdu_list = pdu_list->next;
    }
    if(getflag == 0)
    {
        istc_log("get index failed\n");
        istc_snmp_free_pdulist(pdu_head);
        return -1;
    }
    ifindex = index;
    index = 0;

    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
     if(istc_snmp_walk(ipAdEntAddr, ipAdEntAddr_len, &pdu_head, &status) != ISTC_SNMP_SUCCESS)
    {
        istc_log("can not get ipaddr\n");
        return -1;
    }
    pdu_list = pdu_head;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, ipAdEntAddr, ipAdEntAddr_len * sizeof(oid)) != 0)
            {
                break;
            }
            if(++index == ifindex)
            {
                *ipaddr = *(vars->val.integer);
                istc_snmp_print_pdulist(pdu_list, ipAdEntAddr, ipAdEntAddr_len);
                istc_snmp_free_pdulist(pdu_head);
                istc_log("get ipaddr success\n");
                return 0;
            }
        }
        pdu_list = pdu_list->next;
    }
    istc_snmp_free_pdulist(pdu_head);
    istc_log("get ipaddr failed\n");
    return -1;
}


int istc_interface_netmask_get(const char *ifname, unsigned int *netmask)
{
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT status = ISTC_SNMP_ERR_UNKNOWN;
    int index = 0, ifindex = 0;
    int getflag = 0;

    oid ipAdEntIfIndex[] = {IPADDRTABLE_OID, IPADDRENTRY_OID, COLUMN_IPADENTIFINDEX};
    size_t ipAdEntIfIndex_len = OID_LENGTH(ipAdEntIfIndex);
    oid ipAdEntNetMask[] = {IPADDRTABLE_OID, IPADDRENTRY_OID, COLUMN_IPADENTNETMASK};
    size_t ipAdEntNetMask_len = OID_LENGTH(ipAdEntNetMask);

    SNMP_ASSERT(netmask != NULL);
    
    if(istc_snmp_walk(ipAdEntIfIndex, ipAdEntIfIndex_len, &pdu_head, &status) != ISTC_SNMP_SUCCESS)
    {
        istc_log("can not get ipaddr\n");
        return -1;
    }
    pdu_list = pdu_head;
    while(pdu_list != NULL && getflag == 0)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, ipAdEntIfIndex, ipAdEntIfIndex_len * sizeof(oid)) != 0)
            {
                break;
            }
            index++;
            if(*(vars->val.integer) == WAN_INTERFACE_INDEX)
            {
                istc_log("get index success\n");
                getflag = 1;
                break;
            }
        }
        pdu_list = pdu_list->next;
    }
    if(getflag == 0)
    {
        istc_log("get index failed\n");
        istc_snmp_free_pdulist(pdu_head);
        return -1;
    }
    ifindex = index;
    index = 0;

    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
     if(istc_snmp_walk(ipAdEntNetMask, ipAdEntNetMask_len, &pdu_head, &status) != ISTC_SNMP_SUCCESS)
    {
        istc_log("can not get netmask\n");
        return -1;
    }
    pdu_list = pdu_head;
    istc_log("ifindex = %d\n", ifindex);
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, ipAdEntNetMask, ipAdEntNetMask_len * sizeof(oid)) != 0)
            {
                break;
            }
            if(++index == ifindex)
            {
                *netmask = *(vars->val.integer);
                istc_snmp_print_pdulist(pdu_list, ipAdEntNetMask, ipAdEntNetMask_len);
                istc_snmp_free_pdulist(pdu_head);
                istc_log("get netmask success\n");
                return 0;
            }
        }
        pdu_list = pdu_list->next;
    }
    istc_snmp_free_pdulist(pdu_head);
    istc_log("get netmask failed\n");
    return -1;
}


int istc_interface_addr_mode_get(const char *ifname, int *mode)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_interface_ipaddr_set(const char *ifname, unsigned int ipaddr)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_interface_netmask_set(const char *ifname, unsigned int netmask)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_interface_addr_mode_set(const char *ifname, int mode)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_interface_mac_get(const char *ifname, unsigned char *mac)
{
    SNMP_DATA_LIST_st *data_head = NULL;
    int cnt = 0;

    oid ifPhysAddress[] = {IFTABLE_OID, IFENTRY_OID, COLUMN_IFPHYSADDRESS, WAN_INTERFACE_INDEX};
    size_t ifPhysAddress_len = OID_LENGTH(ifPhysAddress);
    
    SNMP_ASSERT(mac != NULL);

    if(istc_snmp_table_parse_datalist(ifPhysAddress, ifPhysAddress_len, (SnmpTableFun)_ifTable_set_column, sizeof(ifTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse ifPhysAddress\n");
        return -1;
    }
    istc_log("parse ifPhysAddress success\n");
    memcpy(mac, ((ifTable_rowreq_ctx *)(data_head->data))->data.ifPhysAddress, 6);
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;
    istc_log("get mac success\n");
    return 0;
}


int istc_interface_mac_set(const char *ifname, const unsigned char *mac)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_interface_totalflow_get(const char *ifname, unsigned int *up_flow, unsigned int *down_flow)
{
    SNMP_DATA_LIST_st *data_head = NULL;
    clabWIFIRadioStatsTable_rowreq_ctx *ctx = NULL;
    int cnt = 0;
    int ifIndex = 0;

    oid clabWIFIRadioStatsBytesSent[] = {CLABWIFIRADIOSTATSTABLE_OID, CLABWIFIRADIOSTATSENTRY_OID, COLUMN_CLABWIFIRADIOSTATSBYTESSENT, 0};
    size_t clabWIFIRadioStatsBytesSent_len = OID_LENGTH(clabWIFIRadioStatsBytesSent);
    oid clabWIFIRadioStatsBytesReceived[] = {CLABWIFIRADIOSTATSTABLE_OID, CLABWIFIRADIOSTATSENTRY_OID, COLUMN_CLABWIFIRADIOSTATSBYTESRECEIVED, 0};
    size_t clabWIFIRadioStatsBytesReceived_len = OID_LENGTH(clabWIFIRadioStatsBytesReceived);
    
    SNMP_ASSERT(ifname != NULL && *ifname != 0);
    SNMP_ASSERT(up_flow != NULL && down_flow != NULL);

    if(strcmp(ifname, "wlan0") == 0)
    {
        ifIndex = WLAN0_INTERFACE_INDEX;
    }
    else if(strcmp(ifname, "wlan1") == 0)
    {
        ifIndex = WLAN1_INTERFACE_INDEX;
    }

    clabWIFIRadioStatsBytesSent[clabWIFIRadioStatsBytesSent_len - 1] = ifIndex;
    clabWIFIRadioStatsBytesReceived[clabWIFIRadioStatsBytesReceived_len - 1] = ifIndex;

    /*get rx*/
    if(istc_snmp_table_parse_datalist(clabWIFIRadioStatsBytesSent, clabWIFIRadioStatsBytesSent_len, (SnmpTableFun)_clabWIFIRadioStatsTable_set_column, sizeof(clabWIFIRadioStatsTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFIRadioStatsBytesSent\n");
        return -1;
    }
    istc_log("parse clabWIFIRadioStatsBytesSent success\n");
    ctx = (clabWIFIRadioStatsTable_rowreq_ctx *)data_head->data;
    *down_flow = (((unsigned long long)(ctx->data.clabWIFIRadioStatsBytesSent.high) << 32) | (unsigned long long)ctx->data.clabWIFIRadioStatsBytesSent.low) / 1024;
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;

    /*get tx*/
    if(istc_snmp_table_parse_datalist(clabWIFIRadioStatsBytesReceived, clabWIFIRadioStatsBytesReceived_len, (SnmpTableFun)_clabWIFIRadioStatsTable_set_column, sizeof(clabWIFIRadioStatsTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFIRadioStatsBytesReceived\n");
        return -1;
    }
    istc_log("parse clabWIFIRadioStatsBytesReceived success\n");
    ctx = (clabWIFIRadioStatsTable_rowreq_ctx *)data_head->data;
    *up_flow = (((unsigned long long)(ctx->data.clabWIFIRadioStatsBytesReceived.high) << 32) | (unsigned long long)ctx->data.clabWIFIRadioStatsBytesReceived.low) / 1024;
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;

    return 0;
}


int istc_link_state_get(const char *ifname, int *state)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_link_admin_state_get(const char *ifname, int *state)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_link_mtu_get(const char *ifname, int *state)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_link_admin_state_set(const char *ifname, int state)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_wireless_mode_get(const char *ifname, int *mode)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_sta_ssid_scan(const char *ifname)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_async_wireless_sta_ssid_scan(const char *ifname)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_sta_scan_result_get(const char *ifname,
                                      istc_sta_ssid_t * result, int *pcnt)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_sta_state_get(const char *ifname, int *state,
                                istc_sta_ssid_t * ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_sta_ssid_add(const char *ifname, const char *ssid,
                               const char *password)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_sta_ssid_add2(const char *ifname, const char *ssid,
                                const char *password, int encryption)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_wireless_sta_ssid_remove(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_sta_ssid_enable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_sta_ssid_disable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_async_wireless_sta_ssid_enable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_async_wireless_sta_ssid_disable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}


/* ---------------------------- AP CLASS  -------------------------------- */

int istc_wireless_ap_ssid_get(const char *ifname, istc_ap_ssid_t * ssid,
                              int *count)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_ap_ssid_sta_get(const char *ifname, const char *ssid,
                                  istc_ap_sta_t * sta, int *count)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    dot11BssTable_rowreq_ctx *ctx = NULL;
    int ssid_index = -1;
    int cnt = 0;
    int i = 0, j = 0;
    int status = -1;
    istc_ap_sta_t *ap_sta = NULL, *sta_rgIpLanAddrTable = NULL, *sta_wifiAssocStaTable = NULL;
    int sta_count = 0, sta_rgIpLanAddrTable_count = 0, sta_wifiAssocStaTable_count = 0;;
    char ip[16] = {0};
    int ifIndex = 0;
    int nowtime = 0;

    oid dot11BssSsid[] = {DOT11BSSTABLE_OID, DOT11BSSENTRY_OID, COLUMN_DOT11BSSSSID};
    size_t dot11BssSsid_len = OID_LENGTH(dot11BssSsid);

    oid clabWIFIAssociatedDeviceMACAddress[] = {CLABWIFIASSOCIATEDDEVICETABLE_OID, CLABWIFIASSOCIATEDDEVICEENTRY_OID, COLUMN_CLABWIFIASSOCIATEDDEVICEMACADDRESS, 0};
    size_t clabWIFIAssociatedDeviceMACAddress_len = OID_LENGTH(clabWIFIAssociatedDeviceMACAddress);

    oid rgIpLanAddrClientID[] = {RGIPLANADDRTABLE_OID, RGIPLANADDRENTRY_OID, COLUMN_RGIPLANADDRCLIENTID, 0};
    size_t rgIpLanAddrClientID_len = OID_LENGTH(rgIpLanAddrClientID);
    oid rgIpLanAddrHostName[] = {RGIPLANADDRTABLE_OID, RGIPLANADDRENTRY_OID, COLUMN_RGIPLANADDRHOSTNAME, 0};
    size_t rgIpLanAddrHostName_len = OID_LENGTH(rgIpLanAddrHostName);

    oid wifiAssocStaMacAddress[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTAMACADDRESS, 0};
    size_t wifiAssocStaMacAddress_len = OID_LENGTH(wifiAssocStaMacAddress);
    oid wifiAssocStaTxBytes[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTATXBYTES, 0};
    size_t wifiAssocStaTxBytes_len = OID_LENGTH(wifiAssocStaTxBytes);
    oid wifiAssocStaRxBytes[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTARXBYTES, 0};
    size_t wifiAssocStaRxBytes_len = OID_LENGTH(wifiAssocStaRxBytes);
    oid wifiAssocStaTxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTATXRATELIMIT, 0};
    size_t wifiAssocStaTxRateLimit_len = OID_LENGTH(wifiAssocStaTxRateLimit);
    oid wifiAssocStaRxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTARXRATELIMIT, 0};
    size_t wifiAssocStaRxRateLimit_len = OID_LENGTH(wifiAssocStaRxRateLimit);
    
    SNMP_ASSERT(ifname!= NULL && *ifname != 0);
    SNMP_ASSERT(ssid != NULL && *ssid != 0);
    SNMP_ASSERT(sta != NULL);
    SNMP_ASSERT(count != NULL && *count > 0);

    if(istc_init_snmp_wifissid() != 0)
    {
        istc_log("can not init snmp index\n");
        return -1;
    }
    
    if(istc_snmp_table_parse_datalist(dot11BssSsid, dot11BssSsid_len, (SnmpTableFun)_dot11BssTable_set_column, sizeof(dot11BssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSsid\n");
        return -1;
    }
    data_list = data_head;
    while(data_list != NULL)
    {
        ctx = (dot11BssTable_rowreq_ctx *)data_list->data;
        if(strstr(ctx->data.dot11BssSsid, ssid) != NULL)
        {
            for(i = 0; i < sizeof(gSNMPWIFISSID) / sizeof(gSNMPWIFISSID[0]); i++)
            {
                if(strstr(gSNMPWIFISSID[i].ifname, ifname) != NULL)
                {
                    ssid_index = data_list->row;
                    ifIndex = i < 2 ? ssid_index - 1 : ssid_index - 2;
                    break;
                }
            }
            if(ssid_index >= 0)
            {
                istc_log("get ssid_index %d success\n", ssid_index);
                break;
            }
        }
        data_list = data_list->next;
    }
    if(ssid_index < 0)
    {
        istc_log("can not find ssid index, ifname = %s, ssid = %s\n", ifname, ssid);
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }
    istc_snmp_table_free_datalist(data_head);
    data_head= NULL;

    clabWIFIAssociatedDeviceMACAddress[clabWIFIAssociatedDeviceMACAddress_len - 1] = ssid_index;
    rgIpLanAddrClientID[rgIpLanAddrClientID_len - 1] = ssid_index;
    rgIpLanAddrHostName[rgIpLanAddrHostName_len - 1] = ssid_index;
    wifiAssocStaMacAddress[wifiAssocStaMacAddress_len - 1] = ifIndex;
    wifiAssocStaTxBytes[wifiAssocStaTxBytes_len - 1] = ifIndex;
    wifiAssocStaRxBytes[wifiAssocStaRxBytes_len - 1] = ifIndex;
    wifiAssocStaTxRateLimit[wifiAssocStaTxRateLimit_len - 1] = ifIndex;
    wifiAssocStaRxRateLimit[wifiAssocStaRxRateLimit_len - 1] = ifIndex;

    /*get device mac from clabWIFIAssociatedDeviceTable*/
    if(istc_snmp_walk(clabWIFIAssociatedDeviceMACAddress, clabWIFIAssociatedDeviceMACAddress_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiBssAccessStation\n");
        return -1;
    }
    if(istc_snmp_table_get_rows_num(pdu_head, &sta_count) != 0 || sta_count <= 0)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not get sta count from clabWIFIAssociatedDeviceTable\n");
        return -1;
    }
    else
    {
        istc_log("get sta count %d from clabWIFIAssociatedDeviceTable success\n", sta_count);
    }
    if((ap_sta = (istc_ap_sta_t *)calloc(sta_count, sizeof(istc_ap_sta_t))) == NULL)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not calloc\n");
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, clabWIFIAssociatedDeviceMACAddress, clabWIFIAssociatedDeviceMACAddress_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars && i < sta_count; vars = vars->next_variable)
        {
            if(memcmp(vars->name, clabWIFIAssociatedDeviceMACAddress, clabWIFIAssociatedDeviceMACAddress_len * sizeof(oid)) != 0)
            {
                break;
            }
            int len = (sizeof(ap_sta[i].sta_mac) > vars->val_len) ? vars->val_len : sizeof(ap_sta[i].sta_mac);
            memcpy(ap_sta[i].sta_mac, vars->val.bitstring, len);
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device mac from clabWIFIAssociatedDeviceTable success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
    
    /*get device ip and mac from rgIpLanAddrTable*/
    if(istc_snmp_walk(rgIpLanAddrClientID, rgIpLanAddrClientID_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiBssAccessStation\n");
        free(ap_sta);
        return -1;
    }
    if(istc_snmp_table_get_rows_num(pdu_head, &sta_rgIpLanAddrTable_count) != 0 || sta_rgIpLanAddrTable_count <= 0)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not get sta count\n");
        free(ap_sta);
        return -1;
    }
    if((sta_rgIpLanAddrTable = (istc_ap_sta_t *)calloc(sta_rgIpLanAddrTable_count, sizeof(istc_ap_sta_t))) == NULL)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not calloc\n");
        free(ap_sta);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, rgIpLanAddrClientID, rgIpLanAddrClientID_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, rgIpLanAddrClientID, rgIpLanAddrClientID_len * sizeof(oid)) != 0)
            {
                break;
            }
            snprintf(ip, sizeof(ip) - 1, "%d.%d.%d.%d", (int)vars->name[vars->name_length - 4], (int)vars->name[vars->name_length - 3], (int)vars->name[vars->name_length - 2], (int)vars->name[vars->name_length - 1]);
            istc_inet_aton(ip, &sta_rgIpLanAddrTable[i].sta_ip);
            int len = (sizeof(sta_rgIpLanAddrTable[i].sta_mac) > vars->val_len) ? vars->val_len : sizeof(sta_rgIpLanAddrTable[i].sta_mac);
            memcpy(sta_rgIpLanAddrTable[i].sta_mac, vars->val.bitstring, len);
            istc_log("get devices ip %s, index:%d\n", ip, i);
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device ip and mac from rgIpLanAddrTable success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;

    /*get device name from rgIpLanAddrTable*/
    if(istc_snmp_walk(rgIpLanAddrHostName, rgIpLanAddrHostName_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiBssAccessStation\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, rgIpLanAddrHostName, rgIpLanAddrHostName_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars && i < sta_rgIpLanAddrTable_count; vars = vars->next_variable)
        {
            if(memcmp(vars->name, rgIpLanAddrHostName, rgIpLanAddrHostName_len * sizeof(oid)) != 0)
            {
                break;
            }
            int len = (sizeof(sta_rgIpLanAddrTable[i].sta_name) - 1 > vars->val_len) ? vars->val_len : sizeof(sta_rgIpLanAddrTable[i].sta_name) - 1;
            strncpy(sta_rgIpLanAddrTable[i].sta_name, (char *)(vars->val.string), len);
            istc_log("get device name [%s], index: %d\n", sta_rgIpLanAddrTable[i].sta_name, i);
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device name success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;

    /*get device mac from wifiAssocStaTable*/
    if(istc_snmp_walk(wifiAssocStaMacAddress, wifiAssocStaMacAddress_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiAssocStaMacAddress\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        return -1;
    }
    if(istc_snmp_table_get_rows_num(pdu_head, &sta_wifiAssocStaTable_count) != 0 || sta_wifiAssocStaTable_count <= 0)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not get sta count from wifiAssocStaTable\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        return -1;
    }
    else
    {
        istc_log("get sta count %d from wifiAssocStaTable success\n", sta_wifiAssocStaTable_count);
    }
    if((sta_wifiAssocStaTable = (istc_ap_sta_t *)calloc(sta_wifiAssocStaTable_count, sizeof(istc_ap_sta_t))) == NULL)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not calloc\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars && i < sta_wifiAssocStaTable_count; vars = vars->next_variable)
        {
            if(memcmp(vars->name, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len * sizeof(oid)) != 0)
            {
                break;
            }
            int len = (sizeof(sta_wifiAssocStaTable[i].sta_mac) > vars->val_len) ? vars->val_len : sizeof(sta_wifiAssocStaTable[i].sta_mac);
            memcpy(sta_wifiAssocStaTable[i].sta_mac, vars->val.bitstring, len);
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device mac from wifiAssocStaTable success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;

    /*wifiAssocStaTxBytes is defined for wifi ssid, not for device, so we get rx flow of device from wifiAssocStaTxBytes*/
    /*get device rx*/
    if(istc_snmp_walk(wifiAssocStaTxBytes, wifiAssocStaTxBytes_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiAssocStaTxBytes\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        free(sta_wifiAssocStaTable);
        return -1;
    }
    nowtime = istc_now_time_ms();
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaTxBytes, wifiAssocStaTxBytes_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars && i < sta_wifiAssocStaTable_count; vars = vars->next_variable)
        {
            if(memcmp(vars->name, wifiAssocStaTxBytes, wifiAssocStaTxBytes_len * sizeof(oid)) != 0)
            {
                break;
            }
            sta_wifiAssocStaTable[i].down_flow_kbyte = (((unsigned long long)vars->val.counter64->high << 32 ) | (unsigned long long)vars->val.counter64->low) / 1024;
            sta_wifiAssocStaTable[i].down_nowtime_ms = nowtime;
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device rx success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;

    /*get device tx*/
    if(istc_snmp_walk(wifiAssocStaRxBytes, wifiAssocStaRxBytes_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiAssocStaRxBytes\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        free(sta_wifiAssocStaTable);
        return -1;
    }
    nowtime = istc_now_time_ms();
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaRxBytes, wifiAssocStaRxBytes_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars && sta_wifiAssocStaTable_count; vars = vars->next_variable)
        {
            if(memcmp(vars->name, wifiAssocStaRxBytes, wifiAssocStaRxBytes_len * sizeof(oid)) != 0)
            {
                break;
            }
            sta_wifiAssocStaTable[i].up_flow_kbyte = (((unsigned long long)vars->val.counter64->high << 32 ) | (unsigned long long)vars->val.counter64->low) / 1024;
            sta_wifiAssocStaTable[i].up_nowtime_ms = nowtime;
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device tx success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;

    /*get device ceil rx*/
    if(istc_snmp_walk(wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiAssocStaTxRateLimit\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        free(sta_wifiAssocStaTable);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars && i < sta_wifiAssocStaTable_count; vars = vars->next_variable)
        {
            if(memcmp(vars->name, wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len * sizeof(oid)) != 0)
            {
                break;
            }
            if((unsigned long)*vars->val.integer != 0xFFFFFFFF)
            {
                sta_wifiAssocStaTable[i].down_ceil_rate_kbyte = (unsigned long)*vars->val.integer / 1024;
            }
            else
            {
                sta_wifiAssocStaTable[i].down_ceil_rate_kbyte = -1;
            }
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device ceil rx success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;

    /*get device ceil tx*/
    if(istc_snmp_walk(wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len, &pdu_head, &status) != 0)
    {
        istc_log("can not walk wifiAssocStaRxRateLimit\n");
        free(ap_sta);
        free(sta_rgIpLanAddrTable);
        free(sta_wifiAssocStaTable);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len);
    i = 0;
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        for(vars = pdu_list->response->variables; vars && i < sta_wifiAssocStaTable_count; vars = vars->next_variable)
        {
            if(memcmp(vars->name, wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len * sizeof(oid)) != 0)
            {
                break;
            }
            if((unsigned long)*vars->val.integer != 0xFFFFFFFF)
            {
                sta_wifiAssocStaTable[i].up_ceil_rate_kbyte = (unsigned long)*vars->val.integer / 1024;
            }
            else
            {
                sta_wifiAssocStaTable[i].up_ceil_rate_kbyte = -1;
            }
            i++;
        }
        pdu_list = pdu_list->next;
    }
    istc_log("get device ceil tx success\n");
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
    
    for(i = 0; i < sta_count; i++)
    {
        for(j = 0; j < sta_rgIpLanAddrTable_count; j++)
        {
            if(memcmp(ap_sta[i].sta_mac, sta_rgIpLanAddrTable[j].sta_mac, sizeof(ap_sta[i].sta_mac)) == 0)
            {
                ap_sta[i].sta_ip = sta_rgIpLanAddrTable[j].sta_ip;
                strncpy(ap_sta[i].sta_name, sta_rgIpLanAddrTable[j].sta_name, sizeof(ap_sta[i].sta_name) - 1);
            }
        }
    }
    for(i = 0; i < sta_count; i++)
    {
        for(j = 0; j < sta_wifiAssocStaTable_count; j++)
        {
            if(memcmp(ap_sta[i].sta_mac, sta_wifiAssocStaTable[j].sta_mac, sizeof(ap_sta[i].sta_mac)) == 0)
            {
                ap_sta[i].up_flow_kbyte = sta_wifiAssocStaTable[j].up_flow_kbyte;
                ap_sta[i].up_ceil_rate_kbyte = sta_wifiAssocStaTable[j].up_ceil_rate_kbyte;
                ap_sta[i].up_nowtime_ms = sta_wifiAssocStaTable[j].up_nowtime_ms;
                ap_sta[i].down_flow_kbyte = sta_wifiAssocStaTable[j].down_flow_kbyte;
                ap_sta[i].down_ceil_rate_kbyte = sta_wifiAssocStaTable[j].down_ceil_rate_kbyte;
                ap_sta[i].down_nowtime_ms = sta_wifiAssocStaTable[j].down_nowtime_ms;
            }
        }
    }
    
    *count = (*count > sta_count) ? sta_count : *count;
    memcpy(sta, ap_sta, *count * sizeof(istc_ap_sta_t));
    free(ap_sta);
    free(sta_rgIpLanAddrTable);
    free(sta_wifiAssocStaTable);
    istc_log("get devices list success, count = %d\n", *count);
    return 0;
}


int istc_wireless_ap_ssid_add(const char *ifname, const istc_ap_ssid_t * ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_wireless_ap_ssid_remove(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_ap_ssid_enable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_ap_ssid_disable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

static int istc_wireless_ap_ssid_mac_get(const char *ifname, const char *ssid,
                                         unsigned char list[][6], int *count,
                                         int mode)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    dot11BssTable_rowreq_ctx *ctx = NULL;
    int ssid_index = -1;
    int cnt = 0;
    int i = 0;
    int status = -1;

    oid dot11BssSsid[] = {DOT11BSSTABLE_OID, DOT11BSSENTRY_OID, COLUMN_DOT11BSSSSID};
    size_t dot11BssSsid_len = OID_LENGTH(dot11BssSsid);

    oid wifiBssAccessStation[] = {WIFIBSSACCESSTABLE_OID, WIFIBSSACCESSENTRY_OID, COLUMN_WIFIBSSACCESSSTATION, 0};
    size_t wifiBssAccessStation_len = OID_LENGTH(wifiBssAccessStation);

    SNMP_ASSERT(ifname!= NULL && *ifname != 0);
    SNMP_ASSERT(ssid != NULL && *ssid != 0);
    SNMP_ASSERT(count != NULL);

    if(istc_init_snmp_wifissid() != 0)
    {
        istc_log("can not init snmp index\n");
        return -1;
    }
    
    if(istc_snmp_table_parse_datalist(dot11BssSsid, dot11BssSsid_len, (SnmpTableFun)_dot11BssTable_set_column, sizeof(dot11BssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSsid\n");
        return -1;
    }
    data_list = data_head;
    while(data_list != NULL)
    {
        ctx = (dot11BssTable_rowreq_ctx *)data_list->data;
        if(strstr(ctx->data.dot11BssSsid, ssid) != NULL)
        {
            for(i = 0; i < sizeof(gSNMPWIFISSID) / sizeof(gSNMPWIFISSID[0]); i++)
            {
                if(strstr(gSNMPWIFISSID[i].ifname, ifname) != NULL)
                {
                    ssid_index = data_list->row;
                    break;
                }
            }
            if(ssid_index >= 0)
            {
                istc_log("get ssid_index %d success\n", ssid_index);
                break;
            }
        }
        data_list = data_list->next;
    }
    if(data_list == NULL)
    {
        istc_log("can not find ssid index, ifname = %s, ssid = %s\n", ifname, ssid);
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }
    istc_snmp_table_free_datalist(data_head);
    data_head= NULL;

    if(mode == ISTC_ACL_MAC_MODE_ACCEPT || mode == ISTC_ACL_MAC_MODE_DENY)
    {
        wifiBssAccessStation[wifiBssAccessStation_len - 1] = ssid_index;
        i = 0;
        if(istc_snmp_walk(wifiBssAccessStation, wifiBssAccessStation_len, &pdu_head, &status) != 0)
        {
            istc_log("can not walk wifiBssAccessStation\n");
            return -1;
        }
        pdu_list = pdu_head;
        istc_snmp_print_pdulist(pdu_head, wifiBssAccessStation, wifiBssAccessStation_len);
        while(pdu_list != NULL)
        {
            struct variable_list *vars = NULL;
            for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
            {
                if(memcmp(vars->name, wifiBssAccessStation, wifiBssAccessStation_len * sizeof(oid)) != 0)
                {
                    break;
                }
                memcpy(list[i], vars->val.bitstring, sizeof(list[i]));
                i++;
            }
            pdu_list = pdu_list->next;
        }
        *count = i;
        istc_snmp_free_pdulist(pdu_head);
        istc_log("get mac_ctl list success, count = %d\n", *count);
        return 0;
    }
    return 0;
}


int istc_wireless_ap_ssid_mac_accept_get(const char *ifname, const char *ssid,
                                         unsigned char list[][6], int *count)
{
    return istc_wireless_ap_ssid_mac_get(ifname, ssid, list, count,
                                         ISTC_ACL_MAC_MODE_ACCEPT);
}


int istc_wireless_ap_ssid_mac_deny_get(const char *ifname, const char *ssid,
                                       unsigned char list[][6], int *count)
{
    return istc_wireless_ap_ssid_mac_get(ifname, ssid, list, count,
                                         ISTC_ACL_MAC_MODE_DENY);
}



static int istc_wireless_ap_ssid_mac_op(const char *ifname, const char *ssid,
                                        unsigned char *mac, unsigned short op)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    dot11BssTable_rowreq_ctx *ctx = NULL;
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    int ssid_index = -1;
    int cnt = 0;
    int i = 0;
    int status = -1;
    int mac_index = -1;
    char macstr[13] = {0};
    SNMP_AGENT_INFO_st agentinfo;
    int retries = 0;

    oid dot11BssSsid[] = {DOT11BSSTABLE_OID, DOT11BSSENTRY_OID, COLUMN_DOT11BSSSSID};
    size_t dot11BssSsid_len = OID_LENGTH(dot11BssSsid);

    oid wifiBssAccessStation[] = {WIFIBSSACCESSTABLE_OID, WIFIBSSACCESSENTRY_OID, COLUMN_WIFIBSSACCESSSTATION, 0};
    size_t wifiBssAccessStation_len = OID_LENGTH(wifiBssAccessStation);

    SNMP_ASSERT(ifname!= NULL && *ifname != 0);
    SNMP_ASSERT(ssid != NULL && *ssid != 0);

    snprintf(macstr, sizeof(macstr), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    memset(&agentinfo, 0, sizeof(SNMP_AGENT_INFO_st));
    
    if(istc_init_snmp_wifissid() != 0)
    {
        istc_log("can not init snmp index\n");
        return -1;
    }
    
    if(istc_snmp_table_parse_datalist(dot11BssSsid, dot11BssSsid_len, (SnmpTableFun)_dot11BssTable_set_column, sizeof(dot11BssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSsid\n");
        return -1;
    }
    data_list = data_head;
    while(data_list != NULL)
    {
        ctx = (dot11BssTable_rowreq_ctx *)data_list->data;
        if(strstr(ctx->data.dot11BssSsid, ssid) != NULL)
        {
            for(i = 0; i < sizeof(gSNMPWIFISSID) / sizeof(gSNMPWIFISSID[0]); i++)
            {
                if(strstr(gSNMPWIFISSID[i].ifname, ifname) != NULL)
                {
                    ssid_index = data_list->row;
                    break;
                }
            }
            if(ssid_index >= 0)
            {
                istc_log("get ssid_index %d success\n", ssid_index);
                break;
            }
        }
        data_list = data_list->next;
    }
    if(data_list == NULL)
    {
        istc_log("can not find ssid index, ifname = %s, ssid = %s\n", ifname, ssid);
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }
    istc_snmp_table_free_datalist(data_head);
    data_head= NULL;

    wifiBssAccessStation[wifiBssAccessStation_len - 1] = ssid_index;
    i = 0;
    
    if(istc_snmp_walk(wifiBssAccessStation, wifiBssAccessStation_len, &pdu_head, &status) != 0)
    {
        istc_log("wifiBssAccessStation is NULL\n");
    }
    else
    {
        pdu_list = pdu_head;
        istc_snmp_print_pdulist(pdu_head, wifiBssAccessStation, wifiBssAccessStation_len);
        while(pdu_list != NULL)
        {
            struct variable_list *vars = NULL;
            for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
            {
                if(memcmp(vars->name, wifiBssAccessStation, wifiBssAccessStation_len * sizeof(oid)) != 0)
                {
                    break;
                }
                i++;
                if(mac_index < 0 && memcmp(mac, vars->val.bitstring, pdu_list->response->variables->val_len) == 0)
                {
                    istc_log("get mac in maclist, index = %d\n", i);
                    mac_index = i;
                }
            }
            pdu_list = pdu_list->next;
        }
        istc_snmp_free_pdulist(pdu_head);
    }
    istc_log("mac numbers %d\n", i);
    if(op == ISTC_CLASS_AP_CMD_ADD_MAC_ACCEPT || op == ISTC_CLASS_AP_CMD_ADD_MAC_DENY)
    {
        oid wifiBssAccessStation[] = {WIFIBSSACCESSTABLE_OID, WIFIBSSACCESSENTRY_OID, COLUMN_WIFIBSSACCESSSTATION, 0, 0};
        size_t wifiBssAccessStation_len = OID_LENGTH(wifiBssAccessStation);
        wifiBssAccessStation[wifiBssAccessStation_len - 2] = ssid_index;
        wifiBssAccessStation[wifiBssAccessStation_len - 1] = i + 1;
        if(mac_index >= 0)
        {
            istc_log("mac already in maclist, no need to add\n");
            return 0;
        }
        istc_log("set mac:[%s]\n", macstr);
        if(istc_snmp_set(wifiBssAccessStation, wifiBssAccessStation_len, SNMP_X, macstr, &status) != 0)
        {
            istc_log("set mac failed\n");
            return -1;
        }
        istc_log("add mac success, index = %d\n", i + 1);
        return 0;
    }
    else if(op == ISTC_CLASS_AP_CMD_REMOVE_MAC_ACCEPT || op == ISTC_CLASS_AP_CMD_REMOVE_MAC_DENY)
    {
        if(mac_index < 0)
        {
            istc_log("input mac is not in maclist, can not remove\n");
            return -1;
        }
        oid wifiBssAccessStation[] = {WIFIBSSACCESSTABLE_OID, WIFIBSSACCESSENTRY_OID, COLUMN_WIFIBSSACCESSSTATION, 0, 0};
        size_t wifiBssAccessStation_len = OID_LENGTH(wifiBssAccessStation);
        wifiBssAccessStation[wifiBssAccessStation_len - 2] = ssid_index;
        wifiBssAccessStation[wifiBssAccessStation_len - 1] = mac_index;
        istc_snmp_get_agent_info(&agentinfo);
        retries = agentinfo.retries;
        istc_log("old retries = %d\n", retries);
        agentinfo.retries = -1;
        istc_snmp_update_agent_info(agentinfo);
        if(istc_snmp_set(wifiBssAccessStation, wifiBssAccessStation_len, SNMP_X, "000000000000", &status) != 0)
        {
            istc_snmp_get_agent_info(&agentinfo);
            agentinfo.retries = retries;
            istc_snmp_update_agent_info(agentinfo);
            istc_log("set mac failed\n");
            return -1;
        }
        istc_snmp_get_agent_info(&agentinfo);
        agentinfo.retries = retries;
        istc_snmp_update_agent_info(agentinfo);
        istc_log("remove mac success, index = %d\n", mac_index);
        return 0;
    }
    istc_log("mac op error\n");
    return -1;
}


int istc_wireless_ap_ssid_mac_accept_add(const char *ifname, const char *ssid,
                                         unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_ADD_MAC_ACCEPT);
}

int istc_wireless_ap_ssid_mac_accept_remove(const char *ifname,
                                            const char *ssid,
                                            unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_REMOVE_MAC_ACCEPT);
}

int istc_wireless_ap_ssid_mac_deny_add(const char *ifname, const char *ssid,
                                       unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_ADD_MAC_DENY);
}

int istc_wireless_ap_ssid_mac_deny_remove(const char *ifname, const char *ssid,
                                          unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_REMOVE_MAC_DENY);
}


int istc_wireless_ap_ssid_mac_acl_get(const char *ifname, const char *ssid,
                                      int *mode)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    dot11BssTable_rowreq_ctx *ctx = NULL;
    int ssid_index = -1;
    int cnt = 0;
    int i = 0;

    oid dot11BssSsid[] = {DOT11BSSTABLE_OID, DOT11BSSENTRY_OID, COLUMN_DOT11BSSSSID};
    size_t dot11BssSsid_len = OID_LENGTH(dot11BssSsid);

    oid dot11BssAccessMode[] = {DOT11BSSTABLE_OID, DOT11BSSENTRY_OID, COLUMN_DOT11BSSACCESSMODE, 0};
    size_t dot11BssAccessMode_len = OID_LENGTH(dot11BssAccessMode);

    SNMP_ASSERT(ifname!= NULL && *ifname != 0);
    SNMP_ASSERT(ssid != NULL && *ssid != 0);
    SNMP_ASSERT(mode != NULL);

    if(istc_init_snmp_wifissid() != 0)
    {
        istc_log("can not init snmp index\n");
        return -1;
    }
    
    if(istc_snmp_table_parse_datalist(dot11BssSsid, dot11BssSsid_len, (SnmpTableFun)_dot11BssTable_set_column, sizeof(dot11BssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSsid\n");
        return -1;
    }
    data_list = data_head;
    while(data_list != NULL)
    {
        ctx = (dot11BssTable_rowreq_ctx *)data_list->data;
        if(strstr(ctx->data.dot11BssSsid, ssid) != NULL)
        {
            for(i = 0; i < sizeof(gSNMPWIFISSID) / sizeof(gSNMPWIFISSID[0]); i++)
            {
                if(strstr(gSNMPWIFISSID[i].ifname, ifname) != NULL)
                {
                    ssid_index = data_list->row;
                    break;
                }
            }
            if(ssid_index >= 0)
            {
                istc_log("get ssid_index %d success\n", ssid_index);
                break;
            }
        }
        data_list = data_list->next;
    }
    if(data_list == NULL)
    {
        istc_log("can not find ssid index, ifname = %s, ssid = %s\n", ifname, ssid);
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }

    dot11BssAccessMode[dot11BssAccessMode_len - 1] = ssid_index;
    
    istc_snmp_table_free_datalist(data_head);
    data_head= NULL;
    if(istc_snmp_table_parse_datalist(dot11BssAccessMode, dot11BssAccessMode_len, (SnmpTableFun)_dot11BssTable_set_column, sizeof(dot11BssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse dot11BssAccessMode\n");
        return -1;
    }
    ctx = (dot11BssTable_rowreq_ctx *)(data_head->data);
    switch((int)ctx->data.dot11BssAccessMode)
    {
    case DOT11BSSACCESSMODE_ALLOWANY:
        *mode = ISTC_ACL_MAC_MODE_DISABLE;
        break;
    case DOT11BSSACCESSMODE_ALLOWLIST:
        *mode = ISTC_ACL_MAC_MODE_ACCEPT;
        break;
    case DOT11BSSACCESSMODE_DENYLIST:
        *mode = ISTC_ACL_MAC_MODE_DENY;
        break;
    default:
        istc_log("dot11BssAccessMode %d invalued", (int)ctx->data.dot11BssAccessMode);
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }
    istc_snmp_table_free_datalist(data_head);
    istc_log("get mac_ctl mode %d success\n", *mode);
    return 0;
}


int istc_wireless_ap_ssid_mac_acl_set(const char *ifname, const char *ssid,
                                      int mode)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    dot11BssTable_rowreq_ctx *ctx = NULL;
    int ssid_index = -1;
    int cnt = 0;
    int i = 0;
    int value = 0;
    char valuestr[4]= {0};
    int status = -1;;

    oid dot11BssSsid[] = {DOT11BSSTABLE_OID, DOT11BSSENTRY_OID, COLUMN_DOT11BSSSSID};
    size_t dot11BssSsid_len = OID_LENGTH(dot11BssSsid);

    oid dot11BssAccessMode[] = {DOT11BSSTABLE_OID, DOT11BSSENTRY_OID, COLUMN_DOT11BSSACCESSMODE, 0};
    size_t dot11BssAccessMode_len = OID_LENGTH(dot11BssAccessMode);

    SNMP_ASSERT(ifname != NULL && *ifname != 0);
    SNMP_ASSERT(ssid != NULL && *ssid != 0);

    if(istc_init_snmp_wifissid() != 0)
    {
        istc_log("can not init snmp index\n");
        return -1;
    }

    switch(mode)
    {
    case ISTC_ACL_MAC_MODE_DISABLE:
        value = DOT11BSSACCESSMODE_ALLOWANY;
        break;
    case ISTC_ACL_MAC_MODE_DENY:
        value = DOT11BSSACCESSMODE_DENYLIST;
        break;
    case ISTC_ACL_MAC_MODE_ACCEPT:
        value = DOT11BSSACCESSMODE_ALLOWLIST;
        break;
    default:
        istc_log("mode = %d, not support\n", mode);
        return -1;
    }

    if(istc_snmp_table_parse_datalist(dot11BssSsid, dot11BssSsid_len, (SnmpTableFun)_dot11BssTable_set_column, sizeof(dot11BssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSsid\n");
        return -1;
    }
    data_list = data_head;
    while(data_list != NULL)
    {
        ctx = (dot11BssTable_rowreq_ctx *)data_list->data;
        if(strstr(ctx->data.dot11BssSsid, ssid) != NULL)
        {
            for(i = 0; i < sizeof(gSNMPWIFISSID) / sizeof(gSNMPWIFISSID[0]); i++)
            {
                if(strstr(gSNMPWIFISSID[i].ifname, ifname) != NULL)
                {
                    ssid_index = data_list->row;
                    break;
                }
            }
            if(ssid_index >= 0)
            {
                istc_log("get ssid_index %d success\n", ssid_index);
                break;
            }
        }
        data_list = data_list->next;
    }
    if(data_list == NULL)
    {
        istc_log("can not find ssid index, ifname = %s, ssid = %s\n", ifname, ssid);
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }

    dot11BssAccessMode[dot11BssAccessMode_len - 1] = ssid_index;

    istc_inet_itoa(value, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
    if(istc_snmp_set(dot11BssAccessMode, dot11BssAccessMode_len, SNMP_INT, valuestr, &status) != 0)
    {
        istc_log("can not set dot11BssAccessMode, status = %d\n", status);
        istc_log("set mac_ctl mode to %d failed\n", mode);
        return -1;
    }
    istc_log("set dot11BssAccessMode success\n");
    istc_log("set mac_ctl mode to %d success\n", mode);
    return 0;
}

int istc_async_wireless_ap_ssid_enable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_async_wireless_ap_ssid_disable(const char *ifname, const char *ssid)
{
    ISTC_NOTSUPPORT
    return -1;
}





int istc_dhcp_pool_get(istc_dhcp_pool_t * pool, int *count)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_dhcp_lease_get(istc_dhcp_lease_t * lease, int *count)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_dhcp_pool_add(const istc_dhcp_pool_t * pool)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_dhcp_pool_remove(unsigned int start, unsigned int end)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_dhcp_pool_remove_by_name(const char *name)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_dhcpc_option60_add(const char *ifname, const char *data_in)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_dhcpc_option60_remove(const char *ifname)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_dhcpc_option60_s_add(const char *ifname, const char *data_in)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_dhcpc_option60_s_remove(const char *ifname)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_route_state_get(int *state)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_route_state_set(int state)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_route_default_get(const char *ifname, unsigned int *gateway)
{
#if 0
    PDU_LIST_st *pdu_head = NULL;
    struct variable_list *vars = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT status = ISTC_SNMP_ERR_UNKNOWN;

    oid docsDevDraftServerTftp[] = {1,3,6,1,3,83,1,4,4,0};
    size_t docsDevDraftServerTftp_len = OID_LENGTH(docsDevDraftServerTftp);

    SNMP_ASSERT(gateway != NULL);
    
    if(istc_snmp_walk(docsDevDraftServerTftp, docsDevDraftServerTftp_len, &pdu_head, &status) != ISTC_SNMP_SUCCESS)
    {
        istc_log("can not get docsDevDraftServerTftp\n");
        return -1;
    }
    vars = pdu_head->response->variables;
    if(memcmp(vars->name, docsDevDraftServerTftp, docsDevDraftServerTftp_len * sizeof(oid)) != 0)
    {
        istc_log("can not get docsDevDraftServerTftp\n");
        istc_snmp_free_pdulist(pdu_head);
        return -1;
    }
    *gateway = *(vars->val.integer);
    istc_snmp_free_pdulist(pdu_head);
    
    istc_log("get default route success\n");
    return 0;
#else
    SNMP_DATA_LIST_st *data_head = NULL;
    int cnt = 0;
    char *ip = NULL;

    oid cabhCdpWanDnsServerIp[] = {CABHCDPWANDNSSERVERTABLE_OID, CABHCDPWANDNSSERVERENTRY_OID, COLUMN_CABHCDPWANDNSSERVERIP};
    size_t cabhCdpWanDnsServerIp_len = OID_LENGTH(cabhCdpWanDnsServerIp);
    
    SNMP_ASSERT(gateway != NULL);

    if(istc_snmp_table_parse_datalist(cabhCdpWanDnsServerIp, cabhCdpWanDnsServerIp_len, (SnmpTableFun)_cabhCdpWanDnsServerTable_set_column, sizeof(cabhCdpWanDnsServerTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse cabhCdpWanDnsServerIp\n");
        return -1;
    }
    istc_log("parse cabhCdpWanDnsServerIp success\n");
    ip = ((cabhCdpWanDnsServerTable_rowreq_ctx *)data_head->data)->data.cabhCdpWanDnsServerIp;
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;

    *gateway = ((unsigned int)ip[3] << 24) | ((unsigned int)ip[2] << 16) | ((unsigned int)ip[1] << 8) | ((unsigned int)ip[0]);
    istc_log("get mac success\n");
    return 0;
#endif
}


int istc_route_default_set(const char *ifname, unsigned int gateway)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_dns_address_get(unsigned int *primary, unsigned int *secondary)
{
#if 0
    FILE *fp = NULL;
    char result[128] = {0};
    char *buf = result;
    char dns[16] = {0};

    SNMP_ASSERT(primary != NULL && secondary != NULL);

    if(access(DNSINFO_FILE, F_OK) != 0)
    {
        istc_log("can not find dnsinfo.txt\n");
        return -1;
    }
    
    if((fp = popen("busybox cat "DNSINFO_FILE" | grep nameserver | busybox awk '{print $NF}'", "r")) == NULL)
    {
        istc_log("can not popen\n");
        return -1;
    }
    
    memset(result, 0, sizeof(result));
    fread(result, 1, sizeof(result) - 1, fp);
    if(strlen(result) == 0)
    {
        pclose(fp);
        istc_log("can not get dns\n");
        return -1;
    }

    buf = strchr(result, '\n');
    if(buf)
    {
        *buf = 0;
    }
    strncpy(dns, result, sizeof(dns) - 1);
    istc_inet_aton(dns, primary);
    istc_log("get dns1 %s success\n", dns);
    if(++buf)
    {
        char *p = strchr(buf, '\n');
        if(p)
        {
            *p = 0;
        }
        strncpy(dns, buf, sizeof(dns) - 1);
        istc_inet_aton(dns, secondary);
        istc_log("get dns2 %s success\n", dns);
    }
            
    pclose(fp);
    istc_log("get dns success\n");
    return 0;
#else
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    int cnt = 0;
    char *ip = NULL;

    oid cabhCdpWanDnsServerIp[] = {CABHCDPWANDNSSERVERTABLE_OID, CABHCDPWANDNSSERVERENTRY_OID, COLUMN_CABHCDPWANDNSSERVERIP};
    size_t cabhCdpWanDnsServerIp_len = OID_LENGTH(cabhCdpWanDnsServerIp);
    
    SNMP_ASSERT(primary != NULL && secondary != NULL);

    if(istc_snmp_table_parse_datalist(cabhCdpWanDnsServerIp, cabhCdpWanDnsServerIp_len, (SnmpTableFun)_cabhCdpWanDnsServerTable_set_column, sizeof(cabhCdpWanDnsServerTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse cabhCdpWanDnsServerIp\n");
        return -1;
    }
    istc_log("parse cabhCdpWanDnsServerIp success\n");
    data_list = data_head;
    ip = ((cabhCdpWanDnsServerTable_rowreq_ctx *)data_list->data)->data.cabhCdpWanDnsServerIp;
    *primary = ((unsigned int)ip[3] << 24) | ((unsigned int)ip[2] << 16) | ((unsigned int)ip[1] << 8) | ((unsigned int)ip[0]);
    if((data_list = data_list->next) != NULL)
    {
        ip = ((cabhCdpWanDnsServerTable_rowreq_ctx *)data_list->data)->data.cabhCdpWanDnsServerIp;
        *secondary = ((unsigned int)ip[3] << 24) | ((unsigned int)ip[2] << 16) | ((unsigned int)ip[1] << 8) | ((unsigned int)ip[0]);
    }
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;
    
    istc_log("get dns success\n");
    return 0;
#endif
}


int istc_dns_address_set(unsigned int primary, unsigned int secondary)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_misc_config_save()
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_pppoe_config_get(const char *ifname, char *username, char *password)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_pppoe_config_set(const char *ifname, char *username, char *password)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_pppoe_state(const char *ifname, int *state)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_pppoe_connect(const char *ifname)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_async_pppoe_connect(const char *ifname)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_pppoe_disconnect(const char *ifname)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_ping(const istc_ping_para_t * para, istc_ping_result_t * result)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_async_ping(const istc_ping_para_t * para)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_interface_list_get(char list[][ISTC_IFNAME_SIZE], int *count)
{
    ISTC_NOTSUPPORT
    return -1;
}



int istc_interface_type_get(const char *ifname, int *type)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_log_level_get(int *level)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_log_level_set(int level)
{
    ISTC_NOTSUPPORT
    return -1;
}


/* utils */


int istc_str2mac(const char *str, unsigned char *mac)
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_qos_set_mode( int mode )
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_qos_get_mode( int *mode )
{
    ISTC_NOTSUPPORT
    return -1;
}


int istc_qos_set_device_bandwidth( const unsigned char *mac, int download_kbyte, int upload_kbyte )
{
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = ISTC_SNMP_ERR_UNKNOWN;
    int get_flag = 0;
    char valuestr[16] = {0};

    oid wifiAssocStaMacAddress[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTAMACADDRESS};
    size_t wifiAssocStaMacAddress_len = OID_LENGTH(wifiAssocStaMacAddress);
    oid wifiAssocStaTxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTATXRATELIMIT, 0, 0};
    size_t wifiAssocStaTxRateLimit_len = OID_LENGTH(wifiAssocStaTxRateLimit);
    oid wifiAssocStaRxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTARXRATELIMIT, 0, 0};
    size_t wifiAssocStaRxRateLimit_len = OID_LENGTH(wifiAssocStaRxRateLimit);
    
    SNMP_ASSERT(mac != NULL);

    /*get device mac from wifiAssocStaTable*/
    if(istc_snmp_walk(wifiAssocStaMacAddress, wifiAssocStaMacAddress_len, &pdu_head, &stat) != 0)
    {
        istc_log("can not walk wifiAssocStaMacAddress\n");
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len);
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        if(get_flag == 1)
        {
            break;
        }
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len * sizeof(oid)) != 0)
            {
                break;
            }
            if(memcmp(vars->val.bitstring, mac, 6) == 0)
            {
                wifiAssocStaTxRateLimit[wifiAssocStaTxRateLimit_len - 2] = vars->name[vars->name_length- 2];
                wifiAssocStaTxRateLimit[wifiAssocStaTxRateLimit_len - 1] = vars->name[vars->name_length- 1];
                wifiAssocStaRxRateLimit[wifiAssocStaRxRateLimit_len - 2] = vars->name[vars->name_length- 2];
                wifiAssocStaRxRateLimit[wifiAssocStaRxRateLimit_len - 1] = vars->name[vars->name_length- 1];
                get_flag = 1;
                break;
            }
        }
        pdu_list = pdu_list->next;
    }
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
    if(get_flag == 0)
    {
        istc_log("can not get device mac from wifiAssocStaTable success\n");
        return -1;
    }
    istc_log("get device mac from wifiAssocStaTable success\n");

    /*set ceil rx*/
    istc_inet_itoa(download_kbyte, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
    if(istc_snmp_set(wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len, SNMP_U, valuestr, &stat) != 0)
    {
        istc_log("can not set ceil rx to %u\n", download_kbyte);
    }
    istc_log("set ceil rx success\n");

    /*set ceil tx*/
    istc_inet_itoa(upload_kbyte, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
    if(istc_snmp_set(wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len, SNMP_U, valuestr, &stat) != 0)
    {
        istc_log("can not set ceil txt to %u\n", upload_kbyte);
    }
    istc_log("set ceil tx success\n");
    
    return 0;
}



int istc_qos_get_device_bandwidth( const unsigned char *mac, int *download_kbyte, int *upload_kbyte )
{
    SNMP_DATA_LIST_st *data_head = NULL;
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    wifiAssocStaTable_rowreq_ctx *ctx = NULL;
    int cnt = 0;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = ISTC_SNMP_ERR_UNKNOWN;
    int get_flag = 0;
    int download = -1, upload = -1;

    oid wifiAssocStaMacAddress[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTAMACADDRESS};
    size_t wifiAssocStaMacAddress_len = OID_LENGTH(wifiAssocStaMacAddress);
    oid wifiAssocStaTxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTATXRATELIMIT, 0, 0};
    size_t wifiAssocStaTxRateLimit_len = OID_LENGTH(wifiAssocStaTxRateLimit);
    oid wifiAssocStaRxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTARXRATELIMIT, 0, 0};
    size_t wifiAssocStaRxRateLimit_len = OID_LENGTH(wifiAssocStaRxRateLimit);
    
    SNMP_ASSERT(mac != NULL && download_kbyte != NULL && upload_kbyte != NULL);

    /*get device mac from wifiAssocStaTable*/
    if(istc_snmp_walk(wifiAssocStaMacAddress, wifiAssocStaMacAddress_len, &pdu_head, &stat) != 0)
    {
        istc_log("can not walk wifiAssocStaMacAddress\n");
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len);
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        if(get_flag == 1)
        {
            break;
        }
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len * sizeof(oid)) != 0)
            {
                break;
            }
            if(memcmp(vars->val.bitstring, mac, 6) == 0)
            {
                wifiAssocStaTxRateLimit[wifiAssocStaTxRateLimit_len - 2] = vars->name[vars->name_length- 2];
                wifiAssocStaTxRateLimit[wifiAssocStaTxRateLimit_len - 1] = vars->name[vars->name_length- 1];
                wifiAssocStaRxRateLimit[wifiAssocStaRxRateLimit_len - 2] = vars->name[vars->name_length- 2];
                wifiAssocStaRxRateLimit[wifiAssocStaRxRateLimit_len - 1] = vars->name[vars->name_length- 1];
                get_flag = 1;
                break;
            }
        }
        pdu_list = pdu_list->next;
    }
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
    if(get_flag == 0)
    {
        istc_log("can not get device mac from wifiAssocStaTable success\n");
        return -1;
    }
    istc_log("get device mac from wifiAssocStaTable success\n");
    
    /*get ceil rx*/
    if(istc_snmp_table_parse_datalist(wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len, (SnmpTableFun)_wifiAssocStaTable_set_column, sizeof(wifiAssocStaTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiAssocStaTxRateLimit\n");
        return -1;
    }
    istc_log("parse wifiAssocStaTxRateLimit success\n");
    ctx = (wifiAssocStaTable_rowreq_ctx *)(data_head->data);
    download = (int)ctx->data.wifiAssocStaTxRateLimit;
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;
    
    /*set ceil tx*/
    if(istc_snmp_table_parse_datalist(wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len, (SnmpTableFun)_wifiAssocStaTable_set_column, sizeof(wifiAssocStaTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiAssocStaRxRateLimit\n");
        return -1;
    }
    istc_log("parse wifiAssocStaRxRateLimit success\n");
    ctx = (wifiAssocStaTable_rowreq_ctx *)(data_head->data);
    upload = (int)ctx->data.wifiAssocStaRxRateLimit;
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;

    *download_kbyte = (unsigned long)download;
    *upload_kbyte = (unsigned long)upload;

    istc_log("get ceil download %u, ceil upload %u success\n", *download_kbyte, *upload_kbyte);
    return 0;
}



int istc_qos_get_device_bandwidth_list( istc_conf_qos_device_bandwidth_t *list, int *count )
{
    PDU_LIST_st *pdu_head = NULL, *pdu_list = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = ISTC_SNMP_ERR_UNKNOWN;
    int get_flag = 0;
    istc_conf_qos_device_bandwidth_t *qos_list = NULL;
    unsigned char (*mac_list)[6] = NULL;
    int qos_list_count = 0;
    int i = 0, j = 0;
    
    oid wifiAssocStaMacAddress[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTAMACADDRESS};
    size_t wifiAssocStaMacAddress_len = OID_LENGTH(wifiAssocStaMacAddress);
    oid wifiAssocStaTxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTATXRATELIMIT, 0, 0};
    size_t wifiAssocStaTxRateLimit_len = OID_LENGTH(wifiAssocStaTxRateLimit);
    oid wifiAssocStaRxRateLimit[] = {WIFIASSOCSTATABLE_OID, WIFIASSOCSTAENTRY_OID, COLUMN_WIFIASSOCSTARXRATELIMIT, 0, 0};
    size_t wifiAssocStaRxRateLimit_len = OID_LENGTH(wifiAssocStaRxRateLimit);
    
    SNMP_ASSERT(list != NULL && count != NULL && *count > 0);

    /*get device mac from wifiAssocStaTable*/
    if(istc_snmp_walk(wifiAssocStaMacAddress, wifiAssocStaMacAddress_len, &pdu_head, &stat) != 0)
    {
        istc_log("can not walk wifiAssocStaMacAddress\n");
        return -1;
    }
    if(istc_snmp_table_get_rows_num(pdu_head, &qos_list_count) != 0 || qos_list_count <= 0)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not get sta count from wifiAssocStaTable\n");
        return -1;
    }
    else
    {
        istc_log("get sta count %d from wifiAssocStaTable success\n", qos_list_count);
    }
    if((qos_list = (istc_conf_qos_device_bandwidth_t *)calloc(qos_list_count, sizeof(istc_conf_qos_device_bandwidth_t))) == NULL)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not calloc\n");
        return -1;
    }
    if((mac_list = (unsigned char (*)[6])calloc(qos_list_count, sizeof(unsigned char (*)[6]))) == NULL)
    {
        istc_snmp_free_pdulist(pdu_head);
        istc_log("can not calloc\n");
        free(qos_list);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len);
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        if(get_flag == 1)
        {
            break;
        }
        for(i = 0, vars = pdu_list->response->variables; vars && i < qos_list_count; vars = vars->next_variable, i++)
        {
            if(memcmp(vars->name, wifiAssocStaMacAddress, wifiAssocStaMacAddress_len * sizeof(oid)) != 0)
            {
                break;
            }
            int len = (sizeof(mac_list[i]) > vars->val_len) ? vars->val_len : sizeof(mac_list[i]);
            memcpy(mac_list[i], vars->val.bitstring, len);
        }
        pdu_list = pdu_list->next;
    }
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
    istc_log("get device mac from wifiAssocStaTable success\n");

    /*get devices ceil rx*/
    if(istc_snmp_walk(wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len, &pdu_head, &stat) != 0)
    {
        istc_log("can not walk wifiAssocStaTxRateLimit\n");
        free(qos_list);
        free(mac_list);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len);
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        if(get_flag == 1)
        {
            break;
        }
        for(i = 0, vars = pdu_list->response->variables; vars && i < qos_list_count; vars = vars->next_variable, i++)
        {
            if(memcmp(vars->name, wifiAssocStaTxRateLimit, wifiAssocStaTxRateLimit_len * sizeof(oid)) != 0)
            {
                break;
            }
            if((int)vars->val.integer != -1 && j < qos_list_count)
            {
                memcpy(qos_list[j].mac, mac_list[i], sizeof(qos_list[j].mac));
                qos_list[j].download_kbyte = (int)vars->val.integer;
                j++;
            }
        }
        pdu_list = pdu_list->next;
    }
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
    istc_log("get device ceil rx success\n");
    
    /*get device ceil rx*/
    j = 0;
    if(istc_snmp_walk(wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len, &pdu_head, &stat) != 0)
    {
        istc_log("can not walk wifiAssocStaRxRateLimit\n");
        free(qos_list);
        free(mac_list);
        return -1;
    }
    pdu_list = pdu_head;
    istc_snmp_print_pdulist(pdu_head, wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len);
    while(pdu_list != NULL)
    {
        struct variable_list *vars = NULL;
        if(get_flag == 1)
        {
            break;
        }
        for(i = 0, vars = pdu_list->response->variables; vars && i < qos_list_count; vars = vars->next_variable, i++)
        {
            if(memcmp(vars->name, wifiAssocStaRxRateLimit, wifiAssocStaRxRateLimit_len * sizeof(oid)) != 0)
            {
                break;
            }
            if((int)vars->val.integer != -1 && j < qos_list_count)
            {
                qos_list[j].upload_kbyte = (int)vars->val.integer;
                j++;
            }
        }
        pdu_list = pdu_list->next;
    }
    istc_snmp_free_pdulist(pdu_head);
    pdu_head = NULL;
    istc_log("get device ceil tx success\n");

    *count = *count > j ? j : *count;
    memcpy(list, qos_list, *count * sizeof(istc_conf_qos_device_bandwidth_t));
    istc_log("get qos list success, count = %d\n", *count);
    free(qos_list);
    free(mac_list);
    return 0;
}


int istc_init_snmp_wifissid(void)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    clabWIFISSIDTable_rowreq_ctx *ctx = NULL;
    oid clabWIFISSIDName[] = {CLABWIFISSIDTABLE_OID, COLUMN_CLABWIFISSIDID, COLUMN_CLABWIFISSIDNAME};
    size_t clabWIFISSIDName_len = OID_LENGTH(clabWIFISSIDName);
    int ssids_num = 0;
    istc_ap_ssid_t *ssid = NULL;
    int i = 0;
    int ret = 0;
    static int snmp_index_init_flag = 0;

    if(snmp_index_init_flag == 1)
    {
        return 0;
    }

    memset(gSNMPWIFISSID, 0, sizeof(gSNMPWIFISSID));
    
    if(istc_snmp_table_parse_datalist(clabWIFISSIDName, clabWIFISSIDName_len, (SnmpTableFun)_clabWIFISSIDTable_set_column, sizeof(clabWIFISSIDTable_rowreq_ctx), &data_head, &ssids_num) != 0)
    {
        istc_log("can not parse clabWIFISSIDName\n");
        return -1;
    }
    istc_log("parse clabWIFISSIDName success\n");
    if(ssids_num <= 0)
    {
        istc_log("get ssids_num %d wrong\n", ssids_num);
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }
    istc_log("get ssids num %d success\n", ssids_num);

    if((ssid = (istc_ap_ssid_t *)calloc(ssids_num, sizeof(istc_ap_ssid_t))) == NULL)
    {
        istc_log("an not calloc\n");
        istc_snmp_table_free_datalist(data_head);
        return -1;
    }
    
    data_list= data_head; 
    while(data_list != NULL && i < ssids_num)
    {
        ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);
        ssid[i].index = data_list->row;
        strncpy(ssid[i].ifname, ctx->data.clabWIFISSIDName, sizeof(ssid[i].ifname) - 1);
        data_list = data_list->next;
        i++;
    }
    istc_snmp_table_free_datalist(data_head);

    if(ssids_num <= ISTC_AP_SSID_LIST_MAX) /*43228*/
    {
        gSNMPWIFISSID[ISTC_AP_SSID_2DOT4G].index = ssid[0].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_SSID_2DOT4G].ifname, ssid[0].ifname);
        
        gSNMPWIFISSID[ISTC_AP_SSID_5G].index = ssid[0].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_SSID_5G].ifname, ssid[0].ifname);
        
        gSNMPWIFISSID[ISTC_AP_GUEST_SSID_2DOT4G].index = ssid[1].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_GUEST_SSID_2DOT4G].ifname, ssid[1].ifname);
        
        gSNMPWIFISSID[ISTC_AP_GUEST_SSID_5G].index = ssid[1].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_GUEST_SSID_5G].ifname, ssid[1].ifname);
        gSNMPWifiInterfaceCount = 1;
        snmp_index_init_flag = 1;
    }
    else if(ssids_num > ISTC_AP_SSID_LIST_MAX + 2) /*4352*/
    {
        gSNMPWIFISSID[ISTC_AP_SSID_2DOT4G].index = ssid[0].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_SSID_2DOT4G].ifname, ssid[0].ifname);
        
        gSNMPWIFISSID[ISTC_AP_SSID_5G].index = ssid[ISTC_AP_INTERFACE_SSID_MAX].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_SSID_5G].ifname, ssid[ISTC_AP_INTERFACE_SSID_MAX].ifname);
        
        gSNMPWIFISSID[ISTC_AP_GUEST_SSID_2DOT4G].index = ssid[1].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_GUEST_SSID_2DOT4G].ifname, ssid[1].ifname);
        
        gSNMPWIFISSID[ISTC_AP_GUEST_SSID_5G].index = ssid[ISTC_AP_INTERFACE_SSID_MAX + 1].index;
        strcpy(gSNMPWIFISSID[ISTC_AP_GUEST_SSID_5G].ifname, ssid[ISTC_AP_INTERFACE_SSID_MAX + 1].ifname);
        gSNMPWifiInterfaceCount = 2;
        snmp_index_init_flag = 1;
    }
    else
    {
        ret = -1;
    }
    
    free(ssid);
    istc_log("init wifi ssid, ret = %d\n", ret);
    return ret;
}

int istc_init(void)
{
    istc_snmp_init();
    while(0 != istc_init_snmp_wifissid())
    {
        sleep(1);
    }
    return 0;
}

int istc_wireless_ap_ssid_add_by_index( const char *ifname, int index, const istc_ap_ssid_t * ssid )
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_wireless_ap_ssid_get_by_index( const char *ifname, int index, istc_ap_ssid_t * ssid )
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    clabWIFISSIDTable_rowreq_ctx *ssid_ctx = NULL;
    clabWIFIRadioTable_rowreq_ctx *clab_wifi_radio_ctx = NULL;
    wifiBssTable_rowreq_ctx *bss_ctx = NULL;
    wifiBssWpaTable_rowreq_ctx *bsswpa_ctx = NULL;
    istc_ap_ssid_t ap_ssid;
    int cnt = 0;
    int ssid_index = 0;
    int disabledflag = 0;

    oid clabWIFISSIDName[] = {CLABWIFISSIDTABLE_OID, CLABWIFISSIDENTRY_OID, COLUMN_CLABWIFISSIDNAME};
    size_t clabWIFISSIDName_len = OID_LENGTH(clabWIFISSIDName);
    
    oid clabWIFIRadioOperatingFrequencyBand[] = {CLABWIFIRADIOTABLE_OID, CLABWIFIRADIOENTRY_OID, COLUMN_CLABWIFIRADIOOPERATINGFREQUENCYBAND, 0};
    size_t clabWIFIRadioOperatingFrequencyBand_len = OID_LENGTH(clabWIFIRadioOperatingFrequencyBand);

    oid wifiBssEnable[] = {WIFIBSSTABLE_OID, WIFIBSSENTRY_OID, COLUMN_WIFIBSSENABLE, 0};
    size_t wifiBssEnable_len = OID_LENGTH(wifiBssEnable);
    oid wifiBssSsid[] = {WIFIBSSTABLE_OID, WIFIBSSENTRY_OID, COLUMN_WIFIBSSSSID, 0};
    size_t wifiBssSsid_len = OID_LENGTH(wifiBssSsid);
    oid wifiBssSecurityMode[] = {WIFIBSSTABLE_OID, WIFIBSSENTRY_OID, COLUMN_WIFIBSSSECURITYMODE, 0};
    size_t wifiBssSecurityMode_len = OID_LENGTH(wifiBssSecurityMode);
    
    oid wifiBssWpaPreSharedKey[] = {WIFIBSSWPATABLE_OID, WIFIBSSWPAENTRY_OID, COLUMN_WIFIBSSWPAPRESHAREDKEY, 0};
    size_t wifiBssWpaPreSharedKey_len = OID_LENGTH(wifiBssWpaPreSharedKey);
    
    SNMP_ASSERT(ssid != NULL);
    SNMP_ASSERT(index > ISTC_AP_SSID_2DOT4G && index <= ISTC_AP_SSID_TYPE_MAX);
    
    memset(&ap_ssid, 0, sizeof(ap_ssid));
    ssid_index = gSNMPWIFISSID[index - 1].index;
    istc_log("index = %d\n", ssid_index);

    ap_ssid.b_visitor = index <= 2 ? 0 : 1;
    
    if(istc_snmp_table_parse_datalist(clabWIFISSIDName, clabWIFISSIDName_len, (SnmpTableFun)_clabWIFISSIDTable_set_column, sizeof(clabWIFISSIDTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFISSIDName\n");
        return -1;
    }
    istc_log("parse clabWIFISSIDName success\n");
    data_list= data_head; 
    while(data_list != NULL)
    {
        ssid_ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);
        if(data_list->row == ssid_index)
        {
            istc_log("find success, index = %d, ifname = %s\n", ssid_index, ssid_ctx->data.clabWIFISSIDName);
            strncpy(ssid->ifname, ssid_ctx->data.clabWIFISSIDName, sizeof(ssid->ifname) - 1);
            break;
        }
        data_list = data_list->next;
    }
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;
    if(data_list == NULL)
    {
        istc_log("can not get bssid, index = %d\n", ssid_index);
        return -1;
    }

    clabWIFIRadioOperatingFrequencyBand[clabWIFIRadioOperatingFrequencyBand_len - 1] = index <= 2 ? ssid_index - 1 : ssid_index - 2;
    wifiBssEnable[wifiBssEnable_len - 1] = ssid_index;
    wifiBssSsid[wifiBssSsid_len - 1] = ssid_index;
    wifiBssSecurityMode[wifiBssSecurityMode_len - 1] = ssid_index;
    wifiBssWpaPreSharedKey[wifiBssWpaPreSharedKey_len - 1] = ssid_index;

    /*get band*/
    switch(index - 1)
    {
    case ISTC_AP_SSID_2DOT4G:
    case ISTC_AP_GUEST_SSID_2DOT4G:
        ap_ssid.band = ISTC_AP_SSID_2DOT4G;
        break;
    case ISTC_AP_SSID_5G:
    case ISTC_AP_GUEST_SSID_5G:
        ap_ssid.band = ISTC_AP_SSID_5G;
        break;
    default:
        istc_log("index %d, not avaliable\n", index);
        return -1;
    }
    if(istc_snmp_table_parse_datalist(clabWIFIRadioOperatingFrequencyBand, clabWIFIRadioOperatingFrequencyBand_len, (SnmpTableFun)_clabWIFIRadioTable_set_column, sizeof(clabWIFIRadioTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFIRadioOperatingFrequencyBand\n");
        return -1;
    }
    istc_log("parse clabWIFIRadioOperatingFrequencyBand success\n");
    clab_wifi_radio_ctx = (clabWIFIRadioTable_rowreq_ctx *)(data_head->data);
    switch((int)(clab_wifi_radio_ctx->data.clabWIFIRadioOperatingFrequencyBand))
    {
    case CLABWIFIRADIOOPERATINGFREQUENCYBAND_N2DOT4GHZ:
        if(gSNMPWifiInterfaceCount == 1 && (index - 1 ==  ISTC_AP_SSID_5G || index - 1 == ISTC_AP_GUEST_SSID_5G))
        {
            disabledflag = 1;
        }
        break;
    case CLABWIFIRADIOOPERATINGFREQUENCYBAND_N5GHZ:
        if(gSNMPWifiInterfaceCount == 1 && (index - 1 ==  ISTC_AP_SSID_2DOT4G || index - 1 == ISTC_AP_GUEST_SSID_2DOT4G))
        {
            disabledflag = 1;
        }
        break;
    default:
        break;
    }
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;

    /*get enabledflag*/
    if(disabledflag == 0)
    {
        if(istc_snmp_table_parse_datalist(wifiBssEnable, wifiBssEnable_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &cnt) != 0)
        {
            istc_log("can not parse wifiBssEnable\n");
            return -1;
        }
        istc_log("parse wifiBssEnable success\n");
        bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
        ap_ssid.b_disable = (bss_ctx->data.wifiBssEnable == TRUTHVALUE_TRUE) ? 0 : 1;
        istc_snmp_table_free_datalist(data_head);
        data_head = NULL;
    }
    else
    {
        ap_ssid.b_disable = 1;
    }

    /*get ssid name*/
    if(istc_snmp_table_parse_datalist(wifiBssSsid, wifiBssSsid_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSsid\n");
        return -1;
    }
    istc_log("parse wifiBssSsid success\n");
    bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
    strncpy(ap_ssid.ssid, bss_ctx->data.wifiBssSsid, sizeof(ap_ssid.ssid) - 1);
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;

    /*get security mode*/
    if(istc_snmp_table_parse_datalist(wifiBssSecurityMode, wifiBssSecurityMode_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSecurityMode\n");
        return -1;
    }
    istc_log("parse wifiBssSecurityMode success\n");
    bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
    switch(bss_ctx->data.wifiBssSecurityMode)
    {
    case WIFIBSSSECURITYMODE_DISABLED:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_OPEN;
        break;
    case WIFIBSSSECURITYMODE_WEP:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WEP;
        break;
    case WIFIBSSSECURITYMODE_WPAPSK:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA;
        break;
    case WIFIBSSSECURITYMODE_WPA2PSK:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA2;
        break;
    case WIFIBSSSECURITYMODE_WPAWPA2PSK:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA_WPA2;
        break;
    default:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_NONE;
        break;
    }
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;
    if(ap_ssid.encryption == ISTC_WIRELESS_ENCRYPTION_OPEN ||
        ap_ssid.encryption == ISTC_WIRELESS_ENCRYPTION_NONE)
    {
        memcpy((void *)ssid, (const void *)&ap_ssid, sizeof(ap_ssid));
        istc_log("encryption is not open or unknown, we will return\n");
        return 0;
    }

    /*get password*/
    if(istc_snmp_table_parse_datalist(wifiBssWpaPreSharedKey, wifiBssWpaPreSharedKey_len, (SnmpTableFun)_wifiBssWpaTable_set_column, sizeof(wifiBssWpaTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssWpaTable_rowreq_ctx\n");
        return -1;
    }
    istc_log("parse wifiBssWpaTable_rowreq_ctx success\n");
    bsswpa_ctx = (wifiBssWpaTable_rowreq_ctx *)(data_head->data);
    strncpy(ap_ssid.password, bsswpa_ctx->data.wifiBssWpaPreSharedKey, sizeof(ap_ssid.password) - 1);
    istc_snmp_table_free_datalist(data_head);
    data_head = NULL;

    memcpy((void *)ssid, (const void *)&ap_ssid, sizeof(ap_ssid));
    return 0;
}

int istc_wireless_ap_ssid_set_by_index( const char *ifname, int index, const istc_ap_ssid_t * ssid )
{
    istc_ap_ssid_t ap_ssid;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = ISTC_SNMP_ERR_UNKNOWN;
    char security_mode[16] = {0};
    int ssid_index = 0;
    char valuestr[16] = {0};
    int band = 0;
    
    oid wifiBssEnable[] = {WIFIBSSTABLE_OID, WIFIBSSENTRY_OID, COLUMN_WIFIBSSENABLE, 0};
    size_t wifiBssEnable_len = OID_LENGTH(wifiBssEnable);
    oid wifiBssSsid[] = {WIFIBSSTABLE_OID, WIFIBSSENTRY_OID, COLUMN_WIFIBSSSSID, 0};
    size_t wifiBssSsid_len = OID_LENGTH(wifiBssSsid);
    oid wifiBssSecurityMode[] = {WIFIBSSTABLE_OID, WIFIBSSENTRY_OID, COLUMN_WIFIBSSSECURITYMODE, 0};
    size_t wifiBssSecurityMode_len = OID_LENGTH(wifiBssSecurityMode);
    oid wifiBssWpaPreSharedKey[] = {WIFIBSSWPATABLE_OID, WIFIBSSWPAENTRY_OID, COLUMN_WIFIBSSWPAPRESHAREDKEY, 0};
    size_t wifiBssWpaPreSharedKey_len = OID_LENGTH(wifiBssWpaPreSharedKey);
    
    oid clabWIFIRadioOperatingFrequencyBand[] = {CLABWIFIRADIOTABLE_OID, CLABWIFIRADIOENTRY_OID, COLUMN_CLABWIFIRADIOOPERATINGFREQUENCYBAND, 0};
    size_t clabWIFIRadioOperatingFrequencyBand_len = OID_LENGTH(clabWIFIRadioOperatingFrequencyBand);
    oid clabWIFIWIFICommitSettingsValue[] = {CLABWIFIWIFICOMMITSETTINGSVALUE_OID, 0};
    size_t clabWIFIWIFICommitSettingsValue_len = OID_LENGTH(clabWIFIWIFICommitSettingsValue);
    
    SNMP_ASSERT(ssid != NULL && ssid->ssid[0] != 0);
    SNMP_ASSERT(index > ISTC_AP_SSID_2DOT4G && index <= ISTC_AP_SSID_TYPE_MAX);

    if(ssid->encryption != ISTC_WIRELESS_ENCRYPTION_OPEN)
    {
        if(ssid->password[0] == 0 || strlen(ssid->password) < 8)
        {
            istc_log("password wrong\n");
            return -1;
        }
    }

    istc_log("ssid->encryption= %d\n", ssid->encryption);
    switch(ssid->encryption)
    {
    case ISTC_WIRELESS_ENCRYPTION_OPEN:
        istc_inet_itoa(WIFIBSSSECURITYMODE_DISABLED, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
        break;
    case ISTC_WIRELESS_ENCRYPTION_WEP:
        istc_inet_itoa(WIFIBSSSECURITYMODE_WEP, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
        break;
    case ISTC_WIRELESS_ENCRYPTION_WPA:
        istc_inet_itoa(WIFIBSSSECURITYMODE_WPAPSK, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
        break;
    case ISTC_WIRELESS_ENCRYPTION_WPA2:
        istc_inet_itoa(WIFIBSSSECURITYMODE_WPA2PSK, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
        break;
    case ISTC_WIRELESS_ENCRYPTION_WPA_WPA2:
        istc_inet_itoa(WIFIBSSSECURITYMODE_WPAWPA2PSK, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
        break;
    default:
        istc_log("unkonwn security mode:%d\n", ssid->encryption);
        return -1;
    }
    strncpy(security_mode, valuestr, sizeof(security_mode) - 1);
    
    switch(ssid->band)
    {
    case ISTC_AP_SSID_2DOT4G:
        band = CLABWIFIRADIOOPERATINGFREQUENCYBAND_N2DOT4GHZ;
        break;
    case ISTC_AP_SSID_5G:
        band = CLABWIFIRADIOOPERATINGFREQUENCYBAND_N5GHZ;
        break;
    default:
        istc_log("not supported band %d\n", ssid->band);
        return -1;
    }
    
    if(istc_init_snmp_wifissid() != 0)
    {
        istc_log("can not init snmp index\n");
        return -1;
    }
    
    memset(&ap_ssid, 0, sizeof(ap_ssid));
    ssid_index = gSNMPWIFISSID[index - 1].index;
    istc_log("index = %d\n", ssid_index);
    
    wifiBssEnable[wifiBssEnable_len - 1] = ssid_index;
    wifiBssSsid[wifiBssSsid_len - 1] = ssid_index;
    wifiBssWpaPreSharedKey[wifiBssWpaPreSharedKey_len - 1] = ssid_index;
    wifiBssSecurityMode[wifiBssSecurityMode_len - 1] = ssid_index;
    clabWIFIRadioOperatingFrequencyBand[clabWIFIRadioOperatingFrequencyBand_len - 1] = index <= 2 ? ssid_index - 1 : ssid_index - 2;
    
    /*set fenquencry band*/
    istc_inet_itoa(band, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
    if(istc_snmp_set(clabWIFIRadioOperatingFrequencyBand, clabWIFIRadioOperatingFrequencyBand_len, SNMP_INT, valuestr, &stat) != 0)
    {
        istc_log("can not set fenquencry band, index = %d\n", ssid_index);
        //return -1;
    }
    istc_log("set fenquencry band success\n");
    istc_inet_itoa(TRUTHVALUE_TRUE, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
    if(istc_snmp_set(clabWIFIWIFICommitSettingsValue, clabWIFIWIFICommitSettingsValue_len, SNMP_INT, valuestr, &stat) != 0)
    {
        istc_log("can not set clab wifi commit sertings, index = %d\n", ssid_index);
        //return -1;
    }
    istc_log("set clab wifi commit sertings success\n");

    /*set ssid*/
    if(istc_snmp_set(wifiBssSsid, wifiBssSsid_len, SNMP_STRING, (char *)ssid->ssid, &stat) != 0)
    {
        istc_log("can not set ssid name, index = %d\n", ssid_index);
        //return -1;
    }
    istc_log("set ssid name success\n");

    /*set security mode*/
    if(istc_snmp_set(wifiBssSecurityMode, wifiBssSecurityMode_len, SNMP_INT, (char *)security_mode, &stat) != 0)
    {
        istc_log("can not set ssid security mode, index = %d\n", ssid_index);
        //return -1;
    }
    istc_log("set ssid security mode success\n");

    /*set password*/
    if(*security_mode != '0')
    {
        if(istc_snmp_set(wifiBssWpaPreSharedKey, wifiBssWpaPreSharedKey_len, SNMP_STRING, (char *)ssid->password, &stat) != 0)
        {
            istc_log("can not set password\n");
            //return -1;
        }
        istc_log("set wifiBssWpaPreSharedKey success\n");
    }

    /*set enable or disable*/
    if(ssid->b_disable == 1)
    {
        istc_inet_itoa(TRUTHVALUE_FALSE, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
    }
    else
    {
        istc_inet_itoa(TRUTHVALUE_TRUE, valuestr, sizeof(valuestr) / sizeof(valuestr[0]));
    }
    if(istc_snmp_set(wifiBssEnable, wifiBssEnable_len, SNMP_INT, valuestr, &stat) != 0)
    {
        istc_log("can not set bss enable, ssid = %s, index = %d\n", ssid->ssid, ssid_index);
        //return -1;
    }
    istc_log("set wifiBssEnable success\n");
    
    istc_log("ssid set success, index = %d\n", ssid_index);
    return 0;
}

int istc_wireless_ap_ssid_remove_by_index( const char *ifname, int index )
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_lan_set_addr_info( unsigned int gateway, unsigned int addr_begin, unsigned int addr_end )
{
    ISTC_NOTSUPPORT
    return -1;
}

int istc_lan_get_addr_info( unsigned int *gateway, unsigned int *addr_begin, unsigned int *addr_end )
{
    ISTC_NOTSUPPORT
    return -1;
}

