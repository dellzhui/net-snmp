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
  snmp interfaces for istc

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
2016-02-03, chenfx@inspur.com           written
*/


#ifndef __ISTC_SNMP_H__
#define __ISTC_SNMP_H__

#ifdef __plusplus
export "C" {
#endif

#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"

#include "demoIpTable_interface.h"
#include "clabWIFIAccessPointTable_interface.h"
#include "clabWIFISSIDTable_interface.h"
#include "wifiBssWpaTable_interface.h"
#include "wifiBssTable_interface.h"
#include "ifTable_interface.h"
#include "ipAddrTable_oids.h"
#include "ifXTable_interface.h"
#include "dot11BssTable_interface.h"
#include "wifiBssAccessTable_interface.h"
#include "clabWIFIAssociatedDeviceTable_interface.h"
#include "rgIpLanAddrTable_interface.h"
#include "clabWIFIRadioTable_interface.h"
#include "clabWIFIWIFICommitSettings_oids.h"
#include "wifiAssocStaTable_interface.h"
#include "clabWIFIRadioStatsTable_interface.h"
#include "cabhCdpWanDnsServerTable_interface.h"


#define SNMP_INT 'i'
#define SNMP_X 'x'
#define SNMP_STRING 's'
#define SNMP_U 'u'
#define DEFAULT_LAN_INTERFACE "eth2"

#define WAN_INTERFACE_INDEX 1
#define WLAN0_INTERFACE_INDEX 10000
#define WLAN1_INTERFACE_INDEX 10100

#define SNMP_ASSERT(x) \
                do { \
                    if((x) == 0) \
                    { \
                        istc_log("input wrong\n"); \
                        return (-1); \
                    } \
                }while(0)


enum
{
    ISTC_SNMP_ERROR = -1,
    ISTC_SNMP_SUCCESS = 0
};

typedef enum
{
    ISTC_SNMP_ERR_UNKNOWN = -1,
    ISTC_SNMP_ERR_NOERROR = 0,
    ISTC_SNMP_ERR_TOOBIG = 1,
    ISTC_SNMP_ERR_NOSUCHNAME = 2,
    ISTC_SNMP_ERR_BADVALUE = 3,
    ISTC_SNMP_ERR_READONLY= 4,
    ISTC_SNMP_ERR_GENERR = 5,
    ISTC_SNMP_ERR_NOACCESS = 6,
    ISTC_SNMP_ERR_WRONGTYPE = 7,
    ISTC_SNMP_ERR_WRONGLENGTH = 8,
    ISTC_SNMP_ERR_WRONGENCODING = 9,
    ISTC_SNMP_ERR_WRONGVALUE = 10,
    ISTC_SNMP_ERR_NOCREATION = 11,
    ISTC_SNMP_ERR_INCONSISTENTVALUE = 12,
    ISTC_SNMP_ERR_RESOURCEUNAVAILABLE = 13,
    ISTC_SNMP_ERR_COMMITFAILED = 14,
    ISTC_SNMP_ERR_UNDOFAILED = 15,
    ISTC_SNMP_ERR_AUTHORIZATIONERROR = 16,
    ISTC_SNMP_ERR_NOTWRITABLE = 17,
    ISTC_SNMP_ERR_INCONSISTENTNAME = 18,
}ISTC_SNMP_RESPONSE_ERRSTAT;

/*istc_snmp_table_parse_datalist输出的数据结构*/
typedef struct tagSNMP_DATA
{
    struct tagSNMP_DATA *next;
    void *data; /*mib库中每个table对应的结构体，调用istc_snmp_table_parse_datalist后，可以直接映射到特定table的结构I，
                如ssid_ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);*/
    int row;
}SNMP_DATA_LIST_st; 

typedef struct tagPDU_LIST
{
    struct tagPDU_LIST *next;
    struct snmp_pdu *response;
}PDU_LIST_st;

typedef struct tagSNMP_AGENT_INFO_st
{
    int retries;
    char name[32];
    char community[32];
}SNMP_AGENT_INFO_st;

typedef int (*SnmpTableFun)(void *rowreq_ctx, netsnmp_variable_list *var, int column);


int istc_snmp_init(void);
int istc_snmp_get_agent_info(SNMP_AGENT_INFO_st *agentinfo);
int istc_snmp_update_agent_info(SNMP_AGENT_INFO_st agentinfo);

int istc_snmp_walk(oid *anOID, size_t anOID_len, PDU_LIST_st **pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);
int istc_snmp_free_pdulist(PDU_LIST_st *pdu_list);
int istc_snmp_table_get_rows_num(PDU_LIST_st *pPDUList, int *rows_num);

int istc_snmp_set(oid *anOID, size_t anOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);

int istc_snmp_print_oid(oid *Oid, int len);
int istc_snmp_print_pdulist(PDU_LIST_st *pdu_list, oid *rootOID, size_t rootOID_len);


/*************************************************************************

函数: istc_snmp_table_parse_datalist

输入:
    rootOID: snmp OID数组，如 oid clabWIFISSIDName[] = {SNMP_TABLE_ID, SNMP_TABLE_COLUMN_ID, SNMP_TABLE_COLUMN_INDEX};其中至少输入SNMP_TABLE_ID
    rootOID_len: rootOID的长度
    fun: 每一个table的callback
    DataLen: table的数据结构的长度

输出: 
    pDataList: walk的结果链表
    pRowsNum: walk到的结果列表中结构体的个数，即每个属性(column)的行数

返回:
    0: 成功
    -1: 失败
    
*************************************************************************/
int istc_snmp_table_parse_datalist(oid *rootOID, size_t rootOID_len, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList, int *pRowsNum);
int istc_snmp_table_free_datalist(SNMP_DATA_LIST_st *pDataList);



#ifdef __cplusplus
}
#endif
#endif

