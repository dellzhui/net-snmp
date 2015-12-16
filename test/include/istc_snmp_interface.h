#ifndef __ISTC_SNMP_H__
#define __ISTC_SNMP_H__

#ifdef __plusplus
export "C" {
#endif

#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"

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
    ISTC_SNMP_ERR_TOOBIG,
    ISTC_SNMP_ERR_NOSUCHNAME,
    ISTC_SNMP_ERR_BADVALUE,
    ISTC_SNMP_ERR_READONLY,
    ISTC_SNMP_ERR_GENERR,
    ISTC_SNMP_ERR_NOACCESS ,
    ISTC_SNMP_ERR_WRONGTYPE,
    ISTC_SNMP_ERR_WRONGLENGTH,
    ISTC_SNMP_ERR_WRONGENCODING,
    ISTC_SNMP_ERR_WRONGVALUE,
    ISTC_SNMP_ERR_NOCREATION,
    ISTC_SNMP_ERR_INCONSISTENTVALUE,
    ISTC_SNMP_ERR_RESOURCEUNAVAILABLE,
    ISTC_SNMP_ERR_COMMITFAILED,
    ISTC_SNMP_ERR_UNDOFAILED,
    ISTC_SNMP_ERR_AUTHORIZATIONERROR,
    ISTC_SNMP_ERR_NOTWRITABLE,
    ISTC_SNMP_ERR_INCONSISTENTNAME
}ISTC_SNMP_RESPONSE_ERRSTAT;

typedef struct tagSNMP_DATA
{
    struct tagSNMP_DATA *next;
    void *data;
    int row;
    int column;
}SNMP_DATA_LIST_st;

typedef struct tagPDU_LIST
{
    struct tagPDU_LIST *next;
    struct snmp_pdu *response;
}PDU_LIST_st;

typedef struct tagSNMP_AGENT_INFO_st
{
    char name[32];
    char community[32];
}SNMP_AGENT_INFO_st;

typedef int (*SnmpTableFun)(void *rowreq_ctx, netsnmp_variable_list *var, int column);


int istc_snmp_init(void);
int istc_snmp_walk(oid *anOID, size_t anOID_len, PDU_LIST_st **pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);
int istc_snmp_set(oid *anOID, size_t anOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);
int istc_snmp_print_oid(oid *Oid, int len);
int istc_snmp_print_pdulist(PDU_LIST_st *pdu_list, oid *rootOID, size_t rootOID_len);
int istc_snmp_free_pdulist(PDU_LIST_st *pdu_list);
int istc_snmp_free_datalist(SNMP_DATA_LIST_st *pDataList);
int istc_snmp_table_parse_data(oid *rootOID, size_t rootOID_len, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList, int *pRowsNum);
int istc_snmp_update_agent_info(SNMP_AGENT_INFO_st agentinfo);

#ifdef __cplusplus
}
#endif
#endif

