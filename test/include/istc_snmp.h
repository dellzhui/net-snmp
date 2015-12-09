#ifndef __ISTC_SNMP_H__
#define __ISTC_SNMP_H__

#ifdef __plusplus
export "C" {
#endif

#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"

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
}SNMP_DATA_LIST;

typedef struct tagPDU_LIST
{
    struct tagPDU_LIST *next;
    struct snmp_pdu *response;
}PDU_LIST_st;

typedef int (*table_set_column)(void *rowreq_ctx, netsnmp_variable_list *var, int column);


int istc_snmp_init(void);
int istc_snmp_print_oid(oid *Oid, int len);
int istc_snmp_print_pdu(PDU_LIST_st *pdu_list, char *oid_name);
int istc_snmp_free_pdulist(PDU_LIST_st *pdu_list);
int istc_snmp_free_datalist(SNMP_DATA_LIST *data_list);
int istc_snmp_walk(char *oid_name, PDU_LIST_st **pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);
int istc_snmp_set(char *oid_name, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);
int istc_snmp_patse_data(char *oid_name, SNMP_DATA_LIST **data_list);
int istc_snmp_get_host_name(char *host_name, int host_name_len);
int istc_snmp_set_host_name(char *host_name);
int istc_snmp_get_community_name(char *community_name, int community_name_len);
int istc_snmp_set_community_name(char *community_name);


#ifdef __cplusplus
}
#endif
#endif

