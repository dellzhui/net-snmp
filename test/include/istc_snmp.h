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

int istc_snmp_init(void);
int istc_snmp_print_oid(oid *Oid, int len);
int istc_snmp_print_pdu(netsnmp_pdu *pResponse, char *oid_name);
int istc_snmp_free_pdu(netsnmp_pdu *pResponse);
int istc_snmp_walk(char *host, char *community, char *oid_name, int *reps, netsnmp_pdu **pResponse);
int istc_snmp_set(char *host, char *community, char *oid_name, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);


#ifdef __cplusplus
}
#endif
#endif

