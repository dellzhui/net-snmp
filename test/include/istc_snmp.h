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

int istc_snmp_init(void);
int istc_snmp_print_oid(oid *Oid, int len);
int istc_snmp_print_pdu(netsnmp_pdu *pResponse, char *oid_name);
int istc_snmp_free_pdu(netsnmp_pdu *pResponse);
int istc_snmp_walk(char *host, char *community, char *oid_name, int *reps, netsnmp_pdu **pResponse);


#ifdef __cplusplus
}
#endif
#endif

