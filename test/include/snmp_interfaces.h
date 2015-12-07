#ifndef __SNMP_INTERFACES_H__
#define __SNMP_INTERFACES_H__

#ifdef __cplusplus
export "C" {
#endif

#include "local_demoIpTable.h"

NETSNMP_STATIC_INLINE int
demoIpTable_set_column( demoIpTable_rowreq_ctx *rowreq_ctx,
                       netsnmp_variable_list *var, int column );

                       








#ifdef __cplusplus
}
#endif

#endif
