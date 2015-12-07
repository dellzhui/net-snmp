#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "net-snmp/types.h"
#include "local_demoIpTable.h"
#include "snmp_interfaces.h"

NETSNMP_STATIC_INLINE int
demoIpTable_set_column( demoIpTable_rowreq_ctx *rowreq_ctx,
                       netsnmp_variable_list *var, int column )
{
    int rc = SNMPERR_SUCCESS;
    
    //DEBUGMSGTL(("internal:demoIpTable:_demoIpTable_set_column",
    //            "called for %d\n", column));

    //netsnmp_assert(NULL != rowreq_ctx);

    switch(column) {

    /* demoIpInuse(2)/INTEGER32/ASN_INTEGER/long(long)//l/A/W/e/r/d/h */
    case COLUMN_DEMOIPINUSE:
        rowreq_ctx->column_set_flags |= COLUMN_DEMOIPINUSE_FLAG;
        rc = demoIpInuse_set(rowreq_ctx, *((long *)var->val.string) );
        break;

    /* demoIpAddress(3)/OCTETSTR/ASN_OCTET_STR/char(char)//L/A/W/e/r/d/h */
    case COLUMN_DEMOIPADDRESS:
        rowreq_ctx->column_set_flags |= COLUMN_DEMOIPADDRESS_FLAG;
        rc = demoIpAddress_set(rowreq_ctx, (char *)var->val.string, var->val_len );
        break;

    /* demoMacAddress(4)/OCTETSTR/ASN_OCTET_STR/char(char)//L/A/W/e/r/d/h */
    case COLUMN_DEMOMACADDRESS:
        rowreq_ctx->column_set_flags |= COLUMN_DEMOMACADDRESS_FLAG;
        rc = demoMacAddress_set(rowreq_ctx, (char *)var->val.string, var->val_len );
        break;

     default:
         snmp_log(LOG_ERR,"unknown column %d in _demoIpTable_set_column\n", column);
         rc = SNMP_ERR_GENERR;
         break;
    }
    
    return rc;
} /* _demoIpTable_set_column */

