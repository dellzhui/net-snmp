/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 *
 * $Id:$
 */
#ifndef CABHCDPWANDNSSERVERTABLE_DATA_SET_H
#define CABHCDPWANDNSSERVERTABLE_DATA_SET_H

#ifdef __cplusplus
extern "C" {
#endif

/* *********************************************************************
 * SET function declarations
 */

/* *********************************************************************
 * SET Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table cabhCdpWanDnsServerTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * CABH-CDP-MIB::cabhCdpWanDnsServerTable is subid 3 of cabhCdpAddr.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4491.2.4.4.1.2.3, length: 13
*/


int cabhCdpWanDnsServerTable_undo_setup( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx);
int cabhCdpWanDnsServerTable_undo_cleanup( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx);
int cabhCdpWanDnsServerTable_undo( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx);
int cabhCdpWanDnsServerTable_commit( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx);
int cabhCdpWanDnsServerTable_undo_commit( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx);


int cabhCdpWanDnsServerIpType_check_value( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx, u_long cabhCdpWanDnsServerIpType_val);
int cabhCdpWanDnsServerIpType_undo_setup( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx );
int cabhCdpWanDnsServerIpType_set( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx, u_long cabhCdpWanDnsServerIpType_val );
int cabhCdpWanDnsServerIpType_undo( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx );

int cabhCdpWanDnsServerIp_check_value( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx, char *cabhCdpWanDnsServerIp_val_ptr,  size_t cabhCdpWanDnsServerIp_val_ptr_len);
int cabhCdpWanDnsServerIp_undo_setup( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx );
int cabhCdpWanDnsServerIp_set( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx, char *cabhCdpWanDnsServerIp_val_ptr,  size_t cabhCdpWanDnsServerIp_val_ptr_len );
int cabhCdpWanDnsServerIp_undo( cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx );


int cabhCdpWanDnsServerTable_check_dependencies(cabhCdpWanDnsServerTable_rowreq_ctx *ctx);


#ifdef __cplusplus
}
#endif

#endif /* CABHCDPWANDNSSERVERTABLE_DATA_SET_H */
