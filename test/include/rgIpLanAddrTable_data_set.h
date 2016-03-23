/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 *
 * $Id:$
 */
#ifndef RGIPLANADDRTABLE_DATA_SET_H
#define RGIPLANADDRTABLE_DATA_SET_H

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
 *** Table rgIpLanAddrTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * BRCM-RG-IP-MIB::rgIpLanAddrTable is subid 1 of rgIpLanAddr.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4413.2.2.2.1.7.2.3.1, length: 15
*/


int rgIpLanAddrTable_undo_setup( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx);
int rgIpLanAddrTable_undo_cleanup( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx);
int rgIpLanAddrTable_undo( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx);
int rgIpLanAddrTable_commit( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx);
int rgIpLanAddrTable_undo_commit( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx);


int rgIpLanAddrClientID_check_value( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrClientID_val_ptr,  size_t rgIpLanAddrClientID_val_ptr_len);
int rgIpLanAddrClientID_undo_setup( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );
int rgIpLanAddrClientID_set( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrClientID_val_ptr,  size_t rgIpLanAddrClientID_val_ptr_len );
int rgIpLanAddrClientID_undo( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );

int rgIpLanAddrLeaseCreateTime_check_value( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrLeaseCreateTime_val_ptr,  size_t rgIpLanAddrLeaseCreateTime_val_ptr_len);
int rgIpLanAddrLeaseCreateTime_undo_setup( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );
int rgIpLanAddrLeaseCreateTime_set( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrLeaseCreateTime_val_ptr,  size_t rgIpLanAddrLeaseCreateTime_val_ptr_len );
int rgIpLanAddrLeaseCreateTime_undo( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );

int rgIpLanAddrLeaseExpireTime_check_value( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrLeaseExpireTime_val_ptr,  size_t rgIpLanAddrLeaseExpireTime_val_ptr_len);
int rgIpLanAddrLeaseExpireTime_undo_setup( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );
int rgIpLanAddrLeaseExpireTime_set( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrLeaseExpireTime_val_ptr,  size_t rgIpLanAddrLeaseExpireTime_val_ptr_len );
int rgIpLanAddrLeaseExpireTime_undo( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );

int rgIpLanAddrHostName_check_value( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrHostName_val_ptr,  size_t rgIpLanAddrHostName_val_ptr_len);
int rgIpLanAddrHostName_undo_setup( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );
int rgIpLanAddrHostName_set( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx, char *rgIpLanAddrHostName_val_ptr,  size_t rgIpLanAddrHostName_val_ptr_len );
int rgIpLanAddrHostName_undo( rgIpLanAddrTable_rowreq_ctx *rowreq_ctx );


int rgIpLanAddrTable_check_dependencies(rgIpLanAddrTable_rowreq_ctx *ctx);


#ifdef __cplusplus
}
#endif

#endif /* RGIPLANADDRTABLE_DATA_SET_H */
