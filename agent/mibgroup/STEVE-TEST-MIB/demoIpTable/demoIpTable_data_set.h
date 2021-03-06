/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 *
 * $Id:$
 */
#ifndef DEMOIPTABLE_DATA_SET_H
#define DEMOIPTABLE_DATA_SET_H

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
 *** Table demoIpTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * STEVE-TEST-MIB::demoIpTable is subid 1 of products.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.12345.1.1, length: 9
*/


int demoIpTable_undo_setup( demoIpTable_rowreq_ctx *rowreq_ctx);
int demoIpTable_undo_cleanup( demoIpTable_rowreq_ctx *rowreq_ctx);
int demoIpTable_undo( demoIpTable_rowreq_ctx *rowreq_ctx);
int demoIpTable_commit( demoIpTable_rowreq_ctx *rowreq_ctx);
int demoIpTable_undo_commit( demoIpTable_rowreq_ctx *rowreq_ctx);


int demoIpInuse_check_value( demoIpTable_rowreq_ctx *rowreq_ctx, long demoIpInuse_val);
int demoIpInuse_undo_setup( demoIpTable_rowreq_ctx *rowreq_ctx );
int demoIpInuse_set( demoIpTable_rowreq_ctx *rowreq_ctx, long demoIpInuse_val );
int demoIpInuse_undo( demoIpTable_rowreq_ctx *rowreq_ctx );

int demoIpAddress_check_value( demoIpTable_rowreq_ctx *rowreq_ctx, char *demoIpAddress_val_ptr,  size_t demoIpAddress_val_ptr_len);
int demoIpAddress_undo_setup( demoIpTable_rowreq_ctx *rowreq_ctx );
int demoIpAddress_set( demoIpTable_rowreq_ctx *rowreq_ctx, char *demoIpAddress_val_ptr,  size_t demoIpAddress_val_ptr_len );
int demoIpAddress_undo( demoIpTable_rowreq_ctx *rowreq_ctx );

int demoMacAddress_check_value( demoIpTable_rowreq_ctx *rowreq_ctx, char *demoMacAddress_val_ptr,  size_t demoMacAddress_val_ptr_len);
int demoMacAddress_undo_setup( demoIpTable_rowreq_ctx *rowreq_ctx );
int demoMacAddress_set( demoIpTable_rowreq_ctx *rowreq_ctx, char *demoMacAddress_val_ptr,  size_t demoMacAddress_val_ptr_len );
int demoMacAddress_undo( demoIpTable_rowreq_ctx *rowreq_ctx );


int demoIpTable_check_dependencies(demoIpTable_rowreq_ctx *ctx);


#ifdef __cplusplus
}
#endif

#endif /* DEMOIPTABLE_DATA_SET_H */
