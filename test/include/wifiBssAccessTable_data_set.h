/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 *
 * $Id:$
 */
#ifndef WIFIBSSACCESSTABLE_DATA_SET_H
#define WIFIBSSACCESSTABLE_DATA_SET_H

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
 *** Table wifiBssAccessTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * BRCM-WIFI-MGMT-MIB::wifiBssAccessTable is subid 1 of wifiMbssAccess.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4413.2.2.2.1.18.1.2.4.1, length: 16
*/


int wifiBssAccessTable_undo_setup( wifiBssAccessTable_rowreq_ctx *rowreq_ctx);
int wifiBssAccessTable_undo_cleanup( wifiBssAccessTable_rowreq_ctx *rowreq_ctx);
int wifiBssAccessTable_undo( wifiBssAccessTable_rowreq_ctx *rowreq_ctx);
int wifiBssAccessTable_commit( wifiBssAccessTable_rowreq_ctx *rowreq_ctx);
int wifiBssAccessTable_undo_commit( wifiBssAccessTable_rowreq_ctx *rowreq_ctx);


int wifiBssAccessStation_check_value( wifiBssAccessTable_rowreq_ctx *rowreq_ctx, char *wifiBssAccessStation_val_ptr,  size_t wifiBssAccessStation_val_ptr_len);
int wifiBssAccessStation_undo_setup( wifiBssAccessTable_rowreq_ctx *rowreq_ctx );
int wifiBssAccessStation_set( wifiBssAccessTable_rowreq_ctx *rowreq_ctx, char *wifiBssAccessStation_val_ptr,  size_t wifiBssAccessStation_val_ptr_len );
int wifiBssAccessStation_undo( wifiBssAccessTable_rowreq_ctx *rowreq_ctx );

int wifiBssAccessStatus_check_value( wifiBssAccessTable_rowreq_ctx *rowreq_ctx, u_long wifiBssAccessStatus_val);
int wifiBssAccessStatus_undo_setup( wifiBssAccessTable_rowreq_ctx *rowreq_ctx );
int wifiBssAccessStatus_set( wifiBssAccessTable_rowreq_ctx *rowreq_ctx, u_long wifiBssAccessStatus_val );
int wifiBssAccessStatus_undo( wifiBssAccessTable_rowreq_ctx *rowreq_ctx );


int wifiBssAccessTable_check_dependencies(wifiBssAccessTable_rowreq_ctx *ctx);


#ifdef __cplusplus
}
#endif

#endif /* WIFIBSSACCESSTABLE_DATA_SET_H */