/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 *
 * $Id:$
 */
#ifndef IFXTABLE_DATA_SET_H
#define IFXTABLE_DATA_SET_H

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
 *** Table ifXTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * IF-MIB::ifXTable is subid 1 of ifMIBObjects.
 * Its status is Current.
 * OID: .1.3.6.1.2.1.31.1.1, length: 9
*/


int ifXTable_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx);
int ifXTable_undo_cleanup( ifXTable_rowreq_ctx *rowreq_ctx);
int ifXTable_undo( ifXTable_rowreq_ctx *rowreq_ctx);
int ifXTable_commit( ifXTable_rowreq_ctx *rowreq_ctx);
int ifXTable_undo_commit( ifXTable_rowreq_ctx *rowreq_ctx);


int ifName_check_value( ifXTable_rowreq_ctx *rowreq_ctx, char *ifName_val_ptr,  size_t ifName_val_ptr_len);
int ifName_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifName_set( ifXTable_rowreq_ctx *rowreq_ctx, char *ifName_val_ptr,  size_t ifName_val_ptr_len );
int ifName_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifInMulticastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifInMulticastPkts_val);
int ifInMulticastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifInMulticastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifInMulticastPkts_val );
int ifInMulticastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifInBroadcastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifInBroadcastPkts_val);
int ifInBroadcastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifInBroadcastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifInBroadcastPkts_val );
int ifInBroadcastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifOutMulticastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifOutMulticastPkts_val);
int ifOutMulticastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifOutMulticastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifOutMulticastPkts_val );
int ifOutMulticastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifOutBroadcastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifOutBroadcastPkts_val);
int ifOutBroadcastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifOutBroadcastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifOutBroadcastPkts_val );
int ifOutBroadcastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCInOctets_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInOctets_val);
int ifHCInOctets_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCInOctets_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInOctets_val );
int ifHCInOctets_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCInUcastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInUcastPkts_val);
int ifHCInUcastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCInUcastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInUcastPkts_val );
int ifHCInUcastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCInMulticastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInMulticastPkts_val);
int ifHCInMulticastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCInMulticastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInMulticastPkts_val );
int ifHCInMulticastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCInBroadcastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInBroadcastPkts_val);
int ifHCInBroadcastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCInBroadcastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCInBroadcastPkts_val );
int ifHCInBroadcastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCOutOctets_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutOctets_val);
int ifHCOutOctets_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCOutOctets_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutOctets_val );
int ifHCOutOctets_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCOutUcastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutUcastPkts_val);
int ifHCOutUcastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCOutUcastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutUcastPkts_val );
int ifHCOutUcastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCOutMulticastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutMulticastPkts_val);
int ifHCOutMulticastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCOutMulticastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutMulticastPkts_val );
int ifHCOutMulticastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHCOutBroadcastPkts_check_value( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutBroadcastPkts_val);
int ifHCOutBroadcastPkts_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHCOutBroadcastPkts_set( ifXTable_rowreq_ctx *rowreq_ctx, U64 ifHCOutBroadcastPkts_val );
int ifHCOutBroadcastPkts_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifLinkUpDownTrapEnable_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifLinkUpDownTrapEnable_val);
int ifLinkUpDownTrapEnable_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifLinkUpDownTrapEnable_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifLinkUpDownTrapEnable_val );
int ifLinkUpDownTrapEnable_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifHighSpeed_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifHighSpeed_val);
int ifHighSpeed_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifHighSpeed_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifHighSpeed_val );
int ifHighSpeed_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifPromiscuousMode_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifPromiscuousMode_val);
int ifPromiscuousMode_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifPromiscuousMode_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifPromiscuousMode_val );
int ifPromiscuousMode_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifConnectorPresent_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifConnectorPresent_val);
int ifConnectorPresent_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifConnectorPresent_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifConnectorPresent_val );
int ifConnectorPresent_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifAlias_check_value( ifXTable_rowreq_ctx *rowreq_ctx, char *ifAlias_val_ptr,  size_t ifAlias_val_ptr_len);
int ifAlias_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifAlias_set( ifXTable_rowreq_ctx *rowreq_ctx, char *ifAlias_val_ptr,  size_t ifAlias_val_ptr_len );
int ifAlias_undo( ifXTable_rowreq_ctx *rowreq_ctx );

int ifCounterDiscontinuityTime_check_value( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifCounterDiscontinuityTime_val);
int ifCounterDiscontinuityTime_undo_setup( ifXTable_rowreq_ctx *rowreq_ctx );
int ifCounterDiscontinuityTime_set( ifXTable_rowreq_ctx *rowreq_ctx, u_long ifCounterDiscontinuityTime_val );
int ifCounterDiscontinuityTime_undo( ifXTable_rowreq_ctx *rowreq_ctx );


int ifXTable_check_dependencies(ifXTable_rowreq_ctx *ctx);


#ifdef __cplusplus
}
#endif

#endif /* IFXTABLE_DATA_SET_H */
