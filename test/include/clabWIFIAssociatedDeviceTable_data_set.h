/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 *
 * $Id:$
 */
#ifndef CLABWIFIASSOCIATEDDEVICETABLE_DATA_SET_H
#define CLABWIFIASSOCIATEDDEVICETABLE_DATA_SET_H

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
 *** Table clabWIFIAssociatedDeviceTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * CLAB-WIFI-MIB::clabWIFIAssociatedDeviceTable is subid 9 of clabWIFIObjects.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4491.2.5.1.1.9, length: 12
*/


int clabWIFIAssociatedDeviceTable_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx);
int clabWIFIAssociatedDeviceTable_undo_cleanup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx);
int clabWIFIAssociatedDeviceTable_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx);
int clabWIFIAssociatedDeviceTable_commit( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx);
int clabWIFIAssociatedDeviceTable_undo_commit( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx);


int clabWIFIAssociatedDeviceMACAddress_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, char *clabWIFIAssociatedDeviceMACAddress_val_ptr,  size_t clabWIFIAssociatedDeviceMACAddress_val_ptr_len);
int clabWIFIAssociatedDeviceMACAddress_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceMACAddress_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, char *clabWIFIAssociatedDeviceMACAddress_val_ptr,  size_t clabWIFIAssociatedDeviceMACAddress_val_ptr_len );
int clabWIFIAssociatedDeviceMACAddress_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceAuthenticationState_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceAuthenticationState_val);
int clabWIFIAssociatedDeviceAuthenticationState_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceAuthenticationState_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceAuthenticationState_val );
int clabWIFIAssociatedDeviceAuthenticationState_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceLastDataDownlinkRate_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceLastDataDownlinkRate_val);
int clabWIFIAssociatedDeviceLastDataDownlinkRate_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceLastDataDownlinkRate_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceLastDataDownlinkRate_val );
int clabWIFIAssociatedDeviceLastDataDownlinkRate_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceLastDataUplinkRate_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceLastDataUplinkRate_val);
int clabWIFIAssociatedDeviceLastDataUplinkRate_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceLastDataUplinkRate_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceLastDataUplinkRate_val );
int clabWIFIAssociatedDeviceLastDataUplinkRate_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceSignalStrength_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, long clabWIFIAssociatedDeviceSignalStrength_val);
int clabWIFIAssociatedDeviceSignalStrength_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceSignalStrength_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, long clabWIFIAssociatedDeviceSignalStrength_val );
int clabWIFIAssociatedDeviceSignalStrength_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceRetransmissions_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceRetransmissions_val);
int clabWIFIAssociatedDeviceRetransmissions_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceRetransmissions_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceRetransmissions_val );
int clabWIFIAssociatedDeviceRetransmissions_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceActive_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceActive_val);
int clabWIFIAssociatedDeviceActive_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceActive_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceActive_val );
int clabWIFIAssociatedDeviceActive_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceMaxPacketRetryCount_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceMaxPacketRetryCount_val);
int clabWIFIAssociatedDeviceMaxPacketRetryCount_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceMaxPacketRetryCount_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceMaxPacketRetryCount_val );
int clabWIFIAssociatedDeviceMaxPacketRetryCount_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceStationCount_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceStationCount_val);
int clabWIFIAssociatedDeviceStationCount_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceStationCount_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceStationCount_val );
int clabWIFIAssociatedDeviceStationCount_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );

int clabWIFIAssociatedDeviceMaxNumOfStations_check_value( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceMaxNumOfStations_val);
int clabWIFIAssociatedDeviceMaxNumOfStations_undo_setup( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );
int clabWIFIAssociatedDeviceMaxNumOfStations_set( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx, u_long clabWIFIAssociatedDeviceMaxNumOfStations_val );
int clabWIFIAssociatedDeviceMaxNumOfStations_undo( clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx );


int clabWIFIAssociatedDeviceTable_check_dependencies(clabWIFIAssociatedDeviceTable_rowreq_ctx *ctx);


#ifdef __cplusplus
}
#endif

#endif /* CLABWIFIASSOCIATEDDEVICETABLE_DATA_SET_H */
