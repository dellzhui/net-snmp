/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef CLABWIFIASSOCIATEDDEVICETABLE_H
#define CLABWIFIASSOCIATEDDEVICETABLE_H

#ifdef __cplusplus
extern "C" {
#endif


/** @addtogroup misc misc: Miscellaneous routines
 *
 * @{
 */
#include <net-snmp/library/asn1.h>
#if 0
/* other required module components */
    /* *INDENT-OFF*  */
config_add_mib(CLAB-WIFI-MIB)
config_require(CLAB-WIFI-MIB/clabWIFIAssociatedDeviceTable/clabWIFIAssociatedDeviceTable_interface)
config_require(CLAB-WIFI-MIB/clabWIFIAssociatedDeviceTable/clabWIFIAssociatedDeviceTable_data_access)
config_require(CLAB-WIFI-MIB/clabWIFIAssociatedDeviceTable/clabWIFIAssociatedDeviceTable_data_get)
config_require(CLAB-WIFI-MIB/clabWIFIAssociatedDeviceTable/clabWIFIAssociatedDeviceTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for clabWIFIAssociatedDeviceTable */
#include "clabWIFIAssociatedDeviceTable_oids.h"

/* enum definions */
#include "clabWIFIAssociatedDeviceTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_clabWIFIAssociatedDeviceTable(void);
void shutdown_clabWIFIAssociatedDeviceTable(void);

/* *********************************************************************
 * Table declarations
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
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review clabWIFIAssociatedDeviceTable registration context.
     */
typedef netsnmp_data_list clabWIFIAssociatedDeviceTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review clabWIFIAssociatedDeviceTable data context structure.
 * This structure is used to represent the data for clabWIFIAssociatedDeviceTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * clabWIFIAssociatedDeviceTable.
 */
typedef struct clabWIFIAssociatedDeviceTable_data_s {
    
        /*
         * clabWIFIAssociatedDeviceMACAddress(2)/MacAddress/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFIAssociatedDeviceMACAddress[6];
size_t      clabWIFIAssociatedDeviceMACAddress_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFIAssociatedDeviceAuthenticationState(3)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAssociatedDeviceAuthenticationState;
    
        /*
         * clabWIFIAssociatedDeviceLastDataDownlinkRate(4)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/R/d/h
         */
   u_long   clabWIFIAssociatedDeviceLastDataDownlinkRate;
    
        /*
         * clabWIFIAssociatedDeviceLastDataUplinkRate(5)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/R/d/h
         */
   u_long   clabWIFIAssociatedDeviceLastDataUplinkRate;
    
        /*
         * clabWIFIAssociatedDeviceSignalStrength(6)/INTEGER32/ASN_INTEGER/long(long)//l/A/W/e/R/d/h
         */
   long   clabWIFIAssociatedDeviceSignalStrength;
    
        /*
         * clabWIFIAssociatedDeviceRetransmissions(7)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/R/d/h
         */
   u_long   clabWIFIAssociatedDeviceRetransmissions;
    
        /*
         * clabWIFIAssociatedDeviceActive(8)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAssociatedDeviceActive;
    
        /*
         * clabWIFIAssociatedDeviceMaxPacketRetryCount(9)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   clabWIFIAssociatedDeviceMaxPacketRetryCount;
    
        /*
         * clabWIFIAssociatedDeviceStationCount(10)/COUNTER/ASN_COUNTER/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   clabWIFIAssociatedDeviceStationCount;
    
        /*
         * clabWIFIAssociatedDeviceMaxNumOfStations(11)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   clabWIFIAssociatedDeviceMaxNumOfStations;
    
} clabWIFIAssociatedDeviceTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review clabWIFIAssociatedDeviceTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef clabWIFIAssociatedDeviceTable_data clabWIFIAssociatedDeviceTable_undo_data;

/*
 * TODO:120:r: |-> Review clabWIFIAssociatedDeviceTable mib index.
 * This structure is used to represent the index for clabWIFIAssociatedDeviceTable.
 */
typedef struct clabWIFIAssociatedDeviceTable_mib_index_s {

        /*
         * clabWIFIAccessPointId(1)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/r/d/h
         */
   u_long   clabWIFIAccessPointId;

        /*
         * clabWIFIAssociatedDeviceId(1)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/r/d/h
         */
   u_long   clabWIFIAssociatedDeviceId;


} clabWIFIAssociatedDeviceTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review clabWIFIAssociatedDeviceTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_clabWIFIAssociatedDeviceTable_IDX_LEN     2


/* *********************************************************************
 * TODO:130:o: |-> Review clabWIFIAssociatedDeviceTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * clabWIFIAssociatedDeviceTable_rowreq_ctx pointer.
 */
typedef struct clabWIFIAssociatedDeviceTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_clabWIFIAssociatedDeviceTable_IDX_LEN];
    
    clabWIFIAssociatedDeviceTable_mib_index        tbl_idx;
    
    clabWIFIAssociatedDeviceTable_data              data;
    clabWIFIAssociatedDeviceTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to clabWIFIAssociatedDeviceTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *clabWIFIAssociatedDeviceTable_data_list;

} clabWIFIAssociatedDeviceTable_rowreq_ctx;
#if 0
typedef struct clabWIFIAssociatedDeviceTable_ref_rowreq_ctx_s {
    clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx;
} clabWIFIAssociatedDeviceTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int clabWIFIAssociatedDeviceTable_pre_request(clabWIFIAssociatedDeviceTable_registration * user_context);
    int clabWIFIAssociatedDeviceTable_post_request(clabWIFIAssociatedDeviceTable_registration * user_context,
        int rc);

    int clabWIFIAssociatedDeviceTable_rowreq_ctx_init(clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void clabWIFIAssociatedDeviceTable_rowreq_ctx_cleanup(clabWIFIAssociatedDeviceTable_rowreq_ctx *rowreq_ctx);

    int clabWIFIAssociatedDeviceTable_commit(clabWIFIAssociatedDeviceTable_rowreq_ctx * rowreq_ctx);

    clabWIFIAssociatedDeviceTable_rowreq_ctx *
                  clabWIFIAssociatedDeviceTable_row_find_by_mib_index(clabWIFIAssociatedDeviceTable_mib_index *mib_idx);

extern const oid clabWIFIAssociatedDeviceTable_oid[];
extern const int clabWIFIAssociatedDeviceTable_oid_size;


#include "clabWIFIAssociatedDeviceTable_interface.h"
#include "clabWIFIAssociatedDeviceTable_data_access.h"
#include "clabWIFIAssociatedDeviceTable_data_get.h"
#endif
#include "clabWIFIAssociatedDeviceTable_data_set.h"

/*
 * DUMMY markers, ignore
 *
 * TODO:099:x: *************************************************************
 * TODO:199:x: *************************************************************
 * TODO:299:x: *************************************************************
 * TODO:399:x: *************************************************************
 * TODO:499:x: *************************************************************
 */

#ifdef __cplusplus
}
#endif

#endif /* CLABWIFIASSOCIATEDDEVICETABLE_H */
/** @} */
