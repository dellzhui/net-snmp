/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef WIFIASSOCSTATABLE_H
#define WIFIASSOCSTATABLE_H

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
config_add_mib(BRCM-WIFI-MGMT-MIB)
config_require(BRCM-WIFI-MGMT-MIB/wifiAssocStaTable/wifiAssocStaTable_interface)
config_require(BRCM-WIFI-MGMT-MIB/wifiAssocStaTable/wifiAssocStaTable_data_access)
config_require(BRCM-WIFI-MGMT-MIB/wifiAssocStaTable/wifiAssocStaTable_data_get)
config_require(BRCM-WIFI-MGMT-MIB/wifiAssocStaTable/wifiAssocStaTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for wifiAssocStaTable */
#include "wifiAssocStaTable_oids.h"

/* enum definions */
#include "wifiAssocStaTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_wifiAssocStaTable(void);
void shutdown_wifiAssocStaTable(void);

/* *********************************************************************
 * Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table wifiAssocStaTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * BRCM-WIFI-MGMT-MIB::wifiAssocStaTable is subid 3 of wifiAssocStaDiagnostics.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4413.2.2.2.1.18.1.5.3, length: 15
*/
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review wifiAssocStaTable registration context.
     */
typedef netsnmp_data_list wifiAssocStaTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review wifiAssocStaTable data context structure.
 * This structure is used to represent the data for wifiAssocStaTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * wifiAssocStaTable.
 */
typedef struct wifiAssocStaTable_data_s {
    
        /*
         * wifiAssocStaRssi(1)/INTEGER32/ASN_INTEGER/long(long)//l/A/W/e/r/d/h
         */
   long   wifiAssocStaRssi;
    
        /*
         * wifiAssocStaPhyRate(2)/INTEGER32/ASN_INTEGER/long(long)//l/A/W/e/r/d/h
         */
   long   wifiAssocStaPhyRate;
    
        /*
         * wifiAssocStaMacAddress(4)/PhysAddress/ASN_OCTET_STR/char(char)//L/A/W/e/r/d/H
         */
   char   wifiAssocStaMacAddress[32];
size_t      wifiAssocStaMacAddress_len; /* # of char elements, not bytes */
    
        /*
         * wifiAssocStaPRequested(5)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPRequested;
    
        /*
         * wifiAssocStaPStored(6)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPStored;
    
        /*
         * wifiAssocStaPDropped(7)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPDropped;
    
        /*
         * wifiAssocStaPRetried(8)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPRetried;
    
        /*
         * wifiAssocStaPUtilization(9)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPUtilization;
    
        /*
         * wifiAssocStaPQLength(10)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPQLength;
    
        /*
         * wifiAssocStaPRtsFail(11)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPRtsFail;
    
        /*
         * wifiAssocStaPRtryDrop(12)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPRtryDrop;
    
        /*
         * wifiAssocStaPPSRetry(13)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPPSRetry;
    
        /*
         * wifiAssocStaPAcked(14)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPAcked;
    
        /*
         * wifiAssocStaPTput(15)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPTput;
    
        /*
         * wifiAssocStaPPhyRate(16)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   wifiAssocStaPPhyRate;
    
        /*
         * wifiAssocStaTxBytes(17)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   wifiAssocStaTxBytes;
    
        /*
         * wifiAssocStaRxBytes(18)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   wifiAssocStaRxBytes;
    
        /*
         * wifiAssocStaTxRateLimit(19)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/D/h
         */
   u_long   wifiAssocStaTxRateLimit;
    
        /*
         * wifiAssocStaRxRateLimit(20)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/D/h
         */
   u_long   wifiAssocStaRxRateLimit;
    
} wifiAssocStaTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review wifiAssocStaTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef wifiAssocStaTable_data wifiAssocStaTable_undo_data;

/*
 * TODO:120:r: |-> Review wifiAssocStaTable mib index.
 * This structure is used to represent the index for wifiAssocStaTable.
 */
typedef struct wifiAssocStaTable_mib_index_s {

        /*
         * ifIndex(1)/InterfaceIndex/ASN_INTEGER/long(long)//l/A/w/e/R/d/H
         */
   long   ifIndex;


} wifiAssocStaTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review wifiAssocStaTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_wifiAssocStaTable_IDX_LEN     1


/* *********************************************************************
 * TODO:130:o: |-> Review wifiAssocStaTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * wifiAssocStaTable_rowreq_ctx pointer.
 */
typedef struct wifiAssocStaTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_wifiAssocStaTable_IDX_LEN];
    
    wifiAssocStaTable_mib_index        tbl_idx;
    
    wifiAssocStaTable_data              data;
    wifiAssocStaTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to wifiAssocStaTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *wifiAssocStaTable_data_list;

} wifiAssocStaTable_rowreq_ctx;
#if 0
typedef struct wifiAssocStaTable_ref_rowreq_ctx_s {
    wifiAssocStaTable_rowreq_ctx *rowreq_ctx;
} wifiAssocStaTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int wifiAssocStaTable_pre_request(wifiAssocStaTable_registration * user_context);
    int wifiAssocStaTable_post_request(wifiAssocStaTable_registration * user_context,
        int rc);

    int wifiAssocStaTable_rowreq_ctx_init(wifiAssocStaTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void wifiAssocStaTable_rowreq_ctx_cleanup(wifiAssocStaTable_rowreq_ctx *rowreq_ctx);

    int wifiAssocStaTable_commit(wifiAssocStaTable_rowreq_ctx * rowreq_ctx);

    wifiAssocStaTable_rowreq_ctx *
                  wifiAssocStaTable_row_find_by_mib_index(wifiAssocStaTable_mib_index *mib_idx);

extern const oid wifiAssocStaTable_oid[];
extern const int wifiAssocStaTable_oid_size;


#include "wifiAssocStaTable_interface.h"
#include "wifiAssocStaTable_data_access.h"
#include "wifiAssocStaTable_data_get.h"
#endif
#include "wifiAssocStaTable_data_set.h"

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

#endif /* WIFIASSOCSTATABLE_H */
/** @} */
