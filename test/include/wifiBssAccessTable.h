/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef WIFIBSSACCESSTABLE_H
#define WIFIBSSACCESSTABLE_H

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
config_require(BRCM-WIFI-MGMT-MIB/wifiBssAccessTable/wifiBssAccessTable_interface)
config_require(BRCM-WIFI-MGMT-MIB/wifiBssAccessTable/wifiBssAccessTable_data_access)
config_require(BRCM-WIFI-MGMT-MIB/wifiBssAccessTable/wifiBssAccessTable_data_get)
config_require(BRCM-WIFI-MGMT-MIB/wifiBssAccessTable/wifiBssAccessTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for wifiBssAccessTable */
#include "wifiBssAccessTable_oids.h"

/* enum definions */
#include "wifiBssAccessTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_wifiBssAccessTable(void);
void shutdown_wifiBssAccessTable(void);

/* *********************************************************************
 * Table declarations
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
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review wifiBssAccessTable registration context.
     */
typedef netsnmp_data_list wifiBssAccessTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review wifiBssAccessTable data context structure.
 * This structure is used to represent the data for wifiBssAccessTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * wifiBssAccessTable.
 */
typedef struct wifiBssAccessTable_data_s {
    
        /*
         * wifiBssAccessStation(2)/PhysAddress/ASN_OCTET_STR/char(char)//L/A/W/e/r/d/H
         */
   char   wifiBssAccessStation[32];
size_t      wifiBssAccessStation_len; /* # of char elements, not bytes */
    
        /*
         * wifiBssAccessStatus(3)/RowStatus/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   wifiBssAccessStatus;
    
} wifiBssAccessTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review wifiBssAccessTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef wifiBssAccessTable_data wifiBssAccessTable_undo_data;

/*
 * TODO:120:r: |-> Review wifiBssAccessTable mib index.
 * This structure is used to represent the index for wifiBssAccessTable.
 */
typedef struct wifiBssAccessTable_mib_index_s {

        /*
         * ifIndex(1)/InterfaceIndex/ASN_INTEGER/long(long)//l/A/w/e/R/d/H
         */
   long   ifIndex;

        /*
         * wifiBssAccessIndex(1)/INTEGER32/ASN_INTEGER/long(long)//l/a/w/e/R/d/h
         */
   long   wifiBssAccessIndex;


} wifiBssAccessTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review wifiBssAccessTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_wifiBssAccessTable_IDX_LEN     2


/* *********************************************************************
 * TODO:130:o: |-> Review wifiBssAccessTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * wifiBssAccessTable_rowreq_ctx pointer.
 */
typedef struct wifiBssAccessTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_wifiBssAccessTable_IDX_LEN];
    
    wifiBssAccessTable_mib_index        tbl_idx;
    
    wifiBssAccessTable_data              data;
    wifiBssAccessTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to wifiBssAccessTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *wifiBssAccessTable_data_list;

} wifiBssAccessTable_rowreq_ctx;
#if 0
typedef struct wifiBssAccessTable_ref_rowreq_ctx_s {
    wifiBssAccessTable_rowreq_ctx *rowreq_ctx;
} wifiBssAccessTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int wifiBssAccessTable_pre_request(wifiBssAccessTable_registration * user_context);
    int wifiBssAccessTable_post_request(wifiBssAccessTable_registration * user_context,
        int rc);

    int wifiBssAccessTable_rowreq_ctx_init(wifiBssAccessTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void wifiBssAccessTable_rowreq_ctx_cleanup(wifiBssAccessTable_rowreq_ctx *rowreq_ctx);

    int wifiBssAccessTable_commit(wifiBssAccessTable_rowreq_ctx * rowreq_ctx);

    wifiBssAccessTable_rowreq_ctx *
                  wifiBssAccessTable_row_find_by_mib_index(wifiBssAccessTable_mib_index *mib_idx);

extern const oid wifiBssAccessTable_oid[];
extern const int wifiBssAccessTable_oid_size;


#include "wifiBssAccessTable_interface.h"
#include "wifiBssAccessTable_data_access.h"
#include "wifiBssAccessTable_data_get.h"
#endif
#include "wifiBssAccessTable_data_set.h"

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

#endif /* WIFIBSSACCESSTABLE_H */
/** @} */
