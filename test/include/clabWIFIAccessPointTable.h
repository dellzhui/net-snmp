/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef CLABWIFIACCESSPOINTTABLE_H
#define CLABWIFIACCESSPOINTTABLE_H

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
config_require(CLAB-WIFI-MIB/clabWIFIAccessPointTable/clabWIFIAccessPointTable_interface)
config_require(CLAB-WIFI-MIB/clabWIFIAccessPointTable/clabWIFIAccessPointTable_data_access)
config_require(CLAB-WIFI-MIB/clabWIFIAccessPointTable/clabWIFIAccessPointTable_data_get)
config_require(CLAB-WIFI-MIB/clabWIFIAccessPointTable/clabWIFIAccessPointTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for clabWIFIAccessPointTable */
#include "clabWIFIAccessPointTable_oids.h"

/* enum definions */
#include "clabWIFIAccessPointTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_clabWIFIAccessPointTable(void);
void shutdown_clabWIFIAccessPointTable(void);

/* *********************************************************************
 * Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table clabWIFIAccessPointTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * CLAB-WIFI-MIB::clabWIFIAccessPointTable is subid 6 of clabWIFIObjects.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4491.2.5.1.1.6, length: 12
*/
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review clabWIFIAccessPointTable registration context.
     */
typedef netsnmp_data_list clabWIFIAccessPointTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review clabWIFIAccessPointTable data context structure.
 * This structure is used to represent the data for clabWIFIAccessPointTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * clabWIFIAccessPointTable.
 */
typedef struct clabWIFIAccessPointTable_data_s {
    
        /*
         * clabWIFIAccessPointEnable(2)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointEnable;
    
        /*
         * clabWIFIAccessPointStatus(3)/INTEGER/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointStatus;
    
        /*
         * clabWIFIAccessPointAlias(4)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFIAccessPointAlias[64];
size_t      clabWIFIAccessPointAlias_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFIAccessPointSSIDReference(5)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   clabWIFIAccessPointSSIDReference;
    
        /*
         * clabWIFIAccessPointSSIDAdvertisementEnabled(6)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointSSIDAdvertisementEnabled;
    
        /*
         * clabWIFIAccessPointRetryLimit(7)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/R/d/h
         */
   u_long   clabWIFIAccessPointRetryLimit;
    
        /*
         * clabWIFIAccessPointWMMCapability(8)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointWMMCapability;
    
        /*
         * clabWIFIAccessPointUAPSDCapability(9)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointUAPSDCapability;
    
        /*
         * clabWIFIAccessPointWMMEnable(10)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointWMMEnable;
    
        /*
         * clabWIFIAccessPointUAPSDEnable(11)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointUAPSDEnable;
    
        /*
         * clabWIFIAccessPointAssociatedDeviceNumberOfEntries(12)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   clabWIFIAccessPointAssociatedDeviceNumberOfEntries;
    
        /*
         * clabWIFIAccessPointRowStatus(13)/RowStatus/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFIAccessPointRowStatus;
    
} clabWIFIAccessPointTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review clabWIFIAccessPointTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef clabWIFIAccessPointTable_data clabWIFIAccessPointTable_undo_data;

/*
 * TODO:120:r: |-> Review clabWIFIAccessPointTable mib index.
 * This structure is used to represent the index for clabWIFIAccessPointTable.
 */
typedef struct clabWIFIAccessPointTable_mib_index_s {

        /*
         * clabWIFIAccessPointId(1)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/r/d/h
         */
   u_long   clabWIFIAccessPointId;


} clabWIFIAccessPointTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review clabWIFIAccessPointTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_clabWIFIAccessPointTable_IDX_LEN     1


/* *********************************************************************
 * TODO:130:o: |-> Review clabWIFIAccessPointTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * clabWIFIAccessPointTable_rowreq_ctx pointer.
 */
typedef struct clabWIFIAccessPointTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_clabWIFIAccessPointTable_IDX_LEN];
    
    clabWIFIAccessPointTable_mib_index        tbl_idx;
    
    clabWIFIAccessPointTable_data              data;
    clabWIFIAccessPointTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to clabWIFIAccessPointTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *clabWIFIAccessPointTable_data_list;

} clabWIFIAccessPointTable_rowreq_ctx;
#if 0
typedef struct clabWIFIAccessPointTable_ref_rowreq_ctx_s {
    clabWIFIAccessPointTable_rowreq_ctx *rowreq_ctx;
} clabWIFIAccessPointTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int clabWIFIAccessPointTable_pre_request(clabWIFIAccessPointTable_registration * user_context);
    int clabWIFIAccessPointTable_post_request(clabWIFIAccessPointTable_registration * user_context,
        int rc);

    int clabWIFIAccessPointTable_rowreq_ctx_init(clabWIFIAccessPointTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void clabWIFIAccessPointTable_rowreq_ctx_cleanup(clabWIFIAccessPointTable_rowreq_ctx *rowreq_ctx);

    int clabWIFIAccessPointTable_commit(clabWIFIAccessPointTable_rowreq_ctx * rowreq_ctx);

    clabWIFIAccessPointTable_rowreq_ctx *
                  clabWIFIAccessPointTable_row_find_by_mib_index(clabWIFIAccessPointTable_mib_index *mib_idx);

extern const oid clabWIFIAccessPointTable_oid[];
extern const int clabWIFIAccessPointTable_oid_size;


#include "clabWIFIAccessPointTable_interface.h"
#include "clabWIFIAccessPointTable_data_access.h"
#include "clabWIFIAccessPointTable_data_get.h"
#endif
#include "clabWIFIAccessPointTable_data_set.h"

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

#endif /* CLABWIFIACCESSPOINTTABLE_H */
/** @} */
