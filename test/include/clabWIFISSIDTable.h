/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef CLABWIFISSIDTABLE_H
#define CLABWIFISSIDTABLE_H

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
config_require(CLAB-WIFI-MIB/clabWIFISSIDTable/clabWIFISSIDTable_interface)
config_require(CLAB-WIFI-MIB/clabWIFISSIDTable/clabWIFISSIDTable_data_access)
config_require(CLAB-WIFI-MIB/clabWIFISSIDTable/clabWIFISSIDTable_data_get)
config_require(CLAB-WIFI-MIB/clabWIFISSIDTable/clabWIFISSIDTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for clabWIFISSIDTable */
#include "clabWIFISSIDTable_oids.h"

/* enum definions */
#include "clabWIFISSIDTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_clabWIFISSIDTable(void);
void shutdown_clabWIFISSIDTable(void);

/* *********************************************************************
 * Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table clabWIFISSIDTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * CLAB-WIFI-MIB::clabWIFISSIDTable is subid 4 of clabWIFIObjects.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4491.2.5.1.1.4, length: 12
*/
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review clabWIFISSIDTable registration context.
     */
typedef netsnmp_data_list clabWIFISSIDTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review clabWIFISSIDTable data context structure.
 * This structure is used to represent the data for clabWIFISSIDTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * clabWIFISSIDTable.
 */
typedef struct clabWIFISSIDTable_data_s {
    
        /*
         * clabWIFISSIDEnable(2)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFISSIDEnable;
    
        /*
         * clabWIFISSIDStatus(3)/INTEGER/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFISSIDStatus;
    
        /*
         * clabWIFISSIDAlias(4)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFISSIDAlias[64];
size_t      clabWIFISSIDAlias_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFISSIDName(5)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFISSIDName[64];
size_t      clabWIFISSIDName_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFISSIDLastChange(6)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   clabWIFISSIDLastChange;
    
        /*
         * clabWIFISSIDLowerLayers(7)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFISSIDLowerLayers[1024];
size_t      clabWIFISSIDLowerLayers_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFISSIDBSSID(8)/MacAddress/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFISSIDBSSID[6];
size_t      clabWIFISSIDBSSID_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFISSIDMACAddress(9)/MacAddress/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFISSIDMACAddress[6];
size_t      clabWIFISSIDMACAddress_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFISSIDSSID(10)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   clabWIFISSIDSSID[32];
size_t      clabWIFISSIDSSID_len; /* # of char elements, not bytes */
    
        /*
         * clabWIFISSIDRowStatus(11)/RowStatus/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   clabWIFISSIDRowStatus;
    
} clabWIFISSIDTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review clabWIFISSIDTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef clabWIFISSIDTable_data clabWIFISSIDTable_undo_data;

/*
 * TODO:120:r: |-> Review clabWIFISSIDTable mib index.
 * This structure is used to represent the index for clabWIFISSIDTable.
 */
typedef struct clabWIFISSIDTable_mib_index_s {

        /*
         * clabWIFISSIDId(1)/InterfaceIndex/ASN_INTEGER/long(long)//l/a/w/e/R/d/H
         */
   long   clabWIFISSIDId;


} clabWIFISSIDTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review clabWIFISSIDTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_clabWIFISSIDTable_IDX_LEN     1


/* *********************************************************************
 * TODO:130:o: |-> Review clabWIFISSIDTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * clabWIFISSIDTable_rowreq_ctx pointer.
 */
typedef struct clabWIFISSIDTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_clabWIFISSIDTable_IDX_LEN];
    
    clabWIFISSIDTable_mib_index        tbl_idx;
    
    clabWIFISSIDTable_data              data;
    clabWIFISSIDTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to clabWIFISSIDTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *clabWIFISSIDTable_data_list;

} clabWIFISSIDTable_rowreq_ctx;
#if 0
typedef struct clabWIFISSIDTable_ref_rowreq_ctx_s {
    clabWIFISSIDTable_rowreq_ctx *rowreq_ctx;
} clabWIFISSIDTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int clabWIFISSIDTable_pre_request(clabWIFISSIDTable_registration * user_context);
    int clabWIFISSIDTable_post_request(clabWIFISSIDTable_registration * user_context,
        int rc);

    int clabWIFISSIDTable_rowreq_ctx_init(clabWIFISSIDTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void clabWIFISSIDTable_rowreq_ctx_cleanup(clabWIFISSIDTable_rowreq_ctx *rowreq_ctx);

    int clabWIFISSIDTable_commit(clabWIFISSIDTable_rowreq_ctx * rowreq_ctx);

    clabWIFISSIDTable_rowreq_ctx *
                  clabWIFISSIDTable_row_find_by_mib_index(clabWIFISSIDTable_mib_index *mib_idx);

extern const oid clabWIFISSIDTable_oid[];
extern const int clabWIFISSIDTable_oid_size;


#include "clabWIFISSIDTable_interface.h"
#include "clabWIFISSIDTable_data_access.h"
#include "clabWIFISSIDTable_data_get.h"
#endif
#include "clabWIFISSIDTable_data_set.h"

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

#endif /* CLABWIFISSIDTABLE_H */
/** @} */