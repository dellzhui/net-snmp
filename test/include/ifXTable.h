/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef IFXTABLE_H
#define IFXTABLE_H

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
config_add_mib(IF-MIB)
config_require(IF-MIB/ifXTable/ifXTable_interface)
config_require(IF-MIB/ifXTable/ifXTable_data_access)
config_require(IF-MIB/ifXTable/ifXTable_data_get)
config_require(IF-MIB/ifXTable/ifXTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for ifXTable */
#include "ifXTable_oids.h"

/* enum definions */
#include "ifXTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_ifXTable(void);
void shutdown_ifXTable(void);

/* *********************************************************************
 * Table declarations
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
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review ifXTable registration context.
     */
typedef netsnmp_data_list ifXTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review ifXTable data context structure.
 * This structure is used to represent the data for ifXTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * ifXTable.
 */
typedef struct ifXTable_data_s {
    
        /*
         * ifName(1)/DisplayString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   ifName[64];
size_t      ifName_len; /* # of char elements, not bytes */
    
        /*
         * ifInMulticastPkts(2)/COUNTER/ASN_COUNTER/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   ifInMulticastPkts;
    
        /*
         * ifInBroadcastPkts(3)/COUNTER/ASN_COUNTER/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   ifInBroadcastPkts;
    
        /*
         * ifOutMulticastPkts(4)/COUNTER/ASN_COUNTER/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   ifOutMulticastPkts;
    
        /*
         * ifOutBroadcastPkts(5)/COUNTER/ASN_COUNTER/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   ifOutBroadcastPkts;
    
        /*
         * ifHCInOctets(6)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCInOctets;
    
        /*
         * ifHCInUcastPkts(7)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCInUcastPkts;
    
        /*
         * ifHCInMulticastPkts(8)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCInMulticastPkts;
    
        /*
         * ifHCInBroadcastPkts(9)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCInBroadcastPkts;
    
        /*
         * ifHCOutOctets(10)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCOutOctets;
    
        /*
         * ifHCOutUcastPkts(11)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCOutUcastPkts;
    
        /*
         * ifHCOutMulticastPkts(12)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCOutMulticastPkts;
    
        /*
         * ifHCOutBroadcastPkts(13)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/W/e/r/d/h
         */
   U64   ifHCOutBroadcastPkts;
    
        /*
         * ifLinkUpDownTrapEnable(14)/INTEGER/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   ifLinkUpDownTrapEnable;
    
        /*
         * ifHighSpeed(15)/GAUGE/ASN_GAUGE/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   ifHighSpeed;
    
        /*
         * ifPromiscuousMode(16)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   ifPromiscuousMode;
    
        /*
         * ifConnectorPresent(17)/TruthValue/ASN_INTEGER/long(u_long)//l/A/W/E/r/d/h
         */
   u_long   ifConnectorPresent;
    
        /*
         * ifAlias(18)/DisplayString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   ifAlias[64];
size_t      ifAlias_len; /* # of char elements, not bytes */
    
        /*
         * ifCounterDiscontinuityTime(19)/TimeStamp/ASN_TIMETICKS/u_long(u_long)//l/A/W/e/r/d/h
         */
   u_long   ifCounterDiscontinuityTime;
    
} ifXTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review ifXTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef ifXTable_data ifXTable_undo_data;

/*
 * TODO:120:r: |-> Review ifXTable mib index.
 * This structure is used to represent the index for ifXTable.
 */
typedef struct ifXTable_mib_index_s {

        /*
         * ifIndex(1)/InterfaceIndex/ASN_INTEGER/long(long)//l/A/W/e/R/d/H
         */
   long   ifIndex;


} ifXTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review ifXTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_ifXTable_IDX_LEN     1


/* *********************************************************************
 * TODO:130:o: |-> Review ifXTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * ifXTable_rowreq_ctx pointer.
 */
typedef struct ifXTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_ifXTable_IDX_LEN];
    
    ifXTable_mib_index        tbl_idx;
    
    ifXTable_data              data;
    ifXTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to ifXTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *ifXTable_data_list;

} ifXTable_rowreq_ctx;
#if 0
typedef struct ifXTable_ref_rowreq_ctx_s {
    ifXTable_rowreq_ctx *rowreq_ctx;
} ifXTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int ifXTable_pre_request(ifXTable_registration * user_context);
    int ifXTable_post_request(ifXTable_registration * user_context,
        int rc);

    int ifXTable_commit(ifXTable_rowreq_ctx * rowreq_ctx);

    ifXTable_rowreq_ctx *
                  ifXTable_row_find_by_mib_index(ifXTable_mib_index *mib_idx);

extern const oid ifXTable_oid[];
extern const int ifXTable_oid_size;


#include "ifXTable_interface.h"
#include "ifXTable_data_access.h"
#include "ifXTable_data_get.h"
#endif
#include "ifXTable_data_set.h"

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

#endif /* IFXTABLE_H */
/** @} */