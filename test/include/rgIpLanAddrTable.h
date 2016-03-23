/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef RGIPLANADDRTABLE_H
#define RGIPLANADDRTABLE_H

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
config_add_mib(BRCM-RG-IP-MIB)
config_require(BRCM-RG-IP-MIB/rgIpLanAddrTable/rgIpLanAddrTable_interface)
config_require(BRCM-RG-IP-MIB/rgIpLanAddrTable/rgIpLanAddrTable_data_access)
config_require(BRCM-RG-IP-MIB/rgIpLanAddrTable/rgIpLanAddrTable_data_get)
config_require(BRCM-RG-IP-MIB/rgIpLanAddrTable/rgIpLanAddrTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for rgIpLanAddrTable */
#include "rgIpLanAddrTable_oids.h"

/* enum definions */
#include "rgIpLanAddrTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_rgIpLanAddrTable(void);
void shutdown_rgIpLanAddrTable(void);

/* *********************************************************************
 * Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table rgIpLanAddrTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * BRCM-RG-IP-MIB::rgIpLanAddrTable is subid 1 of rgIpLanAddr.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4413.2.2.2.1.7.2.3.1, length: 15
*/
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review rgIpLanAddrTable registration context.
     */
typedef netsnmp_data_list rgIpLanAddrTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review rgIpLanAddrTable data context structure.
 * This structure is used to represent the data for rgIpLanAddrTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * rgIpLanAddrTable.
 */
typedef struct rgIpLanAddrTable_data_s {
    
        /*
         * rgIpLanAddrClientID(3)/OCTETSTR/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/h
         */
   char   rgIpLanAddrClientID[6];
size_t      rgIpLanAddrClientID_len; /* # of char elements, not bytes */
    
        /*
         * rgIpLanAddrLeaseCreateTime(4)/DateAndTime/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   rgIpLanAddrLeaseCreateTime[64];
size_t      rgIpLanAddrLeaseCreateTime_len; /* # of char elements, not bytes */
    
        /*
         * rgIpLanAddrLeaseExpireTime(5)/DateAndTime/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   rgIpLanAddrLeaseExpireTime[64];
size_t      rgIpLanAddrLeaseExpireTime_len; /* # of char elements, not bytes */
    
        /*
         * rgIpLanAddrHostName(6)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/H
         */
   char   rgIpLanAddrHostName[32];
size_t      rgIpLanAddrHostName_len; /* # of char elements, not bytes */
    
} rgIpLanAddrTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review rgIpLanAddrTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef rgIpLanAddrTable_data rgIpLanAddrTable_undo_data;

/*
 * TODO:120:r: |-> Review rgIpLanAddrTable mib index.
 * This structure is used to represent the index for rgIpLanAddrTable.
 */
typedef struct rgIpLanAddrTable_mib_index_s {

        /*
         * ifIndex(1)/InterfaceIndex/ASN_INTEGER/long(long)//l/A/w/e/R/d/H
         */
   long   ifIndex;

        /*
         * rgIpLanAddrIpType(1)/InetAddressType/ASN_INTEGER/long(u_long)//l/a/w/E/r/d/h
         */
   u_long   rgIpLanAddrIpType;

        /*
         * rgIpLanAddrIp(2)/InetAddress/ASN_OCTET_STR/char(char)//L/a/w/e/R/d/h
         */
   char   rgIpLanAddrIp[20];
   size_t      rgIpLanAddrIp_len;


} rgIpLanAddrTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review rgIpLanAddrTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
     *
     * BE VERY CAREFUL TO TAKE INTO ACCOUNT THE MAXIMUM
     * POSSIBLE LENGHT FOR EVERY VARIABLE LENGTH INDEX!
     * Guessing 128 - col/entry(2)  - oid len(15)
*/
#define MAX_rgIpLanAddrTable_IDX_LEN     23


/* *********************************************************************
 * TODO:130:o: |-> Review rgIpLanAddrTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * rgIpLanAddrTable_rowreq_ctx pointer.
 */
typedef struct rgIpLanAddrTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_rgIpLanAddrTable_IDX_LEN];
    
    rgIpLanAddrTable_mib_index        tbl_idx;
    
    rgIpLanAddrTable_data              data;
    rgIpLanAddrTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to rgIpLanAddrTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *rgIpLanAddrTable_data_list;

} rgIpLanAddrTable_rowreq_ctx;
#if 0
typedef struct rgIpLanAddrTable_ref_rowreq_ctx_s {
    rgIpLanAddrTable_rowreq_ctx *rowreq_ctx;
} rgIpLanAddrTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int rgIpLanAddrTable_pre_request(rgIpLanAddrTable_registration * user_context);
    int rgIpLanAddrTable_post_request(rgIpLanAddrTable_registration * user_context,
        int rc);

    int rgIpLanAddrTable_commit(rgIpLanAddrTable_rowreq_ctx * rowreq_ctx);

    rgIpLanAddrTable_rowreq_ctx *
                  rgIpLanAddrTable_row_find_by_mib_index(rgIpLanAddrTable_mib_index *mib_idx);

extern const oid rgIpLanAddrTable_oid[];
extern const int rgIpLanAddrTable_oid_size;


#include "rgIpLanAddrTable_interface.h"
#include "rgIpLanAddrTable_data_access.h"
#include "rgIpLanAddrTable_data_get.h"
#endif
#include "rgIpLanAddrTable_data_set.h"

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

#endif /* RGIPLANADDRTABLE_H */
/** @} */
