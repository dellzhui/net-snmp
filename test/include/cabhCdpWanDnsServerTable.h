/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef CABHCDPWANDNSSERVERTABLE_H
#define CABHCDPWANDNSSERVERTABLE_H

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
config_add_mib(CABH-CDP-MIB)
config_require(CABH-CDP-MIB/cabhCdpWanDnsServerTable/cabhCdpWanDnsServerTable_interface)
config_require(CABH-CDP-MIB/cabhCdpWanDnsServerTable/cabhCdpWanDnsServerTable_data_access)
config_require(CABH-CDP-MIB/cabhCdpWanDnsServerTable/cabhCdpWanDnsServerTable_data_get)
config_require(CABH-CDP-MIB/cabhCdpWanDnsServerTable/cabhCdpWanDnsServerTable_data_set)
    /* *INDENT-ON*  */
#endif
/* OID and column number definitions for cabhCdpWanDnsServerTable */
#include "cabhCdpWanDnsServerTable_oids.h"

/* enum definions */
#include "cabhCdpWanDnsServerTable_enums.h"
#if 0
/* *********************************************************************
 * function declarations
 */
void init_cabhCdpWanDnsServerTable(void);
void shutdown_cabhCdpWanDnsServerTable(void);

/* *********************************************************************
 * Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table cabhCdpWanDnsServerTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * CABH-CDP-MIB::cabhCdpWanDnsServerTable is subid 3 of cabhCdpAddr.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.4491.2.4.4.1.2.3, length: 13
*/
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review cabhCdpWanDnsServerTable registration context.
     */
typedef netsnmp_data_list cabhCdpWanDnsServerTable_registration;
#endif
/**********************************************************************/
/*
 * TODO:110:r: |-> Review cabhCdpWanDnsServerTable data context structure.
 * This structure is used to represent the data for cabhCdpWanDnsServerTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * cabhCdpWanDnsServerTable.
 */
typedef struct cabhCdpWanDnsServerTable_data_s {
    
        /*
         * cabhCdpWanDnsServerIpType(2)/InetAddressType/ASN_INTEGER/long(u_long)//l/A/W/E/r/D/h
         */
   u_long   cabhCdpWanDnsServerIpType;
    
        /*
         * cabhCdpWanDnsServerIp(3)/InetAddress/ASN_OCTET_STR/char(char)//L/A/W/e/R/d/h
         */
   char   cabhCdpWanDnsServerIp[4];
size_t      cabhCdpWanDnsServerIp_len; /* # of char elements, not bytes */
    
} cabhCdpWanDnsServerTable_data;


/* *********************************************************************
 * TODO:115:o: |-> Review cabhCdpWanDnsServerTable undo context.
 * We're just going to use the same data structure for our
 * undo_context. If you want to do something more efficent,
 * define your typedef here.
 */
typedef cabhCdpWanDnsServerTable_data cabhCdpWanDnsServerTable_undo_data;

/*
 * TODO:120:r: |-> Review cabhCdpWanDnsServerTable mib index.
 * This structure is used to represent the index for cabhCdpWanDnsServerTable.
 */
typedef struct cabhCdpWanDnsServerTable_mib_index_s {

        /*
         * cabhCdpWanDnsServerOrder(1)/INTEGER/ASN_INTEGER/long(u_long)//l/a/w/E/r/d/h
         */
   u_long   cabhCdpWanDnsServerOrder;


} cabhCdpWanDnsServerTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review cabhCdpWanDnsServerTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_cabhCdpWanDnsServerTable_IDX_LEN     1


/* *********************************************************************
 * TODO:130:o: |-> Review cabhCdpWanDnsServerTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * cabhCdpWanDnsServerTable_rowreq_ctx pointer.
 */
typedef struct cabhCdpWanDnsServerTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_cabhCdpWanDnsServerTable_IDX_LEN];
    
    cabhCdpWanDnsServerTable_mib_index        tbl_idx;
    
    cabhCdpWanDnsServerTable_data              data;
    cabhCdpWanDnsServerTable_undo_data       * undo;
    unsigned int                column_set_flags; /* flags for set columns */


    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to cabhCdpWanDnsServerTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *cabhCdpWanDnsServerTable_data_list;

} cabhCdpWanDnsServerTable_rowreq_ctx;
#if 0
typedef struct cabhCdpWanDnsServerTable_ref_rowreq_ctx_s {
    cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx;
} cabhCdpWanDnsServerTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int cabhCdpWanDnsServerTable_pre_request(cabhCdpWanDnsServerTable_registration * user_context);
    int cabhCdpWanDnsServerTable_post_request(cabhCdpWanDnsServerTable_registration * user_context,
        int rc);

    int cabhCdpWanDnsServerTable_rowreq_ctx_init(cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void cabhCdpWanDnsServerTable_rowreq_ctx_cleanup(cabhCdpWanDnsServerTable_rowreq_ctx *rowreq_ctx);

    int cabhCdpWanDnsServerTable_commit(cabhCdpWanDnsServerTable_rowreq_ctx * rowreq_ctx);

    cabhCdpWanDnsServerTable_rowreq_ctx *
                  cabhCdpWanDnsServerTable_row_find_by_mib_index(cabhCdpWanDnsServerTable_mib_index *mib_idx);

extern const oid cabhCdpWanDnsServerTable_oid[];
extern const int cabhCdpWanDnsServerTable_oid_size;


#include "cabhCdpWanDnsServerTable_interface.h"
#include "cabhCdpWanDnsServerTable_data_access.h"
#include "cabhCdpWanDnsServerTable_data_get.h"
#endif
#include "cabhCdpWanDnsServerTable_data_set.h"

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

#endif /* CABHCDPWANDNSSERVERTABLE_H */
/** @} */
