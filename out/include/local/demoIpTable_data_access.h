/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef DEMOIPTABLE_DATA_ACCESS_H
#define DEMOIPTABLE_DATA_ACCESS_H

#ifdef __cplusplus
extern "C" {
#endif
#include "net-snmp/agent/cache_handler.h"

/* *********************************************************************
 * function declarations
 */

/* *********************************************************************
 * Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table demoIpTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * STEVE-TEST-MIB::demoIpTable is subid 1 of products.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.12345.1.1, length: 9
*/


    int demoIpTable_init_data(demoIpTable_registration * demoIpTable_reg);


    /*
     * TODO:180:o: Review demoIpTable cache timeout.
     * The number of seconds before the cache times out
     */
#define DEMOIPTABLE_CACHE_TIMEOUT   60

void demoIpTable_container_init(netsnmp_container **container_ptr_ptr,
                             netsnmp_cache *cache);
void demoIpTable_container_shutdown(netsnmp_container *container_ptr);

int demoIpTable_container_load(netsnmp_container *container);
void demoIpTable_container_free(netsnmp_container *container);

int demoIpTable_cache_load(netsnmp_container *container);
void demoIpTable_cache_free(netsnmp_container *container);

    /*
    ***************************************************
    ***             START EXAMPLE CODE              ***
    ***---------------------------------------------***/
/* *********************************************************************
 * Since we have no idea how you really access your data, we'll go with
 * a worst case example: a flat text file.
 */
#define MAX_LINE_SIZE 256
    /*
    ***---------------------------------------------***
    ***              END  EXAMPLE CODE              ***
    ***************************************************/
    int demoIpTable_row_prep( demoIpTable_rowreq_ctx *rowreq_ctx);



#ifdef __cplusplus
}
#endif

#endif /* DEMOIPTABLE_DATA_ACCESS_H */
