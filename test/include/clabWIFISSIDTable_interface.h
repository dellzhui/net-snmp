/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
/** @ingroup interface: Routines to interface to Net-SNMP
 *
 * \warning This code should not be modified, called directly,
 *          or used to interpret functionality. It is subject to
 *          change at any time.
 * 
 * @{
 */
/*
 * *********************************************************************
 * *********************************************************************
 * *********************************************************************
 * ***                                                               ***
 * ***  NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE  ***
 * ***                                                               ***
 * ***                                                               ***
 * ***       THIS FILE DOES NOT CONTAIN ANY USER EDITABLE CODE.      ***
 * ***                                                               ***
 * ***                                                               ***
 * ***       THE GENERATED CODE IS INTERNAL IMPLEMENTATION, AND      ***
 * ***                                                               ***
 * ***                                                               ***
 * ***    IS SUBJECT TO CHANGE WITHOUT WARNING IN FUTURE RELEASES.   ***
 * ***                                                               ***
 * ***                                                               ***
 * *********************************************************************
 * *********************************************************************
 * *********************************************************************
 */
#ifndef CLABWIFISSIDTABLE_INTERFACE_H
#define CLABWIFISSIDTABLE_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif


#include "clabWIFISSIDTable.h"

#if 0
/* ********************************************************************
 * Table declarations
 */

/* PUBLIC interface initialization routine */
void _clabWIFISSIDTable_initialize_interface(clabWIFISSIDTable_registration * user_ctx,
                                    u_long flags);
void _clabWIFISSIDTable_shutdown_interface(clabWIFISSIDTable_registration * user_ctx);

clabWIFISSIDTable_registration *
clabWIFISSIDTable_registration_get( void );

clabWIFISSIDTable_registration *
clabWIFISSIDTable_registration_set( clabWIFISSIDTable_registration * newreg );

netsnmp_container *clabWIFISSIDTable_container_get( void );
int clabWIFISSIDTable_container_size( void );

u_int clabWIFISSIDTable_dirty_get( void );
void clabWIFISSIDTable_dirty_set( u_int status );

    clabWIFISSIDTable_rowreq_ctx * clabWIFISSIDTable_allocate_rowreq_ctx(void *);
void clabWIFISSIDTable_release_rowreq_ctx(clabWIFISSIDTable_rowreq_ctx *rowreq_ctx);

int clabWIFISSIDTable_index_to_oid(netsnmp_index *oid_idx,
                            clabWIFISSIDTable_mib_index *mib_idx);
int clabWIFISSIDTable_index_from_oid(netsnmp_index *oid_idx,
                              clabWIFISSIDTable_mib_index *mib_idx);

/*
 * access to certain internals. use with caution!
 */
void clabWIFISSIDTable_valid_columns_set(netsnmp_column_info *vc);
#endif
int
_clabWIFISSIDTable_set_column( clabWIFISSIDTable_rowreq_ctx *rowreq_ctx,
                       netsnmp_variable_list *var, int column );

#ifdef __cplusplus
}
#endif

#endif /* CLABWIFISSIDTABLE_INTERFACE_H */
/** @} */
