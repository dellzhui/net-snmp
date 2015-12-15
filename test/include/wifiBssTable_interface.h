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
#ifndef WIFIBSSTABLE_INTERFACE_H
#define WIFIBSSTABLE_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif


#include "wifiBssTable.h"

#if 0
/* ********************************************************************
 * Table declarations
 */

/* PUBLIC interface initialization routine */
void _wifiBssTable_initialize_interface(wifiBssTable_registration * user_ctx,
                                    u_long flags);
void _wifiBssTable_shutdown_interface(wifiBssTable_registration * user_ctx);

wifiBssTable_registration *
wifiBssTable_registration_get( void );

wifiBssTable_registration *
wifiBssTable_registration_set( wifiBssTable_registration * newreg );

netsnmp_container *wifiBssTable_container_get( void );
int wifiBssTable_container_size( void );

u_int wifiBssTable_dirty_get( void );
void wifiBssTable_dirty_set( u_int status );

    wifiBssTable_rowreq_ctx * wifiBssTable_allocate_rowreq_ctx(void *);
void wifiBssTable_release_rowreq_ctx(wifiBssTable_rowreq_ctx *rowreq_ctx);

int wifiBssTable_index_to_oid(netsnmp_index *oid_idx,
                            wifiBssTable_mib_index *mib_idx);
int wifiBssTable_index_from_oid(netsnmp_index *oid_idx,
                              wifiBssTable_mib_index *mib_idx);

/*
 * access to certain internals. use with caution!
 */
void wifiBssTable_valid_columns_set(netsnmp_column_info *vc);
#endif
int
_wifiBssTable_set_column( wifiBssTable_rowreq_ctx *rowreq_ctx,
                       netsnmp_variable_list *var, int column );

#ifdef __cplusplus
}
#endif

#endif /* WIFIBSSTABLE_INTERFACE_H */
/** @} */