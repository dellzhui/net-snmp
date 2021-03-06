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
#ifndef WIFIBSSACCESSTABLE_INTERFACE_H
#define WIFIBSSACCESSTABLE_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif


#include "wifiBssAccessTable.h"

#if 0
/* ********************************************************************
 * Table declarations
 */

/* PUBLIC interface initialization routine */
void _wifiBssAccessTable_initialize_interface(wifiBssAccessTable_registration * user_ctx,
                                    u_long flags);
void _wifiBssAccessTable_shutdown_interface(wifiBssAccessTable_registration * user_ctx);

wifiBssAccessTable_registration *
wifiBssAccessTable_registration_get( void );

wifiBssAccessTable_registration *
wifiBssAccessTable_registration_set( wifiBssAccessTable_registration * newreg );

netsnmp_container *wifiBssAccessTable_container_get( void );
int wifiBssAccessTable_container_size( void );

u_int wifiBssAccessTable_dirty_get( void );
void wifiBssAccessTable_dirty_set( u_int status );

    wifiBssAccessTable_rowreq_ctx * wifiBssAccessTable_allocate_rowreq_ctx(void *);
void wifiBssAccessTable_release_rowreq_ctx(wifiBssAccessTable_rowreq_ctx *rowreq_ctx);

int wifiBssAccessTable_index_to_oid(netsnmp_index *oid_idx,
                            wifiBssAccessTable_mib_index *mib_idx);
int wifiBssAccessTable_index_from_oid(netsnmp_index *oid_idx,
                              wifiBssAccessTable_mib_index *mib_idx);

/*
 * access to certain internals. use with caution!
 */
void wifiBssAccessTable_valid_columns_set(netsnmp_column_info *vc);
#endif
int
_wifiBssAccessTable_set_column( wifiBssAccessTable_rowreq_ctx *rowreq_ctx,
                       netsnmp_variable_list *var, int column );

#ifdef __cplusplus
}
#endif

#endif /* WIFIBSSACCESSTABLE_INTERFACE_H */
/** @} */
