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
#ifndef DEMOIPTABLE_INTERFACE_H
#define DEMOIPTABLE_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif


#include "demoIpTable.h"


/* ********************************************************************
 * Table declarations
 */

/* PUBLIC interface initialization routine */
int
_demoIpTable_set_column( demoIpTable_rowreq_ctx *rowreq_ctx,
                       netsnmp_variable_list *var, int column );



#ifdef __cplusplus
}
#endif

#endif /* DEMOIPTABLE_INTERFACE_H */
/** @} */
