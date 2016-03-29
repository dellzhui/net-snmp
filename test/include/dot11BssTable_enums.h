/*
 * Note: this file originally auto-generated by mib2c using
 *  $
 *
 * $Id:$
 */
#ifndef DOT11BSSTABLE_ENUMS_H
#define DOT11BSSTABLE_ENUMS_H

#ifdef __cplusplus
extern "C" {
#endif

 /*
 * NOTES on enums
 * ==============
 *
 * Value Mapping
 * -------------
 * If the values for your data type don't exactly match the
 * possible values defined by the mib, you should map them
 * below. For example, a boolean flag (1/0) is usually represented
 * as a TruthValue in a MIB, which maps to the values (1/2).
 *
 */
/*************************************************************************
 *************************************************************************
 *
 * enum definitions for table dot11BssTable
 *
 *************************************************************************
 *************************************************************************/

/*************************************************************
 * constants for enums for the MIB node
 * dot11BssEnable (TruthValue / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef TRUTHVALUE_ENUMS
#define TRUTHVALUE_ENUMS

#define TRUTHVALUE_TRUE  1 
#define TRUTHVALUE_FALSE  2 

#endif /* TRUTHVALUE_ENUMS */


/*************************************************************
 * constants for enums for the MIB node
 * dot11BssNetworkBridge (INTEGER / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef DOT11BSSNETWORKBRIDGE_ENUMS
#define DOT11BSSNETWORKBRIDGE_ENUMS

#define DOT11BSSNETWORKBRIDGE_LAN  1 
#define DOT11BSSNETWORKBRIDGE_GUEST  2 

#endif /* DOT11BSSNETWORKBRIDGE_ENUMS */


/*************************************************************
 * constants for enums for the MIB node
 * dot11BssSecurityMode (INTEGER / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef DOT11BSSSECURITYMODE_ENUMS
#define DOT11BSSSECURITYMODE_ENUMS

#define DOT11BSSSECURITYMODE_DISABLED  0 
#define DOT11BSSSECURITYMODE_WEP  1 
#define DOT11BSSSECURITYMODE_WPAPSK  2 
#define DOT11BSSSECURITYMODE_WPA2PSK  3 
#define DOT11BSSSECURITYMODE_WPAENTERPRISE  4 
#define DOT11BSSSECURITYMODE_WPA2ENTERPRISE  5 
#define DOT11BSSSECURITYMODE_RADIUSWEP  6 
#define DOT11BSSSECURITYMODE_WPAWPA2PSK  7 
#define DOT11BSSSECURITYMODE_WPAWPA2ENTERPRISE  8 

#endif /* DOT11BSSSECURITYMODE_ENUMS */


/*************************************************************
 * constants for enums for the MIB node
 * dot11BssClosedNetwork (TruthValue / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef TRUTHVALUE_ENUMS
#define TRUTHVALUE_ENUMS

#define TRUTHVALUE_TRUE  1 
#define TRUTHVALUE_FALSE  2 

#endif /* TRUTHVALUE_ENUMS */


/*************************************************************
 * constants for enums for the MIB node
 * dot11BssAccessMode (INTEGER / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef DOT11BSSACCESSMODE_ENUMS
#define DOT11BSSACCESSMODE_ENUMS

#define DOT11BSSACCESSMODE_ALLOWANY  1 
#define DOT11BSSACCESSMODE_ALLOWLIST  2 
#define DOT11BSSACCESSMODE_DENYLIST  3 

#endif /* DOT11BSSACCESSMODE_ENUMS */




#ifdef __cplusplus
}
#endif

#endif /* DOT11BSSTABLE_ENUMS_H */