/*
 * Note: this file originally auto-generated by mib2c using
 *  $
 *
 * $Id:$
 */
#ifndef WIFIBSSTABLE_OIDS_H
#define WIFIBSSTABLE_OIDS_H

#ifdef __cplusplus
extern "C" {
#endif


/* column number definitions for table wifiBssTable */
#define WIFIBSSTABLE_OID              1,3,6,1,4,1,4413,2,2,2,1,18,1,2,1


#define COLUMN_WIFIBSSID         1
    
#define COLUMN_WIFIBSSENABLE         2
#define COLUMN_WIFIBSSENABLE_FLAG    (0x1 << 0)
    
#define COLUMN_WIFIBSSSSID         3
#define COLUMN_WIFIBSSSSID_FLAG    (0x1 << 1)
    
#define COLUMN_WIFIBSSSECURITYMODE         4
#define COLUMN_WIFIBSSSECURITYMODE_FLAG    (0x1 << 2)
    
#define COLUMN_WIFIBSSCLOSEDNETWORK         5
#define COLUMN_WIFIBSSCLOSEDNETWORK_FLAG    (0x1 << 3)
    
#define COLUMN_WIFIBSSACCESSMODE         6
#define COLUMN_WIFIBSSACCESSMODE_FLAG    (0x1 << 4)
    
#define COLUMN_WIFIBSSMAXASSOCIATIONSLIMIT         7
#define COLUMN_WIFIBSSMAXASSOCIATIONSLIMIT_FLAG    (0x1 << 5)
    
#define COLUMN_WIFIBSSOPMODECAPREQUIRED         8
#define COLUMN_WIFIBSSOPMODECAPREQUIRED_FLAG    (0x1 << 6)
    
#define COLUMN_WIFIBSSPROTECTEDMGMTFRAMES         9
#define COLUMN_WIFIBSSPROTECTEDMGMTFRAMES_FLAG    (0x1 << 7)
    
#define COLUMN_WIFIBSSPUBLICACCESSMODE         10
#define COLUMN_WIFIBSSPUBLICACCESSMODE_FLAG    (0x1 << 8)
    
#define COLUMN_WIFIBSSMFBPROBERESPONSE         11
#define COLUMN_WIFIBSSMFBPROBERESPONSE_FLAG    (0x1 << 9)
    
#define COLUMN_WIFIBSSACCESSTABLECLEAR         12
#define COLUMN_WIFIBSSACCESSTABLECLEAR_FLAG    (0x1 << 10)
    
#define COLUMN_WIFIBSSIASSCHEDULERENABLE         13
#define COLUMN_WIFIBSSIASSCHEDULERENABLE_FLAG    (0x1 << 11)
    
#define COLUMN_WIFIBSSIASSCHEDULERTYPE         14
#define COLUMN_WIFIBSSIASSCHEDULERTYPE_FLAG    (0x1 << 12)
    

#define WIFIBSSTABLE_MIN_COL   COLUMN_WIFIBSSID
#define WIFIBSSTABLE_MAX_COL   COLUMN_WIFIBSSIASSCHEDULERTYPE
    

    /*
     * TODO:405:r: Review WIFIBSSTABLE_SETTABLE_COLS macro.
     * OR together all the writable cols.
     */
#define WIFIBSSTABLE_SETTABLE_COLS (COLUMN_WIFIBSSENABLE_FLAG | COLUMN_WIFIBSSSSID_FLAG | COLUMN_WIFIBSSSECURITYMODE_FLAG | COLUMN_WIFIBSSCLOSEDNETWORK_FLAG | COLUMN_WIFIBSSACCESSMODE_FLAG | COLUMN_WIFIBSSMAXASSOCIATIONSLIMIT_FLAG | COLUMN_WIFIBSSOPMODECAPREQUIRED_FLAG | COLUMN_WIFIBSSPROTECTEDMGMTFRAMES_FLAG | COLUMN_WIFIBSSPUBLICACCESSMODE_FLAG | COLUMN_WIFIBSSMFBPROBERESPONSE_FLAG | COLUMN_WIFIBSSACCESSTABLECLEAR_FLAG | COLUMN_WIFIBSSIASSCHEDULERENABLE_FLAG | COLUMN_WIFIBSSIASSCHEDULERTYPE_FLAG)

#ifdef __cplusplus
}
#endif

#endif /* WIFIBSSTABLE_OIDS_H */