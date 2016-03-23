/*
 * Note: this file originally auto-generated by mib2c using
 *  $
 *
 * $Id:$
 */
#ifndef IPADDRTABLE_OIDS_H
#define IPADDRTABLE_OIDS_H

#ifdef __cplusplus
extern "C" {
#endif


/* column number definitions for table ipAddrTable */
#define IPADDRTABLE_OID              1,3,6,1,2,1,4,20
#define IPADDRENTRY_OID              1

#define COLUMN_IPADENTADDR         1
#define COLUMN_IPADENTADDR_FLAG    (0x1 << 0)
    
#define COLUMN_IPADENTIFINDEX         2
#define COLUMN_IPADENTIFINDEX_FLAG    (0x1 << 1)
    
#define COLUMN_IPADENTNETMASK         3
#define COLUMN_IPADENTNETMASK_FLAG    (0x1 << 2)
    
#define COLUMN_IPADENTBCASTADDR         4
#define COLUMN_IPADENTBCASTADDR_FLAG    (0x1 << 3)
    
#define COLUMN_IPADENTREASMMAXSIZE         5
#define COLUMN_IPADENTREASMMAXSIZE_FLAG    (0x1 << 4)
    

#define IPADDRTABLE_MIN_COL   COLUMN_IPADENTADDR
#define IPADDRTABLE_MAX_COL   COLUMN_IPADENTREASMMAXSIZE
    

    /*
     * TODO:405:r: Review IFTABLE_SETTABLE_COLS macro.
     * OR together all the writable cols.
     */
#define IPADDRTABLE_SETTABLE_COLS (COLUMN_IPADENTADDR_FLAG | COLUMN_IPADENTIFINDEX_FLAG | COLUMN_IPADENTNETMASK_FLAG | COLUMN_IPADENTBCASTADDR_FLAG | COLUMN_IPADENTREASMMAXSIZE_FLAG)

#ifdef __cplusplus
}
#endif

#endif /* IPADDRTABLE_OIDS_H */

