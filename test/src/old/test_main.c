#include <stdio.h>
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "net-snmp/types.h"
#include "istc_snmp.h"

struct host {
  const char *name;
  const char *community;
} hosts[] = {
  { "192.168.0.1",		"public" },
  //{"localhost", "public"},
  //{"192.168.172.124", "public"},
  { NULL }
};

struct oid {
  const char *Name;
  oid Oid[MAX_OID_LEN];
  int OidLen;
} oids[] = {
  //{ "system" },
  {"sysName"},
  //{"demoIpAddress"},
  //{"DemoIpEntry"},
    //{"ifTable"},
  //{"clabWIFIAccessPointAssociatedDeviceNumberOfEntries.10001"},
  { NULL }
};


int main(void)
{
    netsnmp_pdu *response = NULL;
    char *host = hosts[0].name;
    char *community = hosts[0].community;
    char *oid_name = oids[0].Name;
    int reps = 10;

    size_t anOID_len = MAX_OID_LEN;
    oid anOID[MAX_OID_LEN];

    memset(anOID, 0, sizeof(anOID));
    
    if(snmp_parse_oid("system", anOID, &anOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        return ISTC_SNMP_ERROR;
    }
    return 0;
    if(istc_snmp_walk(host, community, oid_name, &reps, &response) != 0)
    {
        printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
        return ;
    }

    //snmp_print_pdulist(pdu_list, oid_name); 
    istc_snmp_free_pdu(response); 
    
    return ;
}
