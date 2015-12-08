#include <stdio.h>
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp.h"

struct host {
  const char *name;
  const char *community;
} hosts[] = {
  //{ "192.168.0.1",		"public" },
  {"localhost", "public"},
  //{"192.168.172.124", "public"},
  { NULL }
};

struct oid {
  const char *Name;
  oid Oid[MAX_OID_LEN];
  int OidLen;
} oids[] = {
  //{ "system" },
  //{"sysName"},
  //{"demoIpAddress"},
  {"DemoIpEntry"},
    //{"ifTable"},
  //{"clabWIFIAccessPointAssociatedDeviceNumberOfEntries.10001"},
  { NULL }
};


int main(void)
{
    netsnmp_pdu *response = NULL;
    char *host = (char *)hosts[0].name;
    char *community = (char *)hosts[0].community;
    char *oid_name = (char *)oids[0].Name;
    int reps = 100;

    istc_snmp_init();
    
    if(istc_snmp_walk(host, community, oid_name, &reps, &response) != 0)
    {
        printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
        return -1;
    }
    printf("%s %d:reps = %d\n", __FUNCTION__, __LINE__, reps);

    istc_snmp_print_pdu(response, oid_name); 
    istc_snmp_free_pdu(response); 
    
    return 0;
}

