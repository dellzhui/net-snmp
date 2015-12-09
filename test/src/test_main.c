#include <stdio.h>
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp.h"
#include "demoIpTable.h"
#include "demoIpTable_interface.h"
#include "demoIpTable_oids.h"

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
  //{"demoIpAddress.0"},
  {"DemoIpEntry"},
    //{"ifTable"},
  //{"clabWIFIAccessPointAssociatedDeviceNumberOfEntries.10001"},
  { NULL }
};


int main(void)
{
    netsnmp_pdu *response = NULL;
    netsnmp_pdu *pdu
    char *host = (char *)hosts[0].name;
    char *community = (char *)hosts[0].community;
    char *oid_name = (char *)oids[0].Name;
    int reps = DEMOIPTABLE_SETTABLE_COLS;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = -1;
    demoIpTable_rowreq_ctx ctx;

    istc_snmp_init();
    memset(&ctx, 0, sizeof(ctx));
    
    if(istc_snmp_walk(host, community, oid_name, &reps, &response) != 0)
    {
        printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
        return -1;
    }
    printf("%s %d:reps = %d\n", __FUNCTION__, __LINE__, reps);

     _demoIpTable_set_column(&ctx, response->variables, COLUMN_DEMOIPADDRESS);
     printf("%s %d:%s\n", __FUNCTION__, __LINE__, ctx.data.demoIpAddress);

    istc_snmp_print_pdu(response, oid_name); 
    istc_snmp_free_pdu(response); 

    if(0 && strcmp(oid_name, "demoIpAddress.0") == 0)
    {
        if(istc_snmp_set(host, community, oid_name, 's', "12.34.56.78", &stat) != 0)
        {
            printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
            return -1;
        }
        printf("%s %d:stat = %d\n", __FUNCTION__, __LINE__, stat);
    }
    return 0;
}

