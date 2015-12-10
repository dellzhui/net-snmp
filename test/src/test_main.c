#include <stdio.h>
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp.h"
#include "demoIpTable.h"
#include "demoIpTable_interface.h"
#include "demoIpTable_oids.h"
#include "istc_log.h"

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

int print_iptable_datalist(SNMP_DATA_LIST_st *pDataList)
{
    SNMP_DATA_LIST_st *data_list = NULL;
    demoIpTable_rowreq_ctx *ctx = NULL;
    int rows = 0;
    
    netsnmp_assert(pDataList != NULL);

    for(data_list = pDataList; data_list; data_list = data_list->next)
    {
        if(data_list->data == NULL)
        {
            istc_log("no data beed saved\n");
            return -1;
        }
        ctx = (demoIpTable_rowreq_ctx *)data_list->data;
        printf("\n");
        istc_log("rows index:%d\n", ++rows);
        istc_log("Inuse:%ld\n", ctx->data.demoIpInuse);
        istc_log("IpAdress:%s, len:%d\n", ctx->data.demoIpAddress, ctx->data.demoIpAddress_len);
        istc_log("MacAdress:%s, len:%d\n\n", ctx->data.demoMacAddress, ctx->data.demoMacAddress_len);
    }

    return 0;
}

int main(void)
{
    char *oid_name = (char *)oids[0].Name;
    SNMP_AGENT_INFO_st agent_info;
    SnmpTableFun fun = _demoIpTable_set_column;
    SNMP_DATA_LIST_st *data_list = NULL;
    int data_len = sizeof(demoIpTable_rowreq_ctx);
    
    istc_snmp_init();
    
    memset(&agent_info, 0, sizeof(agent_info));
    strncpy(agent_info.name, (char *)hosts[0].name, sizeof(agent_info.name) - 1);
    strncpy(agent_info.community, (char *)hosts[0].community, sizeof(agent_info.community) - 1);
    istc_snmp_update_agent_info(agent_info);

#if 0    
    PDU_LIST_st *pdu_list = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = -1;
    if(istc_snmp_walk(oid_name, &pdu_list, &stat) != 0 || pdu_list == NULL)
    {
        printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
        return -1;
    }
    printf("%s %d:stat = %d\n", __FUNCTION__, __LINE__, stat);

     //_demoIpTable_set_column(&ctx, response->variables, COLUMN_DEMOIPADDRESS);
     //printf("%s %d:%s\n", __FUNCTION__, __LINE__, ctx.data.demoIpAddress);

    istc_snmp_print_pdulist(pdu_list, oid_name); 
    istc_snmp_free_pdulist(pdu_list); 

    
    if(0 && strcmp(oid_name, "demoIpAddress.0") == 0)
    {
        if(istc_snmp_set(oid_name, 's', "12.34.56.78", &stat) != 0)
        {
            printf("%s %d:snmpset error\n", __FUNCTION__, __LINE__);
            return -1;
        }
        printf("%s %d:stat = %d\n", __FUNCTION__, __LINE__, stat);
    }
#else
    if(istc_snmp_parse_data(oid_name, fun, data_len, &data_list) != 0)
    {
        istc_log("can not parse data_list\n");
        return -1;
    }
    istc_log("parse data success\n");
    print_iptable_datalist(data_list);
#endif    
    return 0;
}

