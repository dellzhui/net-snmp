#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp.h"


static struct snmp_session *pSnmpSession = NULL;


int snmp_get_varcnt(netsnmp_pdu *pResponse, oid *rootOID, size_t rootOID_len, int *pNumbersGet)
{
    int                                       numbers_get = 0;
    netsnmp_variable_list         *vars = NULL;

    if(pResponse == NULL || rootOID == NULL || rootOID_len <= 0 || pNumbersGet == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }

    for(vars = pResponse->variables; vars; vars = vars->next_variable)
    {
        if((vars->name_length < rootOID_len) || memcmp(rootOID, vars->name, rootOID_len* sizeof(oid)) != 0)
        {
            continue;
        }
        numbers_get++;
        //istc_snmp_print_oid(vars->name, vars->name_length);
        //print_variable(vars->name, vars->name_length, vars);
    }
    *pNumbersGet = numbers_get;

    return ISTC_SNMP_SUCCESS;
}

int snmp_walk_to_get(netsnmp_session * ss, oid * theoid, size_t theoid_len, PDU_LIST_st *pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    netsnmp_pdu    *pdu, *response;
    int             status;

    if(ss == NULL || theoid == NULL ||theoid_len <= 0 || pdu_list == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return -1;
    }
    
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, theoid, theoid_len);

    status = snmp_synch_response(ss, pdu, &response);
    if(response == NULL)
    {
        printf("%s %d:snmpget error\n", __FUNCTION__, __LINE__);
        return -1;
    }
    *pStatus = response->errstat;
    if(status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR)
    {
        printf("%s %d:can not get oid", __FUNCTION__, __LINE__);
        istc_snmp_print_oid(theoid, theoid_len);
        snmp_free_pdu(response);
        return -1;
    }
    
    pdu_list->response = response;

    return 0;
}

int snmp_walk(netsnmp_session * pSnmpSession, oid *rootOID, int rootOID_len, PDU_LIST_st **pPDUList, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    PDU_LIST_st *pdu_list = NULL, *pdu_head = NULL;
    struct snmp_pdu *pdu = NULL;
    struct snmp_pdu *response = NULL;
    struct variable_list *vars = NULL, *prev_vars = NULL;
    size_t anOID_len = (MAX_OID_LEN) > rootOID_len ? rootOID_len : (MAX_OID_LEN);
    oid    anOID[MAX_OID_LEN];
    size_t first_oid_len = MAX_OID_LEN;
    oid *first_oid = NULL;
    int    status = -1;
    int running = 1;
    int exitval = 0;
    int rows_num = 0;
    int rows_get_flag = 0;
    int oid_index = 0;
    
    if(pSnmpSession == NULL || rootOID == NULL || rootOID_len <= 0 || pPDUList == NULL || pStatus == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return -1;
    }

    memset(anOID, 0, sizeof(anOID));
    memcpy(anOID, rootOID, rootOID_len * sizeof(oid));
    istc_snmp_print_oid(anOID, anOID_len);

    while(running)
    {
        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu->non_repeaters = 0;
        pdu->max_repetitions = 10;    /* fill the packet */
        snmp_add_null_var(pdu, anOID, anOID_len);
        printf("%s %d:create\n", __FUNCTION__, __LINE__);
        
        /* poll host */
        status = snmp_synch_response(pSnmpSession, pdu, &response);
        printf("%s %d:pass, status = %d, response->errstat = %ld\n", __FUNCTION__, __LINE__, status, response->errstat);
        if(response == NULL)
        {
            printf("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get");
            running = 0;
            exitval = 1;
            status = STAT_ERROR;
            continue;
        }
        switch(status)
        {
            case STAT_SUCCESS:
            {
                *pStatus = response->errstat;
                printf("%s %d:stzt = %d\n", __FUNCTION__, __LINE__, *pStatus);
                if(response->errstat == SNMP_ERR_NOERROR)
                {
                    if(pdu_list == NULL)
                    {
                        pdu_list = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st));
                        pdu_list->response = response;
                        pdu_head = pdu_list;
                    }
                    else if(pdu_list->next == NULL)
                    {
                        pdu_list->next = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st));
                        pdu_list = pdu_list->next;
                        pdu_list->response = response;
                    }

                    if(prev_vars != NULL)
                    {
                        prev_vars->next_variable = response->variables;
                    }
                    
                    for(vars = response->variables; vars; vars = vars->next_variable)
                    {
                        if(first_oid == NULL)
                        {
                            first_oid = vars->name;
                            first_oid_len = vars->name_length;
                            if((vars->name_length < rootOID_len) || memcmp(rootOID, vars->name, rootOID_len* sizeof(oid)) != 0)
                            {
                                printf("%s %d:first oid is not match root oid, we will exec snmpget\n", __FUNCTION__, __LINE__);
                                running = 0;
                                break;
                            }
                            rows_num++;
                        }
                        else if(rows_get_flag == 0 && memcmp(first_oid, vars->name, (first_oid_len - 1) * sizeof(oid)) == 0)
                        {
                            rows_num++;
                        }
                        else if(oid_index == 0)
                        {
                            printf("%s %d:we have get rows num %d\n", __FUNCTION__, __LINE__, rows_num);
                            rows_get_flag= 1;
                            if((vars->name_length < rootOID_len) || memcmp(rootOID, vars->name, rootOID_len* sizeof(oid)) != 0)
                            {
                                running = 0;
                                //continue;
                                break;
                            }
                            oid_index++;
                        }
                        else if(oid_index >= rows_num)
                        {
                            oid_index= 0;
                        }
                        else
                        {
                            oid_index++;
                        }

                        istc_snmp_print_oid(vars->name, vars->name_length);
                        print_variable(vars->name, vars->name_length, vars);
                        
                        if((vars->type != SNMP_ENDOFMIBVIEW) && (vars->type != SNMP_NOSUCHOBJECT) && (vars->type != SNMP_NOSUCHINSTANCE))
                        {
                            if (vars->next_variable == NULL) /*Check if last variable, and if so, save for next request.  */
                            {
                                memmove(anOID, vars->name, vars->name_length * sizeof(oid));
                                anOID_len = vars->name_length;
                                prev_vars = vars;
                            }
                        } 
                        else /* an exception value, so stop */ 
                        {
                            printf("%s %d:out\n", __FUNCTION__, __LINE__);
                            running = 0;
                        }
                    }
                }
                else /*error in response, print it */
                {
                    running = 0;
                    if(response->errstat == SNMP_ERR_NOSUCHNAME)
                    {
                        printf("End of MIB\n");
                    } 
                    else
                    {
                        fprintf(stderr, "Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
                        exitval = 2;
                    }
                }
              break;
            }
            case STAT_TIMEOUT:
            {
                if(pSnmpSession->peername != NULL)
                {
                    fprintf(stderr, "Timeout: No Response from %s\n", pSnmpSession->peername);
                }
                running = 0;
                exitval = 1;
                break;
            } 
            default:
            {
                running = 0;
                exitval = 1;
                break;
            }
        }
    }

    if(rows_num == 0 && status == STAT_SUCCESS)
    {
        printf("exec get\n");
        if(pdu_head)
        {
            istc_snmp_free_pdulist(pdu_head);
        }
        pdu_head = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st));
        if(snmp_walk_to_get(pSnmpSession, rootOID, rootOID_len, pdu_head, pStatus) != 0)
        {
            exitval = 1;
        }
        else
        {
            rows_num= 1;
        }
    }
    
    if(exitval != 0 && pdu_head != NULL)
    {
        istc_snmp_free_pdulist(pdu_head);
        printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
        return exitval;
    }

    if(pdu_head != NULL)
    {
         *pPDUList = pdu_head;
         printf("%s %d:snmpwalk success\n", __FUNCTION__, __LINE__);
        return 0;
    }
    printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
    return -1;
}

int snmp_set(netsnmp_session *pSession, oid * rootOID, size_t rootOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    int                                                              status = -1;
    netsnmp_pdu                                              *pdu = NULL;
    netsnmp_pdu                                              *response = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT stat =     ISTC_SNMP_ERR_UNKNOWN;

    
    netsnmp_assert(pSession != NULL);
    netsnmp_assert(rootOID != NULL);
    netsnmp_assert(rootOID_len > 0);
    netsnmp_assert(values != NULL && *values != 0);
    netsnmp_assert(pStatus != NULL);

    pdu = snmp_pdu_create(SNMP_MSG_SET);
    snmp_add_var(pdu, rootOID, rootOID_len, type, values);

    status = snmp_synch_response(pSession, pdu, &response);
    if(response == NULL)
    {
        *pStatus = ISTC_SNMP_ERR_UNKNOWN;
        return ISTC_SNMP_SUCCESS;
    }
    
    switch(status)
    {
    case STAT_SUCCESS:
        stat = response->errstat;
        if(stat == SNMP_ERR_NOERROR)
        {
            printf("%s %d:snmpset success\n", __FUNCTION__, __LINE__);
        }
        else
        {
            printf("%s %d:snmpset error, status = %d\n", __FUNCTION__, __LINE__, stat);
        }
        break;
    case STAT_TIMEOUT:
        if(pSession->peername != NULL)
        {
            printf("%s %d:Timeout: No Response from %s\n", __FUNCTION__, __LINE__, pSession->peername);
        }
        break;
    default:
        printf("%s %d:snmpset error\n", __FUNCTION__, __LINE__);
        break;
    }

    if(response)
    {
        snmp_free_pdu(response);
    }
    
    printf("%s %d:snmp status:%d\n", __FUNCTION__, __LINE__, stat);
    *pStatus = stat;

    return ISTC_SNMP_SUCCESS;
}


int istc_snmp_init(void)
{
    init_snmp("asynchapp");
    return 0;
}

int istc_snmp_walk(char *oid_name, PDU_LIST_st **pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    size_t anOID_len = MAX_OID_LEN;
    oid anOID[MAX_OID_LEN];
    
    if(oid_name == NULL || *oid_name == 0 || pdu_list == NULL || pStatus == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }

    if(pSnmpSession == NULL)
    {
        printf("%s %d:snmp agent info has not been set\n", __FUNCTION__, __LINE__);
        return -1;
    }

    printf("%s %d:get from host %s, oid_name = %s\n", __FUNCTION__, __LINE__, pSnmpSession->peername, oid_name);
    if(snmp_parse_oid(oid_name, anOID, &anOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        return ISTC_SNMP_ERROR;
    }
    
    if(snmp_walk(pSnmpSession, anOID, anOID_len, pdu_list, pStatus) != 0)
    {
        return ISTC_SNMP_ERROR;
    }
    
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_set(char *oid_name, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    const char *types = "=iu3taosxdb";
    size_t anOID_len = MAX_OID_LEN;
    oid anOID[MAX_OID_LEN];

    netsnmp_assert(oid_name != NULL && *oid_name != 0);
    netsnmp_assert(strchr(types, type) == NULL);
    netsnmp_assert(values != NULL && *values != 0);
    netsnmp_assert(pStatus != NULL);

    if(pSnmpSession == NULL)
    {
        printf("%s %d:snmp agent info has not been set\n", __FUNCTION__, __LINE__);
        return -1;
    }

    *pStatus = ISTC_SNMP_ERR_UNKNOWN;

    printf("%s %d:set host %s, oid_name = %s\n", __FUNCTION__, __LINE__, pSnmpSession->peername, oid_name);
    if(snmp_parse_oid(oid_name, anOID, &anOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        return ISTC_SNMP_ERROR;
    }
    
    if(snmp_set(pSnmpSession, anOID, anOID_len, type, values, pStatus) != 0)
    {
        return ISTC_SNMP_ERROR;
    }
    
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_print_oid(oid *Oid, int len)
{
    oid *oids = Oid;
    
    if(Oid == NULL || len  <= 0)
    {
        printf("%s %d:input wrong, Oid = %p, len = %d\n", __FUNCTION__, __LINE__, Oid, len);
        return ISTC_SNMP_ERROR;
    }

    printf("print oid:");
    while(oids - Oid < len)
    {
        printf("%d ", (int)*oids);
        oids++;
    }
    printf("\n");
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_print_pdulist(PDU_LIST_st *pdu_list, char *oid_name)
{
    PDU_LIST_st *pdu_list_head = pdu_list, *pdu_list_tmp = NULL;
    struct variable_list *vars = NULL;
    int numbers_get = 0;
    size_t rootOID_len = MAX_OID_LEN;
    oid rootOID[MAX_OID_LEN];

    if(pdu_list == NULL || oid_name == NULL)
    {
        printf("%s %d:input wrong, pdu_list = %p, root_oid = %p, root_oid_len = %d\n", __FUNCTION__, __LINE__, pdu_list, rootOID, rootOID_len);
        return -1;
    }

    if(snmp_parse_oid(oid_name, rootOID, &rootOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        return -1;
    }
    
    for(pdu_list_tmp = pdu_list_head; pdu_list_tmp; pdu_list_tmp = pdu_list_tmp->next)
    {
        for(vars = pdu_list_tmp->response->variables; vars; vars = vars->next_variable)
        {
            if(memcmp(vars->name, rootOID, rootOID_len * sizeof(oid)) == 0)
            {
                print_variable(vars->name, vars->name_length, vars);
                numbers_get++;
            }
        }
    }
    printf("%s %d:number total get:%d\n", __FUNCTION__, __LINE__, numbers_get);
    return 0;
}

int istc_snmp_free_pdulist(PDU_LIST_st *pdu_list)
{
    PDU_LIST_st *pdu_list_head = pdu_list, *pdu_list_tmp = NULL;
    
    while(pdu_list != NULL)
    {
        pdu_list_tmp = pdu_list;
        pdu_list = pdu_list->next;
        if(pdu_list_tmp->response)
        {
            snmp_free_pdu(pdu_list_tmp->response);
        }
        free(pdu_list_tmp);
    }
    pdu_list = pdu_list_head;
    return 0;
}

int istc_snmp_set_agent_info(SNMP_AGENT_INFO_st agentinfo)
{
    struct snmp_session ss;

    if(pSnmpSession != NULL)
    {
        snmp_close(pSnmpSession);
        pSnmpSession = NULL;
    }
    snmp_sess_init(&ss);            /* initialize session */
    ss.version = SNMP_VERSION_2c;
    ss.peername = strdup(agentinfo.name);
    ss.community = (u_char *)strdup(agentinfo.community);
    ss.community_len = strlen((char *)ss.community);
    ss.timeout = 5000000;

    if((pSnmpSession = snmp_open(&ss)) == NULL)
    {
      snmp_perror("snmp_open");
      return  ISTC_SNMP_ERROR;
    }
    return 0;
}


