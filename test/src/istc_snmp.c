#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp.h"
#include "istc_log.h"


static struct snmp_session *pSnmpSession = NULL;


static int snmp_walk_to_get(netsnmp_session * ss, oid * theoid, size_t theoid_len, PDU_LIST_st *pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);

static int snmp_walk(netsnmp_session * pSnmpSession, oid *rootOID, int rootOID_len, PDU_LIST_st **pPDUList, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);

static int snmp_set(netsnmp_session *pSession, oid * rootOID, size_t rootOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);

static int snmp_get_rows_num(PDU_LIST_st *pdu_list, int *row_num);

static int snmp_parse_pdulist(PDU_LIST_st *pPDUList, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList);


int snmp_add_datalist(SNMP_DATA_LIST_st **head, int DataLen, SNMP_DATA_LIST_st **pDataList)
{
    SNMP_DATA_LIST_st *data_list = NULL;
    
    if(head == NULL || DataLen <= 0 || pDataList == NULL)
    {
        istc_log("input wrong\n");
        return -1;
    }

    if(*head == NULL)
    {
        if(((*head) = (SNMP_DATA_LIST_st *)calloc(1, sizeof(SNMP_DATA_LIST_st))) == NULL)
        {
            istc_log("can not calloc for data_lis node\n");
            return -1;
        }
        if(((*head)->data = (void *)calloc(1, DataLen)) == NULL)
        {
            istc_log("can not calloc for head data\n");
            free((*head));
            (*head) = NULL;
            return -1;
        }
        //istc_log("add head success\n");
        *pDataList = *head;
        return 0;
    }
    
    data_list = (*head);
    while(data_list->next != NULL)
    {
        data_list = data_list->next;
    }

    if((data_list->next = (SNMP_DATA_LIST_st *)calloc(1, sizeof(SNMP_DATA_LIST_st))) == NULL)
    {
        istc_log("can not calloc for data_lis node\n");
        return -1;
    }
    data_list = data_list->next;
    if((data_list->data = (void *)calloc(1, DataLen)) == NULL)
    {
        istc_log("can not calloc for data_list data\n");
        free(data_list);
        data_list = NULL;
        return -1;
    }
    *pDataList = data_list;
    //istc_log("add data_list node success\n");
    return 0;
}

int snmp_find_datalist(SNMP_DATA_LIST_st *head, int index, SNMP_DATA_LIST_st **pDataList)
{
    SNMP_DATA_LIST_st *data_list = head;
    int i = 0;

    if(head == NULL)
    {
        //istc_log("head is NULL\n");
        return -1;
    }
    
    netsnmp_assert(index >= 0);
    netsnmp_assert(pDataList != NULL);
    
    while(data_list!= NULL)
    {
        if(i == index)
        {
            *pDataList = data_list;
            return 0;
        }
        data_list = data_list->next;
        i++;
    }
    //istc_log("can not find index:%d\n", index);
    return -1;
    
}

int snmp_get_rows_num(PDU_LIST_st *pPDUList, int *rows_num)
{
    PDU_LIST_st *pdu_list = pPDUList;
    struct variable_list *vars = NULL;
    size_t rootOID_len = MAX_OID_LEN;
    oid *rootOID = NULL;
    int oid_index = 0;

    netsnmp_assert(pPDUList != NULL);
    netsnmp_assert(rows_num != NULL);

    for(pdu_list = pdu_list; pdu_list; pdu_list = pdu_list->next)
    {
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            if(rootOID == NULL)
            {
                rootOID = vars->name;
                rootOID_len = vars->name_length;
            }
            else
            {
                if(vars->name_length < (rootOID_len - 1) || memcmp(vars->name, rootOID, (rootOID_len - 1) * sizeof(oid)) != 0)
                {
                    break;
                }
            }
            oid_index++;
        }
    }
    printf("%s %d:get rows_num:%d success\n", __FUNCTION__, __LINE__, oid_index);
    *rows_num = oid_index;
    return ISTC_SNMP_SUCCESS;
}

int snmp_parse_pdulist(PDU_LIST_st *pPDUList, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList)
{
    int rows_num = 0;
    PDU_LIST_st *pdu_list;
    struct variable_list *vars = NULL;
    int column;
    SNMP_DATA_LIST_st *data_tmp = NULL, *data_head = NULL;
    int ret = 0, end = 0;;
    size_t root_oid_len;
    oid *root_oid = NULL;
    int index = 0;
    int oid_index = 0;

    istc_log("data_len = %d\n", DataLen);
    
    if(pPDUList != NULL && pPDUList->response == NULL && fun != NULL && DataLen > 0 && pDataList != NULL)
    {
        istc_log("input wrong\n");
        return ISTC_SNMP_ERROR;
    }
    if((pPDUList->response->variables == NULL) ||
        (root_oid = pPDUList->response->variables->name) == NULL || 
        (root_oid_len = pPDUList->response->variables->name_length) - 2 <= 0)
    {
        istc_log("invald root oid\n");
        return ISTC_SNMP_ERROR;
    }
    if(snmp_get_rows_num(pPDUList, &rows_num) != 0 || rows_num <= 0)
    {
        istc_log("can not get rows_num\n");
        return ISTC_SNMP_ERROR;
    }
    
    for(pdu_list = pPDUList; pdu_list != NULL && end == 0; pdu_list = pdu_list->next)
    {
        if(pdu_list->response == NULL)
        {
            istc_log("pdu_list->response is NULL\n");
            ret = -1;
            end = 1;
            break;
        }
        for(vars = pdu_list->response->variables; vars; vars = vars->next_variable)
        {
            column = (int)vars->name[vars->name_length - 2];
            index = (int)vars->name[vars->name_length - 1];
            if(oid_index == 0)
            {
                if(memcmp(vars->name, root_oid, (root_oid_len - 2) * sizeof(oid)) != 0)
                {
                    istc_log("it is another table, parse done\n");
                    end = 1;
                    break;
                }
                oid_index++;
            }
            else if((++oid_index) >= rows_num)
            {
                oid_index= 0;
            }
            
            if(snmp_find_datalist(data_head, index, &data_tmp) != 0)
            {
                if(snmp_add_datalist(&data_head, DataLen, &data_tmp) != 0)
                {
                    istc_log("can not add datalist node\n");
                    ret = -1;
                    end = 1;
                    break;
                }
                fun(data_tmp->data, vars, column);
            }
            else
            {
                fun(data_tmp->data, vars, column);
            }
        }
    }

    if(data_head != NULL)
    {
        if(ret != 0)
        {
            printf("parse data error\n");
            istc_snmp_free_datalist(data_head);
            return ISTC_SNMP_ERROR;
        }
        *pDataList = data_head;
        istc_log("parse data success\n");
        return ISTC_SNMP_SUCCESS;
    }
    printf("parse data error\n");
    return ISTC_SNMP_ERROR;
}

int snmp_walk_to_get(netsnmp_session * ss, oid * theoid, size_t theoid_len, PDU_LIST_st *pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    netsnmp_pdu    *pdu, *response;
    int             status;

    if(ss == NULL || theoid == NULL ||theoid_len <= 0 || pdu_list == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }
    
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, theoid, theoid_len);

    status = snmp_synch_response(ss, pdu, &response);
    if(response == NULL)
    {
        printf("%s %d:snmpget error\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }
    *pStatus = response->errstat;
    if(status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR)
    {
        printf("%s %d:can not get oid", __FUNCTION__, __LINE__);
        istc_snmp_print_oid(theoid, theoid_len);
        snmp_free_pdu(response);
        return ISTC_SNMP_ERROR;
    }
    
    pdu_list->response = response;

    return ISTC_SNMP_SUCCESS;
}

int snmp_walk(netsnmp_session * pSnmpSession, oid *rootOID, int rootOID_len, PDU_LIST_st **pPDUList, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    PDU_LIST_st *pdu_list = NULL, *pdu_head = NULL;
    struct snmp_pdu *pdu = NULL;
    struct snmp_pdu *response = NULL;
    struct variable_list *vars = NULL;
    size_t anOID_len = (MAX_OID_LEN) > rootOID_len ? rootOID_len : (MAX_OID_LEN);
    oid    anOID[MAX_OID_LEN];
    int    status = -1;
    int running = 1;
    int exitval = 0;
    int b_need_get = 0;
    int oid_index = 0, first_get = 0;
    const int reps = 10;
    
    if(pSnmpSession == NULL || rootOID == NULL || rootOID_len <= 0 || pPDUList == NULL || pStatus == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }

    memset(anOID, 0, sizeof(anOID));
    memcpy(anOID, rootOID, rootOID_len * sizeof(oid));
    istc_snmp_print_oid(anOID, anOID_len);

    while(running)
    {
        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu->non_repeaters = 0;
        pdu->max_repetitions = reps;    /* fill the packet */
        snmp_add_null_var(pdu, anOID, anOID_len);
        //printf("%s %d:create\n", __FUNCTION__, __LINE__);
        
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
                if(response->errstat == SNMP_ERR_NOERROR)
                {
                    if(pdu_list == NULL)
                    {
                        if((pdu_list = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st))) == NULL)
                        {
                            istc_log("can not calloc for pdu_list\n");
                            running = 0;
                            exitval = -1;
                            break;
                        }
                        pdu_list->response = response;
                        pdu_head = pdu_list;
                    }
                    else if(pdu_list->next == NULL)
                    {
                        if((pdu_list->next = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st))) == NULL)
                        {
                            istc_log("can not calloc for pdu_list next\n");
                            running = 0;
                            exitval = -1;
                            break;
                        }
                        pdu_list = pdu_list->next;
                        pdu_list->response = response;
                    }
                    
                    for(vars = response->variables; vars; vars = vars->next_variable)
                    {
                        if(first_get == 0)
                        {
                            first_get = 1;
                            if((vars->name_length < rootOID_len) || memcmp(rootOID, vars->name, rootOID_len* sizeof(oid)) != 0)
                            {
                                printf("%s %d:first oid is not match root oid, we will exec snmpget\n", __FUNCTION__, __LINE__);
                                running = 0;
                                b_need_get = 1;
                                break;
                            }
                        }
                        //printf("index = %d, max =%d\n", oid_index + 1, reps);
                        if((++oid_index) == reps)
                        {
                            if((vars->name_length < rootOID_len) || memcmp(rootOID, vars->name, rootOID_len* sizeof(oid)) != 0)
                            {
                                running = 0;
                                break;
                            }
                            oid_index = 0;
                        }

                        //istc_snmp_print_oid(vars->name, vars->name_length);
                        //print_variable(vars->name, vars->name_length, vars);
                        
                        if((vars->type != SNMP_ENDOFMIBVIEW) && (vars->type != SNMP_NOSUCHOBJECT) && (vars->type != SNMP_NOSUCHINSTANCE))
                        {
                            if (vars->next_variable == NULL) /*Check if last variable, and if so, save for next request.  */
                            {
                                memmove(anOID, vars->name, vars->name_length * sizeof(oid));
                                anOID_len = vars->name_length;
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

    if(b_need_get == 1 && status == STAT_SUCCESS)
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
        return ISTC_SNMP_SUCCESS;
    }
    printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
    return ISTC_SNMP_ERROR;
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
    return ISTC_SNMP_SUCCESS;
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
        return ISTC_SNMP_ERROR;
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
        return ISTC_SNMP_ERROR;
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
        return ISTC_SNMP_ERROR;
    }

    if(snmp_parse_oid(oid_name, rootOID, &rootOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        return ISTC_SNMP_ERROR;
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
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_free_pdulist(PDU_LIST_st *pdu_list)
{
    PDU_LIST_st *pdu_list_head = pdu_list, *pdu_list_tmp = NULL;
    int index = 0;
    
    while(pdu_list != NULL)
    {
        pdu_list_tmp = pdu_list;
        pdu_list = pdu_list->next;
        if(pdu_list_tmp->response)
        {
            printf("%s %d:free index:%d\n", __FUNCTION__, __LINE__, index++);
            snmp_free_pdu(pdu_list_tmp->response);
        }
        free(pdu_list_tmp);
    }
    pdu_list = pdu_list_head;
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_free_datalist(SNMP_DATA_LIST_st *pDataList)
{
    SNMP_DATA_LIST_st *data_list = pDataList, *data_list_tmp = NULL;

    netsnmp_assert(pDataList != NULL);

    while(data_list)
    {
        data_list_tmp = data_list;
        data_list = data_list->next;
        if(data_list_tmp->data != NULL)
        {
            free(data_list_tmp->data);
        }
        free(data_list_tmp);
    }
    return ISTC_SNMP_SUCCESS;
}
int istc_snmp_update_agent_info(SNMP_AGENT_INFO_st agentinfo)
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
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_parse_data(char *oid_name, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList)
{
    PDU_LIST_st *pdu_list = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = ISTC_SNMP_ERR_UNKNOWN;

    
    netsnmp_assert(oid_name != NULL && *oid_name != 0 && fun != NULL && pDataList != NULL);

    if(istc_snmp_walk(oid_name, &pdu_list, &stat) != 0 || pdu_list == NULL)
    {
        istc_log("snmpwalk error, oid_name = %s", oid_name);
        return ISTC_SNMP_ERROR;
    }

    //istc_snmp_print_pdulist(pdu_list, oid_name);
    
    if(snmp_parse_pdulist(pdu_list, fun, DataLen, pDataList) != 0)
    {
        istc_log("can not parse pdulist\n");
        return ISTC_SNMP_ERROR;
    }
    return ISTC_SNMP_SUCCESS;
}

