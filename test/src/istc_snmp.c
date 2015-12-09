#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp.h"


static int snmp_get_varcnt(netsnmp_pdu *pResponse, oid *rootOID, size_t rootOID_len, int *pNumbersGet);
static int snmp_walk_to_get(netsnmp_session * ss, oid * rootOID, size_t rootOID_len, int *pNumbersGet, netsnmp_pdu **pResponse);
static int snmp_walk(netsnmp_session *pSession, oid *rootOID, size_t rootOID_len, int *reps_num, netsnmp_pdu **pResponse);
static int snmp_set(netsnmp_session *pSession, oid * rootOID, size_t rootOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);


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

static int snmp_walk_to_get(netsnmp_session * ss, oid * theoid, size_t theoid_len, int *numprinted, PDU_LIST_st **pdu_list)
{
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *vars;
    int             status;

    if(ss == NULL || theoid == NULL ||theoid_len <= 0 ||  numprinted == NULL || pdu_list == NULL || *pdu_list == NULL)
    {
        printf("%s %d:input wrong\n");
        return -1;
    }
    
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, theoid, theoid_len);

    status = snmp_synch_response(ss, pdu, &response);
    if(status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR)
    {
        printf("%s %d:can not get oid", __FUNCTION__, __LINE__);
        print_oid(theoid, theoid_len);
    }
    
    for(vars = response->variables; vars; vars = vars->next_variable)
    {
        if(memcmp(vars->name, theoid, theoid_len * sizeof(oid)) == 0)
        {
            (*numprinted)++;
        }
    }

    (*pdu_list)->pdu = pdu;
    (*pdu_list)->response = response;

    return 0;
}

int snmp_walk(struct  snmp_session *pSession, oid *rootOID, int rootOID_len, int reps, PDU_LIST_st *pPduList)
{
    PDU_LIST_st *pdu_list = NULL, *pdu_head = NULL, *pdu_tmp = NULL;
    struct snmp_pdu *pdu = NULL;
    struct snmp_pdu *response = NULL;
    struct variable_list *vars = NULL;
    size_t anOID_len = (MAX_OID_LEN) > rootOID_len ? rootOID_len : (MAX_OID_LEN);
    oid    anOID[MAX_OID_LEN];
    int    status = -1;
    int numbers_get = 0;
    int non_reps = 0;
    int running = 1;
    int exitval = 0;
    
    if(pSession == NULL || rootOID == NULL || rootOID_len < 0 || reps <= 0)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return -1;
    }

    memset(anOID, 0, sizeof(anOID));
    memcpy(anOID, rootOID, anOID_len * sizeof(oid));
    print_oid(anOID, anOID_len);

    while(running)
    {
        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu->non_repeaters = non_reps;
        pdu->max_repetitions = reps;    /* fill the packet */
        snmp_add_null_var(pdu, anOID, anOID_len);
        printf("%s %d:create\n", __FUNCTION__, __LINE__);
        
        /* poll host */
        status = snmp_synch_response(pSession, pdu, &response);
        printf("%s %d:pass, status = %d, SUCCESS = %d, response->errstat = %d\n", __FUNCTION__, __LINE__, status, STAT_SUCCESS, response->errstat);

        switch(status)
        {
            case STAT_SUCCESS:
            {
                if(response == NULL)
                {
                    printf("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get");
                    running = 0;
                    exitval = 1;
                    status = STAT_ERROR;
                }
                else
                {
                    if(response->errstat == SNMP_ERR_NOERROR)
                    {
                        if(pdu_list == NULL)
                        {
                            pdu_list = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st));
                            pdu_list->pdu = pdu;
                            pdu_list->response = response;
                            pdu_head = pdu_list;
                        }
                        else if(pdu_list->next == NULL)
                        {
                            pdu_list->next = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st));
                            pdu_list = pdu_list->next;
                            pdu_list->pdu = pdu;
                            pdu_list->response = response;
                        }
                        
                        for(vars = response->variables; vars; vars = vars->next_variable)
                        {
                            //print_oid(vars->name, vars->name_length);
                            if((vars->name_length < rootOID_len) || memcmp(rootOID, vars->name, rootOID_len* sizeof(oid)) != 0)
                            {
                                running = 0;
                                continue;
                            }

                            numbers_get++;
                            print_oid(vars->name, vars->name_length);
                            print_variable(vars->name, vars->name_length, vars);
                            
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
                }
                break;
            }
            case STAT_TIMEOUT:
            {
                if(pSession->peername != NULL)
                {
                    fprintf(stderr, "Timeout: No Response from %s\n", pSession->peername);
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

    if(numbers_get == 0 && status == STAT_SUCCESS)
    {
        printf("exec get\n");
        if(pdu_head)
        {
            snmp_free_pdulist(pdu_head);
        }
        pdu_head = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st));
        snmp_walk_to_get(pSession, rootOID, rootOID_len, &numbers_get, &pdu_head);
    }

    printf("%s %d:number total get:%d\n", __FUNCTION__, __LINE__, numbers_get);
    
    return pdu_head;
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

int istc_snmp_walk(char *host, char *community, char *oid_name, int *reps, netsnmp_pdu **pResponse)
{
    size_t anOID_len = MAX_OID_LEN;
    oid anOID[MAX_OID_LEN];
    struct snmp_session ss, *sp;
    
    if(host == NULL || community == NULL || oid_name == NULL || reps == NULL || *reps <= 0 || pResponse == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }

    snmp_sess_init(&ss);			/* initialize session */
    ss.version = SNMP_VERSION_2c;
    ss.peername = strdup(host);
    ss.community = (u_char *)strdup(community);
    ss.community_len = strlen((char *)ss.community);
    ss.timeout = 5000000;

    if (!(sp = snmp_open(&ss))) {
      snmp_perror("snmp_open");
      return  ISTC_SNMP_ERROR;
    }

    printf("%s %d:get from host %s, oid_name = %s\n", __FUNCTION__, __LINE__, ss.peername, oid_name);
    if(snmp_parse_oid(oid_name, anOID, &anOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        snmp_close(sp);
        return ISTC_SNMP_ERROR;
    }
    if(snmp_walk(sp, anOID, anOID_len, reps, pResponse) != 0)
    {
        snmp_close(sp);
        return ISTC_SNMP_ERROR;
    }
    
    snmp_close(sp);
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_set(char *host, char *community, char *oid_name, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    const char *types = "=iu3taosxdb";
    size_t anOID_len = MAX_OID_LEN;
    oid anOID[MAX_OID_LEN];
    struct snmp_session ss, *sp;
    
    netsnmp_assert(host != NULL && *host != 0);
    netsnmp_assert(community != NULL && *community != 0);
    netsnmp_assert(oid_name != NULL && *oid_name != 0);
    netsnmp_assert(strchr(types, type) == NULL);
    netsnmp_assert(host != NULL && *host != 0);
    netsnmp_assert(values != NULL && *values != 0);
    netsnmp_assert(pStatus != NULL);

    snmp_sess_init(&ss);			/* initialize session */
    ss.version = SNMP_VERSION_2c;
    ss.peername = strdup(host);
    ss.community = (u_char *)strdup(community);
    ss.community_len = strlen((char *)ss.community);
    ss.timeout = 5000000;

    *pStatus = ISTC_SNMP_ERR_UNKNOWN;

    if (!(sp = snmp_open(&ss))) {
      snmp_perror("snmp_open");
      return  ISTC_SNMP_ERROR;
    }

    printf("%s %d:get from host %s, oid_name = %s\n", __FUNCTION__, __LINE__, ss.peername, oid_name);
    if(snmp_parse_oid(oid_name, anOID, &anOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        snmp_close(sp);
        return ISTC_SNMP_ERROR;
    }
    
    if(snmp_set(sp, anOID, anOID_len, type, values, pStatus) != 0)
    {
        snmp_close(sp);
        return ISTC_SNMP_ERROR;
    }
    
    snmp_close(sp);
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

int snmp_print_pdulist(PDU_LIST_st *pdu_list, char *oid_name)
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
}

int snmp_free_pdulist(PDU_LIST_st *pdu_list)
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

