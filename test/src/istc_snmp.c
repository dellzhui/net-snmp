#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp.h"


static int snmp_get_varcnt(netsnmp_pdu *pResponse, oid *rootOID, size_t rootOID_len, int *pNumbersGet);
static int snmp_walk_to_get(netsnmp_session * ss, oid * rootOID, size_t rootOID_len, int *pNumbersGet, netsnmp_pdu **pResponse);
static int snmp_walk(netsnmp_session *pSession, oid *rootOID, size_t rootOID_len, int *reps_num, netsnmp_pdu **pResponse);


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

int snmp_walk_to_get(netsnmp_session * ss, oid * rootOID, size_t rootOID_len, int *pNumbersGet, netsnmp_pdu **pResponse)
{
    int                                      status = -1;
    int                                      numbers_get = 0;
    netsnmp_pdu                      *pdu = NULL;
    netsnmp_pdu                      *response = NULL;

    if(ss == NULL || rootOID == NULL ||rootOID_len <= 0 ||  pNumbersGet == NULL || pResponse == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }
    
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, rootOID, rootOID_len);

    status = snmp_synch_response(ss, pdu, &response);
    if(status != STAT_SUCCESS || response == NULL || response->errstat != SNMP_ERR_NOERROR)
    {
        printf("%s %d:can not get oid", __FUNCTION__, __LINE__);
        istc_snmp_print_oid(rootOID, rootOID_len);
        if(response)
        {
            snmp_free_pdu(response);
        }
        return ISTC_SNMP_ERROR;
    }
    
    snmp_get_varcnt(response, rootOID, rootOID_len, &numbers_get);
    if(numbers_get == 0)
    {
        printf("%s %d:snmp get null\n", __FUNCTION__, __LINE__);
        if(response)
        {
            snmp_free_pdu(response);
        }
        return ISTC_SNMP_ERROR;
    }

    *pResponse = response;
    *pNumbersGet = numbers_get;
    return ISTC_SNMP_SUCCESS;
}

int snmp_walk(netsnmp_session *pSession, oid *rootOID, size_t rootOID_len, int *reps_num, netsnmp_pdu **pResponse)
{
    int                              status = -1;
    int                              numbers_get = 0;
    int                              reps;
    int                              exitval = 0;
    struct snmp_pdu       *pdu = NULL;
    struct snmp_pdu       *response = NULL;
    
    
    if(pSession == NULL || rootOID == NULL || rootOID_len < 0 || reps_num == NULL || *reps_num <= 0 || pResponse == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return ISTC_SNMP_ERROR;
    }

    reps = *reps_num;

    if(reps == 1)
    {
        printf("%s %d:only one oid need to get, try to snmp_get\n", __FUNCTION__, __LINE__);
        if(snmp_walk_to_get(pSession, rootOID, rootOID_len, &numbers_get, &response) == 0)
        {
            printf("%s %d:snmp get success\n", __FUNCTION__, __LINE__);
            *reps_num = numbers_get;
            *pResponse = response;
            return ISTC_SNMP_SUCCESS;
        }
        printf("%s %d:snmp_get error, we will walk the first oid\n", __FUNCTION__, __LINE__);
    }

    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->non_repeaters = 0;
    pdu->max_repetitions = reps;    /* fill the packet */
    snmp_add_null_var(pdu, rootOID, rootOID_len);
    printf("%s %d:create\n", __FUNCTION__, __LINE__);
    
    /* poll host */
    status = snmp_synch_response(pSession, pdu, &response);
    printf("%s %d:pass, status = %d, response->errstat = %ld\n", __FUNCTION__, __LINE__, status, response->errstat);

    switch(status)
    {
        case STAT_SUCCESS:
        {
            if(response == NULL)
            {
                printf("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get");
                exitval = 1;
                status = STAT_ERROR;
                break;
            }
            
            if(response->errstat == SNMP_ERR_NOERROR)
            {
                snmp_get_varcnt(response, rootOID, rootOID_len, &numbers_get);
            }
            else if(response->errstat == SNMP_ERR_NOSUCHNAME)
            {
                printf("End of MIB\n");
            }
            else
            {
                printf("%s %d:Error in packet.\nReason: %s\n", __FUNCTION__, __LINE__, snmp_errstring(response->errstat));
                exitval = 2;
            }
            break;
        }
        case STAT_TIMEOUT:
        {
            if(pSession->peername != NULL)
            {
                printf("%s %d:Timeout: No Response from %s\n", __FUNCTION__, __LINE__, pSession->peername);
            }
            exitval = 1;
            break;
        } 
        default:
        {
            exitval = 1;
            break;
        }
    }

    if(reps > 1 && numbers_get == 0 && status == STAT_SUCCESS)
    {
        printf("exec get\n");
        if(response)
        {
            snmp_free_pdu(response);
            response = NULL;
        }
        if(snmp_walk_to_get(pSession, rootOID, rootOID_len, &numbers_get, &response) != 0)
        {
            printf("%s %d:snmp get error\n", __FUNCTION__, __LINE__);
            exitval = 1;
        }
    }
    if((exitval != 0 || numbers_get == 0) && response != NULL)
    {
        snmp_free_pdu(response);
        response = NULL;
        return ISTC_SNMP_ERROR;
    }

    printf("%s %d:number total get:%d\n", __FUNCTION__, __LINE__, numbers_get);
    *reps_num = numbers_get;
    *pResponse = response;
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

int istc_snmp_print_pdu(netsnmp_pdu *pResponse, char *oid_name)
{
    struct variable_list *vars = NULL;
    int numbers_get = 0;
    size_t rootOID_len = MAX_OID_LEN;
    oid rootOID[MAX_OID_LEN];

    if(pResponse == NULL || oid_name == NULL)
    {
        printf("%s %d:input wrong, pdu_list = %p, root_oid = %p, root_oid_len = %d\n", __FUNCTION__, __LINE__, pResponse, rootOID, rootOID_len);
        return ISTC_SNMP_ERROR;
    }

    if(snmp_parse_oid(oid_name, rootOID, &rootOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        return ISTC_SNMP_ERROR;
    }
    
    for(vars = pResponse->variables; vars; vars = vars->next_variable)
    {
        if(memcmp(vars->name, rootOID, rootOID_len * sizeof(oid)) == 0)
        {
            print_variable(vars->name, vars->name_length, vars);
            numbers_get++;
        }
    }
    printf("%s %d:number total get:%d\n", __FUNCTION__, __LINE__, numbers_get);
    return 0;
}

int istc_snmp_free_pdu(netsnmp_pdu *pResponse)
{
    
    if(pResponse)
    {
        snmp_free_pdu(pResponse);
    }
    return ISTC_SNMP_SUCCESS;
}

