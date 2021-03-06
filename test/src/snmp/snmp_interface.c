/**
 ** Copyright (c) Inspur Group Co., Ltd. Unpublished
 **
 ** Inspur Group Co., Ltd.
 ** Proprietary & Confidential
 **
 ** This source code and the algorithms implemented therein constitute
 ** confidential information and may comprise trade secrets of Inspur
 ** or its associates, and any use thereof is subject to the terms and
 ** conditions of the Non-Disclosure Agreement pursuant to which this
 ** source code was originally received.
 **/

/******************************************************************************
DESCRIPTION:
  snmp interfaces for istc

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
2016-02-03, chenfx@inspur.com           written
*/


#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "snmp_interface.h"
#include "istc_log.h"
#include <assert.h>
#include <semaphore.h>


#define DEFAULT_HOST_NAME "192.168.0.1"
#define DEFAULT_HOST_COMMUNITY "public"
#define RESPONSE_TIMEOUT (5000)
#define REQUEST_RETRIES 5


static struct snmp_session *pSnmpSession = NULL;
static sem_t *gSnmpSem = NULL;


static void snmp_sem_init(void);

static void snmp_sem_post(void);

static void snmp_sem_wait(void);

static int snmp_add_datalist(SNMP_DATA_LIST_st **head, int DataLen, SNMP_DATA_LIST_st **pDataList);

static int snmp_table_parse_pdulist(PDU_LIST_st *pPDUList, oid *rootOID, size_t rootOID_len, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList, int *pRowNum);

static int snmp_get(netsnmp_session * ss, oid * theoid, size_t theoid_len, PDU_LIST_st *pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);

static int snmp_walk(netsnmp_session * pSnmpSession, oid *rootOID, int rootOID_len, PDU_LIST_st **pPDUList, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);

static int snmp_set(netsnmp_session *pSession, oid * rootOID, size_t rootOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus);


void snmp_sem_init(void)
{
    if(gSnmpSem == NULL)
    {
        gSnmpSem = (sem_t *)calloc(1, sizeof(sem_t));
        if(gSnmpSem != NULL)
        {
            sem_init(gSnmpSem, 0, 1);
        }
    }
}

void snmp_sem_post(void)
{
    if(gSnmpSem != NULL)
    {
        sem_post(gSnmpSem);
    }
}

void snmp_sem_wait(void)
{
    if(gSnmpSem != NULL)
    {
        sem_wait(gSnmpSem);
    }
}

int snmp_add_datalist(SNMP_DATA_LIST_st **head, int DataLen, SNMP_DATA_LIST_st **pDataList)
{
    SNMP_DATA_LIST_st *data_list = NULL;

    SNMP_ASSERT(head != NULL && DataLen > 0 && pDataList != NULL);

    if(*head == NULL)
    {
        if(((*head) = (SNMP_DATA_LIST_st *)calloc(1, sizeof(SNMP_DATA_LIST_st))) == NULL)
        {
            istc_log("can not calloc for data_lis node\n");
            return ISTC_SNMP_ERROR;
        }
        if(((*head)->data = (void *)calloc(1, DataLen)) == NULL)
        {
            istc_log("can not calloc for head data\n");
            free((*head));
            (*head) = NULL;
            return ISTC_SNMP_ERROR;
        }
        *pDataList = *head;
        return ISTC_SNMP_SUCCESS;
    }

    data_list = (*head);
    while(data_list->next != NULL)
    {
        data_list = data_list->next;
    }

    if((data_list->next = (SNMP_DATA_LIST_st *)calloc(1, sizeof(SNMP_DATA_LIST_st))) == NULL)
    {
        istc_log("can not calloc for data_lis node\n");
        return ISTC_SNMP_ERROR;
    }
    data_list = data_list->next;
    if((data_list->data = (void *)calloc(1, DataLen)) == NULL)
    {
        istc_log("can not calloc for data_list data\n");
        free(data_list);
        data_list = NULL;
        return ISTC_SNMP_ERROR;
    }
    *pDataList = data_list;
    return ISTC_SNMP_SUCCESS;
}

int snmp_table_parse_pdulist(PDU_LIST_st *pPDUList, oid *rootOID, size_t rootOID_len, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList, int *pRowNum)
{
    int rows_num = 0;
    PDU_LIST_st *pdu_list;
    struct variable_list *vars = NULL;
    int column;
    SNMP_DATA_LIST_st *data_tmp = NULL, *data_head = NULL;
    int ret = 0, end = 0;;
    int index = 0;
    int oid_index = 0;
    int index_prev = 0;
    int row = 0;
    int calloc_finish_flag = 0;
    void **index_data = NULL;

    SNMP_ASSERT(pPDUList != NULL && pPDUList->response != NULL);
    SNMP_ASSERT(rootOID != NULL && rootOID_len > 0);
    SNMP_ASSERT(fun != NULL && DataLen > 0 && pDataList != NULL);
    SNMP_ASSERT(pRowNum != NULL);

    istc_log("data_len = %d\n", DataLen);
    if(istc_snmp_table_get_rows_num(pPDUList, &rows_num) != 0 || rows_num <= 0)
    {
        istc_log("can not get a true rows_num\n");
        return ISTC_SNMP_ERROR;
    }
    if((index_data = (void **)calloc(rows_num, sizeof(void *))) == NULL)
    {
        istc_log("can not calloc for index_data\n");
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
            if((vars->type == SNMP_ENDOFMIBVIEW) || (vars->type == SNMP_NOSUCHOBJECT) || (vars->type == SNMP_NOSUCHINSTANCE))
            {
                istc_log("expection type:%d\n", vars->type);
                continue;
            }
            column = (int)vars->name[vars->name_length - 2];
            row = (int)vars->name[vars->name_length - 1];
            calloc_finish_flag = (row < index_prev) ? 1 : calloc_finish_flag;
            index_prev = row;
            index = oid_index;
            if(oid_index == 0)
            {
                if(memcmp(vars->name, rootOID, rootOID_len * sizeof(oid)) != 0)
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

            if(calloc_finish_flag == 0)
            {
                //istc_log("first calloc ");
                if(snmp_add_datalist(&data_head, DataLen, &data_tmp) != 0)
                {
                    istc_log("can not add datalist node\n");
                    ret = -1;
                    end = 1;
                    break;
                }
                index_data[index] = data_tmp->data;
                data_tmp->row = row;
            }
            //istc_log("index = %d, row = %d, column = %d\n", index, row, column);
            fun(index_data[index], vars, column);
        }
    }

    if(index_data)
    {
        free(index_data);
    }
    if(data_head != NULL && ret == 0)
    {
        *pDataList = data_head;
        *pRowNum= rows_num;
        istc_log("parse data success\n");
        return ISTC_SNMP_SUCCESS;
    }
    istc_snmp_table_free_datalist(data_head);
    istc_log("parse data error\n");
    return ISTC_SNMP_ERROR;
}

int snmp_get(netsnmp_session * ss, oid * theoid, size_t theoid_len, PDU_LIST_st *pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    netsnmp_pdu    *pdu, *response;
    int             status;

    SNMP_ASSERT(ss != NULL && theoid != NULL && theoid_len > 0 && pdu_list != NULL);

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, theoid, theoid_len);

    status = snmp_synch_response(ss, pdu, &response);
    if(response == NULL)
    {
        istc_log("snmpget error\n");
        return ISTC_SNMP_ERROR;
    }
    *pStatus = response->errstat;
    if(status != STAT_SUCCESS ||
        response->errstat != SNMP_ERR_NOERROR||
        response->variables->type == SNMP_ENDOFMIBVIEW ||
        response->variables->type == SNMP_NOSUCHOBJECT ||
        response->variables->type == SNMP_NOSUCHINSTANCE)
    {
        istc_snmp_print_oid(theoid, theoid_len);
        istc_log("snmpget error\n");
        snmp_free_pdu(response);
        return ISTC_SNMP_ERROR;
    }
    pdu_list->response = response;
    istc_log("snmpget success\n");
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

    SNMP_ASSERT(pSnmpSession != NULL && rootOID != NULL && rootOID_len > 0 && pPDUList != NULL && pStatus != NULL);

    memset(anOID, 0, sizeof(anOID));
    memcpy(anOID, rootOID, rootOID_len * sizeof(oid));
    istc_snmp_print_oid(anOID, anOID_len);

    while(running)
    {
        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu->non_repeaters = 0;
        pdu->max_repetitions = reps;    /* fill the packet */
        snmp_add_null_var(pdu, anOID, anOID_len);
        //istc_log("create\n");
        status = snmp_synch_response(pSnmpSession, pdu, &response);
        if(response == NULL)
        {
            istc_log("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get\n");
            running = 0;
            exitval = 1;
            status = (status == STAT_SUCCESS) ? STAT_ERROR : status;
        }
        switch(status)
        {
            case STAT_SUCCESS:
                istc_log("pass, status = %d, response->errstat = %ld\n", status, response->errstat);
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
                                istc_snmp_print_oid(vars->name, vars->name_length);
                                istc_log("first oid is not match root oid, we will exec snmpget\n");
                                running = 0;
                                b_need_get = 1;
                                break;
                            }
                        }
                        //istc_log("index = %d, max =%d\n", oid_index + 1, reps);
                        if((++oid_index) >= reps)
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
                                istc_log("begin to get another pdu\n");
                                memmove(anOID, vars->name, vars->name_length * sizeof(oid));
                                anOID_len = vars->name_length;
                            }
                        }
                        else /* an exception value, so stop */
                        {
                            istc_log("an exception value, so stop\n");
                            running = 0;
                        }
                    }
                }
                else /*error in response, print it */
                {
                    running = 0;
                    if(response->errstat == SNMP_ERR_NOSUCHNAME)
                    {
                        istc_log("End of MIB\n");
                    }
                    else
                    {
                        fprintf(stderr, "Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
                        exitval = 2;
                    }
                }
                break;
            case STAT_TIMEOUT:
                if(pSnmpSession->peername != NULL)
                {
                    istc_log("Timeout: No Response from %s\n", pSnmpSession->peername);
                }
                running = 0;
                exitval = 1;
                break;
            default:
                running = 0;
                exitval = 1;
                break;
        }
    }

    if(b_need_get == 1 && status == STAT_SUCCESS)
    {
        istc_log("exec get\n");
        if(pdu_head)
        {
            istc_snmp_free_pdulist(pdu_head);
        }
        pdu_head = (PDU_LIST_st *)calloc(1, sizeof(PDU_LIST_st));
        if(snmp_get(pSnmpSession, rootOID, rootOID_len, pdu_head, pStatus) != 0)
        {
            exitval = 1;
        }
    }
    if(pdu_head != NULL && exitval == 0)
    {
         *pPDUList = pdu_head;
         istc_log("snmpwalk success\n");
        return ISTC_SNMP_SUCCESS;
    }
    istc_snmp_free_pdulist(pdu_head);
    istc_log("snmpwalk error\n");
    return ISTC_SNMP_ERROR;
}

int snmp_set(netsnmp_session *pSession, oid * rootOID, size_t rootOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    int                                                              status = -1;
    netsnmp_pdu                                              *pdu = NULL;
    netsnmp_pdu                                              *response = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT               stat =     ISTC_SNMP_ERR_UNKNOWN;

    SNMP_ASSERT(pSession != NULL && rootOID != NULL && rootOID_len > 0 && values != NULL && *values != 0 && pStatus != NULL);
    pdu = snmp_pdu_create(SNMP_MSG_SET);
    snmp_add_var(pdu, rootOID, rootOID_len, type, values);

    status = snmp_synch_response(pSession, pdu, &response);
    if(response == NULL)
    {
        *pStatus = ISTC_SNMP_ERR_UNKNOWN;
        return ISTC_SNMP_SUCCESS;
    }

    istc_log("status = %d\n", status);
    switch(status)
    {
    case STAT_SUCCESS:
        stat = response->errstat;
        if(stat == SNMP_ERR_NOERROR)
        {
            istc_log("snmpset success\n");
        }
        else
        {
            istc_log("snmpset error, status = %d\n", stat);
        }
        break;
    case STAT_TIMEOUT:
        if(pSession->peername != NULL)
        {
            istc_log("Timeout: No Response from %s\n", pSession->peername);
        }
        break;
    default:
        istc_log("snmpset error\n");
        break;
    }

    if(response)
    {
        snmp_free_pdu(response);
    }

    istc_log("snmp status:%d\n", stat);
    *pStatus = stat;

    return ISTC_SNMP_SUCCESS;
}


int istc_snmp_init(void)
{
    istc_log("init snmp\n");
    SNMP_AGENT_INFO_st agentinfo;

    init_snmp("asynchapp");
    snmp_sem_init();
    
    memset(&agentinfo, 0, sizeof(SNMP_AGENT_INFO_st));
#if 0    
    strncpy(agentinfo.name, DEFAULT_HOST_NAME, sizeof(agentinfo.name) - 1);
#else
    FILE *fp = NULL;
    char cmd[128] = {0};
    char buf[32] = {0};
    char *p = NULL;
    snprintf(cmd, sizeof(cmd) - 1, "busybox ifconfig %s | grep \"inet addr:\" | busybox sed 's/^.*inet addr://g' | busybox sed 's/  Bcast:.*$//g'", DEFAULT_LAN_INTERFACE);
    if((fp = popen(cmd, "r")) == NULL)
    {
        istc_log("can not popen\n");
        strncpy(agentinfo.name, DEFAULT_HOST_NAME, sizeof(agentinfo.name) - 1);
    }
    else if(fread(buf, 1, sizeof(buf) - 2, fp) <= 0)
    {
        istc_log("can not read ip\n");
        pclose(fp);
        strncpy(agentinfo.name, DEFAULT_HOST_NAME, sizeof(agentinfo.name) - 1);
    }
    else if((p = strrchr(buf, '.')) == NULL)
    {
        istc_log("buf:%s, not a ip str\n", buf);
        pclose(fp);
        strncpy(agentinfo.name, DEFAULT_HOST_NAME, sizeof(agentinfo.name) - 1);
    }
    else
    {
        p++;
        *(p + 1) = 0;
        *p = '1';
        strncpy(agentinfo.name, buf, sizeof(agentinfo.name) - 1);
        pclose(fp);
    }
    istc_log("set host to [%s]\n", agentinfo.name);
#endif
    strncpy(agentinfo.community, DEFAULT_HOST_COMMUNITY, sizeof(agentinfo.community) - 1);
    istc_snmp_update_agent_info(agentinfo);
    istc_log("snmp init success\n");
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_walk(oid *anOID, size_t anOID_len, PDU_LIST_st **pdu_list, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    SNMP_ASSERT(anOID != NULL && anOID_len > 0&& pdu_list != NULL && pStatus != NULL);

    snmp_sem_wait();

    if(pSnmpSession == NULL)
    {
        istc_log("snmp agent info has not been set\n");
        snmp_sem_post();
        return ISTC_SNMP_ERROR;
    }

    istc_log("set host:%s\n", pSnmpSession->peername);
    if(snmp_walk(pSnmpSession, anOID, anOID_len, pdu_list, pStatus) != 0)
    {
        snmp_sem_post();
        return ISTC_SNMP_ERROR;
    }
    snmp_sem_post();
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_set(oid *anOID, size_t anOID_len, char type, char *values, ISTC_SNMP_RESPONSE_ERRSTAT *pStatus)
{
    const char *types = "=iu3taosxdb";
    
    SNMP_ASSERT(anOID != NULL && anOID_len > 0 && values != NULL && *values != 0 && pStatus != NULL);

    snmp_sem_wait();
    if(strchr(types, type) == NULL)
    {
        istc_log("unsupported type:%c", type);
        snmp_sem_post();
        return ISTC_SNMP_ERROR;
    }

    if(pSnmpSession == NULL)
    {
        istc_log("snmp agent info has not been set\n");
        snmp_sem_post();
        return ISTC_SNMP_ERROR;
    }
    
    *pStatus = ISTC_SNMP_ERR_UNKNOWN;

    istc_snmp_print_oid(anOID, anOID_len);
    istc_log("set host %s, type = %c, values = %s\n", pSnmpSession->peername, type, values);

    if(snmp_set(pSnmpSession, anOID, anOID_len, type, values, pStatus) != 0 || (pSnmpSession->retries != 0 && *pStatus != ISTC_SNMP_ERR_NOERROR))
    {
        istc_log("istc_snmp_set error\n");
        snmp_sem_post();
        return ISTC_SNMP_ERROR;
    }
    istc_log("istc_snmp_set success\n");
    snmp_sem_post();
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_table_get_rows_num(PDU_LIST_st *pPDUList, int *rows_num)
{
    PDU_LIST_st *pdu_list = pPDUList;
    struct variable_list *vars = NULL;
    size_t rootOID_len = MAX_OID_LEN;
    oid *rootOID = NULL;
    int oid_index = 0;

    SNMP_ASSERT(pPDUList != NULL && rows_num != NULL);

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

    if(oid_index <= 0)
    {
        *rows_num = 0;
        istc_log("get rows_num error\n");
        return ISTC_SNMP_ERROR;
    }
    istc_log("get rows_num:%d success\n", oid_index);
    *rows_num = oid_index;
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_print_oid(oid *Oid, int len)
{
    oid *oids = Oid;

    SNMP_ASSERT(Oid != NULL && len  > 0);

    istc_print("print oid:");
    while(oids - Oid < len)
    {
        istc_print("%d ", (int)*oids);
        oids++;
    }
    istc_print("\n");
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_print_pdulist(PDU_LIST_st *pdu_list, oid *rootOID, size_t rootOID_len)
{
    if(g_istc_debug)
    {
        PDU_LIST_st *pdu_list_head = pdu_list, *pdu_list_tmp = NULL;
        struct variable_list *vars = NULL;
        int numbers_get = 0;

        SNMP_ASSERT(pdu_list != NULL && rootOID != NULL && rootOID_len > 0);

        snmp_sem_wait();
        istc_print("\n******************************************************************************************\n\n");
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
        istc_print("\n******************************************************************************************\n\n");
        istc_log("number total get:%d\n", numbers_get);
        snmp_sem_post();
    }
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
            istc_log("free index:%d\n", index++);
            snmp_free_pdu(pdu_list_tmp->response);
        }
        free(pdu_list_tmp);
    }
    pdu_list = pdu_list_head;
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_table_free_datalist(SNMP_DATA_LIST_st *pDataList)
{
    SNMP_DATA_LIST_st *data_list = pDataList, *data_list_tmp = NULL;

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

int istc_snmp_get_agent_info(SNMP_AGENT_INFO_st *agentinfo)
{
    SNMP_ASSERT(agentinfo != NULL);

    snmp_sem_wait();
    if(pSnmpSession == NULL)
    {
        istc_log("snmp agent info has not been set\n");
        snmp_sem_post();
        return ISTC_SNMP_ERROR;
    }
    strncpy(agentinfo->name, pSnmpSession->peername, sizeof(agentinfo->name) - 1);
    strncpy(agentinfo->community, (char *)pSnmpSession->community, sizeof(agentinfo->community) - 1);
    agentinfo->retries = pSnmpSession->retries;
    snmp_sem_post();
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_update_agent_info(SNMP_AGENT_INFO_st agentinfo)
{
    struct snmp_session ss;

    snmp_sem_wait();
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
    ss.timeout = RESPONSE_TIMEOUT * 500;
    if(agentinfo.retries == -1)
    {
        ss.retries = 0;
    }
    else if(agentinfo.retries == 0)
    {
        ss.retries = REQUEST_RETRIES;
    }
    else if(agentinfo.retries > 0)
    {
        ss.retries= agentinfo.retries;
    }
    
    if((pSnmpSession = snmp_open(&ss)) == NULL)
    {
      snmp_perror("snmp_open");
      istc_log("update agent failed\n");
      snmp_sem_post();
      return  ISTC_SNMP_ERROR;
    }
    istc_log("update agent info success\n");
    snmp_sem_post();
    return ISTC_SNMP_SUCCESS;
}

int istc_snmp_table_parse_datalist(oid *rootOID, size_t rootOID_len, SnmpTableFun fun, int DataLen, SNMP_DATA_LIST_st **pDataList, int *pRowsNum)
{
    PDU_LIST_st *pdu_list = NULL;
    SNMP_DATA_LIST_st *data_list = NULL;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = ISTC_SNMP_ERR_UNKNOWN;
    int rows_num = 0;

    SNMP_ASSERT(rootOID != NULL && rootOID_len > 0 && fun != NULL && pDataList != NULL&& pRowsNum != NULL);
    
    if(istc_snmp_walk(rootOID, rootOID_len, &pdu_list, &stat) != 0 || pdu_list == NULL)
    {
        istc_log("snmpwalk error\n");
        return ISTC_SNMP_ERROR;
    }
    istc_snmp_print_pdulist(pdu_list, rootOID, rootOID_len);

    if(snmp_table_parse_pdulist(pdu_list, rootOID, rootOID_len, fun, DataLen, &data_list, &rows_num) != 0)
    {
        istc_log("can not parse pdulist\n");
        return ISTC_SNMP_ERROR;
    }

    istc_snmp_free_pdulist(pdu_list);

    if(data_list == NULL || rows_num <= 0)
    {
        if(data_list != NULL)
        {
            istc_snmp_table_free_datalist(data_list);
        }
        istc_log("parse table data error\n");
        return ISTC_SNMP_ERROR;
    }
    *pDataList = data_list;
    *pRowsNum = rows_num;
    istc_log("parse table success, rows_num = %d\n", rows_num);
    return ISTC_SNMP_SUCCESS;
}

