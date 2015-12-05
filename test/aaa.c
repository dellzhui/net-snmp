/*
 * NET-SNMP demo
 *
 * This program demonstrates different ways to query a list of hosts
 * for a list of variables.
 *
 * It would of course be faster just to send one query for all variables,
 * but the intention is to demonstrate the difference between synchronous
 * and asynchronous operation.
 *
 * Niels Baggesen (Niels.Baggesen@uni-c.dk), 1999.
 */

#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
//#include "demoIpTable.h"
#include "net-snmp/types.h"
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

typedef struct __PDU_LIST
{
    struct __PDU_LIST *next;
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
}PDU_LIST_st;

//#define ASYNCHRONOUS

/*
 * a list of hosts to query
 */
struct host {
  const char *name;
  const char *community;
} hosts[] = {
  //{ "192.168.0.12",		"public" },
  {"localhost", "public"},
  { NULL }
};

/*
 * a list of variables to query for
 */
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

static int print_oid(oid *Oid, int len)
{
    oid *oids = Oid;
    
    if(Oid == NULL || len  <= 0)
    {
        printf("%s %d:input wrong, Oid = %p, len = %d\n", __FUNCTION__, __LINE__, Oid, len);
        return -1;
    }

    printf("print oid:");
    while(oids - Oid < len)
    {
        printf("%d ", *oids);
        oids++;
    }
    printf("\n");
    return 0;
}

/*
 * initialize
 */
void initialize (void)
{
  struct oid *op = oids;
  
  /* Win32: init winsock */
  SOCK_STARTUP;

  /* initialize library */
  init_snmp("asynchapp");

  /* parse the oids */
  while (op->Name) {
    op->OidLen = sizeof(op->Oid)/sizeof(op->Oid[0]);
    printf("%s %d:name = %s\n", __FUNCTION__, __LINE__, op->Name);
    if (!snmp_parse_oid(op->Name, op->Oid, (size_t *)&op->OidLen)) {
      //snmp_perror("read_objid");
      printf("%s %d:read error\n", __FUNCTION__, __LINE__);
      exit(1);
    }
    op++;
  }
}

/*! \fn char *snmp_get(host_t *current_host, char *snmp_oid)
 *  \brief performs a single snmp_get for a specific snmp OID
 *
 *	This function will poll a specific snmp OID for a host.  The host snmp
 *  session must already be established.
 *
 *  \return returns the character representaton of the snmp OID, or "U" if
 *  unsuccessful.
 *
 */
int snmp_get(struct  snmp_session *pSession, char *snmp_oid, char *pResult, int len)
{
    struct snmp_pdu *pdu = NULL;
    struct snmp_pdu *response = NULL;
    struct variable_list *vars = NULL;
    size_t anOID_len = MAX_OID_LEN;
    oid    anOID[MAX_OID_LEN];
    int    status;
    char   *result_string;
    int numbers_get = 0;
    int             reps = 10, non_reps = 0;
    
    if(pSession == NULL || snmp_oid == NULL || pResult == NULL || len <= 0)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return -1;
    }

    result_string = pResult;

    status = -1;

    anOID_len = MAX_OID_LEN;
    //pdu = snmp_pdu_create(SNMP_MSG_GET);
    //pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    pdu->non_repeaters = non_reps;
    pdu->max_repetitions = reps;    /* fill the packet */
    
    printf("%s %d:snmp_oid = %s\n", __FUNCTION__, __LINE__, snmp_oid);
    if(!snmp_parse_oid(snmp_oid, anOID, &anOID_len))
    {
        printf("ERROR: Problems parsing SNMP OID");
        return -1;
    }
    else
    {
        print_oid(anOID, anOID_len);
        snmp_add_null_var(pdu, anOID, anOID_len);
    }
    
    /* poll host */
    //status = snmp_sess_synch_response(pSession, pdu, &response);
    status = snmp_synch_response(pSession, pdu, &response);
    //netsnmp_query_walk(pdu->variables, pSession);
    printf("%s %d:pass, status = %d, SUCCESS = %d, response->errstat = %d\n", __FUNCTION__, __LINE__, status, STAT_SUCCESS, response->errstat);
    /* liftoff, successful poll, process it!! */
    if(status == STAT_SUCCESS)
    {
        if(response == NULL)
        {
            printf("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get");

            status = STAT_ERROR;
        }
        else
        {
            if(response->errstat == SNMP_ERR_NOERROR)
            {
#if 0            
                vars = response->variables;
                print_oid(vars->name, vars->name_length);
                printf("%s %d: aaa:%p, oid_name = %d\n", __FUNCTION__, __LINE__, vars->val.string, vars->name);
                //snprint_value(result_string, len, anOID, anOID_len, vars);
                if(vars->val.string != NULL)
                {
                    strncpy(result_string, vars->val.string, len);
                }
#else
                for(vars = response->variables; vars; vars = vars->next_variable)
                {
                    //print_oid(vars->name, vars->name_length);
                    numbers_get++;
                    //printf("%s %d:result:%s\n\n", __FUNCTION__, __LINE__, vars->val.string);
                    print_variable(vars->name, vars->name_length, vars);
                }
                printf("%s %d:number get:%d\n", __FUNCTION__, __LINE__, numbers_get);
#endif
            }
        }
    }

    if(response)
    {
        snmp_free_pdu(response);
        response = NULL;
    }

    return 0;
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

PDU_LIST_st *snmp_walk(struct  snmp_session *pSession, oid *rootOID, int rootOID_len)
{
    PDU_LIST_st *pdu_list = NULL, *pdu_head = NULL, *pdu_tmp = NULL;
    struct snmp_pdu *pdu = NULL;
    struct snmp_pdu *response = NULL;
    struct variable_list *vars = NULL;
    size_t anOID_len = (MAX_OID_LEN) > rootOID_len ? rootOID_len : (MAX_OID_LEN);
    oid    anOID[MAX_OID_LEN];
    int    status = -1;
    int numbers_get = 0;
    int reps = 10, non_reps = 0;
    int running = 1;
    int exitval = 0;
    
    if(pSession == NULL || rootOID == NULL || rootOID_len < 0)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return NULL;
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

int iporting_net_snmp_walk(char *host, char *community, char *oid_name, PDU_LIST_st **pdu_list)
{
    size_t anOID_len = MAX_OID_LEN;
    oid anOID[MAX_OID_LEN];
    struct snmp_session ss, *sp;
    
    if(host == NULL || community == NULL || oid_name == NULL || pdu_list == NULL)
    {
        printf("%s %d:input wrong\n", __FUNCTION__, __LINE__);
        return-1;
    }

    snmp_sess_init(&ss);			/* initialize session */
    ss.version = SNMP_VERSION_2c;
    ss.peername = strdup(host);
    ss.community = (u_char *)strdup(community);
    ss.community_len = strlen((char *)ss.community);
    ss.timeout = 5000000;

    if (!(sp = snmp_open(&ss))) {
      snmp_perror("snmp_open");
      return -1;
    }

    printf("%s %d:get from host %s\n", __FUNCTION__, __LINE__, ss.peername);
    if(snmp_parse_oid(oid_name, anOID, &anOID_len) == 0)
    {
        printf("%s %d:can not find oid:%s\n", __FUNCTION__, __LINE__, oid_name);
        snmp_close(sp);
        return -1;
    }
    if((*pdu_list = snmp_walk(sp, anOID, anOID_len)) == NULL)
    {
        snmp_close(sp);
        return -1;
    }
    
    snmp_close(sp);
    return 0;
}

/*
 * simple printing of returned data
 */
int print_result (int status, struct snmp_session *sp, struct snmp_pdu *pdu)
{
  char buf[1024];
  struct variable_list *vp;
  int ix;
  struct timeval now;
  struct timezone tz;
  struct tm *tm;
  //demoIpTable_data data;

  //memset(&data, 0, sizeof(data));
  //data.demoIpAddress_len = sizeof(data.demoIpAddress) / sizeof(data.demoIpAddress[0]);
  
  gettimeofday(&now, &tz);
  tm = localtime(&now.tv_sec);
  //fprintf(stdout, "%.2d:%.2d:%.2d.%.6d ", (int)tm->tm_hour, (int)tm->tm_min, (int)tm->tm_sec, (int)now.tv_usec);
  switch (status) {
  case STAT_SUCCESS:
    vp = pdu->variables;
    if (pdu->errstat == SNMP_ERR_NOERROR) {
        printf("read state success\n");
      while (vp) {
        snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
        //printf("%s %d:string = %s\n", __FUNCTION__, __LINE__, vp->val.string);
        //strncpy(data.demoIpAddress, vp->val.string, data.demoIpAddress_len);
        //printf("%s %d:string = %s\n", __FUNCTION__, __LINE__, data.demoIpAddress);
        //fprintf(stdout, "%s(%d):%s:%s\n", __FUNCTION__, __LINE__, sp->peername, buf);
	vp = vp->next_variable;
      }
    }
    else {
      for (ix = 1; vp && ix != pdu->errindex; vp = vp->next_variable, ix++)
        ;
      if (vp) snprint_objid(buf, sizeof(buf), vp->name, vp->name_length);
      else strcpy(buf, "(none)");
      fprintf(stdout, "%s: %s: %s\n",
      	sp->peername, buf, snmp_errstring(pdu->errstat));
    }
    return 1;
  case STAT_TIMEOUT:
    fprintf(stdout, "%s: Timeout\n", sp->peername);
    return 0;
  case STAT_ERROR:
    snmp_perror(sp->peername);
    return 0;
  }
  return 0;
}

/*****************************************************************************/

/*
 * simple synchronous loop
 */
void synchronous (void)
{
#if 0
  struct host *hp;

  for (hp = hosts; hp->name; hp++) {
    struct snmp_session ss, *sp;
    struct oid *op;

    snmp_sess_init(&ss);			/* initialize session */
    ss.version = SNMP_VERSION_2c;
    ss.peername = strdup(hp->name);
    ss.community = strdup(hp->community);
    ss.community_len = strlen(ss.community);
    ss.timeout = 500000;
    if (!(sp = snmp_open(&ss))) {
      snmp_perror("snmp_open");
      continue;
    }
    for (op = oids; op->Name; op++) {
      struct snmp_pdu *req, *resp;
      int status;
      req = snmp_pdu_create(SNMP_MSG_GET);
      snmp_add_null_var(req, op->Oid, op->OidLen);
      status = snmp_synch_response(sp, req, &resp);
      if (!print_result(status, sp, resp)) break;
      snmp_free_pdu(resp);
    }
    snmp_close(sp);
   }
#else
    PDU_LIST_st *pdu_list = NULL;
    char *host = hosts[0].name;
    char *community = hosts[0].community;
    char *oid_name = oids[0].Name;
    
    if(iporting_net_snmp_walk(host, community, oid_name, &pdu_list) != 0)
    {
        printf("%s %d:snmpwalk error\n", __FUNCTION__, __LINE__);
        return ;
    }

    //snmp_print_pdulist(pdu_list, oid_name); 
    snmp_free_pdulist(pdu_list); 
    
    return ;
#endif
}

/*****************************************************************************/

/*
 * poll all hosts in parallel
 */
struct session {
  struct snmp_session *sess;		/* SNMP session data */
  struct oid *current_oid;		/* How far in our poll are we */
} sessions[sizeof(hosts)/sizeof(hosts[0])];

int active_hosts;			/* hosts that we have not completed */

/*
 * response handler
 */
int asynch_response(int operation, struct snmp_session *sp, int reqid,
		    struct snmp_pdu *pdu, void *magic)
{
  struct session *host = (struct session *)magic;
  struct snmp_pdu *req;

  printf("%s %d:operation = %d\n", __FUNCTION__, __LINE__, operation);
  if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
    if (print_result(STAT_SUCCESS, host->sess, pdu)) {
      host->current_oid++;			/* send next GET (if any) */
      if (host->current_oid->Name) {
	req = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(req, host->current_oid->Oid, host->current_oid->OidLen);
	if (snmp_send(host->sess, req))
	  return 1;
	else {
	  snmp_perror("snmp_send");
	  snmp_free_pdu(req);
	}
      }
    }
  }
  else
    print_result(STAT_TIMEOUT, host->sess, pdu);

  /* something went wrong (or end of variables) 
   * this host not active any more
   */
  active_hosts--;
  return 1;
}

void asynchronous(void)
{
  struct session *hs;
  struct host *hp;

  /* startup all hosts */

  for (hs = sessions, hp = hosts; hp->name; hs++, hp++) {
    struct snmp_pdu *req;
    struct snmp_session sess;
    snmp_sess_init(&sess);			/* initialize session */
    sess.version = SNMP_VERSION_2c;
    sess.peername = strdup(hp->name);
    sess.community = (u_char *)strdup(hp->community);
    sess.community_len = strlen((char *)sess.community);
    sess.callback = asynch_response;		/* default callback */
    sess.callback_magic = hs;
    //sess.timeout = 5000000;
    printf("%s %d:set success\n", __FUNCTION__, __LINE__);
    if (!(hs->sess = snmp_open(&sess))) {
      snmp_perror("snmp_open");
      continue;
    }
    hs->current_oid = oids;
    req = snmp_pdu_create(SNMP_MSG_GET);	/* send the first GET */
    snmp_add_null_var(req, hs->current_oid->Oid, hs->current_oid->OidLen);
    if (snmp_send(hs->sess, req))
      active_hosts++;
    else {
      snmp_perror("snmp_send");
      snmp_free_pdu(req);
    }
  }

  /* loop while any active hosts */

  printf("%s %d:active_hosts = %d\n", __FUNCTION__, __LINE__, active_hosts);
  while (active_hosts) {
    int fds = 0, block = 1;
    fd_set fdset;
    struct timeval timeout;

    FD_ZERO(&fdset);
    snmp_select_info(&fds, &fdset, &timeout, &block);
    fds = select(fds, &fdset, NULL, NULL, block ? NULL : &timeout);
    //printf("%s %d:fds = %p\n", __FUNCTION__, __LINE__, fds);
    if (fds < 0) {
        perror("select failed");
        exit(1);
    }
    if (fds)
    {
        snmp_read(&fdset);
    }
    else
    {
        snmp_timeout();
    }
  }

  /* cleanup */

  for (hp = hosts, hs = sessions; hp->name; hs++, hp++) {
    if (hs->sess) snmp_close(hs->sess);
  }
  printf("%s %d:asynchronous done\n", __FUNCTION__, __LINE__);
}

/*****************************************************************************/

int main (int argc, char **argv)
{
  initialize();
#ifndef ASYNCHRONOUS
  printf("---------- synchronous -----------\n");
  synchronous();
#endif

#ifdef ASYNCHRONOUS
  printf("---------- asynchronous -----------\n");
  asynchronous();
#endif
  return 0;
}
