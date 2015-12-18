
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
  iSTC(Inspur Safe Token Center) client routine definition

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
01a,19Jun2014,xiongdb@inspur.com           written
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>


#include "istc.h"
#include "istc_protocol.h"

#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include "istc_snmp_interface.h"
#include "istc_log.h"
#include "demoIpTable.h"
#include "demoIpTable_interface.h"
#include "clabWIFIAccessPointTable.h"
#include "clabWIFIAccessPointTable_interface.h"
#include "wifiBssTable.h"
#include "wifiBssTable_interface.h"
#include "clabWIFISSIDTable.h"
#include "clabWIFISSIDTable_interface.h"
#include "wifiBssWpaTable.h"
#include "wifiBssWpaTable_interface.h"


#define ISTC_TIMEOUT_DEFAULT	(6)

#define ISTC_ASYNC_CALLBACK_MAX (4)



typedef struct istc_async_desc_s {
    istc_async_callback_t callback[ISTC_ASYNC_CALLBACK_MAX];
    int sock;
    pthread_t tid;
    pthread_rwlock_t rwlock;
} istc_async_desc_t;


static unsigned int g_istc_seq = 1;
static unsigned int g_istcd_addr = 0;
static unsigned short g_istcd_port = ISTC_DEFAULT_PORT;


static istc_async_desc_t g_istc_async_desc = {
    .sock = -1,
    .tid = 0,
    .rwlock = PTHREAD_RWLOCK_INITIALIZER,
};


//#ifndef ISTC_USE_SNMP
#if 1
const char *istc_inet_ntoa(unsigned int ip, char *buff, int size)
{
    *buff = '\0';

    return (inet_ntop(AF_INET, &ip, buff, size));
}

const char *istc_inet_htoa(unsigned int host, char *buff, int size)
{
    unsigned int ip = htonl(host);

    *buff = '\0';

    return inet_ntop(AF_INET, &ip, buff, size);
}

int istc_inet_aton(const char *str, unsigned int *ip)
{
    if (inet_pton(AF_INET, str, ip) == 1) {
        return 0;
    } else {
        return -1;
    }
}

int istc_inet_atoh(const char *str, unsigned int *ip)
{
    unsigned int u4;
    if (inet_pton(AF_INET, str, &u4) == 1) {
        u4 = ntohl(u4);
        *ip = u4;
        return 0;
    } else {
        return -1;
    }
}



int istc_server_addr_set(unsigned int addr)
{
    g_istcd_addr = addr;

    return 0;
}

int istc_server_port_set(unsigned short port)
{
    g_istcd_port = port;

    return 0;
}


int istc_server_addr_get(unsigned int *addr)
{
    if (!addr) {
        DPRINT("addr is NULL\n");
        return -1;
    }

    *addr = g_istcd_addr;

    return 0;
}

static int istc_client_open()
{
    int sock;

    struct sockaddr_in addr;
    int on;

    if (g_istcd_addr == 0) {
        g_istcd_addr = INADDR_LOOPBACK;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        DERROR("socket create error!\n");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) != 0) {
        DERROR("setsockopt SO_REUSEADDR failed\n");
    }
#if 0
    struct linger lngr;
    memset(&lngr, 0, sizeof (struct linger));
    lngr.l_onoff = 1;
    lngr.l_linger = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_LINGER, &lngr, sizeof (struct linger))
        != 0) {
        DERROR("setsockopt SO_LINGER failed\n");
    }
#endif

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(g_istcd_addr);
    addr.sin_port = htons(g_istcd_port);

    if (connect(sock, (struct sockaddr *) &addr, sizeof (struct sockaddr_in)) ==
        -1) {
        DERROR("connect to server failed\n");
        close(sock);
        return -1;
    }

    //DPRINT("XXXX socket new    %d\n", sock);

    return sock;
}

static void istc_client_close(int sock)
{
    if (sock >= 0) {
        //DPRINT("XXXX socket close %d\n", sock);
        shutdown(sock, SHUT_RDWR);
        close(sock);
        usleep(2000);
    }
}

static int istc_socket_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        DERROR("fcntl F_GETFL fail\n");
        return -1;
    }
#if 0
    if (flags & O_NONBLOCK) {
        /* already non blocked */
        return 0;
    }
#endif
    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1) {
        DERROR("fcntl F_SETFL fail\n");
        return -1;
    }

    return 0;
}

static int istc_recv_timeout(int sock, void *buff, int size, int timeout)
{
    fd_set rdset;
    struct timeval time_val;
    int ret = -1;
    int offset = 0;
    int errno_local;

    if (timeout <= 0) {
        time_val.tv_sec = ISTC_TIMEOUT_DEFAULT;
        time_val.tv_usec = 0;
    } else {
        time_val.tv_sec = timeout;
        time_val.tv_usec = 0;
    }

    istc_socket_nonblock(sock);

    FD_ZERO(&rdset);
    FD_SET(sock, &rdset);

    if ((ret = select(sock + 1, &rdset, NULL, NULL, &time_val)) == -1) {
        DERROR("select error\n");
        return -1;
    }

    if (ret == 0) {
        DPRINT("recv timeout\n");
        return -1;
    }

    ret = -1;
    if (FD_ISSET(sock, &rdset)) {
        while (1) {
            if ((ret = recv(sock, buff + offset, size - offset, 0)) == -1) {
                errno_local = errno;
                if (errno_local == EAGAIN || errno_local == EWOULDBLOCK) {
                    /* no data any more in socket buffer */
                    return offset;
                }
                DERROR("recv error\n");
                return -1;
            }
            if (ret == 0) {
                /* server close the connection */
                return offset;
            }
            offset += ret;
            if (size == offset) {
                /* all data was received, return now */
                return offset;
            }
            /* wait a moument, and try to receive more data */
            usleep(100000);     /* 0.1s */
        }

    }

    return ret;
}


#define SURE_OPEN(sock) \
	if (((sock) = istc_client_open()) == -1) { DERROR("failed, return\n"); return -1; }

#define SURE_SENDN(sock, buff, size, ret) \
	do { \
		int __ret; \
		__ret = send((sock), (buff), (size), MSG_NOSIGNAL); \
		if (__ret == -1) { \
			DERROR("send error, return\n"); \
			istc_client_close((sock)); \
			return -1; \
		} \
		if (__ret != (size)) { \
			DPRINT("send trancated, expect %d, send %d\n", (size), __ret); \
			istc_client_close((sock)); \
			return -1; \
		} \
	} while (0)


#define SURE_RECVN(sock, buff, size, ret) \
	do { \
		int __ret; \
		__ret = istc_recv_timeout((sock), (buff), (size), 0); \
		if (__ret == -1) { \
			DPRINT("recv error, return\n"); \
			istc_client_close((sock)); \
			return -1; \
		} \
		if (__ret != (size)) { \
			DPRINT("recv trancated, expect %d, recv %d, return\n", (size), __ret); \
			istc_client_close((sock)); \
			return -1; \
		} \
		(ret) = __ret; \
	} while (0)

#define SURE_RECVN_TIMEOUT(sock, buff, size, timeout, ret) \
	do { \
		int __ret; \
		__ret = istc_recv_timeout((sock), (buff), (size), (timeout)); \
		if (__ret == -1) { \
			DPRINT("recv error, return\n"); \
			istc_client_close((sock)); \
			return -1; \
		} \
		if (__ret != (size)) { \
			DPRINT("recv trancated, expect %d, recv %d, return\n", (size), __ret); \
			istc_client_close((sock)); \
			return -1; \
		} \
		(ret) = __ret; \
	} while (0)        

#define SURE_RESP(s, h, c, m, x) \
	do { \
		if (h->seq != (x) || h->class != htons(c) || h->command != htons(m)) { \
			DPRINT("response not match, return\n"); \
			istc_client_close(s); \
			return -1; \
		} \
	} while (0)



#define FILL_HEAD(h, c, m, l, s) \
	do { \
		h->version = ISTC_PROTOCOL_VERSION; \
		h->type = ISTC_MSG_TYPE_REQUEST; \
		s = g_istc_seq++; \
		h->seq = htonl(s); \
		h->class = htons(c); \
		h->command = htons(m); \
		h->length = htons(l); \
	} while (0)
#else
#define SURE_OPEN(sock)
#define SURE_SENDN(sock, buff, size, ret)
#define SURE_RECVN(sock, buff, size, ret)
#define SURE_RECVN_TIMEOUT(sock, buff, size, timeout, ret)
#define SURE_RESP(s, h, c, m, x)
#define FILL_HEAD(h, c, m, l, s)
#endif

int istc_interface_ipaddr_get(const char *ifname, unsigned int *ipaddr)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ip_cmd_data_t *data = (istc_class_ip_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(ipaddr);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR,
              sizeof (istc_class_ip_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ip_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);

    head->rc = ntohl(head->rc);

    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_ip_cmd_data_t)) {

            SURE_RECVN(sock, data, length, ret);

            *ipaddr = ntohl(data->u.ipaddr);
            //DPRINT("recv ipaddr 0x%x\n", *ipaddr);
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_interface_netmask_get(const char *ifname, unsigned int *netmask)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ip_cmd_data_t *data = (istc_class_ip_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(netmask);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_NETMASK,
              sizeof (istc_class_ip_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ip_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);

    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_ip_cmd_data_t)) {

            SURE_RECVN(sock, data, length, ret);

            *netmask = ntohl(data->u.netmask);
            //DPRINT("recv netmask 0x%x\n", *netmask);
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}

int istc_interface_addr_mode_get(const char *ifname, int *mode)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ip_cmd_data_t *data = (istc_class_ip_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(mode);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_ADDR_MODE,
              sizeof (istc_class_ip_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ip_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_ip_cmd_data_t)) {

            SURE_RECVN(sock, data, length, ret);

            *mode = ntohl(data->u.addr_mode);
            //DPRINT("recv addr_mode 0x%x\n", *mode);
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}

int istc_interface_ipaddr_set(const char *ifname, unsigned int ipaddr)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ip_cmd_data_t *data = (istc_class_ip_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_SET_IPADDR,
              sizeof (istc_class_ip_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    data->u.ipaddr = htonl(ipaddr);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ip_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        ret = head->rc;
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
    }

    istc_client_close(sock);

    return ret;
}

int istc_interface_netmask_set(const char *ifname, unsigned int netmask)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ip_cmd_data_t *data = (istc_class_ip_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    unsigned int mask = (netmask);
    mask = ~mask + 1;
    if ((mask & (mask - 1)) != 0) {
        DPRINT("netmask 0x%x format error\n", netmask);
        return -1;
    }

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_SET_NETMASK,
              sizeof (istc_class_ip_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    data->u.netmask = htonl(netmask);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ip_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}

int istc_interface_addr_mode_set(const char *ifname, int mode)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ip_cmd_data_t *data = (istc_class_ip_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    if (mode <= ISTC_INTERFACE_ADDR_MODE_UNKNOWN
        || mode >= ISTC_INTERFACE_ADDR_MODE_MAX) {
        DPRINT("mode unknown %d\n", mode);
        return -1;
    }

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_SET_ADDR_MODE,
              sizeof (istc_class_mac_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    data->u.addr_mode = htonl(mode);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_mac_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_interface_mac_get(const char *ifname, unsigned char *mac)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_mac_cmd_data_t *data = (istc_class_mac_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(mac);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MAC, ISTC_CLASS_MAC_CMD_GET_MAC,
              sizeof (istc_class_mac_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_mac_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_mac_cmd_data_t)) {

            SURE_RECVN(sock, data, length, ret);

            memcpy(mac, data->u.mac, 6);

            /*DPRINT("recv mac %02x:%02x:%02x:%02x:%02x:%02x\n", 
             * mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); */
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}

int istc_interface_mac_set(const char *ifname, const unsigned char *mac)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_mac_cmd_data_t *data = (istc_class_mac_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(mac);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MAC, ISTC_CLASS_MAC_CMD_SET_MAC,
              sizeof (istc_class_mac_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    memcpy(data->u.mac, mac, 6);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_mac_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}







int istc_link_state_get(const char *ifname, int *state)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_link_cmd_data_t *data =
        (istc_class_link_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(state);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_LINK, ISTC_CLASS_LINK_CMD_GET_LINK_STATE,
              sizeof (istc_class_link_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_link_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_link_cmd_data_t)) {

            SURE_RECVN(sock, data, length, ret);

            *state = ntohl(data->data);

            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_link_admin_state_get(const char *ifname, int *state)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_link_cmd_data_t *data =
        (istc_class_link_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(state);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_LINK, ISTC_CLASS_LINK_CMD_GET_ADMIN_STATE,
              sizeof (istc_class_link_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_link_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_link_cmd_data_t)) {

            SURE_RECVN(sock, data, length, ret);

            *state = ntohl(data->data);

            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_link_mtu_get(const char *ifname, int *state)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_link_cmd_data_t *data =
        (istc_class_link_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(state);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_LINK, ISTC_CLASS_LINK_CMD_GET_LINK_MTU,
              sizeof (istc_class_link_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_link_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_link_cmd_data_t)) {

            SURE_RECVN(sock, data, length, ret);

            *state = ntohl(data->data);

            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_link_admin_state_set(const char *ifname, int state)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_link_cmd_data_t *data =
        (istc_class_link_cmd_data_t *) (head + 1);

    SURE_STR(ifname);

    if (state < ISTC_LINK_ADMIN_STATE_DOWN || state >= ISTC_LINK_STATE_MAX) {
        DPRINT("admin state %d not support\n", state);
        return -1;
    }

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_LINK, ISTC_CLASS_LINK_CMD_SET_ADMIN_STATE,
              sizeof (istc_class_link_cmd_data_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    data->data = htonl(state);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_link_cmd_data_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_wireless_mode_get(const char *ifname, int *mode)
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_misc_cmd_wireless_mode_get_t *data = (istc_class_misc_cmd_wireless_mode_get_t *) (head + 1);
    printf("istc_wireless_mode_get %s \n", ifname);

    SURE_STR(ifname);

    SURE_PTR(mode);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_WIRELESS_MODE_GET,
              sizeof (istc_class_misc_cmd_wireless_mode_get_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_misc_cmd_wireless_mode_get_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    head->rc = ntohl(head->rc);

    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_misc_cmd_wireless_mode_get_t)) {

            SURE_RECVN(sock, data, length, ret);

            *mode = ntohl(data->mode);
            //DPRINT("recv ipaddr 0x%x\n", *ipaddr);
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);
    
    return ret;
}

int istc_wireless_sta_ssid_scan(const char *ifname)
{
    int sock;
    int ret;
    int seq;

    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_scan_t *data = (istc_class_sta_scan_t *) (head + 1);

    SURE_STR(ifname);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_SCAN,
              sizeof (istc_class_sta_scan_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_scan_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_async_wireless_sta_ssid_scan(const char *ifname)
{
    int sock;
    int ret;
    int seq;

    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_scan_t *data = (istc_class_sta_scan_t *) (head + 1);

    SURE_STR(ifname);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_SCAN_ASYNC,
              sizeof (istc_class_sta_scan_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_scan_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}

int istc_wireless_sta_scan_result_get(const char *ifname,
                                      istc_sta_ssid_t * result, int *pcnt)
{
    int sock = -1;
    int ret = -1;
    int seq;
    int length;
    int cnt = 0;
    int cnt_ret = 0;
    char buff[2048] = { 0 };    /* Warrning: can not alloc stack buffer large than 4096 !!! */
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_get_ssid_t *data = (istc_class_sta_get_ssid_t *) (head + 1);


    SURE_STR(ifname);

    SURE_PTR(result);

    SURE_PTR(pcnt);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_GET_SCAN_RESULT,
              sizeof (istc_class_sta_get_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_get_ssid_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        if (length > 0) {
            int timeout = 4;
            data = (istc_class_sta_get_ssid_t *) buff;

            ret = istc_recv_timeout(sock, buff, sizeof (buff), timeout);
            istc_client_close(sock);    /* close the socket first */
            sock = -1;
            if (ret < 0) {
                DPRINT("recv error\n");
                return -1;
            } else if (ret == 0) {
                DPRINT("server closed the connection\n");
                *pcnt = 0;
                return 0;
            }

            /* calculate the returned bytes and count */
            cnt =
                (ret -
                 sizeof (istc_class_sta_get_ssid_t)) / sizeof (istc_sta_ssid_t);
            cnt_ret = ntohl(data->cnt);
            //DPRINT("real recved %d, expect %d\n", cnt, cnt_ret);      
            if (cnt_ret != cnt) {
                DPRINT("Warning, recv trancated!\n");
            }

            if (*pcnt < cnt) {
                cnt = *pcnt;
            }
            /* copy to result */
            int i;
            istc_sta_ssid_t *ptr =
                (istc_sta_ssid_t *) (buff + sizeof (istc_class_sta_get_ssid_t));
            for (i = 0; i < cnt; i++, result++, ptr++) {
                strncpy(result->ssid, ptr->ssid, ISTC_SSID_NAME_SIZE);
                strncpy(result->mac, ptr->mac, sizeof (ptr->mac));
                result->channel = ntohl(ptr->channel);
                result->signal = ntohl(ptr->signal);
                result->encryption = ntohl(ptr->encryption);
            }
        } else {
            DPRINT("server say no error, but none ssid scaned\n");
            istc_client_close(sock);
            sock = -1;
        }

        ret = 0;
        *pcnt = cnt;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
        istc_client_close(sock);  /* be sure close the socket */
        sock = -1;
    }

    if (sock >= 0) {
        istc_client_close(sock);  /* just for error check */
    }

    return ret;
}

int istc_wireless_sta_state_get(const char *ifname, int *state,
                                istc_sta_ssid_t * ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_state_t *data = (istc_class_sta_state_t *) (head + 1);

    SURE_STR(ifname);

    SURE_PTR(ssid);

    memset(ssid, 0, sizeof (istc_sta_ssid_t));

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_GET_STATE,
              sizeof (istc_class_sta_state_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_state_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data, sizeof (istc_class_sta_state_t), ret);
        *state = ntohl(data->state);
        memcpy(ssid, &data->ssid, sizeof (istc_sta_ssid_t));
        ssid->channel = ntohl(ssid->channel);
        ssid->signal = ntohl(ssid->signal);
        ssid->encryption = ntohl(ssid->encryption);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);


    return ret;
}

int istc_wireless_sta_ssid_add(const char *ifname, const char *ssid,
                               const char *password)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_add_ssid_t *data = (istc_class_sta_add_ssid_t *) (head + 1);

    SURE_STR(ifname);

    SURE_STR(ssid);

    if (password) {
        int password_len = strlen(password);
        if (password_len < 8) {
            DPRINT("password length should no less than 8 characters!\n");
            return -1;
        }
    } else {
        DPRINT("note: no password is used!\n");
    }

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_ADD_SSID,
              sizeof (istc_class_sta_add_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);
    if (password) {
        strncpy(data->pswd, password, ISTC_SSID_PSWD_SIZE);
    } else {
        data->pswd[0] = '\0';
    }

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_add_ssid_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}

int istc_wireless_sta_ssid_add2(const char *ifname, const char *ssid,
                                const char *password, int encryption)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_add2_ssid_t *data =
        (istc_class_sta_add2_ssid_t *) (head + 1);

    SURE_STR(ifname);

    SURE_STR(ssid);

    if (encryption == ISTC_WIRELESS_ENCRYPTION_WPA2 ||
        encryption == ISTC_WIRELESS_ENCRYPTION_WPA ||
        encryption == ISTC_WIRELESS_ENCRYPTION_WPA_WPA2) {
        if (!password || !*password) {
            DPRINT("password is null!\n");
            return -1;
        }
        if (strlen(password) < 8) {
            DPRINT("password length should no less than 8 characters!\n");
            return -1;
        }
    } else if (encryption == ISTC_WIRELESS_ENCRYPTION_WEP) {
		if (!password || !*password) {
            DPRINT("password is null!\n");
            return -1;
        }
    } else if (encryption != ISTC_WIRELESS_ENCRYPTION_OPEN) {
        DPRINT("encryption type %d not supported\n", encryption);
        return -1;
    }

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_ADD2_SSID,
              sizeof (istc_class_sta_add2_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);
    if (password) {
        strncpy(data->pswd, password, ISTC_SSID_PSWD_SIZE);
    } else {
        data->pswd[0] = '\0';
    }
    data->encryption = htonl(encryption);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_add2_ssid_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_wireless_sta_ssid_remove(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_del_ssid_t *data = (istc_class_sta_del_ssid_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_REMOVE_SSID,
              sizeof (istc_class_sta_del_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_del_ssid_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}

int istc_wireless_sta_ssid_enable(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_enable_ssid_t *data =
        (istc_class_sta_enable_ssid_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_ENABLE_SSID,
              sizeof (istc_class_sta_enable_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_enable_ssid_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}

int istc_wireless_sta_ssid_disable(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_disable_ssid_t *data =
        (istc_class_sta_disable_ssid_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_DISABLE_SSID,
              sizeof (istc_class_sta_disable_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_disable_ssid_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}

int istc_async_wireless_sta_ssid_enable(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_enable_ssid_t *data =
        (istc_class_sta_enable_ssid_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_ENABLE_SSID_ASYNC,
              sizeof (istc_class_sta_enable_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_enable_ssid_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}

int istc_async_wireless_sta_ssid_disable(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_sta_disable_ssid_t *data =
        (istc_class_sta_disable_ssid_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_STA_CMD_DISABLE_SSID_ASYNC,
              sizeof (istc_class_sta_disable_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_sta_disable_ssid_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}


/* ---------------------------- AP CLASS  -------------------------------- */

int istc_wireless_ap_ssid_get(const char *ifname, istc_ap_ssid_t * ssid,
                              int *count)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    clabWIFISSIDTable_rowreq_ctx *ssid_ctx = NULL;
    wifiBssTable_rowreq_ctx *bss_ctx = NULL;
    wifiBssWpaTable_rowreq_ctx *bsswpa_ctx = NULL;
    int row = 0;
    istc_ap_ssid_t ap_ssid;
    int cnt = 0;
    
    oid clabWIFISSIDIfName[] = {CLABWIFISSIDTABLE_OID, COLUMN_CLABWIFISSIDID, COLUMN_CLABWIFISSIDNAME};
    size_t clabWIFISSIDIfName_len = OID_LENGTH(clabWIFISSIDIfName);
    
    oid wifiBssSsid[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSSSID, 0};
    size_t wifiBssSsid_len = OID_LENGTH(wifiBssSsid);
    oid wifiBssSecurityMode[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSSECURITYMODE, 0};
    size_t wifiBssSecurityMode_len = OID_LENGTH(wifiBssSecurityMode);
    
    oid wifiBssWpaPreSharedKey[] = {WIFIBSSWPATABLE_OID, COLUMN_WIFIBSSWPAALGORITHM, COLUMN_WIFIBSSWPAPRESHAREDKEY, 0};
    size_t wifiBssWpaPreSharedKey_len = OID_LENGTH(wifiBssWpaPreSharedKey);
    
    SNMP_ASSERT(ifname != NULL && *ifname != 0 && ssid != NULL);
    
    istc_log("ifname = %s\n", ifname);
    memset(&ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid.ifname, ifname, sizeof(ap_ssid.ifname) - 1);
    
    if(istc_snmp_table_parse_data(clabWIFISSIDIfName, clabWIFISSIDIfName_len, (SnmpTableFun)_clabWIFISSIDTable_set_column, sizeof(clabWIFISSIDTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFISSIDIfName\n");
        return -1;
    }
    istc_log("parse clabWIFISSIDIfName success\n");
    data_list= data_head; 
    while(data_list != NULL)
    {
        ssid_ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);
        if(strcmp(ifname, ssid_ctx->data.clabWIFISSIDName) == 0)
        {
            row = data_list->row;
            istc_log("find success, ifname = %s\n", ifname);
            break;
        }
        data_list = data_list->next;
    }
    istc_snmp_free_datalist(data_head);
    data_head = NULL;
    if(data_list == NULL)
    {
        istc_log("can not get bssid, ifname = %s\n", ifname);
        return -1;
    }

    wifiBssSsid[wifiBssSsid_len - 1] = row;
    wifiBssSecurityMode[wifiBssSecurityMode_len - 1] = row;
    wifiBssWpaPreSharedKey[wifiBssWpaPreSharedKey_len - 1] = row;
    
    if(istc_snmp_table_parse_data(wifiBssSsid, wifiBssSsid_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSsid\n");
        return -1;
    }
    istc_log("parse wifiBssSsid success\n");
    bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
    strncpy(ap_ssid.ssid, bss_ctx->data.wifiBssSsid, sizeof(ap_ssid.ssid) - 1);
    istc_snmp_free_datalist(data_head);
    data_head = NULL;

    if(istc_snmp_table_parse_data(wifiBssSecurityMode, wifiBssSecurityMode_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssSecurityMode\n");
        return -1;
    }
    istc_log("parse wifiBssSecurityMode success\n");
    bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
    switch(bss_ctx->data.wifiBssSecurityMode)
    {
    case 0:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_OPEN;
        break;
    case 1:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WEP;
        break;
    case 2:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA;
        break;
    case 3:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA2;
        break;
    case 7:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA_WPA2;
        break;
    default:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_NONE;
        break;
    }
    istc_snmp_free_datalist(data_head);
    data_head = NULL;
    if(ap_ssid.encryption == ISTC_WIRELESS_ENCRYPTION_OPEN ||
        ap_ssid.encryption == ISTC_WIRELESS_ENCRYPTION_NONE)
    {
        memcpy((void *)ssid, (const void *)&ap_ssid, sizeof(ap_ssid));
        *count = 1;
        istc_log("encryption is not open or unknown, we will return\n");
        return 0;
    }
    
    if(istc_snmp_table_parse_data(wifiBssWpaPreSharedKey, wifiBssWpaPreSharedKey_len, (SnmpTableFun)_wifiBssWpaTable_set_column, sizeof(wifiBssWpaTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssWpaTable_rowreq_ctx\n");
        return -1;
    }
    istc_log("parse wifiBssWpaTable_rowreq_ctx success\n");
    bsswpa_ctx = (wifiBssWpaTable_rowreq_ctx *)(data_head->data);
    strncpy(ap_ssid.password, bsswpa_ctx->data.wifiBssWpaPreSharedKey, sizeof(ap_ssid.password) - 1);
    istc_snmp_free_datalist(data_head);
    data_head = NULL;

    memcpy((void *)ssid, (const void *)&ap_ssid, sizeof(ap_ssid));
    *count = 1;
    return 0;
}


int istc_wireless_ap_ssid_sta_get(const char *ifname, const char *ssid,
                                  istc_ap_sta_t * sta, int *count)
{
    int sock;
    int ret;
    int seq;
    char buff[2048] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_get_sta_t *data = (istc_class_ap_get_sta_t *) (head + 1);
    int length = 0;
    int cnt_ret = 0;
    int cnt = 0;

    SURE_STR(ifname);
    //SURE_STR(ssid);
    SURE_PTR(sta);
    SURE_PTR(count);


    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_GET_SSID_STA,
              sizeof (istc_class_ap_get_sta_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    //strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ap_get_sta_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
        length = ntohs(head->length);
        if (length > 0) {
            /* recv cnt */
            SURE_RECVN(sock, data, sizeof (istc_class_ap_get_sta_t), ret);
            cnt_ret = ntohl(data->cnt);
            //DPRINT("recv cnt = %d, pcnt = %d\n", cnt_ret, *pcnt);
            cnt = cnt_ret;
            if (cnt > 0) {
                int total = cnt * sizeof (istc_ap_sta_t);
                memset(buff, 0, sizeof (buff));
                SURE_RECVN(sock, buff, total, ret);
                if (*count < cnt) {
                    cnt = *count;
                }
                /* copy to result */
                int i;
                istc_ap_sta_t *ptr = (istc_ap_sta_t *) buff;
                for (i = 0; i < cnt; i++, sta++, ptr++) {
                    strncpy(sta->sta_name, ptr->sta_name, ISTC_HOST_NAME_SIZE);
                    sta->sta_ip = ntohl(ptr->sta_ip);
                    memcpy(sta->sta_mac, ptr->sta_mac, 6);
                }
            }

        }

        ret = 0;
        *count = cnt;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}

int istc_wireless_ap_ssid_add(const char *ifname, const istc_ap_ssid_t * ssid)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    clabWIFISSIDTable_rowreq_ctx *ssid_ctx = NULL;
    int row = 0;
    istc_ap_ssid_t ap_ssid;
    int cnt = 0;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = -1;
    char *security_mode = NULL;
    
    oid clabWIFISSIDIfName[] = {CLABWIFISSIDTABLE_OID, COLUMN_CLABWIFISSIDID, COLUMN_CLABWIFISSIDNAME};
    size_t clabWIFISSIDIfName_len = OID_LENGTH(clabWIFISSIDIfName);

    oid wifiBssEnable[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSENABLE, 0};
    size_t wifiBssEnable_len = OID_LENGTH(wifiBssEnable);
    oid wifiBssSsid[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSSSID, 0};
    size_t wifiBssSsid_len = OID_LENGTH(wifiBssSsid);
    oid wifiBssSecurityMode[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSSECURITYMODE, 0};
    size_t wifiBssSecurityMode_len = OID_LENGTH(wifiBssSecurityMode);
    oid wifiBssWpaPreSharedKey[] = {WIFIBSSWPATABLE_OID, COLUMN_WIFIBSSWPAALGORITHM, COLUMN_WIFIBSSWPAPRESHAREDKEY, 0};
    size_t wifiBssWpaPreSharedKey_len = OID_LENGTH(wifiBssWpaPreSharedKey);
    
    SNMP_ASSERT(ifname != NULL && *ifname != 0 && ssid != NULL);
    SNMP_ASSERT(ssid->ssid[0] != 0);

    istc_log("ifname = %s\n", ifname);
    memset(&ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid.ifname, ifname, sizeof(ap_ssid.ifname) - 1);
    
    if(istc_snmp_table_parse_data(clabWIFISSIDIfName, clabWIFISSIDIfName_len, (SnmpTableFun)_clabWIFISSIDTable_set_column, sizeof(clabWIFISSIDTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFISSIDTable_rowreq_ctx\n");
        return -1;
    }
    istc_log("parse clabWIFISSIDTable_rowreq_ctx success\n");
    data_list= data_head; 
    while(data_list != NULL)
    {
        ssid_ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);
        if(strcmp(ifname, ssid_ctx->data.clabWIFISSIDName) == 0)
        {
            row = data_list->row;
            istc_log("find success, ifname = %s, row = %d\n", ifname, row);
            break;
        }
        data_list = data_list->next;
    }
    istc_snmp_free_datalist(data_head);
    data_head = NULL;
    if(data_list == NULL)
    {
        istc_log("can not get bssid, ifname = %s\n", ifname);
        return -1;
    }

    istc_log("ssid->encryption= %d\n", ssid->encryption);
    switch(ssid->encryption)
    {
        case ISTC_WIRELESS_ENCRYPTION_OPEN:
            security_mode = "0";
            break;
        case ISTC_WIRELESS_ENCRYPTION_WEP:
            security_mode = "1";
            break;
        case ISTC_WIRELESS_ENCRYPTION_WPA:
            security_mode = "2";
            break;
        case ISTC_WIRELESS_ENCRYPTION_WPA2:
            security_mode = "3";
            break;
        case ISTC_WIRELESS_ENCRYPTION_WPA_WPA2:
            security_mode = "7";
            break;
        default:
            istc_log("unkonwn security mode:%d\n", ssid->encryption);
            return -1;
    }

    wifiBssEnable[wifiBssEnable_len - 1] = row;
    wifiBssSsid[wifiBssSsid_len - 1] = row;
    wifiBssWpaPreSharedKey[wifiBssWpaPreSharedKey_len - 1] = row;
    wifiBssSecurityMode[wifiBssSecurityMode_len - 1] = row;
    
    if(istc_snmp_set(wifiBssSsid, wifiBssSsid_len, 's', (char *)ssid->ssid, &stat) != 0)
    {
        istc_log("can not set ssid name, ifname = %s\n", ifname);
        return -1;
    }
    istc_log("set wifiBssSsid success\n");
    if(istc_snmp_set(wifiBssSecurityMode, wifiBssSecurityMode_len, 'i', (char *)security_mode, &stat) != 0)
    {
        istc_log("can not set ssid security mode, ifname = %s\n", ifname);
        return -1;
    }
    istc_log("set wifiBssSecurityMode success\n");
    if(*security_mode != '0')
    {
        if(ssid->password[0] == 0 || strlen(ssid->password) < 8)
        {
            istc_log("password wrong\n");
            return -1;
        }
        if(istc_snmp_set(wifiBssWpaPreSharedKey, wifiBssWpaPreSharedKey_len, 's', (char *)ssid->password, &stat) != 0)
        {
            istc_log("can not set password\n");
            return -1;
        }
        istc_log("set wifiBssWpaPreSharedKey success\n");
    }

    if(istc_snmp_set(wifiBssEnable, wifiBssEnable_len, 'i', "1", &stat) != 0)
    {
        istc_log("can not set bss enable, ifname = %s, ssid_name = %s\n", ifname, ssid->ssid);
        return -1;
    }
    istc_log("set wifiBssEnable success\n");
    
    istc_log("ssid add success\n");
    return 0;
}



int istc_wireless_ap_ssid_remove(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_remove_ssid_t *data =
        (istc_class_ap_remove_ssid_t *) (head + 1);


    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_REMOVE_SSID,
              sizeof (istc_class_ap_remove_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ap_remove_ssid_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}

int istc_wireless_ap_ssid_enable(const char *ifname, const char *ssid)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    clabWIFISSIDTable_rowreq_ctx *ssid_ctx = NULL;
    wifiBssTable_rowreq_ctx *bss_ctx = NULL;
    int row = 0;
    istc_ap_ssid_t ap_ssid;
    int cnt = 0;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = -1;
    
    oid clabWIFISSIDIfName[] = {CLABWIFISSIDTABLE_OID, COLUMN_CLABWIFISSIDID, COLUMN_CLABWIFISSIDNAME};
    size_t clabWIFISSIDIfName_len = OID_LENGTH(clabWIFISSIDIfName);

    oid wifiBssSsid[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSSSID, 0};
    size_t wifiBssSsid_len = OID_LENGTH(wifiBssSsid);
    oid wifiBssEnable[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSENABLE, 0};
    size_t wifiBssEnable_len = OID_LENGTH(wifiBssEnable);
    
    SNMP_ASSERT(ifname != NULL && *ifname != 0 && ssid != NULL && *ssid != 0);

    istc_log("ifname = %s\n", ifname);
    memset(&ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid.ifname, ifname, sizeof(ap_ssid.ifname) - 1);
    
    if(istc_snmp_table_parse_data(clabWIFISSIDIfName, clabWIFISSIDIfName_len, (SnmpTableFun)_clabWIFISSIDTable_set_column, sizeof(clabWIFISSIDTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFISSIDTable_rowreq_ctx\n");
        return -1;
    }
    istc_log("parse clabWIFISSIDTable_rowreq_ctx success\n");
    data_list= data_head; 
    while(data_list != NULL)
    {
        ssid_ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);
        if(strcmp(ifname, ssid_ctx->data.clabWIFISSIDName) == 0)
        {
            row = data_list->row;
            istc_log("find success, ifname = %s\n", ifname);
            break;
        }
        data_list = data_list->next;
    }
    istc_snmp_free_datalist(data_head);
    data_head = NULL;
    if(data_list == NULL)
    {
        istc_log("can not get bssid, ifname = %s\n", ifname);
        return -1;
    }

    wifiBssSsid[wifiBssSsid_len - 1] = row;
    wifiBssEnable[wifiBssEnable_len - 1] = row;

    if(istc_snmp_table_parse_data(wifiBssSsid, wifiBssSsid_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssTable_rowreq_ctx\n");
        return -1;
    }
    istc_log("parse wifiBssTable_rowreq_ctx success\n");
    bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
    if(strcmp(ssid, bss_ctx->data.wifiBssSsid) != 0)
    {
        istc_log("ifname:%s, ssid_name:%s, not match\n", ifname, ssid);
        istc_snmp_free_datalist(data_head);
        return -1;
    }
    istc_snmp_free_datalist(data_head);
    
    if(istc_snmp_set(wifiBssEnable, wifiBssEnable_len, 'i', "1", &stat) != 0)
    {
        istc_log("can not set bss enable, ifname = %s, ssid = %s\n", ifname, ssid);
        return -1;
    }

    istc_log("ifname:%s, ssid:%s, enable success\n", ifname, ssid);
    return 0;
}

int istc_wireless_ap_ssid_disable(const char *ifname, const char *ssid)
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    clabWIFISSIDTable_rowreq_ctx *ssid_ctx = NULL;
    wifiBssTable_rowreq_ctx *bss_ctx = NULL;
    int row = 0;
    istc_ap_ssid_t ap_ssid;
    int cnt = 0;
    ISTC_SNMP_RESPONSE_ERRSTAT stat = -1;
    
    oid clabWIFISSIDIfName[] = {CLABWIFISSIDTABLE_OID, COLUMN_CLABWIFISSIDID, COLUMN_CLABWIFISSIDNAME};
    size_t clabWIFISSIDIfName_len = OID_LENGTH(clabWIFISSIDIfName);

    oid wifiBssSsid[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSSSID, 0};
    size_t wifiBssSsid_len = OID_LENGTH(wifiBssSsid);
    oid wifiBssEnable[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSENABLE, 0};
    size_t wifiBssEnable_len = OID_LENGTH(wifiBssEnable);
    
    SNMP_ASSERT(ifname != NULL && *ifname != 0 && ssid != NULL && *ssid != 0);

    istc_log("ifname = %s\n", ifname);
    memset(&ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid.ifname, ifname, sizeof(ap_ssid.ifname) - 1);
    
    if(istc_snmp_table_parse_data(clabWIFISSIDIfName, clabWIFISSIDIfName_len, (SnmpTableFun)_clabWIFISSIDTable_set_column, sizeof(clabWIFISSIDTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse clabWIFISSIDTable_rowreq_ctx\n");
        return -1;
    }
    istc_log("parse clabWIFISSIDTable_rowreq_ctx success\n");
    data_list= data_head; 
    while(data_list != NULL)
    {
        ssid_ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);
        if(strcmp(ifname, ssid_ctx->data.clabWIFISSIDName) == 0)
        {
            row = data_list->row;
            istc_log("find success, ifname = %s\n", ifname);
            break;
        }
        data_list = data_list->next;
    }
    istc_snmp_free_datalist(data_head);
    data_head = NULL;
    if(data_list == NULL)
    {
        istc_log("can not get bssid, ifname = %s\n", ifname);
        return -1;
    }

    wifiBssSsid[wifiBssSsid_len - 1] = row;
    wifiBssEnable[wifiBssEnable_len - 1] = row;

    if(istc_snmp_table_parse_data(wifiBssSsid, wifiBssSsid_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &cnt) != 0)
    {
        istc_log("can not parse wifiBssTable_rowreq_ctx\n");
        return -1;
    }
    istc_log("parse wifiBssTable_rowreq_ctx success\n");
    bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
    if(strcmp(ssid, bss_ctx->data.wifiBssSsid) != 0)
    {
        istc_log("ifname:%s, ssid_name:%s, not match\n", ifname, ssid);
        istc_snmp_free_datalist(data_head);
        return -1;
    }
    istc_snmp_free_datalist(data_head);
    
    if(istc_snmp_set(wifiBssEnable, wifiBssEnable_len, 'i', "2", &stat) != 0)
    {
        istc_log("can not set bss enable, ifname = %s, ssid = %s\n", ifname, ssid);
        return -1;
    }

    istc_log("ifname:%s, ssid:%s, enable success\n", ifname, ssid);
    return 0;
}


static int istc_wireless_ap_ssid_mac_get(const char *ifname, const char *ssid,
                                         unsigned char list[][6], int *count,
                                         int mode)
{
    int sock;
    int ret;
    int seq;
    char buff[1024] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_get_mac_t *data = (istc_class_ap_get_mac_t *) (head + 1);
    unsigned short length;
    int cnt_ret = 0;
    int cnt = 0;

    SURE_STR(ifname);
    SURE_STR(ssid);
    SURE_PTR(list);
    SURE_PTR(count);

    if (mode == ISTC_ACL_MAC_MODE_ACCEPT) {
        FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_GET_MAC_ACCEPT,
                  sizeof (istc_class_ap_get_mac_t), seq);
    } else if (mode == ISTC_ACL_MAC_MODE_DENY) {
        FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_GET_MAC_DENY,
                  sizeof (istc_class_ap_get_mac_t), seq);
    } else {
        return -1;
    }

    SURE_OPEN(sock);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ap_get_mac_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
        length = ntohs(head->length);
        if (length > 0) {
            /* recv cnt */
            SURE_RECVN(sock, data, sizeof (istc_class_ap_get_mac_t), ret);
            cnt_ret = ntohl(data->cnt);
            //DPRINT("recv cnt = %d, pcnt = %d\n", cnt_ret, *count);
            cnt = cnt_ret;
            if (cnt > 0) {
                int total = cnt * 6;
                memset(buff, 0, sizeof (buff));
                SURE_RECVN(sock, buff, total, ret);
                if (*count < cnt) {
                    cnt = *count;
                }
                /* copy to result */
                int i;
                int j;
                unsigned char *ptr = (unsigned char *) buff;
                for (i = 0, j = 0; i < cnt; i++, j++, ptr += 6) {
                    memcpy(list[j], ptr, 6);
                }
            }

        }

        ret = 0;
        *count = cnt;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}


int istc_wireless_ap_ssid_mac_accept_get(const char *ifname, const char *ssid,
                                         unsigned char list[][6], int *count)
{
    return istc_wireless_ap_ssid_mac_get(ifname, ssid, list, count,
                                         ISTC_ACL_MAC_MODE_ACCEPT);
}


int istc_wireless_ap_ssid_mac_deny_get(const char *ifname, const char *ssid,
                                       unsigned char list[][6], int *count)
{
    return istc_wireless_ap_ssid_mac_get(ifname, ssid, list, count,
                                         ISTC_ACL_MAC_MODE_DENY);
}



static int istc_wireless_ap_ssid_mac_op(const char *ifname, const char *ssid,
                                        unsigned char *mac, unsigned short op)
{
    int sock;
    int ret;
    int seq;
    char buff[1024] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_mac_t *data = (istc_class_ap_mac_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);
    SURE_PTR(mac);

    FILL_HEAD(head, ISTC_CLASS_AP, op, sizeof (istc_class_ap_mac_t), seq);

    SURE_OPEN(sock);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);
    memcpy(data->mac, mac, 6);

    SURE_SENDN(sock, buff, sizeof (istc_head_t) + sizeof (istc_class_ap_mac_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}


int istc_wireless_ap_ssid_mac_accept_add(const char *ifname, const char *ssid,
                                         unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_ADD_MAC_ACCEPT);
}

int istc_wireless_ap_ssid_mac_accept_remove(const char *ifname,
                                            const char *ssid,
                                            unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_REMOVE_MAC_ACCEPT);
}

int istc_wireless_ap_ssid_mac_deny_add(const char *ifname, const char *ssid,
                                       unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_ADD_MAC_DENY);
}

int istc_wireless_ap_ssid_mac_deny_remove(const char *ifname, const char *ssid,
                                          unsigned char *mac)
{
    return istc_wireless_ap_ssid_mac_op(ifname, ssid, mac,
                                        ISTC_CLASS_AP_CMD_REMOVE_MAC_DENY);
}


int istc_wireless_ap_ssid_mac_acl_get(const char *ifname, const char *ssid,
                                      int *mode)
{
    int sock;
    int ret;
    int seq;
    char buff[1024] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_mac_acl_t *data = (istc_class_ap_mac_acl_t *) (head + 1);
    unsigned short length;

    SURE_STR(ifname);
    SURE_STR(ssid);
    SURE_PTR(mode);

    FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_GET_MAC_ACL,
              sizeof (istc_class_ap_mac_acl_t), seq);

    SURE_OPEN(sock);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ap_mac_acl_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
        length = ntohs(head->length);
        if (length > 0) {
            /* recv cnt */
            SURE_RECVN(sock, data, sizeof (istc_class_ap_mac_acl_t), ret);
            *mode = ntohl(data->mode);
            ret = 0;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}


int istc_wireless_ap_ssid_mac_acl_set(const char *ifname, const char *ssid,
                                      int mode)
{
    int sock;
    int ret;
    int seq;
    char buff[1024] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_mac_acl_t *data = (istc_class_ap_mac_acl_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    if (mode < ISTC_ACL_MAC_MODE_DISABLE || mode >= ISTC_ACL_MAC_MODE_MAX) {
        DPRINT("mode is invalid\n");
        return -1;
    }


    FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_SET_MAC_ACL,
              sizeof (istc_class_ap_mac_acl_t), seq);

    SURE_OPEN(sock);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);
    data->mode = htonl(mode);

    SURE_SENDN(sock, buff, sizeof (istc_head_t) + sizeof (istc_class_ap_mac_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}



int istc_async_wireless_ap_ssid_enable(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_enable_ssid_t *data =
        (istc_class_ap_enable_ssid_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_AP_CMD_ENABLE_SSID_ASYNC,
              sizeof (istc_class_ap_enable_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ap_enable_ssid_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}

int istc_async_wireless_ap_ssid_disable(const char *ifname, const char *ssid)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_disable_ssid_t *data =
        (istc_class_ap_disable_ssid_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(ssid);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_STA, ISTC_CLASS_AP_CMD_DISABLE_SSID_ASYNC,
              sizeof (istc_class_ap_disable_ssid_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid, ssid, ISTC_SSID_NAME_SIZE);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_ap_disable_ssid_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}





int istc_dhcp_pool_get(istc_dhcp_pool_t * pool, int *count)
{
    int sock;
    int ret;
    int seq;
    char buff[2048] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_get_pool_t *data =
        (istc_class_dhcp_get_pool_t *) (head + 1);
    int length = 0;
    int cnt_ret = 0;
    int cnt = 0;

    SURE_PTR(pool);

    SURE_PTR(count);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPS_CMD_GET_POOL,
              sizeof (istc_class_dhcp_get_pool_t), seq);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_get_pool_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
        length = ntohs(head->length);
        if (length > 0) {
            /* recv cnt */
            SURE_RECVN(sock, data, sizeof (istc_class_dhcp_get_pool_t), ret);
            cnt_ret = ntohl(data->cnt);
            //DPRINT("recv cnt = %d, pcnt = %d\n", cnt_ret, *pcnt);
            cnt = cnt_ret;
            if (cnt > 0) {
                int total = cnt * sizeof (istc_dhcp_pool_t);
                memset(buff, 0, sizeof (buff));
                SURE_RECVN(sock, buff, total, ret);
                if (*count < cnt) {
                    cnt = *count;
                }
                /* copy to result */
                int i;
                istc_dhcp_pool_t *ptr = (istc_dhcp_pool_t *) buff;
                for (i = 0; i < cnt; i++, pool++, ptr++) {
                    strncpy(pool->name, ptr->name, ISTC_DHCP_POOL_NAME_SIZE);
                    strncpy(pool->interface, ptr->interface, ISTC_IFNAME_SIZE);
                    pool->start = ntohl(ptr->start);
                    pool->end = ntohl(ptr->end);
                    pool->mask = ntohl(ptr->mask);
                    pool->gateway = ntohl(ptr->gateway);
                    pool->lease = ntohl(ptr->lease);
                    pool->primary_dns = ntohl(ptr->primary_dns);
                    pool->secondary_dns = ntohl(ptr->secondary_dns);
                }
            }

        }

        ret = 0;
        *count = cnt;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}


int istc_dhcp_lease_get(istc_dhcp_lease_t * lease, int *count)
{
    int sock;
    int ret;
    int seq;
    char buff[2048] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_get_lease_t *data =
        (istc_class_dhcp_get_lease_t *) (head + 1);
    int length = 0;
    int cnt_ret = 0;
    int cnt = 0;

    SURE_PTR(lease);

    SURE_PTR(count);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPS_CMD_GET_LEASE,
              sizeof (istc_class_dhcp_get_lease_t), seq);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_get_lease_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
        length = ntohs(head->length);
        if (length > 0) {
            /* recv cnt */
            SURE_RECVN(sock, data, sizeof (istc_class_dhcp_get_lease_t), ret);
            cnt_ret = ntohl(data->cnt);
            //DPRINT("recv cnt = %d, pcnt = %d\n", cnt_ret, *pcnt);
            cnt = cnt_ret;
            if (cnt > 0) {
                int total = cnt * sizeof (istc_dhcp_lease_t);
                memset(buff, 0, sizeof (buff));
                SURE_RECVN(sock, buff, total, ret);
                if (*count < cnt) {
                    cnt = *count;
                }
                /* copy to result */
                int i;
                istc_dhcp_lease_t *ptr = (istc_dhcp_lease_t *) buff;
                for (i = 0; i < cnt; i++, lease++, ptr++) {
                    strncpy(lease->host_name, ptr->host_name,
                            ISTC_HOST_NAME_SIZE);
                    lease->host_ip = ntohl(ptr->host_ip);
                    memcpy(lease->host_mac, ptr->host_mac, 6);
                    lease->host_lease = ntohl(ptr->host_lease);
                }
            }

        }

        ret = 0;
        *count = cnt;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}



int istc_dhcp_pool_add(const istc_dhcp_pool_t * pool)
{
    int sock;
    int ret;
    int seq;
    char buff[1024] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_dhcp_pool_t *data = (istc_dhcp_pool_t *) (head + 1);


    SURE_PTR(pool);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPS_CMD_ADD_POOL,
              sizeof (istc_dhcp_pool_t), seq);

    if (pool->interface[0]) {
        strncpy(data->interface, pool->interface, ISTC_IFNAME_SIZE);
    }

    if (pool->name[0]) {
        strncpy(data->name, pool->name, ISTC_DHCP_POOL_NAME_SIZE);
    }

    if (data->mask > 0) {
        unsigned int mask = data->mask;
        mask = ~mask + 1;
        if ((mask & (mask - 1)) != 0) {
            DPRINT("netmask 0x%x format error\n", data->mask);
            return -1;
        }
    }

    if (data->start > data->end) {
        DPRINT("start must less than end\n");
        return -1;
    }

    data->start = htonl(pool->start);
    data->end = htonl(pool->end);
    data->mask = htonl(pool->mask);
    data->lease = htonl(pool->lease);
    data->gateway = htonl(pool->gateway);
    data->primary_dns = htonl(pool->primary_dns);
    data->secondary_dns = htonl(pool->secondary_dns);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff, sizeof (istc_head_t) + sizeof (istc_dhcp_pool_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_dhcp_pool_remove(unsigned int start, unsigned int end)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_remove_pool_t *data =
        (istc_class_dhcp_remove_pool_t *) (head + 1);

    if (start > end) {
        DPRINT("start should less than end!\n");
        return -1;
    }

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPS_CMD_REMOVE_POOL,
              sizeof (istc_class_dhcp_remove_pool_t), seq);

    data->start = htonl(start);
    data->end = htonl(end);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_remove_pool_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_dhcp_pool_remove_by_name(const char *name)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_remove_pool_by_name_t *data =
        (istc_class_dhcp_remove_pool_by_name_t *) (head + 1);

    SURE_STR(name);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPS_CMD_REMOVE_POOL_BY_NAME,
              sizeof (istc_class_dhcp_remove_pool_by_name_t), seq);

    strncpy(data->name, name, ISTC_DHCP_POOL_NAME_SIZE);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_remove_pool_by_name_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_dhcpc_option60_add(const char *ifname, const char *data_in)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_add_opt60_t *data =
        (istc_class_dhcp_add_opt60_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(data_in);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPC_CMD_ADD_OPT60,
              sizeof (istc_class_dhcp_add_opt60_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->data, data_in, ISTC_DHCP_OPTION60_SIZE);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_add_opt60_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_dhcpc_option60_remove(const char *ifname)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_remove_opt60_t *data =
        (istc_class_dhcp_remove_opt60_t *) (head + 1);

    SURE_STR(ifname);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPC_CMD_REMOVE_OPT60,
              sizeof (istc_class_dhcp_remove_opt60_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_remove_opt60_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_dhcpc_option60_s_add(const char *ifname, const char *data_in)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_add_opt60_s_t *data =
        (istc_class_dhcp_add_opt60_s_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(data_in);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPC_CMD_ADD_OPT60_S,
              sizeof (istc_class_dhcp_add_opt60_s_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->data, data_in, ISTC_DHCP_OPTION60_SIZE);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_add_opt60_s_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_dhcpc_option60_s_remove(const char *ifname)
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dhcp_remove_opt60_s_t *data =
        (istc_class_dhcp_remove_opt60_s_t *) (head + 1);

    SURE_STR(ifname);

    FILL_HEAD(head, ISTC_CLASS_DHCPS, ISTC_CLASS_DHCPC_CMD_REMOVE_OPT60_S,
              sizeof (istc_class_dhcp_remove_opt60_s_t), seq);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_OPEN(sock);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dhcp_remove_opt60_s_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}




/************************    link notification routines    ************************/
#define ISTC_LINK_CHANGE_LIST_MAX	32
#define ISTC_LINK_CHANGE_FLAG_USED	1
#define ISTC_LINK_CHANGE_BUFF_SIZE	128

typedef void (*istc_link_change_callback_t) (const istc_link_change_t * link);

typedef struct istc_link_change_data_s {
    char ifname[ISTC_IFNAME_SIZE];  /* changed interface */
    int iflen;
    void *data;                 /* user data */
    istc_link_change_callback_t callback;
    int flag;
} istc_link_change_data_t;

typedef struct istc_link_change_desc_s {
    pthread_rwlock_t rwlock;
    pthread_t tid;
    int sock;
    istc_link_change_data_t list[ISTC_LINK_CHANGE_LIST_MAX];
} istc_link_change_desc_t;

static istc_link_change_desc_t g_istc_link_desc = {
    .rwlock = PTHREAD_RWLOCK_INITIALIZER,
    .tid = 0,
    .sock = -1,
};


static int istc_interface_link_notify(const char *ifname, int change_to)
{
    int ret = -1;
    int errer_no;
    int i;
    int len;
    istc_link_change_data_t *list = g_istc_link_desc.list;
    istc_link_change_t arg;


    if (!ifname || !*ifname) {
        return -1;
    }
    //DPRINT("interface %s link change to %d\n", ifname, change_to);


    if (change_to < 0) {
        return -1;
    }

    len = strlen(ifname);

    if ((errer_no = pthread_rwlock_rdlock(&g_istc_link_desc.rwlock)) < 0) {
        DPRINT("rdlock error %s\n", strerror(errer_no));
        return -1;
    }

	int b_registered = 0;

    for (i = 0; i < ISTC_LINK_CHANGE_LIST_MAX; i++) {
        if ((list[i].flag & ISTC_LINK_CHANGE_FLAG_USED)) {
            /* check if the interface is registered */
            int b_need_callback = 0;
			if ( 0 == strncmp(ISTC_IFNAME_ALL, list[i].ifname, strlen(ISTC_IFNAME_ALL)) ) {
				b_need_callback = 1;
			} else if (len == list[i].iflen
                && strncmp(ifname, list[i].ifname, len) == 0) {
				b_need_callback = 1;
			}
			if (1 == b_need_callback) {
                /* yes, found, do the callback */
				b_registered = 1;
                strncpy(arg.ifname, ifname, ISTC_IFNAME_SIZE);
                arg.change_to = change_to;
                arg.data = list[i].data;
                /* Call the register function, note, must not blocked !!! */
                //DPRINT("call register function\n");
                list[i].callback(&arg);
            } 
        }
    }

	if (0 == b_registered) {
		DPRINT("error! %s not registered for notify!\n", ifname);
	}

    if ((errer_no = pthread_rwlock_unlock(&g_istc_link_desc.rwlock)) < 0) {
        DPRINT("unlock error %s\n", strerror(errer_no));
        return -1;
    }

    return ret;
}


static void *istc_interface_link_change_handler(void *arg)
{
    int sock = (int) arg;
    fd_set rdset;
    struct timeval time_val;
    int ret = -1;
    int errno_local = 0;
    char buff[ISTC_LINK_CHANGE_BUFF_SIZE];
    int size = sizeof (buff);
    istc_head_t *head = (istc_head_t *) buff;
    istc_link_notification_t *notif = (istc_link_notification_t *) (head + 1);
    int len = sizeof (istc_head_t) + sizeof (istc_link_notification_t);
    int class;
    int command;
    int change_to;

    DPRINT("enter link notification thread(detached), start to watch ...\n");

    pthread_detach(pthread_self());

    while (1) {
        FD_ZERO(&rdset);
        FD_SET(sock, &rdset);
        time_val.tv_sec = ISTC_TIMEOUT_DEFAULT;
        time_val.tv_usec = 0;

        if ((ret = select(sock + 1, &rdset, NULL, NULL, &time_val)) == -1) {
            errno_local = errno;
            if ((errno_local == EINTR)) {
                /* would bock or interrupted */
                continue;
            } else {
                DPRINT("select failed %s, returned\n", strerror(errno_local));
                return (void *) (errno_local);
            }
        }

        if (ret == 0) {
            //DPRINT("recv timeout\n");
            continue;
        }

        if (FD_ISSET(sock, &rdset)) {
            /* may a link notification come */
            memset(buff, 0, size);
            if ((ret = recv(sock, buff, len, 0)) == -1) {
                errno_local = errno;
                if ((errno_local == EAGAIN) ||
                    (errno_local == EWOULDBLOCK) || (errno_local == EINTR)) {
                    /* would blocked, try it again */
                    continue;
                } else {
                    DPRINT("recv failed %s, returned\n", strerror(errno_local));
                    istc_client_close(sock);
                    return (void *) (errno_local);
                }
            }

            if (ret == 0) {
                DPRINT("server close the connection\n");
                istc_client_close(sock);
                return (void *) (errno_local);
            }

            if (ret != len) {
                DPRINT("receive trancated, ignore this message\n");
                continue;
            }

            /* now parse the received data */
            if (head->type == ISTC_MSG_TYPE_NOTIFY) {
                class = ntohs(head->class);
                command = ntohs(head->command);
                if (class == ISTC_CLASS_NOTIFY &&
                    command == ISTC_CLASS_NOTIFY_CMD_LINK_CHANGED) {
                    change_to = ntohl(notif->change_to);
                    istc_interface_link_notify(notif->ifname, change_to);
                }
            }

        }

    }

    return NULL;
}


int istc_link_change_register(const char *ifname,
                              void (*callback) (const istc_link_change_t *
                                                link), void *data)
{
    int ret = -1;
    int errer_no;
    int i;
    istc_link_change_data_t *list = g_istc_link_desc.list;
    int len;

    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_link_notification_t *notif = (istc_link_notification_t *) (head + 1);

    SURE_STR(ifname);
    SURE_PTR(callback);

    len = strlen(ifname);

    FILL_HEAD(head, ISTC_CLASS_NOTIFY,
              ISTC_CLASS_NOTIFY_CMD_REGISTER_LINK_CHANGE,
              sizeof (istc_link_notification_t), seq);
    strncpy(notif->ifname, ifname, ISTC_IFNAME_SIZE);

    if ((errer_no = pthread_rwlock_wrlock(&g_istc_link_desc.rwlock)) < 0) {
        DPRINT("wrlock error %s\n", strerror(errer_no));
        return -1;
    }

    if (g_istc_link_desc.tid == 0) {
        pthread_t tid;
        int sock;
        if ((sock = istc_client_open()) == -1) {
            DPRINT("open socket failed\n");
            goto register_fail;
        }

        istc_socket_nonblock(sock);

        /* create a thread */
        DPRINT("create a thread to receive link notification!\n");
        if ((errer_no =
             pthread_create(&tid, NULL, istc_interface_link_change_handler,
                            (void *) sock)) != 0) {
            DPRINT("unlock error %s\n", strerror(errer_no));
            goto register_fail;
        }
        g_istc_link_desc.tid = tid;
        g_istc_link_desc.sock = sock;
    }

    /* register callback */
    /* duplicate register is allowed */
    for (i = 0; i < ISTC_LINK_CHANGE_LIST_MAX; i++) {
        if (!(list[i].flag & ISTC_LINK_CHANGE_FLAG_USED)) {
            /* insert */
            strncpy(list[i].ifname, ifname, ISTC_IFNAME_SIZE);
            list[i].iflen = len;
            list[i].data = data;
            list[i].callback = callback;

            if (send(g_istc_link_desc.sock, buff,
                     sizeof (istc_head_t) + sizeof (istc_link_notification_t),
                     MSG_NOSIGNAL) == -1) {
                DERROR("send error\n");
                break;
            }
#if 0
            if ((ret =
                 istc_recv_timeout(g_istc_link_desc.sock, buff,
                                   sizeof (istc_head_t), 0)) == -1) {
                DPRINT("recv failed\n");
                break;
            }

            if (ret != sizeof (istc_head_t) || head->rc != 0) {
                break;
            }
#endif
            list[i].flag = ISTC_LINK_CHANGE_FLAG_USED;
            ret = 0;
            break;
        }
    }

  register_fail:

    if ((errer_no = pthread_rwlock_unlock(&g_istc_link_desc.rwlock)) < 0) {
        DPRINT("unlock error %s\n", strerror(errer_no));
        return -1;
    }

    return ret;
}

int istc_link_change_unregister(const char *ifname,
                                void (*callback) (const istc_link_change_t *
                                                  link))
{
    int ret = -1;
    int errer_no;
    int i;
    istc_link_change_data_t *list = g_istc_link_desc.list;
    int len;

    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_link_notification_t *notif = (istc_link_notification_t *) (head + 1);

    SURE_STR(ifname);
    SURE_PTR(callback);

    len = strlen(ifname);

    FILL_HEAD(head, ISTC_CLASS_NOTIFY,
              ISTC_CLASS_NOTIFY_CMD_UNREGISTER_LINK_CHANGE,
              sizeof (istc_link_notification_t), seq);
    strncpy(notif->ifname, ifname, ISTC_IFNAME_SIZE);

    if ((errer_no = pthread_rwlock_wrlock(&g_istc_link_desc.rwlock)) < 0) {
        DPRINT("wrlock error %s\n", strerror(errer_no));
        return -1;
    }

    for (i = 0; i < ISTC_LINK_CHANGE_LIST_MAX; i++) {
        if ((list[i].flag & ISTC_LINK_CHANGE_FLAG_USED)) {
            if (list[i].callback == callback &&
                len == list[i].iflen &&
                strncmp(ifname, list[i].ifname, len) == 0) {
                /* yes, we found the registered data, unregister it now */
                list[i].flag = 0;

                if (send(g_istc_link_desc.sock, buff,
                         sizeof (istc_head_t) +
                         sizeof (istc_link_notification_t),
                         MSG_NOSIGNAL) == -1) {
                    DERROR("send error\n");
                    break;
                }

                ret = 0;
                break;
            }
        }
    }

    if ((errer_no = pthread_rwlock_unlock(&g_istc_link_desc.rwlock)) < 0) {
        DPRINT("unlock error %s\n", strerror(errer_no));
        return -1;
    }

    return ret;
}



static void *istc_async_handler(void *arg)
{
    int sock = (int) arg;
    fd_set rdset;
    struct timeval time_val;
    int ret = -1;
    int errno_local = 0;
    char buff[1600];
    int size = sizeof (buff);
    istc_head_t *head = (istc_head_t *) buff;
    int class;
    int command;
    int i;

    DPRINT("enter async notification thread(detached), start ...\n");

    pthread_detach(pthread_self());

    while (1) {
        FD_ZERO(&rdset);
        FD_SET(sock, &rdset);
        time_val.tv_sec = ISTC_TIMEOUT_DEFAULT;
        time_val.tv_usec = 0;

        if ((ret = select(sock + 1, &rdset, NULL, NULL, &time_val)) == -1) {
            errno_local = errno;
            if ((errno_local == EINTR)) {
                /* would bock or interrupted */
                continue;
            } else {
                DPRINT("select failed %s, returned\n", strerror(errno_local));
                return (void *) (errno_local);
            }
        }

        if (ret == 0) {
            //DPRINT("recv timeout\n");
            continue;
        }

        if (FD_ISSET(sock, &rdset)) {
            /* may a async notification come */
            memset(buff, 0, size);
            if ((ret = recv(sock, buff, sizeof(buff), 0)) == -1) {
                errno_local = errno;
                if ((errno_local == EAGAIN) ||
                    (errno_local == EWOULDBLOCK) || (errno_local == EINTR)) {
                    /* would blocked, try it again */
                    continue;
                } else {
                    DPRINT("recv failed %s, returned\n", strerror(errno_local));
                    istc_client_close(sock);
                    return (void *) (errno_local);
                }
            }

            if (ret == 0) {
                DPRINT("server close the connection\n");
                istc_client_close(sock);
                return (void *) (errno_local);
            }

            /* now parse the received data */
            if (head->type == ISTC_MSG_TYPE_ASYNC) {
                class = ntohs(head->class);
                command = ntohs(head->command);
                if (class != ISTC_CLASS_ASYNC) {
                    DPRINT("unknown class %d\n", class);
                    continue;
                }
                
                /* now callback, need lock it first ? */
                for (i = 0; i < ISTC_ASYNC_CALLBACK_MAX; i++) {
                    if(g_istc_async_desc.callback[i]) {
                        ((g_istc_async_desc.callback)[i])(command, head + 1, 
                            ret - sizeof(istc_head_t));
                    }
                }
            }

        }

    }

    return NULL;
}



int istc_async_callback_register(istc_async_callback_t callback)
{
    //int ret = -1;
    int errer_no;

    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    int sock = -1;
    pthread_t tid = -1;
    int registered = 0;
    int registered_cnt = 0;

    SURE_PTR(callback);

    DPRINT0("register a async callback\n");

    if ((errer_no = pthread_rwlock_wrlock(&g_istc_async_desc.rwlock)) < 0) {
        DPRINT("wrlock error %s\n", strerror(errer_no));
        return -1;
    }

    if (g_istc_async_desc.sock == -1) {
        /* init the sock and create a thread */
        DPRINT0("first call this, init every thing\n");
        if ((sock = istc_client_open()) == -1) {
            DPRINT("open socket failed\n");
            return -1;
        }

        istc_socket_nonblock(sock);
        
        /* create a thread */
        DPRINT("create a thread to receive async notification!\n");
        if ((errer_no =
             pthread_create(&tid, NULL, istc_async_handler,
                            (void *) sock)) != 0) {
            DPRINT("unlock error %s\n", strerror(errer_no));
            istc_client_close(sock);
            
            if ((errer_no = pthread_rwlock_unlock(&g_istc_async_desc.rwlock)) < 0) {
                DPRINT("unlock error %s\n", strerror(errer_no));
            }            
            return -1;
        }

        g_istc_async_desc.sock = sock;
        g_istc_async_desc.tid = tid;
        
    } 
   
    int i;
    for (i = 0; i < ISTC_ASYNC_CALLBACK_MAX; i++) {
        if (g_istc_async_desc.callback[i] != NULL) {
            DPRINT("slot %d is registered\n", i);
            registered_cnt++;
        } else {
            if (!registered) {
                DPRINT("register in index %d\n", i);
                g_istc_async_desc.callback[i] = callback;
                registered = 1;
            }
        }
    }

    if ((errer_no = pthread_rwlock_unlock(&g_istc_async_desc.rwlock)) < 0) {
        DPRINT("unlock error %s\n", strerror(errer_no));
        istc_client_close(sock);
        if (tid != -1) {
            pthread_cancel(tid);
        }
        return -1;
    }

    if (registered == 0) {
        DPRINT("all register slot is full\n");
        return ISTC_ERR_FULL;
    }

    if (registered_cnt > 0) {
        DPRINT0("aready register to server\n");
        return 0;
    }
    
    /* register callback */
    FILL_HEAD(head, ISTC_CLASS_ASYNC, ISTC_CLASS_ASYNC_CMD_REGISTER, 0, seq);
    DPRINT0("send to register info to server\n");
    if (send(g_istc_async_desc.sock, buff, sizeof (istc_head_t), MSG_NOSIGNAL) 
        == -1) {
        DERROR("send error\n");
        istc_client_close(sock);
        if (tid != -1) {
            pthread_cancel(tid);
        }        
        return -1;
    }    

    DPRINT0("register async success\n");
    return 0;
}

int istc_async_callback_unregister(istc_async_callback_t callback)
{
    //int ret = -1;
    int errer_no;

    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    int registered_cnt = 0;

    SURE_PTR(callback);

    FILL_HEAD(head, ISTC_CLASS_ASYNC,
              ISTC_CLASS_ASYNC_CMD_UNREGISTER,
              0, seq);

    DPRINT0("unregister async\n");

    if ((errer_no = pthread_rwlock_wrlock(&g_istc_async_desc.rwlock)) < 0) {
        DPRINT("wrlock error %s\n", strerror(errer_no));
        return -1;
    }

    int i;
    for (i = 0; i < ISTC_ASYNC_CALLBACK_MAX; i++) {
        if (g_istc_async_desc.callback[i] == callback) {
            g_istc_async_desc.callback[i] = NULL;
            continue;
        }
        /* check if any register more, if none unregister from server */
        if (g_istc_async_desc.callback[i] != NULL) {
            registered_cnt++;
        }
    }

    if (registered_cnt == 0 &&
        g_istc_async_desc.sock >= 0) {
        DPRINT0("found the callback\n");
        if (send(g_istc_async_desc.sock, buff, sizeof (istc_head_t),
            MSG_NOSIGNAL) == -1) {
            DERROR("send error\n");
            if ((errer_no = pthread_rwlock_unlock(&g_istc_async_desc.rwlock)) < 0) {
                DPRINT("unlock error %s\n", strerror(errer_no));
            }
            return -1;
        }
    }

    if ((errer_no = pthread_rwlock_unlock(&g_istc_async_desc.rwlock)) < 0) {
        DPRINT("unlock error %s\n", strerror(errer_no));
        return -1;
    }

    return 0;
}


int istc_route_state_get(int *state)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_route_get_state_t *data =
        (istc_class_route_get_state_t *) (head + 1);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_ROUTE, ISTC_CLASS_ROUTE_CMD_GET_STATE,
              sizeof (istc_class_route_get_state_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_route_get_state_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data, sizeof (istc_class_route_get_state_t), ret);
        *state = ntohl(data->state);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);


    return ret;
}


int istc_route_state_set(int state)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_route_set_state_t *data =
        (istc_class_route_set_state_t *) (head + 1);

    data->state = htonl(state);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_ROUTE, ISTC_CLASS_ROUTE_CMD_SET_STATE,
              sizeof (istc_class_route_set_state_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_route_set_state_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);


    return ret;
}



int istc_route_default_get(const char *ifname, unsigned int *gateway)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_route_get_default_t *data =
        (istc_class_route_get_default_t *) (head + 1);

    SURE_PTR(gateway);

    SURE_OPEN(sock);

    if (ifname && *ifname) {
        strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    }

    FILL_HEAD(head, ISTC_CLASS_ROUTE, ISTC_CLASS_ROUTE_CMD_GET_DEFAULT,
              sizeof (istc_class_route_get_default_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_route_get_default_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data, sizeof (istc_class_route_get_default_t), ret);
        *gateway = ntohl(data->gateway);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);


    return ret;
}


int istc_route_default_set(const char *ifname, unsigned int gateway)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_route_set_default_t *data =
        (istc_class_route_set_default_t *) (head + 1);

    if (ifname && *ifname) {
        strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    }

    data->gateway = htonl(gateway);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_ROUTE, ISTC_CLASS_ROUTE_CMD_SET_DEFAULT,
              sizeof (istc_class_route_set_default_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_route_set_default_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);


    return ret;
}



int istc_dns_address_get(unsigned int *primary, unsigned int *secondary)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dns_get_dns_t *data = (istc_class_dns_get_dns_t *) (head + 1);

    SURE_PTR(primary);
    SURE_PTR(secondary);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_DNS, ISTC_CLASS_DNS_CMD_GET_DNS,
              sizeof (istc_class_dns_get_dns_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dns_get_dns_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data, sizeof (istc_class_dns_get_dns_t), ret);
        *primary = ntohl(data->primary);
        *secondary = ntohl(data->secondary);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);


    return ret;
}


int istc_dns_address_set(unsigned int primary, unsigned int secondary)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_dns_set_dns_t *data = (istc_class_dns_set_dns_t *) (head + 1);

    data->primary = htonl(primary);
    data->secondary = htonl(secondary);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_DNS, ISTC_CLASS_DNS_CMD_SET_DNS,
              sizeof (istc_class_dns_set_dns_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_dns_set_dns_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);


    return ret;
}


int istc_misc_config_save()
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_SAVE_CONFIG,
              sizeof (istc_head_t), seq);

    SURE_SENDN(sock, buff, sizeof (istc_head_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_pppoe_config_get(const char *ifname, char *username, char *password)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_pppoe_config_t *data = (istc_class_pppoe_config_t *) (head + 1);

    SURE_STR(ifname);
    SURE_PTR(username);
    SURE_PTR(password);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_PPPOE, ISTC_CLASS_PPPOE_CMD_GET_CONFIG,
              sizeof (istc_class_pppoe_config_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_pppoe_config_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data, sizeof (istc_class_pppoe_config_t), ret);
        strncpy(username, data->username, ISTC_PPPOE_USERNAME_SIZE);
        strncpy(password, data->password, ISTC_PPPOE_PASSWORD_SIZE);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_pppoe_config_set(const char *ifname, char *username, char *password)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_pppoe_config_t *data = (istc_class_pppoe_config_t *) (head + 1);

    SURE_STR(ifname);
    SURE_STR(username);
    SURE_STR(password);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->username, username, ISTC_PPPOE_USERNAME_SIZE);
    strncpy(data->password, password, ISTC_PPPOE_PASSWORD_SIZE);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_PPPOE, ISTC_CLASS_PPPOE_CMD_SET_CONFIG,
              sizeof (istc_class_pppoe_config_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_pppoe_config_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_pppoe_state(const char *ifname, int *state)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_pppoe_state_t *data = (istc_class_pppoe_state_t *) (head + 1);

    SURE_STR(ifname);
    SURE_PTR(state);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_PPPOE, ISTC_CLASS_PPPOE_CMD_GET_STATE,
              sizeof (istc_class_pppoe_state_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_pppoe_state_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data, sizeof (istc_class_pppoe_state_t), ret);
        *state = ntohl(data->state);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_pppoe_connect(const char *ifname)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_pppoe_connect_t *data =
        (istc_class_pppoe_connect_t *) (head + 1);

    SURE_STR(ifname);
    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_PPPOE, ISTC_CLASS_PPPOE_CMD_CONNECT,
              sizeof (istc_class_pppoe_connect_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_pppoe_connect_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_async_pppoe_connect(const char *ifname)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_pppoe_connect_t *data =
        (istc_class_pppoe_connect_t *) (head + 1);
	
    SURE_STR(ifname);
    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_PPPOE, ISTC_CLASS_PPPOE_CMD_ASYNC_CONNECT,
		sizeof (istc_class_pppoe_connect_t), seq);
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_pppoe_connect_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}

int istc_pppoe_disconnect(const char *ifname)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_pppoe_disconnect_t *data =
        (istc_class_pppoe_disconnect_t *) (head + 1);


    SURE_STR(ifname);
    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);


    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_PPPOE, ISTC_CLASS_PPPOE_CMD_DISCONNECT,
              sizeof (istc_class_pppoe_disconnect_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_pppoe_disconnect_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_ping(const istc_ping_para_t * para, istc_ping_result_t * result)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_ping_para_t *data = (istc_ping_para_t *) (buff + sizeof (istc_head_t));
    istc_ping_result_t *pr = NULL;
    int timeout;

    SURE_PTR(para);
    SURE_PTR(result);

    if (para->host[0] == '\0') {
        DPRINT("need host name or IP\n");
        return -1;
    }

    memcpy(data, para, sizeof (istc_ping_para_t));

    if (data->count <= 0 || data->count > ISTC_PING_COUNT_MAX) {
        data->count = ISTC_PING_COUNT_DEFAULT;
    }

    if (data->interval < ISTC_PING_INTERVAL_MIN
        || data->interval > ISTC_PING_INTERVAL_MAX) {
        data->interval = ISTC_PING_INTERVAL_DEFAULT;
    }

    if (data->pkt_size <= 0 || data->pkt_size > ISTC_PING_PKT_SIZE_MAX) {
        data->pkt_size = ISTC_PING_PKT_SIZE_DEFAULT;
    }

    if (data->ip_ttl < ISTC_PING_IP_TTL_MIN
        || data->ip_ttl > ISTC_PING_IP_TTL_MAX) {
        data->ip_ttl = ISTC_PING_IP_TTL_DEFAULT;
    }

    if (data->timeout < ISTC_PING_TIMEOUT_MIN
        || data->timeout > ISTC_PING_TIMEOUT_MAX) {
        data->timeout = ISTC_PING_TIMEOUT_DEFAULT;
    }

    timeout = data->timeout * data->count;

    data->count = htonl(data->count);
    data->interval = htonl(data->interval);
    data->pkt_size = htonl(data->pkt_size);
    data->ip_ttl = htonl(data->ip_ttl);
    data->timeout = htonl(data->timeout);
    data->fragment = htonl(data->fragment);
    data->src_addr = htonl(data->src_addr);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_PING,
              sizeof (istc_ping_para_t), seq);

    SURE_SENDN(sock, buff, sizeof (istc_head_t) + sizeof (istc_ping_para_t),
               ret);

    /* try to recv the head */
    if (istc_recv_timeout(sock, buff, sizeof (istc_head_t), 2) == -1) {
        DPRINT("recv ping result head failed\n");
        istc_client_close(sock);
        return -1;
    }
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        /* now wait the ping result */
        if (istc_recv_timeout
            (sock, buff, sizeof (istc_ping_result_t), timeout + 2) == -1) {
            DPRINT("recv ping result body failed\n");
            istc_client_close(sock);
            return -1;
        }

        /* convert the byte order */
        pr = (istc_ping_result_t *) buff;
        result->rtt_min = ntohl(pr->rtt_min);
        result->rtt_max = ntohl(pr->rtt_max);
        result->rtt_avg = ntohl(pr->rtt_avg);
        result->time = ntohl(pr->time);
        result->send = ntohl(pr->send);
        result->recv = ntohl(pr->recv);

        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;

}


int istc_async_ping(const istc_ping_para_t * para)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_ping_para_t *data = (istc_ping_para_t *) (buff + sizeof (istc_head_t));
    int timeout;

    SURE_PTR(para);

    if (para->host[0] == '\0') {
        DPRINT("need host name or IP\n");
        return -1;
    }

    memcpy(data, para, sizeof (istc_ping_para_t));

    if (data->count <= 0 || data->count > ISTC_PING_COUNT_MAX) {
        data->count = ISTC_PING_COUNT_DEFAULT;
    }

    if (data->interval < ISTC_PING_INTERVAL_MIN
        || data->interval > ISTC_PING_INTERVAL_MAX) {
        data->interval = ISTC_PING_INTERVAL_DEFAULT;
    }

    if (data->pkt_size <= 0 || data->pkt_size > ISTC_PING_PKT_SIZE_MAX) {
        data->pkt_size = ISTC_PING_PKT_SIZE_DEFAULT;
    }

    if (data->ip_ttl < ISTC_PING_IP_TTL_MIN
        || data->ip_ttl > ISTC_PING_IP_TTL_MAX) {
        data->ip_ttl = ISTC_PING_IP_TTL_DEFAULT;
    }

    if (data->timeout < ISTC_PING_TIMEOUT_MIN
        || data->timeout > ISTC_PING_TIMEOUT_MAX) {
        data->timeout = ISTC_PING_TIMEOUT_DEFAULT;
    }

    timeout = data->timeout * data->count;
    timeout= timeout;

    data->count = htonl(data->count);
    data->interval = htonl(data->interval);
    data->pkt_size = htonl(data->pkt_size);
    data->ip_ttl = htonl(data->ip_ttl);
    data->timeout = htonl(data->timeout);
    data->fragment = htonl(data->fragment);
    data->src_addr = htonl(data->src_addr);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_PING_ASYNC,
              sizeof (istc_ping_para_t), seq);

    SURE_SENDN(sock, buff, sizeof (istc_head_t) + sizeof (istc_ping_para_t),
               ret);

    /* try to recv the head */
    if (istc_recv_timeout(sock, buff, sizeof (istc_head_t), 2) == -1) {
        DPRINT("recv ping result head failed\n");
        istc_client_close(sock);
        return -1;
    }
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_interface_list_get(char list[][ISTC_IFNAME_SIZE], int *count)
{
    int sock;
    int ret;
    int seq;
    int length;
    int cnt_ret;
    int cnt = 0;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_misc_cmd_interface_list_get_t *data =
        (istc_class_misc_cmd_interface_list_get_t *) (head + 1);

    SURE_PTR(list);
    SURE_PTR(count);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_INTERFACE_LIST_GET, 0,
              seq);

    SURE_SENDN(sock, buff, sizeof (istc_head_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
        length = ntohs(head->length);
        if (length > 0) {
            /* recv cnt */
            SURE_RECVN(sock, data,
                       sizeof (istc_class_misc_cmd_interface_list_get_t), ret);
            cnt_ret = ntohl(data->cnt);
            //DPRINT("recv cnt = %d, pcnt = %d\n", cnt_ret, *pcnt);
            cnt = cnt_ret;
            if (cnt > 0) {
                int total = cnt * (ISTC_IFNAME_SIZE);
                memset(buff, 0, sizeof (buff));
                SURE_RECVN(sock, buff, total, ret);
                if (*count < cnt) {
                    cnt = *count;
                }
                /* copy to result */
                int i;
                char *ptr = buff;
                for (i = 0; i < cnt; i++, ptr += ISTC_IFNAME_SIZE) {
                    strncpy(list[i], ptr, ISTC_IFNAME_SIZE);
                }
            }

        }

        *count = cnt;

        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}


int istc_interface_type_get(const char *ifname, int *type)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_misc_cmd_interface_type_get_t *data =
        (istc_class_misc_cmd_interface_type_get_t *) (head + 1);

    SURE_STR(ifname);
    SURE_PTR(type);

    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_INTERFACE_TYPE_GET,
              sizeof (istc_class_misc_cmd_interface_type_get_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) +
               sizeof (istc_class_misc_cmd_interface_type_get_t), ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data,
                   sizeof (istc_class_misc_cmd_interface_type_get_t), ret);
        *type = ntohl(data->type);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}




int istc_log_level_get(int *level)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_misc_cmd_log_lv_get_t *data =
        (istc_class_misc_cmd_log_lv_get_t *) (head + 1);

    SURE_PTR(level);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_GET_LOG_LV,
              sizeof (istc_class_misc_cmd_log_lv_get_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_misc_cmd_log_lv_get_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        SURE_RECVN(sock, data, sizeof (istc_class_misc_cmd_log_lv_get_t), ret);
        *level = ntohl(data->level);
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



int istc_log_level_set(int level)
{
    int sock;
    int ret;
    int seq;
    char buff[128] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_misc_cmd_log_lv_set_t *data =
        (istc_class_misc_cmd_log_lv_set_t *) (head + 1);


    if (!((level >= 0 && level <= 7) || (level == -1))) {
        DPRINT("log level is invalid\n");
        return -1;
    }

    data->level = htonl(level);

    SURE_OPEN(sock);

    FILL_HEAD(head, ISTC_CLASS_MISC, ISTC_CLASS_MISC_CMD_SET_LOG_LV,
              sizeof (istc_class_misc_cmd_log_lv_set_t), seq);

    SURE_SENDN(sock, buff,
               sizeof (istc_head_t) + sizeof (istc_class_misc_cmd_log_lv_set_t),
               ret);

    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }

    istc_client_close(sock);

    return ret;
}



/* utils */


int istc_str2mac(const char *str, unsigned char *mac)
{
    char buff[24] = { 0 };
    char *end;
    int ret;

    strncpy(buff, str, 24);

    if (buff[2] == buff[5] &&
        buff[2] == buff[8] && buff[2] == buff[11] && buff[2] == buff[14]) {
        if (buff[2] != ':' && buff[2] != '-') {
            //printf("mac string error format\n");
            return -1;
        }
    }

    int i;
    for (i = 0; i <= 15; i += 3) {
        ret = strtol(buff + i, &end, 16);
        if (end == buff + i) {
            return -1;
        }
        if (ret < 0 || ret > 255) {
            return -1;
        }

        *mac++ = (unsigned char) ret;
    }


    return 0;
}

int istc_qos_set_mode( int mode )
{
	int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_qos_mode_t *data = (istc_class_qos_mode_t *) (head + 1);
	
	
    if (mode <= ISTC_QOS_MODE_NONE
        || mode >= ISTC_QOS_MODE_MAX) {
        DPRINT("mode unknown %d\n", mode);
        return -1;
    }
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_QOS, ISTC_CLASS_QOS_CMD_SET_MODE,
		sizeof (istc_class_qos_mode_t), seq);
	
    data->mode = htonl(mode);
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_qos_mode_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}

int istc_qos_get_mode( int *mode )
{
	int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_qos_mode_t *data = (istc_class_qos_mode_t *) (head + 1);
	
    SURE_PTR(mode);
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_QOS, ISTC_CLASS_QOS_CMD_GET_MODE,
		sizeof (istc_class_qos_mode_t), seq);
	
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_qos_mode_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_qos_mode_t)) {
			
            SURE_RECVN(sock, data, length, ret);
			
            *mode = ntohl(data->mode);
            //DPRINT("recv addr_mode 0x%x\n", *mode);
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}

int istc_qos_set_device_bandwidth( const unsigned char *mac, int download_kbyte, int upload_kbyte )
{
	int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_conf_qos_device_bandwidth_t *data = (istc_conf_qos_device_bandwidth_t *) (head + 1);
		
    SURE_PTR(mac);
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_QOS, ISTC_CLASS_QOS_CMD_SET_DEVICE_BANDWIDTH,
		sizeof (istc_conf_qos_device_bandwidth_t), seq);
	
    memcpy(data->mac, mac, 6);
	data->download_kbyte = htonl(download_kbyte);
	data->upload_kbyte = htonl(upload_kbyte);
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_conf_qos_device_bandwidth_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}

int istc_qos_get_device_bandwidth( const unsigned char *mac, int *download_kbyte, int *upload_kbyte )
{
	int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_conf_qos_device_bandwidth_t *data = (istc_conf_qos_device_bandwidth_t *) (head + 1);
	
    SURE_PTR(download_kbyte);
	SURE_PTR(upload_kbyte);

    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_QOS, ISTC_CLASS_QOS_CMD_GET_DEVICE_BANDWIDTH,
		sizeof (istc_conf_qos_device_bandwidth_t), seq);
	
	memcpy(data->mac, mac, 6);
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_conf_qos_device_bandwidth_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_conf_qos_device_bandwidth_t)) {
			
            SURE_RECVN(sock, data, length, ret);
			
            *download_kbyte = ntohl(data->download_kbyte);
			*upload_kbyte = ntohl(data->upload_kbyte);
            
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}

int istc_qos_get_device_bandwidth_list( istc_conf_qos_device_bandwidth_t *list, int *count )
{
	int sock;
    int ret;
    int seq;
    int length;
    int cnt_max;
	int cnt_ret;
	int b_only_get_count = 0;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_qos_device_bandwidth_list_t *data =
        (istc_class_qos_device_bandwidth_list_t *) (head + 1);
	
    if (NULL == list) {
		b_only_get_count = 1;
    }

    SURE_PTR(count);

	cnt_max = *count;
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_QOS, ISTC_CLASS_QOS_CMD_GET_DEVICE_BANDWIDTH_LIST, 0,
		seq);
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_qos_device_bandwidth_list_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);

	do //only for use break;
	{
		head->rc = ntohl(head->rc);
		if (head->rc != 0) {
			DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
			ret = head->rc;
			*count = 0;
			break;
		}

		length = ntohs(head->length);
		if (0 == length) {
			ret = 0;
			*count = 0;
			break;
		}

		/* recv cnt */
		SURE_RECVN(sock, data,
			sizeof (istc_class_qos_device_bandwidth_list_t), ret);
		cnt_ret = ntohl(data->cnt);

		if (1 == b_only_get_count || 0 == cnt_ret) {
			*count = cnt_ret;
			ret = 0;
			break;
		}

		int total = cnt_ret * (sizeof(istc_conf_qos_device_bandwidth_t));

		if (total > sizeof(buff)) {
			DPRINT("error: recv buff is small than data\n");
			*count = 0;
			ret = -1;
			break;
		}

		if (cnt_max < cnt_ret) {
			DPRINT("error: user space is small than data\n");
			*count = 0;
			ret = -1;
			break;
		}

		memset(buff, 0, sizeof (buff));
		SURE_RECVN(sock, buff, total, ret);
		
		/* copy to result */
		int i;
		istc_conf_qos_device_bandwidth_t *buf_ptr = (istc_conf_qos_device_bandwidth_t *)buff;
		istc_conf_qos_device_bandwidth_t *list_ptr = list;
		for (i = 0; i < cnt_ret; i++) {
			
			buf_ptr->download_kbyte = ntohl(buf_ptr->download_kbyte);
			buf_ptr->upload_kbyte = ntohl(buf_ptr->upload_kbyte);
			buf_ptr->b_used = ntohs(buf_ptr->b_used);
			
			*list_ptr = *buf_ptr;
			
			buf_ptr++;
			list_ptr++;
		}
		*count = cnt_ret;
		ret = 0;

	} while (0);
	
    istc_client_close(sock);
    return ret;
}

int istc_wireless_ap_ssid_add_by_index( const char *ifname, int index, const istc_ap_ssid_t * ssid )
{
	int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_add_ssid_t *data = (istc_class_ap_add_ssid_t *) (head + 1);
    char len;
	
    SURE_STR(ifname);
    SURE_PTR(ssid);
	
    if (ssid->ssid[0] == '\0') {
        DPRINT("SSID name must not null\n");
        return -1;
    }
	
    if (ssid->encryption != ISTC_WIRELESS_ENCRYPTION_OPEN) {
        if (ssid->encryption != ISTC_WIRELESS_ENCRYPTION_WPA &&
            ssid->encryption != ISTC_WIRELESS_ENCRYPTION_WPA2 &&
            ssid->encryption != ISTC_WIRELESS_ENCRYPTION_WPA_WPA2) {
            DPRINT("encryption must be open, wpa or wpa2\n");
            return -1;
        }
        if (ssid->password[0] == '\0') {
            DPRINT("non open SSID need password!\n");
            return -1;
        }
        len = strlen(ssid->password);
        if (len < 8) {
            DPRINT("password must more than 8 characters\n");
            return -1;
        }
    }
	
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_ADD_SSID,
		sizeof (istc_class_ap_add_ssid_t), seq);

	data->ssid.index = htonl(index);
    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    strncpy(data->ssid.ssid, ssid->ssid, ISTC_SSID_NAME_SIZE);
    if (ssid->password[0]) {
        strncpy(data->ssid.password, ssid->password, ISTC_SSID_PSWD_SIZE);
    }
    data->ssid.encryption = htonl(ssid->encryption);
    data->ssid.channel = htonl(ssid->channel);
    data->ssid.b_hidden = htonl(ssid->b_hidden);
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_ap_add_ssid_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;	
}

int istc_wireless_ap_ssid_get_by_index( const char *ifname, int index, istc_ap_ssid_t * ssid )
{
	return 0;
}

int istc_wireless_ap_ssid_set_by_index( const char *ifname, int index, const istc_ap_ssid_t * ssid )
{
    SNMP_DATA_LIST_st *data_head = NULL, *data_list = NULL;
    clabWIFISSIDTable_rowreq_ctx *ssid_ctx = NULL;
    wifiBssTable_rowreq_ctx *bss_ctx = NULL;
    wifiBssWpaTable_rowreq_ctx *bsswpa_ctx = NULL;
    int count = 0;
    int column = 0;
    istc_ap_ssid_t ap_ssid;
    
    oid clabWIFISSIDIfName[] = {CLABWIFISSIDTABLE_OID, COLUMN_CLABWIFISSIDID, COLUMN_CLABWIFISSIDNAME};
    size_t ssiddOID_len = OID_LENGTH(clabWIFISSIDIfName);
    oid wifiBssSsid[] = {WIFIBSSTABLE_OID, COLUMN_WIFIBSSID, COLUMN_WIFIBSSSSID, 0};
    size_t wifiBssSsid_len = OID_LENGTH(wifiBssSsid);
    oid wifiBssWpaPreSharedKey[] = {WIFIBSSWPATABLE_OID, COLUMN_WIFIBSSWPAALGORITHM, COLUMN_WIFIBSSWPAPRESHAREDKEY, 0};
    size_t wifiBssWpaPreSharedKey_len = OID_LENGTH(wifiBssWpaPreSharedKey_len);

    SNMP_ASSERT(ifname != NULL && *ifname != 0 && ssid != NULL);

    istc_log("ifname = %s\n", ifname);
    memset(&ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid.ifname, ifname, sizeof(ap_ssid.ifname) - 1);
    
    if(istc_snmp_table_parse_data(clabWIFISSIDIfName, ssiddOID_len, (SnmpTableFun)_clabWIFISSIDTable_set_column, sizeof(clabWIFISSIDTable_rowreq_ctx), &data_head, &count) != 0)
    {
        istc_log("can not parse data_list\n");
        return -1;
    }
    istc_log("parse data success\n");
    data_list= data_head; 
    while(data_list != NULL)
    {
        ssid_ctx = (clabWIFISSIDTable_rowreq_ctx *)(data_list->data);
        if(strcmp(ifname, ssid_ctx->data.clabWIFISSIDName) == 0 && ssid_ctx->data.clabWIFISSIDBSSID[0] != 0)
        {
            column = (int)ssid_ctx->oid_idx.oids[ssid_ctx->oid_idx.len - 1];
            istc_log("find success, ifname = %s", ifname);
            break;
        }
        data_list = data_list->next;
    }
    istc_snmp_free_datalist(data_head);
    data_head = NULL;
    if(data_list == NULL)
    {
        istc_log("can not get bssid\n");
        return -1;
    }

    wifiBssSsid[wifiBssSsid_len - 1] = column;
    wifiBssWpaPreSharedKey[wifiBssWpaPreSharedKey_len - 1] = column;
    
    if(istc_snmp_table_parse_data(wifiBssSsid, wifiBssSsid_len, (SnmpTableFun)_wifiBssTable_set_column, sizeof(wifiBssTable_rowreq_ctx), &data_head, &count) != 0)
    {
        istc_log("can not parse data_list\n");
        return -1;
    }
    istc_log("parse data success\n");
    bss_ctx = (wifiBssTable_rowreq_ctx *)(data_head->data);
    strncpy(ap_ssid.ssid, bss_ctx->data.wifiBssSsid, sizeof(ap_ssid.ssid) - 1);
    switch(bss_ctx->data.wifiBssSecurityMode)
    {
    case 0:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_OPEN;
        break;
    case 1:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WEP;
        break;
    case 2:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA;
        break;
    case 3:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA2;
        break;
    case 7:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_WPA_WPA2;
        break;
    default:
        ap_ssid.encryption = ISTC_WIRELESS_ENCRYPTION_NONE;
        break;
    }
    istc_snmp_free_datalist(data_head);
    data_head = NULL;

    if(istc_snmp_table_parse_data(wifiBssWpaPreSharedKey, wifiBssWpaPreSharedKey_len, (SnmpTableFun)_wifiBssWpaTable_set_column, sizeof(wifiBssWpaTable_rowreq_ctx), &data_head, &count) != 0)
    {
        istc_log("can not parse data_list\n");
        return -1;
    }
    istc_log("parse data success\n");
    bsswpa_ctx = (wifiBssWpaTable_rowreq_ctx *)(data_head->data);
    strncpy(ap_ssid.password, bsswpa_ctx->data.wifiBssWpaPreSharedKey, sizeof(ap_ssid.password) - 1);
    istc_snmp_free_datalist(data_head);
    data_head = NULL;

    memcpy((void *)ssid, (const void *)&ap_ssid, sizeof(ap_ssid));
    
    return 0;
}

int istc_wireless_ap_ssid_remove_by_index( const char *ifname, int index )
{
	int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_ap_remove_ssid_by_index_t *data =
        (istc_class_ap_remove_ssid_by_index_t *) (head + 1);
	
	
    SURE_STR(ifname);
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_AP, ISTC_CLASS_AP_CMD_REMOVE_SSID_BY_INDEX,
		sizeof (istc_class_ap_remove_ssid_by_index_t), seq);
	
    strncpy(data->ifname, ifname, ISTC_IFNAME_SIZE);
    data->index = htonl(index);
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_ap_remove_ssid_by_index_t),
		ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}

int istc_lan_set_addr_info( unsigned int gateway, unsigned int addr_begin, unsigned int addr_end )
{
    int sock;
    int ret;
    int seq;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_lan_addr_info_t *data = (istc_class_lan_addr_info_t *) (head + 1);
	
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_LAN, ISTC_CLASS_LAN_CMD_SET_ADDR_INFO,
		sizeof (istc_class_lan_addr_info_t), seq);
		
    data->gateway = htonl(gateway);	
    data->addr_begin = htonl(addr_begin);
    data->addr_end = htonl(addr_end);
    printf("%s %d:gateway = %d, start = %d\n", __FUNCTION__, __LINE__, data->gateway, data->addr_begin);	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_lan_addr_info_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        ret = 0;
    } else {
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}

int istc_lan_get_addr_info( unsigned int *gateway, unsigned int *addr_begin, unsigned int *addr_end )
{
    int sock;
    int ret;
    int seq;
    int length;
    char buff[512] = { 0 };
    istc_head_t *head = (istc_head_t *) buff;
    istc_class_lan_addr_info_t *data = (istc_class_lan_addr_info_t *) (head + 1);
	
    SURE_PTR(gateway);
    SURE_PTR(addr_begin);
    SURE_PTR(addr_end);
	
    SURE_OPEN(sock);
	
    FILL_HEAD(head, ISTC_CLASS_LAN, ISTC_CLASS_LAN_CMD_GET_ADDR_INFO,
		sizeof (istc_class_lan_addr_info_t), seq);
	
	
    SURE_SENDN(sock, buff,
		sizeof (istc_head_t) + sizeof (istc_class_lan_addr_info_t), ret);
	
    SURE_RECVN(sock, buff, sizeof (istc_head_t), ret);
	
    //SURE_RESP(sock, head, ISTC_CLASS_IP, ISTC_CLASS_IP_CMD_GET_IPADDR, seq);
    head->rc = ntohl(head->rc);
    if (head->rc == 0) {
        length = ntohs(head->length);
        //DPRINT("length = %d\n", length);
        if (length == sizeof (istc_class_lan_addr_info_t)) {
			
            SURE_RECVN(sock, data, length, ret);
			
            *gateway = ntohl(data->gateway);
            *addr_begin = ntohl(data->addr_begin);
            *addr_end = ntohl(data->addr_end);
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        DPRINT("rc = %d %s\n", head->rc, istc_errstr(head->rc));
        ret = head->rc;
    }
	
    istc_client_close(sock);
	
    return ret;
}
