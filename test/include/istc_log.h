
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
  iSTC(Inspur Safe Token Center) log and debug routine prototype

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
01a,17Jun2014,xiongdb@inspur.com           create
*/
#ifndef __ISTC_LOG_H
#define __ISTC_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>


extern int g_istc_debug;
extern int g_istc_debug_level;

#define ISTC_EMERG	  "<0>"     /* system is unusable               */
#define ISTC_ALERT	  "<1>"     /* action must be taken immediately */
#define ISTC_CRIT	  "<2>"     /* critical conditions              */
#define ISTC_ERR	  "<3>"     /* error conditions                 */
#define ISTC_WARNING  "<4>"     /* warning conditions               */
#define ISTC_NOTICE   "<5>"     /* normal but significant condition */
#define ISTC_INFO	  "<6>"     /* informational                    */
#define ISTC_DEBUG	  "<7>"     /* debug-level messages             */

#define ISTC_LOG_FILE_DEFAULT	"/tmp/istcd.log"
#if 0
#define istc_log(fmt, ...) \
	do { \
		if (1 || g_istc_debug) { \
			if (fmt[0] == '<' && fmt[2] == '>' && (fmt[1] >= '0' && fmt[1] <= '7')) { \
				if ((fmt[1] - '0') <= g_istc_debug_level) { \
					istc_printf("[istcd] %s %d %s " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
				} \
			} else { \
				if (g_istc_debug_level == 7) { \
					istc_printf("[istcd] %s %d %s " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
				} \
			}\
		} \
	} while (0)
#else
#define istc_log(fmt, ...) \
    do { fprintf(stderr, "[istcc] %s %d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); } while (0)
#endif

int istc_printf(const char *fmt, ...)
    __attribute__ ((format(printf, 1, 2)));



int istc_log_init(char *file, int daemon);

int istc_log_exit();


#endif
