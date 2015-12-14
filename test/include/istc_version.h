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
  iSTC(Inspur Safe Token Center) istc type definition and function prototype

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
01a,06Nov2014,xiongdb@inspur.com           written
*/


#ifndef __ISTC_VERSION_H
#define __ISTC_VERSION_H

#include ".version.info"

#ifndef VERSION_INFO
#define ISTC_VERSION_COMMIT "000000.000000"
#else
#define ISTC_VERSION_COMMIT VERSION_INFO
#endif

#define ISTC_VERSION   "1"

#endif

