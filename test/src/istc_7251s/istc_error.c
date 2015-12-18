
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
  iSTC(Inspur Safe Token Center) error number and readable string 

SEE ALSO:

NOTE:

TODO:
  
******************************************************************************/

/* 
modification history 
-------------------------------------------------------------------------------
01a,19Jun2014,xiongdb@inspur.com           written
*/

#include "istc.h"


/**
 *
 typedef enum istc_error_code_e {
	 ISTC_ERR_NONE			 = - __ISTC_ERR_NONE,
	 ISTC_SUCCESS			 = - __ISTC_SUCCESS,
	 ISTC_FAILED			 = - __ISTC_FAILED,
	 ISTC_ERR_ARGUMENT		 = - __ISTC_ERR_ARGUMENT,
	 ISTC_ERR_MEMORY		 = - __ISTC_ERR_MEMORY,
	 ISTC_ERR_ACCESS		 = - __ISTC_ERR_ACCESS,
	 ISTC_ERR_UNSUPPORT 	 = - __ISTC_ERR_UNSUPPORT,
	 ISTC_ERR_EXIST 		 = - __ISTC_ERR_EXIST,
	 ISTC_ERR_TIMEOUT		 = - __ISTC_ERR_TIMEOUT,
	 ISTC_ERR_BUSY			 = - __ISTC_ERR_BUSY,
	 ISTC_ERR_INPROGRESS	 = - __ISTC_ERR_INPROGRESS,
	 ISTC_ERR_LOCK_FAIL 	 = - __ISTC_ERR_LOCK_FAIL,
	 ISTC_ERR_UNLOCK_FAIL	 = - __ISTC_ERR_UNLOCK_FAIL,
	 ISTC_ERR_NOT_INSTANCE	 = - __ISTC_ERR_NOT_INSTANCE,
	 
 
	 ISTC_ERR_UNKNOWN		 = -__ISTC_ERR_UNKNOWN,
 } istc_error_code_t;
 *
 *
 */


const static char *istc_err_str[] = {
    "Success",
    "Failed",
    "Invalid Argument",
    "Memory Alloc Failed",
    "Access Denied",
    "Unsupport Operation",
    "Exist Entry",
    "Timeout",
    "Busy",
    "Inprogress",
    "Lock Failed",
    "Unlock Failed",
    "Not Instance",
    "Not Found",

    "Unknown Error",
};


const char *istc_errstr(int err)
{
    if (err > ISTC_ERR_NONE || err < ISTC_ERR_UNKNOWN) {
        return "Unknown Error";
    }

    return istc_err_str[-err];
}
