/* 	$Id: capability.h,v 1.1.1.1 2009/11/13 09:13:02 kouril Exp $	 */

#ifndef _CAPABILITY_H_
#define _CAPABILITY_H


#include "server.h"

extern char *cap_error;

int check_capabilities(krb525_request *, char **);

#endif
