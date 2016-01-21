/*
 * auth_con.h
 *
 * $Id: auth_con.h,v 1.1.1.1 2009/11/13 09:13:02 kouril Exp $
 */

#ifndef __AUTH_CON_H
#define __AUTH_CON_H

#include "krb5.h"
#include "com_err.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern char auth_con_error[];

extern krb5_error_code setup_auth_context(krb5_context,
					  krb5_auth_context,
					  struct sockaddr_in *,
					  struct sockaddr_in *,
					  char *);



#endif /* __AUTH_CON_H */
