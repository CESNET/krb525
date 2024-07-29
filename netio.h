/*
 * netio.h
 *
 * $Id: netio.h,v 1.1.1.1 2009/11/13 09:13:02 kouril Exp $
 */

#ifndef __NETIO_H
#define __NETIO_H

#include "krb5.h"
#include "com_err.h"

extern char netio_error[];

extern int send_encrypt(krb5_context,
			krb5_auth_context,
			int,
			krb5_data);

extern int send_msg(krb5_context,
		    int,
		    krb5_data);

extern int read_encrypt(krb5_context,
			krb5_auth_context,
			int,
			krb5_data *);

extern int read_msg(krb5_context,
		    int,
		    krb5_data *);

extern int connect_to_server(char *,
			     int,
				 int);


extern int make_accepting_sock(int,
			     int);



#endif /* __NETIO_H */
