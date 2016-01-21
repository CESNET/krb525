/*
 * krb525d include file
 *
 * $Id: server.h,v 1.1.1.1 2009/11/13 09:13:02 kouril Exp $
 */

#ifndef __SERVER_H
#define __SERVER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "krb5.h"

/*
 * The request we're handling.
 */
typedef struct {
  krb5_context	       krb5_context;    /* Our Kerberos context */
  krb5_ticket         *sender_ticket;   /* Sender's ticket */
  char                *sender_name;     /* Sender name     */ 
  krb5_authdata       *auth_data;       /* Additional authorization (optional) */
#ifdef HEIMDAL
  Ticket               tkt;             /* Ticket we're converting */
#endif
  krb5_ticket	      *ticket;          /* Ticket we're converting - decrypted */
  char		      *cname;           /* Original client */
  char		      *sname;           /* Original server */
  struct sockaddr_in   addr;            /* Client's host   */
  char		      *target_cname;    /* Target client   */
  krb5_principal       target_client;
  char		      *target_sname;    /* Target server   */
  krb5_principal       target_server;
} krb525_request;


#endif /* __SERVER_H */
