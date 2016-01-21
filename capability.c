/* 	$Id: capability.c,v 1.4 2015/09/11 18:12:59 kouril Exp $	 */

#ifndef lint
static char vcid[] = "$Id: capability.c,v 1.4 2015/09/11 18:12:59 kouril Exp $";
#endif /* lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "capability.h"
#include "krb525_convert.h"

#include <krb5.h>

#ifdef HEIMDAL
#include "h_db.h"
#else
#include "k5_db.h"
#endif

char *cap_error = "(none)";

static char cap_check_error[1024];


/* This was taken from rd_req.c */
static krb5_error_code
decrypt_tkt_enc_part (krb5_context context,
		      krb5_keyblock *key,
		      EncryptedData *enc_part,
		      EncTicketPart *decr_part)
{
    krb5_error_code ret;
    krb5_data plain;
    size_t len;
    krb5_crypto crypto;

    krb5_crypto_init(context, key, 0, &crypto);
    ret = krb5_decrypt_EncryptedData (context,
				      crypto,
				      KRB5_KU_TICKET,
				      enc_part,
				      &plain);
    krb5_crypto_destroy(context, crypto);
    if (ret)
	return ret;

    ret = krb5_decode_EncTicketPart(context, plain.data, plain.length, 
				    decr_part, &len);
    krb5_data_free (&plain);
    return ret;
}


int
cap_check_ticket(krb525_request *request, krb5_data *cap)
{
  krb5_error_code ret;
  Ticket          cap_tkt;
  krb5_ticket     cap_ticket;
  size_t          len;
  krb5_keyblock   *server_key;
  
  /* decode ticket */
  ret = decode_Ticket(cap->data, cap->length, &cap_tkt, &len);
  if(ret)
    goto out;

  /* create server principal */
  ret = _krb5_principalname2krb5_principal(request->krb5_context, &cap_ticket.server, cap_tkt.sname, cap_tkt.realm);
  if(ret)
    goto out;

  /* get server key */
  ret = hdb_get_key(request->krb5_context, cap_ticket.server, &server_key, 
		    cap_tkt.enc_part.etype);
  if(ret)
    goto out;

  /* decrypt ticket */
  ret = krb5_decrypt_ticket(request->krb5_context, &cap_tkt, server_key, &cap_ticket.ticket, 0);
  if(ret == KRB5KRB_AP_ERR_TKT_EXPIRED) 
    ret = decrypt_tkt_enc_part(request->krb5_context, server_key, 
			       &cap_tkt.enc_part, &cap_ticket.ticket);
  if(ret)
    goto out;
    
  /* create client principal */
  ret = _krb5_principalname2krb5_principal(request->krb5_context, &cap_ticket.client, cap_ticket.ticket.cname, 
				     cap_ticket.ticket.crealm);
  if(ret)
    goto out;

  /* compare principals in capability ticket and request */
  if(!krb5_principal_compare(request->krb5_context,
			     request->target_client,
			     cap_ticket.client)) {
    cap_error = "Target client does not match capability.";
    return(-1);
  }

  if(!krb5_principal_compare(request->krb5_context,
			     request->target_server,
			     cap_ticket.server)) {
    cap_error = "Target server does not match capability.";
    return(-1);
  }
  
 out:
  if(ret) {
    cap_error = (char*)error_message(ret);
    return(-1);
  }
  return(0);
}


struct cap_names_data {
  const char *name;
  int         type;
};


struct cap_checks_data {
  int         type;
  int         (*check_cap)(krb525_request *, krb5_data *);
};


static struct cap_names_data cap_names[] = {
  { "ticket", KRB525_CAP_TICKET }
};


static struct cap_checks_data cap_checks[] = {
  { KRB525_CAP_TICKET, cap_check_ticket }
};


int
find_cap_type(const char *cap_name)
{
  int i, len = sizeof(cap_names)/sizeof(*cap_names);

  for(i=0; i < len; i++) {
    if(strcmp(cap_name, cap_names[i].name) == 0) 
      return(cap_names[i].type);
  }
  return(-1);
}


struct cap_checks_data*
find_cap_check(int cap_type)
{
  int i, len = sizeof(cap_checks)/sizeof(*cap_checks);

  for(i=0; i < len; i++) {
    if(cap_type == cap_checks[i].type)
      return(&cap_checks[i]);
  }
  return(NULL);
}


int
check_capabilities(krb525_request *request, char **cap_names)
{
  krb5_authdata *auth_data = request->auth_data;

  if(auth_data == NULL) {
    cap_error = "no capabilities found";
    return(-1);
  }

  cap_error = cap_check_error;
  while(*cap_names)
  {
    int cap_type = find_cap_type(*cap_names);
    int i, found;

    if(cap_type < 0) {
      sprintf(cap_check_error, "capability type %s not supported", *cap_names);
      return(-1);
    }

    found = 0;
    for(i=0; i < auth_data->len; i++) {
      if(auth_data->val[i].ad_type == cap_type) {
	struct cap_checks_data *cap_check = find_cap_check(cap_type);

	if(cap_check && (*cap_check->check_cap)(request, &auth_data->val[i].ad_data)) {
	  return(-1);
	}
	found = 1;
	break;
      }
    }
    if(!found) {
      sprintf(cap_check_error, "capability %s not found", *cap_names);
      return(-1);
    }
    cap_names++;
  }
  return(0);
}
