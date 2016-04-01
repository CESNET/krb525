/*
 * krb525_convert.c
 *
 *  - convert given credentials
 *
 * 
 */

/* 	$Id: krb525_convert.c,v 1.1.1.1 2009/11/13 09:13:02 kouril Exp $	 */

#ifndef lint
static char vcid[] = "$Id: krb525_convert.c,v 1.1.1.1 2009/11/13 09:13:02 kouril Exp $";
#endif /* lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <krb5.h>
#include <com_err.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif

#include "krb525_convert.h"
#include "krb525.h"
#include "netio.h"
#include "auth_con.h"
#include "version.h"

/* krb5_authdata is defined quite differently in MIT and Heimdal,
   we better use a dedicated container to pass it over calls */
typedef struct krb525_authdata {
#ifdef HEIMDAL
    krb5_authdata  data;
#else
    krb5_authdata  **data;
#endif
} krb525_authdata;

/* Default options if we are authenticating from keytab */
#define KEYTAB_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options if we are authenticating from cache */
#define CACHE_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options for credentials for krb525d */
#define GATEWAY_DEFAULT_TKT_OPTIONS	0


char krb525_convert_error[255] = "";


static krb5_error_code
get_krb525_creds_ccache(krb5_context context,
			krb5_ccache ccache,
			char *cname,
			char *krb525_host,
			krb525_authdata *auth_data,
			krb5_creds **krb525_creds)
{
  krb5_flags      gateway_options = GATEWAY_DEFAULT_TKT_OPTIONS;
  krb5_error_code retval;
  krb5_creds      in_creds;

  memset((char *)&in_creds, 0, sizeof(in_creds));

  in_creds.authdata = auth_data->data;

  /*
   * Get and parse client name to authenticate to krb525d with. If none
   * specified then use cache owner name.
   */
  if (cname == NULL) {
    /* Get cache owner */
    if(retval=krb5_cc_get_principal(context, ccache, &in_creds.client)) {
      sprintf(krb525_convert_error, "%s while getting cache owner",
	      error_message(retval));
      return(retval);
    }
  } else {
    /* Parse name */
    if (retval = krb5_parse_name (context, cname, &in_creds.client)) {
      sprintf(krb525_convert_error, "%s when parsing name %s", 
	      error_message(retval), cname);
      return(retval);
    }
  }
  
  /*
   * Parse service name to authenticate with. (Default is
   * KRB525_SERVICE/<hostname>)
   */
  if (retval = krb5_sname_to_principal(context, krb525_host, KRB525_SERVICE,
				       KRB5_NT_SRV_HST, &in_creds.server)) {
    sprintf(krb525_convert_error, "%s while creating server name for %s/%s",
	    error_message(retval), KRB525_SERVICE, krb525_host);
    return(retval);
  }
  
  /* Get our credentials for the gateway */
  retval = krb5_get_credentials(context, 
				gateway_options,
				ccache,
				&in_creds,
				krb525_creds);
  if(retval) 
    sprintf(krb525_convert_error, "%s while getting credentials",
	    error_message(retval));

  return(retval);
}

static int
krb525_getportbyname(const char *service, const char *proto, short default_port)
{
  struct servent *sp;

  sp = getservbyname (service, proto);
  if (sp)
    return sp->s_port;

  return htons(default_port);
}


static krb5_error_code
krb525_connect(krb5_context context,
#ifdef HEIMDAL
	       krb5_realm          *realm,
#else
	       krb5_data           *realm,
#endif
               char       **hosts,
	       int          port,
	       int         *socket,
	       char       **server_name)
{
  krb5_error_code retval;

  char *krb525_host = NULL;
  char **krb525_hosts = NULL;
  int krb525_host_num = 0;
  int krb525_port = -1, default_port = -1, use_port = 0;
  int sock;
 
#ifdef HEIMDAL
  krb5_realm          default_realm;
#else
  krb5_data           default_realm;
#endif

  *socket = -1;
  *server_name = NULL;


  if(realm == NULL) {
  /* Get default realm */
#ifdef HEIMDAL
    if (retval = krb5_get_default_realm(context, &default_realm)) 
#else
    if (retval = krb5_get_default_realm(context, &(default_realm.data))) 
#endif
      {
	sprintf(krb525_convert_error, "%s while getting default realm\n", 
		error_message(retval));
	return(retval);
      }
    realm = &default_realm;
  }

  /* Get servers for realm - passed as argument, krb525_servers in config file
     or kdc in config file */
  if(hosts) {
    krb525_hosts = hosts;
  } else {
#ifdef HEIMDAL
    krb525_hosts = krb5_config_get_strings(context, NULL, "realms", *realm, "krb525_server", NULL);
    if(krb525_hosts == NULL) {
      /* Get list of possible server hosts (same as KDC server hosts) */
      if (retval = krb5_get_krbhst(context, realm, &krb525_hosts)) {
	sprintf(krb525_convert_error, "%s while getting server hosts\n",
		error_message(retval));
	return(retval);
      }
    } else 
      use_port = 1;
#else
    {
      char *tmp;

      /* N.B. there's a different location of the directive! */
      krb5_appdefault_string(context, NULL, realm, "krb525_server", NULL, &tmp);
      krb525_hosts = &tmp;
    }
#endif
  }

  /* If no host was found, return error */
  if (!krb525_hosts || !krb525_hosts[0]) 
    return(KRB5_KDC_UNREACH);

  /* Get default server port */
  if(port <= 0)
    default_port = krb525_getportbyname(KRB525_SERVICE, "tcp", KRB525_PORT);

  /* Try to contact server */
  for (krb525_host_num = 0; krb525_host = krb525_hosts[krb525_host_num]; krb525_host_num++) {

    if(strncmp(krb525_host, "http://", 7) == 0){
      krb525_host += 7;
    } else if(strncmp(krb525_host, "http/", 5) == 0) {
      krb525_host += 5;
    } else if(strncmp(krb525_host, "tcp/", 4) == 0){
      krb525_host += 4;
    } else if(strncmp(krb525_host, "udp/", 4) == 0) {
      krb525_host += 4;
    }

    /* Get server port - from argument, configuration or default */
    krb525_port = -1;
    {
      char *c;

      if(c = strchr(krb525_host, ':')) {
	if(use_port) 
	  krb525_port = htons(atoi(c+1));
	*c = 0;
      }
    }
    if(port > 0)
      krb525_port = htons(port);
    else if(krb525_port <= 0)
      krb525_port = default_port;

    if ((sock = connect_to_server(krb525_host, krb525_port)) >= 0 )
      /* Success */
      break;
    else {
      fprintf(stderr,"%s while connecting to the server\n",error_message(errno));
#if 0
      sprintf(krb525_convert_error, "%s while connecting to the server\n",
	      error_message(errno));
      return(errno);
#endif
    }
  }

  *socket = sock;
  *server_name = krb525_host;
  return(0);
}
	       

static krb5_error_code
krb525_do_convert(krb5_context context,
		  int          sock,
		  krb5_creds   *krb525_creds,
		  krb5_creds   *in_creds,
		  krb5_creds   *out_creds)
{
  int                 namelen;
  struct sockaddr_in  lsin, rsin;
  krb5_auth_context   auth_context = 0;
  krb5_data           recv_data;
  krb5_error_code     retval;
  char                resp_status;
  krb5_error          *err_ret;
  krb5_data           message;


  /* Send authenticator to the server */
  retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &sock,
			 KRB525_VERSION,      /* Application version */
			 NULL,	              /* Client - not needed */
			 NULL,	              /* Server - not needed */
			 AP_OPTS_MUTUAL_REQUIRED, /* Options */
			 NULL,                /* Application data */
			 krb525_creds,        /* Credentials for server - not needed */
			 NULL,                /* Credentials cache - not needed */
			 &err_ret, NULL, NULL);
  
  if (retval) {
    sprintf(krb525_convert_error, "%s while authenticating to the server\n",
	    error_message(retval));
    return(retval);
  }
  
  /* Get addresses of connection ends */
  namelen = sizeof(rsin);
  if ((retval=getpeername(sock, (struct sockaddr *) &rsin, &namelen)) < 0) {
    close(sock);
    sprintf(krb525_convert_error, "%s while getting local address\n",
	    error_message(retval));
    return(retval);
  }
  
  namelen = sizeof(lsin);
  if ((retval=getsockname(sock, (struct sockaddr *) &lsin, &namelen)) < 0) {
    close(sock);
    sprintf(krb525_convert_error, "%s while getting remote address\n",
	    error_message(retval));
    return(retval);
  }
  
  /* Prepare to encrypt */
  if (retval = setup_auth_context(context, auth_context, &lsin, &rsin,
				  "_525")) {
    sprintf(krb525_convert_error, "%s while setting authentication context\n",
	    auth_con_error);
        return(retval);
  }
  
  /* Send target client name */
  if(retval=krb5_unparse_name(context, out_creds->client, (char **)&message.data)) {
    sprintf(krb525_convert_error, "%s while parsing target client\n",
	    error_message(retval));
    return(retval);
  }
  message.length = strlen(message.data) + 1;
  retval = send_encrypt(context, auth_context, sock, message);
  free(message.data);
  if (retval) {
    sprintf(krb525_convert_error, "%s while sending client name\n",
	    netio_error);
    return(retval);
  }

  /* Send target server name */
  if(retval=krb5_unparse_name(context, out_creds->server, (char **)&message.data)) {
    sprintf(krb525_convert_error, "%s while parsing target server\n",
	    error_message(retval));
    return(retval);
  }
  message.length = strlen(message.data) + 1;
  retval = send_encrypt(context, auth_context, sock, message);
  free(message.data);
  if (retval) {
    sprintf(krb525_convert_error, "%s while sending server name\n",
	    netio_error);
    return(retval);
  }

  /* Send my ticket to be massaged */
  message.data = in_creds->ticket.data;
  message.length = in_creds->ticket.length;
  
  if (retval = send_encrypt(context, auth_context, sock, message)) {
    sprintf(krb525_convert_error, "%s while sending ticket\n",
	    netio_error);
    return(retval);
  }
  
  /* Read reply */
  if ((retval = read_msg(context, sock, &recv_data)) < 0) {
    sprintf(krb525_convert_error, "%s while reading reply\n",
	    netio_error);
    return(retval);
  }
  
  if(recv_data.data == NULL) {
    sprintf(krb525_convert_error, "no data received from server\n");
    return(-1);
  }

  resp_status = *((char *) recv_data.data);
  
  switch(resp_status) {
  case STATUS_OK:

    /* Copy all relevant data from in_creds to out_creds
     * (client and server were already set by the caller).
     */
    /* XXX Use copy_cred instead */
#ifdef HEIMDAL
    copy_EncryptionKey(&in_creds->session, &out_creds->session);
    memcpy(&out_creds->times, &in_creds->times, sizeof(out_creds->times));
    krb5_data_copy(&out_creds->second_ticket,&in_creds->second_ticket, 
		   in_creds->second_ticket.length);
    copy_AuthorizationData(&in_creds->authdata, &out_creds->authdata);
    krb5_copy_addresses(context, &in_creds->addresses, &out_creds->addresses);
    out_creds->flags = in_creds->flags;
#else
    krb5_copy_keyblock_contents(context, &in_creds->keyblock, &out_creds->keyblock);
    memcpy(&out_creds->times, &in_creds->times, sizeof(out_creds->times));
    out_creds->second_ticket.length = in_creds->second_ticket.length;
    out_creds->second_ticket.data = malloc(out_creds->second_ticket.length);
    memcpy(&out_creds->second_ticket.data, &in_creds->second_ticket.data, out_creds->second_ticket.length);
    krb5_copy_authdata(context, in_creds->authdata, &out_creds->authdata);
    krb5_copy_addresses(context, in_creds->addresses, &out_creds->addresses);
    out_creds->ticket_flags = in_creds->ticket_flags;
#endif
    
    /* Read new ticket from server */
    if ((retval = read_encrypt(context, auth_context, sock, &recv_data)) < 0) {
      sprintf(krb525_convert_error, "%s while reading converted ticket\n",
	      netio_error);
      return(retval);
    }

    /* Put new ticket data into credentials */
    out_creds->ticket.data = recv_data.data;
    out_creds->ticket.length = recv_data.length;
    
    break;
    
  case STATUS_ERROR:	
    /* Read and print error message from server */
    if ((retval = read_encrypt(context, auth_context, sock, &recv_data)) < 0) {
      sprintf(krb525_convert_error, "%s while reading error message\n",
	      netio_error);
      return(retval);
    }
    sprintf(krb525_convert_error, "%s from server\n",
	    (char *)recv_data.data);
    return(KRB5KRB_ERR_GENERIC);
    
  default:
    sprintf(krb525_convert_error, "unknown response status\n");
    return(KRB5_BADMSGTYPE);
  }
  return(0);
}

krb5_error_code
krb525_convert_with_ccache(krb5_context context,
			   char         **hosts,
			   int          port,
			   krb5_ccache  ccache,
			   char         *cname,
			   krb5_creds   *in_creds,
			   krb5_creds   *out_creds)
{
  int             sock;
  char           *krb525_host;
  krb5_creds     *krb525_creds;
  krb5_error_code retval;
#ifdef HEIMDAL
  krb5_realm      *realm;
#else
  krb5_data       *realm;
#endif
  krb525_authdata   auth_data;

  realm = &in_creds->server->realm;

  /* Try to contact server and get server name */
  if(retval=krb525_connect(context, realm, hosts, port, &sock, &krb525_host))
    return(retval);

  auth_data.data = in_creds->authdata;

  /* Get credentials for krb525d at the contacted host */
  if(retval=get_krb525_creds_ccache(context, ccache, cname, krb525_host, 
				    &auth_data, &krb525_creds)) {
    close(sock);
    return(retval);
  }

  /* Convert credentials */
  retval = krb525_do_convert(context, sock, krb525_creds, in_creds, out_creds);

  close (sock);
  return retval;
}


krb5_error_code
krb525_convert_with_keytab(krb5_context context,
			   char         **hosts,
			   int          port,
			   krb5_keytab  keytab,
			   char         *cname,
			   krb5_creds   *in_creds,
			   krb5_creds   *out_creds)
{
  /* The implementation has been removed due to its utilization of deprecated calls
	 and incompletness. If the call is ever needed, please refer to the VCS and
	 fix it */
	
  return ENOSYS;
}


krb5_error_code
krb525_get_creds_ccache(krb5_context context,
			krb5_ccache  ccache,
			krb5_creds  *in_creds,
			krb5_creds  *out_creds)
{
  return(krb525_convert_with_ccache(context, NULL, 0, ccache, NULL, in_creds, out_creds));
}


krb5_error_code
krb525_get_creds_keytab(krb5_context context,
			krb5_keytab  keytab,
			char         *cname,
			krb5_creds   *in_creds,
			krb5_creds   *out_creds)
{
  return(krb525_convert_with_keytab(context, NULL, 0, keytab, cname, in_creds, out_creds));
}
