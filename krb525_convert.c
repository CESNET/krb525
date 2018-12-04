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

#define _GNU_SOURCE
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
#include <stdarg.h>
#include <unistd.h>

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

typedef struct krb525_endpoint_t {
    char *hostname;
    unsigned short port;
} krb525_endpoint_t;

/* Default options if we are authenticating from keytab */
#define KEYTAB_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options if we are authenticating from cache */
#define CACHE_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options for credentials for krb525d */
#define GATEWAY_DEFAULT_TKT_OPTIONS	0


char krb525_convert_error[2048] = "";

static void
free_strings(char **strings)
{
	char **s = strings;

	while (s && *s) {
		free(*s);
		s++;
	}

	free(strings);
}

static void
free_endpoints(krb525_endpoint_t **endpoints)
{
	krb525_endpoint_t **eps = endpoints;

	while (eps && *eps) {
		free((*eps)->hostname);
		free(*eps);
		eps++;
	}
	free(endpoints);
}

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

static int
parse_krb525_hosts(char **krb525_hosts, short port, int use_port, krb525_endpoint_t ***endpoints)
{
	krb525_endpoint_t **tmp;
	krb525_endpoint_t **eps = NULL;
	int num = 0, ret;
	char **krb525_host;
	int krb525_port = -1 ;
	char *host, *p;

	eps = calloc(1, sizeof(**eps));
	if (eps == NULL) {
		ret = ENOMEM;
		goto end;
	}
	num = 1;

	for (krb525_host = krb525_hosts; krb525_host && *krb525_host; krb525_host++) {
		host = *krb525_host;

		if (strncmp(host, "http://", 7) == 0)
			host += 7;
		else if (strncmp(host, "http/", 5) == 0)
			host += 5;
		else if (strncmp(host, "tcp/", 4) == 0)
			host += 4;
		else if (strncmp(host, "udp/", 4) == 0)
			host += 4;

		krb525_port = -1;
		p = strchr(host, ':');
		if (p) {
			if(use_port)
				krb525_port = htons(atoi(p+1));
			*p = 0;
		}
		if(port > 0)
			krb525_port = htons(port);
		else if(krb525_port <= 0)
			krb525_port = krb525_getportbyname(KRB525_SERVICE, "tcp", KRB525_PORT);

		tmp = realloc(eps, (num + 1) * sizeof(*eps));
		if (tmp == NULL) {
			ret = ENOMEM;
			goto end;
		}
		eps = tmp;
		eps[num - 1] = malloc(sizeof(**eps));
		if (eps[num - 1] == NULL) {
			ret = ENOMEM;
			goto end;
		}
		eps[num - 1]->hostname = strdup(host);
		eps[num - 1]->port = krb525_port;
		eps[num] = NULL;
		num++;
	}

	ret = 0;
	*endpoints = eps;
	eps = NULL;

end:
	if (eps)
		free_endpoints(eps);
	return ret;
}

static int
get_krb525_endpoints(krb5_context context, short port, char *realm, krb525_endpoint_t ***krb525_endpoints)
{
	krb5_error_code retval;
	char **krb525_hosts = NULL;
	char *default_realm = NULL;
	int use_port = 0;

	if(realm == NULL) {
		retval = krb5_get_default_realm(context, &default_realm);
		if (retval) {
			snprintf(krb525_convert_error, sizeof(krb525_convert_error),
				"%s while getting default realm\n",
				error_message(retval));
			return(retval);
		}
		realm = default_realm;
	}

#ifdef HEIMDAL
	krb525_hosts = krb5_config_get_strings(context, NULL, "realms", realm, "krb525_server", NULL);
	if (krb525_hosts == NULL) {
		/* Get list of possible server hosts (same as KDC server hosts) */
		retval = krb5_get_krbhst(context, &realm, &krb525_hosts);
		if (retval) {
			snprintf(krb525_convert_error, sizeof(krb525_convert_error),
				"%s while getting server hosts\n",
				error_message(retval));
			goto end;
		}
	} else
		use_port = 1;
#else
	{
		char *s;
		krb5_data data_realm;

		data_realm.data = realm;
		data_realm.length = strlen(realm);

		/* N.B. there's a different location of the directive! */
		krb5_appdefault_string(context, NULL, &data_realm, "krb525_server", "", &s);
		krb525_hosts = calloc(2, sizeof(*krb525_hosts));
		if (krb525_hosts == NULL) {
			retval = ENOMEM;
			goto end;
		}
		krb525_hosts[0] = s;
		krb525_hosts[1] = NULL;
	}
#endif

	if (!krb525_hosts || !krb525_hosts[0] || !*krb525_hosts[0]) {
		retval = KRB5_KDC_UNREACH;
		goto end;
	}

	retval = parse_krb525_hosts(krb525_hosts, port, use_port, krb525_endpoints);
	if (retval)
		goto end;

	retval = 0;

end:
	if (krb525_hosts)
		free_strings(krb525_hosts);
	if (default_realm)
		free(default_realm);

	return (retval);
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

static int
update_err_msg(char **err_msg, const char *fmt, ...)
{
	int ret;
	char *s;
	va_list ap;

	va_start(ap, fmt);
	ret = vasprintf(&s, fmt, ap);
	va_end(ap);
	if (ret == -1)
		return ret;

	*err_msg = s;
	return 0;
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
  krb5_creds     *krb525_creds;
  krb5_error_code retval;
  char *realm;
  krb525_authdata   auth_data;
  krb525_endpoint_t **krb525_endpoints = NULL;
  krb525_endpoint_t **ep = NULL;
  char *tmp_err_msg = NULL;

#ifdef HEIMDAL
  realm = in_creds->server->realm;
#else
  realm = in_creds->server->realm.data;
#endif

  if (hosts)
	  retval = parse_krb525_hosts(hosts, port, 0, &krb525_endpoints);
  else
	  retval = get_krb525_endpoints(context, port, realm, &krb525_endpoints);
  if (retval) {
	  snprintf(krb525_convert_error, sizeof(krb525_convert_error), "failed to find krb525 hosts\n");
	  return retval;
  }

  auth_data.data = in_creds->authdata;

  retval = -1;
  for (ep = krb525_endpoints; ep && *ep; ep++) {
	  sock = connect_to_server((*ep)->hostname, (*ep)->port);
	  if (sock < 0) {
		  update_err_msg(&tmp_err_msg, "%s" "Failed to connect to server %s (%s)\n",
				(tmp_err_msg) ? tmp_err_msg : "",
				(*ep)->hostname, error_message(errno));
		  retval = -1;
		  continue;
	  }

	  retval = get_krb525_creds_ccache(context, ccache, cname, (*ep)->hostname,
			  &auth_data, &krb525_creds);
	  if (retval) {
		  update_err_msg(&tmp_err_msg, "%s" "Failed to get credentials for server %s (%s)\n",
				  (tmp_err_msg) ? tmp_err_msg : "",
				  (*ep)->hostname, krb525_convert_error);
		  close(sock);
		  continue;
	  }

	  retval = krb525_do_convert(context, sock, krb525_creds, in_creds, out_creds);
	  if (retval) {
		  update_err_msg(&tmp_err_msg, "%s" "Failed to convert credentials with %s (%s)\n",
				  (tmp_err_msg) ? tmp_err_msg : "",
				  (*ep)->hostname, krb525_convert_error);
		  close(sock);
		  continue;
	  }

	  close(sock);
	  retval = 0;
	  break;
  }

  if (retval) {
	  snprintf(krb525_convert_error, sizeof(krb525_convert_error), "%s",
			  (tmp_err_msg) ? tmp_err_msg : "Failed to contact k525 servers");
	  goto end;
  }

end:
  if (tmp_err_msg)
	  free(tmp_err_msg);
  if (krb525_endpoints)
	  free_endpoints(krb525_endpoints);

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
