/*
 * client.c
 *
 * krb525 client program
 *
 * $Id: client.c,v 1.2 2012/05/16 12:16:16 kouril Exp $
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "krb5.h"
#include "com_err.h"

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

#ifdef AFS_KRB5
#include <sys/stat.h>
#endif

extern int optind;
extern char *optarg;

#include "krb525.h"
#include "krb525_convert.h"
#include "netio.h"
#include "auth_con.h"
#include "version.h"


#define error_exit()	{ exit_code = 1; goto cleanup; }


/* Globals */
static char *progname;			/* This program's name */

/* Default options if we are authenticating from keytab */
#define KEYTAB_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options if we are authenticating from cache */
#define CACHE_DEFAULT_TKT_OPTIONS	KDC_OPT_FORWARDABLE

/* Default options for credentials for krb525d */
#define GATEWAY_DEFAULT_TKT_OPTIONS	0


/*
 * Fill in the structure pointed to by creds with credentials with
 * credentials for client/server using the keytab file indicated by the
 * path pointed to by keytab_name.
 */
krb5_error_code
get_creds_with_keytab(krb5_context context,
		      krb5_principal client,
		      krb5_principal server,
		      krb5_flags options,
		      krb5_keytab keytab,
		      krb5_creds *creds)
{
    krb5_error_code	retval;

    memset((char *)creds, 0, sizeof(*creds));

    creds->client = client;
    creds->server = server;

    /* XXX - this must fail with Heimdal, because Heimdal stores 
       credentials in ccache (NULL here) and does not test it for validity. */
    if (retval = krb5_get_in_tkt_with_keytab(context, options, NULL,
					     NULL, NULL, keytab, 0,
					     creds, 0)) {
        com_err(progname, retval, "when getting credentials");
	return retval;
    }

    return(retval);
}

/*
 * Fill in the structure pointed to by creds with credentials with
 * credentials for client/server using the keytab file indicated by the
 * path pointed to by keytab_name.
 */
krb5_error_code
get_creds_with_ccache(krb5_context context,
		      krb5_principal client,
		      krb5_principal server,
		      krb5_flags options,
		      krb5_ccache ccache,
		      krb5_creds *creds)
{
    krb5_error_code	retval;
    krb5_creds		in_creds, *out_creds;


    memset((char *)&in_creds, 0, sizeof(in_creds));

    in_creds.client = client;
    in_creds.server = server;

    /* XXX - options not used - this is TGS_REQ, not AS_REQ */
    if (retval = krb5_get_credentials(context, 0, ccache,
				      &in_creds, &out_creds)) {
      com_err(progname, retval, "when getting credentials");
      return retval;
    };

    memcpy((char *) creds, (char *) out_creds, sizeof(*creds));

    free(out_creds);

    return retval;
}


/*
 * Fill in the user's gid and uid in the supplied integers.
 *
 * Returns -1 if the user could not be found, 0 otherwise.
 */
static int
get_guid(char *username,
	 uid_t *uid,
	 gid_t *gid)
{
    struct passwd *passwdent;


    passwdent = getpwnam(username);

    if (passwdent == NULL)
	return -1;

    *uid = passwdent->pw_uid;
    *gid = passwdent->pw_gid;

    return 0;
}


void
main(argc, argv)
int argc;
char *argv[];
{

    krb5_context context;
    char *local_realm=NULL;

#ifdef HEIMDAL
    krb5_realm default_realm;
#else
    krb5_data default_realm;
#endif

    krb5_error_code retval;
    int exit_code = 0;

    /* Where the krb525d daemon is running */
    char *krb525_host = NULL;
    char **krb525_hosts = NULL;
    int krb525_port = KRB525_PORT;

    /* Credentials we are converting */
    char *cname = NULL;
    char *sname = NULL;
    krb5_principal cprinc, sprinc;
    krb5_creds     creds;

    /* Target credentials */
    char *target_cname = NULL;
    char *target_sname = NULL;
    krb5_principal target_cprinc, target_sprinc;
    krb5_creds target_creds;
    krb5_flags target_options = 0;

    /* Information about who should own target cache */
    char *cache_owner = NULL;
    uid_t uid = -1;
    gid_t gid = -1;

    /* Where we're going to put the converted credentials */
    krb5_ccache target_ccache = NULL;
    const char *target_cache_name = NULL;
    krb5_boolean initialize_cache = 1;

    /* Where our credentials are */
    char *source_cache_name = NULL;
    krb5_ccache source_ccache = NULL;
    int use_keytab = 0;
    char *keytab_name = NULL;
    krb5_keytab  keytab;

#ifdef AFS_KRB5
    /* Are we running aklog */
    krb5_boolean run_aklog = 0;
    krb5_boolean dont_run_aklog = 0;
#endif /* AFS_KRB5 */
	
    int arg;
    int arg_error = 0;
    int verbose = 0;



    /* Get our name, removing preceding path */
    if (progname = strrchr(argv[0], '/'))
	progname++;
    else
	progname = argv[0];

    /* Process arguments */
    while ((arg = getopt(argc, argv, "aAc:C:g:h:i:ko:p:s:S:t:u:vVr:")) != EOF)
	switch (arg) {
	case 'a':
#ifdef AFS_KRB5
	    run_aklog = 1;
#else
	    fprintf(stderr, "%s: -a option not supported\n", progname);
	    arg_error++;
#endif
	    break;

	case 'A':
#ifdef AFS_KRB5
	    dont_run_aklog = 1;
#else
	    fprintf(stderr, "%s: ignoring -A, not supported\n", progname);
#endif
	    break;


	case 'c':
	    cname = optarg;
	    break;

	case 'C':
	    target_cname = optarg;
	    break;

	case 'h':
	    krb525_host = optarg;
	    break;

	case 'i':
	    source_cache_name = optarg;
	    break;

	case 'k':
	    use_keytab = 1;
	    break;

	case 'o':
	    target_cache_name = optarg;
	    break;

	case 'p':
	    krb525_port = atoi(optarg);
	    if (krb525_port == 0) {
		fprintf(stderr, "Illegal port value \"%s\"\n", optarg);
		arg_error++;
	    }
	    break;

	case 's':
	    sname = optarg;
	    break;

	case 'S':
	    target_sname = optarg;
	    break;

	case 't':
	    keytab_name = optarg;
	    break;

	case 'u':
	    cache_owner = optarg;
	    break;

	case 'v':
	    verbose++;
	    break;

        case 'r':
            local_realm = optarg;
            break;

	case 'V':
	    printf("%s Version %s\n", progname, KRB525_VERSION_STRING);
	    exit(0);

	default:
	    arg_error++;
	    break;
	}

    if ((argc - optind) != 0)
	fprintf(stderr,
		"%s: Ignoring extra command line options starting with %s\n",
		progname, argv[optind]);

    if (keytab_name && !use_keytab) {
	fprintf(stderr,
		"%s: Need to specify keytab (-k) to use keytab name (-t)\n",
		progname);
	arg_error++;
    }

    if (use_keytab && !cname) {
	fprintf(stderr,
		"%s: Need to specify client name (-c) when using keytab (-k)\n",
		progname);
	arg_error++;
    }

#ifdef AFS_KRB5
    if (run_aklog && dont_run_aklog) {
	fprintf(stderr,	"%s: Cannot specify both -a and -A\n", progname);
	arg_error++;
    }
#endif /* AFS_KRB5 */

    if (arg_error) {
	fprintf(stderr, "%s: [<options>]\n"
		" Options are:\n"
#ifdef AFS_KRB5
		"   -a                       Run aklog after acquiring new credentials\n"
		"   -A                       Do not run aklog\n"
#endif /* AFS_KRB5 */
		"   -c <client name>         Client for credentials to convert\n"
		"   -C <target client>       Client to convert to\n"
		"   -h <server host>         Host where server is running\n"
		"   -i <input cache>         Specify cache to get credentials from\n"
		"   -k                       Use key from keytab to authenticate\n"
		"   -o <output cache>        Cache to write credentials out to\n"
		"   -p <server port>         Port where server is running\n"
		"   -s <service name>        Service for credentials to convert\n"
		"   -S <target service>      Service to convert to\n"
		"   -t <keytab file>         Keytab file to use\n"
		"   -u <username>            Specify owner of output cache\n"
		"   -v                       Verbose mode\n"
		"   -V                       Print version and exit\n",
		progname);
	exit(1);
    }


    /* Kerberos initialization */
    if (verbose)
	printf("Initializing Kerberos\n");

    /* Init context and error tables */
    retval = krb5_init_context(&context);
    if (retval) {
	com_err(progname, retval, "while initializing krb5");
	error_exit();
    }
    if (local_realm)
       krb5_set_default_realm(context,local_realm);
#ifdef HEIMDAL
    krb5_init_ets(context);
#if 0
    _et_list = context->et_list;
#endif
#endif

    /* XXX Why is this signal() call here? */
    (void) signal(SIGPIPE, SIG_IGN);

    /*
     * Set default ticket options
     */
    if (use_keytab)
	target_options |= KEYTAB_DEFAULT_TKT_OPTIONS;
    else
	target_options |= CACHE_DEFAULT_TKT_OPTIONS;

    /*
     * Get our cache ready for use if appropriate.
     */
    if (source_cache_name)
      retval = krb5_cc_resolve(context, source_cache_name,
			       &source_ccache);
    else
      retval = krb5_cc_default(context, &source_ccache);
    
    if (retval) {
      com_err(progname, retval, "resolving source cache %s",
	      (source_cache_name ? source_cache_name : "(default)"));
      error_exit();
    }

    /*
     * Get keytab ready if appropriate
     */
    if (use_keytab) {
      if (keytab_name) {
	if (retval = krb5_kt_resolve(context, keytab_name, &keytab)) {
	  com_err(progname, retval, "while parsing keytab \"%s\"",
		  keytab_name);
	  error_exit();
	}
      } else {
	if (retval = krb5_kt_default(context, &keytab)) {
	  com_err(progname, retval, "while getting default keytab");
	  error_exit();
	}
    }   

    }

    /*
     * Get our default realm
     */
#ifdef HEIMDAL
    if (retval = krb5_get_default_realm(context, &default_realm)) {
#else
    if (retval = krb5_get_default_realm(context, &(default_realm.data))) {
#endif
	com_err(progname, retval, "resolving default realm");
	error_exit();
    }
#ifndef HEIMDAL
    default_realm.length = strlen(default_realm.data);
#endif

    /*
     * If neither a target client name or target service name was
     * given, then target ticket is username for krbtgt
     */
    if (!target_cname && !target_sname) {
	struct passwd *pwd;

	pwd = getpwuid(geteuid());

	if (!pwd) {
	    perror("Password entry lookup failed");
	    error_exit();
	}

	target_cname = strdup(pwd->pw_name);
    }


    /*
     * Parse our client name. If none was given then use default for
     * our cache.
     */
    if (!use_keytab) {
	if (retval = krb5_cc_get_principal(context, source_ccache, &cprinc)) {
	    com_err(progname, retval, "while getting principal from cache");
	    error_exit();
	}
    } else {
	/* Client name must be provided with keytab. */
	if (retval = krb5_parse_name (context, cname, &cprinc)) {
	 com_err (progname, retval, "when parsing name %s", cname);
	 error_exit();
	}
    }
 	
    if (retval = krb5_unparse_name(context, cprinc, &cname)) {
	com_err (progname, retval, "when unparsing client");
	error_exit();
    }

    /*
     * Parse service name. If none was given then use krbtgt/<realm>@<realm>
     */
    if (sname == NULL) {
#ifdef HEIMDAL
	if (retval = krb5_build_principal(context,
					  &sprinc,
					  strlen(default_realm),
					  default_realm,
					  KRB5_TGS_NAME,
					  default_realm,
					  0)) {
#else
	if (retval = krb5_build_principal(context,
					  &sprinc,
					  default_realm.length,
					  default_realm.data,
					  KRB5_TGS_NAME,
					  default_realm.data,
					  0)) {
#endif
	    com_err (progname, retval,
		     "building default service principal");
	    error_exit();
	}
    } else {
	/* Service specified */
	if (retval = krb5_parse_name (context, sname, &sprinc)) {
	 com_err (progname, retval, "when parsing name %s", sname);
	 error_exit();
	}
    }
   
    if (retval = krb5_unparse_name(context, sprinc, &sname)) {
	 com_err (progname, retval, "when unparsing service");
	 error_exit();
    }

    /*
     * Parse our target client name. If none was given then use our
     * original client name.
     */
    if (!target_cname)
	target_cname = cname;

    /* Client name must be provided with keytab. */
    if (retval = krb5_parse_name (context, target_cname, &target_cprinc)) {
	com_err (progname, retval, "when parsing name %s", target_cname);
	error_exit();
    }
 	
    if (retval = krb5_unparse_name(context, target_cprinc, &target_cname)) {
	com_err (progname, retval, "when unparsing client");
	error_exit();
    }

    /*
     * Parse target service name. If none was given then use our original
     * service.
     */
    if (target_sname == NULL)
	target_sname = sname;

    /* Service specified */
    if (retval = krb5_parse_name (context, target_sname, &target_sprinc)) {
	com_err (progname, retval, "when parsing name %s", target_sname);
	error_exit();
    }
   
    if (retval = krb5_unparse_name(context, target_sprinc, &target_sname)) {
	com_err (progname, retval, "when unparsing service");
	error_exit();
    }


    if (verbose) {
	printf("Ticket to convert is %s for %s\n", cname, sname);
	printf("Target ticket is %s for %s\n", target_cname, target_sname);
    }

    /*
     * Ok, do we actually have anything to do?
     */
    if (krb5_principal_compare(context, cprinc, target_cprinc) &&
	krb5_principal_compare(context, sprinc, target_sprinc)) {
	fprintf(stderr, "%s: Nothing to do\n", progname);
	error_exit();
    }

    /*
     * Figure out our target cache. If we were given one then use
     * that. If no and we're were given a source cache then use that,
     * otherwise use the default.
     */
    if (!target_cache_name && source_cache_name)
	target_cache_name = source_cache_name;

    if (target_cache_name)
	retval = krb5_cc_resolve(context, target_cache_name,
				     &target_ccache);
    else
	retval = krb5_cc_default(context, &target_ccache);

    if (retval) {
	com_err(progname, retval, "resolving target cache %s",
		(target_cache_name ? target_cache_name : "(default)"));
	error_exit();
    }

    if (!target_cache_name) {
	target_cache_name = krb5_cc_default_name(context);

	if (strncmp(target_cache_name, "FILE:", 5) == 0)
	    target_cache_name += 5;
    }


    /*
     * If we're creating a new cache, figure out who should own it. If a
     * user was specified on the command line then use that user.
     */
    if (cache_owner) {	
	if (get_guid(cache_owner, &uid, &gid)) {
	    fprintf(stderr,
		    "Could not resolve uid and gid for %s\n", cache_owner);
	    perror("User lookup");
	    error_exit();
	}
    } else {
	/*
	 * If we're using a keytab, or if the target client differs from
	 * the original client then try to set the ownership to the
	 * target client, but fail silently.
	 *
	 * Not 100% sure this is what is desired, but we'll try it for now.
	 */
	if (use_keytab || strcmp(cname, target_cname)) {
	    char *realm;

	    cache_owner = strdup(target_cname);

	    if (realm = strchr(cache_owner, '@'))
		*realm = '\0';
	    
	    if (get_guid(cache_owner, &uid, &gid)) {
		/* Fail silently */
		uid = -1;
		gid = -1;
	    }
	}
    }
 
    /* Get credentials to be converted */
    if (use_keytab)
	retval = get_creds_with_keytab(context, cprinc, sprinc, target_options,
				       keytab, &creds);
    else
	retval = get_creds_with_ccache(context, cprinc, sprinc, target_options,
				       source_ccache, &creds);

    if (retval) {
	/* Detailed error message already printed */
	fprintf(stderr, "Couldn't get ticket - %s for %s",
		cname, sname);
	error_exit();
    }


    /*
     * Figure out hostname(s) of server(s). If user supplied a hostname, then
     * use that. Otherwise try all the Kerberos servers for this realm.
     */
    if (krb525_host) {
	/* User provided a hostname, so build list from that */
	krb525_hosts = (char **) malloc( 2 * sizeof(char *));

	if (!krb525_hosts) {
	    perror("malloc() failed");
	    error_exit();
	}

	krb525_hosts[0] = strdup(krb525_host);
	krb525_hosts[1] = NULL;

    };

    
    /* Convert the ticket */
    creds.client = cprinc;
    creds.server = sprinc;

    /* Add original ticket as capability */
#ifdef HEIMDAL
    creds.authdata.len = 1;
    creds.authdata.val = malloc(sizeof(*creds.authdata.val));
    creds.authdata.val[0].ad_type = KRB525_CAP_TICKET;
    creds.authdata.val[0].ad_data = creds.ticket;
#else
    creds.authdata = calloc(2, sizeof(krb5_authdata *));
    creds.authdata[0] = calloc(1, sizeof(krb5_authdata));

    creds.authdata[0]->magic = KV5M_AUTHDATA;
    creds.authdata[0]->ad_type = KRB525_CAP_TICKET;
    creds.authdata[0]->length = creds.ticket.length;
    creds.authdata[0]->contents = (krb5_octet *) creds.ticket.data;

    creds.authdata[1] = NULL;
#endif

    target_creds.client = target_cprinc;
    target_creds.server = target_sprinc;
    if(!use_keytab)
      retval = krb525_convert_with_ccache(context, 
					  krb525_hosts,
					  krb525_port,
					  source_ccache,
					  cname,
					  &creds,
					  &target_creds);
    else
      retval = krb525_convert_with_keytab(context,
					  krb525_hosts,
					  krb525_port,
					  keytab,
					  cname,
					  &creds,
					  &target_creds);

    if (retval) {
      fprintf(stderr, "Could not convert ticket: %s\n", krb525_convert_error);
      error_exit();
    }

    /* Ok now store the ticket */

    /*
     * Decide if we initialize the cache. If we came from a keytab or
     * we changed clients, or the target cache != source cache then
     * initialize the cache.
     *
     * XXX - Not 100% sure this is right.
     */
    if (use_keytab ||
	strcmp(cname, target_cname) ||
	!source_cache_name ||
	source_cache_name && strcmp(source_cache_name, target_cache_name))
      initialize_cache = 1;
    
    if (initialize_cache) {
      if (verbose)
	printf("Initializing cache\n");
      
      if (retval = krb5_cc_initialize(context, target_ccache,
				      target_cprinc)) {
	com_err(progname, retval, "initializing cache");
	error_exit();
      }
    }
    
    if (retval = krb5_cc_store_cred(context, target_ccache, &target_creds)) {
      com_err(progname, retval, "storing credentials");
      error_exit();
    }
    
    if(strstr(target_cache_name, "FILE:") != NULL) {
      const char *p = target_cache_name + 5;

      if (verbose && (uid != -1))
	printf("Changing owner of credentials cache %s to %s\n",
	       target_cache_name, cache_owner);
      if (chown(p, uid, gid)) {
	perror("Setting owner of credentials cache");
	error_exit();
      }
    }
    
#ifdef AFS_KRB5	
    /*
     * If we weren't explicitly told not to run or not to run
     * aklog then check the configuration file.
     */
    if (!run_aklog && !dont_run_aklog)
      krb5_appdefault_boolean(context, progname, &default_realm,
			      "krb5_run_aklog", 0, &run_aklog);
    
    if (run_aklog) {
      char *aklog_path;
      struct stat st;
      
      krb5_appdefault_string(context, progname, &default_realm,
			     "krb5_aklog_path", INSTALLPATH "bin/aklog",
			     &aklog_path);
      
      /*
       * Make sure it exists before we try to run it
       */
      if (stat(aklog_path, &st) == 0) {
	if (verbose)
	  printf("Running %s\n", aklog_path);
	
	system(aklog_path);
      } else {
	if (verbose)
	  printf("Can't run aklog: %s doesn't exist",
		 aklog_path);
      }
      
      free(aklog_path);
    }	
#endif /* AFS_KRB5 */
    


cleanup:
    /* XXX - lots of cleanup should be done here */

    if (krb525_hosts)
	free(krb525_hosts);

    exit(exit_code);
}



