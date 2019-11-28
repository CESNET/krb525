/*
 * A simple client to renew tickets from PBS. It is a simplified version of the
 * krb525 client that outputs plain credentials to be send to PBS moms. The
 * credentials produced are NOT encrypted.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <krb5.h>
#include <parse_time.h>

#include "krb525_convert.h"
#include "base64.h"

#define PBS_SERVICE_NAME "pbs"
#define VAR_NAME_KEYTAB "PBS_K525_KEYTAB"
#define ENV_VAR_USER "PBS_K525_USER"

static krb5_error_code
prepare_ccache(krb5_context context, krb5_creds *creds, krb5_ccache *cc)
{
	krb5_error_code ret;
	krb5_ccache ccache = NULL;

	ret = krb5_cc_new_unique(context, "MEMORY", NULL, &ccache);
	if (ret) {
		fprintf(stderr, "krb5_cc_new_unique() failed (%s)",
				krb5_get_error_message(context, ret));
		goto end;
	}

	ret = krb5_cc_initialize(context, ccache, creds->client);
	if (ret) {
		fprintf(stderr, "krb5_cc_initialize() failed (%s)",
				krb5_get_error_message(context, ret));
		goto end;
	}

	ret = krb5_cc_store_cred(context, ccache, creds);
	if (ret) {
		fprintf(stderr, "krb5_cc_store_cred() failed (%s)",
				krb5_get_error_message(context, ret));
		goto end;
	}

	*cc = ccache;
	ccache = NULL;

end:
	if (ccache)
		krb5_cc_destroy(context, ccache);

	return ret;
}

static krb5_error_code
get_init_creds(krb5_context context, int lifetime, krb5_creds *creds)
{
	krb5_error_code ret;
	krb5_get_init_creds_opt *opt = NULL;
	krb5_keytab keytab = NULL;
	krb5_principal pbs_service = NULL;

	if (getenv(ENV_VAR_USER))
		ret = krb5_parse_name(context, getenv(ENV_VAR_USER), &pbs_service);
	else
		ret = krb5_sname_to_principal(context, NULL, PBS_SERVICE_NAME, KRB5_NT_SRV_HST, &pbs_service);
	if (ret) {
		fprintf(stderr, "Preparing k525 client principal failed: %s.\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	if (getenv(VAR_NAME_KEYTAB))
		ret = krb5_kt_resolve(context, getenv(VAR_NAME_KEYTAB), &keytab);
	else
		ret = krb5_kt_default(context, &keytab);
	if (ret) {
		fprintf(stderr, "Cannot open keytab: %s\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	ret = krb5_get_init_creds_opt_alloc(context, &opt);
	if (ret) {
		fprintf(stderr, "krb5_get_init_creds_opt_alloc() failed (%s)\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	krb5_get_init_creds_opt_set_forwardable(opt, 1);
	krb5_get_init_creds_opt_set_tkt_life(opt, lifetime);

	ret = krb5_get_init_creds_keytab(context, creds, pbs_service, keytab, 0, NULL, opt);
	if (ret) {
		fprintf(stderr, "krb5_get_init_creds_keytab() failed (%s)\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

end:
	if (opt)
		krb5_get_init_creds_opt_free(context, opt);
	if (pbs_service)
		krb5_free_principal(context, pbs_service);
	if (keytab)
		krb5_kt_close(context, keytab);

	return (ret);
}

static krb5_error_code
init_auth_context(krb5_context context, krb5_auth_context *auth_context)
{
	int32_t flags;
	krb5_error_code ret;

	ret = krb5_auth_con_init(context, auth_context);
	if (ret) {
		fprintf(stderr, "krb5_auth_con_init() failed: %s.\n",
				krb5_get_error_message(context, ret));
		return ret;
	}

	krb5_auth_con_getflags(context, *auth_context, &flags);
	/* We disable putting times in the message so the message could be cached
	   and re-sent in the future. If caching isn't needed, it could be enabled
	   again (but read below) */
	/* N.B. The semantics of KRB5_AUTH_CONTEXT_DO_TIME applied in
	   krb5_fwd_tgt_creds() seems to differ between Heimdal and MIT. MIT uses
	   it to (also) enable replay cache checks (that are useless and
	   troublesome for us). Heimdal uses it to just specify whether or not the
	   timestamp is included in the forwarded message. */
	flags &= ~(KRB5_AUTH_CONTEXT_DO_TIME);
#ifdef HEIMDAL
	flags |= KRB5_AUTH_CONTEXT_CLEAR_FORWARDED_CRED;
#endif
	krb5_auth_con_setflags(context, *auth_context, flags);

	return 0;
}

/* Creates a KRB_CRED message containing serialized credentials. The credentials
   aren't encrypted, relying on the protection by application protocol, see RFC 6448 */
static krb5_error_code
get_fwd_creds(krb5_context context, krb5_creds *creds, krb5_data *creds_data)
{
	krb5_error_code ret;
	krb5_auth_context auth_context = NULL;
	krb5_ccache ccache = NULL;

	ret = init_auth_context(context, &auth_context);
	if (ret)
		goto end;

	ret = prepare_ccache(context, creds, &ccache);
	if (ret)
		goto end;

	/* It's necessary to pass a hostname to pass the code (Heimdal segfaults
	 * otherwise), MIT tries to get a credential for the host if session keys
	 * doesn't exist. It should be noted that the krb5 configuration should set
	 * the no-address flags for tickets (otherwise tickets couldn't be cached,
	 * wouldn't work with multi-homed machines etc.).
     */
	ret = krb5_fwd_tgt_creds(context, auth_context, "localhost", creds->client,
			NULL, ccache, 1, creds_data);
	if (ret) {
		fprintf(stderr, "krb5_fwd_tgt_creds() failed: %s.\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

end:
	if (auth_context)
		krb5_auth_con_free(context, auth_context);
	if (ccache)
		krb5_cc_destroy(context, ccache);

	return (ret);
}

static int
output_creds(krb5_context context, krb5_creds *target_creds)
{
	krb5_error_code ret;
	krb5_auth_context auth_context = NULL;
	krb5_creds **creds = NULL, **c;
	char *encoded = NULL;
	krb5_data *creds_data;

	creds_data = calloc(1,sizeof(*creds_data));
	if (!creds_data) return ENOMEM;

	ret = get_fwd_creds(context, target_creds, creds_data);
	if (ret)
		goto end;

	ret = init_auth_context(context, &auth_context);
	if (ret)
		goto end;

	encoded = k5_base64_encode(creds_data->data, creds_data->length);
	if (encoded == NULL) {
		fprintf(stderr, "failed to encode the credentials, exiting.\n");
		ret = -1;
		goto end;
	}

	ret = krb5_rd_cred(context, auth_context, creds_data, &creds, NULL);
	if (ret) {
		fprintf(stderr, "krb5_rd_cred() failed: %s.\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	printf("Type: Kerberos\n");
	/* there might be multiple credentials exported, which we silently ignore */
	printf("Valid until: %ld\n", creds[0]->times.endtime);
	printf("%s\n", encoded);

	ret = 0;

end:
	krb5_free_data(context, creds_data);
	if (auth_context)
		krb5_auth_con_free(context, auth_context);
	if (encoded)
		free(encoded);
	if (creds) {
		for (c = creds; c != NULL && *c != NULL; c++)
			krb5_free_creds(context, *c);
		free(creds);
	}

	return (ret);
}

static krb5_error_code
convert_creds(krb5_context context, krb5_creds *initiator_creds, krb5_creds *target_creds)
{
	krb5_error_code ret;
	krb5_ccache ccache = NULL;
	krb5_creds creds;
	krb5_creds *source_creds = NULL;
	char *realm;
	size_t realm_len;

	memset(&creds, 0, sizeof(creds));

#ifdef HEIMDAL
	realm = target_creds->server->realm;
	realm_len = strlen(realm);
#else
	realm = target_creds->server->realm.data;
	realm_len = target_creds->server->realm.length;
#endif

	ret = prepare_ccache(context, initiator_creds, &ccache);
	if (ret)
		goto end;

	/* Source credentials must be from the target realm. Since we're converting
	   our credentials (i.e. source.client == initiator), we just obtain a TGT for the final
	   realm (to work with cross-realms) and have it converted. We use the existing ccache
	   to store all the credentials. */

	ret = krb5_copy_principal(context, initiator_creds->client, &creds.client);
	if (ret) {
		fprintf(stderr, "krb5_copy_principal() failed: %s.\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	ret = krb5_build_principal(context, &creds.server,
			realm_len, realm, KRB5_TGS_NAME, realm, NULL);
	if (ret) {
		fprintf(stderr, "krb5_build_principal() failed: %s.\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	ret = krb5_get_credentials(context, 0, ccache, &creds, &source_creds);
	if (ret) {
		fprintf(stderr, "krb5_get_credentials() failed: %s.\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	ret = krb525_get_creds_ccache(context, ccache, source_creds, target_creds);
	if (ret) {
		fprintf(stderr, "Failed to translate ticket: %s.\n", krb525_convert_error);
		goto end;
	}

end:
	krb5_free_cred_contents(context, &creds);
	if (ccache)
		krb5_cc_destroy(context, ccache);
	if (source_creds)
		krb5_free_creds(context, source_creds);

	return (ret);
}

static int
doit(const char *user, int lifetime)
{
	int ret;
	krb5_creds my_creds, target_creds;
	krb5_context context = NULL;
	char *realm;

	memset((char *)&my_creds, 0, sizeof(my_creds));
	memset((char *)&target_creds, 0, sizeof(target_creds));

	ret = krb5_init_context(&context);
	if (ret) {
		fprintf(stderr, "Cannot initialize Kerberos, exiting.\n");
		return(ret);
	}

	ret = get_init_creds(context, lifetime, &my_creds);
	if (ret)
		goto end;

	ret = krb5_parse_name(context, user, &target_creds.client);
	if (ret) {
		fprintf(stderr, "krb5_parse_name failed: %s.\n",
				krb5_get_error_message(context, ret));
		goto end;
	}

	realm = strchr(user, '@');
	if (realm == NULL) {
		fprintf(stderr, "The realm of the user must be specified.\n");
		ret = -1;
		goto end;
	}
	realm++;

	ret = krb5_build_principal(context, &target_creds.server,
			strlen(realm), realm, KRB5_TGS_NAME, realm, NULL);
	if (ret) {
		fprintf(stderr, "krb5_build_principal() for %s failed: %s.\n", user,
				krb5_get_error_message(context, ret));
		goto end;
	}

	ret = convert_creds(context, &my_creds, &target_creds);
	if (ret)
		goto end;

	ret = output_creds(context, &target_creds);

end:
	krb5_free_cred_contents(context, &my_creds);
	krb5_free_cred_contents(context, &target_creds);
	krb5_free_context(context);

	return (ret);
}

int
main(int argc, char *argv[])
{
	char *progname;
	int ret;
	int ch;
	int lifetime = 24*3600;

	if ((progname = strrchr(argv[0], '/')))
		progname++;
	else
		progname = argv[0];

	 opterr = 0;
	
	 while ((ch = getopt(argc, argv, "l:")) != EOF)
		switch (ch) {
		case 'l':
		    lifetime = parse_time(optarg, "s");
		    if (lifetime < 0) {
			fprintf(stderr, "error: unparsable lifetime\n");
			exit(1);

		    }
		    break;
	       
		case '?':
		default:
		    opterr++;
		    break;
		}

	if (opterr || optind >= argc) {
		fprintf(stderr, "Usage: %s [ -l lifetime ] principal_name\n", progname);
		exit(1);
	}

	ret = doit(argv[optind], lifetime);

	if (ret != 0)
		ret = 1;
	return(ret);
}
