/*
 * k5_db.c
 *
 * Deal with kerberos database.
 *
 * $Id: h_db.c,v 1.3 2015/09/11 18:12:59 kouril Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb5.h>
#include <hdb.h>
#include <sys/fcntl.h>
#include <com_err.h>

#include "h_db.h"

char k5_db_error[1024] = "No Error";

static struct hdb_dbinfo *db_info;

static void
format_db_error(krb5_context context, int ret, const char *format, ...)
{
	va_list ap;
	const char *msg = krb5_get_error_message(context, ret);

	va_start(ap, format);
	vsnprintf(k5_db_error, sizeof(k5_db_error), format, ap);
	va_end(ap);

	strncat(k5_db_error, ": ", sizeof(k5_db_error) - strlen(k5_db_error) - 1);
	strncat(k5_db_error, msg, sizeof(k5_db_error) - strlen(k5_db_error) - 1);

	return;
}

int
hdb_init_info(krb5_context context, const char *kdc_conf_file)
{
	krb5_error_code ret;
	char **filelist = NULL;
	krb5_context kdc_context = NULL;

	ret = krb5_copy_context(context, &kdc_context);
	if (ret) {
		format_db_error(context, ret, "hdb_init: krb5_copy_context() failed");
		return -1;
	}

	krb5_prepend_config_files(kdc_conf_file, NULL, &filelist);
	if (ret) {
		format_db_error(context, ret, "hdb_init: krb5_prepend_config_files() failed");
		goto end;
	}

	ret = krb5_set_config_files(kdc_context, filelist);
	if (ret) {
		format_db_error(context, ret, "hdb_init: krb5_set_config_files() fauled");
		goto end;
	}

	ret = hdb_get_dbinfo(kdc_context, &db_info);
	if (ret) {
		format_db_error(context, ret, "hdb_init: hdb_get_dbinfo() failed");
		goto end;
	}

 end:
	if (ret) {
		if (db_info)
			hdb_free_dbinfo(kdc_context, &db_info);
		db_info = NULL;
	}

	if (filelist)
		krb5_free_config_files(filelist);
	krb5_free_context(kdc_context);

	return (ret == 0) ? 0 : -1;
}

void
hdb_close_info(krb5_context context)
{
	/* the context is different from what was used for the init but it should be harmless */
	hdb_free_dbinfo(context, &db_info);
}

krb5_error_code
hdb_get_key(krb5_context context, krb5_principal princ, krb5_keyblock ** key, krb5_enctype ktype)
{
	hdb_entry_ex entry;
	krb5_error_code ret;
	Key *k;

	memset(&entry, 0, sizeof(entry));

	*key = (krb5_keyblock *) malloc(sizeof(krb5_keyblock));
	if (*key == NULL) {
		snprintf(k5_db_error, sizeof(k5_db_error), "malloc failed in hdb_get_key()");
		return -1;
	}

	ret = hdb_get_entry(context, princ, &entry);
	if (ret)
		return (ret);

	ret = hdb_enctype2key(context, &entry.entry, NULL, ktype, &k);
	if (ret) {
		format_db_error(context, ret, "hdb_enctype2key() failed");
		return (ret);
	};

	copy_EncryptionKey(&k->key, *key);

	free_hdb_entry(&entry.entry);
	return (0);
}

static krb5_error_code
create_db_handle(krb5_context context, struct hdb_dbinfo *info, krb5_realm realm, struct HDB **out)
{
	const char *mkey;
	krb5_error_code ret;
	struct hdb_dbinfo *di;
	struct HDB *db = NULL;

	di = NULL;
	while ((di = hdb_dbinfo_get_next(info, di)) != NULL) {
		if (strcmp(hdb_dbinfo_get_realm(context, di), realm) == 0)
			break;
	}

	if (di == NULL) {
		snprintf(k5_db_error, sizeof(k5_db_error), "No database available for realm %s", realm);
		return -1;
	}

	ret = hdb_create(context, &db, hdb_dbinfo_get_dbname(context, di));
	if (ret) {
		format_db_error(context, ret, "hdb_create() failed");
		return -1;
	}

	mkey = hdb_dbinfo_get_mkey_file(context, di);
	if (mkey) {
		ret = hdb_set_master_keyfile(context, db, mkey);
		if (ret) {
			format_db_error(context, ret, "hdb_set_master_keyfile() failed");
			goto end;
		}
	}

	*out = db;
	db = NULL;
	ret = 0;

 end:
	if (db)
		db->hdb_destroy(context, db);

	return ret;
}

krb5_error_code
hdb_get_entry(krb5_context context, krb5_principal princ, krb5_db_entry * entry)
{
	krb5_error_code ret;
	struct HDB *db = NULL;

	if (db_info == NULL) {
		snprintf(k5_db_error, sizeof(k5_db_error), "Database info not initialized");
		return -1;
	}

	ret = create_db_handle(context, db_info, princ->realm, &db);
	if (ret)
		return ret;

	ret = db->hdb_open(context, db, O_RDONLY, 0);
	if (ret) {
		format_db_error(context, ret, "Failed to open database");
		goto end;
	};

	ret = db->hdb_fetch_kvno(context, db, princ, HDB_F_DECRYPT, 0, entry);
	db->hdb_close(context, db);
	if (ret) {
		format_db_error(context, ret, "Error fetching principal");
		goto end;
	};

	ret = 0;

 end:
	db->hdb_destroy(context, db);

	return ret;
}
