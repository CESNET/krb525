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

static HDB *db;

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
hdb_init(krb5_context context, const char *kdc_conf_file)
{
  int ret;
  const char *database = NULL, *keyfile = NULL;
  krb5_config_section *cf = NULL;
  
  ret = krb5_config_parse_file(context, kdc_conf_file, &cf);
  if (ret) {
    format_db_error(context, ret, "hdb_init: krb5_config_parse_file() failed");
    return(-1);
  };

  database = krb5_config_get_string (context, cf, "krb525", "database", NULL);
  if(database == NULL) database = "/var/heimdal/heimdal.db";

  keyfile = krb5_config_get_string (context, cf, "krb525", "key-file", NULL);
  if(keyfile == NULL) keyfile = "/var/heimdal/m-key";

  ret = hdb_create(context, &db, database);
  if (ret) {
    format_db_error(context, ret, "hdb_init: hdb_create() failed");
    return(-1);
  };

  ret = hdb_set_master_keyfile(context, db, keyfile);
  if (ret) {
    format_db_error(context, ret, "hdb_init: hdb_set_master_key() failed");
    return(-1);
  };

  return 0;
}

void hdb_close(krb5_context context) {
#if 0
  if(db) 
    db->close(context, db);
#endif
}

krb5_error_code
hdb_get_key(krb5_context context,
	    krb5_principal princ,
	    krb5_keyblock **key,
	    krb5_enctype ktype)
{
  hdb_entry_ex entry;
  krb5_error_code ret;
  Key  *k;

  memset(&entry, 0, sizeof(entry));

  *key = (krb5_keyblock *) malloc(sizeof(krb5_keyblock));
  if (*key == NULL) {
    snprintf(k5_db_error, sizeof(k5_db_error), "malloc failed in hdb_get_key()");
    return -1;
  }

  ret = hdb_get_entry(context, princ, &entry);
  if (ret) return(ret);

  ret = hdb_enctype2key(context, &entry.entry, NULL, ktype, &k);
  if (ret) {
    format_db_error(context, ret, "hdb_enctype2key() failed");
    return(ret);
  };

  copy_EncryptionKey(&k->key, *key);

  free_hdb_entry(&entry.entry);
  return(0);
}

krb5_error_code
hdb_get_entry(krb5_context context,
	      krb5_principal princ,
	      krb5_db_entry *entry)
{
  krb5_error_code ret;

  if (db) {
    ret = db->hdb_open(context, db, O_RDONLY, 0);
    if (ret) {
      format_db_error(context, ret, "Failed to open database");
      return(ret);
    };
    ret = db->hdb_fetch_kvno(context, db, princ, HDB_F_DECRYPT, 0, entry);
    db->hdb_close(context, db);
    if (ret) {
      format_db_error(context, ret, "Error fetching principal");
      return(ret);
    };
  } else {
    snprintf(k5_db_error, sizeof(k5_db_error), "database not initialized");
    return(-1);
  };
  return(0);
}

