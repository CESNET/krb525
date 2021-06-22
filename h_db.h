/*
 * k5_db.h
 *
 * $Id: h_db.h,v 1.2 2012/05/16 12:16:16 kouril Exp $
 */

#ifndef __H_DB_H
#define __H_DB_H

#include <krb5.h>
#include <kadm5/admin.h>
#include <com_err.h>

#include <config.h>
#include <hdb.h>

typedef hdb_entry_ex krb5_db_entry;

extern int hdb_init_info(krb5_context, const char *);

extern void hdb_close_info(krb5_context);

krb5_error_code hdb_get_key(krb5_context,
			    krb5_principal,
			    krb5_keyblock **,
			    krb5_enctype);

krb5_error_code hdb_get_entry(krb5_context,
			       krb5_principal,
			       krb5_db_entry *);


extern char k5_db_error[];


#endif /* __H_DB_H */
