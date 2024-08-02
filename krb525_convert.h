/*
 * krb525_convert.h
 *
 *  - convert given credential into another credential
 *
 * 	$Id: krb525_convert.h,v 1.1.1.1 2009/11/13 09:13:02 kouril Exp $	
 */

#ifndef _KRB525_CONVERT_H_
#define _KRB525_CONVERT_H_

#include <krb5.h>

extern char krb525_convert_error[];

krb5_error_code 
krb525_convert_with_ccache(krb5_context context,
			   char         **hosts,
			   int          port,
			   int          timeout,
			   krb5_ccache  ccache,
			   char         *cname,
			   krb5_creds   *in_creds,
			   krb5_creds   *out_creds);

krb5_error_code
krb525_convert_with_keytab(krb5_context context,
			   char         **hosts,
			   int          port,
			   krb5_keytab  keytab,
			   char         *cname,
			   krb5_creds   *in_creds,
			   krb5_creds   *out_creds);
			   
krb5_error_code
krb525_get_creds_ccache(krb5_context context,
			krb5_ccache  ccache,
			krb5_creds  *in_creds,
			krb5_creds  *out_creds,
			int         timeout);

krb5_error_code
krb525_get_creds_keytab(krb5_context context,
			krb5_keytab  keytab,
			char         *cname,
			krb5_creds   *in_creds,
			krb5_creds   *out_creds);

			    
enum { KRB525_CAP_TICKET = 321 };

#endif
