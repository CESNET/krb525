## run automake on this file to generate Makefile.in

AUTOMAKE_OPTIONS = foreign

ACLOCAL = @ACLOCAL@ -I ./cf

bin_PROGRAMS = krb525
include_HEADERS = krb525.h krb525_convert.h
lib_LTLIBRARIES = libkrb525.la 
man_MANS = krb525.1 krb525.conf.5

noinst_HEADERS = auth_con.h netio.h parse_conf.h version.h \
	         h_db.h k5_db.h  server.h srv_conf.h capability.h

libkrb525_la_SOURCES = krb525_convert.c \
                       netio.c auth_con.c
libkrb525_la_LIBADD = $(K5LIBPATH) $(KRB5LIBS)

krb525_SOURCES = client.c 
krb525_LDADD = $(top_builddir)/.libs/libkrb525.a $(K5LIBPATH) $(KRB5LIBS) $(com_err_LIBS) $(SYSLIBS)

if HEIMDAL
libexec_PROGRAMS = krb525d
krb525d_SOURCES = server.c srv_conf.c parse_conf.c capability.c
EXTRA_krb525d_SOURCES = h_db.c k5_db.c

krb525d_LDADD = $(top_builddir)/.libs/libkrb525.a $(K5_DB_OBJ_FILES)  \
                $(K5LIBPATH) $(KRB5LIBS) \
                $(K5_DB_LIB_PATH) $(K5_DB_LIBS) \
		$(com_err_LIBS) \
		$(SERVERLIBS) $(SYSLIBS)

krb525d_DEPENDENCIES = $(K5_DB_OBJ_FILES)
man_MANS += krb525d.8
endif HEIMDAL

INCLUDES = -I. -I$(top_srcdir) $(K5_DB_INC_PATH) $(K5INCPATH) $(com_err_CFLAGS)
