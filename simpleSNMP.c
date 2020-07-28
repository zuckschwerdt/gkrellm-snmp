/* SNMP reader plugin for GKrellM.
|  Copyright (C) 2000-2020  Christian W. Zuckschwerdt <zany@triq.net>
|  Copyright (C) 2009  Alfred Ganz alfred-ganz:at:agci.com
|
|  Author:  Christian W. Zuckschwerdt  <zany@triq.net>  http://triq.net/
|  Latest versions might be found at:  http://gkrellm.net/
|
| GKrellM_SNMP is free software; you can redistribute it and/or
| modify it under the terms of the GNU General Public License as
| published by the Free Software Foundation; either version 2 of
| the License, or (at your option) any later version.
|
| In addition, as a special exception, the copyright holders give
| permission to link the code of this program with the OpenSSL library,
| and distribute linked combinations including the two.
| You must obey the GNU General Public License in all respects
| for all of the code used other than OpenSSL.  If you modify
| file(s) with this exception, you may extend this exception to your
| version of the file(s), but you are not obligated to do so.  If you
| do not wish to do so, delete this exception statement from your
| version.  If you delete this exception statement from all source
| files in the program, then also delete it here.

| This program is distributed in the hope that it will be useful,
| but WITHOUT ANY WARRANTY; without even the implied warranty of
| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
| GNU General Public License for more details.

| You should have received a copy of the GNU General Public License
| along with GKrellM_SNMP. If not, see <http://www.gnu.org/>.
*/


/* In case of SNMP trouble: #define DEBUG_SNMP */

#include <stdio.h>

#ifdef UCDSNMP
#include <ucd-snmp/asn1.h>
#include <ucd-snmp/mib.h>
#include <ucd-snmp/parse.h>
#include <ucd-snmp/snmp.h>
#include <ucd-snmp/snmp_api.h>
#include <ucd-snmp/snmp_client.h>
#include <ucd-snmp/snmp_impl.h> /* special ASN types */
#ifdef DEBUG_SNMP
#include <ucd-snmp/snmp_debug.h>
#endif /* DEBUG_SNMP */
#else /* UCDSNMP */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#define RECEIVED_MESSAGE NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE
#define TIMED_OUT NETSNMP_CALLBACK_OP_TIMED_OUT
#ifdef DEBUG_SNMP
#include <net-snmp/snmp_debug.h>
#endif /* DEBUG_SNMP */
#endif /* UCDSNMP */

#include <sys/time.h>

#include <simpleSNMP.h>


/* #define STREAM *//* test for Lou Cephyr */


static gchar *
strdup_uptime (glong time)
{
    gint up_d, up_h, up_m;

    up_d = time/100/60/60/24;
    up_h = (time/100/60/60) % 24;
    up_m = (time/100/60) % 60;

    return g_strdup_printf ("%dd %d:%d", up_d, up_h, up_m );
}

#ifdef UCDSNMP_PRE_4_2

/*
 * snmp_parse_args.c
 */

static oid
*snmp_parse_oid(const char *argv,
		oid *root,
		size_t *rootlen)
{
  size_t savlen = *rootlen;
  /* printf("parse_oid: read_objid\n"); */
  if (read_objid(argv,root,rootlen)) {
    return root;
  }
  *rootlen = savlen;
  /* printf("parse_oid: get_node\n"); */
  if (get_node(argv,root,rootlen)) {
    return root;
  }
  *rootlen = savlen;
  /* printf("parse_oid: wildly parsing\n"); */
  if (get_wild_node(argv,root,rootlen)) {
    return root;
  }
  return NULL;
}

#endif /* UCDSNMP_PRE_4_2 */

void
simpleSNMPinit()
{

#ifdef DEBUG_SNMP
    debug_register_tokens("all");
    snmp_set_do_debugging(1);
#endif /* DEBUG_SNMP */

    netsnmp_init_mib();
}

gchar *
simpleSNMPprobe(gchar *peer, gint port, gint vers, gchar *community)
{
    oid sysDescr[MAX_OID_LEN];
    size_t sysDescr_length;
    oid sysObjectID[MAX_OID_LEN];
    size_t sysObjectID_length;
    oid sysUpTime[MAX_OID_LEN];
    size_t sysUpTime_length;
    oid sysContact[MAX_OID_LEN];
    size_t sysContact_length;
    oid sysName[MAX_OID_LEN];
    size_t sysName_length;
    oid sysLocation[MAX_OID_LEN];
    size_t sysLocation_length;

    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;

    int count;
    int status;

    char textbuf[1024]; 
    char *result = NULL;
    char *tmp = NULL;

    /* transform interesting OIDs */
    sysDescr_length = MAX_OID_LEN;
    if (!snmp_parse_oid("system.sysDescr.0", sysDescr, &sysDescr_length))
	    printf("error parsing oid: system.sysDescr.0\n");

    sysObjectID_length = MAX_OID_LEN;
    if (!snmp_parse_oid("system.sysObjectID.0", sysObjectID, &sysObjectID_length))
	    printf("error parsing oid: system.sysObjectID.0\n");

    sysUpTime_length = MAX_OID_LEN;
    if (!snmp_parse_oid("system.sysUpTime.0", sysUpTime, &sysUpTime_length))
	    printf("error parsing oid: system.sysUpTime.0\n");

    sysContact_length = MAX_OID_LEN;
    if (!snmp_parse_oid("system.sysContact.0", sysContact, &sysContact_length))
	    printf("error parsing oid: system.sysContact.0\n");

    sysName_length = MAX_OID_LEN;
    if (!snmp_parse_oid("system.sysName.0", sysName, &sysName_length))
	    printf("error parsing oid: system.sysName.0\n");

    sysLocation_length = MAX_OID_LEN;
    if (!snmp_parse_oid("system.sysLocation.0", sysLocation, &sysLocation_length))
	    printf("error parsing oid: system.sysLocation.0\n");

    /* initialize session to default values */
    snmp_sess_init( &session );

    session.version = vers == 2 ? SNMP_VERSION_2c : SNMP_VERSION_1;
    session.community = (guchar *)community;
    session.community_len = strlen(community);
    session.peername = peer;

#ifdef STREAM
    session.flags |= SNMP_FLAGS_STREAM_SOCKET;
    fprintf (stderr, "local port set to: %d\n", session.local_port);
#endif /* STREAM */

    /* 
     * Open an SNMP session.
     */
    ss = snmp_open(&session);
    if (ss == NULL){
      fprintf (stderr, "local port set to: %d\n", session.local_port);
      snmp_sess_perror("snmp_open", &session);
      exit(1);
    }

    /* 
     * Create PDU for GET request and add object names to request.
     */
    pdu = snmp_pdu_create(SNMP_MSG_GET);

    snmp_add_null_var(pdu, sysDescr, sysDescr_length);
    snmp_add_null_var(pdu, sysObjectID, sysObjectID_length);
    snmp_add_null_var(pdu, sysUpTime, sysUpTime_length);
    snmp_add_null_var(pdu, sysContact, sysContact_length);
    snmp_add_null_var(pdu, sysName, sysName_length);
    snmp_add_null_var(pdu, sysLocation, sysLocation_length);

    /* 
     * Perform the request.
     *
     * If the Get Request fails, note the OID that caused the error,
     * "fix" the PDU (removing the error-prone OID) and retry.
     */
retry:
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
        /* just render all vars */
        for(vars = response->variables; vars; vars = vars->next_variable) {
	    snprint_variable(textbuf, 1023, vars->name, vars->name_length, vars);
	    textbuf[1023] = '\0';
	    if (result) {
	        tmp = result;
		result = g_strdup_printf("%s\n%s\n", tmp, textbuf);
		g_free(tmp);
	    } else {
		result = g_strdup_printf("%s\n", textbuf);
	    }
	}
                              
      } else {
        fprintf(stderr, "Error in packet\nReason: %s\n",
                snmp_errstring(response->errstat));

        if (response->errstat == SNMP_ERR_NOSUCHNAME){
          fprintf(stderr, "This name doesn't exist: ");
          for(count = 1, vars = response->variables; 
                vars && count != response->errindex;
                vars = vars->next_variable, count++)
            /*EMPTY*/ ;
          if (vars)
            fprint_objid(stderr, vars->name, vars->name_length);
          fprintf(stderr, "\n");
        }

        /* retry if the errored variable was successfully removed */
        pdu = snmp_fix_pdu(response, SNMP_MSG_GET);
        snmp_free_pdu(response);
        response = NULL;
        if (pdu != NULL)
          goto retry;

      }  /* endif -- SNMP_ERR_NOERROR */

    } else if (status == STAT_TIMEOUT){
        snmp_close(ss);
        return g_strdup_printf("Timeout: No Response from %s.\n", session.peername);

    } else {    /* status == STAT_ERROR */
      fprintf (stderr, "local port set to: %d\n", session.local_port);
      snmp_sess_perror("STAT_ERROR", ss);
      snmp_close(ss);
      return NULL;

    }  /* endif -- STAT_SUCCESS */

    if (response)
      snmp_free_pdu(response);
    snmp_close(ss);

    return result;
}

static int
snmp_input(int op,
	   struct snmp_session *session,
	   int reqid,
	   struct snmp_pdu *pdu,
	   void *magic)
{
    struct variable_list *vars;
    gint asn1_type[MAX_OID_STR];
    gchar *result[MAX_OID_STR];
    glong result_n[MAX_OID_STR];
    gchar *error = NULL;
    input_data *new_data = NULL;
    gint num_pdu = 0;
    gint i = 0;

    if (op == RECEIVED_MESSAGE) {

        if (pdu->errstat == SNMP_ERR_NOERROR) {

	    /*
		fprintf(stderr, "recv from (@ %ld): %s type: %d\n",
	            	pdu->time, session->peername, pdu->variables->type);
	    */

            for(vars = pdu->variables; vars; vars = vars->next_variable) {
		/*
		    fprintf(stderr, "recv[%d] type: %d\n", i, vars->type);
		*/
                switch (vars->type) {
		case ASN_TIMETICKS:
		    asn1_type[i] = ASN_TIMETICKS;
		    result_n[i] = *vars->val.integer;
		    result[i] = strdup_uptime (result_n[i]);
		    break;
		case ASN_OCTET_STR: /* value is a string */
		    asn1_type[i] = ASN_OCTET_STR;
		    result[i] = g_strndup((gchar *)vars->val.string, 
								vars->val_len);
		    /* Add as ASN_INTEGER if it converts properly */
		    if (sscanf (result[i], "%lu", &result_n[i]) == 1) {
			asn1_type[i] = ASN_INTEGER;
		    } else {
			result_n[i] = 0;
		    }
		    /*
			fprintf(stderr, "recv  result_n: %lu\n", result_n);
		    */
		    break;
		case ASN_INTEGER: /* value is a integer */
		case ASN_COUNTER: /* use as if it were integer */
		case ASN_UNSIGNED: /* use as if it were integer */
		    asn1_type[i] = ASN_INTEGER;
		    result_n[i] = *vars->val.integer;
		    result[i] = g_strdup_printf("%ld", *vars->val.integer);
		    break;
		case ASN_COUNTER64:
		    asn1_type[i] = ASN_INTEGER;
		    result_n[i] = vars->val.counter64->low; // TODO: this ignores upper 32 "high" bits
#ifdef G_GUINT64_FORMAT
            result[i] = g_strdup_printf("%" G_GUINT64_FORMAT, ((guint64)vars->val.counter64->high << 32) | vars->val.counter64->low);
#else
		    result[i] = g_strdup_printf("%lu", vars->val.counter64->low);
#endif
		    break;
		default:
		    i--;
		    fprintf(stderr, "recv unknown ASN type: %d - "
				"please report to zany@triq.net\n", vars->type);
		}
		i++;
	    }
	    num_pdu = i;
        } else {
            error = g_strdup_printf("Error in packet, Reason: %s",
				     snmp_errstring(pdu->errstat));

	    if (pdu->errstat == SNMP_ERR_NOSUCHNAME) {
		error = g_strdup_printf("Error! This name doesn't exist!");
            }
        }


    } else if (op == TIMED_OUT){
        error = g_strdup_printf("Error! SNMP Timeout.");
    }
    /* we use session's callback magic to pass back data */
    if (session->callback_magic) {
	new_data = session->callback_magic;
	if (error) {
	    if (new_data->error) g_free(new_data->error);
	    new_data->error = error;
	} else {
	    for (i = 0; i < num_pdu; i++) {
		if (new_data->sample[i])
		    g_free(new_data->sample[i]);
		new_data->asn1_type[i] = asn1_type[i];
		new_data->sample[i] = result[i];
		new_data->sample_n[i] = result_n[i];
		/*
		    print_objid (name, name_length);
		    print_objid (sysUpTime, sysUpTime_length);
		*/
	    }
	}
	/* Mark that there is new data */
	new_data->num_sample = num_pdu;
	new_data->new = 1;
    }
    return 1;
}

void
simpleSNMPupdate()
{
    int count;
    int numfds, block;
    fd_set fdset;
    struct timeval timeout, *tvp;

    numfds = 0;
    FD_ZERO(&fdset);
    block = 0;
    tvp = &timeout;
    timerclear(tvp);
    tvp->tv_sec = 0;
    snmp_select_info(&numfds, &fdset, tvp, &block);
	/*        if (block == 1)
		  tvp = NULL; */ /* block without timeout */
    count = select(numfds, &fdset, 0, 0, tvp);
    if (count > 0){
        snmp_read(&fdset);
    } else switch(count){
        case 0:
            snmp_timeout();
	    break;
        case -1:
	    fprintf(stderr, "snmp error on select\n");
	    break;
        default:
            fprintf(stderr, "select returned %d\n", count);
    }
}

struct snmp_session *
simpleSNMPopen(gchar *peername,
	       gint port,
	       gint vers,
	       gchar *community,
	       void *data)
{
    struct snmp_session session, *ss;

    /*
     * initialize session to default values
     */
    snmp_sess_init( &session );

    session.version = vers == 2 ? SNMP_VERSION_2c : SNMP_VERSION_1;
    session.community = (guchar *)community;
    session.community_len = strlen(community);
    session.peername = peername;
    session.remote_port = port;

    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;

    session.callback = snmp_input;
    session.callback_magic = data; /* most likely a Reader */
    session.authenticator = NULL;

#ifdef STREAM
    session.flags |= SNMP_FLAGS_STREAM_SOCKET;
#endif

    /* 
     * Open an SNMP session.
     */
    ss = snmp_open(&session);
    if (ss == NULL){
	input_data *new_data = data;
	gint sys_errno;
	gint snmp_errno;
	gchar *error_msg = NULL;
	snmp_error (&session, &sys_errno, &snmp_errno, &error_msg);
	if (new_data->error) g_free (new_data->error);
	new_data->error = error_msg;
	new_data->new = 1;
    }

    return ss;
}

gint
simpleSNMPsend(struct snmp_session *session, gchar **oid_str, gint num_oid_str)
{
    struct snmp_pdu *pdu;
    oid name[num_oid_str][MAX_OID_LEN];
    size_t name_length[num_oid_str];
    gchar *error = NULL;
    input_data *new_data = NULL;
    gint i;

    /* Prepare the objid's */
    for (i = 0; i < num_oid_str; i++) {
	name_length[i] = MAX_OID_LEN;
	if (!snmp_parse_oid(oid_str[i], name[i], &name_length[i])) {
	    error = g_strdup_printf("error parsing oid: %s", oid_str[i]);
	    break;
	}
    }

    if (session->callback_magic) {
	new_data = session->callback_magic;
	if (error) {
	    if (new_data->error) g_free (new_data->error);
	    new_data->error = error;
	    new_data->new = 1;
	}
    }
    if (!error) {
	/* 
	 * Create PDU for GET request and add object names to request.
	 */
	pdu = snmp_pdu_create(SNMP_MSG_GET);

	/* 
	 * First insert uptime request into PDU, then the actual object's
	 */

	/*
	    fprintf (stderr, "Preparing send for %d vars\n", num_oid_str);
	*/
	for (i = 0; i < num_oid_str; i++) {
	    snmp_add_null_var(pdu, name[i], name_length[i]);
	    /*
		print_objid (name[i], name_length[i]);
	    */
	}

	/* 
	 * Perform the request.
	 */

	if (!snmp_send(session, pdu)) {
	    error = g_strdup_printf("snmp_send() returned error\n");
	    if (session->callback_magic) {
		new_data = session->callback_magic;
		if (new_data->error) g_free (new_data->error);
		new_data->error = error;
		new_data->new = 1;
	    }
	}
    }

    return (!error);
}

void 
simpleSNMPclose(struct snmp_session *session)
{

    snmp_close(session);
}

gint
simpleSNMPcheck_oid(const char *argv)
{
    /* Don't really know what is really appropriate here, the 5.4.2 
     *	documentation seems to indicate that this is the most inclusive, 
     *	but the wiki example suggests using read_objid().
     */

    oid     objid[MAX_OID_LEN];
    size_t  objid_length = MAX_OID_LEN;
    oid     *result = NULL;

    result = snmp_parse_oid(argv, objid, &objid_length);

    return (result != NULL);
}

