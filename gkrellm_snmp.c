/* SNMP reader plugin for GKrellM 
|  Copyright (C) 2000-2002  Christian W. Zuckschwerdt <zany@triq.net>
|
|  Author:  Christian W. Zuckschwerdt  <zany@triq.net>  http://triq.net/
|  Latest versions might be found at:  http://gkrellm.net/
|
| This program is free software; you can redistribute it and/or
| modify it under the terms of the GNU General Public License
| as published by the Free Software Foundation; either version 2
| of the License, or (at your option) any later version.
|
| This program is distributed in the hope that it will be useful,
| but WITHOUT ANY WARRANTY; without even the implied warranty of
| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
| GNU General Public License for more details.
|
| You should have received a copy of the GNU General Public License
| along with this program; if not, write to the Free Software
| Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

/* Installation:
|
|     make
|     make install
|      or without using superuser privileges
|     make install-user
|
*/

/* In case of SNMP trouble: #define DEBUG_SNMP */

#include <stdio.h>
#include <sys/types.h>

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

#include <sys/time.h>


#include <gkrellm/gkrellm.h>

/* #define STREAM /* test for Lou Cephyr */


#define SNMP_PLUGIN_MAJOR_VERSION 0
#define SNMP_PLUGIN_MINOR_VERSION 17

#define PLUGIN_CONFIG_NAME   "SNMP"
#define PLUGIN_CONFIG_KEYWORD   "snmp_monitor"


typedef struct Reader Reader;

struct Reader {
	Reader			*next;
	gchar			*label;
	gchar			*peer;
	gint			port;
	gchar			*community;
	gchar			*oid_str;
	oid			objid[MAX_OID_LEN];
	size_t			objid_length;
	gchar			*unit;
	gint			divisor;
	gboolean		scale;
	gint			delay;
	gboolean		active;
	gboolean		delta;
	gint			asn1_type;
	gchar			*sample;
	u_long			sample_n;
	u_long			sample_time;
	gchar			*old_sample;
	u_long			old_sample_n;
	u_long			old_sample_time;
	gchar			*error;
	gchar			*old_error;
	struct snmp_session	*session;

	Panel			*panel;
	GtkTooltips             *tooltip;

	Chart			*chart;
	ChartData		*chart_data;
	ChartConfig		*chart_config;
};


/*
 * caller needs to free the returned gchar*
 */

gchar *
scale(u_long num)
{
    if (num > 6000000000)
	return g_strdup_printf("%ldG", num/1024/1024/1024);
    if (num > 6000000)
	return g_strdup_printf("%ldM", num/1024/1024);
    if (num > 6000)
	return g_strdup_printf("%ldK", num/1024);
    return g_strdup_printf("%ld", num);
}

gchar *
strdup_uptime (u_long time)
{
    gint up_d, up_h, up_m;

    up_d = time/100/60/60/24;
    up_h = (time/100/60/60) % 24;
    up_m = (time/100/60) % 60;

    return g_strdup_printf ("%dd %d:%d", up_d, up_h, up_m );
}

gchar *
render_error(Reader *reader)
{
    return g_strdup_printf ("%s %s (snmp://%s@%s:%d/%s)",
			    reader->label,
			    reader->session ? reader->error : "Unknown host",
			    reader->community,
			    reader->peer, reader->port,
			    reader->oid_str );
}

gchar *
render_label(Reader *reader)
{
    u_long since_last = 0;
    u_long val;

    /* 100: turn TimeTicks into seconds */
    since_last = (reader->sample_time - reader->old_sample_time) / 100;

    /* short-cut if only binary data present */
    if (reader->asn1_type == ASN_OCTET_STR) {
	return g_strdup_printf ("%s %s%s",
				reader->label,
				reader->sample,
				reader->unit);
    }

    /* pretty print Uptime */
    if (reader->asn1_type == ASN_TIMETICKS) {
	return strdup_uptime (reader->sample_n);
    }

    if (reader->delta)
	val = (reader->sample_n - reader->old_sample_n) /
		( (since_last < 1) ? 1 : since_last ) /
		( (reader->divisor == 0) ? 1 : reader->divisor );
    else
	val = reader->sample_n / 
		( (reader->divisor == 0) ? 1 : reader->divisor );

    if (reader->scale)
	return g_strdup_printf ("%s %s%s",
				reader->label,
				scale(val),
				reader->unit);
    else
	return g_strdup_printf ("%s %ld%s",
				reader->label,
				val,
				reader->unit);
}

gchar *
render_info(Reader *reader)
{
    u_long since_last = 0;
    u_long delta;
    gint up_d, up_h, up_m;
    
    /* 100: turn TimeTicks into seconds */
    since_last = (reader->sample_time - reader->old_sample_time) / 100;

    up_d = reader->sample_time/100/60/60/24;
    up_h = (reader->sample_time/100/60/60) % 24;
    up_m = (reader->sample_time/100/60) % 60;

    delta = (reader->sample_n - reader->old_sample_n) /
	    ( (since_last < 1) ? 1 : since_last ) /
	    ( (reader->divisor == 0) ? 1 : reader->divisor );

    return g_strdup_printf ("%s '%s' %ld (%ld s: %ld) %s  (snmp://%s@%s:%d/%s) Uptime: %dd %d:%d",
			    reader->label,
			    reader->sample,
			    reader->sample_n,
			    since_last,
			    delta,
			    reader->unit, 
			    reader->community,
			    reader->peer, reader->port,
			    reader->oid_str,
			    up_d, up_h, up_m );
}

#ifdef UCDSNMP_PRE_4_2

/*
 * snmp_parse_args.c
 */

oid
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

#endif

gchar *
snmp_probe(gchar *peer, gint port, gchar *community)
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

    session.version = SNMP_VERSION_1;
    session.community = community;
    session.community_len = strlen(community);
    session.peername = peer;

#ifdef STREAM
    session.flags |= SNMP_FLAGS_STREAM_SOCKET;
    fprintf (stderr, "local port set to: %d\n", session.local_port);
#endif

    /* 
     * Open an SNMP session.
     */
    ss = snmp_open(&session);
    if (ss == NULL){
      fprintf (stderr, "local port set to: %d\n", session.local_port);
      snmp_sess_perror(__FUNCTION__ "() snmp_open", &session);
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
	    sprint_variable(textbuf, vars->name, vars->name_length, vars);
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
      snmp_sess_perror(__FUNCTION__ "() STAT_ERROR", ss);
      snmp_close(ss);
      return NULL;

    }  /* endif -- STAT_SUCCESS */

    if (response)
      snmp_free_pdu(response);
    snmp_close(ss);

    return result;
}
         
int
snmp_input(int op,
	   struct snmp_session *session,
	   int reqid,
	   struct snmp_pdu *pdu,
	   void *magic)
{
    struct variable_list *vars;
    gint asn1_type = 0;
    gchar *result = NULL;
    u_long result_n = 0;

    gchar *error = NULL;
    u_long time = 0;
    Reader *reader = NULL;

    if (op == RECEIVED_MESSAGE) {

        if (pdu->errstat == SNMP_ERR_NOERROR) {

	    /*
	    fprintf(stderr, "recv from (@ %ld): %s type: %d\n",
	            pdu->time, session->peername, pdu->variables->type);
	    */

            for(vars = pdu->variables; vars; vars = vars->next_variable) {
                switch (vars->type) {
		case ASN_TIMETICKS:
		    time = *vars->val.integer;
		    break;
		case ASN_OCTET_STR: /* value is a string */
		    asn1_type = ASN_OCTET_STR;
		    result = g_strndup(vars->val.string, vars->val_len);
		    break;
		case ASN_INTEGER: /* value is a integer */
		case ASN_COUNTER: /* use as if it were integer */
		case ASN_UNSIGNED: /* use as if it were integer */
		    asn1_type = ASN_INTEGER;
		    result_n = *vars->val.integer;
		    result = g_strdup_printf("%ld", *vars->val.integer);
		    break;
		default:
		    fprintf(stderr, "recv unknown ASN type: %d - please report to zany@triq.net\n", vars->type);
		}
	    }
                              
        } else {
            error = g_strdup_printf("Error in packet\nReason: %s",
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
	reader = session->callback_magic;
	if (error) {
	    if (reader->error)
		g_free(reader->error);
	    reader->error = error;
	} else {
	    if (reader->error)
	    {
		g_free (reader->error);
		reader->error = NULL;
	    }
	    if (reader->sample)
		g_free(reader->sample);
	    /* should we save data ? */
	    /*
	    if (reader->old_sample)
		g_free(reader->old_sample);
	    reader->old_sample = reader->sample;
	    reader->old_sample-time = reader->sample_time;
	    */
	    reader->asn1_type = asn1_type;
	    reader->sample = result;
	    reader->sample_n = result_n;
	    reader->sample_time = time;

	    if (strcmp(reader->oid_str, "sysUpTime.0") == 0) {
	        reader->asn1_type = ASN_TIMETICKS;
	        reader->sample_n = time;
		reader->sample=  strdup_uptime (time);
	    }
	}
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
	       gchar *community,
	       void *data)
{
    struct snmp_session session, *ss;

    /*
     * initialize session to default values
     */
    snmp_sess_init( &session );

    session.version = SNMP_VERSION_1;
    session.community = community;
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
        snmp_sess_perror(__FUNCTION__ "() snmp_open", &session);
        // exit(1);
    }

    return ss;
}

void
simpleSNMPsend(struct snmp_session *session,
	       oid *name,
	       size_t name_length)
{
    struct snmp_pdu *pdu;
    oid uptime[MAX_OID_LEN];
    size_t uptime_length;

    /* 
     * Create PDU for GET request and add object names to request.
     */
    pdu = snmp_pdu_create(SNMP_MSG_GET);

    /* 
     * First insert uptime request into PDU.
     */
    uptime_length = MAX_OID_LEN;
    if (!snmp_parse_oid("system.sysUpTime.0",
			uptime, &uptime_length)) {
	    printf("error parsing oid: system.sysUpTime.0\n");
    }
    snmp_add_null_var(pdu, uptime, uptime_length);

    snmp_add_null_var(pdu, name, name_length);

    /* 
     * Perform the request.
     */

    snmp_send(session, pdu);
}


/* GKrellM interface */
 
static Monitor *mon;
static Reader *readers;
static GtkWidget *main_vbox;

static void
update_plugin()
{
    Reader *reader;
    gchar  *text;
    gint clock_style_id;
    //  Krell       *k;
    //  gint i;

    /* See if we recieved SNMP responses */
    simpleSNMPupdate();

    /* Send new SNMP requests */
    for (reader = readers; reader ; reader = reader->next)
    {
        //      k = KRELL(panel);
	//      k->previous = 0;

	if ( (! reader->session) && (! reader->old_error) ) {
	    reader->session = simpleSNMPopen(reader->peer,
					     reader->port,
					     reader->community,
					     reader);
	    if (! reader->session) {
		text = reader->old_error;
		reader->old_error = render_error(reader);
		g_free(text);
	    }
	}

	/* Send new SNMP requests */
	if ( (reader->session) && ((GK.timer_ticks % reader->delay) == 0))
	    simpleSNMPsend(reader->session,
			   reader->objid,
			   reader->objid_length);


	if ( (reader->session) && (reader->sample) ) {
	    if (reader->error) {
	        if (!reader->old_error ||
		    strcmp(reader->error,
			   reader->old_error) ) {
		    text = reader->old_error;
		    reader->old_error = g_strdup(reader->error);
		    g_free(text);
		    reader->panel->textstyle = gkrellm_panel_alt_textstyle(DEFAULT_STYLE);
		    text = render_error(reader);
		    gtk_tooltips_set_tip(reader->tooltip, reader->panel->drawing_area, text, "");
		    gtk_tooltips_enable(reader->tooltip);
		    g_free(text);
		}
	    } else {
		    if ((GK.timer_ticks % reader->delay) == 0)
			    if (reader->chart != NULL)
			    {
				    gkrellm_store_chartdata(reader->chart, 0, reader->sample_n);
				    gkrellm_draw_chartdata(reader->chart);
				    gkrellm_draw_chart_to_screen(reader->chart);
			    }

		    /* if there are changes update label */
		if ( !reader->old_sample || strcmp(reader->sample,
						   reader->old_sample) ||
		     (reader->sample_n != reader->old_sample_n) ) {

		    g_free(reader->old_sample);
		    reader->old_sample = g_strdup(reader->sample);

		    text = render_label(reader);
		    gkrellm_dup_string(&reader->panel->label->string, text);
		    g_free(text);
		    //	i = atoi(text);

		    text = render_info(reader);
		    gtk_tooltips_set_tip(reader->tooltip, reader->panel->drawing_area, text, "");
		    gtk_tooltips_enable(reader->tooltip);

		    g_free(text);
		    reader->old_sample_n = reader->sample_n;
		    reader->old_sample_time = reader->sample_time;
		}
		reader->panel->textstyle = gkrellm_panel_textstyle(DEFAULT_STYLE);
	    }

	    /* back up the old sample */
	    reader->old_sample_n = reader->sample_n;
	    reader->old_sample_time = reader->sample_time;

	} else {
	    reader->panel->textstyle = gkrellm_panel_alt_textstyle(DEFAULT_STYLE);
	    gtk_tooltips_disable(reader->tooltip);
	    //	i = -1;
	}
      
	//      gkrellm_update_krell(panel, k, i);

	/* Bill mentioned this change for upcoming 0.10.0 */
#if (VERSION_MAJOR <= 0)&&(VERSION_MINOR <= 9)
	clock_style_id = CLOCK_STYLE;
#else
	clock_style_id = gkrellm_lookup_meter_style_id(CLOCK_STYLE_NAME);
#endif

	gkrellm_draw_panel_label( reader->panel,
				  gkrellm_bg_panel_image(clock_style_id) );
	gkrellm_draw_layers(reader->panel);
    }

}

static gint
panel_expose_event(GtkWidget *widget, GdkEventExpose *ev)
{
    Reader *reader;

    for (reader = readers; reader ; reader = reader->next)
        if (widget == reader->panel->drawing_area) {

	    gdk_draw_pixmap(widget->window,
			    widget->style->fg_gc[GTK_WIDGET_STATE (widget)],
			    reader->panel->pixmap,
			    ev->area.x, ev->area.y, ev->area.x, ev->area.y,
			    ev->area.width, ev->area.height);
	}
    return FALSE;
}

static gint
chart_expose_event(GtkWidget *widget, GdkEventExpose *ev)
{
    Reader *reader;

    for (reader = readers; reader ; reader = reader->next)
        if (widget == reader->panel->drawing_area) {

	    gdk_draw_pixmap(widget->window,
			    widget->style->fg_gc[GTK_WIDGET_STATE (widget)],
			    reader->chart->pixmap,
			    ev->area.x, ev->area.y, ev->area.x, ev->area.y,
			    ev->area.width, ev->area.height);
	}
    return FALSE;
}

static void
cb_chart_click(GtkWidget *widget, GdkEventButton *event, gpointer data)
	{
		if (event->button == 3)
			gkrellm_chartconfig_window_create(data);
	}

static void
create_reader(GtkWidget *vbox, Reader *reader, gint first_create)
{
      //    Krell           *k;
    Style           *style;
    //    GdkImlibImage   *krell_image;
    gchar *text;



    if (first_create)
	    reader->chart = gkrellm_chart_new0();

    gkrellm_set_chart_height_default(reader->chart, 20);

    gkrellm_chart_create(vbox, mon, reader->chart, &(reader->chart_config));

    reader->chart_data = gkrellm_add_default_chartdata(reader->chart, "Plugin Data");
    
    gkrellm_monotonic_chartdata(reader->chart_data, FALSE);

    gkrellm_set_chartdata_draw_style_default(reader->chart_data, CHARTDATA_LINE);
    gkrellm_set_chartdata_flags(reader->chart_data, CHARTDATA_ALLOW_HIDE);

    gkrellm_alloc_chartdata(reader->chart);

    if (first_create)
    {
	    gtk_signal_connect(GTK_OBJECT(reader->chart->drawing_area),
			       "expose_event", (GtkSignalFunc) chart_expose_event, NULL);
	    gtk_signal_connect(GTK_OBJECT(reader->chart->drawing_area),
			       "button_press_event", (GtkSignalFunc) cb_chart_click, reader->chart);
    }
    else
    {
	    gkrellm_draw_chartdata(reader->chart);
	    gkrellm_draw_chart_to_screen(reader->chart);
    }






    if (first_create)
        reader->panel = gkrellm_panel_new0();
    else
        gkrellm_destroy_krell_list(reader->panel);

    /* Create a krell.  A Krell structure is allocated and linked into
    |  the list of krells pointed to by panel->krell.
    */
    style = gkrellm_meter_style(DEFAULT_STYLE);
    style->label_position = LABEL_CENTER;
    //    krell_image = gkrellm_krell_meter_image(DEFAULT_STYLE);
    //    k = gkrellm_create_krell(panel, krell_image, style);
    //    k->full_scale = 30;

    /* Configure panel calculates the panel height needed for the "Plugin" label.
    |  and the krell.
    */
    reader->panel->textstyle = gkrellm_meter_textstyle(DEFAULT_STYLE);
    gkrellm_configure_panel(reader->panel, "SNMP", style);
    //    gkrellm_configure_panel(reader->panel, "SNMP", style);

    //    reader->panel->textstyle = gkrellm_panel_alt_textstyle(DEFAULT_STYLE);


    /* Build the configured panel with a background image and pack it into
    |  the vbox assigned to this monitor.
    */
//dep:    gkrellm_create_panel(vbox, reader->panel, gkrellm_bg_meter_image(DEFAULT_STYLE));
    gkrellm_panel_create(vbox, mon, reader->panel);
    gkrellm_monitor_height_adjust(reader->panel->h);

    if (first_create) {
        gtk_signal_connect(GTK_OBJECT (reader->panel->drawing_area),
			   "expose_event",
			   (GtkSignalFunc) panel_expose_event, NULL);
	reader->tooltip=gtk_tooltips_new();
    }

    /* refresh the display */
    text = render_label(reader);
    gkrellm_dup_string(&reader->panel->label->string, text);
    g_free(text);
}

static void
destroy_reader(Reader *reader)
{
  if (!reader)
    return;

  reader->session->callback_magic = 0; /* detach the callback */
  g_free(reader->label);
  g_free(reader->peer);
  g_free(reader->community);
  g_free(reader->oid_str);
  g_free(reader->unit);

  g_free(reader->sample);
  g_free(reader->old_sample);

  /* can't free snmp session. may be there are pending snmp_reads! */
/*
  if (reader->session)
    snmp_close(reader->session);
  g_free(reader->session);
*/

  gkrellm_monitor_height_adjust( - reader->panel->h);
  gkrellm_panel_destroy(reader->panel);
  //  gtk_widget_destroy(reader->vbox);
  g_free(reader);
}

static void
create_plugin(GtkWidget *vbox, gint first_create)
{
  Reader *reader;

  main_vbox = vbox;

  for (reader = readers; reader ; reader = reader->next) {
      create_reader(vbox, reader, first_create);
  }
}

/* Config section */

static GtkWidget        *label_entry;
static GtkWidget        *peer_entry;
static GtkObject        *port_spin_adj;
static GtkWidget        *port_spin;
static GtkWidget        *community_entry;
static GtkWidget        *oid_entry;
static GtkWidget        *unit_entry;
static GtkObject        *freq_spin_adj;
static GtkWidget        *freq_spin;
static GtkObject        *div_spin_adj;
static GtkWidget        *div_spin;
static GtkWidget        *delta_button;
static GtkWidget        *scale_button;
static GtkWidget        *reader_clist;
static gint             selected_row = -1;
static gint             list_modified;
#define CLIST_WIDTH 11

#define	 STR_DELIMITERS	" \t"

static void
save_plugin_config(FILE *f)
{
  Reader *reader;
  gchar *label, *unit;

  for (reader = readers; reader ; reader = reader->next) {
      label = g_strdelimit(g_strdup(reader->label), STR_DELIMITERS, '_');
      unit = g_strdelimit(g_strdup(reader->unit), STR_DELIMITERS, '_');
      if (label[0] == '\0') label = strdup("_");
      if (unit[0] == '\0') unit = strdup("_");
      fprintf(f, "%s %s snmp://%s@%s:%d/%s %s %d %d %d %d\n",
	      PLUGIN_CONFIG_KEYWORD,
	      label, reader->community,
	      reader->peer, reader->port,
	      reader->oid_str, unit,
	      reader->delay, reader->delta,
	      reader->divisor, reader->scale);
      g_free(label);
      g_free(unit);
  }
}

static void
load_plugin_config(gchar *arg)
{
  Reader *reader, *nreader;

  gchar   proto[CFG_BUFSIZE], bufl[CFG_BUFSIZE];
  gchar   bufc[CFG_BUFSIZE], bufp[CFG_BUFSIZE];
  gchar   bufo[CFG_BUFSIZE], bufu[CFG_BUFSIZE];
  gint    n;

  reader = g_new0(Reader, 1); 

  n = sscanf(arg, "%s %[^:]://%[^@]@%[^:]:%d/%s %s %d %d %d %d",
	     bufl, proto, bufc, bufp, &reader->port, bufo, bufu,
	     &reader->delay, &reader->delta,
	     &reader->divisor, &reader->scale);
  if (n >= 6)
    {
      if (g_strcasecmp(proto, "snmp") == 0) {
	gkrellm_dup_string(&reader->label, bufl);
	gkrellm_dup_string(&reader->community, bufc);
	gkrellm_dup_string(&reader->peer, bufp);
	if (reader->delay < 10)
	    reader->delay = 100;
	if (reader->divisor == 0)
	    reader->divisor = 1;

	gkrellm_dup_string(&reader->oid_str, bufo);

	reader->objid_length = MAX_OID_LEN;
	if (!snmp_parse_oid(reader->oid_str,
			    reader->objid, &reader->objid_length)) {
//FIXME:
	    printf("error parsing oid: %s\n", reader->oid_str);
	}

	if (n > 7) {
	    gkrellm_dup_string(&reader->unit, bufu);
	} else {
	    gkrellm_dup_string(&reader->unit, "");
	}

	g_strdelimit(reader->label, "_", ' ');
	g_strdelimit(reader->unit, "_", ' ');

	// reader->old_sample = "SNMP"; // be nice.
      }

      if (!readers)
	  readers = reader;
      else { 
 	  for (nreader = readers; nreader->next ; nreader = nreader->next);
	  nreader->next = reader;
      }

    }
}

static void
apply_plugin_config()
{
  Reader *reader, *nreader;
  gchar  *name;
  gint   row;

  if (!list_modified)
    return;

  for (reader = readers; reader; reader = readers) {
    readers = reader->next;
    destroy_reader(reader);
  }

  for (row = 0; row < GTK_CLIST(reader_clist)->rows; ++row)
    {
      gint i;
      i = 0;
      reader = g_new0(Reader, 1);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->label, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->peer, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->port = atoi(name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->community, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->oid_str, name);
      reader->objid_length = MAX_OID_LEN;
      if (!snmp_parse_oid(reader->oid_str,
			  reader->objid, &reader->objid_length)) {
//FIXME:
	  printf("error parsing oid: %s\n", reader->oid_str);
      }

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->unit, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->delay = atoi(name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->divisor = atoi(name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->delta = (strcmp(name, "yes") == 0) ? TRUE : FALSE;

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->scale = (strcmp(name, "yes") == 0) ? TRUE : FALSE;

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->active = (strcmp(name, "yes") == 0) ? TRUE : FALSE;

      if (!readers)
          readers = reader;
      else { 
	  for (nreader = readers; nreader->next ; nreader = nreader->next);
	  nreader->next = reader;
      }
      create_reader(main_vbox, reader, 1);
    }
  list_modified = 0;
}


static void
reset_entries()
{
  gtk_entry_set_text(GTK_ENTRY(label_entry), "");
  gtk_entry_set_text(GTK_ENTRY(peer_entry), "");
  // gtk_entry_set_text(GTK_ENTRY(port_entry), "");
  gtk_entry_set_text(GTK_ENTRY(community_entry), "");
  gtk_entry_set_text(GTK_ENTRY(oid_entry), "");
  gtk_entry_set_text(GTK_ENTRY(unit_entry), "");
  // gtk_entry_set_text(GTK_ENTRY(freq_entry), "");
  // gtk_entry_set_text(GTK_ENTRY(div_entry), "");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(delta_button), FALSE);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(scale_button), TRUE);
  // gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(active_button), FALSE);
}


static void
cb_clist_selected(GtkWidget *clist, gint row, gint column,
		  GdkEventButton *bevent)
{
  gchar           *s;
  gint            state, i;

  i = 0;
  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(label_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(peer_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(port_spin), s);
  //  gtk_spin_button_get_value_as_int(GTK_SPINBUTTON(port_spin), 161);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(community_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(oid_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(unit_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(freq_spin), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(div_spin), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  state = (strcmp(s, "yes") == 0) ? TRUE : FALSE;
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(delta_button), state);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  state = (strcmp(s, "yes") == 0) ? TRUE : FALSE;
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(scale_button), state);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  state = (strcmp(s, "yes") == 0) ? TRUE : FALSE;
  //  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(active_button), state);

  selected_row = row;
}

static void
cb_clist_unselected(GtkWidget *clist, gint row, gint column,
		    GdkEventButton *bevent)
{
  reset_entries();
  selected_row = -1;
}

static void
cb_clist_up(GtkWidget *widget)
{
  gint            row;

  row = selected_row;
  if (row > 0)
    {
      gtk_clist_row_move(GTK_CLIST(reader_clist), row, row - 1);
      gtk_clist_select_row(GTK_CLIST(reader_clist), row - 1, -1);
      if (gtk_clist_row_is_visible(GTK_CLIST(reader_clist), row - 1)
	  != GTK_VISIBILITY_FULL)
	gtk_clist_moveto(GTK_CLIST(reader_clist), row - 1, -1, 0.0, 0.0);
      selected_row = row - 1;
      list_modified = TRUE;
    }
}

static void
cb_clist_down(GtkWidget *widget)
{
  gint            row;

  row = selected_row;
  if (row >= 0 && row < GTK_CLIST(reader_clist)->rows - 1)
    {
      gtk_clist_row_move(GTK_CLIST(reader_clist), row, row + 1);
      gtk_clist_select_row(GTK_CLIST(reader_clist), row + 1, -1);
      if (gtk_clist_row_is_visible(GTK_CLIST(reader_clist), row + 1)
	  != GTK_VISIBILITY_FULL)
	gtk_clist_moveto(GTK_CLIST(reader_clist), row + 1, -1, 1.0, 0.0);
      selected_row = row + 1;
      list_modified = TRUE;
    }
}

static void
cb_enter(GtkWidget *widget)
{
  gchar           *buf[CLIST_WIDTH];
  gint            i;

  i = 0;
  buf[i++] = gkrellm_entry_get_text(&label_entry);
  buf[i++] = gkrellm_entry_get_text(&peer_entry);
  buf[i++] = gkrellm_entry_get_text(&port_spin);
  buf[i++] = gkrellm_entry_get_text(&community_entry);
  buf[i++] = gkrellm_entry_get_text(&oid_entry);
  buf[i++] = gkrellm_entry_get_text(&unit_entry);
  buf[i++] = gkrellm_entry_get_text(&freq_spin);
  buf[i++] = gkrellm_entry_get_text(&div_spin);
  buf[i++] = GTK_TOGGLE_BUTTON(delta_button)->active ? "yes" : "no";
  buf[i++] = GTK_TOGGLE_BUTTON(scale_button)->active ? "yes" : "no";
  buf[i++] = "yes"; // GTK_TOGGLE_BUTTON(active_button)->active ? "yes" : "no";

  /* validate we have input */
  if (!*(buf[1]) || !*(buf[2]) || !*(buf[3]) || !*(buf[4]))
    {
      gkrellm_config_message_window("Entry Error",
				    "Peer, Port, Community and OID must be entered.", widget);
      return;
    }
  if (selected_row >= 0)
    {
      for (i = 0; i < CLIST_WIDTH; ++i)
	gtk_clist_set_text(GTK_CLIST(reader_clist), selected_row, i, buf[i]);
      gtk_clist_unselect_row(GTK_CLIST(reader_clist), selected_row, 0);
      selected_row = -1;
    }
  else
    gtk_clist_append(GTK_CLIST(reader_clist), buf);
  reset_entries();
  list_modified = TRUE;
}

static void
cb_delete(GtkWidget *widget)
{
  reset_entries();
  if (selected_row >= 0)
    {
      gtk_clist_remove(GTK_CLIST(reader_clist), selected_row);
      list_modified = TRUE;
      selected_row = -1;
    }
}

static void
cb_probe(GtkWidget *widget)
{
	gchar *peer;
	gint port;
	gchar *community;
	gchar *probe;

	peer = gkrellm_entry_get_text(&peer_entry);
	port = atoi(gkrellm_entry_get_text(&port_spin));
	community = gkrellm_entry_get_text(&community_entry);

	/* validate we have input */
	if (!*(peer) || !*(community))
	{
		gkrellm_config_message_window("Entry Error",
			"Peer, Port and Community must be entered.", widget);
		return;
	}
	probe = snmp_probe(peer, port, community);
	gkrellm_config_message_window("SNMP Probe", probe, widget);
	g_free(probe);
}


static gchar    *plugin_info_text =
"This configuration tab is for the SNMP monitor plugin.\n"
"\n"
"Adding new SNMP readers should be fairly easy.\n"
"Peer, Port, Community and OID are the respective SNMP parameters.\n"
"Whereas Port ist preselected with the default value 161.\n"
"Freq sets the delay between updates of the reader value.\n"
"It's measured in GKrellM ticks -- that's 1/10 seconds.\n"
"Label is a unique name that gets prepended to your reader.\n"
"Unit is just a string thats appended to your reader.\n"
"\n"
"Some examples:\n"
"\n"
"(1)\n"
"The ambiente temperature sensor for Oldenburg i.O., Germany\n"
" (see http://www.PMNET.uni-oldenburg.de/temperatur.php3)\n"
"is world readable using the following pseudo URL\n"
"snmp://public@134.106.172.2:161/.1.3.6.1.4.1.2021.8.1.101.1\n"
"\n"
"That is:\n"
" SNMP peer '134.106.172.2' (kyle.pmnet.uni-oldenburg.de)\n"
" SNMP port '161' (that's the default)\n"
" SNMP community name 'public'\n"
" SNMP oid '.1.3.6.1.4.1.2021.8.1.101.1'\n"
"\n"
"Resonable Label/Unit would be 'Temp.' / '°C'\n"
"\n"
"(2)\n"
"\n"
"Server CPU load using a string ranging from 0.00 to 1.00\n"
"\n"
"snmp://public@134.106.120.1:161/.1.3.6.1.4.1.2021.10.1.3.1\n"
"(Thats the load factor for PMNET's Stan)\n"
"\n"
"(3)\n"
"\n"
"Server CPU load using integer variable ranging from 0 to 100\n"
"\n"
"snmp://public@134.106.172.2:161/.1.3.6.1.4.1.2021.10.1.5.1\n"
"(Thats the percentile load on PMNET's Kyle)\n"
"\n"
"please mail any problems/questions to me...\n"
;

static gchar    *plugin_about_text =
   "SNMP plugin 0.17\n"
   "GKrellM SNMP monitor Plugin\n\n"
   "Copyright (C) 2000-2001 Christian W. Zuckschwerdt\n"
   "zany@triq.net\n\n"
   "http://triq.net/gkrellm.html\n\n"
   "Released under the GNU Public Licence"
;

static gchar *reader_title[CLIST_WIDTH] =
{ "Label", "Peer", "Port",
  "Community", "OID", "Unit",
  "Freq", "Divisor", "Delta", "Scale", "Active" };

static void
create_plugin_tab(GtkWidget *tab_vbox)
{
  Reader *reader;

  GtkWidget               *tabs;
  GtkWidget               *vbox;
  GtkWidget               *hbox;
  GtkWidget               *button;
  GtkWidget               *arrow;
  GtkWidget               *scrolled;
  GtkWidget               *text;
  GtkWidget               *label;

  gchar                   *buf[CLIST_WIDTH];
  gint                    row, i;

        /* Make a couple of tabs.  One for setup and one for info
        */
        tabs = gtk_notebook_new();
        gtk_notebook_set_tab_pos(GTK_NOTEBOOK(tabs), GTK_POS_TOP);
        gtk_box_pack_start(GTK_BOX(tab_vbox), tabs, TRUE, TRUE, 0);

/* --- Setup tab */
        vbox = gkrellm_create_tab(tabs, "Setup");

	hbox = gtk_hbox_new(FALSE,0);

	label = gtk_label_new("Label : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	label_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(label_entry), "");
	gtk_box_pack_start(GTK_BOX(hbox),label_entry,FALSE,FALSE,0);

	label = gtk_label_new("Peer : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	peer_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(peer_entry), "");
	gtk_box_pack_start(GTK_BOX(hbox),peer_entry,FALSE,FALSE,0);

	label = gtk_label_new("Port : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	port_spin_adj = gtk_adjustment_new (161, 1, 65535, 1, 10, 10);
	port_spin = gtk_spin_button_new (GTK_ADJUSTMENT (port_spin_adj), 1, 0);
	gtk_box_pack_start(GTK_BOX(hbox),port_spin,FALSE,FALSE,0);

	label = gtk_label_new("Freq : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	freq_spin_adj = gtk_adjustment_new (100, 10, 6000, 10, 100, 100);
	freq_spin = gtk_spin_button_new (GTK_ADJUSTMENT (freq_spin_adj), 1, 0);
	gtk_box_pack_start(GTK_BOX(hbox),freq_spin,FALSE,FALSE,0);

	gtk_container_add(GTK_CONTAINER(vbox),hbox);
	hbox = gtk_hbox_new(FALSE,0);

	label = gtk_label_new("Community : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	community_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(community_entry), "");
        gtk_box_pack_start(GTK_BOX(hbox), community_entry, FALSE, FALSE, 0);

	label = gtk_label_new("OID : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	oid_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(oid_entry), "");
        gtk_box_pack_start(GTK_BOX(hbox), oid_entry, FALSE, FALSE, 0);

	label = gtk_label_new("Unit : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	unit_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(unit_entry), "");
	gtk_box_pack_start(GTK_BOX(hbox),unit_entry,FALSE,FALSE,0);

	gtk_container_add(GTK_CONTAINER(vbox),hbox);
	hbox = gtk_hbox_new(FALSE,0);

	label = gtk_label_new("Divisor : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	div_spin_adj = gtk_adjustment_new (1, 1, 1024, 1, 1, 1);
	div_spin = gtk_spin_button_new (GTK_ADJUSTMENT (div_spin_adj), 1, 0);
	gtk_box_pack_start(GTK_BOX(hbox),div_spin,FALSE,FALSE,0);

        delta_button = gtk_check_button_new_with_label("Compute delta");
        gtk_box_pack_start(GTK_BOX(hbox),delta_button,FALSE,FALSE,0);

        scale_button = gtk_check_button_new_with_label("Auto scale");
        gtk_box_pack_start(GTK_BOX(hbox),scale_button,FALSE,FALSE,0);

        button = gtk_button_new_with_label("Probe");
        gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   (GtkSignalFunc) cb_probe, NULL);
        gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 4);

	gtk_container_add(GTK_CONTAINER(vbox),hbox);

        hbox = gtk_hbox_new(FALSE, 3);
        gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 2);
	/*
        *mount_button = gtk_check_button_new_with_label(
                                        "Enable /etc/fstab mounting");
        gtk_box_pack_start(GTK_BOX(hbox), *mount_button, TRUE, TRUE, 0);
        gtk_signal_connect(GTK_OBJECT(GTK_BUTTON(*mount_button)), "clicked",
                                GTK_SIGNAL_FUNC (cb_mount_button_clicked), NULL);
	*/

        button = gtk_button_new();
        arrow = gtk_arrow_new(GTK_ARROW_UP, GTK_SHADOW_ETCHED_OUT);
        gtk_container_add(GTK_CONTAINER(button), arrow);
        gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   (GtkSignalFunc) cb_clist_up, NULL);
        gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 4);

        button = gtk_button_new();
        arrow = gtk_arrow_new(GTK_ARROW_DOWN, GTK_SHADOW_ETCHED_OUT);
        gtk_container_add(GTK_CONTAINER(button), arrow);
        gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   (GtkSignalFunc) cb_clist_down, NULL);
        gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 4);

        button = gtk_button_new_with_label("Enter");
        gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   (GtkSignalFunc) cb_enter, NULL);
        gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 4);

        button = gtk_button_new_with_label("Delete");
        gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   (GtkSignalFunc) cb_delete, NULL);
        gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 4);


        scrolled = gtk_scrolled_window_new(NULL, NULL);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

	reader_clist = gtk_clist_new_with_titles(CLIST_WIDTH, reader_title);	
        gtk_clist_set_shadow_type (GTK_CLIST(reader_clist), GTK_SHADOW_OUT);
	gtk_clist_set_column_width (GTK_CLIST(reader_clist), 1, 100);
	gtk_clist_set_column_width (GTK_CLIST(reader_clist), 4, 100);

        gtk_signal_connect(GTK_OBJECT(reader_clist), "select_row",
                        (GtkSignalFunc) cb_clist_selected, NULL);
        gtk_signal_connect(GTK_OBJECT(reader_clist), "unselect_row",
                        (GtkSignalFunc) cb_clist_unselected, NULL);

        gtk_container_add(GTK_CONTAINER(scrolled), reader_clist);

        for (reader = readers; reader; reader = reader->next)
	  {
	    i = 0;
	    buf[i++] = reader->label;
	    buf[i++] = reader->peer;
	    buf[i++] = g_strdup_printf("%d", reader->port);
	    buf[i++] = reader->community;
	    buf[i++] = reader->oid_str;
	    buf[i++] = reader->unit;
	    buf[i++] = g_strdup_printf("%d", reader->delay);
	    buf[i++] = g_strdup_printf("%d", reader->divisor);
	    buf[i++] = reader->delta ? "yes" : "no";
	    buf[i++] = reader->scale ? "yes" : "no";
	    buf[i++] = reader->active ? "yes" : "no";
	    row = gtk_clist_append(GTK_CLIST(reader_clist), buf);
	  }


/* --- Info tab */
        vbox = gkrellm_create_tab(tabs, "Info");
        scrolled = gtk_scrolled_window_new(NULL, NULL);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);
        text = gtk_text_new(NULL, NULL);
        gtk_text_insert(GTK_TEXT(text), NULL, NULL, NULL, plugin_info_text, -1);
        gtk_text_set_editable(GTK_TEXT(text), FALSE);
        gtk_container_add(GTK_CONTAINER(scrolled), text);

/* --- about text */

	text = gtk_label_new(plugin_about_text); 

	gtk_notebook_append_page(GTK_NOTEBOOK(tabs), text,
				 gtk_label_new("About"));

}




static Monitor  plugin_mon  =
        {
        PLUGIN_CONFIG_NAME,    /* Name, for config tab.        */
        0,                     /* Id,  0 if a plugin           */
        create_plugin,         /* The create_plugin() function */
        update_plugin,         /* The update_plugin() function */
        create_plugin_tab,     /* The create_plugin_tab() config function */
        apply_plugin_config,   /* The apply_plugin_config() function      */

        save_plugin_config,    /* The save_plugin_config() function  */
        load_plugin_config,    /* The load_plugin_config() function  */
        PLUGIN_CONFIG_KEYWORD, /* config keyword                     */

        NULL,                  /* Undefined 2  */
        NULL,                  /* Undefined 1  */
        NULL,                  /* Undefined 0  */

        MON_MAIL,              /* Insert plugin before this monitor.       */
        NULL,                  /* Handle if a plugin, filled in by GKrellM */
        NULL                   /* path if a plugin, filled in by GKrellM   */
        };

Monitor *
init_plugin(void)
{
    readers = NULL;

#ifdef DEBUG_SNMP
    debug_register_tokens("all");
    snmp_set_do_debugging(1);
#endif /* DEBUG_SNMP */

    init_mib();
    
    mon = &plugin_mon;
    return &plugin_mon;
}
