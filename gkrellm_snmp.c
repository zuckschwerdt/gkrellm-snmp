/* SNMP reader plugin for GKrellM 
|  Copyright (C) 2000 Christian W. Zuckschwerdt <zany@triq.net>
|
|  Author:   Christian W. Zuckschwerdt   <zany@triq.net>
|  Latest versions might be found at:  http://gkrellm.net/
|
|  This program is free software which I release under the GNU General Public
|  License. You may redistribute and/or modify this program under the terms
|  of that license as published by the Free Software Foundation; either
|  version 2 of the License, or (at your option) any later version.
|
|  This program is distributed in the hope that it will be useful,
|  but WITHOUT ANY WARRANTY; without even the implied warranty of
|  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|  GNU General Public License for more details.
|
|  To get a copy of the GNU General Puplic License,  write to the
|  Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* Installation:
|
|     make
|     cp gkrellm_snmp.so ~/.gkrellm/plugins
|
*/

#include <stdio.h>
#include <sys/types.h>

#include <ucd-snmp/asn1.h>
#include <ucd-snmp/mib.h>
#include <ucd-snmp/parse.h>

#include <ucd-snmp/snmp.h>
#include <ucd-snmp/snmp_api.h>
#include <ucd-snmp/snmp_client.h>

#include <gkrellm/gkrellm.h>

 
#define VOLUME_MAJOR_VERSION 0
#define VOLUME_MINOR_VERSION 1

#define PLUGIN_CONFIG_KEYWORD   "snmp_monitor"
#define DEFAULT_OID             ".1.3.6.1.4.1.2021.8.1.101.1"
#define DEFAULT_PEERNAME        "134.106.172.2"
#define DEFAULT_COMMUNITY       "public"

#define DEFAULT_FORMAT          "%s °C"


char *simpleSNMPget(char *peername, char *community,
		    oid *name, size_t name_length)
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;

    int count;
    int current_name = 0;

    int status;

    char buf[100];
    char *result = NULL;


    /* initialize session to default values */
    snmp_sess_init( &session );

    session.version = SNMP_VERSION_1;
    session.community = community;
    session.community_len = strlen(community);
    session.peername = peername;

    /* 
     * Open an SNMP session.
     */
    ss = snmp_open(&session);
    if (ss == NULL){
      snmp_sess_perror("snmpget", &session);
      exit(1);
    }

    /* 
     * Create PDU for GET request and add object names to request.
     */
    pdu = snmp_pdu_create(SNMP_MSG_GET);

    snmp_add_null_var(pdu, name, name_length);


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
        for(vars = response->variables; vars; vars = vars->next_variable)
	  sprint_value(buf, vars->name, vars->name_length, vars);
	result =g_strdup(buf);

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
        fprintf(stderr,"Timeout: No Response from %s.\n", session.peername);
        snmp_close(ss);
        return NULL;

    } else {    /* status == STAT_ERROR */
      snmp_sess_perror("snmpget", ss);
      snmp_close(ss);
      return NULL;

    }  /* endif -- STAT_SUCCESS */


    if (response)
      snmp_free_pdu(response);
    snmp_close(ss);

    return result;
}
 



static Panel    *panel;

gchar *format;
gchar *peername, *community, *oid_str;
oid objid[MAX_OID_LEN];
size_t objid_length;

static void
update_plugin()
{
  Krell       *k;
  gchar *p;
  gchar buf[100];
  gint i;

  if ((GK.timer_ticks % 100) == 0)
    {
      k = KRELL(panel);
      k->previous = 0;

      p = simpleSNMPget(peername, community, objid, objid_length);

      if (! format || ! strlen(format)) {
	format = g_strdup(DEFAULT_FORMAT);
      }

      if (p) {
	sprintf(buf, format, p);
	i = atoi(p);
	g_free(p);
      } else {
	strcpy(buf, "Error");
	i = -1;
      }
      
      gkrellm_update_krell(panel, k, i);

      panel->label->string = g_strdup(buf);

      gkrellm_draw_panel_label( panel, GK.bg_panel_image[CLOCK_STYLE]);
      gkrellm_draw_layers(panel);
    }
}

static gint
panel_expose_event(GtkWidget *widget, GdkEventExpose *ev)
    {
    gdk_draw_pixmap(widget->window,
            widget->style->fg_gc[GTK_WIDGET_STATE (widget)],
            panel->pixmap, ev->area.x, ev->area.y, ev->area.x, ev->area.y,
            ev->area.width, ev->area.height);
    return FALSE;
    }

static void
create_plugin(GtkWidget *vbox, gint first_create)
    {
    Krell           *k;
    Style           *style;
    GdkImlibImage   *krell_image;

    if (first_create)
        panel = gkrellm_panel_new0();
    else
        gkrellm_destroy_krell_list(panel);

    /* Create a krell.  A Krell structure is allocated and linked into
    |  the list of krells pointed to by panel->krell.
    */
    style = gkrellm_meter_style(DEFAULT_STYLE);
    style->label_position = LABEL_CENTER;
    krell_image = gkrellm_krell_meter_image(DEFAULT_STYLE);
    k = gkrellm_create_krell(panel, krell_image, style);
    k->full_scale = 30;

    /* Configure panel calculates the panel height needed for the "Plugin" label.
    |  and the krell.
    */
    panel->textstyle = gkrellm_meter_textstyle(DEFAULT_STYLE);
    gkrellm_configure_panel(panel, "SNMP", style);

    /* Build the configured panel with a background image and pack it into
    |  the vbox assigned to this monitor.
    */
    gkrellm_create_panel(vbox, panel, gkrellm_bg_meter_image(DEFAULT_STYLE));
    gkrellm_monitor_height_adjust(panel->h);

    if (first_create)
        gtk_signal_connect(GTK_OBJECT (panel->drawing_area), "expose_event",
                (GtkSignalFunc) panel_expose_event, NULL);
    }


/* Config section */

static GtkWidget        *peername_entry;
static GtkWidget        *community_entry;
static GtkWidget        *oid_entry;

static GtkWidget        *format_entry;


static void
save_plugin_config(FILE *f)
        {
        fprintf(f, "%s snmp://%s@%s/%s %s\n",
		PLUGIN_CONFIG_KEYWORD,
		community, peername, oid_str, format);
        }

static void
load_plugin_config(gchar *arg)
{
  gchar   proto[255], bufc[255], bufp[255], bufo[255];
  gchar   buff[255];
  gint    n;

  n = sscanf(arg, "%[^:]://%[^@]@%[^/]/%s %[^\n]",
	     proto, bufc, bufp, bufo, buff);
  if (n >= 4)
    {
      if (g_strcasecmp(proto, "snmp") == 0) {
	if (community)
	  g_free(community);
	community = g_strdup(bufc);

	if (peername)
	  g_free(peername);
	peername = g_strdup(bufp);

	if (oid_str)
	  g_free(oid_str);
	oid_str = g_strdup(bufo);
	objid_length = MAX_OID_LEN;
	read_objid(oid_str, objid, &objid_length);

	if (n == 5) {
	  if (format)
	    g_free(format);
	  format = g_strdup(buff);
	}

      }
    }
}

static void
apply_plugin_config()
{
  gchar    *name;
  
  name = gtk_entry_get_text(GTK_ENTRY(peername_entry));
  if (g_strcasecmp(peername, name) != 0)
    {
      if (peername)
	g_free(peername);
      peername = g_strdup(name);
    }

  name = gtk_entry_get_text(GTK_ENTRY(community_entry));
  if (g_strcasecmp(community, name) != 0)
    {
      if (community)
	g_free(community);
      community = g_strdup(name);
    }

  name = gtk_entry_get_text(GTK_ENTRY(oid_entry));
  if (g_strcasecmp(oid_str, name) != 0)
    {
      if (oid_str)
	g_free(oid_str);
      oid_str = g_strdup(name);
      objid_length = MAX_OID_LEN;
      read_objid(oid_str, objid, &objid_length);
    }


  name = gtk_entry_get_text(GTK_ENTRY(format_entry));
  if (g_strcasecmp(format, name) != 0)
    {
      if (format)
	g_free(format);
      format = g_strdup(name);
    }

}


static gchar    *plugin_info_text =
"This configuration tab is for the SNMP monitor plugin.\n"
"Put any documentation here to explain your plugin.\n"
"You could also add your name and email address in case\n"
"of any user questions.\n"
;

static gchar    *plugin_about_text =
   "SNMP plugin 0.1\n"
   "GKrellM SNMP monitor Plugin\n\n"
   "Copyright (C) 2000 Christian W. Zuckschwerdt\n"
   "zany@triq.net\n\n"
   "http://triq.net/...\n\n"
   "Released under the GNU Public Licence"
;


static void
create_plugin_tab(GtkWidget *tab_vbox)
        {
        GtkWidget               *tabs;
        GtkWidget               *vbox;
        GtkWidget               *hbox;
        GtkWidget               *scrolled;
        GtkWidget               *text;
        GtkWidget               *label;

        /* Make a couple of tabs.  One for setup and one for info
        */
        tabs = gtk_notebook_new();
        gtk_notebook_set_tab_pos(GTK_NOTEBOOK(tabs), GTK_POS_TOP);
        gtk_box_pack_start(GTK_BOX(tab_vbox), tabs, TRUE, TRUE, 0);

/* --- Setup tab */
        vbox = create_tab(tabs, "Setup");

	hbox = gtk_hbox_new(FALSE,0);
	label = gtk_label_new("Peername : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	peername_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(peername_entry), peername);
	gtk_box_pack_start(GTK_BOX(hbox),peername_entry,FALSE,FALSE,0);
	gtk_container_add(GTK_CONTAINER(vbox),hbox);

	hbox = gtk_hbox_new(FALSE,0);
	label = gtk_label_new("Community : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	community_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(community_entry), community);
        gtk_box_pack_start(GTK_BOX(hbox), community_entry, FALSE, FALSE, 0);
	gtk_container_add(GTK_CONTAINER(vbox),hbox);

	hbox = gtk_hbox_new(FALSE,0);
	label = gtk_label_new("OID : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	oid_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(oid_entry), oid_str);
        gtk_box_pack_start(GTK_BOX(hbox), oid_entry, FALSE, FALSE, 0);
	gtk_container_add(GTK_CONTAINER(vbox),hbox);


	hbox = gtk_hbox_new(FALSE,0);
	label = gtk_label_new("Format Text : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);

	format_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(format_entry), format);
	gtk_box_pack_start(GTK_BOX(hbox),format_entry,FALSE,FALSE,0);

	gtk_container_add(GTK_CONTAINER(vbox),hbox);



/* --- Info tab */
        vbox = create_tab(tabs, "Info");
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
        "SNMP",                /* Name, for config tab.        */
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
    oid_str = g_strdup(DEFAULT_OID);
    peername = g_strdup(DEFAULT_PEERNAME);
    community = g_strdup(DEFAULT_COMMUNITY);
    format = NULL;

    init_mib();
    objid_length = MAX_OID_LEN;
    read_objid(oid_str, objid, &objid_length);

    return &plugin_mon;
}


/*
int main(int argc, char *argv[])
{

    char *peername = "134.106.172.2";
    char *community = "public";
    char *objid = ".1.3.6.1.4.1.2021.8.1.101.1";

    printf(":%s:", simpleSNMPget(peername, community, objid));

    return 0;
}
*/





