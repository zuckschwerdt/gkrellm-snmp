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

#include <sys/time.h>


#include <gkrellm/gkrellm.h>

 
#define VOLUME_MAJOR_VERSION 0
#define VOLUME_MINOR_VERSION 6

#define PLUGIN_CONFIG_KEYWORD   "snmp_monitor"


typedef struct Reader Reader;

struct Reader {
  Reader           *next;
  gchar           *label;
  gchar            *peer;
  gint              port;
  gchar       *community;
  gchar         *oid_str;
  oid objid[MAX_OID_LEN];
  size_t    objid_length;
  gchar            *unit;
  gint             delay;
  gboolean        active;
  char       *old_sample;
  char     *fresh_sample;
  struct snmp_session *session;
  Panel           *panel;
} ;


int snmp_input(int op,
               struct snmp_session *session,
               int reqid,
               struct snmp_pdu *pdu,
               void *magic)
{
    struct variable_list *vars;
    char *result = NULL;

    if (op == RECEIVED_MESSAGE) {

      if (pdu->errstat == SNMP_ERR_NOERROR) {
        for(vars = pdu->variables; vars; vars = vars->next_variable) {
          if (vars->type == ASN_OCTET_STR) /* value is a string */
            result = g_strndup(vars->val.string, vars->val_len);
          if (vars->type == ASN_INTEGER) /* value is a integer */
            result = g_strdup_printf("%ld", *vars->val.integer);
        }
                              
      } else {
        fprintf(stderr, "Error in packet\nReason: %s\n",
                snmp_errstring(pdu->errstat));

        if (pdu->errstat == SNMP_ERR_NOSUCHNAME){
          fprintf(stderr, "This name doesn't exist: ");
        }
      }

      dup_string(session->callback_magic, result);
      g_free(result);

// besser ?
      /*
      if (session->callback_magic)
	g_free(session->callback_magic);
      session->callback_magic = result;
      */

    } else if (op == TIMED_OUT){
        fprintf(stderr, "Timeout: This shouldn't happen!\n");
    }
    return 1;
}

void simpleSNMPupdate()
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
    // gettimeofday(&Now, 0);
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

struct snmp_session
*simpleSNMPopen(char *peername, char *community,
		     char **destination)
{
    struct snmp_session session, *ss;

    /* initialize session to default values */
    snmp_sess_init( &session );

    session.version = SNMP_VERSION_1;
    session.community = community;
    session.community_len = strlen(community);
    session.peername = peername;

    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;

    session.callback = snmp_input;
    session.callback_magic = destination;
    session.authenticator = NULL;


    /* 
     * Open an SNMP session.
     */
    ss = snmp_open(&session);
    if (ss == NULL){
      snmp_sess_perror("snmpget", &session);
      exit(1);
    }

    return ss;
}

void simpleSNMPsend(struct snmp_session *session,
		   oid *name, size_t name_length)
{
    struct snmp_pdu *pdu;

    /* 
     * Create PDU for GET request and add object names to request.
     */
    pdu = snmp_pdu_create(SNMP_MSG_GET);

    snmp_add_null_var(pdu, name, name_length);

    /* 
     * Perform the request.
     */

    snmp_send(session, pdu);
}
 

static Reader *readers;
static GtkWidget *main_vbox;

static void
update_plugin()
{
  Reader *reader;
  //  Krell       *k;
  //  gint i;

  /* See if we recieved SNMP responses */
  simpleSNMPupdate();

  /* Send new SNMP requests */
  for (reader = readers; reader ; reader = reader->next)
  {
      //      k = KRELL(panel);
      //      k->previous = 0;

      if (! reader->session)
	  reader->session = simpleSNMPopen(reader->peer,
		    reader->community,
		    &reader->fresh_sample);


      /* Send new SNMP requests */
      if ((GK.timer_ticks % 100) == 0)
	  simpleSNMPsend(reader->session,
			 reader->objid,
			 reader->objid_length);


      if (strcmp(reader->fresh_sample, reader->old_sample) != 0)
      {
	g_free(reader->old_sample);
	reader->old_sample = g_strconcat (reader->label,
					  reader->fresh_sample,
					  reader->unit, NULL);
	reader->panel->textstyle = gkrellm_panel_textstyle(DEFAULT_STYLE);
	//	i = atoi(p);
      } else {
	reader->panel->textstyle = gkrellm_panel_alt_textstyle(DEFAULT_STYLE);
	//	i = -1;
      }
      
      //      gkrellm_update_krell(panel, k, i);

      //      reader->panel->label->string = text;
      dup_string(&reader->panel->label->string, reader->old_sample);

      gkrellm_draw_panel_label( reader->panel, GK.bg_panel_image[CLOCK_STYLE]);
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
		      reader->panel->pixmap, ev->area.x, ev->area.y,
		      ev->area.x, ev->area.y,
		      ev->area.width, ev->area.height);
    }
  return FALSE;
}

static void
create_reader(GtkWidget *vbox, Reader *reader, gint first_create)
{
      //    Krell           *k;
    Style           *style;
    //    GdkImlibImage   *krell_image;

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

    //    reader->panel->textstyle = gkrellm_panel_alt_textstyle(DEFAULT_STYLE);


    /* Build the configured panel with a background image and pack it into
    |  the vbox assigned to this monitor.
    */
    gkrellm_create_panel(vbox, reader->panel, gkrellm_bg_meter_image(DEFAULT_STYLE));
    gkrellm_monitor_height_adjust(reader->panel->h);

    if (first_create)
        gtk_signal_connect(GTK_OBJECT (reader->panel->drawing_area), "expose_event",
                (GtkSignalFunc) panel_expose_event, NULL);
}

static void
destroy_reader(Reader *reader)
{
  if (!reader)
    return;
  g_free(reader->label);
  g_free(reader->peer);
  g_free(reader->community);
  g_free(reader->oid_str);
  g_free(reader->unit);

  if (reader->session)
    snmp_close(reader->session);
  g_free(reader->session);

  GK.monitor_height -= reader->panel->h;
  gkrellm_destroy_panel(reader->panel);
  //  gtk_widget_destroy(reader->vbox);
  g_free(reader);
}

static void
create_plugin(GtkWidget *vbox, gint first_create)
{
  Reader *reader;

  main_vbox = vbox;

  for (reader = readers; reader ; reader = reader->next)
    {
      create_reader(vbox, reader, first_create);
    }
}

/* Config section */

static GtkWidget        *label_entry;
static GtkWidget        *peer_entry;
static GtkWidget        *port_entry;
static GtkWidget        *community_entry;
static GtkWidget        *oid_entry;
static GtkWidget        *unit_entry;
static GtkWidget        *reader_clist;
static gint             selected_row;
static gint             list_modified;


static void
save_plugin_config(FILE *f)
{
  Reader *reader;
  for (reader = readers; reader ; reader = reader->next)
    fprintf(f, "%s %s snmp://%s@%s/%s %s\n",
	    PLUGIN_CONFIG_KEYWORD,
	    reader->label, reader->community, reader->peer,
	    reader->oid_str, reader->unit);
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

  n = sscanf(arg, "%s %[^:]://%[^@]@%[^/]/%s %[^\n]",
	     bufl, proto, bufc, bufp, bufo, bufu);
  if (n >= 5)
    {
      if (g_strcasecmp(proto, "snmp") == 0) {
	dup_string(&reader->label, bufl);
	dup_string(&reader->community, bufc);
	dup_string(&reader->peer, bufp);
	dup_string(&reader->oid_str, bufo);
	reader->old_sample = g_strdup("empty");
	reader->fresh_sample = g_strdup("empty");
	reader->session = NULL;

	reader->objid_length = MAX_OID_LEN;
//	get_module_node(oid_str, "ANY", objid, &objid_length);
	read_objid(reader->oid_str, reader->objid, &reader->objid_length);

	if (n == 6) {
	  dup_string(&reader->unit, bufu);
	}

      }

      if (!readers) readers = reader;
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
  gchar    *name;
  gint    row;

  if (!list_modified)
    return;

  for (reader = readers; reader; reader = readers) {
    readers = reader->next;
    destroy_reader(reader);
  }

  for (row = 0; row < GTK_CLIST(reader_clist)->rows; ++row)
    {
      reader = g_new0(Reader, 1);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, 0, &name);
      dup_string(&reader->label, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, 1, &name);
      dup_string(&reader->peer, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, 3, &name);
      dup_string(&reader->community, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, 4, &name);
      dup_string(&reader->oid_str, name);
      reader->objid_length = MAX_OID_LEN;
//      get_module_node(oid_str, "ANY", objid, &objid_length);
      read_objid(reader->oid_str, reader->objid, &reader->objid_length);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, 5, &name);
      dup_string(&reader->unit, name);

      if (!readers) readers = reader;
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
  //  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button1), FALSE);
  gtk_entry_set_text(GTK_ENTRY(community_entry), "");
  gtk_entry_set_text(GTK_ENTRY(oid_entry), "");
  gtk_entry_set_text(GTK_ENTRY(unit_entry), "");
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
  //  gtk_entry_set_text(GTK_ENTRY(port_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(community_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(oid_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(unit_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  //  gtk_entry_set_text(GTK_ENTRY(freq_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  state = (strcmp(s, "yes") == 0) ? TRUE : FALSE;
  //  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(mounting_button), state);

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
  gchar           *buf[9];
  gint            i, n;

  i = 0;
  buf[i++] = entry_get_alpha_text(&label_entry);
  buf[i++] = entry_get_alpha_text(&peer_entry);
  buf[i++] = "161"; // entry_get_alpha_text(port_entry);
  buf[i++] = entry_get_alpha_text(&community_entry);
  n = i;
  buf[i++] = entry_get_alpha_text(&oid_entry);
  buf[i++] = entry_get_alpha_text(&unit_entry);
  buf[i++] = "100"; // entry_get_alpha_text(umount_entry);
  buf[i++] = "no"; // GTK_TOGGLE_BUTTON(mounting_button)->active ? "yes" : "no";
  buf[i] = NULL;

  if (*(buf[0]) == '\0' || *(buf[1]) == '\0')     /* validate we have input */
    return;
  if ((*(buf[n]) && !*(buf[n+1])) || (!*(buf[n]) && *(buf[n+1])))
    {
      gkrellm_config_message_window("Entry Error",
				    "Both mount and umount commands must be entered.", widget);
      return;
    }
  if (selected_row >= 0)
    {
      for (i = 0; i < 8; ++i)
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


static gchar    *plugin_info_text =
"This configuration tab is for the SNMP monitor plugin.\n"
"Put any documentation here to explain your plugin.\n"
"You could also add your name and email address in case\n"
"of any user questions.\n"
;

static gchar    *plugin_about_text =
   "SNMP plugin 0.6\n"
   "GKrellM SNMP monitor Plugin\n\n"
   "Copyright (C) 2000 Christian W. Zuckschwerdt\n"
   "zany@triq.net\n\n"
   "http://triq.net/gkrellm/\n\n"
   "Released under the GNU Public Licence"
;


static gchar *reader_title[8] =
{ "Label", "Peer", "Port",
  "Community", "OID", "Unit",
  "Freq", "Active" };

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

  gchar                   *buf[9];
  gint                    row, i;

        /* Make a couple of tabs.  One for setup and one for info
        */
        tabs = gtk_notebook_new();
        gtk_notebook_set_tab_pos(GTK_NOTEBOOK(tabs), GTK_POS_TOP);
        gtk_box_pack_start(GTK_BOX(tab_vbox), tabs, TRUE, TRUE, 0);

/* --- Setup tab */
        vbox = create_tab(tabs, "Setup");

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
	port_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(port_entry), "");
	gtk_box_pack_start(GTK_BOX(hbox),port_entry,FALSE,FALSE,0);

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

	reader_clist = gtk_clist_new_with_titles(8, reader_title);	
        gtk_clist_set_shadow_type (GTK_CLIST(reader_clist), GTK_SHADOW_OUT);
	gtk_clist_set_column_width (GTK_CLIST(reader_clist), 1, 100);
	gtk_clist_set_column_width (GTK_CLIST(reader_clist), 4, 200);

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
	    buf[i++] = "161"; // reader->port;
	    buf[i++] = reader->community;
	    buf[i++] = reader->oid_str;
	    buf[i++] = reader->unit;
	    buf[i++] = "100"; // reader->delay;
	    buf[i++] = reader->active ? "yes" : "no";
	    buf[i] = NULL;
	    row = gtk_clist_append(GTK_CLIST(reader_clist), buf);
	  }


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
  readers = NULL;

  init_mib();

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





