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


#include <stdio.h>

#include <gkrellm2/gkrellm.h>

#include <simpleSNMP.h>


#define SNMP_PLUGIN_MAJOR_VERSION 1
#define SNMP_PLUGIN_MINOR_VERSION 2


/* The name of the plugin in the Configuration menu */
#define PLUGIN_CONFIG_NAME	"SNMP"
/* The name of the configuration data in the user-config file */
#define PLUGIN_CONFIG_KEYWORD	"snmp_monitor"
/* The plugin specific style for theme subdir name and gkrellmrc */
#define PLUGIN_STYLE_ID		"snmp"

/* The parameters for the format based text display in the a chart */
#define DEFAULT_FORMAT		"$L $0"
#define MAX_FORMAT_VALUES	MAX_OID_STR
#define MAX_CHART_VALUES	3

/* The default settings for spin buttons, so they can be reset */
#define	DEFAULT_PORT		161
#define	DEFAULT_VERS		1
#define	DEFAULT_FREQ		100
#define	DEFAULT_DIVISOR		1

/* The data structure for a chart */

typedef struct Reader Reader;

struct Reader {
	Reader			*next;
	gchar			*label;
	gchar			*peer;
	gint			port;
	gint			vers;
	gchar			*community;
	gchar			*oid_base;
	gchar			*oid_elements;
	gchar			*oid_str[MAX_OID_STR];
	gint			num_oid_str;
	gint			divisor;
	gboolean		panel;
	gint			delay;
	gboolean		delta;
	gchar			*formatString;  /* Format for chart labels */
	gboolean		hideExtra;      /* True to hide extra info */

	/* The sample data for a chart */
	gint			new;
	glong			sample_time;
	glong			old_sample_time;
	gchar			*error;
	gchar			*old_error;
	gint			num_sample;
	gint			asn1_type[MAX_FORMAT_VALUES];
	gchar			*sample[MAX_FORMAT_VALUES];
	glong			sample_n[MAX_FORMAT_VALUES];
	glong			old_sample_n[MAX_FORMAT_VALUES];

	/* The simpleSNMP interface information */
	struct snmp_session	*session;
	struct input_data	new_data;

	/* The gkrellm interface information */
	GtkTooltips             *tooltip;
	GkrellmChart		*chart;
	GkrellmChartconfig	*chart_config;
};

 
static GkrellmMonitor *mon;
static Reader *readers;
static GtkWidget *main_vbox;
static gint style_id;


static gchar *
scale(glong num, gboolean scale_it)
{
    if (scale_it) {
	if (num > 2000000000)
	    return g_strdup_printf("%ldG", num/1024/1024/1024);
	if (num > 6000000)
	    return g_strdup_printf("%ldM", num/1024/1024);
	if (num > 6000)
	    return g_strdup_printf("%ldK", num/1024);
    }
    return g_strdup_printf("%ld", num);
}


static void
render_error(Reader *reader)
{
    gchar *message;

	if (reader->old_error && !strcmp(reader->old_error, reader->error)) {
		// don't repeat the same error message
		g_free(reader->error);

	} else {
		g_free(reader->old_error);
		reader->old_error = reader->error;

    message = g_strdup_printf ("%s (snmp%s://%s@%s:%d/%s[%s])\n%s",
			    reader->label,
			    reader->vers == 2 ? "-v2c" : "",
			    reader->community,
			    reader->peer, reader->port,
			    reader->oid_base,
			    reader->oid_elements,
			    reader->error);
    /* Note, the title is currently not displayed! */
    gkrellm_message_dialog("SNMP Plugin Error", message);

		g_free(message);
	}
}


static glong
new_value (Reader *reader, gint sample_num)
{
    glong since_last = 0;
    glong val;

    /* 100: turn TimeTicks into seconds */
    since_last = (reader->sample_time - reader->old_sample_time) / 100;

//AG Multi: What needs to be different for each sample_num?
    if (reader->delta && reader->divisor == 0)
	val = (reader->sample_n[sample_num] - reader->old_sample_n[sample_num]);
    else if (reader->delta)
	val = (reader->sample_n[sample_num] - reader->old_sample_n[sample_num]) /
		( (since_last < 1) ? 1 : since_last ) / reader->divisor;
    else
	val = reader->sample_n[sample_num] / 
		( (reader->divisor == 0) ? 1 : reader->divisor );

    return val;
}


/*
 * Adapted from cpu.c
 */
static gchar *
render_label(Reader *reader)
{
    gchar c;
    gchar *s;
    gint index;
    gint len;
    gboolean scale_it;
    glong value;
    gchar buffer[128];
    gchar *buf = buffer;
    gint size = sizeof (buffer);

    if (buf == NULL  ||  size < 1)
        return g_strdup ("");
    --size;			/* Make sure there's room for NUL at end */
    *buf = '\0';

    if (reader->formatString == NULL)
        return g_strdup ("");

    for (s = reader->formatString;  *s != '\0'  &&  size > 0;  ++s) {
	len = 1;
	if (*s == '$'  &&  s[1] != '\0') {
	    c = s[1];
	    if (c == 'S' && s[2] != '\0') {
		scale_it = TRUE;
		c = s[2];
		++s;
	    } else {
		scale_it = FALSE;
	    }
	    /*
	     * SEMI-BUG: this code only supports 36 string codes (0-9 and a-z).
	     */
	    if (c == 'L') {
		/* Note, we ignore the scale argument */
		len = snprintf(buf, size, "%s", reader->label);
	    } else if (c == 'M') {
		index = gkrellm_get_chart_scalemax(reader->chart);
		len = snprintf(buf, size, "%s", scale(index, scale_it));
	    } else if (c == 'I') {
		len = snprintf(buf, size, "%ss", 
		   scale((reader->sample_time - reader->old_sample_time + 50)/100,
		   scale_it));
	    } else {
		index = -1;
		if (isdigit(c))
		    index = c - '0';
		else if (islower(c))
		    index = c - 'a';
		if (index >= 0  &&  index < MAX_FORMAT_VALUES) {
		    if (index >= reader->num_sample) {
			len = 0;
		    } else {
			value = new_value (reader, index);
			len = snprintf(buf, size, "%s", scale(value, scale_it));
		    }
		}
		else {
		    *buf = *s;
		    if (size > 1) {
			*(buf + 1) = *(s + 1);
			++len;
		    }
		}
	    }
	    ++s;
	}
	else
	    *buf = *s;
	size -= len;
	buf += len;
    }
    *buf = '\0';	

    return g_strdup (buffer);
}


static gchar *
render_info(Reader *reader)
{
    glong since_last = 0;
    glong val;
    gint up_d, up_h, up_m;
    gint i;
    gchar time_buf [100];
    gchar divisor_buf [100];
    gchar *temp_buf;
    gchar *sample_buf;
    
    /* 100: turn TimeTicks into seconds */
    since_last = (reader->sample_time - reader->old_sample_time) / 100;

    up_d = reader->sample_time/100/60/60/24;
    up_h = (reader->sample_time/100/60/60) % 24;
    up_m = (reader->sample_time/100/60) % 60;


    if (reader->delta && reader->divisor != 0) {
	sprintf (time_buf, "/ %lds", since_last);
    } else {
	sprintf (time_buf, "[%lds]", since_last);
    }
    if (reader->divisor > 1) {
	sprintf (divisor_buf, "/ %d ", reader->divisor);
    } else {
	divisor_buf[0] = '\0';
    }

    sample_buf = g_strdup ("");
    for (i = 0; i < reader->num_sample; i++) {
	val = new_value (reader, i);
	temp_buf = g_strdup_printf ("%s\n '%s' %ld%s%ld%s %s %s-> %ld", sample_buf,
			reader->sample[i],
			reader->sample_n[i],
			reader->delta ? "-" : "[",
			reader->old_sample_n[i],
			reader->delta ? "" : "]",
			time_buf,
			divisor_buf,
			val);
	g_free (sample_buf);
	sample_buf = temp_buf;
	temp_buf = NULL;
    }

    return g_strdup_printf("%s: (snmp%s://%s@%s:%d/%s[%s]) Uptime: %dd %d:%d%s",
			reader->label,
			reader->vers == 2 ? "-v2c" : "",
			reader->community,
			reader->peer, reader->port,
			reader->oid_base,
			reader->oid_elements,
			up_d, up_h, up_m,
			sample_buf);
}


/* GKrellM Callbacks */

static void
cb_draw_chart(gpointer data)
{
	Reader *reader = (Reader *)data;
	gchar *text = NULL;

	gkrellm_draw_chartdata(reader->chart);
	if (!reader->hideExtra) {
	    text = render_label(reader);
	    gkrellm_draw_chart_text(reader->chart,
				style_id,
				text);
	    g_free (text);
	}

	if (reader->chart->panel) gkrellm_draw_panel_label(reader->chart->panel);
	gkrellm_draw_chart_to_screen(reader->chart);
}

static void
cb_chart_click(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	Reader *reader = (Reader *)data;

	if (event->button == 1) {
	    reader->hideExtra = !reader->hideExtra;
	    cb_draw_chart(reader);
	    gkrellm_config_modified();
	} else if (event->button == 3) {
	    gkrellm_chartconfig_window_create(reader->chart);
	}
}

static void
cb_panel_click(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	if (event->button == 3)
            gkrellm_open_config_window(mon);
}


/* GKrellM interface */

static void
update_plugin()
{
    Reader *reader;
    gchar  *text = NULL;
    gint i;
    glong val[MAX_CHART_VALUES];

    /* See if we received SNMP responses */
    simpleSNMPupdate();

    /* Send new SNMP requests */
    for (reader = readers; reader ; reader = reader->next)
    {
	if (! reader->session) {
	    reader->session = simpleSNMPopen(reader->peer,
					     reader->port,
					     reader->vers,
					     reader->community,
					     &reader->new_data);
	    if (! reader->session) {
		reader->error = reader->new_data.error;
		reader->new_data.error = NULL;
		render_error(reader);
	    }
	    reader->new_data.new = 0;
	    reader->new = 0;
	}

	/* Update new data, if available */
	if (reader->session && reader->new_data.new != 0) {
	    if (reader->new_data.error) {
		reader->error = reader->new_data.error;
		reader->new_data.error = NULL;
		render_error(reader);
	    } else {
		reader->old_sample_time = reader->sample_time;
		reader->sample_time = reader->new_data.sample_n[0];
		reader->num_sample = reader->new_data.num_sample - 1;
		for (i = 0; i < reader->num_sample; i++) {
		    reader->asn1_type[i] = reader->new_data.asn1_type[i + 1];
		    if (reader->sample[i]) g_free(reader->sample[i]);
		    reader->sample[i] = reader->new_data.sample[i + 1];
		    reader->new_data.sample[i + 1] = NULL;
		    reader->old_sample_n[i] = reader->sample_n[i];
		    reader->sample_n[i] = reader->new_data.sample_n[i + 1];
		}
		reader->new = 1;
	    }
	    reader->new_data.new = 0;
	}

	/* Send new SNMP requests */
	if ( (reader->session) && ((GK.timer_ticks % reader->delay) == 0)) {
	    if (!simpleSNMPsend(reader->session, reader->oid_str, 
							reader->num_oid_str)) {
		reader->error = reader->new_data.error;
		reader->new_data.error = NULL;
		reader->new_data.new = 0;
		render_error(reader);
	    }
	}

	/* Note, we may get the data delayed by one or more grkrell interval's */
	if (reader->session && reader->new != 0) {
	    if (reader->chart != NULL)
	    {
		for (i = 0; i < MAX_CHART_VALUES; i++) {
		    val[i] = 0;
		}
		for (i = 0; i < MAX_CHART_VALUES && i < reader->num_sample; i++) {
		    val[i] = new_value (reader, i);
		}
		/* Note, the number of val[] must be exactly MAX_CHART_VALUES */
		gkrellm_store_chartdata(reader->chart, 0, val[0], val[1], val[2]);
		cb_draw_chart(reader);

		text = render_info(reader);
		gtk_tooltips_set_tip(reader->tooltip, 
					reader->chart->drawing_area, text, "");
		gtk_tooltips_enable(reader->tooltip);
		g_free(text);
	    }
	    reader->new = 0;
	}
    }
}

static gint
chart_expose_event(GtkWidget *widget, GdkEventExpose *ev, gpointer data_ptr)
{
    gdk_draw_pixmap(widget->window,
			    widget->style->fg_gc[GTK_WIDGET_STATE (widget)],
			    (GdkPixmap *)data_ptr,
			    ev->area.x, ev->area.y, ev->area.x, ev->area.y,
			    ev->area.width, ev->area.height);
    return FALSE;
}

static void
create_chart(GtkWidget *vbox, Reader *reader, gint first_create)
{
    GkrellmChartdata *cd;
    gchar *chart_text;
    gint i;

    if (first_create) {
	reader->chart = gkrellm_chart_new0();
	if (reader->panel) {
	    reader->chart->panel = gkrellm_panel_new0();
	} else {
	    reader->chart->panel = NULL;
	}
    }

    gkrellm_chart_create(vbox, mon, reader->chart, &reader->chart_config);

    gkrellm_chartconfig_grid_resolution_adjustment(reader->chart_config,
                /*map*/TRUE, /*spin_factor*/1.0, /*low*/1, /*high*/100000000,
			/*step0*/0, /*step1*/0, /*digits*/0, /*width*/50);
    gkrellm_chartconfig_grid_resolution_label(reader->chart_config,
	_("Units drawn on the chart"));

    for (i = 0; i < MAX_CHART_VALUES; i++) {
	chart_text = g_strdup_printf ("Data Chart %d", i);
	cd = gkrellm_add_default_chartdata(reader->chart, chart_text);
	gkrellm_monotonic_chartdata(cd, FALSE);
	gkrellm_set_chartdata_draw_style_default(cd, CHARTDATA_LINE);
	gkrellm_set_chartdata_flags(cd, CHARTDATA_ALLOW_HIDE);
	g_free (chart_text);
    }

    if (reader->chart->panel) {
	gkrellm_panel_configure(reader->chart->panel, reader->label, 
						gkrellm_panel_style(style_id));
	gkrellm_panel_create(vbox, mon, reader->chart->panel);
    }

    gkrellm_alloc_chartdata(reader->chart);

    if (first_create)
    {
	gkrellm_set_draw_chart_function(reader->chart, cb_draw_chart, reader);
	gtk_signal_connect(GTK_OBJECT(reader->chart->drawing_area),
			"expose_event", (GtkSignalFunc) chart_expose_event, 
			reader->chart->pixmap);
	gtk_signal_connect(GTK_OBJECT(reader->chart->drawing_area),
			"button_press_event", (GtkSignalFunc) cb_chart_click, 
			reader);
	if (reader->chart->panel) {
	    gtk_signal_connect(GTK_OBJECT(reader->chart->panel->drawing_area),
			"expose_event", (GtkSignalFunc) chart_expose_event, 
			reader->chart->panel->pixmap);
	    gtk_signal_connect(GTK_OBJECT(reader->chart->panel->drawing_area),
			"button_press_event", (GtkSignalFunc) cb_panel_click, 
			reader->chart->panel);
	}
	reader->tooltip=gtk_tooltips_new();
    }
    else
    {
	cb_draw_chart(reader);
    }
}


static void
create_reader(GtkWidget *vbox, Reader *reader, gint first_create)
{
	create_chart(vbox, reader, first_create);
}

static void
destroy_reader(Reader *reader)
{
	gint i;

	if (!reader)
		return;

	g_free(reader->label);
	g_free(reader->peer);
	g_free(reader->community);
	g_free(reader->oid_base);
	g_free(reader->oid_elements);
	for (i = 0; i < reader->num_oid_str; i++) {
	    g_free(reader->oid_str[i]);
	}
	g_free(reader->formatString);

	for (i = 0; i < reader->num_sample; i++) {
	    g_free(reader->sample[i]);
	}

	if (reader->session)
		simpleSNMPclose(reader->session);
	/* can't free snmp session. may be there are pending snmp_reads! */
	/*
	if (reader->session)
		simpleSNMPclose(reader->session);
	g_free(reader->session);
	*/
  
	if (reader->chart)
	{
		gkrellm_chartconfig_destroy(&reader->chart_config);
		gkrellm_chart_destroy(reader->chart);
	}

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

static void
prepare_oid_str (Reader *reader)
{
	gchar *elements;
	gchar *elementp;
	gchar *element;
	gint i;

	/* The first oid_str is for system up time */
	gkrellm_dup_string(&reader->oid_str[0], "system.sysUpTime.0");

	/* Check if there is a marker in the base */
//AG String Functions: don't know about glib or gkrellm functions for this
	if (strstr (reader->oid_base, "%s") == NULL ||
					strlen (reader->oid_elements) == 0) {
	    gkrellm_dup_string(&reader->oid_str[1], reader->oid_base);
	    reader->num_oid_str = 2;
	} else {
	    /* Insert each element into the base */
	    elements = g_strdup (reader->oid_elements);
	    elementp = elements;
	    for (i = 0; i < MAX_FORMAT_VALUES; i++) {
//AG String Functions: don't know about glib or gkrellm functions for this
		element = strsep (&elementp, ",");
		reader->oid_str[1 + i] = 
				g_strdup_printf (reader->oid_base, element);
		if (elementp == NULL) {
		    i++;
		    break;
		}
	    }
	    g_free (elements);
	    reader->num_oid_str = 1 + i;
	}

	for (i = 0; i < reader->num_oid_str; i++) {
	    if (!simpleSNMPcheck_oid(reader->oid_str[i])) {
		reader->error = g_strdup_printf("Error parsing oid: %s", 
							reader->oid_str[i]);
		render_error (reader);
		break;
	    }
	}
}

/* Config section */

#define CLIST_WIDTH 13

/* This list represents the internal order and elements of each config table, */
/* it is used for the definition of reader_clist in create_plugin_tab() below */
static gchar *reader_title[CLIST_WIDTH] =
{ "Label", "Peer", "Port", "V",
  "Community", "OID", "Elements",
  "Freq", "Format", "Divisor", 
  "Hide", "Delta", "Panel" };

/* The global elements underlying the configuration table */
/* They are mapped to the display layout in create_plugin_tab() below */
static GtkWidget        *label_entry;
static GtkWidget        *peer_entry;
static GtkObject        *port_spin_adj;
static GtkWidget        *port_spin;
static GtkObject        *vers_spin_adj;
static GtkWidget        *vers_spin;
static GtkWidget        *community_entry;
static GtkWidget        *oid_entry;
static GtkWidget        *elements_entry;
static GtkObject        *freq_spin_adj;
static GtkWidget        *freq_spin;
static GtkWidget        *format_entry;
static GtkObject        *div_spin_adj;
static GtkWidget        *div_spin;
static GtkWidget        *hide_button;
static GtkWidget        *delta_button;
static GtkWidget        *panel_button;

static GtkWidget        *reader_clist;
static gint             selected_row = -1;
static gint             list_modified;

#define	 STR_DELIMITERS	" \t"

static void
save_plugin_config(FILE *f)
{
  Reader *reader;
  gchar *label, *format, *elements;
  gchar *unit = "_";

  for (reader = readers; reader ; reader = reader->next) {
      label = g_strdelimit(g_strdup(reader->label), STR_DELIMITERS, '_');
      format = g_strdelimit(g_strdup(reader->formatString), STR_DELIMITERS, '_');
      elements = g_strdelimit(g_strdup(reader->oid_elements), STR_DELIMITERS,'_');
      if (label[0] == '\0') label = strdup("_");
      if (format[0] == '\0') format = strdup("_");
      if (elements[0]  == '\0') elements = strdup("_");

      /* The layout of a config file entry is given by the following format, */
      /* unit and scale are not used, but left in place in the config file */
      fprintf(f, "%s %s snmp%s://%s@%s:%d/%s %s %d %d %d %d %d %s %d %s\n",
	      PLUGIN_CONFIG_KEYWORD,
	      label,
		  reader->vers == 2 ? "-v2c" : "",
		  reader->community,
	      reader->peer, reader->port,
	      reader->oid_base, unit,
	      reader->delay, 
//AG Multi: The following may need to be repeated for each oid_str
	      reader->delta, reader->divisor, 
	      0, reader->panel,
	      format, reader->hideExtra, elements);
      gkrellm_save_chartconfig(f, reader->chart_config, PLUGIN_CONFIG_KEYWORD, label);
      g_free(label);
      g_free(format);
      g_free(elements);
  }
}

static void
load_plugin_config(gchar *config_line)
{
  Reader *reader, *nreader = NULL;

  gchar   proto[CFG_BUFSIZE], bufl[CFG_BUFSIZE];
  gchar   bufc[CFG_BUFSIZE], bufp[CFG_BUFSIZE];
  gchar   bufo[CFG_BUFSIZE], bufu[CFG_BUFSIZE];
  gchar   buft[CFG_BUFSIZE], peer[CFG_BUFSIZE];
  gchar   buff[CFG_BUFSIZE], bufe[CFG_BUFSIZE];
  gint    old_scale;
  gint    n;

  if (sscanf(config_line, GKRELLM_CHARTCONFIG_KEYWORD " %s %[^\n]", bufl, bufc) == 2) {
	g_strdelimit(bufl, "_", ' ');
	/* look for any such reader */
	for (reader = readers; reader ; reader = reader->next) {
		if (!strcmp(reader->label, bufl)) {
			nreader = reader;
			break;
		}
	}
	/* look for unconf'd reader */
	for (reader = readers; reader ; reader = reader->next) {
		if (!strcmp(reader->label, bufl) && !reader->chart_config) {
			nreader = reader;
			break;
		}
	}
	if (!nreader) {/* well... */
	    /* There is no reader here, can't use render_error() */
	    g_snprintf(bufc, CFG_BUFSIZE,
		"chart_config appeared before chart, this isn't handled\n%s\n",
		config_line);
	    /* Note, the title is currently not displayed! */
    	    gkrellm_message_dialog("Config file problem", bufc);
	    return;
	}
	gkrellm_load_chartconfig(&nreader->chart_config, bufc, MAX_CHART_VALUES);
  	return;
  }

  // TODO: re-enabling the plugin will load a duplicate config and crash
  reader = g_new0(Reader, 1); 

  /* The layout of a config file entry is given by one of the following formats */
  /* unit and scale are not used, but left in place in the config file */
  n = sscanf(config_line, 
		"%s %[^:]://%[^@]@%[^:]:%[^:]:%d/%s %s %d %d %d %d %d %s %d %s",
	     bufl, proto, bufc, buft, bufp, &reader->port, 
	     bufo, bufu,
	     &reader->delay, 
//AG Multi: The following may need to be repeated for each oid_str
	     &reader->delta, &reader->divisor, 
	     &old_scale, &reader->panel,
	     buff, &reader->hideExtra, bufe);
  if (n >= 6) {
	g_snprintf(peer, CFG_BUFSIZE, "%s:%s", buft, bufp);
	peer[CFG_BUFSIZE-1] = '\0';
  } else
	  n = sscanf(config_line, 
			"%s %[^:]://%[^@]@%[^:]:%d/%s %s %d %d %d %d %d %s %d %s",
	     bufl, proto, bufc, peer, &reader->port, 
	     bufo, bufu,
	     &reader->delay, 
//AG Multi: The following may need to be repeated for each oid_str
	     &reader->delta, &reader->divisor, 
	     &old_scale, &reader->panel,
	     buff, &reader->hideExtra, bufe);
  if (n >= 7)
    {
      if (g_ascii_strcasecmp(proto, "snmp") == 0
      		|| g_ascii_strcasecmp(proto, "snmp-v2c") == 0) {
	reader->vers = g_ascii_strcasecmp(proto, "snmp-v2c") == 0 ? 2 : 1;
	gkrellm_dup_string(&reader->label, bufl);
	gkrellm_dup_string(&reader->community, bufc);
	gkrellm_dup_string(&reader->peer, peer);
	if (reader->delay < 2)
	    reader->delay = 100;

	gkrellm_dup_string(&reader->oid_base, bufo);
	/* Note, bufu is ignored, but left in place in the config file */

	if (n >= 13) {
	    gkrellm_dup_string(&reader->formatString, buff);
	} else {
	    gkrellm_dup_string(&reader->formatString, DEFAULT_FORMAT);
	    reader->panel = FALSE;
	}

	if (n >= 15) {
	    if (bufe[0] == '_') {
		gkrellm_dup_string(&reader->oid_elements, &bufe[1]);
	    } else {
		gkrellm_dup_string(&reader->oid_elements, bufe);
	    }
	    g_strdelimit(reader->oid_elements, "_", ' ');
	} else {
	    gkrellm_dup_string(&reader->oid_elements, "");
	    reader->hideExtra = FALSE;
	}
	prepare_oid_str (reader);

	g_strdelimit(reader->label, "_", ' ');
	g_strdelimit(reader->formatString, "_", ' ');
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

      /* The order of this code must follow reader_clist, */
      /* which is based on reader_title[], defined above */

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->label, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->peer, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->port = atoi(name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->vers = atoi(name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->community, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->oid_base, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->oid_elements, name);

      prepare_oid_str (reader);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->delay = atoi(name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      gkrellm_dup_string(&reader->formatString, name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->divisor = atoi(name);

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->hideExtra = (strcmp(name, "yes") == 0) ? TRUE : FALSE;

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->delta = (strcmp(name, "yes") == 0) ? TRUE : FALSE;

      gtk_clist_get_text(GTK_CLIST(reader_clist), row, i++, &name);
      reader->panel = (strcmp(name, "yes") == 0) ? TRUE : FALSE;

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
  gtk_spin_button_set_value (GTK_SPIN_BUTTON(port_spin), DEFAULT_PORT);
  // gtk_entry_set_text(GTK_ENTRY(port_entry), "");
  gtk_spin_button_set_value (GTK_SPIN_BUTTON(vers_spin), DEFAULT_VERS);
  // gtk_entry_set_text(GTK_ENTRY(vers_entry), "");
  gtk_entry_set_text(GTK_ENTRY(community_entry), "");
  gtk_entry_set_text(GTK_ENTRY(oid_entry), "");
  gtk_entry_set_text(GTK_ENTRY(elements_entry), "");
  gtk_spin_button_set_value (GTK_SPIN_BUTTON(freq_spin), DEFAULT_FREQ);
  // gtk_entry_set_text(GTK_ENTRY(freq_entry), "");
  gtk_entry_set_text(GTK_ENTRY(format_entry), DEFAULT_FORMAT);
  gtk_spin_button_set_value (GTK_SPIN_BUTTON(div_spin), DEFAULT_DIVISOR);
  // gtk_entry_set_text(GTK_ENTRY(div_entry), "");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hide_button), FALSE);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(delta_button), FALSE);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(panel_button), FALSE);
}


static void
cb_clist_selected(GtkWidget *clist, gint row, gint column,
		  GdkEventButton *bevent)
{
  gchar           *s;
  gint            state, i;

  /* The order of this code must follow reader_clist, */
  /* which is based on reader_title[], defined above */

  i = 0;
  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(label_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(peer_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(port_spin), s);
  //  gtk_spin_button_get_value_as_int(GTK_SPINBUTTON(port_spin), 161);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(vers_spin), s);
  //  gtk_spin_button_get_value_as_int(GTK_SPINBUTTON(vers_spin), 1);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(community_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(oid_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(elements_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(freq_spin), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(format_entry), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  gtk_entry_set_text(GTK_ENTRY(div_spin), s);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  state = (strcmp(s, "yes") == 0) ? TRUE : FALSE;
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hide_button), state);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  state = (strcmp(s, "yes") == 0) ? TRUE : FALSE;
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(delta_button), state);

  gtk_clist_get_text(GTK_CLIST(clist), row, i++, &s);
  state = (strcmp(s, "yes") == 0) ? TRUE : FALSE;
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(panel_button), state);

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
  /* The order of this list must follow reader_clist, */
  /* which is based on reader_title[], defined above */
  buf[i++] = gkrellm_gtk_entry_get_text(&label_entry);
  buf[i++] = gkrellm_gtk_entry_get_text(&peer_entry);
  buf[i++] = gkrellm_gtk_entry_get_text(&port_spin);
  buf[i++] = gkrellm_gtk_entry_get_text(&vers_spin);
  buf[i++] = gkrellm_gtk_entry_get_text(&community_entry);
  buf[i++] = gkrellm_gtk_entry_get_text(&oid_entry);
  buf[i++] = gkrellm_gtk_entry_get_text(&elements_entry);
  buf[i++] = gkrellm_gtk_entry_get_text(&freq_spin);
  buf[i++] = gkrellm_gtk_entry_get_text(&format_entry);
  buf[i++] = gkrellm_gtk_entry_get_text(&div_spin);
  buf[i++] = GTK_TOGGLE_BUTTON(hide_button)->active ? "yes" : "no";
  buf[i++] = GTK_TOGGLE_BUTTON(delta_button)->active ? "yes" : "no";
  buf[i++] = GTK_TOGGLE_BUTTON(panel_button)->active ? "yes" : "no";

  /* validate we have input */
  if (!*(buf[1]) || !*(buf[2]) || !*(buf[3]) || !*(buf[4]))
    {
      gkrellm_config_message_dialog("Entry Error",
			"Peer, Port, Community and OID must be entered.");
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
	gint vers;
	gchar *community;
	gchar *probe;

	peer = gkrellm_gtk_entry_get_text(&peer_entry);
	port = atoi(gkrellm_gtk_entry_get_text(&port_spin));
	vers = atoi(gkrellm_gtk_entry_get_text(&vers_spin));
	community = gkrellm_gtk_entry_get_text(&community_entry);

	/* validate we have input */
	if (!*(peer) || !*(community))
	{
		gkrellm_config_message_dialog("Entry Error",
			"Peer, Port and Community must be entered.");
		return;
	}
	probe = simpleSNMPprobe(peer, port, vers, community);
	gkrellm_config_message_dialog("SNMP Probe", probe);
	g_free(probe);
}


static gchar    *plugin_info_text[] = {
"This configuration tab is for the SNMP monitor plugin.\n"
"\n"
"Adding new SNMP readers should be fairly easy.\n",
"<i>Label -", " is a unique name that gets prepended to your reader.\n",
"<i>Peer, Port, and Community -", " are the respective SNMP parameters.\n"
"You can prepend a specific transport to the peer name.\n"
"(i.e. tcp:192.168.0.1)\n",
"<i>Port -", " ist preselected with the default value 161.\n",
"<i>Freq -", " sets the delay between updates of the reader value.\n"
"It's measured in GKrellM ticks -- as specified under General Options.\n"
"\n",
"<i>OID -", " is either a complete SNMP OID, or a base OID containing '%s'.\n",
"<i>Elements -", " contains a comma separated list of elements to be inserted\n"
"individually into the base OID, in order to create a list of SNMP OID's.\n"
"If the OID entry doesn't contain '%s', Elements is ignored.\n"
"Up to 10 SNMP OID's may be created, the values returned for the\n"
"first 3 will be charted, the remaining ones are available for formatting.\n"
"\n",
"<i>Format -", " specifies the chart label format to be overlayed over the chart.\n"
"The position codes defined under General Info are available as well as:\n"
"$L the Label specified for the chart,\n"
"$M the maximum chart value, $I the sample interval,\n"
"and $0 up to $9 and $S0 up to $S9 for the values, or the\n"
"auto scaled values respectively, returned for the defined OID's.\n"
"\n"
"Some examples:\n"
"\n"
"(1)\n"
"The ambient temperature sensor for some net-snmp server\n"
"public / 192.168.1.2 port 161 oid .1.3.6.1.4.1.2021.8.1.101.1\n"
"\n"
"That is:\n"
" SNMP peer '192.168.1.2' (some.server.name)\n"
" SNMP port '161' (that's the default)\n"
" SNMP community name 'public'\n"
" SNMP oid '.1.3.6.1.4.1.2021.8.1.101.1'\n"
"\n"
"Resonable Label/Unit would be 'Temp.' / '°C'\n"
"\n"
"(2)\n"
"\n"
"Server CPU load using a string ranging from 0.00 to 1.00\n"
"\n"
"public / 192.168.1.3 pot 161 oid .1.3.6.1.4.1.2021.10.1.3.1\n"
"(Thats the load factor for some server)\n"
"\n"
"(3)\n"
"\n"
"Server CPU load using integer variable ranging from 0 to 100\n"
"\n"
"public / 192.168.1.4 port 161 oid .1.3.6.1.4.1.2021.10.1.5.1\n"
"(Thats the percentile load for some server)\n"
"\n"
"please mail any problems/questions to me...\n" }
;

static gchar    *plugin_about_text =
   "SNMP plugin  Version %d.%d\n"
   "GKrellM SNMP monitor Plugin\n\n"
   "Copyright (C) 2000-2020 Christian W. Zuckschwerdt <zany@triq.net>\n"
   "\n"
   "http://triq.net/gkrellm.html\n\n"
   "Released under the GNU Public Licence with OpenSSL exemption"
;
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
  gchar                   *about_text;
  gint                    row, i;

        /* Make a couple of tabs.  One for setup and one for info
        */
        tabs = gtk_notebook_new();
        gtk_notebook_set_tab_pos(GTK_NOTEBOOK(tabs), GTK_POS_TOP);
        gtk_box_pack_start(GTK_BOX(tab_vbox), tabs, TRUE, TRUE, 0);

/* --- Setup tab */
	vbox = gkrellm_gtk_framed_notebook_page(tabs, "Setup");

	/* This order reflects the display format of the config table */
	/* It maps elements to their respective static GtkWidget's/GtkObject's, */
	/* and initializes the config table to default values */

	/* This is the first line of the layout */
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
	port_spin_adj = gtk_adjustment_new (DEFAULT_PORT, 1, 65535, 1, 10, 0);
	port_spin = gtk_spin_button_new (GTK_ADJUSTMENT (port_spin_adj), 1, 0);
	gtk_box_pack_start(GTK_BOX(hbox),port_spin,FALSE,FALSE,0);

	label = gtk_label_new("v : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	vers_spin_adj = gtk_adjustment_new (DEFAULT_VERS, 1, 2, 1, 1, 0);
	vers_spin = gtk_spin_button_new (GTK_ADJUSTMENT (vers_spin_adj), 1, 0);
	gtk_box_pack_start(GTK_BOX(hbox),vers_spin,FALSE,FALSE,0);

	label = gtk_label_new("Freq : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	freq_spin_adj = gtk_adjustment_new (DEFAULT_FREQ, 2, 6000, 2, 100, 0);
	freq_spin = gtk_spin_button_new (GTK_ADJUSTMENT (freq_spin_adj), 1, 0);
	gtk_box_pack_start(GTK_BOX(hbox),freq_spin,FALSE,FALSE,0);

	gtk_container_add(GTK_CONTAINER(vbox),hbox);

	/* This is the second line of the layout */
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

	label = gtk_label_new("Elements : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	elements_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(elements_entry), "");
	gtk_box_pack_start(GTK_BOX(hbox),elements_entry,FALSE,FALSE,0);

	gtk_container_add(GTK_CONTAINER(vbox),hbox);

	/* This is the third line of the layout */
	hbox = gtk_hbox_new(FALSE,0);

	label = gtk_label_new("Format : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	format_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(format_entry), DEFAULT_FORMAT);
        gtk_box_pack_start(GTK_BOX(hbox), format_entry, FALSE, FALSE, 0);

	label = gtk_label_new("Divisor : ");
	gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,0);
	div_spin_adj = gtk_adjustment_new (DEFAULT_DIVISOR, 0, 1024, 1, 1, 0);
	div_spin = gtk_spin_button_new (GTK_ADJUSTMENT (div_spin_adj), 1, 0);
	gtk_box_pack_start(GTK_BOX(hbox),div_spin,FALSE,FALSE,0);

        hide_button = gtk_check_button_new_with_label("Hide Text   ");
        gtk_box_pack_start(GTK_BOX(hbox),hide_button,FALSE,FALSE,0);

        delta_button = gtk_check_button_new_with_label("Compute delta");
        gtk_box_pack_start(GTK_BOX(hbox),delta_button,FALSE,FALSE,0);

        panel_button = gtk_check_button_new_with_label("Create Panel");
        gtk_box_pack_start(GTK_BOX(hbox),panel_button,FALSE,FALSE,0);

        button = gtk_button_new_with_label("Probe");
        gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   (GtkSignalFunc) cb_probe, NULL);
        gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 4);

	gtk_container_add(GTK_CONTAINER(vbox),hbox);

	/* This is the fourth line of the layout */
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


	/* And finally the scrolled item list of the layout */
        scrolled = gtk_scrolled_window_new(NULL, NULL);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

        /* This defines the clist for all interactions with the config table */
	/* It follows the order of reader_title[] which is defined above */
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
	    /* The order of this list must follow reader_clist, */
	    /* which is based on reader_title[], defined above */
	    buf[i++] = reader->label;
	    buf[i++] = reader->peer;
	    buf[i++] = g_strdup_printf("%d", reader->port);
	    buf[i++] = g_strdup_printf("%d", reader->vers);
	    buf[i++] = reader->community;
	    buf[i++] = reader->oid_base;
	    buf[i++] = reader->oid_elements;
	    buf[i++] = g_strdup_printf("%d", reader->delay);
	    buf[i++] = reader->formatString;
	    buf[i++] = g_strdup_printf("%d", reader->divisor);
	    buf[i++] = reader->hideExtra ? "yes" : "no";
	    buf[i++] = reader->delta ? "yes" : "no";
	    buf[i++] = reader->panel ? "yes" : "no";
	    row = gtk_clist_append(GTK_CLIST(reader_clist), buf);
	  }


/* --- Info tab */
	vbox = gkrellm_gtk_framed_notebook_page(tabs, "Info");
	text = gkrellm_gtk_scrolled_text_view(vbox, NULL, 
				GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gkrellm_gtk_text_view_append_strings(text, plugin_info_text, 
				sizeof(plugin_info_text) / sizeof(gchar *));
/* --- about text */

	about_text = g_strdup_printf (plugin_about_text,
			SNMP_PLUGIN_MAJOR_VERSION, SNMP_PLUGIN_MINOR_VERSION);
	text = gtk_label_new(about_text); 
	g_free (about_text);

	gtk_notebook_append_page(GTK_NOTEBOOK(tabs), text,
				 gtk_label_new("About"));

}




static GkrellmMonitor  plugin_mon  =
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

GkrellmMonitor *
gkrellm_init_plugin(void)
{
    readers = NULL;

    style_id = gkrellm_add_chart_style(&plugin_mon, PLUGIN_STYLE_ID);

    simpleSNMPinit();
    
    mon = &plugin_mon;
    return &plugin_mon;
}
