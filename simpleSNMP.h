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


#include <glib.h>


/* The data structure for a chart */

#define MAX_OID_STR 10

typedef struct input_data input_data;

struct input_data {
	gint			asn1_type[MAX_OID_STR];
	gchar			*sample[MAX_OID_STR];
	u_long			sample_n[MAX_OID_STR];
	gint			num_sample;
	gchar			*error;
	/* new is set to 1 after input_data has been updated */
	gint			new;
};

/* The interface functions for SNMP */

extern	void simpleSNMPinit();
extern	gchar *simpleSNMPprobe(gchar *peer, gint port, gint vers, gchar *community);
extern	struct snmp_session *simpleSNMPopen(gchar *peername, gint port, gint vers,
					gchar *community, void *data);
extern	void simpleSNMPupdate();
extern	gint simpleSNMPsend(struct snmp_session *session, 
					gchar **oid_str, gint num_oid_str);
extern	void simpleSNMPclose(struct snmp_session *session);
extern	gint simpleSNMPcheck_oid(const char *argv);

