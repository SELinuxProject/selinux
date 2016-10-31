/* stringslist.h -- 
 * Copyright 2006 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Dan Walsh <dwalsh@redhat.com>
 * 
 */
#ifndef STRINGSLIST_H
#define STRINGSLIST_H

struct stringsList {
	struct stringsList *next;
	char *string;
};

void strings_list_free(struct stringsList *list);
void strings_list_add(struct stringsList **list, const char *string);
void strings_list_print(struct stringsList *list);
int strings_list_find(struct stringsList *list, const char *string, int *exact);
int strings_list_diff(struct stringsList *from, struct stringsList *to);

#endif
