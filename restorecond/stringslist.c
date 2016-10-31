/*
 * Copyright (C) 2006, 2008 Red Hat 
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
.* 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA     
 * 02111-1307  USA
 *
 * Authors:  
 *   Dan Walsh <dwalsh@redhat.com>
 *
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "stringslist.h"
#include "restorecond.h"
#include <fnmatch.h>

/* Sorted lists */
void strings_list_add(struct stringsList **list, const char *string)
{
	struct stringsList *ptr = *list;
	struct stringsList *prev = NULL;
	struct stringsList *newptr = NULL;
	while (ptr) {
		int cmp = strcmp(string, ptr->string);
		if (cmp < 0)
			break;	/* Not on list break out to add */
		if (cmp == 0)
			return;	/* Already on list */
		prev = ptr;
		ptr = ptr->next;
	}
	newptr = calloc(1, sizeof(struct stringsList));
	if (!newptr)
		exitApp("Out of Memory");
	newptr->string = strdup(string);
	newptr->next = ptr;
	if (prev)
		prev->next = newptr;
	else
		*list = newptr;
}

int strings_list_find(struct stringsList *ptr, const char *string, int *exact)
{
	while (ptr) {
		*exact = strcmp(ptr->string, string) == 0;
		int cmp = fnmatch(ptr->string, string, 0);
		if (cmp == 0) 
			return 0;	/* Match found */
		ptr = ptr->next;
	}
	return -1;
}

void strings_list_free(struct stringsList *ptr)
{
	struct stringsList *prev = NULL;
	while (ptr) {
		free(ptr->string);
		prev = ptr;
		ptr = ptr->next;
		free(prev);
	}
}

int strings_list_diff(struct stringsList *from, struct stringsList *to)
{
	while (from != NULL && to != NULL) {
		if (strcmp(from->string, to->string) != 0)
			return 1;
		from = from->next;
		to = to->next;
	}
	if (from != NULL || to != NULL)
		return 1;
	return 0;
}

void strings_list_print(struct stringsList *ptr)
{
	while (ptr) {
		printf("%s\n", ptr->string);
		ptr = ptr->next;
	}
}

#ifdef TEST
void exitApp(const char *msg)
{
	perror(msg);
	exit(-1);
}

int main(int argc, char **argv)
{
	struct stringsList *list = NULL;
	struct stringsList *list1 = NULL;
	strings_list_add(&list, "/etc/resolv.conf");
	strings_list_add(&list, "/etc/walsh");
	strings_list_add(&list, "/etc/mtab");
	strings_list_add(&list, "/etc/walsh");
	if (strings_list_diff(list, list) != 0)
		printf("strings_list_diff test1 bug\n");
	strings_list_add(&list1, "/etc/walsh");
	if (strings_list_diff(list, list1) == 0)
		printf("strings_list_diff test2 bug\n");
	strings_list_add(&list1, "/etc/walsh");
	strings_list_add(&list1, "/etc/walsh/*");
	strings_list_add(&list1, "/etc/resolv.conf");
	strings_list_add(&list1, "/etc/mtab1");
	if (strings_list_diff(list, list1) == 0)
		printf("strings_list_diff test3 bug\n");
	printf("strings list\n");
	strings_list_print(list);
	printf("strings list1\n");
	strings_list_find(list1, "/etc/walsh/dan");
	strings_list_print(list1);
	strings_list_free(list);
	strings_list_free(list1);
}
#endif
