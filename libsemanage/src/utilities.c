/* Author: Mark Goldman   <mgoldman@tresys.com>
 *			Paul Rosenfeld	<prosenfeld@tresys.com>
 *
 * Copyright (C) 2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "utilities.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <ustr.h>

#define TRUE 1
#define FALSE 0

char *semanage_findval(const char *file, const char *var, const char *delim)
{
	FILE *fd;
	char *buff = NULL;
	char *retval = NULL;
	size_t buff_len = 0;

	assert(file);
	assert(var);

	if ((fd = fopen(file, "r")) == NULL)
		return NULL;

	while (getline(&buff, &buff_len, fd) > 0) {
		if (semanage_is_prefix(buff, var)) {
			retval = semanage_split(buff, delim);
			if (retval)
				semanage_rtrim(retval, '\n');
			break;
		}
	}
	free(buff);
	fclose(fd);

	return retval;
}

int semanage_is_prefix(const char *str, const char *prefix)
{
	if (!str) {
		return FALSE;
	}
	if (!prefix) {
		return TRUE;
	}

	return strncmp(str, prefix, strlen(prefix)) == 0;
}

char *semanage_split_on_space(const char *str)
{
	/* as per the man page, these are the isspace() chars */
	const char *seps = "\f\n\r\t\v ";
	size_t slen = strlen(seps);
	size_t off = 0, rside_len = 0;
	char *retval = NULL;
	Ustr *ustr = USTR_NULL, *temp = USTR_NULL;

	if (!str)
		goto done;
	if (!(ustr = ustr_dup_cstr(str)))
		goto done;
	temp =
	    ustr_split_spn_chrs(ustr, &off, seps, slen, USTR_NULL,
				USTR_FLAG_SPLIT_DEF);
	if (!temp)
		goto done;
	/* throw away the left hand side */
	ustr_sc_free(&temp);

	rside_len = ustr_len(ustr) - off;
	temp = ustr_dup_subustr(ustr, off + 1, rside_len);
	if (!temp)
		goto done;
	retval = strdup(ustr_cstr(temp));
	ustr_sc_free(&temp);

      done:
	ustr_sc_free(&ustr);
	return retval;
}

char *semanage_split(const char *str, const char *delim)
{
	Ustr *ustr = USTR_NULL, *temp = USTR_NULL;
	size_t off = 0, rside_len = 0;
	char *retval = NULL;

	if (!str)
		goto done;
	if (!delim || !(*delim))
		return semanage_split_on_space(str);
	ustr = ustr_dup_cstr(str);
	temp =
	    ustr_split_cstr(ustr, &off, delim, USTR_NULL, USTR_FLAG_SPLIT_DEF);
	if (!temp)
		goto done;
	/* throw away the left hand side */
	ustr_sc_free(&temp);

	rside_len = ustr_len(ustr) - off;

	temp = ustr_dup_subustr(ustr, off + 1, rside_len);
	if (!temp)
		goto done;
	retval = strdup(ustr_cstr(temp));
	ustr_sc_free(&temp);

      done:
	ustr_sc_free(&ustr);
	return retval;
}

int semanage_list_push(semanage_list_t ** list, const char *data)
{
	semanage_list_t *temp = NULL;

	if (!data)
		return EINVAL;

	if (semanage_list_find(*list, data) != NULL)
		return 0;

	if (!(temp = malloc(sizeof(semanage_list_t))))
		return ENOMEM;

	if (!(temp->data = strdup(data))) {
		free(temp);
		return ENOMEM;
	}
	temp->next = *list;
	*list = temp;

	return 0;
}

char *semanage_list_pop(semanage_list_t ** list)
{
	semanage_list_t *node = NULL;
	char *data = NULL;

	if (!list || !(*list))
		return NULL;

	node = (*list);
	data = node->data;

	(*list) = node->next;
	free(node);

	return data;
}

void semanage_list_destroy(semanage_list_t ** list)
{
	semanage_list_t *temp;

	while ((temp = (*list))) {
		free(temp->data);
		(*list) = temp->next;
		free(temp);
	}
}

semanage_list_t *semanage_list_find(semanage_list_t * l, const char *data)
{
	if (!data)
		return NULL;
	while (l && strcmp(l->data, data))
		l = l->next;

	return l;
}

int semanage_list_sort(semanage_list_t ** l)
{
	semanage_list_t **array = NULL;
	semanage_list_t *temp = NULL;
	size_t count = 0;
	size_t i = 0;

	if (!l)
		return 0;

	for (temp = *l; temp; temp = temp->next)
		++count;

	array = malloc(sizeof(semanage_list_t *) * count);
	if (!array)
		return ENOMEM;	/* couldn't allocate memory for sort */
	for (temp = *l; temp; temp = temp->next) {
		array[i++] = temp;
	}

	qsort(array, count, sizeof(semanage_list_t *),
	      (int (*)(const void *, const void *))&semanage_cmp_plist_t);
	for (i = 0; i < (count - 1); ++i) {
		array[i]->next = array[i + 1];
	}
	array[i]->next = NULL;
	(*l) = array[0];
	free(array);

	return 0;
}

int semanage_cmp_plist_t(const semanage_list_t ** x, const semanage_list_t ** y)
{
	return strcmp((*x)->data, (*y)->data);
}

int semanage_str_count(char *data, char what)
{
	int count = 0;

	if (!data)
		return 0;
	while (*data) {
		if (*data == what)
			++count;
		++data;
	}

	return count;
}

void semanage_rtrim(char *str, char trim_to)
{
	int len = 0;

	if (!str)
		return;
	len = strlen(str);

	while (len > 0) {
		if (str[--len] == trim_to) {
			str[len] = '\0';
			return;
		}
	}
}

/* list_addafter_controlmem does *NOT* duplicate the data argument
 * use at your own risk, I am building a list out of malloc'd memory and
 * it is only going to get stored into this list, thus when I destroy it
 * later I won't free a ptr twice.
 *
 * returns the newly created node or NULL on error
 */
semanage_list_t *list_addafter_controlmem(semanage_list_t * item, char *data)
{
	semanage_list_t *temp = malloc(sizeof(semanage_list_t));

	if (!temp)
		return NULL;
	temp->data = data;
	temp->next = item->next;
	item->next = temp;

	return temp;
}

semanage_list_t *semanage_slurp_file_filter(FILE * file,
					    int (*pred) (const char *))
{
	semanage_list_t head;
	semanage_list_t *current = &head;
	char *line = NULL;
	size_t buff_len = 0;

	head.next = NULL;	/* initialize head, we aren't going to use the data */
	while (getline(&line, &buff_len, file) >= 0) {
		if (pred(line)) {
			semanage_rtrim(line, '\n');
			current = list_addafter_controlmem(current, line);
			if (!current) 
				break;
			line = NULL;
			buff_len = 0;
		}
	}
	free(line);

	return head.next;
}
