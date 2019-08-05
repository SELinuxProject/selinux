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
	size_t off = 0;

	if (!str)
		return NULL;

	/* skip one token and the spaces before and after it */
	off = strspn(str, seps);
	off += strcspn(str + off, seps);
	off += strspn(str + off, seps);
	return strdup(str + off);
}

char *semanage_split(const char *str, const char *delim)
{
	char *retval;

	if (!str)
		return NULL;
	if (!delim || !(*delim))
		return semanage_split_on_space(str);

	retval = strstr(str, delim);
	if (retval == NULL)
		return NULL;

	return strdup(retval + strlen(delim));
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

int semanage_str_count(const char *data, char what)
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

char *semanage_str_replace(const char *search, const char *replace,
			   const char *src, size_t lim)
{
	size_t count = 0, slen, rlen, newsize;
	char *p, *pres, *result;
	const char *psrc;

	slen = strlen(search);
	rlen = strlen(replace);

	/* Do not support empty search strings */
	if (slen == 0)
		return NULL;

	/* Count the occurrences of search in src and compute the new size */
	for (p = strstr(src, search); p != NULL; p = strstr(p + slen, search)) {
		count++;
		if (lim && count >= lim)
			break;
	}
	if (!count)
		return strdup(src);

	/* Allocate the result string */
	newsize = strlen(src) + 1 + count * (rlen - slen);
	result = malloc(newsize);
	if (!result)
		return NULL;

	/* Fill the result */
	psrc = src;
	pres = result;
	for (p = strstr(src, search); p != NULL; p = strstr(psrc, search)) {
		/* Copy the part which has not been modified */
		if (p != psrc) {
			size_t length = (size_t)(p - psrc);
			memcpy(pres, psrc, length);
			pres += length;
		}
		/* Copy the replacement part */
		if (rlen != 0) {
			memcpy(pres, replace, rlen);
			pres += rlen;
		}
		psrc = p + slen;
		count--;
		if (!count)
			break;
	}
	/* Copy the last part, after doing a sanity check */
	assert(pres + strlen(psrc) + 1 == result + newsize);
	strcpy(pres, psrc);
	return result;
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
