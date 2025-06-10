/* Author: Mark Goldman   <mgoldman@tresys.com>
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

/* This file contains helper functions that are loosely based off of what is
 * available from the python script genhomedircon.  Also this file contains
 * c implementations of a couple of python functions so that genhomedircon will
 * look/act like the python script.
 */
#ifndef _SEMANAGE_UTILITIES_H_
#define _SEMANAGE_UTILITIES_H_

#include <stdio.h>

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#define WARN_UNUSED \
	__attribute__ ((__warn_unused_result__))
#else
# define WARN_UNUSED		/* nothing */
#endif

typedef struct list {
	char *data;
	struct list *next;
} semanage_list_t;

/**
 * @param file  the path to the file to look for a variable in
 * @param var   the variable that you want the value of
 * @param delim the value that separates the part you care about from the part
 *	       that you don't.
 * @return for the first instance of var in the file, returns everything after
 *	   delim.
 *	   returns "" if not found IE if(*(semanage_findval(f,v,d)) == '\0'){
 *					  printf("%s not found in file", v);
 *				       }
 *
 *	   NULL for error (out of memory, etc)
 */
char *semanage_findval(const char *file, const char *var, const char *delim) WARN_UNUSED;

/**
 * @param str   string to test
 * @param	 val   prefix
 * @return  1 if val is the prefix of str
 *	    0 if val is not the prefix of str
 *
 * note: if str == NULL, returns false
 *	 if val == NULL, returns true --nothing can always be the prefix of
 *				        something
 *	 if (*val) == "" returns true same as above.
 */
int semanage_is_prefix(const char *str, const char *val) WARN_UNUSED;

/**
 * @param str   the string to semanage_split
 * @return     malloc'd string after the first run of characters that aren't whitespace
 */
char *semanage_split_on_space(const char *str) WARN_UNUSED;

/**
 * @param	 str   the string to semanage_split
 * @param	 delim the string delimiter.  NOT a set of characters that can be
 *	       a delimiter.
 *	       if *delim == '\0' behaves as semanage_splitOnSpace()
 * @return   a ptr to the first character past the delimiter.
 *	    if delim doesn't appear in the string, returns a ptr to the
 *	    trailing null in the string
 */
char *semanage_split(const char *str, const char *delim) WARN_UNUSED;

/* linked list string functions
 * Functions allocate memory.  Must be free'd with
 * either semanage_list_pop until list == NULL or semanage_list_destroy()
 */
int semanage_list_push(semanage_list_t ** list, const char *data) WARN_UNUSED;
char *semanage_list_pop(semanage_list_t ** list);
void semanage_list_destroy(semanage_list_t ** list);
semanage_list_t *semanage_list_find(semanage_list_t * l,
				    const char *data) WARN_UNUSED;
int semanage_list_sort(semanage_list_t ** l) WARN_UNUSED;
/* function to compare 2 semanage_list_t nodes,
 * returns strcmp(x->data, y->data)
 * used internally by semanage_list_sort()
 */
int semanage_cmp_plist_t(const void *x, const void *y);
/**
 * @param      data a target string
 * @param      what  a character
 * @returns    the number of times the char appears in the string
 */
size_t semanage_str_count(const char *data, char what);
/**
 * @param      - a string
 * @param            the character to trim to
 * @return   - mangles the string, converting the first
 *             occurrence of the character to a '\0' from
 *             the end of the string.
 */
void semanage_rtrim(char *str, char trim_to);

/**
 * @param      value being searched for
 * @param      replacement value that replaces found search values
 * @param      string being searched and replaced on
 * @param      maximum number of value occurrences (zero for unlimited)
 * @return     newly-allocated string with the replaced values
 */
char *semanage_str_replace(const char *search, const char *replace,
			   const char *src, size_t lim);

/**
 * @param data    some string
 * @return  modifies the string such that the first whitespace char becomes
 *	    '\0', ending the string.
 */
void semanage_keep_until_space(char *data);

/**
 * @param    file    - an open FILE to read from
 * @param    pred    - a function taking a string that
 *                    returns 1 if the string should be
 *                    kept and 0 otherwise
 * @return  a list of lines from the file (empty lines become
 *          empty strings) in the file order where pred(line)
 *          returns > 0
 */
semanage_list_t *semanage_slurp_file_filter(FILE * file,
					    int (*pred) (const char *))
    WARN_UNUSED;

/**
 * Wrapper around write(2), which retries on short writes.
 *
 * @param fd   file descriptor to write to
 * @param buf  buffer to be written
 * @param len  number of bytes to be written from buffer
 *
 * @return 0 on success, -1 else (with errno set)
 */

int write_full(int fd, const void *buf, size_t len) WARN_UNUSED;

/**
 * Portable implementation of the glibc version of basename(3).
 *
 * @param filename  path to find basename of
 *
 * @return          basename of filename
 */

#ifdef __GNUC__
__attribute__((nonnull))
#endif
char *semanage_basename(const char *filename);

#endif
