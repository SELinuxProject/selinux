/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_FCONTEXT_RECORD_H_
#define _SEMANAGE_FCONTEXT_RECORD_H_

#include <semanage/context_record.h>
#include <semanage/handle.h>

#ifndef _SEMANAGE_FCONTEXT_DEFINED_
struct semanage_fcontext;
struct semanage_fcontext_key;
typedef struct semanage_fcontext semanage_fcontext_t;
typedef struct semanage_fcontext_key semanage_fcontext_key_t;
#define _SEMANAGE_FCONTEXT_DEFINED_
#endif

/* Key */
extern int semanage_fcontext_compare(const semanage_fcontext_t * fcontext,
				     const semanage_fcontext_key_t * key);

extern int semanage_fcontext_compare2(const semanage_fcontext_t * fcontext,
				      const semanage_fcontext_t * fcontext2);

extern int semanage_fcontext_key_create(semanage_handle_t * handle,
					const char *expr,
					int type,
					semanage_fcontext_key_t ** key_ptr);

extern int semanage_fcontext_key_extract(semanage_handle_t * handle,
					 const semanage_fcontext_t * fcontext,
					 semanage_fcontext_key_t ** key_ptr);

extern void semanage_fcontext_key_free(semanage_fcontext_key_t * key);

/* Regexp */
extern const char *semanage_fcontext_get_expr(const semanage_fcontext_t *
					      fcontext);

extern int semanage_fcontext_set_expr(semanage_handle_t * handle,
				      semanage_fcontext_t * fcontext,
				      const char *expr);

/* Type */
#define SEMANAGE_FCONTEXT_ALL   0
#define SEMANAGE_FCONTEXT_REG   1
#define SEMANAGE_FCONTEXT_DIR   2
#define SEMANAGE_FCONTEXT_CHAR  3
#define SEMANAGE_FCONTEXT_BLOCK 4
#define SEMANAGE_FCONTEXT_SOCK  5
#define SEMANAGE_FCONTEXT_LINK  6
#define SEMANAGE_FCONTEXT_PIPE  7

extern int semanage_fcontext_get_type(const semanage_fcontext_t * fcontext);

extern const char *semanage_fcontext_get_type_str(int type);

extern void semanage_fcontext_set_type(semanage_fcontext_t * fcontext,
				       int type);

/* Context */
extern semanage_context_t *semanage_fcontext_get_con(const semanage_fcontext_t *
						     fcontext);

extern int semanage_fcontext_set_con(semanage_handle_t * handle,
				     semanage_fcontext_t * fcontext,
				     semanage_context_t * con);

/* Create/Clone/Destroy */
extern int semanage_fcontext_create(semanage_handle_t * handle,
				    semanage_fcontext_t ** fcontext_ptr);

extern int semanage_fcontext_clone(semanage_handle_t * handle,
				   const semanage_fcontext_t * fcontext,
				   semanage_fcontext_t ** fcontext_ptr);

extern void semanage_fcontext_free(semanage_fcontext_t * fcontext);

#endif
