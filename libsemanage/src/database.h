/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_DATABASE_H_
#define _SEMANAGE_DATABASE_H_

#ifndef DBASE_RECORD_DEFINED
typedef void *record_t;
typedef void *record_key_t;
#define DBASE_RECORD_DEFINED
#endif

#ifndef DBASE_DEFINED
typedef void *dbase_t;
#define DBASE_DEFINED
#endif

/* Circular dependency */
struct semanage_handle;

/* RECORD interface - method table */
typedef struct record_table {

	/* Create a record */
	int (*create) (struct semanage_handle * handle, record_t ** rec);

	/* Extract key from record */
	int (*key_extract) (struct semanage_handle * handle,
			    const record_t * rec, record_key_t ** key);

	/* Free record key */
	void (*key_free) (record_key_t * key);

	/* Return 0 if the record matches the key, 
	 * -1 if the key represents a record that should
	 * be ordered before this record, and 1 if vice-versa */
	int (*compare) (const record_t * rec, const record_key_t * key);

	/* Return 0 if the record matches record2,
	 * -1 if record2 should be ordered before this record,
	 * and 1 if vice-versa */
	int (*compare2) (const record_t * rec, const record_t * rec2);

	/* Same as above, but dereferences the pointer first.
	 * This function is intenteded to be used as a qsort
	 * comparator. */
	int (*compare2_qsort) (const record_t ** rec, const record_t ** rec2);

	/* Deep-copy clone of this record */
	int (*clone) (struct semanage_handle * handle,
		      const record_t * rec, record_t ** new_rec);

	/* Deallocate record resources. Must sucessfully handle NULL. */
	void (*free) (record_t * rec);

} record_table_t;

/* DBASE interface - method table */
typedef struct dbase_table {

	/* --------------- Database Functionality ----------- */

	/* Note: In all the functions below, the key is property
	 * of the caller, and will not be modified by the database. 
	 * In add/set/modify, the data is also property of the caller */

	/* Add the specified record to
	 * the database. No check for duplicates is performed */
	int (*add) (struct semanage_handle * handle,
		    dbase_t * dbase,
		    const record_key_t * key, const record_t * data);

	/* Add the specified record to the  
	 * database if it not present. 
	 * If it's present, replace it
	 */
	int (*modify) (struct semanage_handle * handle,
		       dbase_t * dbase,
		       const record_key_t * key, const record_t * data);

	/* Modify the specified record in the database
	 * if it is present. Fail if it does not yet exist
	 */
	int (*set) (struct semanage_handle * handle,
		    dbase_t * dbase,
		    const record_key_t * key, const record_t * data);

	/* Delete a record */
	int (*del) (struct semanage_handle * handle,
		    dbase_t * dbase, const record_key_t * key);

	/* Clear all records, and leave the database in
	 * cached, modified state. This function does 
	 * not require a call to cache() */
	int (*clear) (struct semanage_handle * handle, dbase_t * dbase);

	/* Retrieve a record 
	 * 
	 * Note: the resultant record
	 * becomes property of the caller, and
	 * must be freed accordingly */

	int (*query) (struct semanage_handle * handle,
		      dbase_t * dbase,
		      const record_key_t * key, record_t ** response);

	/* Check if a record exists */
	int (*exists) (struct semanage_handle * handle,
		       dbase_t * dbase,
		       const record_key_t * key, int *response);

	/* Count the number of records */
	int (*count) (struct semanage_handle * handle,
		      dbase_t * dbase, unsigned int *response);

	/* Execute the specified handler over 
	 * the records of this database. The handler
	 * can signal a successful exit by returning 1,
	 * an error exit by returning -1, and continue by
	 * returning 0
	 * 
	 * Note: The record passed into the iterate handler
	 * may or may not persist after the handler invocation,
	 * and writing to it has unspecified behavior. It *must*
	 * be cloned if modified, or preserved.
	 * 
	 * Note: The iterate handler may not invoke any other
	 * semanage read functions outside a transaction. It is only
	 * reentrant while in transaction. The iterate handler may
	 * not modify the underlying database.
	 */
	int (*iterate) (struct semanage_handle * handle,
			dbase_t * dbase,
			int (*fn) (const record_t * record,
				   void *varg), void *fn_arg);

	/* Construct a list of all records in this database
	 * 
	 * Note: The list returned becomes property of the caller,
	 * and must be freed accordingly. 
	 */
	int (*list) (struct semanage_handle * handle,
		     dbase_t * dbase,
		     record_t *** records, unsigned int *count);

	/* ---------- Cache/Transaction Management ---------- */

	/* Cache the database (if supported).
	 * This function must be invoked before using
	 * any of the database functions above. It may be invoked
	 * multiple times, and will update the cache if a commit
	 * occurred between invocations */
	int (*cache) (struct semanage_handle * handle, dbase_t * dbase);

	/* Forgets all changes that haven't been written
	 * to the database backend */
	void (*drop_cache) (dbase_t * dbase);

	/* Checks if there are any changes not written to the backend */
	int (*is_modified) (dbase_t * dbase);

	/* Writes the database changes to its backend */
	int (*flush) (struct semanage_handle * handle, dbase_t * dbase);

	/* ------------- Polymorphism ----------------------- */

	/* Retrieves the record table for this database,
	 * which specifies how to perform basic operations
	 * on each record. */
	record_table_t *(*get_rtable) (dbase_t * dbase);

} dbase_table_t;

typedef struct dbase_config {

	/* Database state */
	dbase_t *dbase;

	/* Database methods */
	dbase_table_t *dtable;

} dbase_config_t;

extern int dbase_add(struct semanage_handle *handle,
		     dbase_config_t * dconfig,
		     const record_key_t * key, const record_t * data);

extern int dbase_modify(struct semanage_handle *handle,
			dbase_config_t * dconfig,
			const record_key_t * key, const record_t * data);

extern int dbase_set(struct semanage_handle *handle,
		     dbase_config_t * dconfig,
		     const record_key_t * key, const record_t * data);

extern int dbase_del(struct semanage_handle *handle,
		     dbase_config_t * dconfig, const record_key_t * key);

extern int dbase_query(struct semanage_handle *handle,
		       dbase_config_t * dconfig,
		       const record_key_t * key, record_t ** response);

extern int dbase_exists(struct semanage_handle *handle,
			dbase_config_t * dconfig,
			const record_key_t * key, int *response);

extern int dbase_count(struct semanage_handle *handle,
		       dbase_config_t * dconfig, unsigned int *response);

extern int dbase_iterate(struct semanage_handle *handle,
			 dbase_config_t * dconfig,
			 int (*fn) (const record_t * record,
				    void *fn_arg), void *fn_arg);

extern int dbase_list(struct semanage_handle *handle,
		      dbase_config_t * dconfig,
		      record_t *** records, unsigned int *count);

#endif
