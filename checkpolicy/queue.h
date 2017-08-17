
/* Author : Stephen Smalley, <sds@tycho.nsa.gov> */

/* FLASK */

/* 
 * A double-ended queue is a singly linked list of 
 * elements of arbitrary type that may be accessed
 * at either end.
 */

#ifndef _QUEUE_H_
#define _QUEUE_H_

typedef void *queue_element_t;

typedef struct queue_node *queue_node_ptr_t;

typedef struct queue_node {
	queue_element_t element;
	queue_node_ptr_t next;
} queue_node_t;

typedef struct queue_info {
	queue_node_ptr_t head;
	queue_node_ptr_t tail;
} queue_info_t;

typedef queue_info_t *queue_t;

queue_t queue_create(void);
int queue_insert(queue_t, queue_element_t);
int queue_push(queue_t, queue_element_t);
queue_element_t queue_remove(queue_t);
queue_element_t queue_head(queue_t);
void queue_destroy(queue_t);

/* 
   Applies the specified function f to each element in the
   specified queue. 

   In addition to passing the element to f, queue_map
   passes the specified void* pointer to f on each invocation.

   If f returns a non-zero status, then queue_map will cease
   iterating through the hash table and will propagate the error
   return to its caller.
 */
int queue_map(queue_t, int (*f) (queue_element_t, void *), void *);

/*
   Same as queue_map, except that if f returns a non-zero status,
   then the element will be removed from the queue and the g
   function will be applied to the element. 
 */
void queue_map_remove_on_error(queue_t,
			       int (*f) (queue_element_t, void *),
			       void (*g) (queue_element_t, void *), void *);

#endif

/* FLASK */
