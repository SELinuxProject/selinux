
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* FLASK */

/*
 * Implementation of the double-ended queue type.
 */

#include <stdlib.h>
#include "queue.h"

queue_t queue_create(void)
{
	queue_t q;

	q = (queue_t) malloc(sizeof(struct queue_info));
	if (q == NULL)
		return NULL;

	q->head = q->tail = NULL;

	return q;
}

int queue_insert(queue_t q, queue_element_t e)
{
	queue_node_ptr_t newnode;

	if (!q)
		return -1;

	newnode = (queue_node_ptr_t) malloc(sizeof(struct queue_node));
	if (newnode == NULL)
		return -1;

	newnode->element = e;
	newnode->next = NULL;

	if (q->head == NULL) {
		q->head = q->tail = newnode;
	} else {
		q->tail->next = newnode;
		q->tail = newnode;
	}

	return 0;
}

int queue_push(queue_t q, queue_element_t e)
{
	queue_node_ptr_t newnode;

	if (!q)
		return -1;

	newnode = (queue_node_ptr_t) malloc(sizeof(struct queue_node));
	if (newnode == NULL)
		return -1;

	newnode->element = e;
	newnode->next = NULL;

	if (q->head == NULL) {
		q->head = q->tail = newnode;
	} else {
		newnode->next = q->head;
		q->head = newnode;
	}

	return 0;
}

queue_element_t queue_remove(queue_t q)
{
	queue_node_ptr_t node;
	queue_element_t e;

	if (!q)
		return NULL;

	if (q->head == NULL)
		return NULL;

	node = q->head;
	q->head = q->head->next;
	if (q->head == NULL)
		q->tail = NULL;

	e = node->element;
	free(node);

	return e;
}

queue_element_t queue_head(queue_t q)
{
	if (!q)
		return NULL;

	if (q->head == NULL)
		return NULL;

	return q->head->element;
}

void queue_destroy(queue_t q)
{
	queue_node_ptr_t p, temp;

	if (!q)
		return;

	p = q->head;
	while (p != NULL) {
		temp = p;
		p = p->next;
		free(temp);
	}

	free(q);
}

int queue_map(queue_t q, int (*f) (queue_element_t, void *), void *vp)
{
	queue_node_ptr_t p;
	int ret;

	if (!q)
		return 0;

	p = q->head;
	while (p != NULL) {
		ret = f(p->element, vp);
		if (ret)
			return ret;
		p = p->next;
	}
	return 0;
}

void queue_map_remove_on_error(queue_t q,
			       int (*f) (queue_element_t, void *),
			       void (*g) (queue_element_t, void *), void *vp)
{
	queue_node_ptr_t p, last, temp;
	int ret;

	if (!q)
		return;

	last = NULL;
	p = q->head;
	while (p != NULL) {
		ret = f(p->element, vp);
		if (ret) {
			if (last) {
				last->next = p->next;
				if (last->next == NULL)
					q->tail = last;
			} else {
				q->head = p->next;
				if (q->head == NULL)
					q->tail = NULL;
			}

			temp = p;
			p = p->next;
			g(temp->element, vp);
			free(temp);
		} else {
			last = p;
			p = p->next;
		}
	}

	return;
}

/* FLASK */
