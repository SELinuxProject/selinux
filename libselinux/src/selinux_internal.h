#include <selinux/selinux.h>
#include <pthread.h>


extern int require_seusers ;
extern int selinux_page_size ;

/* Make pthread_once optional */
#pragma weak pthread_once
#pragma weak pthread_key_create
#pragma weak pthread_key_delete
#pragma weak pthread_setspecific

/* Call handler iff the first call.  */
#define __selinux_once(ONCE_CONTROL, INIT_FUNCTION)	\
	do {						\
		if (pthread_once != NULL)		\
			pthread_once (&(ONCE_CONTROL), (INIT_FUNCTION));  \
		else if ((ONCE_CONTROL) == PTHREAD_ONCE_INIT) {		  \
			INIT_FUNCTION ();		\
			(ONCE_CONTROL) = 2;		\
		}					\
	} while (0)

/* Pthread key macros */
#define __selinux_key_create(KEY, DESTRUCTOR)			\
	(pthread_key_create != NULL ? pthread_key_create(KEY, DESTRUCTOR) : -1)

#define __selinux_key_delete(KEY)				\
	do {							\
		if (pthread_key_delete != NULL)			\
			pthread_key_delete(KEY);		\
	} while (0)

#define __selinux_setspecific(KEY, VALUE)			\
	do {							\
		if (pthread_setspecific != NULL)		\
			pthread_setspecific(KEY, VALUE);	\
	} while (0)

/* selabel_lookup() is only thread safe if we're compiled with pthreads */

#pragma weak pthread_mutex_init
#pragma weak pthread_mutex_destroy
#pragma weak pthread_mutex_lock
#pragma weak pthread_mutex_unlock

#define __pthread_mutex_init(LOCK, ATTR) 			\
	do {							\
		if (pthread_mutex_init != NULL)			\
			pthread_mutex_init(LOCK, ATTR);		\
	} while (0)

#define __pthread_mutex_destroy(LOCK) 				\
	do {							\
		if (pthread_mutex_destroy != NULL)		\
			pthread_mutex_destroy(LOCK);		\
	} while (0)

#define __pthread_mutex_lock(LOCK) 				\
	do {							\
		if (pthread_mutex_lock != NULL)			\
			pthread_mutex_lock(LOCK);		\
	} while (0)

#define __pthread_mutex_unlock(LOCK) 				\
	do {							\
		if (pthread_mutex_unlock != NULL)		\
			pthread_mutex_unlock(LOCK);		\
	} while (0)


#define SELINUXDIR "/etc/selinux/"
#define SELINUXCONFIG SELINUXDIR "config"

extern int has_selinux_config ;
