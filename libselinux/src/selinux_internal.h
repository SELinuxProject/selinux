#ifndef SELINUX_INTERNAL_H_
#define SELINUX_INTERNAL_H_

#include <selinux/selinux.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>

extern int require_seusers;
extern size_t selinux_page_size;

/* Make pthread_once optional */
#pragma weak pthread_once
#pragma weak pthread_key_create
#pragma weak pthread_key_delete
#pragma weak pthread_setspecific
#pragma weak pthread_getspecific

/* Call handler iff the first call.  */
#define __selinux_once(ONCE_CONTROL, INIT_FUNCTION)                     \
	do {                                                            \
		if (pthread_once != NULL)                               \
			pthread_once(&(ONCE_CONTROL), (INIT_FUNCTION)); \
		else if ((ONCE_CONTROL) == PTHREAD_ONCE_INIT) {         \
			INIT_FUNCTION();                                \
			(ONCE_CONTROL) = 2;                             \
		}                                                       \
	} while (0)

/* Pthread key macros */
#define __selinux_key_create(KEY, DESTRUCTOR) \
	(pthread_key_create != NULL ? pthread_key_create(KEY, DESTRUCTOR) : -1)

#define __selinux_key_delete(KEY)                \
	do {                                     \
		if (pthread_key_delete != NULL)  \
			pthread_key_delete(KEY); \
	} while (0)

#define __selinux_setspecific(KEY, VALUE)                \
	do {                                             \
		if (pthread_setspecific != NULL)         \
			pthread_setspecific(KEY, VALUE); \
	} while (0)

#define __selinux_getspecific(KEY) \
	(pthread_getspecific != NULL ? pthread_getspecific(KEY) : NULL)

/* selabel_lookup() is only thread safe if we're compiled with pthreads */

#pragma weak pthread_mutex_init
#pragma weak pthread_mutex_destroy
#pragma weak pthread_mutex_lock
#pragma weak pthread_mutex_unlock

#define __pthread_mutex_init(LOCK, ATTR)                \
	do {                                            \
		if (pthread_mutex_init != NULL)         \
			pthread_mutex_init(LOCK, ATTR); \
	} while (0)

#define __pthread_mutex_destroy(LOCK)                \
	do {                                         \
		if (pthread_mutex_destroy != NULL)   \
			pthread_mutex_destroy(LOCK); \
	} while (0)

#define __pthread_mutex_lock(LOCK)                \
	do {                                      \
		if (pthread_mutex_lock != NULL)   \
			pthread_mutex_lock(LOCK); \
	} while (0)

#define __pthread_mutex_unlock(LOCK)                \
	do {                                        \
		if (pthread_mutex_unlock != NULL)   \
			pthread_mutex_unlock(LOCK); \
	} while (0)

#pragma weak pthread_create
#pragma weak pthread_join
#pragma weak pthread_cond_init
#pragma weak pthread_cond_signal
#pragma weak pthread_cond_destroy
#pragma weak pthread_cond_wait

/* check if all functions needed to do parallel operations are available */
#define __pthread_supported                                     \
	(pthread_create && pthread_join && pthread_cond_init && \
	 pthread_cond_destroy && pthread_cond_signal && pthread_cond_wait)

#define SELINUXDIR "/etc/selinux/"
#define SELINUXCONFIG SELINUXDIR "config"

/*
 * Ordered list of configuration roots, each with a trailing slash.
 * SELINUXDIR is always first: it is the write target and the value the
 * existing selinux_*_path() accessors return. The remaining entries are
 * read-only fallbacks for hermetic-/usr / factory-reset systems where
 * /etc and /var may be empty at boot. Distributions can override the
 * fallback list at build time.
 */
#ifndef SELINUXFALLBACKDIRS
#define SELINUXFALLBACKDIRS "/usr/lib/selinux/"
#endif

extern const char *const selinux_confdirs[];

/*
 * NULL-terminated list of <confdir><SELINUXTYPE> roots, populated by
 * init_selinux_config(); [0] == selinux_policy_root(). Empty (only the
 * NULL terminator) after selinux_set_policy_root() so that callers fall
 * back to the single overridden root. Internal only.
 */
const char *const *selinux_policy_roots(void);

/*
 * Open @path (as returned by one of the selinux_*_path() accessors),
 * falling back through selinux_policy_roots() when the primary path
 * yields ENOENT. Internal-only.
 */
FILE *selinux_policy_fopen(const char *path, const char *mode);
int selinux_policy_open(const char *path, int flags);

/*
 * Resolve @path against the configuration-root list: write into @out
 * the first remapping under which @out (or @out concatenated with
 * @sibling, when the base file is optional but a sibling such as .bin
 * may exist alone is present. If no root has the file, @out receives
 * @path unchanged and -1 is returned with errno ENOENT. Internal only.
 */
int selinux_policy_resolve(const char *path, const char *sibling, char *out,
			   size_t outlen);

extern int has_selinux_config;

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dest, const char *src, size_t size);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *ptr, size_t nmemb, size_t size);
#endif

/* Use to ignore intentional unsigned under- and overflows while running under UBSAN. */
#if defined(__clang__) && defined(__clang_major__) && (__clang_major__ >= 4)
#if (__clang_major__ >= 12)
#define ignore_unsigned_overflow_                               \
	__attribute__((no_sanitize("unsigned-integer-overflow", \
				   "unsigned-shift-base")))
#else
#define ignore_unsigned_overflow_ \
	__attribute__((no_sanitize("unsigned-integer-overflow")))
#endif
#else
#define ignore_unsigned_overflow_
#endif

/* Ignore usage of deprecated declaration */
#ifdef __clang__
#define IGNORE_DEPRECATED_DECLARATION_BEGIN       \
	_Pragma("clang diagnostic push") _Pragma( \
		"clang diagnostic ignored \"-Wdeprecated-declarations\"")
#define IGNORE_DEPRECATED_DECLARATION_END _Pragma("clang diagnostic pop")
#elif defined __GNUC__
#define IGNORE_DEPRECATED_DECLARATION_BEGIN     \
	_Pragma("GCC diagnostic push") _Pragma( \
		"GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define IGNORE_DEPRECATED_DECLARATION_END _Pragma("GCC diagnostic pop")
#else
#define IGNORE_DEPRECATED_DECLARATION_BEGIN
#define IGNORE_DEPRECATED_DECLARATION_END
#endif

static inline void fclose_errno_safe(FILE *stream)
{
	int saved_errno;

	saved_errno = errno;
	(void)fclose(stream);
	errno = saved_errno;
}

#ifdef __GNUC__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif /* __GNUC__ */

#define spaceship_cmp(a, b) (((a) > (b)) - ((a) < (b)))

static inline void selinux_reset_errno(int *saved_errno)
{
	errno = *saved_errno;
}

#define SELINUX_PROTECT_ERRNO                             \
	__attribute__((__cleanup__(selinux_reset_errno))) \
	__attribute__((__unused__)) int _saved_errno = errno

#endif /* SELINUX_INTERNAL_H_ */
