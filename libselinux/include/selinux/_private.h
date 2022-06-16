#if defined __INCLUDE_LEVEL__ && __INCLUDE_LEVEL__ < 2 && ! defined NO_INCLUDE_ERROR
# error This file should not be included directly!
#endif


#ifndef _SELINUX_PRIVATE_H_
#define _SELINUX_PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif


/* helper macro to check GCC version */
#if defined __GNUC__ && defined __GNUC_MINOR__
# define REQUIRE_GNUC(major, minor)	(__GNUC__ > (major) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
# define REQUIRE_GNUC(major, minor)	0
#endif


/* format */
#ifndef selinux_format
# ifdef __GNUC__
#  define selinux_format(opts)		__attribute__((__format__ opts))
# else
#  define selinux_format(opts)
# endif
#endif


/* nonnull */
#ifndef selinux_nonnull
# if REQUIRE_GNUC(3,3)
#  define selinux_nonnull(params)	__attribute__((__nonnull__ params))
# else
#  define selinux_nonnull(params)
# endif
#endif


/* nodiscard / warn-unused-result */
#ifndef selinux_nodiscard
# if REQUIRE_GNUC(3,4)
#  define selinux_nodiscard		__attribute__((__warn_unused_result__))
# else
#  define selinux_nodiscard
# endif
#endif


/* deprecated */
#ifndef selinux_deprecated
# if REQUIRE_GNUC(4,5)
#  define selinux_deprecated(msg)	__attribute__((__deprecated__ (msg)))
# else
#  define selinux_deprecated(msg)
# endif
#endif


/* access */
#ifndef selinux_access
# if REQUIRE_GNUC(10,0)
#  define selinux_access(opts)		__attribute__((__access__ opts))
# else
#  define selinux_access(opts)
# endif
#endif


#ifdef __cplusplus
}
#endif

#endif /* _SELINUX_PRIVATE_H_ */
