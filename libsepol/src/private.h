/* Private definitions for libsepol. */

/* Endian conversion for reading and writing binary policies */

#include <sepol/policydb/policydb.h>


#ifdef __APPLE__
#include <sys/types.h>
#include <machine/endian.h>
#else
#include <byteswap.h>
#include <endian.h>
#endif

#include <errno.h>

#ifdef __APPLE__
#define __BYTE_ORDER  BYTE_ORDER
#define __LITTLE_ENDIAN  LITTLE_ENDIAN
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le16(x) bswap_16(x)
#define le16_to_cpu(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

#undef min
#define min(a,b) (((a) < (b)) ? (a) : (b))

#undef max
#define max(a,b) ((a) >= (b) ? (a) : (b))

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

#define is_saturated(x) (x == (typeof(x))-1)
#define zero_or_saturated(x) ((x == 0) || is_saturated(x))

/* Policy compatibility information. */
struct policydb_compat_info {
	unsigned int type;
	unsigned int version;
	unsigned int sym_num;
	unsigned int ocon_num;
	unsigned int target_platform;
};

extern struct policydb_compat_info *policydb_lookup_compat(unsigned int version,
							   unsigned int type,
						unsigned int target_platform);

/* Reading from a policy "file". */
extern int next_entry(void *buf, struct policy_file *fp, size_t bytes);
extern size_t put_entry(const void *ptr, size_t size, size_t n,
		        struct policy_file *fp);
extern int str_read(char **strp, struct policy_file *fp, size_t len);
