/* Private definitions for libsepol. */

/* Endian conversion for reading and writing binary policies */

#include <byteswap.h>
#include <endian.h>
#include <sepol/policydb/policydb.h>

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

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

/* Policy compatibility information. */
struct policydb_compat_info {
	unsigned int type;
	unsigned int version;
	unsigned int sym_num;
	unsigned int ocon_num;
};

extern struct policydb_compat_info *policydb_lookup_compat(unsigned int version,
							   unsigned int type);

/* Reading from a policy "file". */
static inline int next_entry(void *buf, struct policy_file *fp, size_t bytes)
{
	size_t nread;

	switch (fp->type) {
	case PF_USE_STDIO:
		nread = fread(buf, bytes, 1, fp->fp);
		if (nread != 1)
			return -1;
		break;
	case PF_USE_MEMORY:
		if (bytes > fp->len)
			return -1;
		memcpy(buf, fp->data, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		break;
	default:
		return -1;
	}
	return 0;
}

static inline size_t put_entry(const void *ptr, size_t size, size_t n,
			       struct policy_file *fp)
{
	size_t bytes = size * n;

	switch (fp->type) {
	case PF_USE_STDIO:
		return fwrite(ptr, size, n, fp->fp);
	case PF_USE_MEMORY:
		if (bytes > fp->len) {
			errno = ENOSPC;
			return 0;
		}

		memcpy(fp->data, ptr, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		return n;
	case PF_LEN:
		fp->len += bytes;
		return n;
	default:
		return 0;
	}
	return 0;
}
