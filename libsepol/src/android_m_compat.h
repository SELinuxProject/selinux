/*
 * extended permissions compatibility. Make ToT Android kernels compatible
 * with Android M releases
 */
#define AVTAB_OPTYPE_ALLOWED	0x1000
#define AVTAB_OPTYPE_AUDITALLOW	0x2000
#define AVTAB_OPTYPE_DONTAUDIT	0x4000
#define AVTAB_OPTYPE		(AVTAB_OPTYPE_ALLOWED | \
				AVTAB_OPTYPE_AUDITALLOW | \
				AVTAB_OPTYPE_DONTAUDIT)
#define AVTAB_XPERMS_OPTYPE	4

#define avtab_xperms_to_optype(x) (x << AVTAB_XPERMS_OPTYPE)
#define avtab_optype_to_xperms(x) (x >> AVTAB_XPERMS_OPTYPE)

extern unsigned int avtab_android_m_compat;

void avtab_android_m_compat_set(void);
