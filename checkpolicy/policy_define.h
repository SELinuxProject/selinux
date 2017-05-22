/* Functions used to define policy grammar components. */

#ifndef _POLICY_DEFINE_H_
#define _POLICY_DEFINE_H_

/* 
 * We need the following so we have a valid error return code in yacc
 * when we have a parse error for a conditional rule.  We can't check 
 * for NULL (ie 0) because that is a potentially valid return.
 */
#define COND_ERR ((avrule_t *)-1)
#define TRUE 1
#define FALSE 0

avrule_t *define_cond_compute_type(int which);
avrule_t *define_cond_pol_list(avrule_t *avlist, avrule_t *stmt);
avrule_t *define_cond_te_avtab(int which);
avrule_t *define_cond_filename_trans(void);
cond_expr_t *define_cond_expr(uint32_t expr_type, void *arg1, void* arg2);
int define_attrib(void);
int define_attrib_role(void);
int define_av_perms(int inherits);
int define_bool_tunable(int is_tunable);
int define_category(void);
int define_class(void);
int define_default_user(int which);
int define_default_role(int which);
int define_default_type(int which);
int define_default_range(int which);
int define_common_perms(void);
int define_compute_type(int which);
int define_conditional(cond_expr_t *expr, avrule_t *t_list, avrule_t *f_list );
int define_constraint(constraint_expr_t *expr);
int define_dominance(void);
int define_fs_context(unsigned int major, unsigned int minor);
int define_fs_use(int behavior);
int define_genfs_context(int has_type);
int define_initial_sid_context(void);
int define_initial_sid(void);
int define_ipv4_node_context(void);
int define_ipv6_node_context(void);
int define_level(void);
int define_netif_context(void);
int define_permissive(void);
int define_polcap(void);
int define_ibpkey_context(unsigned int low, unsigned int high);
int define_ibendport_context(unsigned int port);
int define_port_context(unsigned int low, unsigned int high);
int define_pirq_context(unsigned int pirq);
int define_iomem_context(uint64_t low, uint64_t high);
int define_ioport_context(unsigned long low, unsigned long high);
int define_pcidevice_context(unsigned long device);
int define_devicetree_context(void);
int define_range_trans(int class_specified);
int define_role_allow(void);
int define_role_trans(int class_specified);
int define_role_types(void);
int define_role_attr(void);
int define_roleattribute(void);
int define_filename_trans(void);
int define_sens(void);
int define_te_avtab(int which);
int define_te_avtab_extended_perms(int which);
int define_typealias(void);
int define_typeattribute(void);
int define_typebounds(void);
int define_type(int alias);
int define_user(void);
int define_validatetrans(constraint_expr_t *expr);
int expand_attrib(void);
int insert_id(const char *id,int push);
int insert_separator(int push);
role_datum_t *define_role_dom(role_datum_t *r);
role_datum_t *merge_roles_dom(role_datum_t *r1,role_datum_t *r2);
uintptr_t define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2);

#endif /* _POLICY_DEFINE_H_ */
