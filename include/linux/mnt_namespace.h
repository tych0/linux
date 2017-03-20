#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

struct mnt_namespace;
struct fs_struct;
struct user_namespace;

extern struct mnt_namespace *copy_mnt_ns(unsigned long, struct mnt_namespace *,
		struct user_namespace *, struct fs_struct *);
extern void put_mnt_ns(struct mnt_namespace *ns);

#ifdef CONFIG_IMA_PER_NAMESPACE
// XXX: this is probably bad. We need some way to export the inum so that we
// can get it in IMA fs. There's probably a better way to do that.
extern unsigned int mnt_namespace_inum(struct mnt_namespace *ns);
#endif

extern const struct file_operations proc_mounts_operations;
extern const struct file_operations proc_mountinfo_operations;
extern const struct file_operations proc_mountstats_operations;

#endif
#endif
