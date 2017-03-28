/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Kylene Hall <kjhall@us.ibm.com>
 * Reiner Sailer <sailer@us.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_fs.c
 *	implemenents security file system for reporting
 *	current measurement list and IMA statistics
 */
#include <linux/fcntl.h>
#include <linux/slab.h>
#ifdef CONFIG_IMA_PER_NAMESPACE
#include <linux/mnt_namespace.h>
#endif
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>
#include <linux/vmalloc.h>

#include "ima.h"

static DEFINE_MUTEX(ima_write_mutex);

bool ima_canonical_fmt;
static int __init default_canonical_fmt_setup(char *str)
{
#ifdef __BIG_ENDIAN
	ima_canonical_fmt = 1;
#endif
	return 1;
}
__setup("ima_canonical_fmt", default_canonical_fmt_setup);

extern struct list_head *ima_rules;
extern struct list_head ima_default_rules;

#ifdef CONFIG_IMA_PER_NAMESPACE
static LIST_HEAD(ns_policies);
#endif

#define TMPBUFLEN 12
static ssize_t ima_show_htable_value(char __user *buf, size_t count,
				     loff_t *ppos, atomic_long_t *val)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t len;

	len = scnprintf(tmpbuf, TMPBUFLEN, "%li\n", atomic_long_read(val));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);
}

static ssize_t ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos)
{
	return ima_show_htable_value(buf, count, ppos, &ima_htable.violations);
}

static const struct file_operations ima_htable_violations_ops = {
	.read = ima_show_htable_violations,
	.llseek = generic_file_llseek,
};

static ssize_t ima_show_measurements_count(struct file *filp,
					   char __user *buf,
					   size_t count, loff_t *ppos)
{
	return ima_show_htable_value(buf, count, ppos, &ima_htable.len);

}

static const struct file_operations ima_measurements_count_ops = {
	.read = ima_show_measurements_count,
	.llseek = generic_file_llseek,
};

/* returns pointer to hlist_node */
static void *ima_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct ima_queue_entry *qe;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(qe, &ima_measurements, later) {
		if (!l--) {
			rcu_read_unlock();
			return qe;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *ima_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ima_queue_entry *qe = v;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */
	rcu_read_lock();
	qe = list_entry_rcu(qe->later.next, struct ima_queue_entry, later);
	rcu_read_unlock();
	(*pos)++;

	return (&qe->later == &ima_measurements) ? NULL : qe;
}

static void ima_measurements_stop(struct seq_file *m, void *v)
{
}

void ima_putc(struct seq_file *m, void *data, int datalen)
{
	while (datalen--)
		seq_putc(m, *(char *)data++);
}

/* print format:
 *       32bit-le=pcr#
 *       char[20]=template digest
 *       32bit-le=template name size
 *       char[n]=template name
 *       [eventdata length]
 *       eventdata[n]=template specific data
 */
int ima_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	u32 pcr, namelen, template_data_len; /* temporary fields */
	bool is_ima_template = false;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/*
	 * 1st: PCRIndex
	 * PCR used defaults to the same (config option) in
	 * little-endian format, unless set in policy
	 */
	pcr = !ima_canonical_fmt ? e->pcr : cpu_to_le32(e->pcr);
	ima_putc(m, &pcr, sizeof(e->pcr));

	/* 2nd: template digest */
	ima_putc(m, e->digest, TPM_DIGEST_SIZE);

	/* 3rd: template name size */
	namelen = !ima_canonical_fmt ? strlen(template_name) :
		cpu_to_le32(strlen(template_name));
	ima_putc(m, &namelen, sizeof(namelen));

	/* 4th:  template name */
	ima_putc(m, template_name, strlen(template_name));

	/* 5th:  template length (except for 'ima' template) */
	if (strcmp(template_name, IMA_TEMPLATE_IMA_NAME) == 0)
		is_ima_template = true;

	if (!is_ima_template) {
		template_data_len = !ima_canonical_fmt ? e->template_data_len :
			cpu_to_le32(e->template_data_len);
		ima_putc(m, &template_data_len, sizeof(e->template_data_len));
	}

	/* 6th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		enum ima_show_type show = IMA_SHOW_BINARY;
		struct ima_template_field *field = e->template_desc->fields[i];

		if (is_ima_template && strcmp(field->field_id, "d") == 0)
			show = IMA_SHOW_BINARY_NO_FIELD_LEN;
		if (is_ima_template && strcmp(field->field_id, "n") == 0)
			show = IMA_SHOW_BINARY_OLD_STRING_FMT;
		field->field_show(m, show, &e->template_data[i]);
	}
	return 0;
}

static const struct seq_operations ima_measurments_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_measurements_show
};

static int ima_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_measurments_seqops);
}

static const struct file_operations ima_measurements_ops = {
	.open = ima_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

void ima_print_digest(struct seq_file *m, u8 *digest, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++)
		seq_printf(m, "%02x", *(digest + i));
}

/* print in ascii */
static int ima_ascii_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/* 1st: PCR used (config option) */
	seq_printf(m, "%2d ", e->pcr);

	/* 2nd: SHA1 template hash */
	ima_print_digest(m, e->digest, TPM_DIGEST_SIZE);

	/* 3th:  template name */
	seq_printf(m, " %s", template_name);

	/* 4th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		seq_puts(m, " ");
		if (e->template_data[i].len == 0)
			continue;

		e->template_desc->fields[i]->field_show(m, IMA_SHOW_ASCII,
							&e->template_data[i]);
	}
	seq_puts(m, "\n");
	return 0;
}

static const struct seq_operations ima_ascii_measurements_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_ascii_measurements_show
};

static int ima_ascii_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_ascii_measurements_seqops);
}

static const struct file_operations ima_ascii_measurements_ops = {
	.open = ima_ascii_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static ssize_t ima_read_policy(char *path, struct ima_ns_file *f)
{
	void *data;
	char *datap;
	loff_t size;
	int rc, pathlen = strlen(path);

	char *p;

	/* remove \n */
	datap = path;
	strsep(&datap, "\n");

	rc = kernel_read_file_from_path(path, &data, &size, 0, READING_POLICY);
	if (rc < 0) {
		pr_err("Unable to open file: %s (%d)", path, rc);
		return rc;
	}

	datap = data;
	while (size > 0 && (p = strsep(&datap, "\n"))) {
		pr_debug("rule: %s\n", p);
		rc = ima_parse_add_rule(p, &f->temp_rules, &f->temp_ima_appraise);
		if (rc < 0)
			break;
		size -= rc;
	}

	vfree(data);
	if (rc < 0)
		return rc;
	else if (size)
		return -EINVAL;
	else
		return pathlen;
}

static ssize_t ima_write_policy(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t result;
	struct ima_ns_file *imaf = file->private_data;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	result = -ENOMEM;
	data = kmalloc(datalen + 1, GFP_KERNEL);
	if (!data)
		goto out;

	*(data + datalen) = '\0';

	result = -EFAULT;
	if (copy_from_user(data, buf, datalen))
		goto out_free;

	result = mutex_lock_interruptible(&ima_write_mutex);
	if (result < 0)
		goto out_free;

	if (data[0] == '/') {
		result = ima_read_policy(data, imaf);
	} else if (ima_appraise & IMA_APPRAISE_POLICY) {
		pr_err("IMA: signed policy file (specified as an absolute pathname) required\n");
		integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
				    "policy_update", "signed policy required",
				    1, 0);
		if (ima_appraise & IMA_APPRAISE_ENFORCE)
			result = -EACCES;
	} else {
		result = ima_parse_add_rule(data, &imaf->temp_rules, &imaf->temp_ima_appraise);
	}
	mutex_unlock(&ima_write_mutex);
out_free:
	kfree(data);
out:
	if (result < 0)
		imaf->valid_policy = 0;

	return result;
}

static struct dentry *ima_dir;
static struct dentry *ima_namespaces_dir;
static struct dentry *binary_runtime_measurements;
static struct dentry *ascii_runtime_measurements;
static struct dentry *runtime_measurements_count;
static struct dentry *violations;
static struct dentry *ima_policy;
static struct dentry *namespaces;

enum ima_fs_flags {
	IMA_FS_BUSY,
};

static unsigned long ima_fs_flags;

#ifdef	CONFIG_IMA_READ_POLICY
static const struct seq_operations ima_policy_seqops = {
		.start = ima_policy_start,
		.next = ima_policy_next,
		.stop = ima_policy_stop,
		.show = ima_policy_show,
};
#endif

/*
 * ima_open_policy: sequentialize access to the policy file
 */
static int ima_open_policy(struct inode *inode, struct file *filp)
{
	if (!(filp->f_flags & O_WRONLY)) {
#ifndef	CONFIG_IMA_READ_POLICY
		return -EACCES;
#else
		if ((filp->f_flags & O_ACCMODE) != O_RDONLY)
			return -EACCES;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return seq_open(filp, &ima_policy_seqops);
#endif
	}
	if (test_and_set_bit(IMA_FS_BUSY, &ima_fs_flags))
		return -EBUSY;

#ifdef CONFIG_IMA_PER_NAMESPACE
	if (inode->i_private) {
		struct ima_ns_file *f;

		f = kmalloc(sizeof(struct ima_ns_file), GFP_KERNEL);
		if (!f)
			return -ENOMEM;

		INIT_LIST_HEAD(&f->temp_rules);
		f->ns = inode->i_private;
		f->valid_policy = 1;

		filp->private_data = f;
	}
#endif

	return 0;
}

/*
 * ima_release_policy - start using the new measure policy rules.
 *
 * Initially, ima_measure points to the default policy rules, now
 * point to the new policy rules, and remove the securityfs policy file,
 * assuming a valid policy.
 */
static int ima_release_policy(struct inode *inode, struct file *file)
{
	struct ima_ns_file *imaf = file->private_data;
	const char *cause = imaf->valid_policy ? "completed" : "failed";

	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
		return seq_release_private(inode, file);

	if (imaf->valid_policy && ima_check_policy(&imaf->temp_rules) < 0) {
		cause = "failed";
		imaf->valid_policy = 0;
	}

	pr_info("IMA: policy update %s\n", cause);
	integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
			    "policy_update", cause, !imaf->valid_policy, 0);

	if (!imaf->valid_policy) {
		ima_delete_rules(&imaf->temp_rules);
		clear_bit(IMA_FS_BUSY, &ima_fs_flags);
		return 0;
	}

	ima_update_policy(imaf->ns, &imaf->temp_rules, imaf->temp_ima_appraise);
#ifndef	CONFIG_IMA_WRITE_POLICY
	securityfs_remove(ima_policy);
	ima_policy = NULL;
#else
	clear_bit(IMA_FS_BUSY, &ima_fs_flags);
#endif
	return 0;
}

static const struct file_operations ima_measure_policy_ops = {
	.open = ima_open_policy,
	.write = ima_write_policy,
	.read = seq_read,
	.release = ima_release_policy,
	.llseek = generic_file_llseek,
};

#ifdef CONFIG_IMA_PER_NAMESPACE
static int ima_open_namespaces(struct inode *inode, struct file *filp)
{
	if (!(filp->f_flags & O_WRONLY)) {
#ifndef	CONFIG_IMA_READ_POLICY
		return -EACCES;
#else
		if ((filp->f_flags & O_ACCMODE) != O_RDONLY)
			return -EACCES;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return seq_open(filp, &ima_policy_seqops);
#endif
	}
	if (test_and_set_bit(IMA_FS_BUSY, &ima_fs_flags))
		return -EBUSY;

	return 0;
}

static ssize_t ima_write_namespaces(struct file *file, const char __user *buf,
				    size_t datalen, loff_t *ppos)
{
	pid_t pid;
	struct task_struct *task;
	struct ima_ns_entry *new;
	ssize_t ret;
	char kbuf[50];

	if (datalen >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, buf, datalen))
		return -EFAULT;
	kbuf[datalen] = 0;

	// TODO: we said this should be nsid, but it's not immediately obvious
	// how to get a list of all the mount namespaces to search through.
	// Maybe we don't have to since the nsid exposed to userspace is just
	// the inode on procfs.
	if (kstrtoint(strstrip(kbuf), 0, &pid) || pid < 0)
		return -EINVAL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task)
		return -ESRCH;

	new = kzalloc(sizeof(struct ima_ns_entry), GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	new->mnt_ns = task->nsproxy->mnt_ns;
	INIT_LIST_HEAD(&new->list);
	INIT_LIST_HEAD(&new->policy_rules);
	new->rules = &ima_default_rules;

	// XXX: explicitly don't get_mnt_ns() here, so that when the refcount
	// gets to 0 we call our free-ing routines.
	// get_mnt_ns(new->mnt_ns);

	ret = snprintf(kbuf, sizeof(kbuf), "%u", mnt_namespace_inum(new->mnt_ns));
	if (ret < 0)
		return -EINVAL;

	ret = 0;
	new->dir = securityfs_create_dir(kbuf, ima_namespaces_dir);
	if (IS_ERR(new->dir)) {
		ret = PTR_ERR(new->dir);
		goto out;
	}

	new->policy = securityfs_create_file("policy", S_IWUSR, new->dir,
					     new, &ima_measure_policy_ops);
	if (IS_ERR(new->policy)) {
		securityfs_remove(new->dir);
		ret = PTR_ERR(new->policy);
	}

out:
	if (ret) {
		kfree(new);
	} else {
		list_add(&new->list, &ns_policies);
		ret = datalen;
	}

	put_task_struct(task);
	return ret;
}

static int ima_release_namespaces(struct inode *inode, struct file *file)
{
	clear_bit(IMA_FS_BUSY, &ima_fs_flags);
	return 0;
}

static const struct file_operations ima_namespaces_ops = {
	.open = ima_open_namespaces,
	.write = ima_write_namespaces,
	.release = ima_release_namespaces,
	.llseek = generic_file_llseek,
};

void mnt_namespace_dying(struct mnt_namespace *ns)
{
	struct ima_ns_entry *pos;
	list_for_each_entry(pos, &ns_policies, list) {
		if (pos->mnt_ns != ns)
			continue;

		list_del(&pos->list);
		securityfs_remove(pos->policy);
		securityfs_remove(pos->dir);
		kfree(pos);
		return;
	}
}

static int create_ima_namespace_files(void)
{
	ima_namespaces_dir = securityfs_create_dir("ns", ima_dir);
	if (IS_ERR(ima_namespaces_dir))
		return -1;

	namespaces = securityfs_create_file("namespaces", S_IWUSR, ima_dir,
					    NULL, &ima_namespaces_ops);
	if (IS_ERR(namespaces))
		return -1;

	return 0;
}
#else
static inline int create_ima_namespace_files(void)
{
	return 0;
}
#endif // CONFIG_IMA_PER_NAMESPACE

int __init ima_fs_init(void)
{
	ima_dir = securityfs_create_dir("ima", NULL);
	if (IS_ERR(ima_dir))
		return -1;

	if (create_ima_namespace_files() < 0)
		return -1;

	binary_runtime_measurements =
	    securityfs_create_file("binary_runtime_measurements",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_measurements_ops);
	if (IS_ERR(binary_runtime_measurements))
		goto out;

	ascii_runtime_measurements =
	    securityfs_create_file("ascii_runtime_measurements",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_ascii_measurements_ops);
	if (IS_ERR(ascii_runtime_measurements))
		goto out;

	runtime_measurements_count =
	    securityfs_create_file("runtime_measurements_count",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_measurements_count_ops);
	if (IS_ERR(runtime_measurements_count))
		goto out;

	violations =
	    securityfs_create_file("violations", S_IRUSR | S_IRGRP,
				   ima_dir, NULL, &ima_htable_violations_ops);
	if (IS_ERR(violations))
		goto out;

	ima_policy = securityfs_create_file("policy", POLICY_FILE_FLAGS,
					    ima_dir, NULL,
					    &ima_measure_policy_ops);
	if (IS_ERR(ima_policy))
		goto out;

	return 0;
out:
	securityfs_remove(violations);
	securityfs_remove(runtime_measurements_count);
	securityfs_remove(ascii_runtime_measurements);
	securityfs_remove(binary_runtime_measurements);
	securityfs_remove(ima_dir);
	securityfs_remove(ima_namespaces_dir);
	securityfs_remove(ima_policy);
	securityfs_remove(namespaces);
	return -1;
}
