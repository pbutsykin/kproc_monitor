/*
 * Intrusion Detection Monitor for Test Platform
 *
 * License: GPL-2.0
 *
 * Copyright (C) 2019  Pavel Butsykin
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/file.h>
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define DEBUG_TARCE

#ifdef DEBUG_TARCE
#define TRACE(FMT, ...) trace_printk(FMT, ## __VA_ARGS__)
#else
#define TRACE(FMT, ...) do {} while (0)
#endif

struct rprocess_map {
	size_t size;
	unsigned long *bitmap;
	u32 enforcing;
	u32 separated_gid;
	bool inited;
};

struct global_security {
	struct {
		struct {
			int *ptr;
			int back;
		} enabled;
		struct {
			int *ptr;
			int back;
		} enforcing;
		rwlock_t lock;
		bool inited;
	} se;

	struct {
		struct {
			unsigned long *ptr;
			unsigned long back;
		} val;
		struct {
			unsigned long *ptr;
			unsigned long back;
		} dac;
			/* We can't use semaphore inside kret hook,
			 * but as a prototype for kernel patch it's ok.
			 */
		struct rw_semaphore rwsem;
		bool inited;
	} mmap_min_addr;
};

struct cpu_sec_features {
#ifndef X86_CR4_SMEP
#define X86_CR4_SMEP 0x00100000
#endif

#ifndef X86_CR4_SMAP
#define X86_CR4_SMAP 0x00200000
#endif

#ifndef X86_CR4_UMIP
#define X86_CR4_UMIP 0x00000800
#endif
	bool smep;
	bool smap;
	bool umip;
	u32 recovery;
	bool inited;
};

struct log_entry {
	struct {
		kuid_t uid;
		kuid_t parent_uid;
		pid_t pid;
		pid_t parent_pid;
		char name[TASK_COMM_LEN + 1];
		char parent_name[TASK_COMM_LEN + 1];
	} process;
	const char *func;
	char *event;
	u64  time;
};

struct rlog {
#define KCS_MESSAGE_NUM 100
	u32 limit;
	u32 count;
	struct log_entry *arr;
	rwlock_t lock;
};

static struct kc_sec {
	struct rprocess_map rmap;
	struct global_security gs;
	struct cpu_sec_features cpu;
	struct ctl_table_header *sysctl;
	struct proc_dir_entry *proc_dir;
	struct rlog log;
} g_kcs;

static void selinux_verify(struct global_security *gs);
static void mmap_min_addr_verify(struct global_security *gs);
static void cpu_security_verify(struct cpu_sec_features *cpu);

#define KCS_EVENT_LOG(__msg, __parent, __curr, __parent_uid, __uid) \
	kcs_log(__func__, __msg, __parent, __curr, __parent_uid, __uid)

#define KCS_EVENT_PUSH(__entry) kcs_log_push(__func__, __entry)

static void kcs_log(const char *func, char *event, struct task_struct *parent,
		    struct task_struct *curr, kuid_t parent_uid, kuid_t uid)
{
	struct rlog *log = &g_kcs.log;
	struct log_entry *lentry;

	pr_warn("%s: %s: %s(pid:%u uid:%u) --> %s(pid:%u, uid:%u)\n",
		func, event, parent->comm, task_pid_nr(parent), parent_uid.val,
		curr->comm, task_pid_nr(curr), uid.val);

	write_lock(&log->lock);
	lentry = &log->arr[log->count++ % log->limit];
	*lentry = (struct log_entry) {
		.process.uid = uid,
		.process.parent_uid = parent_uid,
		.process.pid = task_pid_nr(curr),
		.process.parent_pid = task_pid_nr(parent),
		.func = func,
		.event = event,
		.time = ktime_to_us(ktime_get()),
	};
	strncpy(lentry->process.name, curr->comm, TASK_COMM_LEN);
	strncpy(lentry->process.parent_name, parent->comm, TASK_COMM_LEN);
	write_unlock(&log->lock);
}

static void kcs_log_pack(char *event, struct task_struct *parent,
			 struct task_struct *curr, kuid_t parent_uid,
			 kuid_t uid, struct log_entry *lentry)
{
	*lentry = (struct log_entry) {
		.process.uid = uid,
		.process.parent_uid = parent_uid,
		.process.pid = task_pid_nr(curr),
		.process.parent_pid = task_pid_nr(parent),
		.event = event,
	};
	strncpy(lentry->process.name, curr->comm, TASK_COMM_LEN);
	strncpy(lentry->process.parent_name, parent->comm, TASK_COMM_LEN);
}

static void kcs_log_push(const char *func, struct log_entry *lentry)
{
	struct rlog *log = &g_kcs.log;

	lentry->func = func;
	lentry->time = ktime_to_us(ktime_get());

	pr_warn("%s: %s: %s(pid:%u uid:%u) --> %s(pid:%u, uid:%u)\n",
		func, lentry->event, lentry->process.parent_name,
		lentry->process.parent_pid, lentry->process.parent_uid.val,
		lentry->process.name, lentry->process.pid, lentry->process.uid.val);

	write_lock(&log->lock);
	log->arr[log->count++ % log->limit] = *lentry;
	write_unlock(&log->lock);
}

static inline void rprocess_bitmap_set(struct rprocess_map *rmap, struct task_struct *task)
{
	pid_t pid = task_pid_nr(task);

	set_bit(pid, rmap->bitmap);
}

static inline void rprocess_bitmap_clear(struct rprocess_map *rmap, struct task_struct *task)
{
	pid_t pid = task_pid_nr(task);

	clear_bit(pid, rmap->bitmap);
}

static inline bool rprocess_bitmap_check(struct rprocess_map *rmap, struct task_struct *task)
{
	pid_t pid = task_pid_nr(task);

	return test_bit(pid, rmap->bitmap);
}

/* taken from kernel\fork.c */
struct file *get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	/* We need mmap_sem to protect against races with removal of exe_file */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
	return exe_file;
}

/* WARN: can sleep inside get_mm_exe_file() */
static bool is_suid_root_file(struct task_struct *task)
{
	struct mm_struct *mm;
	struct file *exec_file;
	struct inode *inode;
	bool check;

	mm = get_task_mm(task);
	if (!mm) {
		return false;
	}

	exec_file = get_mm_exe_file(mm);
	if (!exec_file) {
		mmput(mm);
		return false;
	}
	inode = file_inode(exec_file);
	check = (inode->i_mode & S_ISUID) && !inode->i_uid.val;

	fput(exec_file);
	mmput(mm);

	return check;
}

static int clone_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rprocess_map *rmap = &g_kcs.rmap;
	struct task_struct *child;
	const struct cred *child_cred;
	int child_pid = regs->ax;
	kuid_t uid;

	if (!child_pid) {
		return 0;
	}

	rcu_read_lock();
	/* XXX: maybe worth to use task_lock() to reduce chances of race with child exit */
	child = pid_task(find_vpid(child_pid), PIDTYPE_PID);
	if (!child) {
		rcu_read_unlock();
		return 0;
	}
	get_task_struct(child);

	child_cred = __task_cred(child);

	TRACE("clone: %s(pid:%u, uid:%u) --> %s(pid:%u, uid:%u) (%p)\n",
		current->comm, task_pid_nr(current), __task_cred(current)->uid.val,
		child->comm, task_pid_nr(child), child_cred->uid.val, child);

	uid = child_cred->uid;
	rcu_read_unlock();

	if (!uid.val || rprocess_bitmap_check(rmap, current)) {
		if (!(child->flags & PF_EXITING)) { /* still possible race with do_exit */
			rprocess_bitmap_set(rmap, child);
		}
	}

	put_task_struct(child);

	return 0;
}

static int execute_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rprocess_map *rmap = &g_kcs.rmap;
	const struct cred *cred;
	kuid_t uid;

	rcu_read_lock();
	cred = __task_cred(current);

	TRACE("exec: %s(pid:%u, uid:%u) --> %s(pid:%u, uid:%u) (%p)\n",
		current->parent->comm, task_pid_nr(current->parent),
		__task_cred(current->parent)->uid.val, current->comm,
		task_pid_nr(current), cred->uid.val, current);

	uid = cred->uid;
	rcu_read_unlock();

	if (!uid.val || is_suid_root_file(current)) {
		rprocess_bitmap_set(rmap, current);
	}

	return 0;
}

static int (*get_vfs_caps_from_disk_func)(const struct dentry *dentry, struct cpu_vfs_cap_data *cpu_caps);

static bool verify_setuid_capability(struct task_struct *task)
{
	struct cpu_vfs_cap_data caps;
	struct mm_struct *mm;
	struct dentry *dentry;
	struct file *exec_file;
	bool cap_setuid, cap_setcap;
	int ret;

	if (!ns_capable(current_user_ns(), CAP_SETUID))
		return false;

	mm = get_task_mm(task);
	if (!mm)
		return true;

	exec_file = get_mm_exe_file(mm);
	if (!exec_file) {
		mmput(mm);
		return true;
	}

	dentry = dget(exec_file->f_dentry);
	ret = get_vfs_caps_from_disk_func(dentry, &caps);
	dput(dentry);
	fput(exec_file);
	mmput(mm);

	if (ret < 0) {
		TRACE("get_vfs_caps_from_disk_func ret: %d\n", ret);
		return ret == -ENODATA || ret == -EOPNOTSUPP ? false : true;
	}

	cap_setuid = cap_raised(caps.permitted, CAP_SETUID);
	cap_setcap = cap_raised(caps.permitted, CAP_SETPCAP);
	TRACE("%s(pid:%u), cap_setuid:%u cap_setcap:%u\n",
		task->comm, task_pid_nr(task), cap_setuid, cap_setcap);

	if (!cap_setuid && !cap_setcap)
		return false;

	rprocess_bitmap_set(&g_kcs.rmap, task);
	return true;
}

static int rprocess_verify(struct rprocess_map *rmap, struct task_struct *curr)
{
	const struct cred *cred, *parent_cred;
	struct task_struct *parent;
	struct log_entry lentry;

	if (unlikely(!rmap->inited))
		return 0;

	rcu_read_lock();
	cred = __task_cred(curr);

	parent = rcu_dereference(curr->parent);
	parent_cred = __task_cred(parent);

	TRACE("secure exec: %s(pid:%u uid:%u) --> %s(pid:%u, uid:%u)\n",
		parent->comm, task_pid_nr(parent), parent_cred->uid.val,
		curr->comm, task_pid_nr(curr), cred->uid.val);

	if (rmap->separated_gid) {
		if (unlikely(parent_cred->uid.val && !parent_cred->gid.val &&
			     !rprocess_bitmap_check(rmap, parent)))
		{
			kcs_log_pack("Privilege escalation detected! "
				     "mismatch root uid/gid (parent process)",
				     parent, curr, parent_cred->uid, cred->uid,
				     &lentry);
			goto parent_kill;
		}

		if (unlikely(cred->uid.val && !cred->gid.val &&
			     !rprocess_bitmap_check(rmap, curr)))
		{
			kcs_log_pack("Privilege escalation detected! "
				      "mismatch root uid/gid", parent, curr,
				      parent_cred->uid, cred->uid, &lentry);
			goto curr_kill;
		}
	}

	if (unlikely(!parent_cred->uid.val && !rprocess_bitmap_check(rmap, parent))) {
		kcs_log_pack("Privilege escalation detected! "
			      "Parent process is illegally modified.",
			      parent, curr, parent_cred->uid, cred->uid,
			      &lentry);
		goto parent_kill;
	}

	if (unlikely(parent_cred->uid.val && !cred->uid.val &&
		     !rprocess_bitmap_check(rmap, curr))) {

		kcs_log_pack("Privilege escalation detected! "
			      "Child process is illegally modified.",
			      parent, curr, parent_cred->uid, cred->uid,
			      &lentry);
		goto curr_kill;
	}
	rcu_read_unlock();

	return 0;

parent_kill:
	rcu_read_unlock();
	if (verify_setuid_capability(parent))
		return 0;

	KCS_EVENT_PUSH(&lentry);
	if (!rmap->enforcing)
		return 0;

	send_sig_info(SIGKILL, SEND_SIG_FORCED, parent);
	send_sig_info(SIGKILL, SEND_SIG_FORCED, curr);
	return -EPERM;

curr_kill:
	rcu_read_unlock();
	if (verify_setuid_capability(curr))
		return 0;

	KCS_EVENT_PUSH(&lentry);
	if (!rmap->enforcing)
		return 0;

	send_sig_info(SIGKILL, SEND_SIG_FORCED, curr);
	return -EPERM;
}

static int secure_execute_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int err;

	selinux_verify(&g_kcs.gs);
	mmap_min_addr_verify(&g_kcs.gs);

	err = rprocess_verify(&g_kcs.rmap, current);
	if (likely(!err)) { /* avoid potential kernel crash if the attack was caught by rmap */
		cpu_security_verify(&g_kcs.cpu);
	}
	return err;
}

static struct kretprobe exec_kretprobe = {
	.kp.symbol_name = "sys_execve",
	.handler = execute_handler,
	.entry_handler = secure_execute_handler,
};

static struct kretprobe clone_kretprobe = {
	.kp.symbol_name = "do_fork",
	.handler = clone_handler,
	.entry_handler = secure_execute_handler,
};

static int commit_creds_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rprocess_map *rmap = &g_kcs.rmap;

	TRACE("drop uid-0: %s(pid:%u, uid:%u, euid: %u, suid: %u)\n",
		current->comm, task_pid_nr(current), __task_cred(current)->uid.val,
		__task_cred(current)->euid.val, __task_cred(current)->suid.val);

	rprocess_bitmap_clear(rmap, current);

	return 0;
}

static int commit_creds_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rprocess_map *rmap = &g_kcs.rmap;
	struct cred *new = (struct cred *)regs->di;

	selinux_verify(&g_kcs.gs);
	mmap_min_addr_verify(&g_kcs.gs);
	cpu_security_verify(&g_kcs.cpu);

	if (!virt_addr_valid(new)) { /* depends on kernel/build */
		WARN_ON(1);
		return -EPERM;
	}

	if (rprocess_bitmap_check(rmap, current) &&
	    (new->uid.val && new->euid.val && new->suid.val)) {
		return 0;
	}

	return -EPERM;
}

static struct kretprobe commit_creds_kretprobe = {
	.kp.symbol_name = "commit_creds",
	.handler = commit_creds_handler,
	.entry_handler = commit_creds_entry,
};

static int exit_handler(struct kretprobe_instance *ri, struct pt_regs *p_regs)
{
	struct rprocess_map *rmap = &g_kcs.rmap;
	const struct cred *cred;

	selinux_verify(&g_kcs.gs);
	mmap_min_addr_verify(&g_kcs.gs);
	cpu_security_verify(&g_kcs.cpu);

	rcu_read_lock();
	cred = __task_cred(current);

	TRACE("exit: %s(pid:%u, uid:%u suid:%u euid:%u)\n",
		current->comm, task_pid_nr(current), cred->uid.val,
		cred->suid.val, cred->euid.val);

	if (!cred->uid.val || !cred->suid.val || !cred->euid.val) {
		rprocess_bitmap_clear(rmap, current);
	} else {
		WARN_ON(rprocess_bitmap_check(rmap, current));
	}
	rcu_read_unlock();

	return 0;
}

static struct kretprobe exit_kretprobe = {
	.kp.symbol_name = "do_exit",
	.entry_handler = exit_handler,
};

static struct kretprobe mayopen_kretprobe = {
	.kp.symbol_name = "may_open",
	.entry_handler = secure_execute_handler,
};

static struct kretprobe may_init_module_kretprobe = {
	// .kp.symbol_name = "may_init_module",
	.entry_handler = secure_execute_handler,
};

static struct kretprobe umodehelper_exec_kretprobe = {
	.kp.symbol_name = "call_usermodehelper_exec",
	.entry_handler = secure_execute_handler,
};

/* XXX: still need hook after exit_signals(tsk); for correct synchronization */
static void rprocess_map_fill(struct rprocess_map *rmap)
{
	struct task_struct *p;

	set_bit(0, rmap->bitmap); /* idle */

	rcu_read_lock();
	for_each_process(p) {
		const struct cred *cred = __task_cred(p);
		struct sighand_struct *sighand = rcu_dereference(p->sighand);

		if (!sighand || !cred) {
			continue;
		}
		spin_lock_irq(&sighand->siglock);
		if (!cred->uid.val && !(p->flags & PF_EXITING)) {
			rprocess_bitmap_set(rmap, p);
		}
		spin_unlock_irq(&sighand->siglock);
	}
	rcu_read_unlock();
}

static void verify_rprocess_bitmap(struct rprocess_map *rmap)
{
	int pid;

	pid = find_first_bit(rmap->bitmap, rmap->size);
	if (pid == 0) { /* skip idle */
		pid = 1;
	}

	rcu_read_lock();
	while (pid < rmap->size) {
		struct task_struct *task;

		task = pid_task(find_vpid(pid), PIDTYPE_PID);
		if (task) {
			const struct cred *cred = __task_cred(task);
			if (cred->uid.val && cred->euid.val && cred->suid.val) {
				pr_warn("Verify: uid mismatch %s(pid:%u uid:%u euid:%u suid:%u)\n",
					task->comm, pid, cred->uid.val, cred->euid.val, cred->suid.val);
			}
		} else {
			pr_warn("Verify: non-existent process pid(%u) in rmap\n", pid);
		}
		pid = find_next_bit(rmap->bitmap, rmap->size, pid + 1);
	}
	rcu_read_unlock();
}

static int rprocess_mon_init(struct rprocess_map *rmap)
{
	int err;

	/* extern int pid_max_min, pid_max_max; */
	rmap->size = BITS_TO_LONGS(PID_MAX_LIMIT) * sizeof(long);
	rmap->bitmap = vzalloc(rmap->size);
	if (!rmap->bitmap) {
		pr_err("can't allocate rp_map.bitmap %lu\n", rmap->size);
		return -ENOMEM;
	}

	err = register_kretprobe(&clone_kretprobe);
	if (err) {
		pr_err("%s: clone register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		goto fail1;
	}

	err = register_kretprobe(&exec_kretprobe);
	if (err) {
		pr_err("%s: exec register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		goto fail2;
	}

	err = register_kretprobe(&exit_kretprobe);
	if (err) {
		pr_err("%s: exit register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		goto fail3;
	}

	err = register_kretprobe(&commit_creds_kretprobe);
	if (err) {
		pr_err("%s: commit_creds register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		goto fail4;
	}

	err = register_kretprobe(&mayopen_kretprobe);
	if (err) {
		pr_err("%s: may_open register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		goto fail5;
	}

	may_init_module_kretprobe.kp.addr = (void*)kallsyms_lookup_name("may_init_module");
	err = register_kretprobe(&may_init_module_kretprobe);
	if (err) {
		pr_err("%s: may_init_module register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		goto fail6;
	}

	err = register_kretprobe(&umodehelper_exec_kretprobe);
	if (err) {
		pr_err("%s: umodehelper_exec register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		goto fail7;
	}

	get_vfs_caps_from_disk_func = (void*)kallsyms_lookup_name("get_vfs_caps_from_disk");
	if (!get_vfs_caps_from_disk_func) {
		pr_err("can't lookup get_vfs_caps_from_disk\n");
		goto fail8;
	}

	rprocess_map_fill(rmap);

	rmap->enforcing = 1;
	rmap->separated_gid = 1;
	rmap->inited = true;
	TRACE("kproc: rprocess monitor inited.\n");

	return 0;

fail8:
	unregister_kretprobe(&umodehelper_exec_kretprobe);
fail7:
	unregister_kretprobe(&may_init_module_kretprobe);
fail6:
	unregister_kretprobe(&mayopen_kretprobe);
fail5:
	unregister_kretprobe(&commit_creds_kretprobe);
fail4:
	unregister_kretprobe(&exit_kretprobe);
fail3:
	unregister_kretprobe(&exec_kretprobe);
fail2:
	unregister_kretprobe(&clone_kretprobe);
fail1:
	vfree(rmap->bitmap);

	return err;
}

static void rprocess_mon_deinit(struct rprocess_map *rmap)
{
	if (rmap->inited) {
		rmap->inited = false;
		TRACE("kproc: rprocess monitor deinited.\n");

		verify_rprocess_bitmap(rmap);

		unregister_kretprobe(&clone_kretprobe);
		unregister_kretprobe(&exec_kretprobe);
		unregister_kretprobe(&exit_kretprobe);
		unregister_kretprobe(&commit_creds_kretprobe);
		unregister_kretprobe(&mayopen_kretprobe);
		unregister_kretprobe(&may_init_module_kretprobe);
		unregister_kretprobe(&umodehelper_exec_kretprobe);

		vfree(rmap->bitmap);
	}
}

static void selinux_verify(struct global_security *gs)
{
	const struct cred *cred, *parent_cred;
	struct task_struct *parent;

	if (!gs->se.inited) {
		return;
	}

	rcu_read_lock();
	cred = __task_cred(current);
	parent = rcu_dereference(current->parent);
	parent_cred = __task_cred(parent);

	if (*gs->se.enabled.ptr != gs->se.enabled.back) {
		TRACE("selinux: %s(pid:%u) enabled(%d -> %d) value restored\n",
			current->comm, task_pid_nr(current),
			*gs->se.enabled.ptr, gs->se.enabled.back);
		KCS_EVENT_LOG("'enabled' value restored", parent, current,
			      parent_cred->uid, cred->uid);
		*gs->se.enabled.ptr = gs->se.enabled.back;
	}

	read_lock(&gs->se.lock);
	if (*gs->se.enforcing.ptr != gs->se.enforcing.back) {
		TRACE("selinux: %s(pid:%u) enforcing(%d -> %d) value restored\n",
			current->comm, task_pid_nr(current),
			*gs->se.enforcing.ptr, gs->se.enforcing.back);
		KCS_EVENT_LOG("'enforcing' value restored", parent, current,
			      parent_cred->uid, cred->uid);
		*gs->se.enforcing.ptr = gs->se.enforcing.back;
	}
	read_unlock(&gs->se.lock);
	rcu_read_unlock();
}

static int se_enforce_entry(struct kretprobe_instance *ri, struct pt_regs *p_regs)
{
	struct global_security *gs = &g_kcs.gs;

	TRACE("selinux enforce(%d) entry\n", *gs->se.enforcing.ptr);

	write_lock(&gs->se.lock);

	return 0;
}

static int se_enforce_handler(struct kretprobe_instance *ri, struct pt_regs *p_regs)
{
	struct global_security *gs = &g_kcs.gs;
	ssize_t length = (ssize_t)p_regs->ax;

	if (length > 0) {
		gs->se.enforcing.back = *gs->se.enforcing.ptr;
		TRACE("selinux enforce(%d) updated\n", *gs->se.enforcing.ptr);
	}
	write_unlock(&gs->se.lock);

	return 0;
}

static struct kretprobe se_enforce_kretprobe = {
	.kp.symbol_name = "sel_write_enforce",
	.handler = se_enforce_handler,
	.entry_handler = se_enforce_entry,
};

static void gs_selinux_init(struct global_security *gs)
{
	int err;

	if (!selinux_is_enabled()) {
		return;
	}

	gs->se.enabled.ptr = (int*)kallsyms_lookup_name("selinux_enabled");
	if (!gs->se.enabled.ptr) {
		return;
	}

	gs->se.enforcing.ptr = (int*)kallsyms_lookup_name("selinux_enforcing");
	if (!gs->se.enforcing.ptr) {
		return;
	}

	rwlock_init(&gs->se.lock);

	err = register_kretprobe(&se_enforce_kretprobe);
	if (err) {
		pr_err("%s: se_enforce register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		return;
	}

	gs->se.enabled.back = *gs->se.enabled.ptr;

	write_lock(&gs->se.lock);
	gs->se.enforcing.back = *gs->se.enforcing.ptr;
	write_unlock(&gs->se.lock);

	gs->se.inited = true;

	TRACE("selinux: e:%d protect enabled.\n", gs->se.enforcing.back);
}

static void gs_selinux_deinit(struct global_security *gs)
{
	if (gs->se.inited) {
		gs->se.inited = false;
		unregister_kretprobe(&se_enforce_kretprobe);
		TRACE("selinux: e:%d protect disabled.\n", gs->se.enforcing.back);
	}
}

static void mmap_min_addr_verify(struct global_security *gs)
{
	const struct cred *cred, *parent_cred;
	struct task_struct *parent;

	if (!gs->mmap_min_addr.inited) {
		return;
	}

	down_read(&gs->mmap_min_addr.rwsem);
	rcu_read_lock();
	cred = __task_cred(current);
	parent = rcu_dereference(current->parent);
	parent_cred = __task_cred(parent);
	if (*gs->mmap_min_addr.val.ptr != gs->mmap_min_addr.val.back) {
		TRACE("mmap_min_addr: %s(pid:%u) mmap_min_addr(%lu -> %lu) value restored\n",
			current->comm, task_pid_nr(current),
			*gs->mmap_min_addr.val.ptr, gs->mmap_min_addr.val.back);
		KCS_EVENT_LOG("'mmap_min_addr' value restored", parent, current,
			      parent_cred->uid, cred->uid);
		*gs->mmap_min_addr.val.ptr = gs->mmap_min_addr.val.back;
	}

	if (*gs->mmap_min_addr.dac.ptr != gs->mmap_min_addr.dac.back) {
		TRACE("mmap_min_addr: %s(pid:%u) dac_mmap_min_addr(%lu -> %lu) value restored\n",
			current->comm, task_pid_nr(current),
			*gs->mmap_min_addr.dac.ptr, gs->mmap_min_addr.dac.back);
		KCS_EVENT_LOG("'dac_mmap_min_addr' value restored",
			      parent, current, parent_cred->uid, cred->uid);
		*gs->mmap_min_addr.dac.ptr = gs->mmap_min_addr.dac.back;
	}
	rcu_read_unlock();
	up_read(&gs->mmap_min_addr.rwsem);
}

static int mmap_min_addr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct global_security *gs = &g_kcs.gs;
	bool write = !!regs->si; /* depends on kernel/build */

	if (!write) {
		return -EPERM;
	}

	TRACE("mmap_min_addr: val: %lu, dac_val: %lu entry\n",
		*gs->mmap_min_addr.val.ptr, *gs->mmap_min_addr.dac.ptr);

	down_write(&gs->mmap_min_addr.rwsem);

	return 0;
}

static int mmap_min_addr_control(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct global_security *gs = &g_kcs.gs;

	TRACE("mmap_min_addr: val: %lu, dac_val: %lu updated\n",
		*gs->mmap_min_addr.val.ptr, *gs->mmap_min_addr.dac.ptr);

	gs->mmap_min_addr.val.back = *gs->mmap_min_addr.val.ptr;
	gs->mmap_min_addr.dac.back = *gs->mmap_min_addr.dac.ptr;

	up_write(&gs->mmap_min_addr.rwsem);

	return 0;
}

static struct kretprobe mmap_min_addr_kretprobe = {
	.kp.symbol_name = "mmap_min_addr_handler",
	.handler = mmap_min_addr_control,
	.entry_handler = mmap_min_addr_entry,
};

static void gs_mmap_min_addr_init(struct global_security *gs)
{
	int err;

	gs->mmap_min_addr.val.ptr = (void*)kallsyms_lookup_name("mmap_min_addr");
	if (!gs->mmap_min_addr.val.ptr) {
		return;
	}

	gs->mmap_min_addr.dac.ptr = (void*)kallsyms_lookup_name("dac_mmap_min_addr");
	if (!gs->mmap_min_addr.dac.ptr) {
		return;
	}

	init_rwsem(&gs->mmap_min_addr.rwsem);

	err = register_kretprobe(&mmap_min_addr_kretprobe);
	if (err) {
		pr_err("%s: mmap_min_addr register_kprobe() failed with error %d\n",
			THIS_MODULE->name, err);
		return;
	}

	down_write(&gs->mmap_min_addr.rwsem);
	gs->mmap_min_addr.val.back = *gs->mmap_min_addr.val.ptr;
	gs->mmap_min_addr.dac.back = *gs->mmap_min_addr.dac.ptr;
	up_write(&gs->mmap_min_addr.rwsem);

	gs->mmap_min_addr.inited = true;
	TRACE("mmap_min_addr: val:%lu dac:%lu protect enabled.\n",
		gs->mmap_min_addr.val.back, gs->mmap_min_addr.dac.back);
}

static void gs_mmap_min_addr_deinit(struct global_security *gs)
{
	if (gs->mmap_min_addr.inited) {
		gs->mmap_min_addr.inited = false;
		unregister_kretprobe(&mmap_min_addr_kretprobe);
		TRACE("mmap_min_addr: val:%lu dac:%lu protect disabled.\n",
			gs->mmap_min_addr.val.back, gs->mmap_min_addr.dac.back);
	}
}

static void cpu_security_verify(struct cpu_sec_features *cpu)
{
	unsigned long cr4;
	unsigned int restore_bits;
	const struct cred *cred, *parent_cred;
	struct task_struct *parent;

	if (unlikely(!cpu->inited)) {
		return;
	}

	cr4 = native_read_cr4();
	restore_bits = 0;

	rcu_read_lock();
	cred = __task_cred(current);
	parent = rcu_dereference(current->parent);
	parent_cred = __task_cred(parent);

	if (unlikely(cpu->smep && !(cr4 & X86_CR4_SMEP))) {
		pr_warn_once("kproc: Unauthorized modifications CR4: %s(pid:%u)"
			" SMEP disabled\n", current->comm, task_pid_nr(current));
		KCS_EVENT_LOG("Unauthorized modifications CR4 (SMEP disabled)",
			      parent, current, parent_cred->uid, cred->uid);
		restore_bits |= X86_CR4_SMEP;
	}

	if (unlikely(cpu->smap && !(cr4 & X86_CR4_SMAP))) {
		pr_warn_once("kproc: Unauthorized modifications CR4: %s(pid:%u)"
			" SMAP disabled\n", current->comm, task_pid_nr(current));
		KCS_EVENT_LOG("Unauthorized modifications CR4 (SMAP disabled)",
			      parent, current, parent_cred->uid, cred->uid);
		restore_bits |= X86_CR4_SMAP;
	}

	if (unlikely(cpu->umip && !(cr4 & X86_CR4_UMIP))) {
		pr_warn_once("kproc: Unauthorized modifications CR4: %s(pid:%u)"
			" UMIP disabled\n", current->comm, task_pid_nr(current));
		KCS_EVENT_LOG("Unauthorized modifications CR4 (UMIP disabled)",
			      parent, current, parent_cred->uid, cred->uid);
		restore_bits |= X86_CR4_UMIP;
	}
	rcu_read_unlock();

	if (unlikely(cpu->recovery && restore_bits)) {
		unsigned long flags;

		raw_local_irq_save(flags);
		cr4 = native_read_cr4();
		native_write_cr4(cr4 | restore_bits);
		raw_local_irq_restore(flags);

		TRACE("cpu_security: %s(pid:%u)%s%s%s restored\n",
			current->comm, task_pid_nr(current),
			(restore_bits & X86_CR4_SMEP) ? " smep" : "",
			(restore_bits & X86_CR4_SMAP) ? " smap" : "",
			(restore_bits & X86_CR4_UMIP) ? " umip" : "");
		pr_warn("CPU Verify:%s%s%s restored\n",
			(restore_bits & X86_CR4_SMEP) ? " smep" : "",
			(restore_bits & X86_CR4_SMAP) ? " smap" : "",
			(restore_bits & X86_CR4_UMIP) ? " umip" : "");
	}
}

static void cpu_security_init(struct cpu_sec_features *cpu)
{
	unsigned long cr4 = native_read_cr4();

	cpu->smep = cr4 & X86_CR4_SMEP;
	cpu->smap = cr4 & X86_CR4_SMAP;
	cpu->umip = cr4 & X86_CR4_UMIP;

	if (cpu->smep || cpu->smap || cpu->umip) {
		TRACE("cpu_security: smep:%u smap:%u umip:%u protect enabled.\n",
			cpu->smep, cpu->smap, cpu->umip);
		cpu->inited = true;
	}
}

static void cpu_security_deinit(struct cpu_sec_features *cpu)
{
	if (cpu->inited) {
		TRACE("cpu_security: smep:%u smap:%u umip:%u protect disabled.\n",
			cpu->smep, cpu->smap, cpu->umip);
		cpu->inited = false;
	}
}

static int kcs_log_show(struct seq_file *m, void *v)
{
	struct rlog *log = m->private;
	u32 i;

	read_lock(&log->lock);
	seq_printf(m, "KCS event log (caught %u events, limit is %u messages):\n",
		   log->count, log->limit);

	i = log->count < log->limit ? log->limit - log->count : 0;
	for (; i < log->limit; i++) {
		struct log_entry *le = &log->arr[(i + log->count) % log->limit];

		seq_printf(m, "[%llu] %s: %s: %s(pid:%u uid:%u) --> %s(pid:%u, uid:%u)\n",
			   le->time, le->func, le->event,
			   le->process.parent_name, le->process.parent_pid,
			   le->process.parent_uid.val, le->process.name,
			   le->process.pid, le->process.uid.val);
	}
	read_unlock(&log->lock);
	return 0;
 }

static int kcs_log_open(struct inode *inode, struct file *file)
{
	return single_open(file, kcs_log_show, &g_kcs.log);
}

static const struct file_operations kcs_log_fops = {
	.owner   = THIS_MODULE,
	.open    = kcs_log_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int kcs_log_init(struct rlog *log, struct proc_dir_entry *kcs_dir)
{
	if (!proc_create("log", S_IRUSR, kcs_dir, &kcs_log_fops)) {
		pr_err("Can't create /proc/kcs/log");
		return -ENOMEM;
	}

	log->limit = KCS_MESSAGE_NUM;
	log->arr = vmalloc(log->limit * sizeof(struct log_entry));
	if (!log->arr) {
		remove_proc_entry("log", kcs_dir);
		pr_err("Can't allocate log->arr\n");
		return -ENOMEM;
	}
	rwlock_init(&log->lock);

	return 0;
}

static void kcs_log_deinit(struct rlog *log, struct proc_dir_entry *kcs_dir)
{
	remove_proc_entry("log", kcs_dir);
	vfree(log->arr);
}

static int kcs_info_show(struct seq_file *m, void *v)
{
	struct kc_sec *kcs = m->private;

	seq_printf(m, "kc security:\n");
	seq_printf(m, "root process monitor: %s\n",
		   kcs->rmap.inited ? "enabled" : "disabled");
	seq_printf(m, "selinux protection: %s\n",
		   kcs->gs.se.inited ? "enabled" : "disabled");
	seq_printf(m, "mmap_min_addr protection: %s\n",
		   kcs->gs.mmap_min_addr.inited ? "enabled" : "disabled");
	seq_printf(m, "cpu security:[%s%s%s] protection %s\n",
		   kcs->cpu.smep ? " smep": "",
		   kcs->cpu.smap ? " smap": "",
		   kcs->cpu.umip ? " umip": "",
		   kcs->cpu.inited ? "enabled" : "disabled");
	return 0;
}

static int kcs_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, kcs_info_show, &g_kcs);
}

static const struct file_operations kcs_info_fops = {
	.owner   = THIS_MODULE,
	.open    = kcs_info_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static u32 zero, one = 1;

static struct ctl_table kcs_table[] =
{
	{
		.procname	= "enforcing",
		.data		= &g_kcs.rmap.enforcing,
		.maxlen		= sizeof(g_kcs.rmap.enforcing),
		.mode		= S_IRUSR | S_IWUSR,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "cpu_recovery",
		.data		= &g_kcs.cpu.recovery,
		.maxlen		= sizeof(g_kcs.cpu.recovery),
		.mode		= S_IRUSR | S_IWUSR,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{	/* separated_gid - catch a situation when a process has
		 * unprivileged uid and privileged gid.
		 */
		.procname	= "separated_gid",
		.data		= &g_kcs.rmap.separated_gid,
		.maxlen		= sizeof(g_kcs.rmap.separated_gid),
		.mode		= S_IRUSR | S_IWUSR,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{ }
};

static struct ctl_table kcs_dir_table[] =
{
	{
		.procname	= "kcs",
		.mode		= S_IRUSR,
		.child		= kcs_table,
	},
	{ }
};

static int __init kprocm_init(void)
{
	struct proc_dir_entry *info;
	struct kc_sec *kcs = &g_kcs;
	int err;

	kcs->sysctl = register_sysctl_table(kcs_dir_table);
	if (!kcs->sysctl) {
		pr_err("Can't register kcs sysctl");
		return -ENOMEM;
	}

	kcs->proc_dir = proc_mkdir_mode("kcs", S_IRUSR, NULL);
	if (!kcs->proc_dir) {
		 pr_err("Can't create /proc/kcs");
		 err = -ENOMEM;
		 goto fail1;
	}

	info = proc_create("info", S_IRUSR, kcs->proc_dir, &kcs_info_fops);
	if (!info) {
		pr_err("Can't create /proc/kcs/info");
		err = -ENOMEM;
		goto fail2;
	}

	err = kcs_log_init(&kcs->log, kcs->proc_dir);
	if (err)
		goto fail3;

	err = rprocess_mon_init(&kcs->rmap);
	if (err)
		goto fail4;

	gs_selinux_init(&kcs->gs);
	gs_mmap_min_addr_init(&kcs->gs);
	cpu_security_init(&kcs->cpu);

	return 0;
fail4:
	kcs_log_deinit(&kcs->log, kcs->proc_dir);
fail3:
	remove_proc_entry("info", kcs->proc_dir);
fail2:
	remove_proc_entry("kcs", NULL);
fail1:
	unregister_sysctl_table(kcs->sysctl);
	return err;
}

static void __exit kprocm_exit(void)
{
	gs_selinux_deinit(&g_kcs.gs);
	gs_mmap_min_addr_deinit(&g_kcs.gs);
	cpu_security_deinit(&g_kcs.cpu);
	rprocess_mon_deinit(&g_kcs.rmap);

	unregister_sysctl_table(g_kcs.sysctl);

	kcs_log_deinit(&g_kcs.log, g_kcs.proc_dir);
	remove_proc_entry("info", g_kcs.proc_dir);
	remove_proc_entry("kcs", NULL);
}

module_init(kprocm_init);
module_exit(kprocm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intrusion Detection Monitor");
