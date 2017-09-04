/*
 * Core Infrastrucure to support Opportunistic Huge Pages.
 * Abbreaviated to ohp.
 */

#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/khugepaged.h>
#include <linux/ohp.h>

/* To protect ohp maintenance list */
DEFINE_SPINLOCK(ohp_mm_lock);

static struct task_struct *kbinmanager_thread __read_mostly;
static unsigned int kbinmanager_scan_sleep_msecs = 10000;
static DECLARE_WAIT_QUEUE_HEAD(kbinmanager_wait);

/*
 * This exists for testing purpose as of now.
 * It tells how many huge pages are still to be promoted.
 * We always update it with ohp_mm_lock held.
 * Hence, no need for separate synchronization for this.
 */
unsigned long nr_ohp_bins = 0;

/*
 * List of mm structs to be processed for huge page promotion.
 */
struct ohp_scan {
	struct list_head mm_head;
};

struct ohp_scan ohp_scan = {
	.mm_head = LIST_HEAD_INIT(ohp_scan.mm_head),
};

bool ohp_has_work(void)
{
	/*
	return !list_empty(&ohp_scan.mm_head);
	*/
	return !(!nr_ohp_bins);
}

#define OHP_TASK_ENTER	1000
#define OHP_TASK_EXIT	1001

/*
 * TODO: Verify if how we get reference to task mm in below functions
 * is correct. Handle cases if mm runs away from under us.
 */
static inline int ohp_add_task(struct task_struct *task)
{
	struct mm_struct *mm;

	mm = get_task_mm(task);
	if (!mm)
		return -EINVAL;

	spin_lock(&ohp_mm_lock);
	list_add_tail(&mm->ohp_list, &ohp_scan.mm_head);
	atomic_inc(&mm->mm_count);
	spin_unlock(&ohp_mm_lock);
	/*
	 * kbinmanager may not have been started yet.
	 */
	start_kbinmanager();
	mmput(mm);
	return 0;
}

static inline void ohp_add_mm(struct mm_struct *mm)
{
	struct mm_struct *mm_struct = NULL;

	spin_lock(&ohp_mm_lock);

	/* Check if mm is already present in the list. */
	list_for_each_entry(mm_struct, &ohp_scan.mm_head, ohp_list)
		if (mm_struct == mm)
			goto out;

	list_add_tail(&mm->ohp_list, &ohp_scan.mm_head);
	atomic_inc(&mm->mm_count);
out:
	spin_unlock(&ohp_mm_lock);
	return;
}

static inline int ohp_exit_task(struct task_struct *task)
{
	struct mm_struct *mm;

	mm = get_task_mm(task);

	if (!mm)
		return -EINVAL;

	spin_lock(&ohp_mm_lock);
	list_del(&mm->ohp_list);
	mmdrop(mm);
	spin_unlock(&ohp_mm_lock);
	mmput(mm);
	return 0;
}

void ohp_exit_mm(struct mm_struct *mm_src)
{
	struct mm_struct *mm, *tmp;

	spin_lock(&ohp_mm_lock);
	list_for_each_entry_safe(mm, tmp, &ohp_scan.mm_head,
					ohp_list) {
		if (mm == mm_src) {
			list_del(&mm->ohp_list);
			mmdrop(mm);
			break;
		}
	}
	spin_unlock(&ohp_mm_lock);
	return;
}

/*
 * Initialize ohp buckets for the specified process.
 * This would hold all the huge page aligned addresses
 * in different buckets based on the heatmap of accesses.
 */
void init_mm_ohp_bins(struct mm_struct *mm)
{
	int i;

	for (i=0; i<MAX_BINS; i++) {
		INIT_LIST_HEAD(&mm->ohp.priority[i]);
		mm->ohp.count[i] = 0;
	}
}

/*
 * Traverse through the list of all processes currently
 * participating in ohp framework and select the process
 * with the highest weight.
 */
struct mm_struct *ohp_get_suitable_mm(void)
{
	struct mm_struct *mm, *best_mm = NULL;
	unsigned int best_weight = 0;

	spin_lock(&ohp_mm_lock);
	list_for_each_entry(mm, &ohp_scan.mm_head, ohp_list) {
		if (mm->ohp.ohp_weight > best_weight)
			best_mm = mm;
	}
	spin_unlock(&ohp_mm_lock);
	return best_mm;
}

/*
 * Get the next huge page candidate.
 */
unsigned long get_next_ohp_addr(struct mm_struct **mm_src)
{
	struct mm_struct *mm;
	struct ohp_addr *kaddr;
	unsigned long address = 0;
	int i;

	*mm_src = NULL;
	/* select the best process first.*/
	mm = ohp_get_suitable_mm();
	if (!mm)
		return address;

	spin_lock(&ohp_mm_lock);
	for (i = MAX_BINS-1; i >= 0; i--) {
		if (list_empty(&mm->ohp.priority[i]))
			continue;
		/* If we are here, we have found the next ohp candidate. */
		goto found;
	}
	spin_unlock(&ohp_mm_lock);
	return address;

found:
	kaddr = list_first_entry(&mm->ohp.priority[i],
			struct ohp_addr, entry);

	address = kaddr->address;
	*mm_src = kaddr->mm;
	/*
	 * We perhaps do not want to see the same address again.
	 * Delete it.
	 */
	list_del(&kaddr->entry);
	kfree(kaddr);
	mm->ohp.count[i] -= 1;
	nr_ohp_bins -= 1;
	spin_unlock(&ohp_mm_lock);
	/*
	trace_printk(KERN_INFO"Found mm address to promote\n");
	*/
	return address;
}

/*
 * Remove a range of addresses from the ohps.
 * This should also take care of cases when mm is being destroyed.
 */
void remove_ohp_bins(struct vm_area_struct *vma)
{
	struct mm_struct *mm;
	struct ohp_addr *tmp, *kaddr;
	int i;

	mm = vma->vm_mm;
	if (!mm)
		return;
	/* TODO: See if this can be optimized. */
	for (i=0; i<MAX_BINS; i++) {
		list_for_each_entry_safe(kaddr, tmp,
				&mm->ohp.priority[i], entry) {
			if (kaddr->address >= vma->vm_start &&
				kaddr->address <= vma->vm_end) {
				spin_lock(&ohp_mm_lock);
				list_del(&kaddr->entry);
				mm->ohp.count[i] -= 1;
				nr_ohp_bins -= 1;
				kfree(kaddr);
				spin_unlock(&ohp_mm_lock);
			}
		}
	}
}

/*
 * Check for potential race conditions. We should already
 * be holding mm semaphore at this point.
 */
int add_ohp_bin(struct mm_struct *mm, unsigned long addr)
{
	struct ohp_addr *kaddr;

	if (!mm)
		return 0;

	/* Align with huge page boundary.
	 * TODO: Verify if the address is still valid after alignment.
	 * It can also be done at the time of promotion.
	 */
	addr = (addr + ~HPAGE_PMD_MASK) & HPAGE_PMD_MASK;

	/*
	 * TODO: Optimize this for performance with a dedicated slab.
	 */
	kaddr = kzalloc(sizeof(struct ohp_addr), GFP_KERNEL);
	if (!kaddr)
		return -ENOMEM;

	/*
	 * This may be enabled if a generic huge page support extension
	 * is needed. For now, we rely on the userspace to provide us with
	 * every process that needs to be considered for huge pages.
	 */
	/* ohp_add_mm(mm); */
	kaddr->address = addr;
	kaddr->mm = mm;

	spin_lock(&ohp_mm_lock);
	list_add_tail(&kaddr->entry, &mm->ohp.priority[0]);
	mm->ohp.count[0] += 1;
	nr_ohp_bins += 1;
	spin_unlock(&ohp_mm_lock);
	return 0;
}

/*
 * Helper function which can be used by a loadable kernel module
 * for debugging or analysis purpose.
 */
long count_ohp_bins(struct mm_struct *mm)
{
	int i;
	long count = 0;

	if (!mm)
		return -EINVAL;

	/*
	 * This is potentially racy. But does it matter ?
	 */
	for (i=0; i<MAX_BINS; i++) {
		count += mm->ohp.count[i];
	}

	return count;
}
EXPORT_SYMBOL(count_ohp_bins);

/*
 * We decide the action to be taken using value, as per the
 * following rules -
 * 1000 -   The process has just started and needs to be added to
 *          the queue for monitoring its huge pages.
 * 1001 -   The process has finished and hence it is safe to remove
 *          from the list. Make sure to drop reference to any of task
 *          members. Ideally, this should not be required as we take care
 *          of this case at the time of mmexit.
 * Others - All other values denote a legitimate sensitivity for
 *          the process. It must be between 0 and 100.
 */
SYSCALL_DEFINE2(update_mm_ohp_stats, unsigned int, pid, unsigned int, value)
{
	struct task_struct *task;
	struct pid *pid_struct;
	struct mm_struct *mm;
	long ret = 0;

	pid_struct = find_get_pid(pid);
	if (!pid_struct) {
		printk(KERN_INFO"Invalid pid: %d\n", pid);
		return -EINVAL;
	}

	task = pid_task(pid_struct, PIDTYPE_PID);
	if (!task) {
		printk(KERN_INFO"Unable to retrieve task for pid: %d\n", pid);
		return -EINVAL;
	}

	//task_lock(task);
	if (value == OHP_TASK_ENTER) {
		ohp_add_task(task);
		printk(KERN_INFO"Added pid: %d %s to scan list\n",
						pid, task->comm);
		goto exit_success;
	}

	if (value == OHP_TASK_EXIT) {
		ohp_exit_task(task);
		printk(KERN_INFO"Removed pid: %d %s from scan list\n",
						pid, task->comm);
		goto exit_success;
	}
	/*
	 * Verify the validity of the sensitivity value.
	 * Valid range is only from 0 - 100.
	 * We can't simply return from here as the task is locked.
	 */
	if (value > 100)
		return -EINVAL;

	mm = get_task_mm(task);
	if (!mm)
		return -EINVAL;

	mm->ohp.ohp_weight = value;
	mmput(mm);

exit_success:
	//task_unlock(task);
	return ret;
}

static void kbinmanager_do_scan(void)
{
	static unsigned long iteration = 0;

	printk(KERN_INFO"kbinmanager scan: %ld Promotions Left: %ld\n",
					iteration, nr_ohp_bins);
	iteration += 1;
}

static void kbinmanager_wait_work(void)
{
	/* put to sleep for a certain period */
	wait_event_freezable_timeout(kbinmanager_wait, kthread_should_stop(),
			msecs_to_jiffies(kbinmanager_scan_sleep_msecs));
	return;
}

/*
 * Kernel thread that opportunistically scans process
 * address space to get a measure of its working set.
 */
static int kbinmanager(void *none)
{
	set_freezable();
	set_user_nice(current, MAX_NICE);

	while (!kthread_should_stop()) {
		kbinmanager_do_scan();
		kbinmanager_wait_work();
	}

	return 0;
}

int start_kbinmanager(void)
{
	int err=  0;

	/*
	 * Check if the thread is not active already. Start if it is not.
	 */
	if (khugepaged_enabled()) {
		if (!kbinmanager_thread) {
			kbinmanager_thread = kthread_run(kbinmanager, NULL,
								"kbinmanager");
			if (unlikely(IS_ERR(kbinmanager_thread))) {
				pr_err("kbinmanager thread failed to start\n");
				err = PTR_ERR(kbinmanager_thread);
				kbinmanager_thread = NULL;
				goto fail;
			}
			printk(KERN_INFO"kbinmanager thread started\n");
		}
	}
fail:
	return err;
}

void stop_kbinmanager(void)
{
	if (kbinmanager_thread) {
		kthread_stop(kbinmanager_thread);
		kbinmanager_thread = NULL;
	}
}
