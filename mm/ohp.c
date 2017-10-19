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
#include <linux/log2.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/khugepaged.h>
#include <linux/ohp.h>

/* To protect ohp maintenance list */
DEFINE_SPINLOCK(ohp_mm_lock);

static struct task_struct *kbinmanager_thread __read_mostly;
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

unsigned long get_time_difference(struct timeval *t0, struct timeval *t1)
{
	long msecs;

	msecs = (t1->tv_sec - t0->tv_sec) * 1000 +
			(t1->tv_usec - t0->tv_usec) / 1000;
	if (msecs < 0)
		msecs = 0;

	return (unsigned long) msecs;
}

bool ohp_has_work(void)
{
	/*
	return !list_empty(&ohp_scan.mm_head);
	*/
	return !(!nr_ohp_bins);
}

#define OHP_TASK_ENTER	1000
#define OHP_TASK_EXIT	1001

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
 * TODO: Verify if how we get reference to task mm in below functions
 * is correct. Handle cases if mm runs away from under us.
 */
static inline int ohp_add_task(struct task_struct *task)
{
	struct mm_struct *mm;

	mm = get_task_mm(task);
	if (!mm)
		return -EINVAL;

	ohp_add_mm(mm);
	/*
	 * kbinmanager may not have been started yet.
	 */
	start_kbinmanager();
	mmput(mm);
	return 0;
}

static inline int ohp_exit_task(struct task_struct *task)
{
	struct mm_struct *mm;

	mm = get_task_mm(task);

	if (!mm)
		return -EINVAL;

	ohp_exit_mm(mm);
	mmput(mm);
	return 0;
}

/*
 * Initialize ohp buckets for the specified process.
 * This would hold all the huge page aligned addresses
 * in different buckets based on the heatmap of accesses.
 */
void init_mm_ohp_bins(struct mm_struct *mm)
{
	int i;

	/* We perhaps do not need locking here as the process
	 * is just getting initialized.
	 */
	for (i=0; i<MAX_BINS; i++) {
		mutex_init(&mm->ohp.lock);
		INIT_LIST_HEAD(&mm->ohp.priority[i]);
		mm->ohp.count[i] = 0;
		mm->ohp.ohp_remaining = 0;
		mm->ohp.nr_scans = 0;
	}
}

/*
 * We use this to decide if we should continue scanning the
 * mm. The mm belong to the list as long as the process exists.
 * This handles processes with dynamic memory requirements.
 */
unsigned long ohp_mm_pending_promotions(struct mm_struct *mm)
{
	int i;
	unsigned long remaining = 0;

	for (i = MAX_BINS - 1; i > 1; i--)
		remaining += mm->ohp.count[i];

	/*
	 * mm should have enough promotions pending for the
	 * atleat 1 khugepaged iteration.
	 */
	return remaining > 7 ? 1 : 0;
}
EXPORT_SYMBOL(ohp_mm_pending_promotions);

static inline unsigned long mm_ohp_weight(struct mm_struct *mm)
{
	unsigned long weight = 0;

	mutex_lock(&mm->ohp.lock);
	if (ohp_mm_pending_promotions(mm))
		weight = ((mm->ohp.ohp_weight * 10000) /
					mm->ohp.ohp_remaining);
	mutex_unlock(&mm->ohp.lock);

	return weight;
}

/*
 * Traverse through the list of all processes currently
 * participating in ohp framework and select the process
 * with the highest weight.
 */
struct mm_struct *ohp_get_target_mm(void)
{
	struct mm_struct *mm = NULL, *best_mm = NULL;
	unsigned long weight, best_weight = 0;

	spin_lock(&ohp_mm_lock);
	list_for_each_entry(mm, &ohp_scan.mm_head, ohp_list) {
		weight = mm_ohp_weight(mm);
		if (weight > best_weight) {
			best_mm = mm;
			best_weight = weight;
		}
	}
	spin_unlock(&ohp_mm_lock);
	return best_mm;
}
EXPORT_SYMBOL(ohp_get_target_mm);

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
	mm = ohp_get_target_mm();
	if (!mm)
		return address;

	mutex_lock(&mm->ohp.lock);
#if 0
	for (i = MAX_BINS-1; i >= 0; i--) {
		if (list_empty(&mm->ohp.priority[i]))
			continue;
		/* If we are here, we have found the next ohp candidate. */
		goto found;
	}
#endif
	i = MAX_BINS - 1;
	if (list_empty(&mm->ohp.priority[i]))
		goto out;

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
	mm->ohp.ohp_remaining -= 1;
	nr_ohp_bins -= 1;
out:
	mutex_unlock(&mm->ohp.lock);
	return address;
}

/*
 * Get the next huge page candidate for a specific mm.
 */
struct ohp_addr *get_ohp_mm_addr(struct mm_struct *mm)
{
	struct ohp_addr *kaddr = NULL;
	int i;

	if (!mm)
		return 0;

	mutex_lock(&mm->ohp.lock);

	/* search backwards from high to low priority bins. */
	for (i = MAX_BINS - 1; i > 1; i--) {
		if (list_empty(&mm->ohp.priority[i]))
			continue;
		/* If we are here, we have found the next ohp candidate. */
		goto found;
	}

	if (list_empty(&mm->ohp.priority[i]))
		goto out;

found:
	kaddr = list_first_entry(&mm->ohp.priority[i],
			struct ohp_addr, entry);

	/*
	 * We perhaps do not want to see the same address again.
	 * Delete it.
	 */
	list_del(&kaddr->entry);
	mm->ohp.count[i] -= 1;
	mm->ohp.ohp_remaining -= 1;
	nr_ohp_bins -= 1;
out:
	mutex_unlock(&mm->ohp.lock);
	return kaddr;
}

void ohp_putback_kaddr(struct mm_struct *mm, struct ohp_addr *kaddr)
{
	int pos;

	mutex_lock(&mm->ohp.lock);
	/* put back on the to be scanned list */
	pos = 1 - mm->ohp.current_scan_idx;
	list_add_tail(&kaddr->entry, &mm->ohp.priority[pos]);
	mm->ohp.count[pos] += 1;
	mm->ohp.ohp_remaining += 1;
	mutex_unlock(&mm->ohp.lock);
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
	mutex_lock(&mm->ohp.lock);
	for (i=0; i<MAX_BINS; i++) {
		list_for_each_entry_safe(kaddr, tmp,
				&mm->ohp.priority[i], entry) {
			if (kaddr->address >= vma->vm_start &&
				kaddr->address <= vma->vm_end) {
				list_del(&kaddr->entry);
				mm->ohp.count[i] -= 1;
				mm->ohp.ohp_remaining -= 1;
				nr_ohp_bins -= 1;
				kfree(kaddr);
			}
		}
	}
	mutex_unlock(&mm->ohp.lock);
}

/*
 * Check for potential race conditions. We should already
 * be holding mm semaphore at this point.
 */
int add_ohp_bin(struct mm_struct *mm, unsigned long addr)
{
	struct ohp_addr *kaddr;
	unsigned int index;

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

	mutex_lock(&mm->ohp.lock);
	index = mm->ohp.current_scan_idx;
	list_add_tail(&kaddr->entry, &mm->ohp.priority[!(!index)]);
	mm->ohp.count[index] += 1;
	mm->ohp.ohp_remaining += 1;
	nr_ohp_bins += 1;
	mutex_unlock(&mm->ohp.lock);
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

	/*
	 * We expect the user-space deamon to suppply weight
	 * as the moving average. Floating point caclulation is
	 * easier in the user-space so it also avoids the need
	 * for tuning the calculation.
	 */
	mm->ohp.ohp_weight = value;
	mmput(mm);

exit_success:
	return ret;
}

static void kbinmanager_wait_cpu_bound(unsigned long busy_msecs,
				unsigned long idle_msecs)
{
	unsigned long sleep_msecs;

	/*
	 * We have seen idle to be more than busy at times.
	 * Below is a workaround to handle indefinite sleeping.
	 */
	if (idle_msecs > busy_msecs)
		busy_msecs = 0;
	else
		busy_msecs = busy_msecs - idle_msecs;
	/*
	 * Bound by 5% cpu utilization.
	 * Also, enforce minimum bound of 5 seconds.
	 */
	sleep_msecs = busy_msecs * 19;
	if (sleep_msecs < 5000)
		sleep_msecs = 5000;

	trace_printk("busy: %ld ms sleep: %ld ms\n", busy_msecs, sleep_msecs);

	/* put to sleep for a certain period */
	wait_event_freezable_timeout(kbinmanager_wait, kthread_should_stop(),
			msecs_to_jiffies(sleep_msecs));
}

static void kbinmanager_wait_scan_period(unsigned long msecs)
{
	/* put to sleep for a certain period */
	wait_event_freezable_timeout(kbinmanager_wait, kthread_should_stop(),
			msecs_to_jiffies(msecs));
}

static struct mm_struct *ohp_next_scan_candidate(unsigned long curr_tstamp)
{
	struct mm_struct *mm, *mm_candidate = NULL;

	spin_lock(&ohp_mm_lock);
	/* Select the mm with least scan timestamp. */
	list_for_each_entry(mm, &ohp_scan.mm_head, ohp_list) {
		if (mm->ohp.tstamp < curr_tstamp) {
			mm_candidate = mm;
			break;
		}
	}
	spin_unlock(&ohp_mm_lock);

	return mm_candidate;
}

static void kbinmanager_do_scan(unsigned long *idle_msecs)
{
	static unsigned long curr_tstamp = 0;
	struct mm_struct *mm = NULL;

	/* First, update the current timestamp. */
	curr_tstamp += 1;

	/*
	 * Now, scan and adjust every mm whose timestamp is
	 * less than the current iteration.
	 */
	while (true) {
		mm = ohp_next_scan_candidate(curr_tstamp);
		if (!mm)
			break;

		ohp_clear_pte_accessed_mm(mm);
		kbinmanager_wait_scan_period(1000);
		*idle_msecs += 1000;
		ohp_adjust_mm_bins(mm);
		mm->ohp.tstamp = curr_tstamp;
	}
}

/*
 * Kernel thread that opportunistically scans process
 * address space to get a measure of its working set.
 */
static int kbinmanager(void *none)
{
	struct timeval start, end;
	unsigned long idle_msecs, busy_msecs;

	set_freezable();
	set_user_nice(current, MAX_NICE);

	while (!kthread_should_stop()) {
		idle_msecs = 0;
		do_gettimeofday(&start);
		kbinmanager_do_scan(&idle_msecs);
		do_gettimeofday(&end);
		kbinmanager_wait_cpu_bound(busy_msecs, idle_msecs);
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

#define CLEAR_PTE	0
#define PTE_ACCESSED	1
int ohp_follow_pte(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long addr, unsigned int op)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte, cleared;
	spinlock_t *ptl;
	int ret = 0;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || unlikely (pgd_bad(*pgd)))
		return ret;

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return ret;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return ret;

	if (pmd_protnone(*pmd))
		return ret;

	/* This should be a bug. */
	if (pmd_trans_huge(*pmd))
		return ret;

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	/* Sanity check to make sure the page table exists. */
	if (pte_none(*ptep))
		goto unlock;

	pte = *ptep;
	if (!pte_present(pte))
		goto unlock;

	if (op == PTE_ACCESSED) {
		ret = pte_young(pte);
	} else {
		cleared = pte_mkold(pte);
		set_pte_at(mm, addr, ptep, cleared);
	}
unlock:
	pte_unmap_unlock(ptep, ptl);
	return ret;
}

static void ohp_clear_hpage_range(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte, cleared;
	spinlock_t *ptl;
	unsigned long addr;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely (pgd_bad(*pgd)))
		return;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud))
		return;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return;

	if (pmd_trans_huge(*pmd))
		return;

	for (addr = address; addr < address + HPAGE_PMD_SIZE;
			addr += PAGE_SIZE) {
		ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
		/* Sanity check to make sure the page table exists. */
		if (pte_none(*ptep))
			goto unlock;

		pte = *ptep;
		if (!pte_present(pte))
			goto unlock;

		cleared = pte_mkold(pte);
		set_pte_at(mm, addr, ptep, cleared);
unlock:
		pte_unmap_unlock(ptep, ptl);
	}
}

/*
 * find_vma can also return the next vma if the address
 * does not currently belong to a region. We can not promote
 * such addresses. Hence, it seems more safe to discard such
 * regions from further huge page considerations.
 */
static inline bool is_vma_valid(struct vm_area_struct *vma, unsigned long addr)
{
	return (addr >= vma->vm_start && addr < vma->vm_end);
}

/* Clears the page table accessed bit for the specified huge page region.
 * The address must be aligned with the huge page boundary.
 */
void ohp_clear_pte_accessed_range(struct mm_struct *mm, unsigned long start)
{
	struct vm_area_struct *vma1, *vma2;
	unsigned long end = start + HPAGE_PMD_SIZE;

	/*
	 * Check if the whole range falls within a single vma.
	 * If not, there is no need to scan this page as it can not
	 * be promoted anyway.
	 */
	vma1 = find_vma(mm, start);
	if (!vma1 || !is_vma_valid(vma1, start))
		return;

	vma2 = find_vma(mm, end - PAGE_SIZE);
	if (!vma2 || vma2 != vma1)
		return;

	/* Clear the accessed bit of each base page */
	ohp_clear_hpage_range(mm, vma1, start);
}

void ohp_clear_pte_accessed_mm(struct mm_struct *mm)
{
	unsigned int index;
	struct ohp_addr *kaddr;
	/*
	 * Identify the list to be scanned and clear accessed bit of each base
	 * page.
	 */
	mutex_lock(&mm->ohp.lock);
	index = mm->ohp.current_scan_idx;
	list_for_each_entry(kaddr, &mm->ohp.priority[index], entry)
		ohp_clear_pte_accessed_range(mm, kaddr->address);
	mutex_unlock(&mm->ohp.lock);
}
EXPORT_SYMBOL(ohp_clear_pte_accessed_mm);

static int ohp_calc_hpage_hotness(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	unsigned long addr;
	int accessed = 0;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely (pgd_bad(*pgd)))
		return -1;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud))
		return -1;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return -1;

	if (pmd_trans_huge(*pmd))
		return -1;

	for (addr = address; addr < address + HPAGE_PMD_SIZE;
			addr += PAGE_SIZE) {
		ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
		/* Sanity check to make sure the page table exists. */
		if (pte_none(*ptep))
			goto unlock;

		pte = *ptep;
		if (!pte_present(pte))
			goto unlock;

		if (pte_young(pte))
			accessed += 1;
unlock:
		pte_unmap_unlock(ptep, ptl);
	}
	return accessed;
}

/*
 * Returns the number of active baseline pages for the given huge page region.
 * The address must be already aligned with the huge page boundary.
 */
static int ohp_nr_accessed(struct mm_struct *mm, unsigned long start)
{
	struct vm_area_struct *vma1, *vma2;
	unsigned long end = start + HPAGE_PMD_SIZE;

	vma1 = find_vma(mm, start);
	if (!vma1 || !is_vma_valid(vma1, start))
		return -1;

	vma2 = find_vma(mm, end - PAGE_SIZE);
	if (!vma2 || vma2 != vma1)
		return -1;

	return ohp_calc_hpage_hotness(mm, vma1, start);
}

static inline int update_get_kaddr_index(struct ohp_addr *kaddr, int nr_accessed)
{
	kaddr->weight = (kaddr->weight * 4 + nr_accessed * 6)/10;

	if (kaddr->weight > HPAGE_PMD_NR)
		kaddr->weight = HPAGE_PMD_NR;

	return order_base_2(kaddr->weight);
}

void ohp_adjust_mm_bins(struct mm_struct *mm)
{
	int nr_accessed, index, new_index;
	struct ohp_addr *kaddr, *tmp;

	/* TODO: Optimize locking behavior. */
	mutex_lock(&mm->ohp.lock);
	index = mm->ohp.current_scan_idx;
	list_for_each_entry_safe(kaddr, tmp, &mm->ohp.priority[index], entry) {
		nr_accessed = ohp_nr_accessed(mm, kaddr->address);
		/* Remove invalid addressed first. */
		if (nr_accessed < 0) {
			/*
			 * We treat this to be an error and discard this from
			 * further considerations.
			 */
			list_del(&kaddr->entry);
			mm->ohp.ohp_remaining -= 1;
			mm->ohp.count[index] -= 1;
			mm->ohp.invalid += 1;
			nr_ohp_bins -= 1;
			kfree(kaddr);
			continue;
		}

		new_index = update_get_kaddr_index(kaddr, nr_accessed);

		/* First 3 scans are used to indentify hot regions. */
		if (mm->ohp.nr_scans < 3)
			continue;
		else {
			/*
			 * Less than 32 references and we put the region onto
			 * the scan list to give it another chance. Note that
			 * the first 2 lists are scanning lists used to hold
			 * relatively inactive regions and hence addition of 2.
			 */
			if (new_index < 2)
				new_index = 1 - index;
			else
				new_index = 2 + new_index;
		}

		/* Validate the new index of the current huge page region. */
		VM_BUG_ON(new_index >= MAX_BINS);
		list_move_tail(&kaddr->entry, &mm->ohp.priority[new_index]);
		mm->ohp.count[index] -= 1;
		mm->ohp.count[new_index] += 1;
	}
	index = 1 - index;
	mm->ohp.current_scan_idx = index;
	mm->ohp.nr_scans += 1;
	mutex_unlock(&mm->ohp.lock);
}
EXPORT_SYMBOL(ohp_adjust_mm_bins);
