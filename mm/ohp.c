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

/* To protect ohp maintenance list */
DEFINE_SPINLOCK(ohp_mm_lock);

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
	return !list_empty(&ohp_scan.mm_head);
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
	spin_unlock(&ohp_mm_lock);
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
 * Get the next huge page candidate.
 */
unsigned long get_next_ohp_addr(struct mm_struct **mm_src)
{
	struct mm_struct *mm;
	struct ohp_addr *kaddr;
	unsigned long address = 0;
	int i;

	*mm_src = NULL;
	spin_lock(&ohp_mm_lock);

	list_for_each_entry(mm, &ohp_scan.mm_head, ohp_list) {
		for (i = MAX_BINS-1; i >= 0 ; i--) {
				if (list_empty(&mm->ohp.priority[i]))
					continue;
				goto found;
		}
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
	spin_unlock(&ohp_mm_lock);
	printk(KERN_INFO"Found mm address to promote\n");
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