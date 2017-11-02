#include <linux/khugepaged.h>
#include <linux/time.h>

extern struct mm_struct *ohp_get_target_mm(unsigned int);
extern void ohp_clear_pte_accessed_mm(struct mm_struct *mm);
extern void ohp_adjust_mm_bins(struct mm_struct *mm);
extern void ohp_exit_mm(struct mm_struct *mm);
extern bool ohp_has_work(void);
extern void init_mm_ohp_bins(struct mm_struct *mm);
extern void remove_ohp_bins(struct vm_area_struct *vma);
extern int add_ohp_bin(struct mm_struct *mm, unsigned long addr);
extern unsigned long get_next_ohp_addr(struct mm_struct **mm_struct);
extern struct ohp_addr *get_ohp_mm_addr(struct mm_struct *mm_struct);
extern void ohp_putback_kaddr(struct mm_struct *mm, struct ohp_addr *kaddr);
extern unsigned long ohp_mm_pending_promotions(struct mm_struct *mm);
extern unsigned long ohp_mm_priority_promotions(struct mm_struct *mm);
extern unsigned long get_time_difference(struct timeval *t0, struct timeval *t1);
extern struct ohp_addr *get_ohp_global_kaddr(struct mm_struct **src);
int start_kbinmanager(void);
void stop_kbinmanager(void);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int ohp_enter(struct vm_area_struct *vma,
				unsigned long address, unsigned long vm_flags)
{
	//if (!test_bit(MMF_VM_HUGEPAGE, &vma->vm_mm->flags)) {
	/*
	 * khugepaged_enter sets the above flag. Hence, we need to skip this
	 * to add the current address to ohp_bins.
	 */
	if ((khugepaged_always() ||
	     (khugepaged_req_madv() && (vm_flags & VM_HUGEPAGE))) &&
	    !(vm_flags & VM_NOHUGEPAGE)) {
		if (add_ohp_bin(vma->vm_mm, address))
			return -ENOMEM;
	}
	//}
	return 0;
}
#else
static inline int ohp_enter(struct vm_area_struct *vma,
			unsigned long address, unsigned long vm_flags)
{
	return 0;
}
#endif
