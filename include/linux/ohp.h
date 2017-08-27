#include <linux/khugepaged.h>

extern void ohp_exit_mm(struct mm_struct *mm);
extern bool ohp_has_work(void);
extern void init_mm_ohp_bins(struct mm_struct *mm);
extern void remove_ohp_bins(struct vm_area_struct *vma);
extern int add_ohp_bin(struct mm_struct *mm, unsigned long addr);
extern unsigned long get_next_ohp_addr(struct mm_struct **mm_struct);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int ohp_enter(struct vm_area_struct *vma,
				unsigned long address, unsigned long vm_flags)
{
	if (!test_bit(MMF_VM_HUGEPAGE, &vma->vm_mm->flags)) {
		if ((khugepaged_always() ||
		     (khugepaged_req_madv() && (vm_flags & VM_HUGEPAGE))) &&
		    !(vm_flags & VM_NOHUGEPAGE)) {
			if (add_ohp_bin(vma->vm_mm, address))
				return -ENOMEM;
		}
	}
	return 0;
}
#else
static inline int ohp_enter(struct vm_area_struct *vma,
			unsigned long address, unsigned long vm_flags)
{
	return 0;
}
#endif
