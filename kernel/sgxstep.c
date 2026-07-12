/*
 *  This file is part of the SGX-Step enclave execution control framework.
 *
 *  Copyright (C) 2017 Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>,
 *                     Raoul Strackx <raoul.strackx@cs.kuleuven.be>
 *
 *  SGX-Step is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SGX-Step is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SGX-Step. If not, see <http://www.gnu.org/licenses/>.
 */

 #include "sgxstep_internal.h"
 #include "sgxstep_ioctl.h"
 
 #include <asm/pgtable.h>
 #include <asm/page.h>
 #include <linux/mm.h>
 #include <linux/sched.h>
 #include <asm/irq.h>
 #include <asm/apic.h>
 
 #include <linux/fs.h>
 #include <linux/miscdevice.h>
 #include <linux/uaccess.h>
 #include <linux/kprobes.h>
 #include <linux/mm.h>
 #include <linux/highmem.h>
 #include <linux/slab.h>
 #include <asm/set_memory.h>
 
 #include <linux/clockchips.h>
 #include <linux/version.h>
 
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>, Raoul Strackx <raoul.strackx@cs.kuleuven.be>");
 MODULE_DESCRIPTION("SGX-Step: A Practical Attack Framework for Precise Enclave Execution Control");
 
 static int mtrr_id;

 #if (LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
     #define pin_user_pages_fast         get_user_pages_fast
     #define unpin_user_pages            put_user_pages
 #endif

 /*
  * PER-OPEN ISR mappings with deferred free (Design B). Each process that calls
  * SETUP_ISR_MAP gets its OWN pinned+vmapped copy of the ISR section at a distinct
  * kernel address. This is REQUIRED: the timer handler keeps per-step state in
  * rip-relative globals (__ss_irq_fired handshake, __ss_irq_count, rax/rdx/rcx
  * save slots). A single shared copy makes two concurrently single-stepping
  * processes race on those globals (one core's IRQ sets the other's __ss_irq_fired
  * → broken step handshake, corrupted saved regs). Per-process copies isolate them.
  *
  * The stateless X2APIC MSR gates (vec 50/51) also live in each copy; IDT[50/51] is
  * a single global entry (last-writer-wins across processes), but since the gates
  * are stateless and position-independent, whichever process's copy the IDT points
  * at runs correctly for everyone. The ONLY hazard is freeing a copy while its
  * kernel address is still live in some IDT gate. We avoid that by freeing ALL
  * per-open copies together only on the LAST close (g_open_count==0), so no gate
  * can point at an unmapped address while any process is still running.
  *
  * (Supersedes both the per-open-free design — which dangled IDT gates when one
  * process exited early — and the single-shared-mapping design — which raced the
  * timer-handler globals. This keeps per-process isolation AND defers all frees.)
  */
 /*
  * Max concurrent single-stepping processes. Must match SGX_STEP_MAX_INSTANCES in
  * libsgxstep/config.h (kernel module does not include that user header).
  */
 #ifndef SGX_STEP_MAX_INSTANCES
 #define SGX_STEP_MAX_INSTANCES 4
 #endif
 struct isr_map {
     struct page **pages;
     uint64_t nr_pages;
     void *kernel_vbase;
 };
 /*
  * Slot-based ISR-map table. A slot is FREE iff kernel_vbase==NULL. Each attacker
  * process (instance) gets its OWN pinned+vmapped copy so the timer handler's
  * rip-relative globals are isolated between concurrently single-stepping cores.
  *
  * LIFETIME: all maps are freed together ONLY on the last close (g_open_count==0)
  * -- never per-process. A process installs a GLOBAL IDT gate pointing at its map;
  * freeing that map while any process is still open (its APIC timer may still be
  * armed) would leave the gate dangling and a late IRQ would jump into unmapped
  * kernel memory -> hard lockup. The batch-barrier orchestrator bounds how many
  * maps coexist (<= batch size) and drains open_count to 0 between batches, so
  * the table never accumulates past the batch and is torn down cleanly each time.
  */
 static struct isr_map g_isr_maps[SGX_STEP_MAX_INSTANCES];
 static DEFINE_MUTEX(g_isr_map_lock);

 /*
  * Reference count of currently-open /dev/sgx-step handles. The IDT and APIC
  * are global hardware/CPU state shared across all callers, so we save them on
  * the FIRST open and restore them only on the LAST close. This prevents one
  * exiting process from restoring the IDT while other processes are still
  * single-stepping (which would crash them). Replaces the old binary g_in_use
  * exclusive-open flag.
  */
 static atomic_t g_open_count = ATOMIC_INIT(0);
 
 typedef struct {
     uint16_t size;
     uint64_t base;
 } __attribute__((packed)) idtr_t;
 static idtr_t g_idtr = {0};
 static void *g_idt_copy = NULL;
 
 static uint32_t g_apic_lvtt_copy = 0x0, g_apic_tdcr_copy = 0x0;
 
 /* ********************** UTIL FUNCTIONS ******************************* */
 
 /*
  * NOTE: Linux's default `write_cr0` does not allow to change protected bits,
  * so we include our own here.
  */
 inline void do_write_cr0(unsigned long val) {
     asm volatile("mov %0, %%cr0" : : "r"(val));
 }
 
 void enable_write_protection(void)
 {
     unsigned long cr0 = read_cr0();
     set_bit(16, &cr0);
     do_write_cr0(cr0);
 }
 
 void disable_write_protection(void)
 {
     unsigned long cr0 = read_cr0();
     clear_bit(16, &cr0);
     do_write_cr0(cr0);
 }
 
 /* ********************** DEVICE OPEN ******************************* */
 
 /*
  * Save original interrupt descriptor table register (IDTR) -- remains
  * unmodified by libsgxstep; addresses the single global IDT memory structure
  * setup by Linux at boot time and shared accross all CPUs.
  *
  * Copy original interrupt descriptor table (IDT) -- may be modified by
  * libsgxstep; will be auto restored when closing /dev/sgx-step.
  */
 int save_idt(void)
 {
     asm volatile ("sidt %0\n\t"
                   :"=m"(g_idtr) :: );
     log("original IDT: %#llx with size %u", g_idtr.base, g_idtr.size+1);
     RET_ASSERT(g_idtr.base);
 
     g_idt_copy = kmalloc(g_idtr.size+1, GFP_KERNEL);
     RET_ASSERT(g_idt_copy);
     memcpy(g_idt_copy, (void*)g_idtr.base, g_idtr.size+1);
 
     return 0;
 }
 
 /*
  * Save APIC timer configuration registers that may be modified by libsgxstep;
  * will be auto restored when closing /dev/sgx-step.
  */
 int save_apic(void)
 {
     g_apic_lvtt_copy = apic->read(APIC_LVTT);
     g_apic_tdcr_copy = apic->read(APIC_TDCR);
     log("original APIC_LVTT=%#x/TDCR=%#x)", g_apic_lvtt_copy, g_apic_tdcr_copy);
 
     return 0;
 }
 
 int step_open(struct inode *inode, struct file *file)
 {
     /*
      * Save global IDT/APIC state only on the first open. Subsequent opens
      * (other attacker processes) reuse the already-saved copy. Restore happens
      * on the last close (see step_release). The shared ISR mapping is set up
      * lazily on the first SETUP_ISR_MAP ioctl (see sgx_step_ioctl_setup_isr_map).
      */
     if (atomic_inc_return(&g_open_count) == 1)
     {
         if (save_idt() || save_apic())
         {
             atomic_dec(&g_open_count);
             err("failed to save IDT/APIC on first open");
             return -EIO;
         }
     }

     return 0;
 }
 
 /* ********************** DEVICE CLOSE ******************************* */
 
 /* Tear down one slot (caller holds g_isr_map_lock). */
 static void free_isr_slot(struct isr_map *m)
 {
     if (m->kernel_vbase) {
         vunmap(m->kernel_vbase);
         m->kernel_vbase = NULL;
     }
     if (m->pages) {
         unpin_user_pages(m->pages, m->nr_pages);
         kfree(m->pages);
         m->pages = NULL;
     }
     m->nr_pages = 0;
 }

 /*
  * Free ALL ISR map slots and unpin their user pages. Called ONLY on the last
  * close (g_open_count==0): once every process has gone, no IDT gate can still
  * point at any of these kernel addresses, so tearing them all down together is
  * safe. Freeing earlier (per-process) risks a dangling gate + armed timer while
  * a peer still runs -> hard lockup (see the isr_map lifetime note above).
  */
 void free_isr_map(void)
 {
     int i;

     mutex_lock(&g_isr_map_lock);
     for (i = 0; i < SGX_STEP_MAX_INSTANCES; i++)
         free_isr_slot(&g_isr_maps[i]);
     mutex_unlock(&g_isr_map_lock);
 }

 /*
  * Restore original IDT to ensure no user pointers are left. Called only on the
  * LAST close (global hardware state shared across all processes).
  *
  * NOTE: the IDT virtual memory page is mapped write-protected by Linux, so we
  * have to disable CR0.WP temporarily here.
  */
 void restore_idt(void)
 {
     disable_write_protection();
     memcpy((void*)g_idtr.base, g_idt_copy, g_idtr.size+1);
     enable_write_protection();
     log("restored IDT: %#llx with size %u", g_idtr.base, g_idtr.size+1);

     kfree(g_idt_copy);
     g_idt_copy = NULL;
 }
 
 void restore_apic(void)
 {
     int delta = 100;
 
     apic->write(APIC_LVTT, g_apic_lvtt_copy);
     apic->write(APIC_TDCR, g_apic_tdcr_copy);
     log("restored APIC_LVTT=%#x/TDCR=%#x)", g_apic_lvtt_copy, g_apic_tdcr_copy);
 
     /* In xAPIC mode the memory-mapped write to LVTT needs to be serialized. */
     asm volatile("mfence" : : : "memory");
 
     /* Re-arm the timer so Linux's original handler should take over again. */
     if (g_apic_lvtt_copy & APIC_LVT_TIMER_TSCDEADLINE)
     {
         log("restoring APIC timer tsc-deadline operation");
         wrmsrl(MSR_IA32_TSC_DEADLINE, rdtsc() + delta);
     }
     else
     {
         log("restoring APIC timer one-shot/periodic operation");
         apic->write(APIC_TMICT, delta);
     }
 }
 
 /*
  * Called when /dev/sgx-step is closed, also when the application that
  * originally opened it crashed. We take care to restore any IDT and APIC
  * modifications made by user-space libsgxstep here to their original values,
  * such that everything runs again normally and Linux does not panic.
  */
 int step_release(struct inode *inode, struct file *file)
 {
     /*
      * Restore global IDT/APIC and free ALL ISR maps only when the LAST handle
      * closes. Peers may still be single-stepping and need the modified IDT/APIC
      * + their kernel-mapped ISR gates intact. Freeing a map before then, while
      * its GLOBAL IDT gate is live and its APIC timer may still be armed, would
      * let a late IRQ jump into unmapped kernel memory -> hard lockup. The batch-
      * barrier orchestrator drains open_count to 0 between batches, so this runs
      * per batch and the table never accumulates past one batch.
      */
     if (atomic_dec_return(&g_open_count) == 0)
     {
         restore_idt();
         restore_apic();
         free_isr_map();
     }

     return 0;
 }
 
 #include <asm/msr.h>
 #include <asm/mtrr.h>
 
 /* ********************** IOCTL FUNCTIONS ******************************* */
 // MSR register addresses for MTRRs
 #define MSR_MTRRcap              0xFE
 #define MSR_MTRRdefType          0x2FF
 #define MSR_MTRRphysBase0        0x200  // Base address for MTRRphysBase
 #define MSR_MTRRphysMask0        0x201  // Base address for MTRRphysMask
 
 // MTRR type definitions
 #define MTRR_TYPE_UC             0x00   // Uncacheable type
 #define MTRR_TYPE_WC             0x01   // Write-Combining type
 #define MTRR_TYPE_WT             0x04   // Writethrough type
 #define MTRR_TYPE_WP             0x05   // Write-Protect type
 #define MTRR_TYPE_WB             0x06   // Writeback type
 
 // Address alignment and mask definitions
 #define PAGE_SHIFT               12     // Shift for 4 KB page alignment
 #define PAGE_SIZE                (1UL << PAGE_SHIFT)   // 4 KB page size
 #define MTRR_VALID               (1UL << 11)  // Valid bit in mask register
 #define ADDRESS_WIDTH            52     // Assume 52-bit address width
 
 // PFN to physical address conversion (macro for demonstration)
 #define PFN_PHYS(pfn)            ((pfn) << PAGE_SHIFT)
 
 // Sample macros for MTRR configuration
 #define MTRR_BASE(base, type)    ((base) | (type))  // Set base address and type
 #define MTRR_MASK(size)          (~((size) - 1) | MTRR_VALID)  // Valid bit set
 /* Convenience function when editing PTEs from user space (but normally not
  * needed, since SGX already flushes the TLB on enclave entry/exit) */
  
 long sgx_step_ioctl_invpg(struct file *filep, unsigned int cmd, unsigned long arg)
 {
     uint64_t addr = ((invpg_t *) arg)->adrs;
 
     asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
     asm volatile ("wbinvd" ::: "memory");
 
     return 0;
 }
 
 long sgx_step_get_pt_mapping(struct file *filep, unsigned int cmd, unsigned long arg)
 {
     address_mapping_t *map = (address_mapping_t*) arg;
     pgd_t *pgd = NULL;
     pud_t *pud = NULL;
     pmd_t *pmd = NULL;
     pte_t *pte = NULL;
     #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
         p4d_t *p4d = NULL;
     #endif
 
     uint64_t virt;
     RET_ASSERT(map);
     
     virt = map->virt;
     memset( map, 0x00, sizeof( address_mapping_t ) );
     map->virt = virt;
     
     map->pgd_phys_address = __pa( current->mm->pgd );
     pgd = pgd_offset( current->mm, virt );
     map->pgd = *((uint64_t *) pgd);
     
     if ( !pgd_present( *pgd ) )
         return 0;
 
     #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
         #if CONFIG_PGTABLE_LEVELS > 4
             #warning 5-level page tables currently not supported by SGX-Step
             #warning unfolding dummy p4d; try rebooting with `no5lvl` kernel parameter if needed
         #endif
 
         /* simply unfold the pgd inside the dummy p4d struct */
         p4d = p4d_offset( pgd, virt);
         pud = pud_offset( p4d, virt );
     #else
         pud = pud_offset( pgd, virt );
     #endif
 
     map->pud = *((uint64_t *) pud);
     
     if ( !pud_present( *pud ) )
         return 0;
     
     pmd = pmd_offset( pud, virt );
     map->pmd = *((uint64_t *) pmd);
     
     if ( !pmd_present( *pmd ) )
         return 0;
     
     pte = pte_offset_kernel( pmd, virt );
     map->pte = *((uint64_t *) pte);
     
     if ( !pte_present( *pte ) )
         return 0;
     
     map->phys = PFN_PHYS( pte_pfn( *pte ) ) | ( virt & 0xfff );
 
     return 0;
 }
 
 long sgx_step_ioctl_setup_isr_map(struct file *filep, unsigned int cmd, unsigned long arg)
 {
     uint64_t nr_pinned_pages, nr_pages;
     setup_isr_map_t *data = (setup_isr_map_t*) arg;
     struct page **pages = NULL;
     void *kernel_vbase = NULL;
     long ret = -EINVAL;
     int slot;

     mutex_lock(&g_isr_map_lock);

     /*
      * Design B: give THIS caller its OWN pinned+vmapped copy of the ISR region
      * (per-process, so the timer handler's rip-relative globals — __ss_irq_fired
      * handshake, count, reg save slots — are isolated between concurrently
      * single-stepping processes). Each process's isr_section is identical in
      * layout but lives at a distinct user vaddr; it computes its own kernel-map
      * offset from the returned isr_kernel_base. Slot-finding avoids clobbering a
      * concurrent peer's slot; all slots are freed together on the last close
      * (free_isr_map) -- see the isr_map lifetime note near the struct definition.
      */
     for (slot = 0; slot < SGX_STEP_MAX_INSTANCES; slot++)
         if (!g_isr_maps[slot].kernel_vbase)
             break;
     if (slot == SGX_STEP_MAX_INSTANCES) {
         ret = -EBUSY;
         err("ISR map table full (max %d concurrent instances)", SGX_STEP_MAX_INSTANCES);
         goto out;
     }

     /* allocate space to hold Linux `struct page` pointers */
     nr_pages = (data->isr_stop - data->isr_start + PAGE_SIZE - 1) / PAGE_SIZE;
     pages = kmalloc(nr_pages * sizeof(struct page *), GFP_KERNEL);
     GOTO_ASSERT(pages, "cannot allocate memory", out);

     /* pin user physical memory so it cannot be swapped out by the kernel */
     nr_pinned_pages = pin_user_pages_fast(data->isr_start & ~(PAGE_SIZE - 1),
                         nr_pages, FOLL_LONGTERM | FOLL_WRITE, pages);
     GOTO_ASSERT(nr_pinned_pages == nr_pages, "cannot pin all ISR pages", cleanup_pages);

     /* map pinned physical memory into the kernel virtual address range */
     kernel_vbase = vmap(pages, nr_pages,
                             VM_READ | VM_EXEC | VM_SHARED, PAGE_SHARED_EXEC);
     GOTO_ASSERT(kernel_vbase, "cannot vmap ISR pages", cleanup_pin);

     /* commit this per-open mapping into the free slot */
     g_isr_maps[slot].pages = pages;
     g_isr_maps[slot].nr_pages = nr_pages;
     g_isr_maps[slot].kernel_vbase = kernel_vbase;

     data->isr_kernel_base = (uint64_t) kernel_vbase;
     log("mapped %lld pinned user ISR pages to kernel vaddr %#llx (slot %d/%d)",
             nr_pages, data->isr_kernel_base, slot, SGX_STEP_MAX_INSTANCES);
     mutex_unlock(&g_isr_map_lock);
     return 0;

 cleanup_pin:
     unpin_user_pages(pages, nr_pages);

 cleanup_pages:
     kfree(pages);

 out:
     mutex_unlock(&g_isr_map_lock);
     return ret;
 }
 
 typedef long (*ioctl_t)(struct file *filep, unsigned int cmd, unsigned long arg);
 
 long step_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 {
     char data[256];
     ioctl_t handler = NULL;
     long ret;
 
     switch (cmd)
     {
         case SGX_STEP_IOCTL_GET_PT_MAPPING:
             handler = sgx_step_get_pt_mapping;
             break;
         case SGX_STEP_IOCTL_INVPG:
             handler = sgx_step_ioctl_invpg;
             break;
         case SGX_STEP_IOCTL_SETUP_ISR_MAP:
             handler = sgx_step_ioctl_setup_isr_map;
             break;
         default:
             return -EINVAL;
     }
 
     RET_ASSERT(handler && (_IOC_SIZE(cmd) < 256));
     if (copy_from_user(data, (void __user *) arg, _IOC_SIZE(cmd)))
         return -EFAULT;
 
     ret = handler(filep, cmd, (unsigned long) ((void *) data));
 
     if (!ret && (cmd & IOC_OUT)) {
         if (copy_to_user((void __user *) arg, data, _IOC_SIZE(cmd)))
             return -EFAULT;
     }
 
     return ret;
 }
 
 /* ********************** FILE OPERATIONS ******************************* */
 
 static const struct file_operations step_fops = {
     .owner              = THIS_MODULE,
     .compat_ioctl       = step_ioctl,
     .unlocked_ioctl     = step_ioctl,
     .open               = step_open,
     .release            = step_release
 };
 
 static struct miscdevice step_dev = {
     .minor  = MISC_DYNAMIC_MINOR,
     .name   = DEV,
     .fops   = &step_fops,
     .mode   = S_IRUGO | S_IWUGO
 };
 
 /* Code from: <https://www.libcrack.so/index.php/2012/09/02/bypassing-devmem_is_allowed-with-kprobes/> */
 static int devmem_is_allowed_handler (struct kretprobe_instance *rp, struct pt_regs *regs)
 {
     if (regs->ax == 0) {
         regs->ax = 0x1;
     }
     return 0;
 }
 
 static struct kretprobe krp = {
     .handler = devmem_is_allowed_handler,
     .maxactive = 20 /* Probe up to 20 instances concurrently. */
 };
 
 int init_module(void)
 {
     /* Register virtual device */
     if (misc_register(&step_dev))
     {
         err("virtual device registration failed..");
         step_dev.this_device = NULL;
         return -EINVAL;
     }
 
     /* Activate a kretprobe to bypass CONFIG_STRICT_DEVMEM kernel compilation option */
     krp.kp.symbol_name = "devmem_is_allowed";
     if (register_kretprobe(&krp) < 0)
     {
         err("register_kprobe failed..");
         step_dev.this_device = NULL;
         return -EINVAL;
     }
 
     log("listening on /dev/" DEV);
     return 0;
 }
 
 void cleanup_module(void)
 {   
     /* Unregister virtual device */
     if (step_dev.this_device)
         misc_deregister(&step_dev);
 
     unregister_kretprobe(&krp);
     log("kernel module unloaded");
 }
 