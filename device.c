#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>


#define DEVICE_NAME "chardevice"

//reading in param: https://tldp.org/LDP/lkmpg/2.6/html/x323.html
static char *file = NULL;
//gonna be using this a lot wanna make sure it gets cited: https://sysprog21.github.io/lkmpg/#registering-a-device
static int major;
static struct class *cls;
module_param(file, charp, 0644);//perm did have to change :(
static char *file_contents = NULL;//gonna store whats in the file here
static size_t file_size = 0;//need to know how much to kmalloc


//this needs to work without fuse first so this mod needs to:
// open and read files then add to char device

// function to open and read the file contents:
//filp_open, file_size, and kernel_read functions found: https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/fs/kernel_read_file.c
//filp_close: https://elixir.bootlin.com/linux/v4.2/source/include/linux/fs.h#L2227
//this website is already cited above im gonna put this here anyway: https://elixir.bootlin.com/linux/v4.7/source/include/linux/err.h#L33
static int read_file(void)
{
    struct file *fd;
    loff_t pos = 0;
    ssize_t bytes_read;
    //open file path
    fd = filp_open(file, O_RDONLY, 0);
    if (IS_ERR(fd)) {
       	if (PTR_ERR(fd) == -ENOENT) {
           	pr_err("File does not exist\n");
       	} else {
           	pr_err("Error opening file: %ld\n", PTR_ERR(fd));
       	}
   	return PTR_ERR(fd);
    	}
    
    //get size and kmalloc
    file_size = i_size_read(file_inode(fd));
    file_contents = kmalloc(file_size + 1, GFP_KERNEL);// +1 for null
    	//read the bytes
    bytes_read = kernel_read(fd, file_contents, file_size, &pos);
    if (bytes_read < 0) {
   		pr_err("Failed to read file: %zd\n", bytes_read);
   		kfree(file_contents);
   		filp_close(fd, NULL);
   		return bytes_read;
    }

    file_contents[bytes_read] = '\0'; // null term
    	//check IT WORKED
    //printk("Read file contents: %s\n", file_contents);

    filp_close(fd, NULL);
    return 0;
}


// when cat character device : https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html
static ssize_t dev_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    
    //check where in the file
    size_t len = file_size - *offset;

    if (len == 0){//theres nothing left
   	return 0;
    }
   	 //"out of bounds check"
    if (count > len){
   	count = len; // read up to the file length
    }
    //this puts into char device but doesnt follow example output so commented out
    /*
    	//put into the dev
    if (copy_to_user(buf, file_contents + *offset, count)){
   	pr_err("copy to user failed\n");
   	return -EFAULT;
    }
    */
    //output to dmesg
    if (file_contents == NULL){//it helps if you treat it like theres nothing left cause there never was anything
   	printk("no file exists\n");
   	return 0;
    }else {
   	printk("Read file contents: %s\n", file_contents);
    }
    
    
    //update if more Reads
    *offset = *offset + count;
    return count;
}


static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = dev_read
};

// initialization function: https://sysprog21.github.io/lkmpg/#registering-a-device
static int __init memefs_init(void)
{
    int readF;
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
   		pr_err("Registering char device failed with %d\n", major);
   		return -1;
    }
    //IT WORKS
    //printk("major number %d.\n", major);

    cls = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
 
	//check path has been read in
    if (file == NULL){
    	pr_err("Error: please provide a file param\n");
    	return -EINVAL;  
    }
    //read the file have to let insmod even if no file exists
    readF = read_file();
    if (readF != 0) {
    	pr_err("Error: unable to read the file check file exists\n");
   	 
    }
    //alert the user everthing has been set up
    printk(KERN_INFO "Kernel module loaded.\n");

    //debug IT WORKED
    //printk(KERN_INFO "mystring is a string: %s\n", file);
    return 0;
}
// cleanup function: https://sysprog21.github.io/lkmpg/#registering-a-device
static void __exit memefs_exit(void)
{
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, DEVICE_NAME);
    if (file_contents != NULL){
   	kfree(file_contents);
    }
    
    printk(KERN_INFO "Goodbye Cruel World ahhhhh! Kernel module unloaded.\n");
}

module_init(memefs_init);
module_exit(memefs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("kernel module to read a file and DMESG it via a character device");


