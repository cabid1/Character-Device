#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>

//adding hardcoded file got this from hello.c(part 1 example): https://github.com/libfuse/libfuse/blob/master/example/hello.c
static struct options {
	const char *filename;
	const char *contents;
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--name=%s", filename),
	OPTION("--contents=%s", contents),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};
// Define constants for filesystem parameters
#define BLOCK_SIZE 512            // Block size is 512 bytes
#define MAX_FILENAME_LEN 11       // Max length for filenames 
#define DIRECTORY_ENTRY_SIZE 32   // Each directory entry is 32 bytes
#define END_CHAIN 0xFFFF 
#define FREE_BLOCK 0x0000 

// Superblock structure copy from mkmemfs.c 
typedef struct memefs_superblock
{
    char signature[16];        // Filesystem signature
    uint8_t cleanly_unmounted; // Flag for unmounted state
    uint8_t reseerved1[3];     // Reserved bytes
    uint32_t fs_version;       // Filesystem version
    uint8_t fs_ctime[8];       // Creation timestamp in BCD format
    uint16_t main_fat;         // Starting block for main FAT
    uint16_t main_fat_size;    // Size of the main FAT
    uint16_t backup_fat;       // Starting block for backup FAT
    uint16_t backup_fat_size;  // Size of the backup FAT
    uint16_t directory_start;  // Starting block for directory
    uint16_t directory_size;   // Directory size in blocks
    uint16_t num_user_blocks;  // Number of user data blocks
    uint16_t first_user_block; // First user data block
    char volume_label[16];     // Volume label
    uint8_t unused[448];       // Unused space for alignment
} __attribute__((packed)) memefs_superblock_t;

// Directory structure (updated to follow the doc more closely)
typedef struct{
    uint16_t typeAndPerm;
    uint16_t location;
    char filename[11];
    uint8_t unused;
    uint64_t timestamp;
    uint32_t filesize;
    uint16_t userId;
    uint16_t groupId;       
} memefs_directory_entry_t;

const char *image_path;
int image_fd;
memefs_superblock_t superblock;
uint16_t fat[BLOCK_SIZE];
uint16_t backFat[BLOCK_SIZE];

// read a block from the filesystem image already included in sources provided but used documentaion from:https://libfuse.github.io/doxygen/structfuse__operations.html#a272960bfd96a0100cbadc4e5a8886038
static int read_block(off_t block_num, void *block_buf) {
    int debug = (int)block_num;
    printf("Reading blocksssssss %d\n", debug);
//Find next data or hole after the specified offset
    if(lseek(image_fd, block_num * BLOCK_SIZE, SEEK_SET)  == -1 ){
	    perror("lseek");
	    return -1;
    }
//Read data from an open file
    if(read(image_fd, block_buf, BLOCK_SIZE) == BLOCK_SIZE ){
        return 0;
    }else{
	perror("read");
        return -1;
    }
}

// Load the filesystem image
// sources so i font lose them: https://pubs.opengroup.org/onlinepubs/7908799/xsh/open.html
//https://linux.die.net/man/3/ntohs
void load_filesystem_image(const char *path) {
    //int i;
    // Open the filesystem image
    image_fd = open(path, O_RDONLY);
    if (image_fd < 0) {
        perror("open");
        exit(1);
    }

    // Read the superblock
    if (read_block(0, &superblock) != 0) {
        fprintf(stderr, "Failed superblock\n");
        exit(1);
    }

   //debug
   if (strncmp(superblock.signature, "?MEMEFS++CMSC421", 16) != 0) {
       fprintf(stderr, "Invalid filesystem signature\n");
       exit(1);
   }

   // Read the FAT
   // fat = malloc(BLOCK_SIZE);//almost changed this but one block of fat so i think its right(i hope)
    if (read_block(ntohs(superblock.main_fat), fat) != 0) {
	//free(fat);
        fprintf(stderr, "Failed FAT\n");
        exit(1);
    }

    // Read the Backup FAT
    //backFat = malloc(BLOCK_SIZE);//should prob account for this too
    if (read_block(ntohs(superblock.backup_fat), backFat) != 0) {
	//free(fat);
	//free(backFat);
        fprintf(stderr, "Failed Backup FAT\n");
        exit(1);
    }


//For every open() call there will be exactly one release() call with the same flags and file handle.
 //close(image_fd);
}

//changed the traverse 
//added hardcoded file:https://github.com/libfuse/libfuse/blob/master/example/hello.c
int memefs_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
        uint16_t curr_block = ntohs(superblock.directory_start);
        char block_data[BLOCK_SIZE];
	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0644;
		stbuf->st_nlink = 2;
		return 0;
	}
	if(strcmp(path+1, options.filename) == 0) {
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(options.contents);
		return 0;
	}
	while(curr_block != END_CHAIN){
	    read_block(curr_block,block_data);
	    memefs_directory_entry_t *file_data = (memefs_directory_entry_t *)block_data;
	    for (size_t i = 0; i < BLOCK_SIZE / sizeof(memefs_directory_entry_t); i++) {
		if (strcmp(path+1, file_data[i].filename) == 0) {
			// oooooooh i was doing this wroooonnngggg https://pubs.opengroup.org/onlinepubs/7908799/xsh/sysstat.h.html
		    stbuf->st_mode = file_data[i].typeAndPerm;
		    stbuf->st_size = ntohl(file_data[i].filesize);
		    stbuf->st_uid = file_data[i].userId;
		    stbuf->st_gid = file_data[i].groupId;
		    stbuf->st_mtime = ntohl(file_data[i].timestamp);
		return 0;
             }
            }

        // Follow the FAT chain to the next block
            curr_block = ntohs(fat[curr_block]);
    }

	return -ENOENT;
}

//changed the traverse
//hardcoded file:https://github.com/libfuse/libfuse/blob/master/example/hello.c
int memefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	uint16_t curr_block = ntohs(superblock.directory_start);
        char block_data[BLOCK_SIZE];
	
	//from hello.c file i dont see why they would change 
        if (strcmp(path, "/") != 0){
		return -ENOENT;
	}
	if (strcmp(path, "/") == 0) {
	   filler(buf, ".", NULL, 0, 0);
           filler(buf, "..", NULL, 0, 0);
	   filler(buf, options.filename, NULL, 0, 0);
	}
	
	
	//lets trav thro FAT instead 
	while(curr_block != END_CHAIN){
	    if (read_block(curr_block,block_data) != 0){
	        fprintf(stderr, "Failed to read directory block\n");
                return -EIO;
	    }
	    memefs_directory_entry_t *file_data = (memefs_directory_entry_t *)block_data;
	    for (size_t i = 0; i < BLOCK_SIZE / sizeof(memefs_directory_entry_t); i++) {
		if (file_data[i].unused != FREE_BLOCK) { 
		    filler(buf, file_data[i].filename, NULL, 0, 0);
                }
            }

        // Follow the FAT chain to the next block
            curr_block = ntohs(fat[curr_block]);
    }

	return 0;
}

//changed the traverse
//https://github.com/libfuse/libfuse/blob/master/example/hello.c
int memefs_open(const char *path, struct fuse_file_info *fi) {
   if (strcmp(path+1, options.filename) == 0) {
       return 0;
    }
    uint16_t curr_block = ntohs(superblock.directory_start);
    char block_data[BLOCK_SIZE];
    //lets trav thro FAT instead 
    while(curr_block != END_CHAIN){
	read_block(curr_block,block_data);
	memefs_directory_entry_t *file_data = (memefs_directory_entry_t *)block_data;
	for (size_t i = 0; i < BLOCK_SIZE / sizeof(memefs_directory_entry_t); i++) {
	   if (strcmp(file_data[i].filename, path + 1) == 0) {  // Match filename
             return 0;
           }
        }

        // Follow the FAT chain to the next block
            curr_block = ntohs(fat[curr_block]);
    }
    
    if ((fi->flags & O_ACCMODE) != O_RDONLY){
	    return -EACCES;
    }
    // No file found
    return -ENOENT;

}


//https://github.com/libfuse/libfuse/blob/master/example/hello.c
int memefs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
    if(strcmp(path+1, options.filename) == 0) {
	size_t len = strlen(options.contents);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, options.contents + offset, size);
	} else
		size = 0;

	return size;

    }
    size_t bytes_to_read = size;
    size_t bytes_read = 0;
    char block_data[BLOCK_SIZE];
    uint16_t curr_block = ntohs(superblock.directory_start);
    //lets trav thro FAT instead 
    while(curr_block != END_CHAIN){
	read_block(curr_block,block_data);
	memefs_directory_entry_t *file_data = (memefs_directory_entry_t *)block_data;
	for (size_t i = 0; i < BLOCK_SIZE / sizeof(memefs_directory_entry_t); i++) {
	   if (strcmp(file_data[i].filename, path + 1) == 0) {  // match filename
		if (offset + size > ntohl(file_data[i].filesize)) {//adjust the offset
		   bytes_to_read = ntohl(file_data[i].filesize) - offset;
		}
           }
	   //find the starting block by traversing the FAT for the offset
	   curr_block = ntohs(file_data[i].location);//location of the first block of the file
           size_t block_offset = offset / BLOCK_SIZE;//given the offset how many blocks into the chain do we need to trav to get to the off
           size_t offset_in_block = offset % BLOCK_SIZE;//once we are in the right block how many bytes do we need to go till we are at the off
           while (block_offset > 0 && curr_block != END_CHAIN) {
		curr_block = fat[curr_block];
		block_offset--;
    
	   }
	   // read the file's data
	   while (bytes_to_read > 0 && curr_block != END_CHAIN) {
		read_block(curr_block, block_data);
		// how much to read from the current block 
		size_t bytes_from_block = BLOCK_SIZE - offset_in_block;
		if (bytes_from_block > bytes_to_read) {
		    bytes_from_block = bytes_to_read;
		}
		// copy data from the block to the buffer
		memcpy(buf + bytes_read, block_data + offset_in_block, bytes_from_block);
		// update counters and move to the next block
		bytes_read += bytes_from_block;//whats read
		bytes_to_read -= bytes_from_block;//whats left
		offset_in_block = 0; // set to zero to ensure the offset only the first time it comes in the loop
		curr_block = fat[curr_block];//next block
	   }
	   return bytes_read; // Return the number of bytes read
        }
	     // Follow the FAT chain to the next block
            curr_block = ntohs(fat[curr_block]);
    }
      return -ENOENT; // File not found  
}


struct fuse_operations memefs_oper = {
    .getattr = memefs_getattr,    
    .readdir = memefs_readdir,    
    .open    = memefs_open,       
    .read    = memefs_read
};

//https://github.com/libfuse/libfuse/blob/master/example/hello.c
int main(int argc, char *argv[])
{
        if (argc<3) {
	    fprintf(stderr," input as <image_file> <mount_point> \n");
	    exit(1);
	}
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.filename = strdup("hello.txt");
	options.contents = strdup("Hello World!\n");

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;
	int ret;
	image_path = argv[1];
	load_filesystem_image(image_path);
	ret = fuse_main(argc-1, argv+1, &memefs_oper, NULL);
	close(image_fd);
	return ret;
}
