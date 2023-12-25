#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"

static void syscall_handler (struct intr_frame *);
void get_stack_arguments (struct intr_frame *f, int * args, int num_of_args);

//Cau truc de chen cac files va fd vao luong hien tai
struct thread_file
{
    struct list_elem file_elem;
    struct file *file_addr;
    int file_descriptor;
};

//chi cho phep 1 tien trinh truy cap he thong tep
struct lock lock_filesys;

void
syscall_init (void)
{
  //khoi tao khoa cho he thong tep
  lock_init(&lock_filesys);
  //goi den ham syscall_handler bang ngat 0x30
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
    check_valid_addr((const void *) f->esp);
    
    //luu tru cac doi so truyen vao
    int args[3];

    //luu tru con tro trang vat ly
    void * phys_page_ptr;
    
		switch(*(int *) f->esp)
		{
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
        		get_stack_arguments(f, &args[0], 1);
			exit(args[0]);
			break;

		case SYS_EXEC:
			get_stack_arguments(f, &args[0], 1);
        		phys_page_ptr = (void *) pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        		if (phys_page_ptr == NULL)
          			exit(-1);      
        		args[0] = (int) phys_page_ptr;
			f->eax = exec((const char *) args[0]);
			break;

		case SYS_WAIT:
			get_stack_arguments(f, &args[0], 1);
			f->eax = wait((pid_t) args[0]);
			break;

		case SYS_CREATE:
			get_stack_arguments(f, &args[0], 2);
        		check_buffer((void *)args[0], args[1]);
       		phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        		if (phys_page_ptr == NULL)    
          			exit(-1);
        		args[0] = (int) phys_page_ptr;      
        		f->eax = create((const char *) args[0], (unsigned) args[1]);
			break;

		case SYS_REMOVE:
        		get_stack_arguments(f, &args[0], 1);     
        		phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        		if (phys_page_ptr == NULL)
          			exit(-1);
        		args[0] = (int) phys_page_ptr;    
        		f->eax = remove((const char *) args[0]);
			break;

		case SYS_OPEN:
        		get_stack_arguments(f, &args[0], 1);
        		phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        		if (phys_page_ptr == NULL)
          			exit(-1);
        		args[0] = (int) phys_page_ptr;    
        		f->eax = open((const char *) args[0]);
			break;

		case SYS_FILESIZE:
        		get_stack_arguments(f, &args[0], 1);
        		f->eax = filesize(args[0]);
			break;

		case SYS_READ:
        		get_stack_arguments(f, &args[0], 3);      
        		check_buffer((void *)args[1], args[2]);       
        		phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        		if (phys_page_ptr == NULL)   
          			exit(-1);
        		args[1] = (int) phys_page_ptr;       
        		f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
			break;

		case SYS_WRITE:
        		get_stack_arguments(f, &args[0], 3);      
        		check_buffer((void *)args[1], args[2]);       
        		phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        		if (phys_page_ptr == NULL)
          			exit(-1);
        		args[1] = (int) phys_page_ptr;
        		f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
        		break;

		case SYS_SEEK:
        		get_stack_arguments(f, &args[0], 2);
        		seek(args[0], (unsigned) args[1]);
        		break;

		case SYS_TELL:
        		get_stack_arguments(f, &args[0], 1);
        		f->eax = tell(args[0]);
        		break;

		case SYS_CLOSE:
        		get_stack_arguments(f, &args[0], 1);
        		close(args[0]);
			break;

		default:
			exit(-1);
			break;
		}
}

void halt (void)
{
	shutdown_power_off();
}

void exit (int status)
{
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
  	thread_exit ();
}

int write (int fd, const void *buffer, unsigned length)
{

  	struct list_elem *temp;
  	lock_acquire(&lock_filesys);
	if(fd == 1)
	{
		putbuf(buffer, length);//xuat du lieu tu bo dem ra console
    		lock_release(&lock_filesys);
    		return length;
	}

  	if (fd == 0 || list_empty(&thread_current()->file_descriptors))
  	{
    		lock_release(&lock_filesys);
    		return 0;
  	}


  	for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  	{
      		struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      		if (t->file_descriptor == fd)
      		{
        		int bytes_written = (int) file_write(t->file_addr, buffer, length);
        		lock_release(&lock_filesys);
        		return bytes_written;
      		}
  	}

  	lock_release(&lock_filesys);
  	return 0;
}

pid_t exec (const char * file)
{
	if(!file)
		return -1;
  	lock_acquire(&lock_filesys);
	pid_t child_tid = process_execute(file);
  	lock_release(&lock_filesys);
	return child_tid;
}

int wait (pid_t pid)
{
  	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
  	lock_acquire(&lock_filesys);
  	bool file_status = filesys_create(file, initial_size);
  	lock_release(&lock_filesys);
  	return file_status;
}

bool remove (const char *file)
{
  	lock_acquire(&lock_filesys);
  	bool was_removed = filesys_remove(file);
  	lock_release(&lock_filesys);
  	return was_removed;
}

int open (const char *file)
{
  	lock_acquire(&lock_filesys);
  	struct file* f = filesys_open(file);
  	if(f == NULL)
  	{
    		lock_release(&lock_filesys);
    		return -1;
  	}

  	struct thread_file *new_file = malloc(sizeof(struct thread_file));
  	new_file->file_addr = f;
  	int fd = thread_current ()->cur_fd;
  	thread_current ()->cur_fd++;
  	new_file->file_descriptor = fd;
  	list_push_front(&thread_current ()->file_descriptors, &new_file->file_elem);
  	lock_release(&lock_filesys);
  	return fd;
}

int filesize (int fd)
{
  	struct list_elem *temp;
  	lock_acquire(&lock_filesys);
  	if (list_empty(&thread_current()->file_descriptors))
  	{
    		lock_release(&lock_filesys);
    		return -1;
  	}

  	for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  	{
      		struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      		if (t->file_descriptor == fd)
      		{
        		lock_release(&lock_filesys);
        		return (int) file_length(t->file_addr);
      		}
  	}

  	lock_release(&lock_filesys);
  	return -1;
}

int read (int fd, void *buffer, unsigned length)
{
  	struct list_elem *temp;
  	lock_acquire(&lock_filesys);
  	if (fd == 0)
  	{
  		lock_release(&lock_filesys);
    		return (int) input_getc();
  	}

  	if (fd == 1 || list_empty(&thread_current()->file_descriptors))
  	{
  		lock_release(&lock_filesys);
    		return 0;
  	}

  	for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  	{
      		struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      		if (t->file_descriptor == fd)
      		{
        		lock_release(&lock_filesys);
        		int bytes = (int) file_read(t->file_addr, buffer, length);
        		return bytes;
      		}
  	}

  	lock_release(&lock_filesys);
  	return -1;
}

void seek (int fd, unsigned position)
{
  	struct list_elem *temp;
  	lock_acquire(&lock_filesys);
  	if (list_empty(&thread_current()->file_descriptors))
  	{
    		lock_release(&lock_filesys);
    		return;
  	}

  	for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  	{
      		struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      		if (t->file_descriptor == fd)
      		{
        		file_seek(t->file_addr, position);
        		lock_release(&lock_filesys);
        		return;
      		}
  	}

  	lock_release(&lock_filesys);
  	return;
}

unsigned tell (int fd)
{
  	struct list_elem *temp;
  	lock_acquire(&lock_filesys);
  	if (list_empty(&thread_current()->file_descriptors))
  	{
    		lock_release(&lock_filesys);
    		return -1;
  	}

  	for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  	{
      		struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      		if (t->file_descriptor == fd)
      		{
        		unsigned position = (unsigned) file_tell(t->file_addr);
        		lock_release(&lock_filesys);
        		return position;
      		}
  	}
  	
  	lock_release(&lock_filesys);
  	return -1;
}

void close (int fd)
{
  	struct list_elem *temp;
  	lock_acquire(&lock_filesys);

  	if (list_empty(&thread_current()->file_descriptors))
  	{
    		lock_release(&lock_filesys);
    		return;
  	}

  	for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  	{
      		struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      		if (t->file_descriptor == fd)
      		{
       	 	file_close(t->file_addr);
        		list_remove(&t->file_elem);
        		lock_release(&lock_filesys);
        		return;
      		}
  	}

  	lock_release(&lock_filesys);
  	return;
}
//kiem tra tinh hop le cua con tro
void check_valid_addr (const void *ptr_check)
{
  if(!is_user_vaddr(ptr_check) || ptr_check == NULL)
    {
      exit(-1);
    }
}

//kiem tra tinh hop le cua mot doan ngan xep
void check_buffer (void *buff_check, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buff_check;
  for (i = 0; i < size; i++)
    {
      check_valid_addr((const void *) ptr);
      ptr++;
    }
}
//luu cac doi so truyen vao
void get_stack_arguments (struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_valid_addr((const void *) ptr);
      args[i] = *ptr;
    }
}
