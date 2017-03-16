#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "mbox.h"
#include "debug.h"

#ifdef DEBUG_MBOX

#undef DUMMY_FLASH_FILE

int init_mbox_dev(struct mbox_context *context)
{
	int fd, rc;
	uint8_t buf[16] = { 0 };

	fd = open("mbox_dummy_regs", O_RDWR | O_CREAT,
		  S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd < 0) {
		MSG_DEBUG("Failed to open dummy regs file: %s\n",
			  strerror(errno));
		return -errno;
	}

	rc = write(fd, buf, 16);
	if (rc != 16) {
		MSG_DEBUG("Failed to write to dummy regs file: %s\n",
			  strerror(errno));
		return -errno;
	}

	rc = lseek(fd, 0, SEEK_SET);
	if (rc) {
		MSG_DEBUG("Failed to seek dummy regs file: %s\n",
			  strerror(errno));
		return -errno;
	}

	context->fds[MBOX_FD].fd = fd;
	return 0;
}

int init_lpc_dev(struct mbox_context *context)
{
	int rc, fd;

	fd = open("mbox_dummy_mem", O_RDWR | O_CREAT,
		  S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd < 0) {
		MSG_DEBUG("Failed to open dummy mem file: %s\n",
			  strerror(errno));
		return -errno;
	}

	rc = fallocate(fd, 0, 0, context->flash_size);
	if (rc) {
		MSG_DEBUG("Failed to allocate space for dummy mem file: %s\n",
			  strerror(errno));
		return -errno;
	}

	context->mem = mmap(NULL, context->flash_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, 0);
	if (context->mem == MAP_FAILED) {
		MSG_DEBUG("Failed to mmap dummy mem file: %s\n",
			  strerror(errno));
		return -errno;
	}

	memset(context->mem, 0, context->flash_size);

	context->mem_size = context->flash_size;
	context->lpc_base = 0x0FFFFFFF & -context->mem_size;
	
	context->fds[LPC_CTRL_FD].fd = fd; /* At least it'll get freed */
	return 0;
}

int init_flash_dev(struct mbox_context *context)
{
	int fd, rc;
#ifndef DUMMY_FLASH_FILE
	uint8_t *buf = calloc(context->flash_size, sizeof(*buf));
	memset(buf, 0xFF, context->flash_size);

	fd = open("mbox_dummy_flash", O_RDWR | O_CREAT,
		  S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#else
	fd = open(DUMMY_FLASH_FILE, O_RDWR);
#endif /* DUMMY_FLASH_FILE */
	if (fd < 0) {
		MSG_DEBUG("Failed to open dummy flash file: %s\n",
			  strerror(errno));
#ifndef DUMMY_FLASH_FILE
		free(buf);
#endif /* DUMMY_FLASH_FILE */
		return -errno;
	}

#ifndef DUMMY_FLASH_FILE
	rc = write(fd, buf, context->flash_size);
	free(buf);
	if (rc != context->flash_size) {
		MSG_DEBUG("Failed to write to dummy flash file: %s\n",
			  strerror(errno));
		return -errno;
	}

	rc = lseek(fd, 0, SEEK_SET);
	if (rc) {
		MSG_DEBUG("Failed to seek dummy flash file: %s\n",
			  strerror(errno));
		return -errno;
	}
#endif /* DUMMY_FLASH_FILE */

	context->fds[MTD_FD].fd = fd;
	return 0;
}

#endif /* DEBUG_MBOX */
