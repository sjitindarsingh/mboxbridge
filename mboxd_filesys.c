/*
 * Mailbox Daemon Flash Helpers
 *
 * Copyright 2016 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
#include <mtd/mtd-abi.h>

#include "mbox.h"
#include "common.h"
#include "mboxd_filesys.h"

/* Copy the whole pnor to the reserved memory region... */
int init_filesys(struct mbox_context *context)
{
	int fd, rc = 0;
	void *m;
       
	fd = open(context->filesys, O_RDONLY);
	if (fd < 1) {
		MSG_ERR("Couldn't open %s: %s\n", context->filesys, strerror(errno));
		return -errno;
	}

	m = mmap(NULL, context->mem_size, PROT_READ, MAP_SHARED, fd, 0);
	if (m == (void *) -1) {
		MSG_ERR("Couldn't mmap %s: %s\n", context->filesys, strerror(errno));
		rc = -errno;
		goto out;
	}

	memcpy(context->mem, m, context->mem_size);
	MSG_INFO("Copied pnor [%s] to reserved memory region 0x%.16p @ 0x%.8x for 0x%.8x\n", context->filesys, context->mem, 0, context->mem_size);

	munmap(m, context->mem_size);
	{
		char *c = context->mem;
		MSG_INFO("HDR: %c%c%c%c\n", *c, *(c + 1), *(c + 2), *(c + 3));
		c = context->mem + 0x3ff7000;
		MSG_INFO("HDR: %c%c%c%c\n", *c, *(c + 1), *(c + 2), *(c + 3));
	}

	/* We know the erase size so we can allocate the flash_erased bytemap */
	context->erase_size_shift = 12;
	context->flash_bmap = calloc(context->flash_size >>
				     context->erase_size_shift,
				     sizeof(*context->flash_bmap));
	MSG_DBG("Flash erase size: 0x%.8x\n", 1 << context->erase_size_shift);
	context->mtd_info.size = 1 << 26;
	context->mtd_info.erasesize = 1 << 12;

out:
	close(fd);
	return rc;
}

int copy_file(struct mbox_context *context, uint32_t offset, void *mem,
	      uint32_t size)
{
	int fd, rc = 0;
	void *m;

	fd = open(context->filesys, O_RDONLY);
	if (fd < 1) {
		MSG_ERR("Couldn't open %s: %s\n", context->filesys, strerror(errno));
		return -errno;
	}

	m = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	if (m == (void *) -1) {
		MSG_ERR("Couldn't mmap %s: %s\n", context->filesys, strerror(errno));
		rc = -errno;
		goto out;
	}

	memcpy(mem, m, size);
	MSG_INFO("Copy %s @ 0x%.8x for 0x%.8x\n", context->filesys, offset, size);

	munmap(m, size);
out:
	close(fd);
	return rc;
}

int write_file(struct mbox_context *context, uint32_t offset, void *mem,
	       uint32_t size)
{
	int fd, rc = 0;
	void *m;

	fd = open(context->filesys, O_RDWR);
	if (fd < 1) {
		MSG_ERR("Couldn't open %s: %s\n", context->filesys, strerror(errno));
		return -errno;
	}

	m = mmap(NULL, size, PROT_WRITE, MAP_SHARED, fd, offset);
	if (m == (void *) -1) {
		MSG_ERR("Couldn't mmap %s: %s %d\n", context->filesys, strerror(errno), errno);
		rc = -errno;
		goto out;
	}

	memcpy(m, mem, size);
	MSG_INFO("Write %s @ 0x%.8x for 0x%.8x\n", context->filesys, offset, size);

	munmap(m, size);
out:
	close(fd);
	return rc;
}
