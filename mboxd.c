/*
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

#include "linux/aspeed-lpc-ctrl.h"

#include "mbox.h"
#include "common.h"
#include "debug.h"

#define USAGE \
"Usage: %s [ -v[v] | --verbose ] [ -s | --syslog ]\n" \
"\t\t-w | --window-size <size>M\n" \
"\t\t-n | --window-num <num>\n" \
"\t\t-f | --flash <size>[K|M]\n\n" \
"\t-v | --verbose\t\tBe [more] verbose\n" \
"\t-s | --syslog\t\tLog output to syslog (pointless without -v)\n" \
"\t-w | --window-size\tThe window size (power of 2) in MB\n" \
"\t-n | --window-num\tThe number of windows\n" \
"\t-f | --flash\t\tSize of flash in [K|M] bytes\n\n"

/* LPC Device Path */
#define LPC_CTRL_PATH		"/dev/aspeed-lpc-ctrl"

/* Put pulled fds first */
#define MBOX_FD			0
#define POLL_FDS		1
#define LPC_CTRL_FD		1
#define MTD_FD			2
#define TOTAL_FDS		3

#define ALIGN_UP(val, size)	(((val) + (size) - 1) & ~((size) - 1))
#define ALIGN_DOWN(val, size)	(val & ~((size - 1)))

#define MSG_OUT(...)	 	fprintf(stderr, __VA_ARGS__)
				/*do { if (verbosity != MBOX_LOG_NONE) { \
				    mbox_log(LOG_INFO, f_, ##__VA_ARGS__); } } \
				while(0)*/
#define MSG_ERR(...)		fprintf(stdout, __VA_ARGS__)
				/*do { if (verbosity != MBOX_LOG_NONE) { \
				    mbox_log(LOG_ERR, f_, ##__VA_ARGS__); } } \
				while(0)*/
#define DELETE_ME(...)		fprintf(stdout, __VA_ARGS__);

#define BOOT_HICR7		0x30000e00U
#define BOOT_HICR8		0xfe0001ffU

static int sighup = 0;
static int sigint = 0;
/* We need to keep track of this because we may resize windows due to V1 bugs */
static uint32_t default_window_size = 0;
/*
 * Used to track the oldest window value for the LRU eviction scheme.
 *
 * Everytime a window is created/accessed it is given the max_age and max_age
 * is incremented. This means that more recently accessed windows will have a
 * higher age. Thus when selecting a window to evict, we simple choose the one
 * with the lowest age and this is the least recently used (LRU) window.
 *
 * We could try to look at windows which are used least often rather than least
 * recently, but an LRU scheme should suffice for now.
 */
static uint32_t max_age = 0;

static int handle_cmd_close_window(struct mbox_context *context,
				   union mbox_regs *req);

/******************************************************************************/

/* Flash Functions */

static int point_to_flash(struct mbox_context *context)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_FLASH,
		.window_id = 0, /* Theres only one */
		.flags = 0,
		/*
		 * The mask is because the top nibble is the host LPC FW space,
		 * we want space 0.
		 */
		.addr = 0x0FFFFFFF & -context->flash_size,
		.offset = 0,
		.size = context->flash_size
	};

	MSG_OUT("Pointing HOST LPC bus at the actual flash\n");
	MSG_OUT("Assuming %dMB of flash: HOST LPC 0x%08x\n",
		context->flash_size >> 20, map.addr);

	if (ioctl(context->fds[LPC_CTRL_FD].fd, ASPEED_LPC_CTRL_IOCTL_MAP, &map)
			== -1) {
		MSG_ERR("Failed to point the LPC BUS at the actual flash: %s\n",
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	return 0;
}

#define CHUNKSIZE (64 * 1024)

/*
 * Copy size bytes from flash with file descriptor fd at offset into buffer mem
 * which is of atleast size
 * Note: All in bytes
 */
static int copy_flash(int fd, uint32_t offset, void *mem, uint32_t size)
{
	MSG_OUT("Loading flash at %p for 0x%08x bytes from offset 0x%.8x\n",
							mem, size, offset);
	if (lseek(fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	while (size) {
		uint32_t size_read = read(fd, mem, min_u32(CHUNKSIZE, size));
		if (size_read < 0) {
			MSG_ERR("Couldn't copy mtd into ram: %d. %s\n",
				size_read, strerror(size_read));
			return -MBOX_R_SYSTEM_ERROR;
		}

		size -= size_read;
		mem += size_read;
	}

	return 0;
}

/*
 * Erase the flash at offset (bytes) for count (bytes)
 * Note: The erase ioctl will fail for an offset and count not aligned to erase
 * size
 */
static int erase_flash(int fd, uint32_t offset, uint32_t count)
{
	int rc;

	struct erase_info_user erase_info = {
		.start = offset,
		.length = count
	};

	MSG_OUT("Erasing 0x%.8x for 0x%.8x\n", offset, count);

	rc = ioctl(fd, MEMERASE, &erase_info);

	if (rc < 0) {
		MSG_ERR("Couldn't erase flash at 0x%.8x for 0x%.8x\n",
			offset, count);
		return -MBOX_R_SYSTEM_ERROR;
	}

	return 0;
}

/*
 * Write the flash at offset (bytes) for count (bytes) from buf
 */
static int write_flash(int fd, uint32_t offset, void *buf, uint32_t count)
{
	int rc;

	MSG_OUT("Writing 0x%.8x for 0x%.8x from %p\n", offset, count, buf);

	if (lseek(fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	while (count) {
		rc = write(fd, buf, count);
		if (rc < 0) {
			MSG_ERR("Couldn't write to flash, write lost: %s\n",
				strerror(errno));
			return -MBOX_R_WRITE_ERROR;
		}
		count -= rc;
		buf += rc;
	}

	return 0;
}

/*
 * Handle a write_to_flash for dirty memory when block_size is less than the
 * flash erase size
 * This requires us to be a bit careful because we might have to erase more
 * than we want to write which could result in data loss if we don't have the
 * entire portion of flash to be erased already saved in memory (for us to
 * write back after the erase)
 *
 * offset and count are in number of bytes where offset is within the window
 */
static int write_to_flash_dirty_v1(struct mbox_context *context,
				   uint32_t offset_bytes, uint32_t count_bytes)
{
	int rc;
	uint32_t flash_offset;
	struct window_context low_mem = { 0 }, high_mem = { 0 };

	/* Find where in phys flash this is based on the window.flash_offset */
	flash_offset = context->current->flash_offset + offset_bytes;

	/*
	 * low_mem.flash_offset = erase boundary below where we're writing
	 * low_mem.size = size from low_mem.flash_offset to where we're writing
	 *
	 * high_mem.flash_offset = end of where we're writing
	 * high_mem.size = size from end of where we're writing to next erase
	 * 		   boundary
	 */
	low_mem.flash_offset = ALIGN_DOWN(flash_offset,
					  context->mtd_info.erasesize);
	low_mem.size = flash_offset - low_mem.flash_offset;
	high_mem.flash_offset = flash_offset + count_bytes;
	high_mem.size = ALIGN_UP(high_mem.flash_offset,
				 context->mtd_info.erasesize) -
			high_mem.flash_offset;

	DELETE_ME("Write to flash V1\n");
	DELETE_ME("@0x%.8x for 0x%.8x\n", flash_offset, count_bytes);
	DELETE_ME("Current Window @0x%.8x for 0x%.8x\n", context->current->flash_offset,
			context->current->size);
	DELETE_ME("low_mem @0x%.8x for 0x%.8x\n", low_mem.flash_offset, low_mem.size);
	DELETE_ME("high_mem @0x%.8x for 0x%.8x\n", high_mem.flash_offset, high_mem.size);

	/*
	 * Check if we already have a copy of the required flash areas in
	 * memory as part of the existing window
	 */
	if (low_mem.flash_offset < context->current->flash_offset) {
		DELETE_ME("low_mem\n");
		/* Before the start of our current window */
		low_mem.mem = malloc(low_mem.size);
		if (!low_mem.mem) {
			MSG_ERR("Unable to allocate memory\n");
			return -MBOX_R_SYSTEM_ERROR;
		}
		rc = copy_flash(context->fds[MTD_FD].fd, low_mem.flash_offset,
				low_mem.mem, low_mem.size);
		if (rc < 0) {
			goto out;
		}
	}
	if ((high_mem.flash_offset + high_mem.size) >
	    (context->current->flash_offset + context->current->size)) {
		DELETE_ME("high_mem\n");
		/* After the end of our current window */
		high_mem.mem = malloc(high_mem.size);
		if (!high_mem.mem) {
			MSG_ERR("Unable to allocate memory\n");
			rc = -MBOX_R_SYSTEM_ERROR;
			goto out;
		}
		rc = copy_flash(context->fds[MTD_FD].fd, high_mem.flash_offset,
				high_mem.mem, high_mem.size);
		if (rc < 0) {
			goto out;
		}
	}

	/*
	 * We need to erase the flash from low_mem.flash_offset->
	 * high_mem.flash_offset + high_mem.size
	 */
	rc = erase_flash(context->fds[MTD_FD].fd, low_mem.flash_offset,
			 (high_mem.flash_offset - low_mem.flash_offset) +
			 high_mem.size);
	if (rc < 0) {
		MSG_ERR("Couldn't erase flash\n");
		goto out;
	}

	/* Write back over the erased area */
	if (low_mem.mem) {
		DELETE_ME("low_mem\n");
		/* Exceed window at the start */
		rc = write_flash(context->fds[MTD_FD].fd, low_mem.flash_offset,
				 low_mem.mem, low_mem.size);
		if (rc < 0) {
			goto out;
		}
	}
	DELETE_ME("window_mem\n");
	rc = write_flash(context->fds[MTD_FD].fd, flash_offset,
			 context->current->mem + offset_bytes, count_bytes);
	if (rc < 0) {
		goto out;
	}
	/*
	 * We still need to write the last little bit that we erased - it's
	 * either in the current window or the high_mem window.
	 */
	if (high_mem.mem) {
		DELETE_ME("high_mem\n");
		/* Exceed window at the end */
		rc = write_flash(context->fds[MTD_FD].fd, high_mem.flash_offset,
				 high_mem.mem, high_mem.size);
		if (rc < 0) {
			goto out;
		}
	} else {
		DELETE_ME("window_mem\n");
		/* Write from the current window - it's atleast that big */
		rc = write_flash(context->fds[MTD_FD].fd, high_mem.flash_offset,
				 context->current->mem + offset_bytes +
				 count_bytes, high_mem.size);
		if (rc < 0) {
			goto out;
		}
	}

out:
	free(low_mem.mem);
	free(high_mem.mem);
	return rc;
}

/*
 * Write back to the flash from the current window at offset for count blocks
 * We either just erase or erase then write depending on type
 *
 * offset and count are in number of blocks where offset is within the window
 */
static int write_to_flash(struct mbox_context *context, uint32_t offset,
			  uint32_t count, uint8_t type)
{
	int rc;
	uint32_t flash_offset, count_bytes = count << context->block_size_shift;
	uint32_t offset_bytes = offset << context->block_size_shift;

	switch (type) {
	case BITMAP_ERASED: /* >= V2 ONLY -> block_size == erasesize */
		DELETE_ME("ERASE: @0x%.8x for 0x%.8x blocks\n", offset, count);
		flash_offset = context->current->flash_offset + offset_bytes;
		rc = erase_flash(context->fds[MTD_FD].fd, flash_offset,
				 count_bytes);
		if (rc < 0) {
			MSG_ERR("Couldn't erase flash\n");
			return rc;
		}
		break;
	case BITMAP_DIRTY:
		DELETE_ME("WRITE: @0x%.8x for 0x%.8x blocks\n", offset, count);
		/*
		 * For protocol V1, block_size may be smaller than erase size
		 * so we have a special function to make sure that we do this
		 * correctly without losing data.
		 */
		if (log_2(context->mtd_info.erasesize) !=
						context->block_size_shift) {
			return write_to_flash_dirty_v1(context, offset_bytes,
						       count_bytes);
		}
		flash_offset = context->current->flash_offset + offset_bytes;

		/* Erase the flash */
		rc = erase_flash(context->fds[MTD_FD].fd, flash_offset,
				 count_bytes);
		if (rc < 0) {
			return rc;
		}

		/* Write to the erased flash */
		rc = write_flash(context->fds[MTD_FD].fd, flash_offset,
				 context->current->mem + offset_bytes,
				 count_bytes);
		if (rc < 0) {
			return rc;
		}

		break;
	default:
		break;
	}

	return 0;
}

/******************************************************************************/

/* Window Functions */

/*
 * Point the LPC bus mapping to the reserved memory region
 */
static int point_to_memory(struct mbox_context *context)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY,
		.window_id = 0, /* There's only one */
		.flags = 0,
		.addr = context->lpc_base,
		.offset = 0,
		.size = context->mem_size
	};

	MSG_OUT("Pointing HOST LPC bus at memory region %p of size 0x%.8x\n",
			context->mem, context->mem_size);
	MSG_OUT("LPC address 0x%.8x\n", map.addr);

	if (ioctl(context->fds[LPC_CTRL_FD].fd, ASPEED_LPC_CTRL_IOCTL_MAP,
		  &map)) {
		MSG_ERR("Failed to point the LPC BUS to memory: %s\n",
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	return 0;
}

/* Allocates (with inital free) dirty bitmaps for windows based on block size */
static void alloc_window_dirty_bitmap(struct mbox_context *context)
{
	struct window_context *window;
	int i;

	for (i = 0; i < context->windows.num; i++) {
		window = &context->windows.window[i];
		/* There may already be one allocated */
		free(window->dirty_bitmap);
		/* Allocate the new one */
		window->dirty_bitmap = calloc((window->size >>
					       context->block_size_shift),
					      sizeof(*window->dirty_bitmap));
	}
}

/* Reset all windows to a default state */
static void reset_windows(struct mbox_context *context)
{
	int i;

	/* We might have an open window which needs closing/flushing */
	if (context->current) {
		handle_cmd_close_window(context, NULL);
	}

	for (i = 0; i < context->windows.num; i++) {
		struct window_context *window = &context->windows.window[i];

		window->flash_offset = -1;
		window->size = default_window_size;
		if (window->dirty_bitmap) { /* Might not have been allocated */
			memset(window->dirty_bitmap, BITMAP_CLEAN,
			       window->size >> context->block_size_shift);
		}
		window->age = 0;
	}

	max_age = 0;
}

/* Finds and returns the oldest (LRU) window */
static struct window_context *find_oldest_window(struct mbox_context *context)
{
	struct window_context *oldest, *cur;
	uint32_t min_age = max_age + 1;
	int i;

	DELETE_ME("Searching for oldest window num: %d\n", context->windows.num);

	for (i = 0; i < context->windows.num; i++) {
		cur = &context->windows.window[i];
		DELETE_ME("%d min_age %u cur->age %u\n", i, min_age, cur->age);

		if (cur->age < min_age) {
			DELETE_ME("Oldest!!!\n");
			min_age = cur->age;
			oldest = cur;
		}
	}

	return oldest;
}

/*
 * Search window list for one containing the given offset.
 * Returns the window that maps that offset
 * If exact == 1 then the window must exactly map the offset (required for
 * protocol V1)
 *
 * offset given as absolute flash offset in bytes
 */
static struct window_context *search_windows(struct mbox_context *context,
					     uint32_t offset, bool exact)
{
	int i = 0;
	struct window_context *cur = &context->windows.window[i];

	DELETE_ME("Searching windows\n");
	for (; i < context->windows.num; cur = &context->windows.window[++i]) {
		if (cur->flash_offset == (uint32_t) -1) {
			DELETE_ME("%d: NO MATCH - uninitialised\n", i);
			/* Uninitialised Window */
			continue;
		}
		if ((offset >= cur->flash_offset) &&
		    (offset < (cur->flash_offset + cur->size))) {
			if (exact && (cur->flash_offset != offset)) {
				DELETE_ME("%d: NO MATCH - not exact\n", i);
				continue;
			}
			DELETE_ME("%d: match!!!\n", i);
			/* This window contains the requested offset */
			cur->age = ++max_age;
			return cur;
		}
		DELETE_ME("%d: NO MATCH\n", i);

	}
	DELETE_ME("No Match\n");

	return NULL;
}

/*
 * Used when we don't have a window that already maps the required offset.
 * Chooses one to evict and sets up a window to contain that offset.
 * Returns negative on error, or zero if context->current set to window
 * If exact == 1 then the window must exactly map the offset (required for
 * protocol V1)
 *
 * offset given as absolute flash offset in bytes
 */
static struct window_context *create_map_window(struct mbox_context *context,
						uint32_t offset, bool exact,
						int *rc)
{
	struct window_context *cur = NULL;
	int i, size;

	/* Search for an uninitialised window, use this before evicting */
	for (i = 0; i < context->windows.num; i++) {
		cur = &context->windows.window[i];
		if (cur->flash_offset == (uint32_t) -1) {
			DELETE_ME("%d: Uninitialised - Using It to Map\n", i);
			/* Uninitialised window -> use this one */
			break;
		}
	}

	/* No uninitialised window found, we need to choose one to "evict" */
	if (i == context->windows.num) {
		DELETE_ME("No uninitialised window - evicting\n");
		cur = find_oldest_window(context);
	}

	if (!exact) {
		/*
		 * It would be nice to align the offsets which we map to window
		 * size, this will help prevent overlap which would be an
		 * inefficient use of our reserved memory area (we would like
		 * to "cache" as much of the acutal flash as possible in
		 * memory). If we're protocol V1 however we must ensure the
		 * offset requested is exactly mapped.
		 */
		offset &= ~(cur->size - 1);
	}

	if ((offset + cur->size) > context->flash_size) {
		/*
		 * There is V1 skiboot implementations out there which don't
		 * mask offset with window size, meaning when we have
		 * window size == flash size we will never allow the host to
		 * open a window except at 0x0, which isn't alway where the host
		 * requests it. Thus we have to ignore this check and just
		 * hope the host doesn't access past the end of the window
		 * (which it shouldn't) for V1 implementations to get around
		 * this.
		 */
		if (exact) {
			cur->size = ALIGN_DOWN(context->flash_size - offset,
					       1 << context->block_size_shift);
		} else {
			/* Trying to read past the end of flash */
			MSG_ERR("Tried to open read window past flash limit\n");
			*rc = -MBOX_R_PARAM_ERROR;
			return NULL;
		}
	}

	DELETE_ME("Window at 0x%.8x of size 0x%.8x maps flash 0x%.8x\n",
			cur->mem, cur->size, offset);

	/* Copy from flash into the window buffer */
	*rc = copy_flash(context->fds[MTD_FD].fd, offset, cur->mem, cur->size);
	if (*rc < 0) {
		return NULL;
	}

	/* Clear the Dirty/Erase Bitmap */
	memset(cur->dirty_bitmap, BITMAP_CLEAN,
	       cur->size >> context->block_size_shift);

	/* Update so we know what's in the window */
	cur->flash_offset = offset;
	cur->age = ++max_age;

	return cur;
}

/******************************************************************************/

/* Command Handlers */

/*
 * Command: RESET_STATE
 * Reset the LPC mapping to point back at the flash
 */
static int handle_cmd_reset(struct mbox_context *context)
{
	reset_windows(context);
	return point_to_flash(context);
}

/*
 * Command: GET_MBOX_INFO
 * Get the API version, default window size and block size
 * We also set the LPC mapping to point to the reserved memory region here so
 * this command must be called before any window manipulation
 *
 * V1:
 * ARGS[0]: API Version
 *
 * RESP[0]: API Version
 * RESP[1:2]: Default read window size (number of blocks)
 * RESP[3:4]: Default write window size (number of blocks)
 * RESP[5]: Block size (as shift)
 *
 * V2:
 * ARGS[0]: API Version
 *
 * RESP[0]: API Version
 * RESP[1:2]: Default read window size (number of blocks)
 * RESP[3:4]: Default write window size (number of blocks)
 * RESP[5]: Block size (as shift)
 */
static int handle_cmd_mbox_info(struct mbox_context *context,
				union mbox_regs *req, struct mbox_msg *resp)
{
	uint8_t mbox_api_version = req->msg.args[0];
	int i, rc;

	DELETE_ME("Host api version: %d\n", mbox_api_version);

	/* Check we support the version requested */
	if (mbox_api_version < API_MIN_VERISON ||
	    mbox_api_version > API_MAX_VERSION) {
		return -MBOX_R_PARAM_ERROR;
	}
	context->version = mbox_api_version;

	switch (context->version) {
	case API_VERISON_2:
		context->block_size_shift = log_2(context->mtd_info.erasesize);
		break;
	default:
		context->block_size_shift = BLOCK_SIZE_SHIFT_V1;
		break;
	}

	DELETE_ME("block_size_shift: %d\n", context->block_size_shift);

	/* Now we know the blocksize we can allocate the window dirty_bitmap */
	alloc_window_dirty_bitmap(context);

	/* Point the LPC bus mapping to the reserved memory region */
	rc = point_to_memory(context);
	if (rc < 0) {
		return rc;
	}

	DELETE_ME("window size: %d\n", context->windows.window[0].size >>
					context->block_size_shift);

	resp->args[0] = mbox_api_version;
	put_u16(&resp->args[1], default_window_size >>
				context->block_size_shift);
	put_u16(&resp->args[3], default_window_size >>
				context->block_size_shift);
	resp->args[5] = context->block_size_shift;

	return 0;
}

/*
 * Command: GET_FLASH_INFO
 * Get the flash size and erase granularity
 *
 * V1:
 * RESP[0:3]: Flash Size (bytes)
 * RESP[4:7]: Eraze Size (bytes)
 * V2:
 * RESP[0:1]: Flash Size (number of blocks)
 * RESP[2:3]: Eraze Size (number of blocks)
 */
static int handle_cmd_flash_info(struct mbox_context *context,
				 struct mbox_msg *resp)
{
	switch (context->version) {
	case API_VERISON_1:
		DELETE_ME("flash_size: 0x%.8x\n", context->flash_size);
		DELETE_ME("erase_size: 0x%.8x\n", context->mtd_info.erasesize);

		/* Both Sizes in Bytes */
		put_u32(&resp->args[0], context->flash_size);
		put_u32(&resp->args[4], context->mtd_info.erasesize);
		break;
	case API_VERISON_2:
		DELETE_ME("flash_size: 0x%.8x\n", context->flash_size
				>> context->block_size_shift);
		DELETE_ME("erase_size: 0x%.8x\n", context->mtd_info.erasesize
				>> context->block_size_shift);

		/* Both Sizes in Block Size */
		put_u16(&resp->args[0],
			context->flash_size >> context->block_size_shift);
		put_u16(&resp->args[2],
			context->mtd_info.erasesize >>
					context->block_size_shift);
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Command: CREATE_READ_WINDOW
 * Opens a read window
 * First checks if any current window with the requested data, if so we just
 * point the host to that. Otherwise we read the request data in from flash and
 * point the host there.
 *
 * V1:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 *
 * V2:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 * ARGS[2:3]: Requested window size (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 * RESP[2:3]: Actual window size that was mapped/host can access (n.o. blocks)
 */
static int handle_cmd_read_window(struct mbox_context *context,
				  union mbox_regs *req, struct mbox_msg *resp)
{
	uint32_t flash_offset, size;
	int rc;

	DELETE_ME("Opening Window\n");
	if (context->current) {
		/* Already window open -> close it */
		DELETE_ME("Already window open, closing it\n");
		rc = handle_cmd_close_window(context, req);
		if (rc < 0) {
			return rc;
		}
	}

	/* Offset the host has requested */
	flash_offset = get_u16(&req->msg.args[0]) << context->block_size_shift;
	DELETE_ME("Host req flash at 0x%.8x\n", flash_offset);
	/* Check if we have an existing window */
	context->current = search_windows(context, flash_offset,
					  context->version == API_VERISON_1);

	if (!context->current) { /* No existing window */
		DELETE_ME("No existing window, mapping new one\n");
		context->current = create_map_window(context, flash_offset,
						     context->version ==
						     API_VERISON_1, &rc);
		if (rc < 0) { /* Unable to map offset */
			MSG_ERR("Couldn't create window mapping for offset %u\n"
				, flash_offset);
			return rc;
		}
	}

	/*
	 * Tell the host the lpc bus address of what they requested, this is
	 * the base lpc address + the offset of this window in the reserved
	 * memory region + the offset of the actual data they requested within
	 * this window
	 */
	put_u16(&resp->args[0],
		(context->lpc_base + (context->current->mem - context->mem) +
		 (flash_offset - context->current->flash_offset))
		>> context->block_size_shift);
	if (context->version >= API_VERISON_2) {
		/*
		 * Tell the host how much data they can actually access from
		 * that address, this is the window size - the offset of the
		 * actual data they requested within this window
		 */
		put_u16(&resp->args[2], 
			(context->current->size - (flash_offset -
			 context->current->flash_offset))
			>> context->block_size_shift);
	}
	DELETE_ME("Window made: lpc addr: 0x%.8x (0x%.8x) size: 0x%.8x"
			" (0x%.8x)\n",
		(context->lpc_base + (context->current->mem - context->mem) +
		 (flash_offset - context->current->flash_offset))
		>> context->block_size_shift,
		context->lpc_base + (context->current->mem - context->mem) +
		(flash_offset - context->current->flash_offset),
		(context->current->size - (flash_offset -
		context->current->flash_offset))
		>> context->block_size_shift,
		(context->current->size - (flash_offset -
		context->current->flash_offset)));

	context->is_write = false;
	context->window_offset = (flash_offset - context->current->flash_offset)
				 >> context->block_size_shift;
	DELETE_ME("Window offset: 0x%.8x (0x%.8x)\n", context->window_offset,
			context->window_offset << context->block_size_shift);

	return 0;
}

/*
 * Command: CREATE_WRITE_WINDOW
 * Opens a write window
 * First checks if any current window with the requested data, if so we just
 * point the host to that. Otherwise we read the request data in from flash and
 * point the host there.
 *
 * V1:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 *
 * V2:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 * ARGS[2:3]: Requested window size (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 * RESP[2:3]: Actual window size that was mapped/host can access (n.o. blocks)
 */
static int handle_cmd_write_window(struct mbox_context *context,
				   union mbox_regs *req, struct mbox_msg *resp)
{
	int rc;
	/*
	 * This is very similar to opening a read window (exactly the same
	 * for now infact)
	 */
	DELETE_ME("Write window\n");

	rc = handle_cmd_read_window(context, req, resp);
	if (rc < 0) {
		return rc;
	}

	context->is_write = true;
	return rc;
}

/*
 * Commands: MARK_WRITE_DIRTY
 * Marks a portion of the current (write) window dirty, informing the daemon
 * that is has been written to and thus must be at some point written to the
 * backing store
 * These changes aren't written back to the backing store unless flush is then
 * called or the window closed
 *
 * V1:
 * ARGS[0:1]: Where within flash to start (number of blocks)
 * ARGS[2:5]: Number to mark dirty (number of bytes)
 *
 * V2:
 * ARGS[0:1]: Where within window to start (number of blocks)
 * ARGS[2:3]: Number to mark dirty (number of blocks)
 */
static int handle_cmd_dirty_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	uint32_t offset, size;

	DELETE_ME("MARK DIRTY\n");
	if (!context->current || !context->is_write) {
		MSG_ERR("Tried to call mark dirty without open write window\n");
		return -MBOX_R_WINDOW_ERROR;
	}

	offset = get_u16(&req->msg.args[0]);
	DELETE_ME("offset: 0x%.8x\n", offset);
	/* We need to offset based on where in the window we pointed the host */
	offset += context->window_offset;
	DELETE_ME("window offset: 0x%.8x\n", offset);

	if (context->version >= API_VERISON_2) {
		size = get_u16(&req->msg.args[2]);
		DELETE_ME("size: 0x%.8x blocks\n", size);
	} else {
		uint32_t off;
		/* For V1 offset is relative to flash not the current window */
		off = offset - ((context->current->flash_offset) >>
				context->block_size_shift);
		if (off > offset) { /* Underflow - before current window */
			MSG_ERR("Tried to mark dirty past window limits\n");
			return -MBOX_R_PARAM_ERROR;
		}
		offset = off;
		DELETE_ME("actual window offset: 0x%.8x\n", off);
		size = get_u32(&req->msg.args[2]);
		DELETE_ME("size: 0x%.8x bytes\n", size);
		/*
		 * We only track dirty at the block level.
		 * For protocol V1 we can get away with just marking the whole
		 * block dirty.
		 */
		size = ALIGN_UP(size, 1 << context->block_size_shift);
		size >>= context->block_size_shift;
		DELETE_ME("size: 0x%.8x blocks\n", size);
	}

	if ((size + offset) > (context->current->size >>
			       context->block_size_shift)) {
		/* Exceeds window limits */
		MSG_ERR("Tried to mark dirty past window limits\n");
		return -MBOX_R_PARAM_ERROR;
	}

	/*
	 * Mark the blocks dirty, even if they had been erased we have to erase
	 * before write anyway so it's sufficient to just mark them dirty
	 */
	memset(context->current->dirty_bitmap + offset, BITMAP_DIRTY, size);

	return 0;
}

/*
 * Commands: MARK_WRITE_ERASE
 * Erases a portion of the current window
 * These changes aren't written back to the backing store unless flush is then
 * called or the window closed
 *
 * V1:
 * Unimplemented
 *
 * V2:
 * ARGS[0:1]: Where within window to start (number of blocks)
 * ARGS[2:3]: Number to erase (number of blocks)
 */
static int handle_cmd_erase_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	uint32_t offset, size;

	DELETE_ME("MARK ERASED\n");
	if (context->version < API_VERISON_2) {
		MSG_ERR("Erase command called in protocol version 1\n");
		return -MBOX_R_PARAM_ERROR;
	}

	if (!context->current || !context->is_write) {
		MSG_ERR("Tried to call erase without open write window\n");
		return -MBOX_R_WINDOW_ERROR;
	}

	offset = get_u16(&req->msg.args[0]);
	DELETE_ME("offset: 0x%.8x\n blocks", offset);
	/* We need to offset based on where in the window we pointed the host */
	offset += context->window_offset;
	size = get_u16(&req->msg.args[2]);
	DELETE_ME("window offset: 0x%.8x\n blocks", offset);
	DELETE_ME("size: 0x%.8x\n blocks", size);

	if ((size + offset) > (context->current->size >>
			       context->block_size_shift)) {
		/* Exceeds window limits */
		MSG_ERR("Tried to erase past window limits\n");
		return -MBOX_R_PARAM_ERROR;
	}

	/*
	 * Mark the blocks erased, even if they had been dirtied they've now
	 * been erased so there is no loss of information and it's sufficient
	 * to just mark them erased
	 */
	memset(context->current->dirty_bitmap + offset, BITMAP_ERASED, size);
	/* Write 0xFF to mem -> This ensures consistency between flash & ram */
	memset(context->current->mem + (offset << context->block_size_shift),
	       0xFF, size << context->block_size_shift);

	return 0;
}

/*
 * Command: WRITE_FLUSH
 * Flushes any dirty or erased blocks in the current window back to the backing
 * store
 * NOTE: For V1 this behaves much the same as the dirty command in that it
 * takes an offset and number of blocks to dirty, then also performs a flush as
 * part of the same command. For V2 this will only flush blocks already marked
 * dirty/erased with the appropriate commands and doesn't take any arguments
 * directly.
 *
 * V1:
 * ARGS[0:1]: Where within window to start (number of blocks)
 * ARGS[2:5]: Number to mark dirty (number of bytes)
 *
 * V2:
 * NONE
 */
static int handle_cmd_flush_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	int rc, i, offset, count;
	uint8_t prev;

	DELETE_ME("Flushing Window\n");
	if (!context->current || !context->is_write) {
		MSG_ERR("Tried to call flush without open write window\n");
		return -MBOX_R_WINDOW_ERROR;
	}

	/*
	 * For V1 the Flush command acts much the same as the dirty command
	 * except with a flush as well. Only do this on an actual flush
	 * command not when we call flush because we've implicitly closed a
	 * window because we might not have the required args in req.
	 */
	if (context->version == API_VERISON_1 && req &&
			req->msg.command == MBOX_C_WRITE_FLUSH) {
		rc = handle_cmd_dirty_window(context, req);
		if (rc < 0) {
			return rc;
		}
	}

	offset = 0;
	count = 0;
	prev = BITMAP_CLEAN;

	/*
	 * We look for streaks of the same type and keep a count, when the type
	 * (dirty/erased) changes we perform the required action on the backing
	 * store and update the current streak-type
	 */
	for (i = 0; i < (context->current->size >> context->block_size_shift);
			i++) {
		uint8_t cur = context->current->dirty_bitmap[i];
		if (cur != BITMAP_CLEAN) {
			if (cur == prev) { /* Same as previous block, incrmnt */
				count++;
			} else if (prev == BITMAP_CLEAN) { /* Start of run */
				offset = i;
				count++;
			} else { /* Change in streak type */
				rc = write_to_flash(context, offset, count,
						    prev);
				if (rc < 0) {
					return rc;
				}
				offset = i;
				count = 1;
			}
		} else {
			if (prev != BITMAP_CLEAN) { /* End of a streak */
				rc = write_to_flash(context, offset, count,
						    prev);
				if (rc < 0) {
					return rc;
				}
				offset = 0;
				count = 0;
			}
		}
		prev = cur;
	}

	if (prev != BITMAP_CLEAN) { /* Still the last streak to write */
		rc = write_to_flash(context, offset, count, prev);
		if (rc < 0) {
			return rc;
		}
	}

	/* Clear the dirty bitmap since we have written back all changes */
	memset(context->current->dirty_bitmap, BITMAP_CLEAN,
	       context->current->size >> context->block_size_shift);

	return 0;
}

/*
 * Command: CLOSE_WINDOW
 * Close the current window
 * NOTE: There is an implicit flush
 *
 * V1:
 * NONE
 *
 * V2:
 * ARGS[0]: FLAGS
 */
static int handle_cmd_close_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	uint8_t flags = 0;
	int rc;

	DELETE_ME("Closing window\n");
	if (context->is_write) { /* Perform implicit flush */
		rc = handle_cmd_flush_window(context, req);
		if (rc < 0) {
			MSG_ERR("Couldn't flush window on close\n");
			return rc;
		}
	}

	/* Check for flags -> only if this was an explicit close command */
	if (context->version >= API_VERISON_2 &&
	    req->msg.command == MBOX_C_CLOSE_WINDOW) {
		flags = req->msg.args[0];
		if (flags & FLAGS_SHORT_LIFETIME) {
			context->current->age = 0;
		}
	}

	/* We may have resized this - reset to the default */
	context->current->size = default_window_size;
	context->current = NULL;
	context->is_write = false;
	context->window_offset = 0;
	DELETE_ME("Window Closed\n");

	return 0;
}

/*
 * Command: BMC_EVENT_ACK
 * Sent by the host to acknowledge BMC events supplied in mailbox register 15
 *
 * ARGS[0]: Bitmap of bits to ack (by clearing)
 */
static int handle_cmd_ack(struct mbox_context *context, union mbox_regs *req)
{
	int rc;
	uint8_t byte;

	/* Clear all bits except those already set but not acked */
	byte = req->raw[MBOX_BMC_BYTE] & ~req->msg.args[0];

	/* Seek mbox registers */
	rc = lseek(context->fds[MBOX_FD].fd, MBOX_BMC_BYTE, SEEK_SET);
	if (rc != MBOX_BMC_BYTE) {
		MSG_ERR("Couldn't lseek mbox to byte %d: %s\n", MBOX_BMC_BYTE,
				strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	/* Write to mbox status register */
	rc = write(context->fds[MBOX_FD].fd, &byte, 1);
	if (rc != 1) {
		MSG_ERR("Couldn't write to BMC status reg: %s\n",
				strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	/* Reset to start */
	rc = lseek(context->fds[MBOX_FD].fd, 0, SEEK_SET);
	if (rc) {
		MSG_ERR("Couldn't reset MBOX offset to zero\n");
		return -MBOX_R_SYSTEM_ERROR;
	}

	return 0;
}

static int handle_mbox_req(struct mbox_context *context, union mbox_regs *req)
{
	struct mbox_msg resp = {
		.command = req->msg.command,
		.seq = req->msg.seq,
		.args = { 0 },
		.response = MBOX_R_SUCCESS
	};
	int rc = 0, len;

	MSG_OUT("Got data in with command %d\n", req->msg.command);
	/* Must have already called get_mbox_info for other commands */
	if (!context->block_size_shift &&
			!(req->msg.command == MBOX_C_RESET_STATE ||
			req->msg.command == MBOX_C_GET_MBOX_INFO ||
			req->msg.command == MBOX_C_ACK)) {
		MSG_ERR("Must call GET_MBOX_INFO before that command\n");
		rc = -MBOX_R_PARAM_ERROR;
		goto cmd_out;
	}

	/* Handle the command */
	switch (req->msg.command) {
		case MBOX_C_RESET_STATE:
			rc = handle_cmd_reset(context);
			break;
		case MBOX_C_GET_MBOX_INFO:
			rc = handle_cmd_mbox_info(context, req, &resp);
			break;
		case MBOX_C_GET_FLASH_INFO:
			rc = handle_cmd_flash_info(context, &resp);
			break;
		case MBOX_C_READ_WINDOW:
			rc = handle_cmd_read_window(context, req, &resp);
			break;
		case MBOX_C_CLOSE_WINDOW:
			rc = handle_cmd_close_window(context, req);
			break;
		case MBOX_C_WRITE_WINDOW:
			rc = handle_cmd_write_window(context, req, &resp);
			break;
		case MBOX_C_WRITE_DIRTY:
			rc = handle_cmd_dirty_window(context, req);
			break;
		case MBOX_C_WRITE_FLUSH:
			rc = handle_cmd_flush_window(context, req);
			break;
		case MBOX_C_ACK:
			rc = handle_cmd_ack(context, req);
			break;
		case MBOX_C_WRITE_ERASE:
			rc = handle_cmd_erase_window(context, req);
			break;
		default:
			MSG_ERR("UNKNOWN MBOX COMMAND\n");
			rc = -MBOX_R_PARAM_ERROR;
	}

cmd_out:
	if (rc < 0) {
		MSG_ERR("Error handling mbox cmd: %d\n", req->msg.command);
		resp.response = -rc;
	}

	MSG_OUT("Writing response to MBOX regs\n");
	len = write(context->fds[MBOX_FD].fd, &resp, sizeof(resp));
	if (len < sizeof(resp)) {
		MSG_ERR("Didn't write the full response\n");
		rc = -errno;
	}

	return rc;
}

static int get_message(struct mbox_context *context, union mbox_regs *msg)
{
	int rc;

	rc = read(context->fds[MBOX_FD].fd, msg, sizeof(msg->raw));
	if (rc < 0) {
		MSG_ERR("Couldn't read: %s\n", strerror(errno));
		return -errno;
	} else if (rc < sizeof(msg->msg)) {
		MSG_ERR("Short read: %d expecting %zu\n", rc, sizeof(msg->msg));
		return -1;
	}
	{
		int i = 0;
		DELETE_ME("Got Message:\n");
		for (; i < MBOX_REG_BYTES; i++) {
			DELETE_ME("0x%.2x: 0x%.2x\n", i, msg->raw[i]);
		}
	}

	return 0;
}

static int dispatch_mbox(struct mbox_context *context)
{
	int rc = 0;
	union mbox_regs req = { 0 };

	assert(context);

	MSG_OUT("Dispatched to mbox\n");
	rc = get_message(context, &req);
	if (rc) {
		return rc;
	}

	return handle_mbox_req(context, &req);
}

static int poll_loop(struct mbox_context *context)
{
	sigset_t set;
	int rc = 0;

	sigemptyset(&set);
	context->fds[MBOX_FD].events = POLLIN;

	while (1) {
		const struct timespec timeout = {
			.tv_sec = POLL_TIMEOUT_S,
			.tv_nsec = 0
		};
		/*
		 * Poll for events
		 * Note: we only want to recieve SIGHUPs' while we're polling,
		 * not while we're handling a request as otherwise we'll poll
		 * again without handling the signal, whereas if we only turn
		 * them on again before polling we'll immediately jump to the
		 * handler if one was pending without having to wait the entire
		 * poll interval.
		 *
		 * ppoll will replace the signal mask with set before beginning
		 * to poll and then reset it to the original mask before
		 * completing. By default we are blocking the SIGHUP signal, so
		 * give the empty set to ppoll. Thus we enable all signals ->
		 * poll -> disable SIGHUP again, meaning we can only take a
		 * SIGHUP while we're polling and not while handling a request.
		 */
		rc = ppoll(context->fds, POLL_FDS, &timeout, &set);

		if (!rc) { /* Timeout */
			continue;
		}
		if (rc < 0) { /* Error or Signal */
			if (errno == EINTR && sighup) {
				/*
				 * Something may be changing the flash behind
				 * our backs, better to reset all the windows
				 * to ensure we don't cache stale data.
				 */
				reset_windows(context);
				rc = point_to_flash(context);
				/* Not much we can do if this fails */
				if (rc < 0) {
					MSG_ERR("WARNING: Failed to point the "
						"LPC bus back to flash on "
						"SIGHUP\nIf the host requires "
						"this expect problems...\n");
				}
				sighup = 0;
				continue;
			}
			if (errno == EINTR && sigint) {
				MSG_OUT("Caught signal - Exiting...\n");
				/* Probably best to do this for safety */
				rc = point_to_flash(context);
				/* Not much we can do if this fails */
				if (rc < 0) {
					MSG_ERR("WARNING: Failed to point the "
						"LPC bus back to flash\n"
						"If the host requires "
						"this expect problems...\n");
				}
				sigint = 0;
				/* By returning we should cleanup nicely */
				break;
			}
			MSG_ERR("Error from poll(): %s\n", strerror(errno));
			rc = -errno;
			break;
		}

		/* MBOX Request Received */
		rc = dispatch_mbox(context);
		if (rc) {
			MSG_ERR("Error handling MBOX event\n");
		}
	}

	return rc;
}

/******************************************************************************/

/* Init Functions */

#ifndef DEBUG_MBOX
static int init_mbox_dev(struct mbox_context *context)
{
	int fd;

	/* Open MBOX Device */
	fd = open(MBOX_HOST_PATH, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
			MBOX_HOST_PATH, strerror(errno));
		return -errno;
	}
	DELETE_ME("MBOX_DEV OPENED: %d\n", fd);
	

	context->fds[MBOX_FD].fd = fd;
	return 0;
}

static int init_lpc_dev(struct mbox_context *context)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY,
		.window_id = 0, /* There's only one */
		.flags = 0,
		.addr = 0,
		.offset = 0,
		.size = 0
	};
	int fd;

	/* Open LPC Device */
	MSG_OUT("Opening %s\n", LPC_CTRL_PATH);
	fd = open(LPC_CTRL_PATH, O_RDWR | O_SYNC);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
			LPC_CTRL_PATH, strerror(errno));
		return -errno;
	}
	DELETE_ME("LPC_CTRL_DEV OPENED: %d\n", fd);

	context->fds[LPC_CTRL_FD].fd = fd;

	/* Find Size of Reserved Memory Region */
	MSG_OUT("Getting buffer size...\n");
	if (ioctl(fd, ASPEED_LPC_CTRL_IOCTL_GET_SIZE, &map) < 0) {
		MSG_ERR("Couldn't get lpc control buffer size: %s\n",
			strerror(errno));
		return -errno;
	}

	context->mem_size = map.size;
	/* Map at the top of the 28-bit LPC firmware address space-0 */
	context->lpc_base = 0x0FFFFFFF & -context->mem_size;
	DELETE_ME("mem size: 0x%.8x\n", context->mem_size);
	DELETE_ME("lpc base: 0x%.8x\n", context->lpc_base);
	
	/* mmap the Reserved Memory Region */
	MSG_OUT("Mapping %s for %u\n", LPC_CTRL_PATH, context->mem_size);
	context->mem = mmap(NULL, context->mem_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
	if (context->mem == MAP_FAILED) {
		MSG_ERR("Didn't manage to mmap %s: %s\n", LPC_CTRL_PATH,
			strerror(errno));
		return -errno;
	}
	DELETE_ME("Reserved mem at: 0x%.8x\n", context->mem);

	return 0;
}

static int init_flash_dev(struct mbox_context *context)
{
	char *filename = get_dev_mtd();
	int fd, rc = 0;

	if (!filename) {
		MSG_ERR("Couldn't find the PNOR /dev/mtd partition\n");
		return -1;
	}

	MSG_OUT("Opening %s\n", filename);

	/* Open Flash Device */
	fd = open(filename, O_RDWR);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
			filename, strerror(errno));
		rc = -errno;
		goto out;
	}
	DELETE_ME("Flash fd: %d\n", fd);
	context->fds[MTD_FD].fd = fd;

	/* Read the Flash Info */
	if (ioctl(fd, MEMGETINFO, &context->mtd_info) == -1) {
		MSG_ERR("Couldn't get information about MTD: %s\n",
			strerror(errno));
		rc = -1;
		goto out;
	}
	DELETE_ME("Flash size: %d, erase_size %d\n", context->mtd_info.size,
			context->mtd_info.erasesize);

out:
	free(filename);
	return rc;
}
#endif /* DEBUG_MBOX */

static void usage(const char *name)
{
	fprintf(stderr, USAGE, name);
}

static int init_window_mem(struct mbox_context *context)
{
	void *mem_location = context->mem;
	int i;

	/*
	 * Carve up the reserved memory region and allocate it to each of the
	 * windows. The windows are placed one after the other in ascending
	 * order, so window 1 will be first in memory and so on. We shouldn't
	 * have allocated more windows than we have memory, but if we did we
	 * will error out here
	 */
	for (i = 0; i < context->windows.num; i++) {
		DELETE_ME("Window %d at 0x%.8x size 0x%.8x\n",
				i, mem_location, context->windows.window[i].size);
		context->windows.window[i].mem = mem_location;
		mem_location += context->windows.window[i].size;
		if (mem_location > (context->mem + context->mem_size)) {
			/* Tried to allocate window past the end of memory */
			MSG_ERR("Total size of windows exceeds reserved mem\n");
			MSG_ERR("Try smaller or fewer windows\n");
			MSG_ERR("Mem size: 0x%.8x\n", context->mem_size);
			return -1;
		}
	}

	return 0;
}

static void init_window(struct window_context *window, uint32_t size)
{
	window->mem = NULL;
	window->flash_offset = -1;
	window->size = size;
	window->dirty_bitmap = NULL;
	window->age = 0;
}

static bool parse_cmdline(int argc, char **argv,
			  struct mbox_context *context)
{
	char *endptr;
	int opt, i;

	static const struct option long_options[] = {
		{ "flash",		required_argument,	0, 'f' },
		{ "window-size",	required_argument,	0, 'w' },
		{ "window-num",		required_argument,	0, 'n' },
		{ "verbose",		no_argument,		0, 'v' },
		{ "syslog",		no_argument,		0, 's' },
		{ 0,			0,			0, 0   }
	};

	mbox_vlog = &mbox_log_console;

	default_window_size = 0;
	context->windows.num = 0;
	context->current = NULL; /* No current window */

	while ((opt = getopt_long(argc, argv, "f:w:n:vs", long_options, NULL))
			!= -1) {
		switch (opt) {
		case 0:
			break;
		case 'f':
			context->flash_size = strtol(optarg, &endptr, 10);
			if (optarg == endptr) {
				fprintf(stderr, "Unparseable flash size\n");
				return false;
			}
			switch (*endptr) {
			case '\0':
				break;
			case 'M':
				context->flash_size <<= 10;
			case 'K':
				context->flash_size <<= 10;
				break;
			default:
				fprintf(stderr, "Unknown units '%c'\n",
					*endptr);
				return false;
			}
			break;
		case 'n':
			context->windows.num = strtol(optarg, &endptr, 10);
			if (optarg == endptr || *endptr != '\0') {
				fprintf(stderr, "Unparseable window num\n");
				return false;
			}
			break;
		case 'w':
			default_window_size = strtol(optarg, &endptr, 10);
			default_window_size <<= 20; /* Given in MB */
			if (optarg == endptr || *endptr != '\0') {
				fprintf(stderr, "Unparseable window size\n");
				return false;
			}
			break;
		case 'v':
			verbosity++;
			break;
		case 's':
			/* Avoid a double openlog() */
			/*if (mbox_vlog != &vsyslog) {
				openlog(PREFIX, LOG_ODELAY, LOG_DAEMON);
				mbox_vlog = &vsyslog;
			}*/
			break;
		default:
			return false;
		}
	}

	if (!context->flash_size) {
		fprintf(stderr, "Must specify a non-zero flash size\n");
		return false;
	}

	if (!default_window_size) {
		fprintf(stderr, "Must specify a non-zero window size\n");
		return false;
	}

	if (!context->windows.num) {
		fprintf(stderr, "Must specify a non-zero number of windows\n");
		return false;
	}

	MSG_OUT("Flash_size: 0x%.8x\nWindow_num: %d\n"
		"Window_size: 0x%.8x\nverbosity: %d\n",
		  context->flash_size, context->windows.num,
		  default_window_size, verbosity);

	context->windows.window = calloc(context->windows.num,
					 sizeof(*context->windows.window));

	for (i = 0; i < context->windows.num; i++) {
		init_window(&context->windows.window[i], default_window_size);
	}

	if (verbosity) {
		MSG_OUT("%s logging\n", verbosity == MBOX_LOG_DEBUG ? "Debug" :
					"Verbose");
	}

	return true;
}

static int debug_test_mbox_regs(struct mbox_context *context)
{
	int i;

	/* Test the single write facility by setting all the regs to 0xFF */
	MSG_OUT("Setting all MBOX regs to 0xff individually...\n");
	for (i = 0; i < MBOX_REG_BYTES; i++) {
		uint8_t byte = 0xff;
		off_t pos;
		int len;

		pos = lseek(context->fds[MBOX_FD].fd, i, SEEK_SET);
		if (pos != i) {
			MSG_ERR("Couldn't lseek() to byte %d: %s\n", i,
				strerror(errno));
			break;
		}
		len = write(context->fds[MBOX_FD].fd, &byte, 1);
		if (len != 1) {
			MSG_ERR("Couldn't write MBOX reg %d: %s\n", i,
				strerror(errno));
			break;
		}
	}

	if (lseek(context->fds[MBOX_FD].fd, 0, SEEK_SET)) {
		MSG_ERR("Couldn't reset MBOX pos to zero\n");
		return -errno;
	}

	return 0;

}

/******************************************************************************/

/* Signal Handlers */

void signal_hup(int signum)
{
	sighup = 1;
}

void signal_int(int signum)
{
	sigint = 1;
}

/******************************************************************************/

int main(int argc, char **argv)
{
	struct sigaction act_sighup = { 0 }, act_sigint = { 0 };
	struct sigaction act_sigterm = { 0 };
	struct mbox_context *context;
	char *name = argv[0];
	sigset_t set;
	int rc, i;

#ifdef DEBUG_MBOX
	MSG_DEBUG("\n\n!!!DEBUG MODE - USING DUMMY FILES!!!\n\n");
#endif /* DEBUG_MBOX */

	context = calloc(1, sizeof(*context));

	if (!parse_cmdline(argc, argv, context)) {
		usage(name);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < TOTAL_FDS; i++) {
		context->fds[i].fd = -1;
	}

	/* Block SIGHUPs and SIGINTs */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP | SIGINT);
	sigprocmask(SIG_SETMASK, &set, NULL);
	/* Register Hang-Up Signal Handler */
	act_sighup.sa_handler = signal_hup;
	sigemptyset(&act_sighup.sa_mask);
	if (sigaction(SIGHUP, &act_sighup, NULL)) {
		perror("Registering SIGHUP");
		exit(1);
	}
	sighup = 0;
	/* Register Interrupt Signal Handler */
	act_sigint.sa_handler = signal_int;
	sigemptyset(&act_sigint.sa_mask);
	if (sigaction(SIGINT, &act_sigint, NULL)) {
		perror("Registering SIGINT");
		exit(1);
	}
	/* Register Terminate Signal Handler - Same as SIGINT */
	if (sigaction(SIGTERM, &act_sigint, NULL)) {
		perror("Registering SIGTERM");
		exit(1);
	}
	sigint = 0;

	MSG_OUT("Starting Daemon\n");

	rc = init_mbox_dev(context);
	if (rc) {
		goto finish;
	}

	rc = init_lpc_dev(context);
	if (rc) {
		goto finish;
	}

	/* We've found the reserved memory region -> we can assign to windows */
	rc = init_window_mem(context);
	if (rc) {
		goto finish;
	}

	rc = init_flash_dev(context);
	if (rc) {
		goto finish;
	}

	/* Set the LPC bus mapping to point to the physical flash device */
	rc = point_to_flash(context);
	if (rc) {
		goto finish;
	}

#ifdef DEBUG_MBOX
	rc = debug_test_mbox_regs(context);
	if (rc) {
		goto finish;
	}
#endif

	MSG_OUT("Entering Polling Loop\n");
	rc = poll_loop(context);

	MSG_OUT("Exiting Poll Loop: %d\n", rc);

finish:
	MSG_OUT("Daemon Exiting...\n");
	if (context->mem) {
		munmap(context->mem, context->mem_size);
	}
	for (i = 0; i < TOTAL_FDS; i++) {
		close(context->fds[i].fd);
	}
	for (i = 0; i < context->windows.num; i++) {
		DELETE_ME("%d window at %p mapped 0x%.8x size 0x%.8x age %d\n",
			i, context->windows.window[i].mem,
			context->windows.window[i].flash_offset,
			context->windows.window[i].size,
			context->windows.window[i].age);
		free(context->windows.window[i].dirty_bitmap);
	}
	free(context->windows.window);
	free(context);

	return rc;
}
