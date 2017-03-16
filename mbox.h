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

#ifndef MBOX_H
#define MBOX_H

#include <mtd/mtd-abi.h>

enum api_version {
	API_VERISON_INVAL	= 0,
	API_VERISON_1		= 1,
	API_VERISON_2		= 2
};

#define API_MIN_VERISON			API_VERISON_1
#define API_MAX_VERSION			API_VERISON_2

/* Command Values */
#define MBOX_C_RESET_STATE		0x01
#define MBOX_C_GET_MBOX_INFO		0x02
#define MBOX_C_GET_FLASH_INFO		0x03
#define MBOX_C_READ_WINDOW		0x04
#define MBOX_C_CLOSE_WINDOW		0x05
#define MBOX_C_WRITE_WINDOW		0x06
#define MBOX_C_WRITE_DIRTY		0x07
#define MBOX_C_WRITE_FLUSH		0x08
#define MBOX_C_ACK			0x09
#define MBOX_C_WRITE_ERASE		0x0a

/* Response Values */
#define MBOX_R_SUCCESS			0x01
#define MBOX_R_PARAM_ERROR		0x02
#define MBOX_R_WRITE_ERROR		0x03
#define MBOX_R_SYSTEM_ERROR		0x04
#define MBOX_R_TIMEOUT			0x05

#define MBOX_HOST_PATH			"/dev/aspeed-mbox"
#define MBOX_HOST_TIMEOUT_SEC		1
#define MBOX_ARGS_BYTES			11
#define MBOX_REG_BYTES			16
#define MBOX_HOST_BYTE			14
#define MBOX_BMC_BYTE			15

#define BLOCK_SIZE_SHIFT_V1		12 /* 4K */
#define POLL_TIMEOUT_S			1

/* Dirty/Erase bitmap masks */
#define BITMAP_CLEAN			0x00
#define BITMAP_DIRTY			0x01
#define BITMAP_ERASED			0x02

struct mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t args[MBOX_ARGS_BYTES];
	uint8_t response;
};

union mbox_regs {
	char raw[MBOX_REG_BYTES];
	struct mbox_msg msg;
};

#define MBOX_FD                 0
#define POLL_FDS                1
#define LPC_CTRL_FD             1
#define MTD_FD                  2
#define TOTAL_FDS               3

struct window_context {
        void *mem;                      /* Portion of Reserved Memory Region */
        uint32_t flash_offset;          /* Flash area the window maps (bytes) */
        uint32_t size;                  /* Size of the Window (bytes) POWER2 */
        uint8_t *dirty_bitmap;          /* Bitmap of the dirty/erased state */
};

struct window_list {
        int num; 
        struct window_context *window;
};

struct mbox_context {
        enum api_version version;
        struct pollfd fds[TOTAL_FDS];
        struct window_list windows;     /* The "Windows" */
        struct window_context *current; /* The current window */
        void *mem;                      /* Reserved Memory Region */
        uint32_t lpc_base;              /* LPC Bus Base Address (bytes) */
        uint32_t mem_size;              /* Reserved Mem Size (bytes) */
        uint32_t flash_size;            /* From cmdline (bytes) */
        uint32_t block_size_shift;
        struct mtd_info_user mtd_info;  /* Actual Flash */
};


#endif /* MBOX_H */
