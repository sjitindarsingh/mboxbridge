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

#ifndef MBOXD_FILESYS_H
#define MBOXD_FILESYS_H

#include "mbox.h"

int init_filesys(struct mbox_context *context);
int copy_file(struct mbox_context *context, uint32_t offset, void *mem,
	      uint32_t size);
int write_file(struct mbox_context *context, uint32_t offset, void *mem,
	       uint32_t size);

#endif /* MBOXD_FILESYS_H */
