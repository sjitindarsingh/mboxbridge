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

#ifndef MBOX_DBUS_H
#define MBOX_DBUS_H

#define DBUS_NAME		"org.openbmc.mboxd"
#define DOBJ_NAME		"/org/openbmc/mboxd"

/* Commands */
#define DBUS_C_PING		0x00
#define	DBUS_C_STATUS		0x01

/* Return Values */
#define DBUS_SUCCESS		0x00
#define E_DBUS_INTERNAL		0x01
#define E_DBUS_INVAL		0x02
#define E_DBUS_REJECTED		0x03

/* Response Args */
/* Status */
#define STATUS_ACTIVE		0x00
#define STATUS_SUSPENDED	0x01

struct mbox_dbus_msg {
	uint8_t cmd;
	uint8_t *args;
};

#endif /* MBOX_DBUS_H */
