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

#include <systemd/sd-bus.h>

#include "mbox_dbus.h"

#define USAGE \
"Usage: %s <command> [args]\n\n" \
"\tCommands:\n" \
"\t\t--ping - ping the daemon (args: 0)\n" \
"\t\t--status - check status of the daemon (args: 0)\n"

#define NAME		"MBOX Control"
#define VERSION		1
#define SUBVERSION	0

struct mboxctl_context {
	sd_bus *bus;
};

static void usage(char *name)
{
	printf(USAGE, name);
	exit(0);
}

static int init_dbus_dev(struct mboxctl_context *context)
{
	int rc;

	rc = sd_bus_default_system(&context->bus);
	if (rc < 0) {
		fprintf(stderr, "Failed to connect to the system bus: %s\n",
			strerror(-rc));
	}

	return rc;
}

static int send_dbus_msg(struct mboxctl_context *context,
			 struct mbox_dbus_msg *msg, uint8_t *num_args,
			 struct mbox_dbus_msg *resp)
{
	sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *m = NULL, *n = NULL;

	/* Generate the bus message */
	rc = sd_bus_message_new_method_call(context->bus, &m, DBUS_NAME,
					    DOBJ_NAME, DBUS_NAME, "cmd");
	if (rc < 0) {
		fprintf(stderr, "Failed to init method call: %s\n",
			strerror(-rc));
		goto out;
	}

	/* Add the command */
	rc = sd_bus_message_append(m, "y", msg->cmd);
	if (rc < 0) {
		fprintf(stderr, "Failed to add cmd to message: %s\n",
			strerror(-rc));
		goto out;
	}

	/* Add the args */
	rc = sd_bus_message_append_array(m, 'y', msg->args, *num_args);
	if (rc < 0) {
		fprintf(stderr, "Failed to add args to message: %s\n",
			strerror(-rc));
		goto out;
	}

	{
		int i;
		printf("%d: [%d]\n", msg->cmd, *num_args);
		for (i = 0; i < *num_args; i++) {
			printf("%d: %d\n", i, msg->args[i]);
		}
	}

	/* Send the message */
	rc = sd_bus_call(context->bus, m, 0, error, &n);
	if (rc < 0) {
		fprintf(stderr, "Failed to post message: %s\n", strerror(-rc));
		goto out;
	}

	/* Read response code */
	rc = sd_bus_message_read(n, "y", &resp->cmd);
	if (rc < 0) {
		fprintf(stderr, "Failed to read response code: %s\n",
			strerror(-rc));
		goto out;
	}

	/* Read response args */
	rc = sd_bus_message_read_array(n, 'y', (const void **) &resp->args,
				       num_args);
	if (rc < 0) {
		fprintf(stderr, "Failed to read response args: %s\n",
			strerror(-rc));
		goto out;
	}

	rc = 0;
	{
		int i;
		printf("%d: [%d]\n", resp->cmd, *num_args);
		for (i = 0; i < *num_args; i++) {
			printf("%d: %d\n", i, resp->args[i]);
		}
	}

out:
	sd_bus_error_free(&error);
	sd_bus_message_unref(m);
	sd_bus_message_unref(n);

	return rc;
}

static int handle_cmd_ping(struct mboxctl_context *context)
{
	struct mbox_dbus_msg msg = {
		.cmd = DBUS_C_PING,
		.args = NULL
	};
	struct mbox_dbus_msg resp = { 0 };
	uint8_t num_args = 0;
	int rc;

	rc = send_dbus_msg(context, &msg, &num_args, &resp);
	if (rc < 0) {
		fprintf(stderr, "Failed to send ping command\n");
		return 0;
	}

	printf("Ping: %s\n", resp.cmd ? "Failed" : "Success");
	return 0;
}

static int handle_cmd_status(struct mboxctl_context *context)
{
	uint8_t resp_args[1];
	struct mbox_dbus_msg msg = {
		.cmd = DBUS_C_STATUS,
		.args = NULL
	};
	struct mbox_dbus_msg resp = {
		.args = &resp_args
	};
	uint8_t num_args = 0;
	int rc;

	rc = send_dbus_msg(context, &msg, &num_args, &resp);
	if (rc < 0) {
		fprintf(stderr, "Failed to send status command\n");
		return 0;
	}

	if (resp.cmd != DBUS_SUCCESS) {
		fprintf(stderr, "Status command failed\n");
		return 0;
	}

	printf("Daemon Status: %s\n", resp.args[0] ? "Suspended" : "Active");
	return 0;
}

static int parse_cmdline(struct mboxctl_context *context, int argc, char **argv)
{
	int opt, rc = -1;
	char *endptr;

	static const struct option long_options[] = {
		{ "ping",	no_argument,	0, 'p' },
		{ "status",	no_argument,	0, 's' },
		{ "version",	no_argument,	0, 'v' },
		{ "help",	no_argument,	0, 'h' },
		{ 0,		0,		0, 0   }
	};

	while (opt = getopt_long(argc, argv, "psvh", long_options, NULL) != -1)
	{
		switch (opt) {
		case 'p':
			rc = handle_cmd_ping(context);
			break;
		case 's':
			rc = handle_cmd_status(context);
			break;
		case 'v':
			printf("%s V%d.%.2d\n", NAME, VERSION, SUBVERSION);
			rc = 0;
			break;
		default:
			break;
	}


	return rc;
}

int main(int argc, char **argv)
{
	struct mboxctl_context context;
	char *name = argv[0];
	int rc;

	if (argv != 2) {
		usage(name);
		exit(0);
	}

	rc = init_dbus_dev(&context);
	if (rc < 0) {
		fprintf(stderr, "Failed to init dbus\n");
		goto out;
	}

	rc = parse_cmdline(&context, argc, argv);

	if (rc) {
		usage(name);
		exit(0);
	}

out:
	return rc;
}
