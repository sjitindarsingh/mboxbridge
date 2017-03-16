#ifndef DEBUG_H
#define DEBUG_H

#undef DEBUG_MBOX

#ifdef DEBUG_MBOX
#define MSG_DEBUG(...)		fprintf(stdout, __VA_ARGS__)
#else
#define MSG_DEBUG(...)		do { } while (0)
#endif /* DEBUG_MBOX */

#ifdef DEBUG_MBOX
int init_mbox_dev(struct mbox_context *context);
int init_lpc_dev(struct mbox_context *context);
int init_flash_dev(struct mbox_context *context);
#endif /* DEBUG_MBOX */

#endif /* DEBUG_H */
