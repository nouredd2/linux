#ifndef __INET_PRIORITY_QUEUE_H
#define __INET_PRIORITY_QUEUE_H

#include <net/inet_connection_sock.h>

void heapify_up(struct priority_request_sock_queue *queue, u32 index);

#endif
