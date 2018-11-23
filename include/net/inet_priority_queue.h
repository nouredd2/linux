#ifndef _INET_PRIORITY_QUEUE_H
#define _INET_PRIORITY_QUEUE_H

#include <linux/types.h>

struct priority_request_sock_queue;

void heapify_up (struct priority_request_sock_queue *queue, u32 index);

void heap_swap (struct priority_request_sock_queue *queue, u32 index, u32 parent);

void max_heapify (struct priority_request_sock_queue *queue);

#endif
