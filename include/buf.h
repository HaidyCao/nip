//
// Created by haidy on 20-6-27.
//

#ifndef NETWORK_BUF_H
#define NETWORK_BUF_H

#include "socks/lib/c_linked_list.h"

typedef struct packet_buf {
    void *data;         // data
    size_t len;         // data length
    size_t index;       // data start index
    size_t cap;         // data cap

    struct packet_buf *next;    // next data
} PacketBuf;

PacketBuf *PacketBuf_new(CLinkedList *pool, size_t size);

void PacketBuf_free(CLinkedList *pool, PacketBuf *buf);

#endif //NETWORK_BUF_H
