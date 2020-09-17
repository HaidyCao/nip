//
// Created by haidy on 20-6-27.
//

#include <malloc.h>

#include "buf.h"

PacketBuf *PacketBuf_new(CLinkedList *pool, size_t size) {
    PacketBuf *buf = c_linked_list_get_header(pool);
    if (buf != NULL) {
        return buf;
    }

    buf = calloc(1, sizeof(PacketBuf));
    buf->data = malloc(size);
    buf->cap = size;
    return buf;
}

void PacketBuf_free(CLinkedList *pool, PacketBuf *buf) {
    PacketBuf *b = buf;

    while (b != NULL) {
        PacketBuf *next = b->next;
        b->len = 0;
        b->index = 0;

        // TODO free buf

        c_linked_list_add(pool, b);
        b->next = NULL;
        b = next;
    }
}