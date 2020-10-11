//
// Created by haidy on 20-7-10.
//

#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "tcp_window.h"
#include "nip_tcp.h"
#include "tun_to_socket.h"

size_t nip_out_buffer_to_window(Socket *socket, size_t max) {
    size_t move_count = 0;
    TCP_WINDOW *window = socket->window_send;

    PacketBuf *buffer = socket->out_buf;
    PacketBuf *next = NULL;
    while (buffer != NULL) {
        next = buffer->next;
        char *dest = window->window + window->data_index + window->data_len;
        char *src = buffer->data + buffer->index;
        if (max < buffer->len) {
            memcpy(dest, src, max);
            window->data_len += max;
            buffer->index += max;
            buffer->len -= max;

            move_count += max;
            break;
        }

        memcpy(dest, src, buffer->len);
        window->data_len += buffer->len;
        move_count += buffer->len;
        max -= buffer->len;

        PacketBuf_free(socket->tts->buf_pool, buffer);
        buffer = next;
    }

    socket->out_buf = buffer;
    return move_count;
}