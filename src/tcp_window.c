//
// Created by Haidy on 2020/6/21.
//

#include "tcp_window.h"
#include <malloc.h>
#include <stdbool.h>

TCP_WINDOW *TCP_WINDOW_new_with_size(uint32_t len) {
    TCP_WINDOW *window = calloc(1, sizeof(TCP_WINDOW));
    window->window_size = len;
    window->window = malloc(len);

    return window;
}

TCP_WINDOW *TCP_WINDOW_new() {
    return TCP_WINDOW_new_with_size(TCP_WINDOW_DEFAULT_SIZE);
}

void TCP_WINDOW_free(TCP_WINDOW *window) {
    if (window == NULL) {
        return;
    }

    free(window->window);
    free(window);
}

bool TCP_WINDOW_has_space(TCP_WINDOW *window) {
    if (window->data_index + window->data_len == window->window_size) {
        return false;
    }
    return true;
}