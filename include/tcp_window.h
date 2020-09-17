//
// Created by Haidy on 2020/6/21.
//

#ifndef NETWORK_TCP_WINDOW_H
#define NETWORK_TCP_WINDOW_H

#include <sys/types.h>
#include <stdbool.h>

#define TCP_WINDOW_TYPE_SEND 0
#define TCP_WINDOW_TYPE_RECEIVE 1

#define TCP_WINDOW_DEFAULT_SIZE 65535

typedef struct {
    uint32_t window_size;   // tcp window size

    char *window;               // window data
    size_t data_len;            // data length
    size_t data_index;          // read data index
    size_t send_not_ack_count;  // send bu not yet ack count
} TCP_WINDOW;

/**
 * new TCP_WINDOW with fix size
 * @param len window size
 * @return TCP_WINDOW
 */
TCP_WINDOW *TCP_WINDOW_new_with_size(uint32_t len);

/**
 * new TCP_WINDOW with default 65535
 * @return TCP_WINDOW
 */
TCP_WINDOW *TCP_WINDOW_new();

/**
 * free window
 * @param window window
 */
void TCP_WINDOW_free(TCP_WINDOW *window);

/**
 * is window has space
 *
 * @param window window
 * @return true or false
 */
bool TCP_WINDOW_has_space(TCP_WINDOW *window);

#define TCO_WINDOW_not_send_data(window) (window->data_len - window->send_not_ack_count)

#endif //NETWORK_TCP_WINDOW_H
