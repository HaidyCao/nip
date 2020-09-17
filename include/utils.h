//
// Created by haidy on 20-7-10.
//

#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include "tun_to_socket.h"

size_t nip_out_buffer_to_window(Socket *socket, size_t max);

#endif //NETWORK_UTILS_H
