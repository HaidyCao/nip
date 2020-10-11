//
// Created by Haidy on 2020/10/9.
//

#ifndef NETWORK_NIP_UDP_H
#define NETWORK_NIP_UDP_H

#include "ip_proto.h"

typedef struct {
    UDP_PROTO_HEADER *header;

    char *data;
} UDP_PROTO;

void udp_init_with_data(UDP_PROTO *udp, IP_PROTO *ip);

#endif //NETWORK_NIP_UDP_H
