//
// Created by Haidy on 2020/6/18.
//

#ifndef NETWORK_CHECKSUM_H
#define NETWORK_CHECKSUM_H

#include <stdbool.h>

#include "nip_tcp.h"
#include "ip_proto.h"

unsigned short nip_read_short(const char *data, int offset);

uint32_t nip_read_int32(const char *data, int offset);

void ip_checksum(IP_PROTO *ip);

bool tcp_checksum(IP_PROTO *ip, TCP_PROTO *tcp);

bool udp_checksum(IP_PROTO *ip);

#endif //NETWORK_CHECKSUM_H
