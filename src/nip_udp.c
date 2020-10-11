//
// Created by Haidy on 2020/10/9.
//

#include "nip_udp.h"

void udp_init_with_data(UDP_PROTO *udp, IP_PROTO *ip) {
    udp->header = (UDP_PROTO_HEADER *) ip->data + IP_HEADER_LEN(ip->header);
    udp->data = ip->data;
}