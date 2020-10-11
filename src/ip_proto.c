//
// Created by Haidy on 2020/6/16.
//

#include "ip_proto.h"

#define INTERNET_PROTOCOL_VERSION_4 4
#define IP_DEFAULT_HEADER_LEN 5
#define IP_DEFAULT_TOTAL_LEN 40

void ip_init_from_empty_data(IP_PROTO *ip) {
    ip->header->header_len = IP_DEFAULT_HEADER_LEN;
    ip->header->version = INTERNET_PROTOCOL_VERSION_4;
    ip->header->tos = 0;
    ip->header->total_len = ntohs(IP_DEFAULT_TOTAL_LEN);
    ip->header->identifier = ntohs(0);
    ip->header->R = 0;
    ip->header->DF = 1;
    ip->header->MF = 0;
    ip->header->offset1 = 0;
    ip->header->offset2 = 0;
    ip->header->ttl = 0xff;
    ip->header->protocol = IPPROTO_TCP;
    ip->header->checksum = 0;
    ip->header->src = 0;
    ip->header->dest = 0;
}

void ip_proto_init(IP_PROTO *ip, const char *data) {
    ip->header = (IP_PROTO_HEADER *) data;
    ip->proto_header.data = data + IP_HEADER_LEN(ip->header);
    ip->data = (char *) data;
}