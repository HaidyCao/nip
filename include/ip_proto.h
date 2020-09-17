//
// Created by Haidy on 2020/6/16.
//

#ifndef NETWORK_IP_PROTO_H
#define NETWORK_IP_PROTO_H

#include <stdint.h>
#include <netinet/in.h>

// https://www.eit.lth.se/ppplab/IPHeader.htm
typedef struct {
    unsigned char header_len : 4;
    unsigned char version : 4;
    unsigned char tos;
    unsigned short total_len;

    unsigned short identifier;
    unsigned short offset1 : 5; // Fragment offset
    unsigned short MF : 1;      // More fragments
    unsigned short DF : 1;      // Don't fragment
    unsigned short R : 1;       // Reserved
    unsigned short offset2 : 8;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int src;
    unsigned int dest;
} IP_PROTO_HEADER;

/**
 * Ip Header length
 */
#define IP_HEADER_LEN(ip_header) ip_header->header_len * 4

/**
 * IP Packet length
 */
#define IP_TOTAL_LEN(ip_header) ntohs(ip_header->total_len)

/**
 * Ip Package Data length
 */
#define IP_DATA_LEN(ip_header) IP_TOTAL_LEN(ip_header) - IP_HEADER_LEN(ip_header)

#define SET_IP_OFFSET(ip, offset)                                     \
    uint8_t offset_h = (uint8_t)(&ip_resp)->data[6] | (uint8_t)0x1F;  \
    ip->data[6] = (char)(offset_h & (uint8_t)(offset >> (uint8_t)8)); \
    ip->data[7] = (char)((uint16_t)0x00FF & offset)

typedef struct {
    IP_PROTO_HEADER *header;
    char *data;
} IP_PROTO;

/**
 * init ip protocol
 * @param ip
 */
void ip_init_from_empty_data(IP_PROTO *ip);

#endif //NETWORK_IP_PROTO_H
