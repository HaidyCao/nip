//
// Created by haidy on 20-6-26.
//

#ifndef NETWORK_NIP_ERR_H
#define NETWORK_NIP_ERR_H

#define NIP_OK 0
#define NIP_ERR_NOT_IMPL -1
#define NIP_ERR_OUTPUT -2
#define NIP_ERR_BAD_DATA -3
#define NIP_ERR_CLOSED -4

const char *nip_error(int err);

#endif //NETWORK_NIP_ERR_H
