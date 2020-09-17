//
// Created by haidy on 20-6-26.
//

#include "nip_err.h"

const char *nip_error(int err) {
    switch (err) {
        case NIP_OK:
            return "NIP success";
        case NIP_ERR_NOT_IMPL:
            return "NIP not implement";
        case NIP_ERR_OUTPUT:
            return "NIP output error";
        case NIP_ERR_BAD_DATA:
            return "NIP bad data";
        case NIP_ERR_CLOSED:
            return "NIP socket closed";
        default:
            return "NIP unknown error";
    }
}