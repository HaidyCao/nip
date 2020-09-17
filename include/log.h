//
// Created by Haidy on 2020/6/16.
//

#ifndef NETWORK_LOG_H
#define NETWORK_LOG_H

#ifdef __ANDROID__

#include <android/log.h>

#define NIP_LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, "nip", __FILE__ "(%d): %s: " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define NIP_LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO, "nip", __FILE__ "(%d): %s: " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define NIP_LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN, "nip", __FILE__ "(%d): %s: " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define NIP_LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "nip", __FILE__ "(%d): %s(): " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#else

#endif

#endif //NETWORK_LOG_H
