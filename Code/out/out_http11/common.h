
#ifndef HTTP11_COMMON_H
#define HTTP11_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>

struct Request_rec {
    __u16 method_off; // offset from the start of the application payload
    __u16 method_len;
    __u16 uri_off; // offset from the start of the application payload
    __u16 uri_len;
    __u16 version_off; // offset from the start of the application payload
    __u16 version_len;
};

struct Header_rec {
    __u16 name_off; // offset from the start of the application payload
    __u16 name_len;
    __u16 value_off; // offset from the start of the application payload
    __u16 value_len;
};

#endif // HTTP11_COMMON_H
