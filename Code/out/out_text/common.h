
#ifndef TEXTPROTO_COMMON_H
#define TEXTPROTO_COMMON_H

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

struct Frame_rec {
    __u8 tag;
    __u16 name_off; // offset from the start of the application payload
    __u16 name_len;
    __u16 len;
    __u16 body_off; // offset from the start of the application payload
    __u16 body_len;
    __u8 end;
};

#endif // TEXTPROTO_COMMON_H
