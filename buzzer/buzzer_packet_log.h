
#ifndef HCI_DUMP_H
#define HCI_DUMP_H

#include "../debug.h"
#include "../types.h"
#include "bluetooth.h"
#include "compiler.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>

enum 
{
    PKLG_COMMAND = 0,
    PKLG_EVENT = 1,
    PKLG_ACL_HS_TO_CTRL = 2,
    PKLG_ACL_CTRL_TO_HS = 3,
    PKLG_SCO_HS_TO_CTRL = 8,
    PKLG_SCO_CTRL_TO_HS = 9,
    PKLG_MESSAGE = 0xfc
};

struct PacketLogHeader
{
    u32 length;
    u32 tv_sec;
    u32 tv_us;
    u8 type;
}__packed;


static inline int pklg_write_init(const char* fname)
{
    return fileno(fopen(fname, "wb"));
}

static inline int pklg_read_init(const char* fname)
{
    return fileno(fopen(fname, "rb"));
}

static inline void pklg_write_header(struct PacketLogHeader* header, u8 type, bool ctrl_to_hs, u16 len)
{
    // struct timeval curr_time;
    // gettimeofday(&curr_time, NULL);

    header->length = to_big_endian(len + 9);
    // header->tv_sec = to_big_endian(curr_time.tv_sec);
    // header->tv_us = to_big_endian(curr_time.tv_usec);
    header->tv_sec = header->tv_us = 0;

    static u8 h4_to_pklg_map[][2] = {
        {},
        {PKLG_COMMAND, PKLG_COMMAND},
        {PKLG_ACL_HS_TO_CTRL, PKLG_ACL_CTRL_TO_HS},
        {PKLG_SCO_HS_TO_CTRL, PKLG_SCO_CTRL_TO_HS},
        {PKLG_EVENT, PKLG_EVENT},
    };
    header->type = h4_to_pklg_map[type][ctrl_to_hs];
}

static inline bool pklg_read_header(int fd, struct PacketLogHeader* header)
{
    int n = read(fd, header, sizeof(struct PacketLogHeader));
    header->length = to_big_endian(header->length);
    return n == sizeof(struct PacketLogHeader);
}

static inline void pklg_write_packet(int fd, u8 type, u8 in, u8* packet, u32 len)
{
    struct PacketLogHeader header;
    pklg_write_header(&header, type, in, len);
    struct iovec iov[] = {
        {.iov_base = &header, .iov_len = sizeof(header)},
        {.iov_base = packet, .iov_len = len}
    };
    writev(fd, iov, 2);
}

static inline void pklg_write_packet_v(int fd, u8 type, bool in, struct iovec* iov, u32 n, u32 len)
{
    struct PacketLogHeader header;
    pklg_write_header(&header, type, in, len);
    write(fd, &header, sizeof(header));
    writev(fd, iov, n);
}

static inline void pklg_read_packet(int fd, struct PacketLogHeader* header, u8* buffer)
{
    *buffer = header->type;
    read(fd, &buffer[1], header->length - 9);
}

#endif 
