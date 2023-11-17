
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

static inline u32 to_big_endian(u32 value)
{
    u32 result;
    for (int i = 0; i < 4; ++i)
    {
        ((u8*)&result)[i] = ((u8*)&value)[3 - i];
    }
    return result;
}

struct __packed PacketLogHeader
{
    u32 length_;
    u32 tv_sec_;
    u32 tv_us_;
    u8 type_;
};

static inline int init_packet_log(const char* fname)
{
    return fileno(fopen(fname, "wb"));
}

static inline void setup_log_header(struct PacketLogHeader* log, u8 type, bool ctrl_to_hs, u16 len)
{
    struct timeval curr_time;
    gettimeofday(&curr_time, NULL);

    log->length_ = to_big_endian(len + 9);
    log->tv_sec_ = to_big_endian(curr_time.tv_sec);
    log->tv_us_ = to_big_endian(curr_time.tv_usec);

    static u8 h4_to_pklg_map[][2] = {
        {},
        {PKLG_COMMAND, PKLG_COMMAND},
        {PKLG_ACL_HS_TO_CTRL, PKLG_ACL_CTRL_TO_HS},
        {PKLG_SCO_HS_TO_CTRL, PKLG_SCO_CTRL_TO_HS},
        {PKLG_EVENT, PKLG_EVENT},
    };
    log->type_ = h4_to_pklg_map[type][ctrl_to_hs];
    
}

static inline void log_packet(int fd, u8 type, u8 in, u8* packet, u32 len)
{
    struct PacketLogHeader header;
    setup_log_header(&header, type, in, len);
    struct iovec iov[] = {
        {.iov_base = &header, .iov_len = sizeof(header)},
        {.iov_base = packet, .iov_len = len}
    };
    writev(fd, iov, 2);
}

static inline void log_packet_v(int fd, u8 type, bool in, struct iovec* iov, u32 n, u32 len)
{
    struct PacketLogHeader header;
    setup_log_header(&header, type, in, len);
    write(fd, &header, sizeof(header));
    writev(fd, iov, n);
}


#endif 
