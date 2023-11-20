#ifndef __AFL_BLUETOOTH_H
#define __AFL_BLUETOOTH_H

#include "bluetooth.h"
#include "types.h"

#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct host_t {
    const char* path;
    pid_t pid;
    int socket_fd;
    int log_fd;
    u8 bd_addr[6];
    u8 random_address[6];
    u8 public_key[64];
    u8 private_key[32];

    bool scan_enabled, adv_enabled;
    struct bt_hci_cmd_le_set_adv_parameters adv_params;
    struct bt_hci_cmd_le_set_scan_parameters scan_params;
    struct bt_hci_cmd_le_set_adv_data adv_data;
    struct bt_hci_cmd_le_set_scan_rsp_data scan_data;
} host_t;



#endif