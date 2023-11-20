#include "virtual_controller.h"

#include "../debug.h"
#include "bluetooth.h"
#include "buzzer_packet_log.h"
#include "buzzer_config.h"
#include "tinycrypt/ecc.h"
#include "tinycrypt/ecc_dh.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
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




static int init_host_record(host_t* host, int sk, const char* name, const char* path)
{
    host->path = path;
    host->pid = fork();
    if (!host->pid)
    {
        setsid();
        char* argv[] = { (char*)path, "--bt-dev=hci0", NULL};
        setenv("LD_PRELOAD", "/home/xaz/Documents/aflnet/buzzer/build/libbuzzer_socket.so", 1);
        if (host == &host[1])
        {
            int dev_null_fd = open("/dev/null", O_RDWR); 
            dup2(dev_null_fd, 1);
            dup2(dev_null_fd, 2);
        }
        execv(path, argv);
    }
    else 
    {
        host->log_fd = pklg_write_init(name);
        host->socket_fd = accept(sk, 0, 0);
        uECC_make_key(host->public_key, host->private_key, uECC_secp256r1());
        OKF("HCI Socket connected");
    }
}

static int bz_vctrl_start_replay(int sk, const char* name, const char* path)
{
    int n, log_fd, socket_fd;
    pid_t pid ;
    pid = hosts[0].pid = fork();
    if (!pid)
    {
        setsid();
        char* argv[] = { (char*)path, "--bt-dev=hci0", NULL};
        setenv("LD_PRELOAD", "/home/xaz/Documents/aflnet/buzzer/build/libbuzzer_socket.so", 1);
        execv(path, argv);
    }
    else 
    {
        log_fd = pklg_read_init(name);
        socket_fd = accept(sk, 0, 0);
        OKF("HCI Socket connected");
    }

    struct pollfd pfd          = { .fd = socket_fd, .events = POLLIN };

    OKF("Virtual Controller start replaying packets");

    u8 pklg_buffer[BZ_BUFFER_SIZE];
    struct PacketLogHeader header;
    while(pklg_read_header(log_fd, &header))
    {
        OKF("%u %u", header.type, header.length);
        if (header.type == PKLG_COMMAND || header.type == PKLG_ACL_HS_TO_CTRL) 
        {
            OKF("start polling");
            poll(&pfd, 1, -1);
            OKF("finished polling: %d", header.length);
            read(log_fd, pklg_buffer, header.length - 9);
            OKF("finished reading log: %d", header.length);
            read(socket_fd, hci_buffer, header.length - 8);
            OKF("finished reading socket: %d", header.length);

            if (memcmp(&hci_buffer[1], pklg_buffer, header.length - 9))
                FATAL("Packet log unmatch %0x %0x", hci_buffer[3], pklg_buffer[2]);
            OKF("finished comparing");
        }
        else if (header.type == PKLG_EVENT || header.type == PKLG_ACL_CTRL_TO_HS) 
        {
            *hci_buffer = (header.type == PKLG_EVENT ? BT_H4_EVT_PKT : BT_H4_ACL_PKT);
            read(log_fd, &hci_buffer[1], header.length - 9);
            u32 k = write(socket_fd, hci_buffer, header.length - 8);
            sleep(1);
            OKF("send %0x %0x %0x len %u:%u", hci_buffer[0],hci_buffer[1], hci_buffer[2], header.length - 8, k);
        }
        OKF("read pklg item");
    }
}


static void init_signal_handlers()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_flags = SA_RESETHAND;

    /* Various ways of saying "stop". */
    sa.sa_handler = stop;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    atexit(at_exit);
}

int main(int argc, char** argv)
{
    // if (argc != 3)
    // {
    //     FATAL("Expected 2 arguments");
    // }

    int sk = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    addr.sun_family = PF_UNIX;
    strcpy(addr.sun_path, BZ_HCI_SOCKET_PATH);
    bind(sk, (struct sockaddr*)&addr, sizeof(addr));
    listen(sk, 3);

    init_signal_handlers();
    init_host_record(&hosts[0], sk, "central_otc.pklg", "/home/xaz/Documents/BlueBench/targets/zephyr/tests/central_otc/build/zephyr/zephyr.exe");
    init_host_record(&hosts[1], sk, "peripheral_ots.pklg", "/home/xaz/Documents/BlueBench/targets/zephyr/tests/peripheral_ots/build/zephyr/zephyr.exe");
    bz_vctrl_start_record();

    // bz_vctrl_start_replay(sk, "central_otc.pklg", "/home/xaz/Documents/BlueBench/targets/zephyr/tests/central_otc/build/zephyr/zephyr.exe");
}