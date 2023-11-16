#include "virtual_controller.h"

#include "../debug.h"
#include "bluetooth.h"
#include "buzzer_packet_log.h"
#include "buzzer_config.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>

typedef struct host_t {
    const char* path;
    pid_t pid;
    int socket_fd;
    FILE* log;
    u8 bd_addr[6];
    u8 random_address[6];

    bool scan_enabled, adv_enabled;
    struct bt_hci_cmd_le_set_adv_parameters adv_params;
    struct bt_hci_cmd_le_set_scan_parameters scan_params;
    struct bt_hci_cmd_le_set_adv_data adv_data;
    struct bt_hci_cmd_le_set_scan_rsp_data scan_data;
}host_t;

static host_t hosts[2] = {
    {.bd_addr = "11111"}, {.bd_addr = "22222"}
};

static void stop(int sig)
{
    unlink(BZ_HCI_SOCKET);
    for (int i=0;i<2;i++)
    {
        if (hosts[i].pid > 0)
        {
            kill(hosts[i].pid, SIGKILL);
            OKF("Stopped host: %d", hosts[i].pid);
        }
    }
    raise(sig);
}

static void at_exit()
{
    unlink(BZ_HCI_SOCKET);
    for (int i=0;i<2;i++)
    {
        if (hosts[i].pid > 0)
        {
            kill(hosts[i].pid, SIGKILL);
            OKF("Stopped host: %d", hosts[i].pid);
        }
    }
}

static void send_command_complete(int this, uint16_t opcode, void* payload, int size)
{
    u8 type                           = BT_H4_EVT_PKT;
    struct bt_hci_evt_cmd_complete cc = { .ncmd = 10, .opcode = opcode };
    struct bt_hci_evt_hdr evt         = { .evt  = BT_HCI_EVT_CMD_COMPLETE,
                                          .plen = sizeof(cc) + size };
    struct iovec iov[]                = { { .iov_base = &type, .iov_len = 1 },
                                          { .iov_base = &evt, .iov_len = sizeof(evt) },
                                          { .iov_base = &cc, .iov_len = sizeof(cc) },
                                          { .iov_base = payload, .iov_len = size } };
    writev(hosts[this].socket_fd, iov, 4);
}

static void send_command_status(int this, u16 opcode)
{
    u8 type                         = BT_H4_EVT_PKT;
    struct bt_hci_evt_cmd_status cs = { .ncmd = 10, .opcode = opcode, .status = 0 };
    struct bt_hci_evt_hdr evt = { .evt = BT_HCI_EVT_CMD_STATUS, .plen = sizeof(cs) };
    struct iovec iov[]        = { { .iov_base = &type, .iov_len = 1 },
                                  { .iov_base = &evt, .iov_len = sizeof(evt) },
                                  { .iov_base = &cs, .iov_len = sizeof(cs) } };
    writev(hosts[this].socket_fd, iov, 3);
}

static void handle_cmd_reset(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));
}

static void handle_read_local_version(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_read_local_version rsp = 
    { 
        .status       = BT_HCI_ERR_SUCCESS,
        .manufacturer = 0xFFFF,
        .lmp_ver      = 0xFF,
        .lmp_subver   = 0xFFFF,
        .hci_ver      = 0xFF,
        .hci_rev      = 0xFFFF 
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_local_name(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_read_local_name rsp = 
    { 
        .status = BT_HCI_ERR_SUCCESS,
        .name   = "Buzzer" 
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_local_commands(int this, struct bt_hci_cmd_hdr* cmd) {
    struct bt_hci_rsp_read_local_commands rsp = {
        .status = BT_HCI_ERR_SUCCESS
    };
    memset(rsp.commands, 0xFF, sizeof(rsp.commands));
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_bd_addr(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_read_bd_addr rsp =
    { 
        .status = BT_HCI_ERR_SUCCESS
    };
    memcpy(rsp.bdaddr, hosts[this].bd_addr, 6);
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_read_buffer_size(int this, struct bt_hci_cmd_hdr* cmd) {
    struct bt_hci_rsp_read_buffer_size rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .acl_mtu = BZ_ACL_MTU,
        .acl_max_pkt = BZ_ACL_MAX_PKT,
        .sco_mtu = BZ_SCO_MTU,
        .sco_max_pkt = BZ_SCO_MAX_PKT
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));   
}

static void handle_read_local_features(int this, struct bt_hci_cmd_hdr* cmd) {
    struct bt_hci_rsp_read_local_features rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .features = { 0xFF, 0xFF, 0xFF, 0xFF, 0xDF, 0xFF, 0xFF, 0xFF }
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));
}

static void handle_set_event_mask(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));
}

static void handle_write_erroneous_data_reporting(int this, struct bt_hci_cmd_hdr* cmd) {
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));   
}

static void handle_le_rand(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_le_rand rsp =  {
	    .status = BT_HCI_ERR_SUCCESS,
	    .number = 0xdeadbeefdeadbeef
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));   
}

static void handle_host_buffer_size(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));     
}

static void handle_host_flow_ctrl(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));     
}

static void handle_le_local_features(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_le_read_local_features rsp = {
        .status = BT_HCI_ERR_SUCCESS
    };
    memset(rsp.features, 0xFF, sizeof(rsp.features));
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));   
}

static void handle_le_read_buffer_size(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_le_read_buffer_size rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .le_max_pkt = 0x3,
        .le_mtu = 512
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));   
}

static void handle_le_write_host_supported(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status)); 
}

static void handle_le_read_supported_states(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_le_read_supported_states rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .states = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));    
}

static void handle_le_read_max_data_length(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_le_read_max_data_length rsp;
    memset(&rsp, 0xFF, sizeof(rsp));
    rsp.status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));      
}

static void handle_le_write_default_data_length(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));     
}

static void handle_le_read_resolv_list_size(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_le_read_resolv_list_size rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .size = 0
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));      
}

static void handle_le_set_event_mask(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));         
}

static void handle_le_read_local_pk256(int this, struct bt_hci_cmd_hdr* cmd)
{
    send_command_status(this, cmd->opcode);
}

static void handle_le_set_random_address(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    memcpy(hosts[this].random_address, cmd->params, 6);
    send_command_complete(this, cmd->opcode, &status, sizeof(status));          
}

static void handle_le_set_adv_parameters(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    memcpy(cmd->params, &hosts[this].adv_params, cmd->plen);
    send_command_complete(this, cmd->opcode, &status, sizeof(status));   
}

static void handle_le_set_scan_parameters(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    memcpy(cmd->params, &hosts[this].scan_params, cmd->plen);
    send_command_complete(this, cmd->opcode, &status, sizeof(status));      
}

static void handle_le_set_adv_data(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    memcpy(cmd->params, &hosts[this].adv_data, cmd->plen);
    send_command_complete(this, cmd->opcode, &status, sizeof(status)); 
}

static void handle_le_set_scan_enable(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    hosts[this].scan_enabled = cmd->params[0];
    send_command_complete(this, cmd->opcode, &status, sizeof(status));    
}

static void handle_le_set_scan_rsp_data(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    memcpy(cmd->params, &hosts[this].scan_data, cmd->plen);
    send_command_complete(this, cmd->opcode, &status, sizeof(status));    
}

static void handle_le_set_adv_enable(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    hosts[this].adv_enabled = cmd->params[0];
    send_command_complete(this, cmd->opcode, &status, sizeof(status));    
}

static void handle_cmd(int this, struct bt_hci_cmd_hdr* cmd, int size)
{
    if (cmd->plen + sizeof(struct bt_hci_cmd_hdr) != size){
        u8* p = ((u8*)cmd) + 3;
        FATAL("Incorrect size for hci command: expected %d, recv %d", cmd->plen, size);
    }

    switch (cmd->opcode)
    {
    case BT_HCI_CMD_RESET: handle_cmd_reset(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_VERSION: handle_read_local_version(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_NAME: handle_read_local_name(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_COMMANDS: handle_read_local_commands(this, cmd); break;
    case BT_HCI_CMD_READ_BD_ADDR: handle_read_bd_addr(this, cmd); break;
    case BT_HCI_CMD_READ_BUFFER_SIZE: handle_read_buffer_size(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_FEATURES: handle_read_local_features(this, cmd); break;
    case BT_HCI_CMD_SET_EVENT_MASK: handle_set_event_mask(this, cmd); break;
    case BT_HCI_CMD_WRITE_ERRONEOUS_REPORTING: handle_write_erroneous_data_reporting(this, cmd); break;
    case BT_HCI_CMD_LE_RAND: handle_le_rand(this, cmd); break;
    case BT_HCI_CMD_HOST_BUFFER_SIZE: handle_host_buffer_size(this, cmd); break;
    case BT_HCI_CMD_SET_HOST_FLOW_CONTROL: handle_host_flow_ctrl(this, cmd); break;
    case BT_HCI_CMD_LE_READ_LOCAL_FEATURES: handle_le_local_features(this, cmd); break;
    case BT_HCI_CMD_LE_READ_BUFFER_SIZE: handle_le_read_buffer_size(this, cmd); break;
    case BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED: handle_le_write_host_supported(this, cmd); break;
    case BT_HCI_CMD_LE_READ_SUPPORTED_STATES: handle_le_read_supported_states(this, cmd); break;
    case BT_HCI_CMD_LE_READ_MAX_DATA_LENGTH: handle_le_read_max_data_length(this, cmd); break;
    case BT_HCI_CMD_LE_WRITE_DEFAULT_DATA_LENGTH: handle_le_write_default_data_length(this, cmd); break;
    case BT_HCI_CMD_LE_READ_RESOLV_LIST_SIZE: handle_le_read_resolv_list_size(this, cmd); break;
    case BT_HCI_CMD_LE_SET_EVENT_MASK: handle_le_set_event_mask(this, cmd); break;
    case BT_HCI_CMD_LE_READ_LOCAL_PK256: handle_le_read_local_pk256(this, cmd); break;
    case BT_HCI_CMD_LE_SET_RANDOM_ADDRESS: handle_le_set_random_address(this, cmd); break;
    case BT_HCI_CMD_LE_SET_ADV_PARAMETERS: handle_le_set_adv_parameters(this, cmd); break;
    case BT_HCI_CMD_LE_SET_SCAN_PARAMETERS: handle_le_set_scan_parameters(this, cmd); break;
    case BT_HCI_CMD_LE_SET_ADV_DATA: handle_le_set_adv_data(this, cmd); break;
    case BT_HCI_CMD_LE_SET_SCAN_ENABLE: handle_le_set_scan_enable(this, cmd); break;
    case BT_HCI_CMD_LE_SET_SCAN_RSP_DATA: handle_le_set_scan_rsp_data(this, cmd); break;
    case BT_HCI_CMD_LE_SET_ADV_ENABLE: handle_le_set_adv_enable(this, cmd); break;
    default: FATAL("Unhandled command: 0x%x", cmd->opcode);
    }
}

static void handle_acl(int this, struct bt_hci_acl_hdr* acl, int size)
{
    send(hosts[1 - this].socket_fd, &((char*)acl)[-1], size + 1, 0);
}

static void handle_data(int this, char* data, int size)
{
    log_packet(hosts[this].log, data[0], true, &data[1], size - 1);
    switch (data[0])
    {
    case BT_H4_CMD_PKT: handle_cmd(this, (struct bt_hci_cmd_hdr*)&data[1], size - 1); break;
    case BT_H4_ACL_PKT: handle_acl(this, (struct bt_hci_acl_hdr*)&data[1], size - 1); break;
    default: FATAL("Unhandled packet type: %d", data[0]);
    }
}

void bz_vctrl_start_record()
{
    int n                      = 0;
    char* temp_buf             = calloc(BZ_BUFFER_SIZE, 1);
    struct pollfd pfd[2];
    OKF("Virtual Controller start relaying packets");
    for (int i = 0; i < 2; i++)
    {
        pfd[i].fd     = hosts[i].socket_fd;
        pfd[i].events = POLLIN;
    }

    while (1)
    {
        int rv = poll(pfd, 2, 0);
        for (int i = 0; i < 2; i++)
        {
            if (pfd[i].revents & POLLIN)
            {
                n = recv(pfd[i].fd, temp_buf, BZ_BUFFER_SIZE, 0);
                if (n > 0)
                {
                    handle_data(i, temp_buf, n);
                }
            }
        }
    }
}

static int init_host(host_t* host, int sk, const char* name, const char* path)
{
    host->path = path;
    host->pid = fork();
    if (!host->pid)
    {
        setsid();
        char* argv[] = { (char*)path, "--bt-dev=hci0", NULL};
        setenv("LD_PRELOAD", "/home/xaz/Documents/aflnet/buzzer/buzzer.so", 1);
        execv(path, argv);
    }
    else 
    {
        host->log = init_packet_log(name);
        host->socket_fd = accept(sk, 0, 0);
        OKF("HCI Socket connected");
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
    strcpy(addr.sun_path, BZ_HCI_SOCKET);
    bind(sk, (struct sockaddr*)&addr, sizeof(addr));
    listen(sk, 3);

    init_signal_handlers();
    init_host(&hosts[0], sk, "central_otc.pklg", "/home/xaz/Documents/BlueBench/targets/zephyr/tests/central_otc/build/zephyr/zephyr.exe");
    init_host(&hosts[1], sk, "peripheral_ots.pklg", "/home/xaz/Documents/BlueBench/targets/zephyr/tests/peripheral_ots/build/zephyr/zephyr.exe");
    bz_vctrl_start_record();
}