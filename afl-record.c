#include "afl-record.h"
#include "config.h"
#include "debug.h"

#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/uio.h>

static host_t hosts[2] = {
    {.bd_addr = "111111"}, {.bd_addr = "222222"}
};

static u8 hci_buffer[BZ_BUFFER_SIZE];

static void send_command_complete(int this, u16 opcode, void* payload, int size)
{
    u8 type                           = BT_H4_EVT_PKT;
    struct bt_hci_evt_cmd_complete cc = { .ncmd = 10, .opcode = opcode };
    struct bt_hci_evt_hdr evt         = { .evt  = BT_HCI_EVT_CMD_COMPLETE,
                                          .plen = sizeof(cc) + size };
    struct iovec iov[]                = { { .iov_base = &type, .iov_len = 1 },
                                          { .iov_base = &evt, .iov_len = sizeof(evt) },
                                          { .iov_base = &cc, .iov_len = sizeof(cc) },
                                          { .iov_base = payload, .iov_len = size } };
   
    int n = writev(hosts[this].socket_fd, iov, 4);
    pklg_write_packet_v(hosts[this].log_fd, type, true, &iov[1], 3, n - 1);
}

static void send_command_status(int this, u8 status, u16 opcode)
{
    u8 type                         = BT_H4_EVT_PKT;
    struct bt_hci_evt_cmd_status cs = { .ncmd = 10, .opcode = opcode, .status = status };
    struct bt_hci_evt_hdr evt = { .evt = BT_HCI_EVT_CMD_STATUS, .plen = sizeof(cs) };
    struct iovec iov[]        = { { .iov_base = &type, .iov_len = 1 },
                                  { .iov_base = &evt, .iov_len = sizeof(evt) },
                                  { .iov_base = &cs, .iov_len = sizeof(cs) } };

    int n = writev(hosts[this].socket_fd, iov, 3);
    pklg_write_packet_v(hosts[this].log_fd, type, true, &iov[1], 2, n - 1);
}

static void send_command_status_success(int this, u16 opcode)
{
    send_command_status(this, BT_HCI_ERR_SUCCESS, opcode);
}

static void send_le_meta(int this, u8 opcode, void* payload, int size)
{
    u8 type = BT_H4_EVT_PKT;
    struct bt_hci_evt_hdr evt = { .evt = BT_HCI_EVT_LE_META_EVENT, .plen = size + 1 };
    struct iovec iov[]        = { { .iov_base = &type,      .iov_len = 1 },
                                  { .iov_base = &evt,       .iov_len = sizeof(evt) },
                                  { .iov_base = &opcode,    .iov_len = 1 },
                                  { .iov_base = payload,    .iov_len = size} };
    
    int n = writev(hosts[this].socket_fd, iov, 4);
    pklg_write_packet_v(hosts[this].log_fd, type, true, &iov[1], 3, n - 1);
}

static void send_event(int this, u16 opcode, void* payload, int size)
{
    u8 type = BT_H4_EVT_PKT;
    struct bt_hci_evt_hdr evt = { .evt = opcode, .plen = size };
    struct iovec iov[]        = { { .iov_base = &type,      .iov_len = 1 },
                                  { .iov_base = &evt,       .iov_len = sizeof(evt) },
                                  { .iov_base = payload,    .iov_len = size} };
    
    int n = writev(hosts[this].socket_fd, iov, 3);
    pklg_write_packet_v(hosts[this].log_fd, type, true, &iov[1], 2, n - 1);
}

static void send_num_completed_packets(int this, u16 handle, u32 n)
{
    struct bt_hci_evt_num_completed_packets e = {
        .count = n,
        .handle = handle,
        .num_handles = 1
    };
    send_event(this, BT_HCI_EVT_NUM_COMPLETED_PACKETS, &e, sizeof(e));
}

static void handle_cmd_default(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    send_command_complete(this, cmd->opcode, &status, sizeof(status));
}

static void handle_cmd_none(int this, struct bt_hci_cmd_hdr* cmd)
{
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

static void handle_le_read_resolv_list_size(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_rsp_le_read_resolv_list_size rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .size = 0
    };
    send_command_complete(this, cmd->opcode, &rsp, sizeof(rsp));      
}

static void handle_le_read_local_pk256(int this, struct bt_hci_cmd_hdr* cmd)
{
    send_command_status_success(this, cmd->opcode);
    struct bt_hci_evt_le_read_local_pk256_complete rsp = {
        .status = BT_HCI_ERR_SUCCESS
    };
    memcpy(rsp.local_pk256, hosts[this].public_key, sizeof(rsp.local_pk256));
    send_le_meta(this, BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE, &rsp ,sizeof(rsp));
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
    memcpy(&hosts[this].adv_params, cmd->params, cmd->plen);
    send_command_complete(this, cmd->opcode, &status, sizeof(status));   
}

static void handle_le_set_scan_parameters(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    memcpy(&hosts[this].scan_params, cmd->params, cmd->plen);
    send_command_complete(this, cmd->opcode, &status, sizeof(status));      
}

static void handle_le_set_adv_data(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    memcpy(&hosts[this].adv_data, cmd->params, cmd->plen);
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
    memcpy(&hosts[this].scan_data, cmd->params, cmd->plen);
    send_command_complete(this, cmd->opcode, &status, sizeof(status));    
}

static void handle_le_set_adv_enable(int this, struct bt_hci_cmd_hdr* cmd)
{
    u8 status = BT_HCI_ERR_SUCCESS;
    hosts[this].adv_enabled = cmd->params[0];
    send_command_complete(this, cmd->opcode, &status, sizeof(status));    
}

static void handle_le_create_conn(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_cmd_le_create_conn* create = (struct bt_hci_cmd_le_create_conn*)cmd->params;

    if (create->own_addr_type != BD_ADDR_TYPE_PUBLIC || create->peer_addr_type != BD_ADDR_TYPE_PUBLIC)
    {
        FATAL("Cannot handle non-public BD_ADDR");
    }

    struct bt_hci_evt_le_conn_complete central =  {
        .status = BT_HCI_ERR_SUCCESS,
        .handle = 0,
        .role = HCI_ROLE_CENTRAL,
        .peer_addr_type = create->peer_addr_type,
        .interval = create->max_interval,
        .latency = create->latency,
        .supv_timeout = create->supv_timeout,
        .supv_timeout = create->supv_timeout
    };
    memcpy(central.peer_addr, create->peer_addr, 6);

    struct bt_hci_evt_le_conn_complete peripheral =  {
        .status = BT_HCI_ERR_SUCCESS,
        .handle = 0,
        .role = HCI_ROLE_PERIPHERAL,
        .peer_addr_type = create->own_addr_type,
        .interval = create->max_interval,
        .latency = create->latency,
        .supv_timeout = create->supv_timeout,
        .supv_timeout = create->supv_timeout
    };
    memcpy(peripheral.peer_addr, hosts[this].bd_addr, 6);

    send_command_status_success(this, cmd->opcode);
    send_le_meta(this, BT_HCI_EVT_LE_CONN_COMPLETE, &central, sizeof(central));
    send_le_meta(1 - this, BT_HCI_EVT_LE_CONN_COMPLETE, &peripheral, sizeof(peripheral));
}

static void handle_le_read_remote_features(int this, struct bt_hci_cmd_hdr* cmd)
{
    send_command_status_success(this, cmd->opcode);
    struct bt_hci_cmd_le_read_remote_features* rrf = 
        (struct bt_hci_cmd_le_read_remote_features*)cmd->params;
    struct bt_hci_evt_le_remote_features_complete rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .handle = rrf->handle,
        .features = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
    };
    send_le_meta(this, BT_HCI_EVT_LE_REMOTE_FEATURES_COMPLETE, &rsp, sizeof(rsp));
}

static void handle_le_set_phy(int this, struct bt_hci_cmd_hdr* cmd)
{
    struct bt_hci_cmd_le_set_phy* sp = ( struct bt_hci_cmd_le_set_phy* )cmd->params;
    struct bt_hci_evt_le_phy_update_complete rsp = {
        .status = BT_HCI_ERR_SUCCESS,
        .handle = sp->handle,
        .rx_phy = sp->rx_phys,
        .tx_phy = sp->tx_phys
    };
    send_command_status_success(this, cmd->opcode);
    send_le_meta(this, BT_HCI_EVT_LE_PHY_UPDATE_COMPLETE, &rsp, sizeof(rsp));
}

static u32 handle_cmd(int this, struct bt_hci_cmd_hdr* cmd, int size)
{
    u32 actual_size = cmd->plen + sizeof(*cmd);
    if (actual_size > size){
        FATAL("Invalid Command size");
    }

    switch (cmd->opcode)
    {
    case BT_HCI_CMD_RESET: handle_cmd_default(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_VERSION: handle_read_local_version(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_NAME: handle_read_local_name(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_COMMANDS: handle_read_local_commands(this, cmd); break;
    case BT_HCI_CMD_READ_BD_ADDR: handle_read_bd_addr(this, cmd); break;
    case BT_HCI_CMD_READ_BUFFER_SIZE: handle_read_buffer_size(this, cmd); break;
    case BT_HCI_CMD_READ_LOCAL_FEATURES: handle_read_local_features(this, cmd); break;
    case BT_HCI_CMD_SET_EVENT_MASK: handle_cmd_default(this, cmd); break;
    case BT_HCI_CMD_WRITE_ERRONEOUS_REPORTING: handle_cmd_default(this, cmd); break;
    case BT_HCI_CMD_LE_RAND: handle_le_rand(this, cmd); break;
    case BT_HCI_CMD_HOST_BUFFER_SIZE: handle_host_buffer_size(this, cmd); break;
    case BT_HCI_CMD_SET_HOST_FLOW_CONTROL: handle_cmd_default(this, cmd); break;
    case BT_HCI_CMD_LE_READ_LOCAL_FEATURES: handle_le_local_features(this, cmd); break;
    case BT_HCI_CMD_LE_READ_BUFFER_SIZE: handle_le_read_buffer_size(this, cmd); break;
    case BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED: handle_cmd_default(this, cmd); break;
    case BT_HCI_CMD_LE_READ_SUPPORTED_STATES: handle_le_read_supported_states(this, cmd); break;
    case BT_HCI_CMD_LE_READ_MAX_DATA_LENGTH: handle_le_read_max_data_length(this, cmd); break;
    case BT_HCI_CMD_LE_WRITE_DEFAULT_DATA_LENGTH: handle_cmd_default(this, cmd); break;
    case BT_HCI_CMD_LE_READ_RESOLV_LIST_SIZE: handle_le_read_resolv_list_size(this, cmd); break;
    case BT_HCI_CMD_LE_SET_EVENT_MASK: handle_cmd_default(this, cmd); break;
    case BT_HCI_CMD_LE_READ_LOCAL_PK256: handle_le_read_local_pk256(this, cmd); break;
    case BT_HCI_CMD_LE_SET_RANDOM_ADDRESS: handle_le_set_random_address(this, cmd); break;
    case BT_HCI_CMD_LE_SET_ADV_PARAMETERS: handle_le_set_adv_parameters(this, cmd); break;
    case BT_HCI_CMD_LE_SET_SCAN_PARAMETERS: handle_le_set_scan_parameters(this, cmd); break;
    case BT_HCI_CMD_LE_SET_ADV_DATA: handle_le_set_adv_data(this, cmd); break;
    case BT_HCI_CMD_LE_SET_SCAN_ENABLE: handle_le_set_scan_enable(this, cmd); break;
    case BT_HCI_CMD_LE_SET_SCAN_RSP_DATA: handle_le_set_scan_rsp_data(this, cmd); break;
    case BT_HCI_CMD_LE_SET_ADV_ENABLE: handle_le_set_adv_enable(this, cmd); break;
    case BT_HCI_CMD_LE_CREATE_CONN: handle_le_create_conn(this, cmd); break;
    case BT_HCI_CMD_LE_READ_REMOTE_FEATURES: handle_le_read_remote_features(this, cmd); break;
    case BT_HCI_CMD_LE_SET_PHY: handle_le_set_phy(this, cmd); break;
    case BT_HCI_CMD_HOST_NUM_COMPLETED_PACKETS: handle_cmd_none(this, cmd); break;
    default: FATAL("Unhandled command: 0x%x", cmd->opcode);
    }
    return actual_size + 1;
}

static u16 convert_acl_handle(u16 handle)
{
    u8 flags = acl_flags(handle);
    u8 pb = acl_flags_pb(flags);
    u8 bc = acl_flags_bc(flags);
    handle = acl_handle(handle);
    if (pb == PB_START_NO_FLUSH)
        pb = PB_START;
    else if (pb == PB_CONT) FATAL("");
    else FATAL("");
    return acl_handle_pack(handle, (pb) | (bc << 2));
}

static u32 handle_acl(int this, struct bt_hci_acl_hdr* acl, u32 size)
{
    u32 actual_size = acl->dlen + sizeof(*acl);
    if (actual_size > size)
        FATAL("Invalid ACL packet size");

    send_num_completed_packets(this, acl_handle(acl->handle), 1);
    acl->handle = convert_acl_handle(acl->handle);
    write(hosts[1 - this].socket_fd, &((char*)acl)[-1], actual_size + 1);
    pklg_write_packet(hosts[1 - this].log_fd, ((char*)acl)[-1], true, (u8*)acl, actual_size);
    return actual_size + 1;
}

static void handle_data(int this, u8* data, u32 size)
{
    u8* pos = data;
    u8* end = data + size;
    u32 len = 0;

    while (pos < end)
    {
        pklg_write_packet(hosts[this].log_fd, pos[0], false, &pos[1], size - 1);
        switch (pos[0])
        {
        case BT_H4_CMD_PKT: len = handle_cmd(this, (struct bt_hci_cmd_hdr*)&pos[1], size - 1); break;
        case BT_H4_ACL_PKT: len = handle_acl(this, (struct bt_hci_acl_hdr*)&pos[1], size - 1); break;
        default: FATAL("Unhandled packet type: %d", pos[0]);
        }
        pos += len;
        size -= len;
    }
}

void emit_adv_report(int i)
{
    host_t* this = &hosts[i];
    host_t* other = &hosts[1 - i];

    struct bt_hci_evt_le_adv_report* report = (struct bt_hci_evt_le_adv_report*)hci_buffer;
    report->num_reports = 1;
    report->event_type = other->adv_params.type;
    report->addr_type = other->adv_params.own_addr_type;
    report->data_len = other->adv_data.len;

    if (other->adv_params.own_addr_type != BD_ADDR_TYPE_PUBLIC)
        FATAL("Cannot handle non-public BD_ADDR");
    else
        memcpy(report->addr, other->bd_addr, 6);

    memcpy(report->data, other->adv_data.data, report->data_len);
    report->data[report->data_len] = 0;

    send_le_meta(i, BT_HCI_EVT_LE_ADV_REPORT, report, 1 + sizeof(*report) + report->data_len);
}

void emit_scan_rsp(int i)
{
    host_t* this = &hosts[i];
    host_t* other = &hosts[1 - i];

    struct bt_hci_evt_le_adv_report* report = (struct bt_hci_evt_le_adv_report*)hci_buffer;
    report->num_reports = 1;
    report->event_type = other->adv_params.type;
    report->addr_type = other->adv_params.own_addr_type;
    report->data_len = other->scan_data.len;

    if (report->addr_type != BD_ADDR_TYPE_PUBLIC)
        FATAL("Cannot handle non-public BD_ADDR");
    else
        memcpy(report->addr, other->bd_addr, 6);

    memcpy(report->data, other->scan_data.data, report->data_len);
    report->data[report->data_len] = 0;

    send_le_meta(i, BT_HCI_EVT_LE_ADV_REPORT, report, 1 + sizeof(*report) + report->data_len);
}

void start_record()
{
    int n                      = 0;
    char* temp_buf             = calloc(BZ_BUFFER_SIZE, 1);
    struct pollfd pfd[2];

    OKF("Virtual Controller start recording packets");

    for (int i = 0; i < 2; i++)
    {
        pfd[i].fd     = hosts[i].socket_fd;
        pfd[i].events = POLLIN;
    }

    static bool adv_report_sent = false;

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
            else 
            {
                if (hosts[i].scan_enabled && hosts[1 - i].adv_enabled && !adv_report_sent)
                {
                    emit_adv_report(i);
                    emit_scan_rsp(i);
                    adv_report_sent = true;
                }
            }
        }
    }
}



/* 
    Expected arguments:
    1. Bluetooth Host Application1 path
    2. Path to store packet log for Host1
    3. Bluetooth Host Appllication2 path 
    4. Path to store packet log for Host2
*/

int main(int argc, char** argv)
{
    if (argc != 5) {
        FATAL("Usage: ./afl-record host1 host1_out host2 host2_out");
    }


}