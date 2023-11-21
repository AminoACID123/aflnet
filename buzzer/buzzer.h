#include "../types.h"
#include "buzzer_config.h"

#include <sys/socket.h>
#include <sys/un.h>

#define BZ_PROTO_CMD        (0)
#define BZ_PROTO_EVT        (1)
#define BZ_PROTO_EVT_LE     (2)
#define BZ_PROTO_L2CAP      (3)
#define BZ_PROTO_L2CAP_LE   (4)
#define BZ_PROTO_ATT        (5)
#define BZ_PROTO_SMP        (6)
#define BZ_PROTO_SMP_BREDR  (7)
#define BZ_PROTO_ISO        (8)
#define BZ_PROTO_SCO        (9)

static inline u32 bz_get_state_id(u32 proto, u32 opcode) {
  return (proto << 16) | opcode;
}

static inline s32 create_hci_socket() {
  
  remove(BZ_HCI_SOCKET);

  int sk = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  addr.sun_family = PF_UNIX;
  strcpy(addr.sun_path, BZ_HCI_SOCKET);
  bind(sk, (struct sockaddr*)&addr, sizeof(addr));
  listen(sk, 3);
  return sk;
}