#pragma once

#include "../config/core.hpp"
#include "../common/core.hpp" // CORE_ST_LAST
#include "../common/msg_conf.hpp"
#include "../common/mmo.hpp"

#include "channel.hpp"

struct mmo_bridge_server {
	int fd;
	uint32 ip;
	uint16 port;
};

int disif_parse_login(int fd);
int disif_parse(int fd);

void disif_connectack(int fd, uint8 errCode);
