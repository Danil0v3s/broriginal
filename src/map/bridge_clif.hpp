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

int bridge_parse(int fd);
int bridge_parse_login(int fd);
int bridge_check_length(int fd, int length);

int bridge_notify_auction_add(int auction_id);
int bridge_create_auction_data(int seller_id, char seller_name[NAME_LENGTH], struct item item, int value);

int bridge_buy_auction(int fd);
int bridge_mail_savemessage(struct mail_message* msg);

void bridge_auction_delete(struct auction_data *auction);

bool bridge_send_mail(struct map_session_data* sd, int send_id, const char* send_name, int dest_id, const char* dest_name, const char* title, const char* body, int zeny, struct item *item, int amount);

void bridge_connectack(int fd, uint8 errCode);
void bridge_auction_response(int fd, uint8 err_code, uint32 account_id, int auction_id);
void bridge_setuserid(char *id);
void bridge_setpasswd(char *pwd);
void bridge_setport(uint16 port);
void do_init_bridge(void);
void do_final_bridge(void);
void bridge_on_disconnect();
