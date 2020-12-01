#include "bridge_clif.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <ctime>

#include "../common/cbasetypes.hpp"
#include "../common/socket.hpp"
#include "../common/timer.hpp"
#include "../common/grfio.hpp"
#include "../common/malloc.hpp"
#include "../common/nullpo.hpp"
#include "../common/random.hpp"
#include "../common/showmsg.hpp"
#include "../common/strlib.hpp"
#include "../common/utils.hpp"
#include "../common/ers.hpp"
#include "../common/conf.hpp"
#include "../common/sql.hpp"

#include "map.hpp"
#include "chrif.hpp"
#include "pc.hpp"
#include "pc_groups.hpp"
#include "status.hpp"
#include "npc.hpp"
#include "itemdb.hpp"
#include "chat.hpp"
#include "trade.hpp"
#include "storage.hpp"
#include "script.hpp"
#include "skill.hpp"
#include "atcommand.hpp"
#include "intif.hpp"
#include "battle.hpp"
#include "battleground.hpp"
#include "mob.hpp"
#include "party.hpp"
#include "unit.hpp"
#include "guild.hpp"
#include "vending.hpp"
#include "pet.hpp"
#include "homunculus.hpp"
#include "instance.hpp"
#include "mercenary.hpp"
#include "elemental.hpp"
#include "log.hpp"
#include "clif.hpp"
#include "mail.hpp"
#include "quest.hpp"
#include "cashshop.hpp"
#include "channel.hpp"
#include "achievement.hpp"
#include "clan.hpp"

static DBMap* auction_db_ = NULL;
struct mmo_bridge_server bridge_server;
static uint32 bind_ip = INADDR_ANY;
static uint32 dis_port = 5131;
static char userid[NAME_LENGTH];
static char passwd[NAME_LENGTH];

TIMER_FUNC(auction_end_timer);

int bridge_fd;

// Received packet Lengths from discord-server
int bridge_recv_packet_length[] = {
	0, 56, 3, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0E00
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0E10
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0E20
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  //0E30
};

int bridge_parse(int fd)
{
	if (bridge_server.fd != fd) {
		ShowDebug("disif_parse: Disconnecting invalid session #%d (is not a discord-server)\n", fd);
		do_close(fd);
		return 0;
	}
	if (session[fd]->flag.eof)
	{
		do_close(fd);
		bridge_server.fd = -1;
		bridge_on_disconnect();
		return 0;
	}

	if (RFIFOREST(fd) < 2)
		return 0;

	ShowInfo("Disif_parse called!\n");
	int cmd;
	int len = 0;
	cmd = RFIFOW(fd, 0);
	// Check is valid packet entry
	if (cmd < 0x0E00 || cmd >= 0x0E00 + ARRAYLENGTH(bridge_recv_packet_length) || bridge_recv_packet_length[cmd - 0x0E00] == 0) {
		//invalid cmd, just close it
		ShowError("Unknown packet 0x%04x from discord server, disconnecting.\n", RFIFOW(fd, 0));
		set_eof(fd);
		return 0;
	}

	while (RFIFOREST(fd) >= 2) {
		int next = 1;

		// Check packet length
		if ((len = bridge_check_length(fd, bridge_recv_packet_length[cmd - 0x0E00])) == 0) {
			//invalid cmd, just close it
			ShowError("Unknown packet 0x%04x from discord server, disconnecting.\n", RFIFOW(fd, 0));
			set_eof(fd);
			return 0;
		}

		if (len == -1) { // variable-length packet
			if (RFIFOREST(fd) < 4)
				return 0;

			len = RFIFOW(fd, 2);
			if (len < 4 || len > 32768) {
				ShowWarning("disif_parse: Received packet 0x%04x specifies invalid packet_len (%d), disconnecting discord server #%d.\n", cmd, len, fd);
#ifdef DUMP_INVALID_PACKET
				ShowDump(RFIFOP(fd, 0), RFIFOREST(fd));
#endif
				set_eof(fd);
				return 0;
			}
		}
		if ((int)RFIFOREST(fd) < len)
			return 0; // not enough data received to form the packet

		switch (RFIFOW(fd, 0)) {
		case 0x0e01: next = bridge_parse_login(fd); return 0;
		case 0x0e03: next = bridge_buy_auction(fd); break;
		case 0x0e05: next = bridge_parse_message_from_disc(fd);
		default:
			ShowError("Unknown packet 0x%04x from discord server, disconnecting.\n", RFIFOW(fd, 0));
			set_eof(fd);
			return 0;
		}
		if (next == 0) return 0; //avoid processing rest of packet
		RFIFOSKIP(fd, len);
	}
	return 1;
}

/**
* Parse discord server login attempt
* @param fd : file descriptor to parse, (link to discord)
* 0D01 <user id>.24B <password>.24B <ip>.L <port>.W (DZ_ENTER)
*/
int bridge_parse_login(int fd)
{
	if (RFIFOREST(fd) < 56)
		return 0;
	else {
		char* l_user = RFIFOCP(fd, 2);
		char* l_pass = RFIFOCP(fd, 26);
		l_user[23] = '\0';
		l_pass[23] = '\0';
		uint32 ip = ntohl(RFIFOL(fd, 50));
		uint16 port = ntohs(RFIFOW(fd, 54));
		RFIFOSKIP(fd, 56);
		if (runflag != MAPSERVER_ST_RUNNING ||
			strcmp(l_user, userid) != 0 ||
			strcmp(l_pass, passwd) != 0) {
			ShowInfo("Rejected Discord server connection attempt\n");
			bridge_connectack(fd, 3); //fail
		}
		else {
			bridge_connectack(fd, 0); //success

			bridge_server.fd = fd;
			bridge_server.ip = ip;
			bridge_server.port = port;
			ShowInfo("Discord server ip is %s:%d\n", ip2str(ip, NULL), port);

			session[fd]->func_parse = bridge_parse;
			session[fd]->flag.server = 1;
			realloc_fifo(fd, FIFOSIZE_SERVERLINK, FIFOSIZE_SERVERLINK);
		}
	}
	return 0;
}

/**
* Inform the discord server whether his login attempt to us was a success or not
* @param fd : file descriptor to parse, (link to discord)
* @param errCode 0:success, 3:fail
* 0D02 <error code>.B
*/
void bridge_connectack(int fd, uint8 errCode)
{
	WFIFOHEAD(fd, 3);
	WFIFOW(fd, 0) = 0x0e02;
	WFIFOB(fd, 2) = errCode;
	WFIFOSET(fd, 3);
}

/** Returns the length of the next complete packet to process,
* or 0 if no complete packet exists in the queue.
*
* @param length The minimum allowed length, or -1 for dynamic lookup
*/
int bridge_check_length(int fd, int length)
{
	if (length == -1)
	{// variable-length packet
		if (RFIFOREST(fd) < 4)
			return 0;
		length = RFIFOW(fd, 2);
	}

	if ((int)RFIFOREST(fd) < length)
		return 0;

	return length;
}

int bridge_notify_auction_add(int auction_id) {
	int fd = bridge_server.fd;

	WFIFOHEAD(fd, 3);
	WFIFOW(fd, 0) = 0x0e04;
	WFIFOB(fd, 2) = auction_id;
	WFIFOSET(fd, 3);

	return 0;
}

int bridge_create_auction_data(int seller_id, char seller_name[NAME_LENGTH], item item, int value)
{
	int j;
	StringBuf buf;
	SqlStmt* stmt;
	struct auction_data *auction = new auction_data();
	item_data *db_item = itemdb_search(item.nameid);

	if (db_item->nameid == 0) {
		return 0;
	}

	auction->seller_id = seller_id;
	auction->item = item;
	auction->hours = 99;
	auction->type = db_item->type;
	auction->price = value;
	auction->timestamp = time(NULL) + (auction->hours * 3600);

	safestrncpy(auction->seller_name, seller_name, sizeof(auction->seller_name));
	safestrncpy(auction->item_name, db_item->jname, sizeof(auction->item_name));

	StringBuf_Init(&buf);
	StringBuf_Printf(&buf, "INSERT INTO `%s` (`seller_id`,`seller_name`,`buyer_id`,`buyer_name`,`price`,`buynow`,`hours`,`timestamp`,`nameid`,`item_name`,`type`,`refine`,`attribute`,`unique_id`", "auction");
	for (j = 0; j < MAX_SLOTS; j++)
		StringBuf_Printf(&buf, ",`card%d`", j);
	for (j = 0; j < MAX_ITEM_RDM_OPT; ++j) {
		StringBuf_Printf(&buf, ", `option_id%d`", j);
		StringBuf_Printf(&buf, ", `option_val%d`", j);
		StringBuf_Printf(&buf, ", `option_parm%d`", j);
	}
	StringBuf_Printf(&buf, ") VALUES ('%d',?,'%d',?,'%d','%d','%d','%lu','%hu',?,'%d','%d','%d','%" PRIu64 "'",
		auction->seller_id, auction->buyer_id, auction->price, auction->buynow, auction->hours, (unsigned long)auction->timestamp, auction->item.nameid, auction->type, auction->item.refine, auction->item.attribute, auction->item.unique_id);
	for (j = 0; j < MAX_SLOTS; j++)
		StringBuf_Printf(&buf, ",'%hu'", auction->item.card[j]);
	for (j = 0; j < MAX_ITEM_RDM_OPT; ++j) {
		StringBuf_Printf(&buf, ", '%d'", auction->item.option[j].id);
		StringBuf_Printf(&buf, ", '%d'", auction->item.option[j].value);
		StringBuf_Printf(&buf, ", '%d'", auction->item.option[j].param);
	}
	StringBuf_AppendStr(&buf, ")");

	stmt = SqlStmt_Malloc(mmysql_handle);
	if (SQL_SUCCESS != SqlStmt_PrepareStr(stmt, StringBuf_Value(&buf))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 0, SQLDT_STRING, auction->seller_name, strnlen(auction->seller_name, NAME_LENGTH))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 1, SQLDT_STRING, auction->buyer_name, strnlen(auction->buyer_name, NAME_LENGTH))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 2, SQLDT_STRING, auction->item_name, strnlen(auction->item_name, ITEM_NAME_LENGTH))
		|| SQL_SUCCESS != SqlStmt_Execute(stmt))
	{
		SqlStmt_ShowDebug(stmt);
		auction->auction_id = 0;
	}
	else
	{
		struct auction_data *auction_;
		t_tick tick = auction->hours * 3600000;

		auction->item.amount = 1;
		auction->item.identify = 1;
		auction->item.expire_time = 0;

		auction->auction_id = (unsigned int)SqlStmt_LastInsertId(stmt);
		auction->auction_end_timer = add_timer(gettick() + tick, auction_end_timer, auction->auction_id, 0);
		ShowInfo("New Auction %u | time left %" PRtf " ms | By %s.\n", auction->auction_id, tick, auction->seller_name);

		CREATE(auction_, struct auction_data, 1);
		memcpy(auction_, auction, sizeof(struct auction_data));
		idb_put(auction_db_, auction_->auction_id, auction_);
		bridge_notify_auction_add(auction->auction_id);
	}

	SqlStmt_Free(stmt);
	StringBuf_Destroy(&buf);

	return auction->auction_id;
}

int bridge_buy_auction(int fd)
{
	int auction_id = RFIFOL(fd, 4);
	int account_id = RFIFOL(fd, 8);
	struct map_session_data *bsd = map_id2sd(account_id);
	struct auction_data *auction;

	if (bsd == NULL) {
		bridge_auction_response(fd, 1, account_id, auction_id);
		return 1;
	}

	if ((auction = (struct auction_data *) idb_get(auction_db_, auction_id)) == NULL || auction->price > bsd->status.zeny || auction->seller_id == bsd->status.char_id) {
		bridge_auction_response(fd, 2, account_id, auction_id);
		return 1;
	}

	if (auction->buyer_id > 0) {
		bridge_auction_response(fd, 3, account_id, auction_id);
		return 1;
	}

	auction->buyer_id = bsd->status.char_id;
	safestrncpy(auction->buyer_name, bsd->status.name, NAME_LENGTH);

	pc_payzeny(bsd, auction->price, LOG_TYPE_AUCTION, NULL);

	bridge_send_mail(bsd, 0, "Auction System", auction->buyer_id, auction->buyer_name, "Auction Result", "You've successfully bought an Item", 0, &auction->item, 1);
	bridge_send_mail(bsd, 0, "Auction System", auction->seller_id, auction->seller_name, "Auction Result", "You've successfully sold an Item", auction->price, NULL, 0);

	bridge_auction_delete(auction);
	bridge_auction_response(fd, 0, account_id, auction_id);

	return 1;
}

/**
* Inform the discord server whether his auction buy request was successful or not
* @param fd : file descriptor to parse, (link to discord)
* @param errCode 0:success, 1: buying char not online, 2: not enough zeny, 3: invalid auction
* 0D02 <error code>.B
*/
void bridge_auction_response(int fd, uint8 err_code, uint32 account_id, int auction_id) {
	WFIFOHEAD(fd, 8);
	WFIFOW(fd, 0) = 0x0e03;
	WFIFOB(fd, 2) = err_code;
	WFIFOL(fd, 3) = account_id;
	WFIFOB(fd, 7) = auction_id;
	WFIFOSET(fd, 8);
}

bool bridge_send_mail(struct map_session_data* sd, int send_id, const char* send_name, int dest_id, const char* dest_name, const char* title, const char* body, int zeny, struct item *item, int amount) {
	struct mail_message msg;
	memset(&msg, 0, sizeof(struct mail_message));

	msg.send_id = send_id;
	safestrncpy(msg.send_name, send_name, NAME_LENGTH);
	msg.dest_id = dest_id;
	safestrncpy(msg.dest_name, dest_name, NAME_LENGTH);
	safestrncpy(msg.title, title, MAIL_TITLE_LENGTH);
	safestrncpy(msg.body, body, MAIL_BODY_LENGTH);
	msg.zeny = zeny;
	if (item != NULL) {
		int i;

		for (i = 0; i < amount && i < MAIL_MAX_ITEM; i++) {
			memcpy(&msg.item[i], &item[i], sizeof(struct item));
		}
	}

	msg.timestamp = time(NULL);
	msg.type = MAIL_INBOX_NORMAL;

	intif_Mail_send(sd->status.account_id, &msg);
	return true;
}

/**
* Parse discord server message and send to chat channel
* @param fd : file descriptor to parse
* 0E05 <packet len>.W <channel name>.20B <user name>.24B <message>.?B
*/
int bridge_parse_message_from_disc(int fd)
{
	int len;
	struct Channel * channel;
	char channel_name[CHAN_NAME_LENGTH];
	char username[NAME_LENGTH];
	char msg[CHAT_SIZE_MAX];
	char output[CHAT_SIZE_MAX];

	if (RFIFOREST(fd) < 4)
		return 0;

	len = RFIFOW(fd, 2);

	if (RFIFOREST(fd) < len)
		return 0;

	safestrncpy(channel_name, RFIFOCP(fd, 4), CHAN_NAME_LENGTH);

	channel = channel_name2channel(channel_name, NULL, 0);

	if (channel == NULL) {
		ShowInfo("Discord server sending to non-existing channel %s\n", channel_name);
		return 1;
	}

	safestrncpy(username, RFIFOCP(fd, 24), NAME_LENGTH);
	safestrncpy(msg, RFIFOCP(fd, 48), CHAT_SIZE_MAX - 4 - strlen(channel->alias) - strlen(username));

	safesnprintf(output, CHAT_SIZE_MAX, "%s %s : %s", channel->alias, username, RFIFOCP(fd, 48));
	clif_channel_msg(channel, output, channel->color);


	return 1;
}

/**
* Send channel message to discord server
* @param channel : channel that sent the message
* @param msg : message that was sent
* 0E04 <packet len>.W <channel name>.20B <message>.?B
*/
int bridge_send_message_to_disc(Channel * channel, char * msg)
{
	unsigned short msg_len = 0, len = 0;

	if (!channel || !msg || bridge_server.fd == -1)
		return 0;
	ShowInfo("Sending message %s\n", msg);
	msg_len = (unsigned short)(strlen(msg) + 1);

	if (msg_len > CHAT_SIZE_MAX - 24) {
		msg_len = CHAT_SIZE_MAX - 24;
	}

	len = msg_len + 24;

	WFIFOHEAD(bridge_server.fd, len);
	WFIFOW(bridge_server.fd, 0) = 0xE06;
	WFIFOW(bridge_server.fd, 2) = len;
	WFIFOB(bridge_server.fd, 4) = '#';
	safestrncpy(WFIFOCP(bridge_server.fd, 5), channel->name, 20);
	safestrncpy(WFIFOCP(bridge_server.fd, 24), msg, msg_len);
	WFIFOSET(bridge_server.fd, len);
	return 0;
}

int bridge_mail_savemessage(struct mail_message* msg)
{
	StringBuf buf;
	SqlStmt* stmt;
	int i, j;
	bool found = false;

	// build message save query
	StringBuf_Init(&buf);
	StringBuf_Printf(&buf, "INSERT INTO `%s` (`send_name`, `send_id`, `dest_name`, `dest_id`, `title`, `message`, `time`, `status`, `zeny`,`type`", "mail");
	StringBuf_Printf(&buf, ") VALUES (?, '%d', ?, '%d', ?, ?, '%lu', '%d', '%d', '%d'", msg->send_id, msg->dest_id, (unsigned long)msg->timestamp, msg->status, msg->zeny, msg->type);
	StringBuf_AppendStr(&buf, ")");

	// prepare and execute query
	stmt = SqlStmt_Malloc(mmysql_handle);
	if (SQL_SUCCESS != SqlStmt_PrepareStr(stmt, StringBuf_Value(&buf))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 0, SQLDT_STRING, msg->send_name, strnlen(msg->send_name, NAME_LENGTH))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 1, SQLDT_STRING, msg->dest_name, strnlen(msg->dest_name, NAME_LENGTH))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 2, SQLDT_STRING, msg->title, strnlen(msg->title, MAIL_TITLE_LENGTH))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 3, SQLDT_STRING, msg->body, strnlen(msg->body, MAIL_BODY_LENGTH))
		|| SQL_SUCCESS != SqlStmt_Execute(stmt))
	{
		SqlStmt_ShowDebug(stmt);
		StringBuf_Destroy(&buf);
		return msg->id = 0;
	}
	else
		msg->id = (int)SqlStmt_LastInsertId(stmt);

	SqlStmt_Free(stmt);

	StringBuf_Clear(&buf);
	StringBuf_Printf(&buf, "INSERT INTO `%s` (`id`, `index`, `amount`, `nameid`, `refine`, `attribute`, `identify`, `unique_id`, `bound`", "mail_attachments");
	for (j = 0; j < MAX_SLOTS; j++)
		StringBuf_Printf(&buf, ", `card%d`", j);
	for (j = 0; j < MAX_ITEM_RDM_OPT; ++j) {
		StringBuf_Printf(&buf, ", `option_id%d`", j);
		StringBuf_Printf(&buf, ", `option_val%d`", j);
		StringBuf_Printf(&buf, ", `option_parm%d`", j);
	}
	StringBuf_AppendStr(&buf, ") VALUES ");

	for (i = 0; i < MAIL_MAX_ITEM; i++) {
		// skip empty and already matched entries
		if (msg->item[i].nameid == 0)
			continue;

		if (found) {
			StringBuf_AppendStr(&buf, ",");
		}
		else {
			found = true;
		}

		StringBuf_Printf(&buf, "('%" PRIu64 "', '%hu', '%d', '%hu', '%d', '%d', '%d', '%" PRIu64 "', '%d'", (uint64)msg->id, i, msg->item[i].amount, msg->item[i].nameid, msg->item[i].refine, msg->item[i].attribute, msg->item[i].identify, msg->item[i].unique_id, msg->item[i].bound);
		for (j = 0; j < MAX_SLOTS; j++)
			StringBuf_Printf(&buf, ", '%hu'", msg->item[i].card[j]);
		for (j = 0; j < MAX_ITEM_RDM_OPT; ++j) {
			StringBuf_Printf(&buf, ", '%d'", msg->item[i].option[j].id);
			StringBuf_Printf(&buf, ", '%d'", msg->item[i].option[j].value);
			StringBuf_Printf(&buf, ", '%d'", msg->item[i].option[j].param);
		}
		StringBuf_AppendStr(&buf, ")");
	}

	if (found && SQL_ERROR == Sql_QueryStr(mmysql_handle, StringBuf_Value(&buf))) {
		Sql_ShowDebug(mmysql_handle);
	}

	StringBuf_Destroy(&buf);

	return msg->id;
}

TIMER_FUNC(auction_end_timer) {
	//struct auction_data *auction;
	//if ((auction = (struct auction_data *)idb_get(auction_db_, id)) != NULL)
	//{
	//	if (auction->buyer_id)
	//	{
	//		mail_sendmail(0, msg_txt(200), auction->buyer_id, auction->buyer_name, msg_txt(201), msg_txt(202), 0, &auction->item, 1);
	//		mapif_Auction_message(auction->buyer_id, 6); // You have won the auction
	//		mail_sendmail(0, msg_txt(200), auction->seller_id, auction->seller_name, msg_txt(201), msg_txt(203), auction->price, NULL, 0);
	//	}
	//	else
	//		mail_sendmail(0, msg_txt(200), auction->seller_id, auction->seller_name, msg_txt(201), msg_txt(204), 0, &auction->item, 1);

	//	ShowInfo("Auction End: id %u.\n", auction->auction_id);

	//	auction->auction_end_timer = INVALID_TIMER;
	//	bridge_auction_delete(auction);
	//}

	return 0;
}

void bridge_auction_delete(struct auction_data *auction)
{
	unsigned int auction_id = auction->auction_id;

	if (SQL_ERROR == Sql_Query(mmysql_handle, "DELETE FROM `%s` WHERE `auction_id` = '%d'", "auction", auction_id))
		Sql_ShowDebug(mmysql_handle);

	if (auction->auction_end_timer != INVALID_TIMER)
		delete_timer(auction->auction_end_timer, auction_end_timer);

	idb_remove(auction_db_, auction_id);
}

void inter_auctions_fromsql(void)
{
	int i;
	char *data;
	StringBuf buf;
	t_tick tick = gettick(), endtick;
	time_t now = time(NULL);

	StringBuf_Init(&buf);
	StringBuf_AppendStr(&buf, "SELECT `auction_id`,`seller_id`,`seller_name`,`buyer_id`,`buyer_name`,"
		"`price`,`buynow`,`hours`,`timestamp`,`nameid`,`item_name`,`type`,`refine`,`attribute`,`unique_id`");
	for (i = 0; i < MAX_SLOTS; i++)
		StringBuf_Printf(&buf, ",`card%d`", i);
	for (i = 0; i < MAX_ITEM_RDM_OPT; ++i) {
		StringBuf_Printf(&buf, ", `option_id%d`", i);
		StringBuf_Printf(&buf, ", `option_val%d`", i);
		StringBuf_Printf(&buf, ", `option_parm%d`", i);
	}
	StringBuf_Printf(&buf, " FROM `%s` ORDER BY `auction_id` DESC", "auction");

	if (SQL_ERROR == Sql_Query(mmysql_handle, StringBuf_Value(&buf)))
		Sql_ShowDebug(mmysql_handle);

	StringBuf_Destroy(&buf);

	while (SQL_SUCCESS == Sql_NextRow(mmysql_handle))
	{
		struct item *item;
		struct auction_data *auction;
		CREATE(auction, struct auction_data, 1);
		Sql_GetData(mmysql_handle, 0, &data, NULL); auction->auction_id = atoi(data);
		Sql_GetData(mmysql_handle, 1, &data, NULL); auction->seller_id = atoi(data);
		Sql_GetData(mmysql_handle, 2, &data, NULL); safestrncpy(auction->seller_name, data, NAME_LENGTH);
		Sql_GetData(mmysql_handle, 3, &data, NULL); auction->buyer_id = atoi(data);
		Sql_GetData(mmysql_handle, 4, &data, NULL); safestrncpy(auction->buyer_name, data, NAME_LENGTH);
		Sql_GetData(mmysql_handle, 5, &data, NULL); auction->price = atoi(data);
		Sql_GetData(mmysql_handle, 6, &data, NULL); auction->buynow = atoi(data);
		Sql_GetData(mmysql_handle, 7, &data, NULL); auction->hours = atoi(data);
		Sql_GetData(mmysql_handle, 8, &data, NULL); auction->timestamp = atoi(data);

		item = &auction->item;
		Sql_GetData(mmysql_handle, 9, &data, NULL); item->nameid = atoi(data);
		Sql_GetData(mmysql_handle, 10, &data, NULL); safestrncpy(auction->item_name, data, ITEM_NAME_LENGTH);
		Sql_GetData(mmysql_handle, 11, &data, NULL); auction->type = atoi(data);

		Sql_GetData(mmysql_handle, 12, &data, NULL); item->refine = atoi(data);
		Sql_GetData(mmysql_handle, 13, &data, NULL); item->attribute = atoi(data);
		Sql_GetData(mmysql_handle, 14, &data, NULL); item->unique_id = strtoull(data, NULL, 10);

		item->identify = 1;
		item->amount = 1;
		item->expire_time = 0;

		for (i = 0; i < MAX_SLOTS; i++)
		{
			Sql_GetData(mmysql_handle, 15 + i, &data, NULL);
			item->card[i] = atoi(data);
		}

		for (i = 0; i < MAX_ITEM_RDM_OPT; i++) {
			Sql_GetData(mmysql_handle, 15 + MAX_SLOTS + i * 3, &data, NULL);
			item->option[i].id = atoi(data);
			Sql_GetData(mmysql_handle, 16 + MAX_SLOTS + i * 3, &data, NULL);
			item->option[i].value = atoi(data);
			Sql_GetData(mmysql_handle, 17 + MAX_SLOTS + i * 3, &data, NULL);
			item->option[i].param = atoi(data);
		}

		if (auction->timestamp > now)
			endtick = ((unsigned int)(auction->timestamp - now) * 1000) + tick;
		else
			endtick = tick + 10000; // 10 Second's to process ended auctions

		auction->auction_end_timer = add_timer(endtick, auction_end_timer, auction->auction_id, 0);
		idb_put(auction_db_, auction->auction_id, auction);
	}

	Sql_FreeResult(mmysql_handle);
}

// sets map-server's user id
void bridge_setuserid(char *id) {
	memcpy(userid, id, NAME_LENGTH);
}

// sets map-server's password
void bridge_setpasswd(char *pwd) {
	memcpy(passwd, pwd, NAME_LENGTH);
}

/*==========================================
* Sets discord port to 'port'
*------------------------------------------*/
void bridge_setport(uint16 port)
{
	dis_port = port;
}

void do_init_bridge(void) {
	if ((bridge_fd = make_listen_bind(bind_ip, dis_port)) == -1) {
		ShowFatalError("Failed to bind to port '" CL_WHITE "%d" CL_RESET "'\n", dis_port);
		exit(EXIT_FAILURE);
	}

	auction_db_ = idb_alloc(DB_OPT_RELEASE_DATA);
	inter_auctions_fromsql();
}

void do_final_bridge(void) {
	auction_db_->destroy(auction_db_, NULL);
}

void bridge_on_disconnect()
{
	ShowStatus("Discord-server has disconnected.\n");
}
