/**
 * Stormbreaker (c) Epoque 2019. All rights reserved.
 */

#include "stormbreaker.hpp"

#include <stdlib.h>

#include "../common/db.hpp"
#include "../common/malloc.hpp"
#include "../common/nullpo.hpp"
#include "../common/showmsg.hpp"
#include "../common/strlib.hpp"
#include "../common/utils.hpp"

#include "battle.hpp"
#include "itemdb.hpp"
#include "log.hpp"
#include "npc.hpp"
#include "pc.hpp"
#include "pet.hpp"
#include "script.hpp"
#include "status.hpp"

/// Database of the variables used by NPCs for hiding
struct DBMap* npcvariables;

/// Database of the crafting materials
struct DBMap* craftdb;

/// Database of the enchantment materials
struct DBMap* enchantdb;

/// Database of the status bonuses
struct DBMap* statusbonusdb;

/*==========================================================================*
 * Enchantment
 *--------------------------------------------------------------------------*/

/**
 * Gets whether an item is available for enchantment.
 *
 * @param sd the player
 * @param index the index of the item
 */
bool storm_enchant_available(struct map_session_data* sd, uint16 index)
{
	int i, max;
	struct item_data* id;

	nullpo_retr(false, sd);
	
	if (!(id = sd->inventory_data[index]))
		return false;

	if (id->type == IT_WEAPON)
		max = battle_config.storm_enchant_weapon_max;
	else if (id->type == IT_ARMOR) {
		if (id->equip & (EQP_HEAD_TOP | EQP_HEAD_MID | EQP_HEAD_LOW))
			max = battle_config.storm_enchant_headgear_max;
		else if (id->equip & EQP_ACC)
			max = battle_config.storm_enchant_accessory_max;
		else if (id->equip & EQP_SHIELD)
			max = battle_config.storm_enchant_shield_max;
		else if (id->equip & EQP_SHOES)
			max = battle_config.storm_enchant_shoes_max;
		else if (id->equip & EQP_GARMENT)
			max = battle_config.storm_enchant_garment_max;
		else if (id->equip & EQP_ARMOR)
			max = battle_config.storm_enchant_garment_max;
		else
			return false;
	}

	max = min(max, MAX_ITEM_RDM_OPT);

	ARR_FIND(0, max, i, sd->inventory.u.items_inventory[index].option[i].id == 0);

	return i < max;

}

 /**
  * Attempts to enchant an item at the provided index, using the provided material.
  *
  * @param sd the player
  * @param index the index of the item
  * @param materialid the material id
  */
int storm_enchant_attempt(struct map_session_data* sd, uint16 index, uint16 materialid)
{
	int i, j;
	enchant_data* enchant;
	enchant_material* material;
	struct item_data* id;
	struct item* it;

	nullpo_retr(-1, sd);

	if (!(id = sd->inventory_data[index]))
		return 0;

	enchant = storm_enchant_get(id->nameid);

	if (enchant == nullptr)
		return 0;

	ARR_FIND(0, MAX_REFINE_MATERIALS, i, enchant->materials[i].material == materialid);

	if (i == MAX_REFINE_MATERIALS)
		return 0;

	material = &enchant->materials[i];

	it = &sd->inventory.u.items_inventory[index];

	ARR_FIND(0, MAX_ITEM_RDM_OPT, j, it->option[j].id == 0);

	if (j == MAX_ITEM_RDM_OPT)
		return 0;

	if (material->rate[j] <= rand() % 100)
	{
		if (material->flag&ENCHANT_FAIL_DESTROY)
			pc_delitem(sd, index, 1, 0, 0, LOG_TYPE_CONSUME);
		else if (material->flag&ENCHANT_FAIL_BREAK) {
			it->attribute = 1;
			if (it->equip)
				pc_unequipitem(sd, index, 3);
			else {
				clif_delitem(sd, index, 1, 3);
				clif_additem(sd, index, 1, 0);
			}
		}

		return 0;
	}

	ARR_FIND(0, MAX_ITEM_RDM_OPT, i, it->option[i].id == 0);

	if (i == MAX_ITEM_RDM_OPT)
		return 0;

	it->option[i].id = material->option;
	it->option[i].value = material->value;
	it->option[i].param = (char)material->param;

	if (it->equip)
		clif_equiplist(sd);

	log_pick_pc(sd, LOG_TYPE_CONSUME, -1, it);
	clif_delitem(sd, index, 1, 3);

	log_pick_pc(sd, LOG_TYPE_PRODUCE, 1, it);
	clif_additem(sd, index, 1, 0);

	return 1;
}

 /**
  * Gets an enchantment record for the provided item id.
  *
  * @param nameid the item id
  * @return an enchant_data* record, or nullptr otherwise
  */
enchant_data* storm_enchant_get(uint16 nameid) {
	return (enchant_data*)uidb_get(enchantdb, nameid);
}

/**
 * Splits the content of a column in the enchantment database.
 *
 * @param column the column value
 * @param value the value to receive the values
 * @param max the maximum number of values
 */
static void storm_enchant_split(char* column, int* value, int max)
{
	int i;

	for (i = 0; i < max; i++)
	{
		if (!column)
			break;

		value[i] = atoi(column);
		column = strchr(column, ':');

		if (column)
			*column++ = 0;
	}

	if (i > 0 && i < max)
	{
		for (; i < max; i++)
			value[i] = value[i - 1];
	}
}

 /**
  * Processes a row from the enchantment database.
  *
  * @param row the row content
  * @param columns the number of columns
  * @param line the current line number
  * @return true if the line is processed
  */
static bool storm_readdb_enchant_sub(char** row, int32 columns, int32 line)
{
	int i;
	unsigned int nameid = atoi(row[0]);
	unsigned int materialid = atoi(row[1]);
	int64 optionid;
	unsigned short optionval = atoi(row[3]);
	unsigned short optionparam = atoi(row[4]);
	int rate[MAX_REFINE_MATERIALS];
	int zeny[MAX_REFINE_MATERIALS];
	enchant_flag flags = ENCHANT_NONE;
	struct item_data* id;
	struct item_data* mid;
	enchant_data* ed;
	enchant_material* em;

	if (nameid < 0 || nameid >= MAX_ITEMID || !(id = itemdb_exists(nameid))) {
		ShowWarning("storm_readdb_enchant_sub: Invalid item %d in line %d of \"item_craft_db.txt\", skipping.\n", nameid, line);
		return false;
	}

	if (id->type != IT_ARMOR && id->type != IT_WEAPON && id->type != IT_SHADOWGEAR) {
		ShowWarning("storm_readdb_enchant_sub: Item %d is not an equipment in line %d of \"item_craft_db.txt\", skipping.\n", nameid, line);
		return false;
	}

	if (materialid < 0 || materialid >= MAX_ITEMID || !(mid = itemdb_exists(materialid))) {
		ShowWarning("storm_readdb_enchant_sub: Invalid item %d in line %d of \"item_craft_db.txt\", skipping.\n", materialid, line);
		return false;
	}

	script_number_or_constant(row[2], optionid) {
		ShowWarning("storm_readdb_enchant_sub: Invalid random option %s in line %d of \"item_craft_db.txt\", skipping.\n", row[2], line);
		return false;
	}

	storm_enchant_split(row[5], rate, MAX_REFINE_MATERIALS);
	storm_enchant_split(row[6], zeny, MAX_REFINE_MATERIALS);

	if (columns == 8) {
		flags = (enchant_flag)strtoul(row[7], nullptr, 0);
	}

	ed = (enchant_data*)uidb_get(enchantdb, nameid);

	if (ed == nullptr) {
		CREATE(ed, enchant_data, 1);
		memset(ed, 0, sizeof(enchant_data));
		ed->nameid = nameid;
		uidb_put(enchantdb, nameid, ed);
	}

	if (ed->count >= MAX_REFINE_MATERIALS) {
		ShowWarning("storm_readdb_enchant_sub: Item %d has already reached the maximum %d items, skipping.\n", id->nameid, MAX_REFINE_MATERIALS);
		return false;
	}

	ARR_FIND(0, MAX_REFINE_MATERIALS, i, ed->materials[i].material == mid->nameid);

	if (i < MAX_REFINE_MATERIALS) {
		ShowWarning("storm_readdb_enchant_sub: Material %d has already been added as an enchantment material for item %d, skipping.\n", mid->nameid, id->nameid);
		return false;
	}

	em = &ed->materials[ed->count++];
	em->flag = flags;
	em->material = mid->nameid;
	em->option = (unsigned short)optionid;
	em->value = optionval;
	em->param = optionparam;

	for (i = 0; i < MAX_REFINE_MATERIALS; i++) {
		em->rate[i] = cap_value(rate[i], 0, 100);
		em->zeny[i] = zeny[i];
	}

	return true;
}

 /**
  * Reads the enchantment database entries from the database file into memory.
  */
void storm_enchant_read(void)
{
	sv_readdb(db_path, "item_enchant_db.txt", ',', 7, 8, -1, storm_readdb_enchant_sub, false);
}

/**
 * Destroys a record in the item enchantment database.
 */
static int storm_enchant_final_sub(DBKey key, DBData* data, va_list ap)
{
	enchant_data* ed = (enchant_data*)db_data2ptr(data);

#ifdef DEBUG
	memset(ed, 0xDD, sizeof(enchant_data));
#endif

	aFree(ed);

	return 0;
}

/**
 * Reload the item enchantment database.
 */
void storm_enchant_reload(void)
{
	enchantdb->clear(enchantdb, storm_enchant_final_sub);
	storm_enchant_read();
}

/*==========================================================================*
 * Bazaar
 *--------------------------------------------------------------------------*/

#ifdef STORM_BAZAAR

/// Bazaar entries
struct DBMap* bazaardb;

/// Bazaar search entries used to speed up sold item processing
struct DBMap* bazaarsearchdb;

/// The name of the cut-in to use when a bazaar item has been unlocked
static const char* bazaar_cutin = "bazaar.bmp";

/**
 * Called when the timer for a bazaar cut-in has expired.
 *
 * @param tid the timer ID
 * @param tick the timer tick
 * @param id the player id
 * @param data the optional data
 */
static int storm_bazaar_clearcutin(int tid, t_tick tick, int id, intptr_t data)
{
	struct map_session_data* sd;

	if ((sd = map_id2sd(id))) {
		clif_cutin(sd, bazaar_cutin, 255);
		sd->bazaar_timer_id = INVALID_TIMER;
	}

	return 0;
}

/**
 * Completes a bazaar entry for the provided player.
 *
 * @param sd the player
 * @param entry the bazaar database entry
 * @return true if the bazaar was completed; otherwise, false
 */
static bool storm_bazaar_complete(struct map_session_data* sd, bazaar* entry)
{
	int i, j;
	bazaarunlocked* buy;
	struct item_data* id;

	if (!battle_config.storm_bazaar)
		return false;

	nullpo_retr(false, sd);
	nullpo_retr(false, entry);

	if (!entry->nameid || !(id = itemdb_exists(entry->nameid)))
		return false;

	ARR_FIND(0, MAX_BAZAAR_ITEMS, i, sd->status.bazaar_unlocked[i].bazaarid == entry->id);

	if (i < MAX_BAZAAR_ITEMS)
	{
		if (entry->flags & (BZF_ONE_TIME_ACCOUNT | BZF_UNLIMITED) || !(entry->flags & BZF_REPEAT))
			return false;

		buy = &sd->status.bazaar_unlocked[i];
		buy->available += entry->max;
	}
	else
	{
		ARR_FIND(0, MAX_BAZAAR_ITEMS, i, sd->status.bazaar_unlocked[i].bazaarid == 0);

		if (i == MAX_BAZAAR_ITEMS)
			return false;

		buy = &sd->status.bazaar_unlocked[i];
		buy->bazaarid = entry->id;
		buy->available = entry->max;

		if (entry->flags & BZF_ONE_TIME_ACCOUNT)
			buy->accountid = sd->status.account_id;
	}

	for (i = 0; i < entry->count; i++)
	{
		uint16 amount;

		ARR_FIND(0, MAX_BAZAAR_SELL, j, sd->status.bazaar_sold[j].nameid == entry->items[i].nameid);

		if (j == MAX_BAZAAR_SELL)
			continue;

		amount = entry->items[i].amount;

		if (amount > sd->status.bazaar_sold[j].amount)
			sd->status.bazaar_sold[j].amount = 0;
		else
			sd->status.bazaar_sold[j].amount -= amount;
	}

	if (battle_config.storm_bazaar_notice == 2) {
		char message[CHAT_SIZE_MAX];
		memset(message, 0, sizeof(message));

		snprintf(message, sizeof(message), msg_txt(sd, 1524), id->jname, entry->max);
		clif_messagecolor(&sd->bl, color_table[COLOR_WHITE], message, false, SELF);
	}

	return true;
}

/**
 * Gets whether a player has sold enough of the required items for unlock an entry.
 *
 * @param sold the player sold items
 * @param entry the bazaar database entry
 */
static bool storm_bazaar_has_requirements(bazaarsolditem* sold, bazaar* entry)
{
	int i, j;

	nullpo_retr(false, sold);
	nullpo_retr(false, entry);

	for (i = 0; i < entry->count; i++)
	{
		ARR_FIND(0, MAX_BAZAAR_SELL, j, sold[j].nameid == entry->items[i].nameid);

		if (j == MAX_BAZAAR_SELL)
			return false;

		if (sold[j].amount < entry->items[i].amount)
			return false;
	}

	return true;
}

/**
 * Processes when an item has been sold to an NPC and must be counted toward the bazaar shop.
 *
 * @param sd the player
 * @param item the item
 * @param amount the amount
 */
void storm_bazaar_sold(struct map_session_data* sd, uint16 item, uint16 amount)
{
	int i;
	bazaarsearch* search;
	bazaarsearch* check;
	bazaarsolditem* sold;
	bool completed = false;

	if (!battle_config.storm_bazaar)
		return;

	nullpo_retv(sd);

	if (item < 1 || item >= MAX_ITEMID || !itemdb_exists(item) || !amount)
		return;

	search = (bazaarsearch*)uidb_get(bazaarsearchdb, item);

	if (search == nullptr)
		return;

	for (check = search; check != nullptr; check = check->next)
	{
		bazaar* entry = check->entry;

		if (entry == nullptr)
			continue;

		ARR_FIND(0, MAX_BAZAAR_ITEMS, i, sd->status.bazaar_unlocked[i].bazaarid == entry->id);

		if (i == MAX_BAZAAR_ITEMS || entry->flags & BZF_REPEAT)
			break;
	}

	if (check == nullptr)
		return;

	ARR_FIND(0, MAX_BAZAAR_SELL, i, sd->status.bazaar_sold[i].nameid == item || sd->status.bazaar_sold[i].nameid == 0);

	if (i == MAX_BAZAAR_SELL)
		return;

	sold = &sd->status.bazaar_sold[i];

	if (sold->nameid)
		sold->amount = cap_value(sold->amount + amount, 0, USHRT_MAX);
	else
	{
		sold->nameid = item;
		sold->amount = amount;
	}

	for (; search != nullptr; search = search->next)
	{
		bazaar* entry = search->entry;

		if (entry == nullptr)
			continue;
		
		ARR_FIND(0, MAX_BAZAAR_ITEMS, i, sd->status.bazaar_unlocked[i].bazaarid == entry->id);

		if (i < MAX_BAZAAR_ITEMS && (entry->flags & (BZF_ONE_TIME_ACCOUNT | BZF_UNLIMITED) || !(entry->flags & BZF_REPEAT)))
			continue;

		if (storm_bazaar_has_requirements(sd->status.bazaar_sold, entry))
			completed |= storm_bazaar_complete(sd, entry);
	}

	if (!completed)
		return;

	if (battle_config.storm_bazaar_notice == 1) {
		char message[CHAT_SIZE_MAX];
		memset(message, 0, sizeof(message));

		snprintf(message, sizeof(message), msg_txt(sd, 1520));
		clif_messagecolor(&sd->bl, color_table[COLOR_WHITE], message, false, SELF);
	}

	if (battle_config.storm_bazaar_cutin && sd->bazaar_timer_id == INVALID_TIMER) {
		clif_cutin(sd, bazaar_cutin, 1);
		sd->bazaar_timer_id = add_timer(gettick() + battle_config.storm_bazaar_cutin, storm_bazaar_clearcutin, sd->bl.id, NULL);
	}
}

#define BAZAAR_ITEM_UNLIMITED_AMOUNT 999

/**
 * Creates a list of the items which can be bought at a bazaar shop.
 *
 * @param sd the player
 * @param nd the shop
 * @return a list containing the results
 */
bazaarlist storm_bazaar_list(struct map_session_data* sd, struct npc_data* nd)
{
	int i, j;
	bazaarlist list;
	bazaarunlocked* available;

	memset(&list, 0, sizeof(list));

	nullpo_retr(list, sd);
	nullpo_retr(list, nd);

	if (nd->subtype != NPCTYPE_BAZAARSHOP)
		return list;

	available = sd->status.bazaar_unlocked;

	for (i = 0; list.count < MAX_BAZAAR_SHOP && i < MAX_BAZAAR_ITEMS; i++)
	{
		uint16 amount;
		uint16 count;
		bazaar* entry;
		bool single = false;
		struct item_data* id;

		if (available[i].bazaarid == 0)
			break;

		if (available[i].bazaarid >= MAX_BAZAAR ||
			available[i].bought >= available[i].available)
			continue;

		entry = (bazaar*)uidb_get(bazaardb, available[i].bazaarid);

		if (entry == nullptr || entry->nameid == 0 || !(id = itemdb_exists(entry->nameid)))
			continue;

		single = !itemdb_isstackable2(id) || id->flag.guid > 0;

		if (nd->u.shop.count > 0) {
			ARR_FIND(0, nd->u.shop.count, j, nd->u.shop.shop_item[j].nameid == entry->nameid);

			if (j == nd->u.shop.count)
				continue;
		}

		amount = available[i].available - available[i].bought;
		count = single ? 1 : amount;

		ARR_FIND(0, MAX_BAZAAR_SHOP, j, list.items[j].nameid == entry->nameid);

		if (j < MAX_BAZAAR_SHOP)
		{
			if (entry->flags & BZF_UNLIMITED)
				continue;

			list.items[j].amount += count;
		}
		else
		{
			list.items[list.count].nameid = entry->nameid;
			list.items[list.count].cost = entry->cost;

			if (entry->flags & BZF_UNLIMITED && !single)
				list.items[list.count].amount = BAZAAR_ITEM_UNLIMITED_AMOUNT;
			else
				list.items[list.count].amount = count;

			list.count++;
		}
	}

	return list;
}

/**
 * Purchases a collection of items from a bazaar shop.
 *
 * @param sd the player
 * @param data the item list
 * @param count the item list count
 */
void storm_bazaar_purchase(struct map_session_data* sd, const uint8* data, uint16 count)
{
	double zeny;
	int i, j, weight, add;
	bazaar* entry;
	bazaarunlocked* buy;
	bazaarlist list;
	struct npc_data* nd;
	struct item_data* id;

	if (!battle_config.storm_bazaar)
		return;

	nullpo_retv(sd);
	nullpo_retv(nd = map_id2nd(sd->bazaar_shop_id));
	nullpo_retv(data);

	list = storm_bazaar_list(sd, nd);

	if (list.count == 0) {
		clif_buyvending(sd, 0, 0, 6);
		return;
	}

	zeny = 0;
	weight = 0;
	add = 0;

	buy = sd->status.bazaar_unlocked;

	for (i = 0; i < count; i++)
	{
		uint32 cost = 0;
		uint16 index = *(uint16*)(data + 4 * i + 2) - 2;
		uint16 amount = *(uint16*)(data + 4 * i + 0);
		uint16 available = 0;
		uint16 item;

		if (index < 0 || index >= list.count) {
			clif_buyvending(sd, 0, 0, 6);
			return;
		}

		item = list.items[index].nameid;

		if (!itemdb_exists(item)) {
			clif_buyvending(sd, index + 2, amount, 4);
			return;
		}

		for (j = 0; j < MAX_BAZAAR_ITEMS; j++)
		{
			bool single;

			if (buy[j].bazaarid == 0)
				break;

			entry = (bazaar*)uidb_get(bazaardb, buy[j].bazaarid);

			if (entry == nullptr || entry->nameid != item)
				continue;

			if ((buy[j].bought >= buy[j].available) && !(entry->flags & BZF_UNLIMITED))
				continue;

			if (!(id = itemdb_exists(entry->nameid)))
				continue;

			single = !itemdb_isstackable2(id) || id->flag.guid > 0;

			if (!cost)
				cost = entry->cost;

			if (entry->flags & BZF_UNLIMITED && !single) {
				available = BAZAAR_ITEM_UNLIMITED_AMOUNT;
				break;
			}

			if (single)
				available = amount = *(uint16*)(data + 4 * i + 0) = 1;
			else
				available += buy[j].available - buy[j].bought;
		}

		if (j == MAX_BAZAAR_ITEMS || available < amount) {
			clif_buyvending(sd, index + 2, amount, 4);
			return;
		}

		if (!itemdb_isstackable2(id) && amount > 1)
			amount = *(uint16*)(data + 4 * i + 0) = 1;
		
		switch (pc_checkadditem(sd, item, amount))
		{
			case CHKADDITEM_NEW:
				add++;
				break;

			case CHKADDITEM_OVERAMOUNT:
				clif_buyvending(sd, i + 2, amount, 2);
				return;
		}

		if (!(entry->flags & BZF_NO_DISCOUNT))
			cost = (uint32)pc_modifybuyvalue(sd, (int)cost);

		zeny += (double)cost * amount;
		weight += itemdb_weight(item) * amount;
	}

	if (zeny > (double)sd->status.zeny) {
		clif_buyvending(sd, 0, 0, 1);
		return;
	}

	if (weight + sd->weight > sd->max_weight) {
		clif_buyvending(sd, 0, 0, 2);
		return;
	}

	pc_payzeny(sd, (int)zeny, LOG_TYPE_NPC, nullptr);

	for (i = 0; i < count; i++)
	{
		uint16 item;
		uint16 index = *(uint16*)(data + 4 * i + 2) - 2;
		uint16 amount = *(uint16*)(data + 4 * i + 0);
		uint16 remaining = amount;
		bazaar* current = nullptr;

		if (index < 0 || index >= list.count) {
			clif_buyvending(sd, 0, 0, 6);
			return;
		}

		item = list.items[index].nameid;

		for (j = 0; 0 < remaining && j < MAX_BAZAAR_ITEMS; j++)
		{
			uint16 remove;

			if (buy[j].bazaarid == 0)
				break;

			entry = (bazaar*)uidb_get(bazaardb, buy[j].bazaarid);

			if (entry == nullptr || entry->nameid != item)
				continue;

			if (entry->flags & BZF_UNLIMITED) {
				remaining = 0;
				break;
			}

			if (buy[j].bought >= buy[j].available)
				continue;

			if (current == nullptr)
				current = entry;

			remove = min(remaining, buy[j].available);

			buy[j].bought += remove;
			remaining -= remove;
		}

		if (remaining > 0) {
			clif_buyvending(sd, index + 2, amount, 4);
			return;
		}

		if (itemdb_type(item) == IT_PETEGG)
			pet_create_egg(sd, item);
		else {
			struct item_data* id = itemdb_search(item);
			struct item it;
			memset(&it, 0, sizeof(it));

			it.nameid = item;
			it.identify = 1;
			STORM_DURABILITY(id, it);

			if (current && current->flags & BZF_BOUND_CHAR)
				it.bound = 1;

			pc_additem(sd, &it, amount, LOG_TYPE_NPC);
		}
	}
}

/**
 * Destroys a record in the bazaar database.
 */
static int storm_bazaar_final_sub(DBKey key, DBData* data, va_list ap)
{
	bazaar* entry = (bazaar*)db_data2ptr(data);

#ifdef DEBUG
	memset(entry, 0xDD, sizeof(bazaar));
#endif

	aFree(entry);

	return 0;
}


/**
 * Destroys a record in the bazaar search database.
 */
static int storm_bazaarsearch_final_sub(DBKey key, DBData* data, va_list ap)
{
	bazaarsearch* search = (bazaarsearch*)db_data2ptr(data);

	while (search != nullptr) {
		bazaarsearch* next = search->next;
		aFree(search);
		search = next;
	}

	return 0;
}

/**
 * Process the content of a line within the bazaar database.
 *
 * @param row the row content
 * @param columns the number of columns
 * @param line the line number
 */
static bool storm_readdb_bazaar_sub(char** row, int columns, int line)
{
	int i;
	unsigned short id = atoi(row[0]);
	unsigned short nameid = atoi(row[1]);
	bazaar_flag flags = (bazaar_flag)strtoull(row[2], nullptr, 0);
	unsigned short limit = atoi(row[3]);
	unsigned int cost = atoi(row[4]);
	bazaar* entry;

	if (id < 0 || id >= MAX_BAZAAR) {
		ShowWarning("storm_readdb_bazaar_sub: Invalid id %d in line %d of \"item_bazaar_db.txt\", skipping.\n", id, line);
		return false;
	}

	if (uidb_exists(bazaardb, id)) {
		ShowWarning("storm_readdb_bazaar_sub: Duplicate bazaar id in line %d of \"item_bazaar_db.txt\", skipping.\n", id, line);
		return false;
	}

	if (nameid < 0 || nameid >= MAX_ITEMID || !itemdb_exists(nameid)) {
		ShowWarning("storm_readdb_bazaar_sub: Invalid item %d in line %d of \"item_bazaar_db.txt\", skipping.\n", nameid, line);
		return false;
	}

	CREATE(entry, bazaar, 1);
	memset(entry, 0, sizeof(bazaar));

	entry->id = id;
	entry->cost = cost;
	entry->nameid = nameid;
	entry->flags = flags;
	entry->max = limit;

	for (i = 0; i < MAX_BAZAAR_ENTRY && i < (columns - 5); i++)
	{
		unsigned short item;
		unsigned short amount;
		char* p = row[5 + i];

		item = atoi(p);
		p = strchr(p, ':');

		if (p)
		{
			*p++ = '\0';
			amount = atoi(p);
		}

		if (p == nullptr || amount < 1 || item < 1 || item >= MAX_ITEMID || !itemdb_exists(item)) {
			ShowWarning("storm_readdb_bazaar_sub: Invalid item requirement in line %d of \"item_bazaar_db.txt\", skipping.\n", line);
			aFree(entry);
			return false;
		}

		entry->items[entry->count].nameid = item;
		entry->items[entry->count].amount = amount;
		entry->count++;
	}

	uidb_put(bazaardb, id, entry);
	
	for (i = 0; i < MAX_BAZAAR_ENTRY; i++)
	{
		bazaarsearch* search;
		bazaarsearch* node;

		nameid = entry->items[i].nameid;

		if (nameid == 0)
			break;

		CREATE(search, bazaarsearch, 1);
		memset(search, 0, sizeof(bazaarsearch));
		search->entry = entry;

		node = (bazaarsearch*)uidb_get(bazaarsearchdb, nameid);

		if (node == nullptr)
			uidb_put(bazaarsearchdb, nameid, search);
		else {
			while (node->next != nullptr)
				node = node->next;

			node->next = search;
			search->prev = node;
		}
	}

	return true;
}

/**
 * Read the bazaar database.
 */
void storm_bazaar_read(void)
{
	if (battle_config.storm_bazaar)
		sv_readdb(db_path, "item_bazaar_db.txt", ',', 5, 4 + MAX_BAZAAR_ENTRY, -1, storm_readdb_bazaar_sub, false);
}

/**
 * Reload the bazaar database.
 */
void storm_bazaar_reload(void)
{
	bazaardb->clear(bazaardb, storm_bazaar_final_sub);
	bazaarsearchdb->clear(bazaarsearchdb, storm_bazaarsearch_final_sub);
	storm_bazaar_read();
}

#endif // STORM_BAZAAR

/*==========================================================================*
 * Crafting
 *--------------------------------------------------------------------------*/

/**
 * Attempts to craft an item at the provided index, using the provided material.
 *
 * @param sd the player
 * @param index the index of the item
 * @param materialid the material id
 */
int storm_craft_attempt(struct map_session_data* sd, uint16 index, uint16 materialid)
{
	int i;
	craft_data* craft;
	craft_material* material;
	struct item_data* id;
	struct item* it;
	struct item result;

	nullpo_retr(-1, sd);

	if (!(id = sd->inventory_data[index]))
		return -1;

	craft = storm_craft_get(id->nameid);

	if (craft == nullptr)
		return -1;

	ARR_FIND(0, MAX_REFINE_MATERIALS, i, craft->materials[i].material == materialid);

	if (i == MAX_REFINE_MATERIALS)
		return -1;

	material = &craft->materials[i];

	if (material->rate <= rand() % 100)
		return -1;

	it = &sd->inventory.u.items_inventory[index];

	memset(&result, 0, sizeof(result));

	result.amount = 1;
	result.bound = it->bound;
	result.nameid = material->nameid;
	result.identify = 1;

	if (id->type == IT_ARMOR || id->type == IT_WEAPON || id->type == IT_SHADOWGEAR)
	{
		if (material->flag & CRAFT_KEEP_REFINE)
			result.refine = it->refine;

		if (material->flag & CRAFT_KEEP_RANDOPT)
			memcpy(result.option, it->option, sizeof(result.option));

		if (material->flag & CRAFT_KEEP_SLOTS)
			memcpy(result.card, it->card, sizeof(result.card));

#ifdef STORM_ITEM_DURABILITY
		if (material->flag & CRAFT_KEEP_DURABILITY)
			result.durability = it->durability;
#endif
	}

	if (it->equip)
		pc_unequipitem(sd, index, 0);

	if (pc_delitem(sd, index, 1, 0, 0, LOG_TYPE_CONSUME))
		return -1;

	if (pc_additem(sd, &result, 1, LOG_TYPE_PRODUCE))
		return -1;

	if (result.unique_id)
		ARR_FIND(0, MAX_INVENTORY, i, sd->inventory.u.items_inventory[i].unique_id == result.unique_id);
	else
		i = pc_search_inventory(sd, material->nameid);

	return i;
}

/**
 * Gets a crafting record for the provided item id.
 *
 * @param nameid the item id
 * @return a craft_data* record, or nullptr otherwise
 */
craft_data* storm_craft_get(uint16 nameid) {
	return (craft_data*)uidb_get(craftdb, nameid);
}

/**
 * Processes a row from the crafting database.
 *
 * @param row the row content
 * @param columns the number of columns
 * @param line the current line number
 * @return true if the line is processed
 */
static bool storm_readdb_craft_sub(char** row, int32 columns, int32 line)
{
	int i;
	unsigned int nameid = atoi(row[0]);
	unsigned int makeid = atoi(row[1]);
	unsigned int materialid = atoi(row[2]);
	unsigned short rate = atoi(row[3]);
	unsigned int cost = atoi(row[4]);
	craft_flag flags = CRAFT_NONE;
	struct item_data* id;
	struct item_data* cid;
	struct item_data* mid;
	craft_data* cd;
	craft_material* cm;

	if (nameid < 0 || nameid >= MAX_ITEMID || !(id = itemdb_exists(nameid))) {
		ShowWarning("storm_readdb_craft_sub: Invalid item %d in line %d of \"item_craft_db.txt\", skipping.\n", nameid, line);
		return false;
	}

	if (makeid < 0 || makeid >= MAX_ITEMID || !(cid = itemdb_exists(makeid))) {
		ShowWarning("storm_readdb_craft_sub: Invalid item %d in line %d of \"item_craft_db.txt\", skipping.\n", makeid, line);
		return false;
	}

	if (materialid < 0 || materialid >= MAX_ITEMID || !(mid = itemdb_exists(materialid))) {
		ShowWarning("storm_readdb_craft_sub: Invalid item %d in line %d of \"item_craft_db.txt\", skipping.\n", materialid, line);
		return false;
	}

	if (columns == 6) {
		flags = (craft_flag)strtoul(row[5], nullptr, 0);
	}
	
	cd = (craft_data*)uidb_get(craftdb, nameid);

	if (cd == nullptr) {
		CREATE(cd, craft_data, 1);
		memset(cd, 0, sizeof(craft_data));
		cd->nameid = nameid;
		uidb_put(craftdb, nameid, cd);
	}

	if (cd->count >= MAX_REFINE_MATERIALS) {
		ShowWarning("storm_readdb_craft_sub: Item %d has already reached the maximum %d items, skipping.\n", id->nameid, MAX_REFINE_MATERIALS);
		return false;
	}

	ARR_FIND(0, MAX_REFINE_MATERIALS, i, cd->materials[i].material == mid->nameid);

	if (i < MAX_REFINE_MATERIALS) {
		ShowWarning("storm_readdb_craft_sub: Material %d has already been added as a crafting material for item %d, skipping.\n", mid->nameid, id->nameid);
		return false;
	}

	cm = &cd->materials[cd->count++];
	cm->flag = flags;
	cm->material = mid->nameid;
	cm->nameid = cid->nameid;
	cm->rate = cap_value(rate, 0, 100);
	cm->zeny = cost;

	return true;
}

/**
 * Reads the crafting database entries from the database file into memory.
 */
void storm_craft_read(void)
{
	sv_readdb(db_path, "item_craft_db.txt", ',', 5, 6, -1, storm_readdb_craft_sub, false);
}

/**
 * Destroys a record in the item crafting database.
 */
static int storm_craft_final_sub(DBKey key, DBData* data, va_list ap)
{
	craft_data* cd = (craft_data*)db_data2ptr(data);

#ifdef DEBUG
	memset(cd, 0xDD, sizeof(craft_data));
#endif

	aFree(cd);

	return 0;
}

/**
 * Reload the item crafting database.
 */
void storm_craft_reload(void)
{
	craftdb->clear(craftdb, storm_craft_final_sub);
	storm_craft_read();
}

/*==========================================================================*
 * NPC Variables
 *--------------------------------------------------------------------------*/

/**
 * Clears all NPC variables from the system, used when reloading scripts.
 */
void storm_clear_npcvar(void)
{
	db_clear(npcvariables);
}

/**
 * Registers an NPC variable within the system.
 *
 * @param nd the npc
 * @param value the variable
 */
void storm_set_npcvar(struct npc_data* nd, const char* value)
{
	nullpo_retv(nd);
	nullpo_retv(value);

	if (!*value)
		return;

	safestrncpy(nd->variable, value, sizeof(nd->variable));

	if (strdb_exists(npcvariables, value))
		return;

	strdb_put(npcvariables, nd->variable, nd);
}

 /**
  * Checks whether a provided player has a required NPC variable.
  *
  * @param sd the player
  * @param nd the npc
  * @return true if the variable exists, or false otherwise
  */
bool storm_has_npcvar(struct map_session_data* sd, struct npc_data* nd)
{
	nullpo_retr(false, sd);
	nullpo_retr(false, nd);

	if (!sd->vars_ok)
		return false;

	if (nd && *nd->variable) {
		int64 uid = reference_uid(add_str(nd->variable), 0);
		int value = pc_readglobalreg(sd, uid);
		return value > 0;
	}

	return true;
}

/**
 * Checks whether a provided variable is an NPC variable.
 *
 * @param value the variable
 * @return true if the variable is an NPC variable, or false otherwise
 */
bool storm_is_npcvar(const char* value)
{
	return strdb_exists(npcvariables, value);
}

/*==========================================================================*
 * Script Commands
 *--------------------------------------------------------------------------*/

/**
 * Adds a status bonus to the internal database for cache performance increase.
 *
 * @param bonus the bonus script
 */
static void storm_statusbonus_add_script(const char* bonus)
{
	if (strdb_get(statusbonusdb, bonus) == nullptr)
	{
		struct script_code* script = parse_script(bonus, "statusbonus", 0, 0);

		if (script)
			strdb_put(statusbonusdb, bonus, script);
	}
}

/**
 * Called when the system is shutdown and must release the status bonuses.
 *
 * @param key the key
 * @param data the data
 * @param ap the args
 * @return 0 if successful
 */
static int storm_statusbonus_final_sub(DBKey key, DBData* data, va_list ap)
{
	struct script_code* script = static_cast<script_code*>(db_data2ptr(data));

	if (script)
		script_free_code(script);

	return 0;
}

/**
 * Runs a status bonus against the provided player.
 *
 * @param sd the player
 * @param bonus the bonus script
 */
void storm_statusbonus_run_script(struct map_session_data* sd, std::vector<s_statusbonus_entry>& entries)
{
	for (auto& it : entries)
	{
		struct script_code* script;

		if (it.active)
			continue;

		script = (struct script_code*)strdb_get(statusbonusdb, it.script);

		if (script)
		{
			it.active = true;
			run_script(script, 0, sd->bl.id, 0);
		}
	}
}

/**
 * Adds a status bonus to the provided player using the provided status type and script.
 *
 * @param sd the player
 * @param type the status type
 * @param script the bonus script
 */
void storm_statusbonus_add(struct map_session_data* sd, sc_type type, const char* script)
{
	s_statusbonus bonus = {};
	s_statusbonus_entry entry = {};

	nullpo_retv(sd);
	nullpo_retv(script);

	entry.active = false;
	entry.script = aStrdup(script);

	for (auto& it : sd->statusbonus)
	{
		if (it.type != type)
			continue;

		it.entries.push_back(entry);
		return;
	}

	bonus.type = type;
	bonus.entries.push_back(entry);

	sd->statusbonus.push_back(bonus);
	storm_statusbonus_add_script(script);
}

/**
 * Clears all status bonuses from the provided player, used mainly when calculating the player.
 *
 * @param sd the player
 */
void storm_statusbonus_clear(struct map_session_data* sd)
{
	nullpo_retv(sd);

	for (auto& it : sd->statusbonus)
	{
		if (it.entries.empty())
			continue;

		for (auto& eit : it.entries)
			aFree(eit.script);
	}

	sd->statusbonus.clear();
}

/**
 * Processes an inventory select script command by populating an inventory list.
 *
 * @param sd the player
 * @param flag the search flag
 * @param equip the equipment mask
 * @param filter the list of item IDs
 * @param filter_count the number of filters
 * @return the matched items
 */
inventoryselect storm_inventoryselect(struct map_session_data* sd, inventoryselect_flag flag, enum equip_pos equip, uint16 filter[MAX_INVENTORY_SELECT_FILTER], int filter_count)
{
	int i, j;
	inventoryselect result;

	memset(&result, 0, sizeof(result));

	nullpo_retr(result, sd);

	for (i = 0; i < MAX_INVENTORY && result.count < MAX_INVENTORY_SELECT_RESULT; i++)
	{
		struct item_data* id;
		struct item* it;

		if (!(id = sd->inventory_data[i]))
			continue;

		it = &sd->inventory.u.items_inventory[i];

		if (it->nameid == 0 || it->amount == 0 || it->equip)
			continue;

		if (!it->identify && !(flag & ISF_SHOW_UNIDENTIFIED))
			continue;

		if (it->attribute & !(flag & ISF_SHOW_BROKEN))
			continue;

		if (filter_count > 0)
		{
			ARR_FIND(0, MAX_INVENTORY_SELECT_FILTER, j, filter[j] == id->nameid);

			if (j == MAX_INVENTORY_SELECT_FILTER)
				continue;

			result.positions[result.count] = i;
		}
		else
		{
			switch (id->type)
			{
				case IT_HEALING: if (!(flag & ISF_HEALING)) continue; break;
				case IT_USABLE: if (!(flag & ISF_USABLE)) continue; break;
				case IT_ETC: if (!(flag & ISF_ETC)) continue; break;
				case IT_ARMOR:
				case IT_WEAPON: if (!(flag & ISF_EQUIP)) continue; break;
				case IT_CARD: if (!(flag & ISF_CARD)) continue; break;
				case IT_PETEGG: if (!(flag & ISF_PET_EGG)) continue; break;
				case IT_PETARMOR: if (!(flag & ISF_PET_EQUIP)) continue; break;
				case IT_AMMO: if (!(flag & ISF_AMMO)) continue; break;
				case IT_DELAYCONSUME: if (!(flag & ISF_USABLE_DELAY)) continue; break;
				case IT_SHADOWGEAR: if (!(flag & ISF_SHADOW)) continue; break;
				case IT_CASH: if (!(flag & ISF_USABLE_CONFIRM)) continue; break;
				default: continue;
			}
			
			if ((id->type == IT_ARMOR || id->type == IT_WEAPON) && !(id->equip & equip))
				continue;

			result.positions[result.count] = i;
		}

		result.count++;
	}

	return result;
}

/**
 * Opens a player-specific shop using the provided item list and flags.
 *
 * @param sd the player
 * @param items the item list
 * @parma count the item list count
 * @param flags the shop flags
 * @param item the optional item (flags&OSHP_ITEMSHOP)
 * @param points the optiona points variable (flags&OSHP_POINTSHOP)
 */
void storm_openshop(struct map_session_data* sd, struct npc_item_list* items, uint16 count, openshop_flag flags, uint16 item, const char* points)
{
	int i;
	openshoplist* shop;

	nullpo_retv(sd);
	nullpo_retv(items);

	if (sd->openshop || !count)
		return;

	if (flags&OSHP_ITEMSHOP && (!item || !itemdb_exists(item))) {
		ShowWarning("storm_openshop: Invalid item shop item %d provided\n", item);
		return;
	}

	if (flags&OSHP_POINTSHOP && (!points || !*points)) {
		ShowWarning("storm_openshop: Invalid point shop variable provided\n");
		return;
	}

	for (i = 0; i < count; i++) {
		struct npc_item_list* it = &items[i];

		if (!it->nameid || !it->value || !itemdb_exists(it->nameid)) {
			ShowWarning("storm_openshop: Invalid item %d with value %d provided\n", it->nameid, it->value);
			return;
		}
	}

	CREATE(shop, openshoplist, 1);
	memset(shop, 0, sizeof(openshoplist));

	shop->count = count;
	shop->flag = flags;
	shop->type = NPCTYPE_SHOP;
	shop->discount = !(flags & OSHP_NODISCOUNT);

	CREATE(shop->shop_item, struct npc_item_list, count);
	memcpy(shop->shop_item, items, sizeof(struct npc_item_list) * count);

	if (flags&OSHP_CASHSHOP)
		shop->type = NPCTYPE_CASHSHOP;
	if (flags&OSHP_ITEMSHOP) {
		shop->itemshop_nameid = item;
		shop->type = NPCTYPE_ITEMSHOP;
	} else if (flags&OSHP_POINTSHOP) {
		safestrncpy(shop->pointshop_str, points, sizeof(shop->pointshop_str));
		shop->type = NPCTYPE_POINTSHOP;
	}

	sd->openshop = shop;

	switch (shop->type)
	{
		case NPCTYPE_SHOP:
			clif_openshop_buylist(sd);
			break;
		case NPCTYPE_CASHSHOP:
		case NPCTYPE_ITEMSHOP:
		case NPCTYPE_POINTSHOP:
			clif_openshop_cashlist(sd);
			break;
	}
}

/**
 * Process the purchase of items on offer in a player-specific shop.
 *
 * @param sd the player
 * @param list the buying list
 * @param count the number of items on the list
 * @return the result code for the response
 */
int storm_openshop_buy(struct map_session_data* sd, struct s_npc_buy_list* list, uint16 count)
{
	double zeny;
	int i, j, add, cost, weight;
	openshoplist* shop;

	nullpo_retr(3, sd);
	nullpo_retr(3, list);

	if (!count || !sd->openshop || !sd->openshop->shop_item)
		return 3;

	zeny = 0;
	weight = 0;
	shop = sd->openshop;

	for (i = 0, add = 0; i < count; i++)
	{
		uint16 id;
		uint16 amount;

		ARR_FIND(0, shop->count, j, list[i].nameid == shop->shop_item[j].nameid || list[i].nameid == itemdb_viewid(shop->shop_item[j].nameid));

		if (j == shop->count)
			return 3;

		id = list[i].nameid = shop->shop_item[j].nameid;
		amount = list[i].qty;
		cost = shop->shop_item[j].value;

		if (!itemdb_exists(id))
			return 3;

		if (amount > 1 && !itemdb_isstackable(id))
			amount = 1;

		switch (pc_checkadditem(sd, id, amount))
		{
			case CHKADDITEM_NEW:
				add++;
				break;
			case CHKADDITEM_OVERAMOUNT:
				return 2;
		}

		if (npc_shop_discount2(shop->type, shop->discount))
			cost = pc_modifybuyvalue(sd, cost);

		zeny += (double)cost * amount;
		weight += itemdb_weight(id) * amount;
	}

	if (zeny > (double)sd->status.zeny)
		return 1;

	if (weight + sd->weight > sd->max_weight)
		return 2;
	if (add > pc_inventoryblank(sd))
		return 3;

	pc_payzeny(sd, (int)zeny, LOG_TYPE_NPC, nullptr);

	for (i = 0; i < count; i++)
	{
		uint16 id = list[i].nameid;
		uint16 amount = list[i].qty;

		if (itemdb_type(id) == IT_PETEGG)
			pet_create_egg(sd, id);
		else
		{
			uint16 sum = amount;
			struct item_data* itemdb;

			if ((itemdb = itemdb_search(id))->flag.guid)
				sum = 1;

			for (j = 0; j < amount; j += sum)
			{
				struct item itm;

				memset(&itm, 0, sizeof(itm));
				itm.nameid = id;
				itm.identify = 1;
				STORM_DURABILITY(itemdb, itm);

				pc_additem(sd, &itm, sum, LOG_TYPE_NPC);
			}
		}
	}

	return 0;
}

/**
 * Process the purchase of items depending on the type of cash purchase shop which was opened.
 *
 * @param sd the player
 * @param shop the shop item list
 * @param price the price
 * @param points the points
 * @eturn an error indicator
 */
static int storm_openshop_cashbuy_sub(struct map_session_data* sd, openshoplist* shop, int price, int points)
{
	int cost[2] = { 0, 0 };

	storm_openshop_currency(sd, cost, false);

	switch (shop->type)
	{
		case NPCTYPE_CASHSHOP:
			if (cost[1] < points || cost[0] < (price - points))
				return ERROR_TYPE_MONEY;
			if (pc_paycash(sd, price, points, LOG_TYPE_NPC) < 1)
				return ERROR_TYPE_MONEY;
			break;

		case NPCTYPE_ITEMSHOP: {
			int i, amount = price;
			struct item_data* id = itemdb_exists(shop->itemshop_nameid);

			if (!id)
				return ERROR_TYPE_PURCHASE_FAIL;

			if (cost[1] < points || cost[0] < (price - points))
			{
				char message[CHAT_SIZE_MAX];
				memset(message, 0, sizeof(message));

				snprintf(message, sizeof(message), msg_txt(sd, 712), id->jname, id->nameid);
				clif_messagecolor(&sd->bl, color_table[COLOR_RED], message, false, SELF);
				return ERROR_TYPE_PURCHASE_FAIL;
			}

			for (i = 0; i < MAX_INVENTORY && 0 < amount; i++)
			{
				int current = 0;
				struct item* it = &sd->inventory.u.items_inventory[i];

				if (it->nameid != shop->itemshop_nameid || !sd->inventory_data[i])
					continue;
				if (!pc_can_sell_item(sd, it, shop->type))
					continue;

				current = it->amount;

				if (current > amount)
					current = amount;

				if (pc_delitem(sd, i, current, 0, 0, LOG_TYPE_NPC))
					return ERROR_TYPE_PURCHASE_FAIL;

				amount -= current;
			}

			if (amount > 0)
				return ERROR_TYPE_PURCHASE_FAIL;

		}	break;

		case NPCTYPE_POINTSHOP: {
			char message[CHAT_SIZE_MAX];
			memset(message, 0, sizeof(message));

			if (cost[1] < points || cost[0] < (price - points))
			{
				snprintf(message, sizeof(message), msg_txt(sd, 713), shop->pointshop_str);
				clif_messagecolor(&sd->bl, color_table[COLOR_RED], message, false, SELF);
				return ERROR_TYPE_PURCHASE_FAIL;
			}

			pc_setreg2(sd, shop->pointshop_str, cost[0] - (price - points));
			snprintf(message, sizeof(message), msg_txt(sd, 716), shop->pointshop_str, cost[0] - (price - points));
			clif_messagecolor(&sd->bl, color_table[COLOR_LIGHT_GREEN], message, false, SELF);
		}	break;
	}

	return ERROR_TYPE_NONE;
}

/**
 * Process the purchase of special items on offer in a player-specific shop.
 *
 * @param sd the player
 * @param points the secondary points
 * @param count the number of items on the list
 * @param items the items list
 * @return the result code for the response
 */
int storm_openshop_cashbuy(struct map_session_data* sd, int points, int count, uint16* items)
{
	int i, j, add, weight, total;
	openshoplist* shop;

	nullpo_retr(ERROR_TYPE_NPC, sd);
	nullpo_retr(ERROR_TYPE_NPC, sd->openshop);
	nullpo_retr(ERROR_TYPE_NPC, items);

	shop = sd->openshop;

	if (shop->type != NPCTYPE_CASHSHOP &&
		shop->type != NPCTYPE_ITEMSHOP &&
		shop->type != NPCTYPE_POINTSHOP)
		return ERROR_TYPE_NPC;

	if (sd->state.trading)
		return ERROR_TYPE_EXCHANGE;

	add = 0;
	total = 0;
	weight = 0;

	for (i = 0; i < count; i++)
	{
		int id = items[i * 2 + 1];
		int amount = items[i * 2 + 0];

		if (amount < 1 || !itemdb_exists(id))
			return ERROR_TYPE_ITEM_ID;

		ARR_FIND(0, shop->count, j, shop->shop_item[j].nameid == id || itemdb_viewid(shop->shop_item[j].nameid) == id);

		if (j == shop->count || shop->shop_item[j].value < 1)
			return ERROR_TYPE_ITEM_ID;

		id = items[i * 2 + 1] = shop->shop_item[j].nameid;

		if (amount > 1 && !itemdb_isstackable(id))
			amount = 1;

		switch (pc_checkadditem(sd, id, amount))
		{
			case CHKADDITEM_NEW:
				add++;
				break;
			case CHKADDITEM_OVERAMOUNT:
				return ERROR_TYPE_INVENTORY_WEIGHT;
		}

		total += shop->shop_item[j].value * amount;
		weight += itemdb_weight(id) * amount;
	}

	if (weight + sd->weight > sd->max_weight)
		return ERROR_TYPE_INVENTORY_WEIGHT;
	if (add > pc_inventoryblank(sd))
		return ERROR_TYPE_INVENTORY_WEIGHT;

	if (points > total)
		points = total;

	if ((i = storm_openshop_cashbuy_sub(sd, shop, total, points)) != ERROR_TYPE_NONE)
		return i;

	for (i = 0; i < count; i++)
	{
		int id = items[i * 2 + 1];
		int amount = items[i * 2 + 0];
		uint16 sum = amount;
		struct item it;
		struct item_data* itemdb = itemdb_search(id);

		if (pet_create_egg(sd, id))
			continue;

		memset(&it, 0, sizeof(it));
		it.nameid = id;
		it.identify = 1;
		STORM_DURABILITY(itemdb, it);

		if (itemdb->flag.guid)
			sum = 1;

		for (j = 0; j < amount; j += sum)
			pc_additem(sd, &it, sum, LOG_TYPE_NPC);
	}

	return ERROR_TYPE_NONE;
}

/**
 * Calculates the currency required for a specialist shop.
 *
 * @param sd the player
 * @param cost the cost values
 * @param display whether the cost should be displayed
 */
void storm_openshop_currency(struct map_session_data* sd, int* cost, bool display)
{
	nullpo_retv(sd);
	nullpo_retv(sd->openshop);

	switch (sd->openshop->type)
	{
		case NPCTYPE_CASHSHOP:
			cost[0] = sd->cashPoints;
			cost[1] = sd->kafraPoints;
			break;
		case NPCTYPE_ITEMSHOP: {
			int total = 0, i;
			struct item_data* id = itemdb_exists(sd->openshop->itemshop_nameid);

			if (id)
			{
				if (display)
				{
					char message[CHAT_SIZE_MAX];
					memset(message, 0, sizeof(message));

					snprintf(message, sizeof(message), msg_txt(sd, 714), id->jname, id->nameid);
					clif_broadcast(&sd->bl, message, strlen(message) + 1, BC_BLUE, SELF);
				}

				for (i = 0; i < MAX_INVENTORY; i++)
				{
					if (sd->inventory.u.items_inventory[i].nameid == sd->openshop->itemshop_nameid)
						total += sd->inventory.u.items_inventory[i].amount;
				}
			}

			cost[0] = total;
		}	break;
		case NPCTYPE_POINTSHOP:
			if (display)
			{
				char message[CHAT_SIZE_MAX];
				memset(message, 0, sizeof(message));

				snprintf(message, sizeof(message), msg_txt(sd, 715), sd->openshop->pointshop_str);
				clif_broadcast(&sd->bl, message, strlen(message) + 1, BC_BLUE, SELF);
			}

			cost[0] = pc_readreg2(sd, sd->openshop->pointshop_str);
			break;
	}
}

/*==========================================================================*
 * Item Durability
 *--------------------------------------------------------------------------*/

#ifdef STORM_ITEM_DURABILITY

/**
 * Called when a player is attacking or being attacked and the equipment must checked for breaking.
 *
 * @param sd the player
 * @param chance the breaking chance modifier
 * @param flag the type of item to break
 */
void storm_itembreak(struct map_session_data* sd, int chance, item_break type)
{
	int i, j;
	int rate;
	struct item* it;
	struct item_data* id;
	bool broken = false;

	if (!battle_config.storm_item_durability)
		return;

	nullpo_retv(sd);

	for (i = 0; i < EQI_MAX; i++)
	{
		if ((j = sd->equip_index[i]) < 0 || !(id = sd->inventory_data[j]))
			continue;
		if (type == ITBREAK_ARMOR && (id->type == IT_WEAPON || !(id->equip & battle_config.storm_item_armor_mask)))
			continue;
		if (type == ITBREAK_WEAPON && id->type != IT_WEAPON)
			continue;
		if (pc_is_same_equip_index((enum equip_index)i, sd->equip_index, j))
			continue;

		it = &sd->inventory.u.items_inventory[j];

		if (it->attribute == 1 || it->durability == STORM_ITEM_MAX_DURABILITY)
			continue;
		
		if (it->durability == 0)
			rate = 0;
		else {
			rate = STORM_ITEM_MAX_DURABILITY - it->durability;
			rate = (rate / 10000) * chance;
		}

		if (rate > rand() % 10000) {
			it->attribute = 1;
			it->durability = 0;
			pc_unequipitem(sd, j, 3);
			broken = true;
		}
	}

	if (broken) {
		clif_emotion(&sd->bl, ET_HUK);
		clif_equiplist(sd);
	}
}

/**
 * Called when a player has received or inflicted damage upon a target.
 *
 * @param sd the player
 * @param bl the target
 * @param type the type of equipment being affected
 * @param damage the damage
 * @param hits the number of hits
 */
void storm_itemdamage(struct map_session_data* sd, struct block_list* bl, uint16 type, uint64 damage, uint16 hits)
{
	int adjust;
	int i, count;
	int auto_break;
	uint64 amount;
	uint32 rate;
	item_damage method;
	struct status_change* sc;
	bool post_calc = false;
	bool post_list = false;
	bool post_emot = false;

	nullpo_retv(sd);
	nullpo_retv(bl);

	if (!battle_config.storm_item_durability || (type == IT_ARMOR && !battle_config.storm_item_armor_mask))
		return;

	adjust = map_getmapflag(sd->bl.m, MF_ITEM_DURABILITY);

	if (adjust < 1)
		return;

	switch (type) {
		case IT_ARMOR:
			auto_break = battle_config.storm_item_armor_break;
			method = (item_damage)battle_config.storm_item_armor_decrease;
			rate = battle_config.storm_item_armor_decrease_rate;
			break;
		case IT_WEAPON:
			auto_break = battle_config.storm_item_weapon_break;
			method = (item_damage)battle_config.storm_item_weapon_decrease;
			rate = battle_config.storm_item_weapon_decrease_rate;
			break;
		default:
			return;
	}

	if (!method || !rate)
		return;

	switch (method) {
		case ITDMG_FIXED:
			amount = rate;
			break;
		case ITDMG_VARIABLE:
			amount = max(type == IT_ARMOR ? status_get_max_hp(&sd->bl) : status_get_max_hp(bl), 1);
			amount = amount < damage ? 100 : (damage * 100) / amount;
			amount = amount * rate;
			break;
		default:
			return;
	}

	amount = cap_value(amount, 1, UINT_MAX);
	sc = &sd->sc;

	if (adjust != 100)
		amount = cap_value((amount * adjust) / 100, 1, UINT_MAX);

	if (!amount)
		return;

	for (i = 0, count = 0; i < EQI_MAX; i++) {
		uint32 before;
		int index = sd->equip_index[i];
		struct item* it;
		struct item_data* id;
		int reduce = 0;
		bool not_same = false;

		if (i == EQI_AMMO || index == -1)
			continue;
		if (!(id = sd->inventory_data[index]) || id->type != type)
			continue;
		if (id->type == IT_ARMOR && !(id->equip & battle_config.storm_item_armor_mask))
			continue;
		if (pc_is_same_equip_index((enum equip_index)i, sd->equip_index, index))
			continue;

		if (battle_config.storm_item_durability_protect)
		{
			if (id->equip&(EQP_HEAD_TOP | EQP_HEAD_MID | EQP_HEAD_LOW | EQP_COSTUME_HEAD_TOP | EQP_COSTUME_HEAD_MID | EQP_COSTUME_HEAD_LOW) && sc->data[SC_CP_HELM])
				continue;
			if (id->equip&(EQP_ARMOR) && sc->data[SC_CP_ARMOR])
				continue;
			if (id->equip&(EQP_WEAPON) && sc->data[SC_CP_WEAPON])
				continue;
			if (id->equip&(EQP_SHIELD) && sc->data[SC_CP_SHIELD])
				continue;
		}

		it = &sd->inventory.u.items_inventory[index];

		if (it->attribute == 1)
			continue;

		reduce = sd->bonus.durabilitydef + sd->durabilitydef[i];

		if (reduce >= 100)
			continue;

		if (reduce != 0)
			amount -= (amount * reduce) / 100;

		before = it->durability;
		it->durability -= (uint32)min(it->durability, (uint32)cap_value(amount, 0, UINT_MAX));

		not_same = before/10000 != it->durability/10000;

		if (not_same)
			post_calc = true;
		
#ifdef STORM_ITEM_RANDOPT_ENABLED
		if (battle_config.storm_item_durability_random_option && not_same)
			post_list = true;
#endif

		if (it->durability == 0 && auto_break) {
			it->attribute = 1;
			pc_unequipitem(sd, index, 3);
			post_emot = true;
			post_list = true;
		}
	}

	if (post_emot)
		clif_emotion(&sd->bl, ET_HUK);

	if (post_list)
		clif_equiplist(sd);

	if (post_calc)
		status_calc_pc(sd, SCO_FORCE);
}

#endif

/*==========================================================================*
 * Item Passive Status/Script
 *--------------------------------------------------------------------------*/

#if defined(STORM_ITEM_STATUS) || defined(STORM_ITEM_SCRIPT)

#ifdef STORM_ITEM_STATUS
/// Item status database storage
struct DBMap* itemstatusdb;
#endif

#ifdef STORM_ITEM_SCRIPT
/// Item script database storage
struct DBMap* itemscriptdb;
#endif

/**
 * Processes an item of a player for a passive status. This method checks to ensure that the item is equipped if required,
 * and also checks whether more than one item remains in the inventory.
 *
 * @param sd the player
 * @param nameid the item id
 * @param flag the item change flag
 */
static void storm_itempassive_sub(struct map_session_data* sd, uint16 nameid, item_change_flag flag)
{
	int i;
	struct status_change* sc;
	struct item_data* id;
	item_status_entry* ise;
	item_script_entry* ice;

	nullpo_retv(sd);

	if (nameid == 0 || !(id = itemdb_search(nameid)))
		return;

	if (id->passive_status && (ise = (item_status_entry*)uidb_get(itemstatusdb, nameid)) && ise->count && (sc = status_get_sc(&sd->bl)))
	{
		for (i = 0; i < ise->count; i++)
		{
			item_status* st = &ise->statuses[i];
			struct status_change_entry* sce = sc->data[st->type];

			switch (flag)
			{
			case ICF_ITEM_ADD:
				if ((!sce || !sce->passive) && !(st->flag & IPF_EQUIP))
					status_change_start(&sd->bl, &sd->bl, (sc_type)st->type, 10000, st->val1, st->val2, st->val3, st->val4, INVALID_TIMER, SCSTART_PASSIVE | SCSTART_NOAVOID);
				break;
			case ICF_ITEM_EQUIP:
				if ((!sce || !sce->passive) && (st->flag & IPF_EQUIP))
					status_change_start(&sd->bl, &sd->bl, (sc_type)st->type, 10000, st->val1, st->val2, st->val3, st->val4, INVALID_TIMER, SCSTART_PASSIVE | SCSTART_NOAVOID);
				break;
			case ICF_ITEM_REMOVE:
				if (sce && sce->passive && !(st->flag & IPF_EQUIP) && pc_search_inventory(sd, nameid) < 0)
					status_change_end_passive(&sd->bl, (sc_type)st->type, INVALID_TIMER);
				break;
			case ICF_ITEM_UNEQUIP:
				if (sce && sce->passive && (st->flag & IPF_EQUIP))
				{
					for (i = 0; i < EQI_MAX; i++) {
						short index = sd->equip_index[i];
						if (index < 0 || !sd->inventory_data[index])
							continue;
						if (sd->inventory_data[index]->nameid == nameid)
							break;
					}

					if (i == EQI_MAX)
						status_change_end_passive(&sd->bl, (sc_type)st->type, INVALID_TIMER);
				}
				break;
			default:
				ShowWarning("storm_itempassive_sub: Invalid item status change flag %d for item %d, ignoring.\n", flag, nameid);
				break;
			}
		}
	}

	if (id->passive_script && (ice = (item_script_entry*)uidb_get(itemscriptdb, nameid)) && ice->count)
	{
		bool calc = false;

		for (i = 0; i < ice->count && !calc; i++)
		{
			item_script* st = &ice->scripts[i];

			if (!st->script)
				continue;

			switch (flag)
			{
			case ICF_STATUS_CALC:
				if (!(st->flag & IPF_EQUIP))
					run_script(st->script, 0, sd->bl.id, 0);
				break;
			case ICF_ITEM_ADD:
			case ICF_ITEM_REMOVE:
				if (!(st->flag & IPF_EQUIP))
					calc = true;
				break;
			case ICF_ITEM_EQUIP:
				if (st->flag & IPF_EQUIP)
					run_script(st->script, 0, sd->bl.id, 0);
				break;
			default:
				ShowWarning("storm_itempassive_sub: Invalid item script change flag %d for item %d, ignoring.\n", flag, nameid);
				break;
			}
		}

		if (calc)
			status_calc_bl(&sd->bl, SCB_BASE);
	}
}

/**
 * Processes all passive item statuses associated with a character. If neither of the 'gained' or 'lost' parameters
 * are provided then the entire inventory is processed.
 *
 * @param sd the player
 * @param nameid the item id
 * @param flag the item change flag
 */
void storm_itempassive(struct map_session_data* sd, uint16 nameid, item_change_flag flag)
{
	int i;

	nullpo_retv(sd);

	if (flag != ICF_NONE)
		storm_itempassive_sub(sd, nameid, flag);
	else {
		for (i = 0; i < MAX_INVENTORY; i++) {
			if (sd->inventory_data[i])
				storm_itempassive_sub(sd, sd->inventory_data[i]->nameid, ICF_ITEM_ADD);
		}
		for (i = 0; i < EQI_MAX; i++) {
			short index = sd->equip_index[i];
			if (index >= 0 && sd->inventory_data[index] && !pc_is_same_equip_index((enum equip_index)i, sd->equip_index, index))
				storm_itempassive_sub(sd, sd->inventory_data[index]->nameid, ICF_ITEM_EQUIP);
		}
	}
}

/**
 * Renews any passive statuses on a character which may have been disabled following death.
 *
 * @param sd the player
 */
void storm_itempassive_renew(struct map_session_data* sd)
{
	int i;
	struct status_change* sc;
	struct status_change_entry* sce;

	nullpo_retv(sd);

	if (!(sc = status_get_sc(&sd->bl)) || !sc->count)
		return;

	for (i = 0; i < SC_MAX; i++)
	{
		int val1, val2, val3, val4;

		if (!(sce = sc->data[i]) || !sce->passive)
			continue;

		val1 = sce->val1;
		val2 = sce->val2;
		val3 = sce->val3;
		val4 = sce->val4;

		status_change_end_passive(&sd->bl, (sc_type)i, INVALID_TIMER);
		status_change_start(&sd->bl, &sd->bl, (sc_type)i, 10000, val1, val2, val3, val4, INVALID_TIMER, SCSTART_PASSIVE | SCSTART_NOAVOID);
	}
}

#ifdef STORM_ITEM_SCRIPT

/**
 * Processes a record from the item passive script database.
 *
 * @param row the row content
 * @param columns the number of columns
 * @param line the current line number
 * @return true if the line is processed
 */
static bool storm_readdb_itemscript_sub(char** row, int32 columns, int32 line)
{
	int64 i = 0, j;
	unsigned short item_id;
	struct item_data* id;
	struct script_code* script;
	item_passive_flag flag = IPF_NONE;
	item_script_entry* ise;

	item_id = atoi(row[0]);

	if (item_id <= 0 || item_id >= MAX_ITEMID || !(id = itemdb_search(item_id))) {
		ShowWarning("storm_readdb_itemscript_sub: Invalid item %d in line %d of \"item_passive_script.txt\", skipping.\n", item_id, line);
		return false;
	}

	ise = (item_script_entry*)uidb_get(itemscriptdb, item_id);

	if (ise && (i = ise->count) >= MAX_PASSIVE_ITEM_SCRIPT) {
		ShowWarning("storm_readdb_itemscript_sub: Item ID %d has reached the maximum of %d passive scripts, skipping.\n", item_id, MAX_PASSIVE_ITEM_SCRIPT);
		return false;
	}

	if (columns > 2) {
		script_number_or_constant(row[1], j) {
			ShowWarning("storm_readdb_itemscript_sub: Invalid flag %d in line %d of \"item_passive_script.txt\", skipping.\n", item_id, line);
			return false;
		}
		flag = (item_passive_flag)j;
	}

	if (*row[columns - 1])
		script = parse_script(row[columns - 1], "item_passive_script.txt", line, SCRIPT_IGNORE_EXTERNAL_BRACKETS);

	if (!script)
		return false;

	if (ise == nullptr) {
		CREATE(ise, item_script_entry, 1);
		memset(ise, 0, sizeof(item_script_entry));
	}

	ise->scripts[i].flag = flag;
	ise->scripts[i].script = script;
	ise->count++;

	id->passive_script = true;
	uidb_put(itemscriptdb, item_id, ise);

	return true;
}

/**
 * Processes the records from the item passive script database.
 */
static void storm_readdb_itemscript(void)
{
	int lines;
	int count;
	char path[256];
	char line[1024];
	FILE* fp;

	snprintf(path, sizeof(path), "%s/%s", db_path, "item_passive_script.txt");
	fp = fopen(path, "r");

	if (!fp) {
		ShowError("storm_readdb_itemscript: File not found \"%s\", skipping.\n", path);
		return;
	}

	lines = 0;
	count = 0;

	while (fgets(line, sizeof(line), fp))
	{
		int col = 0;
		char* columns[3];
		char* p;

		lines++;

		if (line[0] == '/' && line[1] == '/')
			continue;

		memset(columns, 0, sizeof(columns));

		p = strstr(line, "//");

		if (p)
			*p = '\0';

		p = line;

		while (ISSPACE(*p))
			++p;

		if (*p == '\0')
			continue;

		columns[col++] = p;
		p = strchr(p, ',');

		if (!p) {
			ShowWarning("storm_readdb_itemscript: Not enough columns in line %d of \"item_passive_script.txt\", skipping.\n", lines);
			continue;
		}

		*p++ = '\0';

		if (*p != '{') {
			columns[col++] = p;
			p = strchr(p, ',');

			if (!p) {
				ShowWarning("storm_readdb_itemscript: Not enough columns in line %d of \"item_passive_script.txt\", skipping.\n", lines);
				continue;
			}

			*p++ = '\0';
		}

		if (*p != '{') {
			ShowWarning("storm_readdb_itemscript: Invalid format (script column) in line %d of \"item_passive_script.txt\", skipping.\n", lines);
			continue;
		}

		columns[col] = p;
		p = &columns[col][strlen(columns[col]) - 1];

		if (*p != '}') {
			int i, left = 0, right = 0;

			for (i = 0; i < strlen(columns[col]); i++) {
				if (columns[col][i] == '{')
					left++;
				else if (columns[col][i] == '}') {
					right++;
					p = &columns[col][i];
				}
			}

			if (left != right) {
				ShowWarning("storm_readdb_itemscript: Mismatching curly braces in line %d of \"item_passive_script.txt\", skipping.\n", lines);
				continue;
			}
		}

		columns[col] = columns[col] + 1;
		*p = '\0';
		col++;

		if (storm_readdb_itemscript_sub(columns, col, lines))
			count++;
	}

	fclose(fp);

	ShowStatus("Done reading '" CL_WHITE "%u" CL_RESET "' entries in '" CL_WHITE "%s" CL_RESET "'.\n", count, path);
}

#endif // SBF_PASSIVE_ITEM_SCRIPT

#ifdef STORM_ITEM_STATUS

/**
 * Processes a record from the item passive status database.
 *
 * @param row the row content
 * @param columns the number of columns
 * @param line the current line number
 * @return true if the line is processed
 */
static bool storm_readdb_itemstatus_sub(char** row, int32 columns, int32 line)
{
	struct item_data* id;
	int64 status, j;
	int i = 0, val1 = 0, val2 = 0, val3 = 0, val4 = 0;
	unsigned short item_id;
	item_passive_flag flag = IPF_NONE;
	item_status_entry* ise;

	item_id = atoi(row[0]);

	if (item_id <= 0 || item_id >= MAX_ITEMID || !(id = itemdb_search(item_id))) {
		ShowWarning("storm_readdb_itemstatus_sub: Invalid item %d in line %d of \"item_passive_status.txt\", skipping.\n", item_id, line);
		return false;
	}

	ise = (item_status_entry*)uidb_get(itemstatusdb, item_id);

	if (ise && (i = ise->count) >= MAX_PASSIVE_ITEM_STATUS) {
		ShowWarning("storm_readdb_itemstatus_sub: Item ID %d has reached the maximum of %d passive statuses, skipping.\n", item_id, MAX_PASSIVE_ITEM_STATUS);
		return false;
	}

	script_number_or_constant(row[1], status) {
		ShowWarning("storm_readdb_itemstatus_sub: Invalid status %s in line %d of \"item_passive_status.txt\", skipping.\n", row[1], line);
		return false;
	}
	
	if (status <= SC_NONE || status >= SC_MAX) {
		ShowWarning("storm_readdb_itemstatus_sub: Invalid status %d in line %d of \"item_passive_status.txt\", skipping.\n", status, line);
		return false;
	}

	if (columns > 2 && *row[2]) {
		script_number_or_constant(row[2], j) {
			ShowWarning("storm_readdb_itemstatus_sub: Invalid flag %s in line %d of \"item_passive_status.txt\", skipping.\n", row[2], line);
			j = 0;
		}
		flag = (item_passive_flag)j;
	}

	if (columns > 3 && *row[3])
		val1 = atoi(row[3]);
	if (columns > 4 && *row[4])
		val2 = atoi(row[4]);
	if (columns > 5 && *row[5])
		val3 = atoi(row[5]);
	if (columns > 6 && *row[6])
		val4 = atoi(row[6]);

	if (ise == nullptr) {
		CREATE(ise, struct s_item_status_entry, 1);
		memset(ise, 0, sizeof(struct s_item_status_entry));
	}

	ise->statuses[i].type = (sc_type)status;
	ise->statuses[i].val1 = val1;
	ise->statuses[i].val2 = val2;
	ise->statuses[i].val3 = val3;
	ise->statuses[i].val4 = val4;
	ise->statuses[i].flag = flag;
	ise->count++;

	id->passive_status = true;
	uidb_put(itemstatusdb, item_id, ise);

	return true;
}

#endif // SBF_PASSIVE_ITEM_STATUS

 /**
  * Loads the item passive status database and updates the item records.
  */
void storm_itempassive_read(void)
{
#ifdef STORM_ITEM_STATUS
	sv_readdb(db_path, "item_passive_status.txt", ',', 2, 7, -1, &storm_readdb_itemstatus_sub, false);
#endif

#ifdef STORM_ITEM_SCRIPT
	storm_readdb_itemscript();
#endif
}

#ifdef STORM_ITEM_STATUS

/**
 * Destroys a record in the item status database.
 */
static int storm_itemstatus_final_sub(DBKey key, DBData* data, va_list ap)
{
	item_status_entry* ise = (item_status_entry*)db_data2ptr(data);

#ifdef DEBUG
	memset(ise, 0xDD, sizeof(struct s_item_status_entry));
#endif

	if (ise)
		aFree(ise);

	return 0;
}

#endif // SBF_PASSIVE_ITEM_STATUS

#ifdef STORM_ITEM_SCRIPT
/**
 * Destroys a record in the item status database.
 */
static int storm_itemscript_final_sub(DBKey key, DBData* data, va_list ap)
{
	item_script_entry* ise = (item_script_entry*)db_data2ptr(data);
	
	if (ise)
	{
		int i;

		for (i = 0; i < MAX_PASSIVE_ITEM_SCRIPT; i++)
		{
			if (ise->scripts[i].script) {
				script_free_code(ise->scripts[i].script);
				ise->scripts[i].script = nullptr;
			}
		}

#ifdef DEBUG
		memset(ise, 0xDD, sizeof(struct s_item_script_entry));
#endif

		aFree(ise);
	}

	return 0;
}

#endif // SBF_PASSIVE_ITEM_SCRIPT

/**
 * Reload the item passive status database.
 */
void storm_itempassive_reload(void)
{
#ifdef STORM_ITEM_STATUS
	itemstatusdb->clear(itemstatusdb, storm_itemstatus_final_sub);
#endif
#ifdef STORM_ITEM_SCRIPT
	itemscriptdb->clear(itemscriptdb, storm_itemscript_final_sub);
#endif

	storm_itempassive_read();
}

#endif // SBF_PASSIVE_ITEM_STATUS || SBF_PASSIVE_ITEM_SCRIPT

/*==========================================================================*
 * Stormbreaker
 *--------------------------------------------------------------------------*/

/**
 * Called when the map-server is starting and must begin processing.
 */
void do_init_storm(void)
{
#ifdef STORM_ITEM_STATUS
	itemstatusdb = uidb_alloc(DB_OPT_BASE);
#endif
#ifdef STORM_ITEM_SCRIPT
	itemscriptdb = uidb_alloc(DB_OPT_BASE);
#endif
	npcvariables = strdb_alloc(DB_OPT_BASE, MAX_NPC_VARIABLE_NAME);
	craftdb = uidb_alloc(DB_OPT_BASE);
	enchantdb = uidb_alloc(DB_OPT_BASE);
	statusbonusdb = strdb_alloc(DB_OPT_DUP_KEY, 0);
#ifdef STORM_BAZAAR
	bazaardb = uidb_alloc(DB_OPT_BASE);
	bazaarsearchdb = uidb_alloc(DB_OPT_BASE);
#endif
}

/**
 * Called when the map-server is shutting down and must finalize.
 */
void do_final_storm(void)
{
#ifdef STORM_ITEM_STATUS
	itemstatusdb->destroy(itemstatusdb, storm_itemstatus_final_sub);
#endif
#ifdef STORM_ITEM_SCRIPT
	itemscriptdb->destroy(itemscriptdb, storm_itemscript_final_sub);
#endif
	npcvariables->destroy(npcvariables, nullptr);
	craftdb->destroy(craftdb, storm_craft_final_sub);
	enchantdb->destroy(enchantdb, storm_enchant_final_sub);
	statusbonusdb->destroy(statusbonusdb, storm_statusbonus_final_sub);
#ifdef STORM_BAZAAR
	bazaardb->destroy(bazaardb, storm_bazaar_final_sub);
	bazaarsearchdb->destroy(bazaarsearchdb, storm_bazaarsearch_final_sub);
#endif
}

