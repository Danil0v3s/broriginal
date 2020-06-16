/**
 * Stormbreaker (c) Epoque 2019. All rights reserved.
 */

#ifndef STORMBREAKER_HPP
#define STORMBREAKER_HPP

#include <vector>

#include "../common/cbasetypes.hpp"
#include "../common/mmo.hpp"
#include "../common/stormbreaker.hpp"
#include "../config/packets.hpp"

#include "script.hpp"

#define MAX_INVENTORY_SELECT_FILTER 200
#define MAX_INVENTORY_SELECT_RESULT MAX_INVENTORY
#define MAX_REFINE_MATERIALS 4
#define MAX_SKILL_SELECT 50

struct npc_data;
struct npc_item_list;
struct s_statusbonus_entry;
enum sc_type : int16;
enum npc_subtype : unsigned char;

/**
 * Calculates the signum of a provided value.
 *
 * @param value the value
 * @return -1 if the value is less than zero, 0 if the value is equal to zero, or 1 if the value is greater than zero
 */
inline int signum(int value) {
	if (value < 0) return -1;
	if (value > 0) return 1;
	return 0;
}

#if PACKETVER >= 20161012

typedef enum e_refine_process_type {
	REFT_REFINE,
	REFT_CRAFT,
	REFT_ENCHANT

} refine_process_type;

typedef enum e_craft_flag : short {
	CRAFT_NONE				= 0x00,
	CRAFT_KEEP_REFINE		= 0x01,
	CRAFT_KEEP_SLOTS		= 0x02,
	CRAFT_KEEP_RANDOPT		= 0x04,
	CRAFT_KEEP_DURABILITY	= 0x08,

} craft_flag;

typedef struct s_craft_material {
	unsigned short material;
	unsigned short nameid;
	unsigned int zeny;
	unsigned char rate;
	craft_flag flag;
	
} craft_material;

typedef struct s_craft_data {
	unsigned short nameid;
	unsigned short count;
	craft_material materials[MAX_REFINE_MATERIALS];

} craft_data;

typedef enum e_enchant_flag : short {
	ENCHANT_NONE = 0x00,
	ENCHANT_FAIL_DESTROY = 0x01,
	ENCHANT_FAIL_BREAK = 0x02,

} enchant_flag;

typedef struct s_enchant_material {
	unsigned short material;
	unsigned short option;
	unsigned short value;
	unsigned short param;
	unsigned int zeny[MAX_REFINE_MATERIALS];
	unsigned char rate[MAX_REFINE_MATERIALS];
	enchant_flag flag;

} enchant_material;

typedef struct s_enchant_data {
	unsigned short nameid;
	unsigned short count;
	enchant_material materials[MAX_REFINE_MATERIALS];

} enchant_data;

typedef enum e_refineinfo {
	REFINE_MATERIAL_ID,
	REFINE_ZENY_COST,
	REFINE_DOWNGRADE

} refineinfo;

typedef struct s_refinematerial {
	unsigned short nameid;
	int zeny;
	bool downgrade;
	unsigned char rate;

} refinematerial;

typedef struct s_refinematerial_list {
	unsigned short count;
	refinematerial materials[MAX_REFINE_MATERIALS];

} refinematerial_list;

#endif

typedef enum e_openshop_flag : short {
	OSHP_NONE		= 0x00,
	OSHP_NODISCOUNT = 0x01,
	OSHP_CASHSHOP	= 0x02,
	OSHP_ITEMSHOP	= 0x04,
	OSHP_POINTSHOP	= 0x08

} openshop_flag;

typedef struct s_openshoplist {
	struct npc_item_list* shop_item;
	uint16 count;
	unsigned short itemshop_nameid;
	char pointshop_str[32];
	bool discount;
	openshop_flag flag;
	npc_subtype type;

} openshoplist;

typedef struct s_inventoryselect {
	unsigned short count;
	int positions[MAX_INVENTORY_SELECT_RESULT];

} inventoryselect;

typedef enum e_inventoryselect_flag : short {
	ISF_NONE				= 0x0000,
	ISF_HEALING				= 0x0001,
	ISF_USABLE				= 0x0002,
	ISF_ETC					= 0x0004,
	ISF_EQUIP				= 0x0008,
	ISF_CARD				= 0x0010,
	ISF_PET_EGG				= 0x0020,
	ISF_PET_EQUIP			= 0x0040,
	ISF_AMMO				= 0x0080,
	ISF_USABLE_DELAY		= 0x0100,
	ISF_SHADOW				= 0x0200,
	ISF_USABLE_CONFIRM		= 0x0400,
	ISF_SHOW_UNIDENTIFIED	= 0x0800,
	ISF_SHOW_BROKEN			= 0x1000,

} inventoryselect_flag;

#ifdef STORM_BAZAAR

#define MAX_BAZAAR 1000
#define MAX_BAZAAR_ENTRY 20
#define MAX_BAZAAR_SHOP 100

typedef enum e_bazaar_state : short {
	BZS_LOCKED		= 0,
	BZS_AVAILABLE	= 1,
	BZS_BOUGHT		= 2

} bazaar_state;

typedef enum e_bazaar_flag : short {
	BZF_ONE_TIME_ACCOUNT = 0x01,
	BZF_REPEAT			 = 0x02,
	BZF_UNLIMITED		 = 0x04,
	BZF_BOUND_CHAR		 = 0x10,
	BZF_NO_DISCOUNT		 = 0x20,

} bazaar_flag;

typedef struct s_bazaaritem {
	unsigned short nameid;
	unsigned short amount;

} bazaaritem;

typedef struct s_bazaar {
	unsigned short id;
	unsigned short nameid;
	unsigned short count;
	unsigned short max;
	unsigned int cost;
	bazaar_flag flags;
	bazaaritem items[MAX_BAZAAR_ENTRY];

} bazaar;

typedef struct s_bazaarsearch {
	bazaar* entry;
	struct s_bazaarsearch* next;
	struct s_bazaarsearch* prev;

} bazaarsearch;

typedef struct s_bazaarlistitem {
	unsigned short nameid;
	unsigned short amount;
	unsigned int cost;

} bazaarlistitem;

typedef struct s_bazaarlist {
	unsigned short count;
	bazaarlistitem items[MAX_BAZAAR_SHOP];

} bazaarlist;

#endif

#if defined(STORM_ITEM_STATUS) || defined(STORM_ITEM_SCRIPT)

typedef enum e_item_passive_flag : short {
	IPF_NONE = 0,
	IPF_EQUIP,

} item_passive_flag;

typedef enum e_item_change_flag : short {
	ICF_NONE = 0,
	ICF_ITEM_ADD,
	ICF_ITEM_REMOVE,
	ICF_ITEM_EQUIP,
	ICF_ITEM_UNEQUIP,
	ICF_STATUS_CALC

} item_change_flag;

#endif

#ifdef STORM_ITEM_STATUS

typedef struct s_item_status {
	int16 type;
	int32 val1;
	int32 val2;
	int32 val3;
	int32 val4;
	item_passive_flag flag;

} item_status;

typedef struct s_item_status_entry {
	uint8 count;
	item_status statuses[MAX_PASSIVE_ITEM_STATUS];

} item_status_entry;

#endif

#ifdef STORM_ITEM_SCRIPT

typedef struct s_item_script {
	struct script_code* script;
	item_passive_flag flag;

} item_script;

typedef struct s_item_script_entry {
	uint8 count;
	item_script scripts[MAX_PASSIVE_ITEM_SCRIPT];

} item_script_entry;

#endif

#ifdef STORM_ITEM_DURABILITY

#if PACKETVER >= 20150225
#define STORM_ITEM_RANDOPT_ENABLED
#define STORM_ITEM_RANDOPT_ID 300
#define STORM_ITEM_MAX_DURABILITY 1000000
#endif

typedef enum e_item_damage {
	ITDMG_NONE = 0,
	ITDMG_FIXED,
	ITDMG_VARIABLE

} item_damage;

typedef enum e_item_break {
	ITBREAK_ARMOR = 1,
	ITBREAK_WEAPON,

} item_break;

#endif

#ifdef STORM_ITEM_DURABILITY
#	define STORM_DURABILITY(itemdata, item) if (itemdata && (itemdata->type == IT_ARMOR || itemdata->type == IT_SHADOWGEAR || itemdata->type == IT_WEAPON)) item.durability = STORM_ITEM_MAX_DURABILITY;
#else
#	define STORM_DURABILITY(itemdata, item)
#endif

#define script_number_or_constant(src, dest) \
	if (ISDIGIT(*src)) dest = atoi(src); \
	else if (!script_get_constant(src, &dest))

int storm_enchant_attempt(struct map_session_data* sd, uint16 index, uint16 materialid);
bool storm_enchant_available(struct map_session_data* sd, uint16 index);
enchant_data* storm_enchant_get(uint16 nameid);
void storm_enchant_reload(void);
void storm_enchant_read(void);

int storm_craft_attempt(struct map_session_data* sd, uint16 index, uint16 materialid);
craft_data* storm_craft_get(uint16 nameid);
void storm_craft_reload(void);
void storm_craft_read(void);

void storm_clear_npcvar(void);
bool storm_has_npcvar(struct map_session_data* sd, struct npc_data* nd);
bool storm_is_npcvar(const char* value);
void storm_set_npcvar(struct npc_data* nd, const char* value);
inventoryselect storm_inventoryselect(struct map_session_data* sd, inventoryselect_flag flag, enum equip_pos equip, uint16 filter[MAX_INVENTORY_SELECT_FILTER], int filter_count);
void storm_openshop(struct map_session_data* sd, struct npc_item_list* items, uint16 count, openshop_flag flags, uint16 item, const char* points);
int storm_openshop_buy(struct map_session_data* sd, struct s_npc_buy_list* list, uint16 count);
int storm_openshop_cashbuy(struct map_session_data* sd, int points, int count, uint16* items);
void storm_openshop_currency(struct map_session_data* sd, int* cost, bool display);
void storm_statusbonus_add(struct map_session_data* sd, sc_type type, const char* script);
void storm_statusbonus_clear(struct map_session_data* sd);
void storm_statusbonus_run_script(struct map_session_data* sd, std::vector<s_statusbonus_entry>& entries);

#ifdef STORM_BAZAAR
bazaarlist storm_bazaar_list(struct map_session_data* sd, struct npc_data* nd);
void storm_bazaar_purchase(struct map_session_data* sd, const uint8* data, uint16 count);
void storm_bazaar_sold(struct map_session_data* sd, uint16 item, uint16 amount);
void storm_bazaar_reload(void);
void storm_bazaar_read(void);
#endif

#ifdef STORM_ITEM_DURABILITY
void storm_itembreak(struct map_session_data* sd, int chance, item_break type);
void storm_itemdamage(struct map_session_data* sd, struct block_list* bl, uint16 type, uint64 damage, uint16 hits);
#endif

#if defined(STORM_ITEM_STATUS) || defined(STORM_ITEM_SCRIPT)
void storm_itempassive(struct map_session_data* sd, uint16 nameid, item_change_flag flag);
void storm_itempassive_renew(struct map_session_data* sd);
void storm_itempassive_reload(void);
void storm_itempassive_read(void);
#endif

void do_final_storm(void);
void do_init_storm(void);

#endif
