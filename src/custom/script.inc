// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

/**
 * Custom Script Commands
 * Place the body of custom script commands in this file.
 * Format:
 *	BUILDIN_FUNC(command_name)
 *	{
 *		<code>;
 *	}
 **/

/**
 * Shows the inventory item selection prompt.
 */
BUILDIN_FUNC(inventoryselect)
{
	int i;
	struct map_session_data* sd;
	inventoryselect options;

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_SUCCESS;
	
	if (sd->state.menu_or_input == 0)
	{
		int flag = script_getnum(st, 2);
		int equip = 0xFFFFFF;
		int count, total;
		unsigned short filter[MAX_INVENTORY_SELECT_FILTER];

		if (script_hasdata(st, 3))
			equip = script_getnum(st, 3);

		if (flag == 0)
			flag = 0xFFFF;

		if (equip == 0)
			equip = 0xFFFFFF;

		memset(filter, 0, sizeof(filter));
		memset(&options, 0, sizeof(options));

		count = script_lastdata(st) - 3;
		total = 0;

		for (i = 0; i < count; i++)
		{
			int nameid = script_getnum(st, i + 4);

			if (nameid <= 0 || nameid >= MAX_ITEMID)
				continue;

			filter[total++] = (unsigned short)nameid;
		}

		options = storm_inventoryselect(sd, (inventoryselect_flag)flag, (equip_pos)equip, filter, total);

		if (options.count == 0)
		{
			script_pushint(st, -1);
			return SCRIPT_CMD_SUCCESS;
		}

		sd->npc_menu = options.count;
		st->state = RERUNLINE;
		sd->state.menu_or_input = 1;

		clif_inventory_select_list(sd, options.positions, options.count);
	}
	else if (sd->npc_menu == 0xFFFF)
	{
		script_pushint(st, 0);

		sd->state.menu_or_input = 0;
		st->state = RUN;
	}
	else
	{
		struct item* it;

		if (sd->npc_menu < 0 || sd->npc_menu >= MAX_INVENTORY || !sd->inventory_data[sd->npc_menu])
		{
			sd->state.menu_or_input = 0;
			st->state = END;

			return SCRIPT_CMD_SUCCESS;
		}

		it = &sd->inventory.u.items_inventory[sd->npc_menu];

		pc_setreg(sd, add_str("@select_id"), it->nameid);
		pc_setreg(sd, add_str("@select_amount"), it->amount);
		pc_setreg(sd, add_str("@select_equip"), it->equip);
		pc_setreg(sd, add_str("@select_refine"), it->refine);
		pc_setreg(sd, add_str("@select_identify"), it->identify);
		pc_setreg(sd, add_str("@select_attribute"), it->attribute);

		for (i = 0; i < MAX_SLOTS; i++)
			pc_setreg(sd, reference_uid(add_str("@select_cards"), i), it->card[i]);

		for (i = 0; i < MAX_ITEM_RDM_OPT; i++)
		{
			pc_setreg(sd, reference_uid(add_str("@select_options_ids"), i), it->option[i].id);
			pc_setreg(sd, reference_uid(add_str("@select_options_vals"), i), it->option[i].value);
			pc_setreg(sd, reference_uid(add_str("@select_options_params"), i), it->option[i].param);
		}

		script_pushint(st, 1);

		sd->state.menu_or_input = 0;
		st->state = RUN;
	}

	return SCRIPT_CMD_SUCCESS;
}

/**
 * Shows the skill selection prompt.
 */
BUILDIN_FUNC(skillselect)
{
	int i;
	int count, total;
	struct map_session_data* sd;
	unsigned short skills[MAX_SKILL_SELECT];

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_SUCCESS;

	if (sd->state.menu_or_input == 0 || sd->npc_menu != 0xFFFF)
	{
		memset(skills, 0, sizeof(skills));

		count = script_lastdata(st) - 1;
		total = 0;

		for (i = 0; i < count; i++)
		{
			int skill;
			struct script_data* data;

			data = script_getdata(st, i + 2);
			get_val(st, data);

			skill = data_isstring(data) ? skill_name2id(script_getstr(st, i + 2)) : script_getnum(st, i + 2);

			if (skill <= 0 || skill >= MAX_SKILL || !skill_get_index(skill))
				continue;

			skills[total++] = (unsigned short)skill;
		}

		if (total == 0)
		{
			script_pushint(st, -1);
			return SCRIPT_CMD_SUCCESS;
		}
	}

	if (sd->state.menu_or_input == 0)
	{
		sd->npc_menu = total;
		st->state = RERUNLINE;
		sd->state.menu_or_input = 1;

		clif_skill_select_list(sd, skills, total);
	}
	else if (sd->npc_menu == 0xFFFF)
	{
		script_pushint(st, 0);

		sd->state.menu_or_input = 0;
		st->state = RUN;
	}
	else
	{
		sd->state.menu_or_input = 0;

		if (sd->npc_menu < 0 || sd->npc_menu >= MAX_SKILL)
		{
			st->state = END;
			return SCRIPT_CMD_FAILURE;
		}

		ARR_FIND(0, total, i, skills[i] == sd->npc_menu);

		if (i == total)
			script_pushint(st, 0);
		else
			script_pushint(st, sd->npc_menu);

		st->state = RUN;
	}

	return SCRIPT_CMD_SUCCESS;
}

/**
 * Opens a player-specific shop for purchasing items from a provided array of options.
 */
BUILDIN_FUNC(openshop)
{
	int i, id, count;
	const char* name;
	struct script_data* items;
	struct reg_db* ref;
	struct map_session_data* sd;
	openshop_flag flags;
	char* variable = NULL;
	unsigned short item = 0;
	struct npc_item_list* list;

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_FAILURE;

	items = script_getdata(st, 2);

	if (!data_isreference(items)) {
		ShowError("buildin_openshop: Invalid array containing the items\n");
		script_reportdata(items);
		st->state = END;
		return SCRIPT_CMD_FAILURE;
	}
	
	id = reference_getid(items);
	name = reference_getname(items);
	ref = reference_getref(items);

	if (is_string_variable(name)) {
		ShowError("buildin_openshop: Expected a numeric array of items\n");
		return SCRIPT_CMD_FAILURE;
	}

	flags = (openshop_flag)script_getnum(st, 3);

	if (flags & OSHP_ITEMSHOP) {
		if (!script_hasdata(st, 4) || !script_isint(st, 4)) {
			ShowError("buildin_openshop: Expected an item value when opening an item shop\n");
			return SCRIPT_CMD_FAILURE;
		}
		item = script_getnum(st, 4);
	} else if (flags & OSHP_POINTSHOP) {
		struct script_data* var;

		if (!script_hasdata(st, 4)) {
			ShowError("buildin_openshop: Expected a variable when opening a point shop\n");
			return SCRIPT_CMD_FAILURE;
		}

		var = script_getdata(st, 4);

		if (!data_isreference(var)) {
			ShowError("buildin_openshop: Invalid variable used for the point shop\n");
			return SCRIPT_CMD_FAILURE;
		}

		variable = reference_getname(var);

		if (is_string_variable(variable)) {
			ShowError("buildin_openshop: Expected a numeric variable for the point shop\n");
			return SCRIPT_CMD_FAILURE;
		}
	}

	count = script_array_highest_key(st, sd, name, ref);

	if (count < 0 || count % 2 != 0) {
		ShowWarning("buildin_openshop: Expected the item array to be greater than zero and contain an even number of values\n");
		return SCRIPT_CMD_FAILURE;
	}

	CREATE(list, struct npc_item_list, count / 2);
	memset(list, 0, sizeof(struct npc_item_list) * count / 2);

	for (i = 0; i < count; i += 2) {
		list[i / 2].nameid = (uint16)get_val2_num(st, reference_uid(id, i), ref);
		script_removetop(st, -1, 0);

		list[i / 2].value = (uint32)get_val2_num(st, reference_uid(id, i + 1), ref);
		script_removetop(st, -1, 0);
	}

	storm_openshop(sd, list, count / 2, flags, item, variable);
	aFree(list);

	return SCRIPT_CMD_SUCCESS;
}

/**
 * Summons a monster (the same as the monster; command) except isolated to the attached player and party.
 *
 * *partymonster "<map name>",<x>,<y>,"<name to show>",<mob id>,<amount>{,"<event label>",<size>,<ai>};
 */
BUILDIN_FUNC(partymonster)
{
	const char* mapn  = script_getstr(st, 2);
	int x             = script_getnum(st, 3);
	int y             = script_getnum(st, 4);
	const char* str   = script_getstr(st, 5);
	int class_        = script_getnum(st, 6);
	int amount        = script_getnum(st, 7);
	const char* event = "";
	unsigned int size = SZ_SMALL;
	enum mob_ai ai    = AI_NONE;

	struct map_session_data* sd;
	int16 m;
	int i;

	if (!script_rid2sd(sd)) {
		ShowWarning("buildin_partymonster: Attempted to spawn a monster with no player attached\n");
		return SCRIPT_CMD_FAILURE;
	}

	if (script_hasdata(st, 8)) {
		event = script_getstr(st, 8);
		check_event(st, event);
	}

	if (script_hasdata(st, 9)) {
		size = script_getnum(st, 9);
		if (size > SZ_BIG) {
			ShowWarning("buildin_monster: Attempted to spawn non-existing size %d for monster class %d\n", size, class_);
			return SCRIPT_CMD_FAILURE;
		}
	}

	if (script_hasdata(st, 10)) {
		ai = static_cast<enum mob_ai>(script_getnum(st, 10));
		if (ai >= AI_MAX) {
			ShowWarning("buildin_monster: Attempted to spawn non-existing ai %d for monster class %d\n", ai, class_);
			return SCRIPT_CMD_FAILURE;
		}
	}

	if (class_ >= 0 && !mobdb_checkid(class_)) {
		ShowWarning("buildin_monster: Attempted to spawn non-existing monster class %d\n", class_);
		return SCRIPT_CMD_FAILURE;
	}

	if (strcmp(mapn, "this") == 0)
		m = sd->bl.m;
	else
		m = map_mapname2mapid(mapn);

	for (i = 0; i < amount; i++) { //not optimised
		int mobid = mob_once_spawn(sd, m, x, y, str, class_, 1, event, size, ai);

		if (mobid)
		{
			struct mob_data* md = map_id2md(mobid);

			if (md)
				md->party_id = sd->bl.id;

			mapreg_setreg(reference_uid(add_str("$@mobid"), i), mobid);
		}
	}

	return SCRIPT_CMD_SUCCESS;
}

/**
 * statusbonus <type>,"{ <script> }";
 */
BUILDIN_FUNC(statusbonus)
{
	int16 type;
	const char* script;
	struct map_session_data* sd;

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_SUCCESS;

	type = (int16)script_getnum(st, 2);

	if (type < 0 || type >= SC_MAX) {
		ShowWarning("buildin_statusbonus: Invalid status %d\n", type);
		return SCRIPT_CMD_FAILURE;
	}

	script = script_getstr(st, 3);

	if (!script)
		return SCRIPT_CMD_SUCCESS;

	storm_statusbonus_add(sd, (sc_type)type, script);
	return SCRIPT_CMD_SUCCESS;
}

#ifdef STORM_ITEM_DURABILITY

/**
 * Gets whether the item at the provided index is a valid item for durability processing.
 */
static bool script_getdurability_sub(struct map_session_data* sd, int index)
{
	struct item* it;
	struct item_data* id;

	nullpo_retr(false, sd);

	if (index < 0 || index >= MAX_INVENTORY)
		return false;

	it = &sd->inventory.u.items_inventory[index];
	id = sd->inventory_data[index];
	
	if (!id || !(id->type == IT_ARMOR || id->type == IT_WEAPON || id->type == IT_SHADOWGEAR))
		return false;
	if (!it->nameid || it->durability >= STORM_ITEM_MAX_DURABILITY)
		return false;

	return true;
}

/**
 * Gets the identifier for an item in the player inventory which has a durability of less than 100%.
 */
BUILDIN_FUNC(getdurabilityid)
{
	int i, n;
	int number;
	struct map_session_data* sd;

	if (!script_rid2sd(sd)) {
		script_pushint(st, 0);
		return SCRIPT_CMD_FAILURE;
	}

	number = script_getnum(st, 2);

	if (number < 1) {
		ShowWarning("buildin_getdurabilityid: expected a number greater than zero, got %d\n", number);
		script_pushint(st, 0);
		return SCRIPT_CMD_SUCCESS;
	}

	for (i = 0, n = 1; i < MAX_INVENTORY; i++) {
		if (!script_getdurability_sub(sd, i))
			continue;

		if (n++ == number) {
			script_pushint(st, 1);
			return SCRIPT_CMD_SUCCESS;
		}
	}

	script_pushint(st, 0);
	return SCRIPT_CMD_SUCCESS;
}

/**
 * Gets the current durability of the equipped or specified item.
 */
BUILDIN_FUNC(getdurability)
{
	int i, n, number;
	struct map_session_data* sd;

	if (!script_rid2sd(sd)) {
		script_pushint(st, 0);
		return SCRIPT_CMD_FAILURE;
	}

	if (!script_hasdata(st, 2)) {
		number = current_equip_item_index;
	} else {
		number = script_getnum(st, 2);

		for (i = 0, n = 1; i < MAX_INVENTORY; i++) {
			if (!script_getdurability_sub(sd, i))
				continue;

			if (n++ == number) {
				number = i;
				break;
			}
		}

		if (i == MAX_INVENTORY)
			number = i;
	}

	if (number >= 0 && number < MAX_INVENTORY)
		script_pushint(st, sd->inventory.u.items_inventory[number].durability / 10000);
	else
		script_pushint(st, 0);

	return SCRIPT_CMD_SUCCESS;
}

/**
 * Gets the durability of an equipment at a specified position.
 */
BUILDIN_FUNC(getequipdurability)
{
	int i, pos;
	struct map_session_data* sd;

	if (!script_rid2sd(sd)) {
		script_pushint(st, 0);
		return SCRIPT_CMD_FAILURE;
	}

	pos = script_getnum(st, 2);

	if (pos < 0 || pos >= EQI_MAX) {
		ShowWarning("buildin_getequipdurability: invalid equipment position %d\n", pos);
		script_pushint(st, 0);
		return SCRIPT_CMD_FAILURE;
	}

	i = sd->equip_index[pos];

	if (i > 0)
		script_pushint(st, sd->inventory.u.items_inventory[i].durability / 10000);
	else
		script_pushint(st, 0);

	return SCRIPT_CMD_SUCCESS;
}

/**
 * Sets the current durability of the equipped or specified item.
 */
BUILDIN_FUNC(setdurability)
{
	int i, n;
	int number;
	int amount;
	struct map_session_data* sd;
	struct item* it;
	bool post_item = false;

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_FAILURE;

	number = script_getnum(st, 2);
	amount = script_getnum(st, 3);
	amount = cap_value(amount, 0, 100);

	for (i = 0, n = 1; i < MAX_INVENTORY; i++) {
		if (!script_getdurability_sub(sd, i))
			continue;

		if (n++ == number) {
			number = i;
			break;
		}
	}

	if (i == MAX_INVENTORY || number < 0 || number >= MAX_INVENTORY)
		return SCRIPT_CMD_FAILURE;

	it = &sd->inventory.u.items_inventory[number];
	it->durability = (amount * STORM_ITEM_MAX_DURABILITY) / 100;

	if (it->equip)
		clif_equiplist(sd);
	else
		post_item = true;

	if (amount == 0) {
		int i = sd->inventory_data[number]->type == IT_ARMOR ? battle_config.storm_item_armor_break : battle_config.storm_item_weapon_break;
		if (i) {
			it->attribute = 1;
			post_item = true;

			if (it->equip)
				pc_unequipitem(sd, number, 3);
		}
	}

	if (post_item) {
		clif_delitem(sd, number, 1, 3);
		clif_additem(sd, number, 1, 0);
	}

	status_calc_pc(sd, SCO_FORCE);

	return SCRIPT_CMD_SUCCESS;
}

#endif

/**
 * Opens the new refine user interface.
 */
BUILDIN_FUNC(openrefine)
{
#if PACKETVER >= 20161012
	struct map_session_data* sd;

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_FAILURE;

	clif_refine_open(sd, REFT_REFINE);
	return SCRIPT_CMD_SUCCESS;
#else
	ShowWarning("buildin_openrefine: The client packet version %d does not support the refine interface\n", PACKETVER);
	return SCRIPT_CMD_SUCCESS;
#endif
}

/**
 * Opens the new craft user interface.
 */
BUILDIN_FUNC(opencraft)
{
#if PACKETVER >= 20161012
	struct map_session_data* sd;

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_FAILURE;

	clif_refine_open(sd, REFT_CRAFT);
	return SCRIPT_CMD_SUCCESS;
#else
	ShowWarning("buildin_openrefine: The client packet version %d does not support the crafting interface\n", PACKETVER);
	return SCRIPT_CMD_SUCCESS;
#endif
}

/**
 * Opens the new enchantment user interface.
 */
BUILDIN_FUNC(openenchant)
{
#if PACKETVER >= 20161012
	struct map_session_data* sd;

	if (!script_rid2sd(sd))
		return SCRIPT_CMD_FAILURE;

	clif_refine_open(sd, REFT_ENCHANT);
	return SCRIPT_CMD_SUCCESS;
#else
	ShowWarning("buildin_openrefine: The client packet version %d does not support the enchantment interface\n", PACKETVER);
	return SCRIPT_CMD_SUCCESS;
#endif
}
