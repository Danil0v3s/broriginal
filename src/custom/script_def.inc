// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

/**
 * Custom Script Commands
 * Place the definition of custom script commands in this file.
 * Format:
 *	BUILDIN_DEF(command_name,"parameters"),
 **/

BUILDIN_DEF(inventoryselect, "i?*"),
BUILDIN_DEF(skillselect, "?*"),
BUILDIN_DEF(partymonster, "siisii*"),
BUILDIN_DEF(openrefine, ""),
BUILDIN_DEF(opencraft, ""),
BUILDIN_DEF(openenchant, ""),
BUILDIN_DEF(openshop, "ri*"),
BUILDIN_DEF(statusbonus, "is"),

#ifdef STORM_ITEM_DURABILITY
BUILDIN_DEF(getdurabilityid, "i"),
BUILDIN_DEF(getdurability, "*"),
BUILDIN_DEF(getequipdurability, "i"),
BUILDIN_DEF(setdurability, "ii"),
#endif

