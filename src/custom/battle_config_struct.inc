// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

/**
 * Custom battle config structure
 * Place the definition of custom battle configuration structure members in this file.
 *
 * Make sure that the name you want is not already taken by looking into battle.hpp
 * Do not forget to add initilization logic to battle_config_init.inc
 *
 * Format:
 *	 <datatype> name;
 **/

#ifdef STORM_ITEM_DURABILITY
int storm_item_durability;
int storm_item_armor_mask;
int storm_item_armor_break;
int storm_item_weapon_break;
int storm_item_armor_break_chance;
int storm_item_weapon_break_chance;
int storm_item_armor_weaken;
int storm_item_weapon_weaken;
int storm_item_armor_decrease;
int storm_item_weapon_decrease;
int storm_item_armor_decrease_rate;
int storm_item_weapon_decrease_rate;
int storm_item_durability_random_option;
int storm_item_durability_repair;
int storm_item_durability_protect;
#endif
int storm_enchant_weapon_max;
int storm_enchant_shield_max;
int storm_enchant_armor_max;
int storm_enchant_garment_max;
int storm_enchant_shoes_max;
int storm_enchant_accessory_max;
int storm_enchant_headgear_max;
#ifdef STORM_BAZAAR
int storm_bazaar;
int storm_bazaar_cutin;
int storm_bazaar_notice;
#endif
