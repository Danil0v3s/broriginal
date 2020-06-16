// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

/**
 * Custom battle config initializations
 * Place the definition of custom battle configuration initializations in this file.
 *
 * Do not forget to add a comma at the end of the line, if you want to add another config
 *
 * Format:
 *	 { "name", &battle_config.<variable name>, <default value>, <minimum value>, <maximum value> },
 **/

#ifdef STORM_ITEM_DURABILITY
{ "stormbreaker.item_durability", &battle_config.storm_item_durability, 0, 0, 1 },
{ "stormbreaker.item_armor_mask", &battle_config.storm_item_armor_mask, 0xffffff, 0, INT_MAX },
{ "stormbreaker.item_armor_break", &battle_config.storm_item_armor_break, 1, 0, 1 },
{ "stormbreaker.item_weapon_break", &battle_config.storm_item_weapon_break, 1, 0, 1 },
{ "stormbreaker.item_armor_weaken", &battle_config.storm_item_armor_weaken, 0, 0, 10000 },
{ "stormbreaker.item_weapon_weaken", &battle_config.storm_item_weapon_weaken, 0, 0, 10000 },
{ "stormbreaker.item_armor_break_chance", &battle_config.storm_item_armor_break_chance, 0, 0, 10000 },
{ "stormbreaker.item_weapon_break_chance", &battle_config.storm_item_weapon_break_chance, 0, 0, 10000 },
{ "stormbreaker.item_armor_decrease", &battle_config.storm_item_armor_decrease, 1, 0, 2 },
{ "stormbreaker.item_weapon_decrease", &battle_config.storm_item_weapon_decrease, 1, 0, 2 },
{ "stormbreaker.item_armor_decrease_rate", &battle_config.storm_item_armor_decrease_rate, 1, 0, STORM_ITEM_MAX_DURABILITY },
{ "stormbreaker.item_weapon_decrease_rate", &battle_config.storm_item_weapon_decrease_rate, 1, 0, STORM_ITEM_MAX_DURABILITY },
{ "stormbreaker.item_durability_random_option", &battle_config.storm_item_durability_random_option, 1, 0, 1 },
{ "stormbreaker.item_durability_repair", &battle_config.storm_item_durability_repair, 1, 0, 1 },
{ "stormbreaker.item_durability_protect", &battle_config.storm_item_durability_protect, 0, 0, 1 },
#endif

{ "stormbreaker.enchant_weapon_max", &battle_config.storm_enchant_weapon_max, 0, 0, MAX_ITEM_RDM_OPT },
{ "stormbreaker.enchant_shield_max", &battle_config.storm_enchant_shield_max, 0, 0, MAX_ITEM_RDM_OPT },
{ "stormbreaker.enchant_armor_max", &battle_config.storm_enchant_armor_max, 0, 0, MAX_ITEM_RDM_OPT },
{ "stormbreaker.enchant_garment_max", &battle_config.storm_enchant_garment_max, 0, 0, MAX_ITEM_RDM_OPT },
{ "stormbreaker.enchant_shoes_max", &battle_config.storm_enchant_shoes_max, 0, 0, MAX_ITEM_RDM_OPT },
{ "stormbreaker.enchant_accessory_max", &battle_config.storm_enchant_accessory_max, 0, 0, MAX_ITEM_RDM_OPT },
{ "stormbreaker.enchant_headgear_max", &battle_config.storm_enchant_headgear_max, 0, 0, MAX_ITEM_RDM_OPT },

#ifdef STORM_BAZAAR
{ "stormbreaker.bazaar", &battle_config.storm_bazaar, 0, 0, 1 },
{ "stormbreaker.bazaar_cutin", &battle_config.storm_bazaar_cutin, 0, 0, INT_MAX },
{ "stormbreaker.bazaar_notice", &battle_config.storm_bazaar_notice, 0, 0, 2 },
#endif
