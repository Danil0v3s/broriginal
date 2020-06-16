--
-- Feature: Item durability
--

ALTER TABLE `auction` ADD `durability` INT(11) UNSIGNED;
ALTER TABLE `cart_inventory` ADD `durability` INT(11) UNSIGNED;
ALTER TABLE `guild_storage` ADD `durability` INT(11) UNSIGNED;
ALTER TABLE `inventory` ADD `durability` INT(11) UNSIGNED;
ALTER TABLE `mail_attachments` ADD `durability` INT(11) UNSIGNED;
ALTER TABLE `storage` ADD `durability` INT(11) UNSIGNED;

ALTER TABLE `picklog` ADD `durability` INT(11) UNSIGNED;
ALTER TABLE `guild_storage_log` ADD `durability` INT(11) UNSIGNED;

UPDATE `auction` SET `durability` = 1000000;
UPDATE `cart_inventory` SET `durability` = 1000000;
UPDATE `guild_storage` SET `durability` = 1000000;
UPDATE `inventory` SET `durability` = 1000000;
UPDATE `mail_attachments` SET `durability` = 1000000;
UPDATE `storage` SET `durability` = 1000000;

--
-- Feature: Item Bazaar
--

CREATE TABLE `bazaar` (
	`id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
	`char_id` INT(11) UNSIGNED NOT NULL,
	`account_id` INT(11) UNSIGNED,
	`bazaar_id` SMALLINT(5) UNSIGNED NOT NULL,
	`available` SMALLINT(5) UNSIGNED NOT NULL,
	`bought` SMALLINT(5) UNSIGNED NOT NULL,
	PRIMARY KEY (`id`),
	KEY `id` (`id`),
	INDEX `bazaar_char` (`char_id`),
	INDEX `bazaar_account` (`account_id`)
) ENGINE = MyISAM;

CREATE TABLE `bazaar_sell` (
	`id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
	`char_id` INT(11) UNSIGNED NOT NULL,
	`item_id` SMALLINT(5) UNSIGNED NOT NULL,
	`amount` SMALLINT(5) UNSIGNED NOT NULL DEFAULT 0,
	PRIMARY KEY (`id`),
	KEY `id` (`id`),
	INDEX `bazaar_sell_char` (`char_id`)
) ENGINE = MyISAM;