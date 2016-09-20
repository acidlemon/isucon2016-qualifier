ALTER TABLE entry ADD COLUMN `keyword_length` int(10) unsigned;

UPDATE entry SET keyword_length = CHARACTER_LENGTH(keyword);

;ALTER TABLE entry ADD INDEX `idx_keyword_length_keyword` (`keyword_length`, `keyword`);

ALTER TABLE star ADD INDEX `idx_keyword` (`keyword`);

ALTER TABLE entry ADD INDEX `idx_updated_at` (`updated_at`);

ALTER TABLE entry ADD COLUMN `keyword_sha1` varchar(40);

UPDATE entry SET keyword_sha1 = SHA1(keyword);

ALTER TABLE entry ADD INDEX `idx_keyword_length_keyword_keyword_sha1` (`keyword_length`, `keyword`, `keyword_sha1`);

ALTER TABLE entry ADD COLUMN description_html MEDIUMTEXT AFTER description;

alter table entry add fulltext(description);
