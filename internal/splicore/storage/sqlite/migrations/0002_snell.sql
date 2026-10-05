ALTER TABLE transactions ADD COLUMN operation TEXT NOT NULL DEFAULT 'domain';
CREATE TRIGGER snell_single_binding BEFORE INSERT ON bindings
WHEN (SELECT protocol FROM inbounds WHERE id=NEW.inbound_id)='snell'
AND EXISTS(SELECT 1 FROM bindings WHERE inbound_id=NEW.inbound_id)
BEGIN SELECT RAISE(ABORT,'Snell profile requires one binding'); END;
