-- Use a transation to absolutely
-- no miss any inserts into messages
-- while making the function and trigger

BEGIN;


-- When making the table, import history
-- The producition table has a unique contraint  
-- On topic as part of the plan to keep the number of rows
-- constrained to the number of topics

CREATE TABLE IF NOT EXISTS recent_messages AS
SELECT DISTINCT ON (topic) topic, max(timestamp) timestamp 
FROM messages
where public = 't'
group by topic  ORDER BY topic;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'unique_topic'
    ) THEN
        ALTER TABLE recent_messages
        ADD CONSTRAINT unique_topic UNIQUE (topic);
    END IF;
END
$$;

-- New topics are rare in the wild
-- As part development  use thsi alternate table
-- to check that insert works
-- needs to work as topics are added.
--
--CREATE TABLE recent_messages (
--  topic TEXT UNIQUE,
--  timestamp BIGINT
--);


--
-- Insert or  update  recent_messagee from messages
-- Trigger on inserts
--
CREATE OR REPLACE FUNCTION update_recent_messages()
RETURNS TRIGGER AS $$
BEGIN
  -- If a row with the same topic exists, update its timestamp
  UPDATE recent_messages
  SET timestamp = NEW.timestamp
  WHERE topic = NEW.topic;

  -- If no row was updated, insert a new one
  IF NOT FOUND THEN
    INSERT INTO recent_messages (topic, timestamp)
    VALUES (NEW.topic, NEW.timestamp);
  END IF;
  RAISE NOTICE 'Inserted topic: %, timestamp: %', NEW.topic, NEW.timestamp;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trigger_update_recent_messages'
    ) THEN
       CREATE TRIGGER trigger_update_recent_messages
       AFTER INSERT ON messages
       FOR EACH ROW
       EXECUTE FUNCTION update_recent_messages();
    END IF;
END;
$$;


-- end the transaction

COMMIT;
 
-- reminder this will remove all the state development --- remove all this.
-- DROP TRIGGER trigger_update_recent_messages ON messages;
-- DROP FUNCTION update_recent_messages();
-- DROP TABLE recent_messages;

-- The follwing is a good test.
-- The selects should return identical numbers if all is working
-- SELECT count(distinct topic) , max(timestamp) from messages; ;SELECT count(*), max(timestamp) from recent_messages;


