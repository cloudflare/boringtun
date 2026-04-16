-- V005: widen blocked_events.ja3_lite to match the runtime JA3-lite payload
-- and the normalized tls_fingerprints store.
DECLARE
  v_count INTEGER;
  v_len   INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'JA3_LITE';

  IF v_count = 1 THEN
    SELECT COALESCE(char_col_decl_length, data_length) INTO v_len
    FROM user_tab_columns
    WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'JA3_LITE';

    IF v_len < 512 THEN
      EXECUTE IMMEDIATE 'ALTER TABLE blocked_events MODIFY (ja3_lite VARCHAR2(512))';
    END IF;
  END IF;
END;
/
