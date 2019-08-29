CREATE TABLE IF NOT EXISTS scratchverifier_clients (
  -- client ID
  client_id integer PRIMARY KEY,
  -- API token
  token text UNIQUE,
  -- Scratch username of owner
  username text
);
CREATE TABLE IF NOT EXISTS scratchverifier_sessions (
  -- session ID
  session_id integer PRIMARY KEY,
  -- expiry time: unix epoch integer
  expiry integer,
  -- Scratch username of session
  username text
);
CREATE TABLE IF NOT EXISTS scratchverifier_usage (
  -- client ID responsible for this verification
  client_id integer,
  -- the verification code in question
  code text,
  -- name of user who needs to comment the code
  username text,
  -- expiry time of code: linux epoch integer
  expiry integer
);
CREATE TABLE IF NOT EXISTS scratchverifier_logs (
  -- log ID to look up by
  log_id integer PRIMARY KEY AUTOINCREMENT,
  -- client ID used for the verification
  client_id integer,
  -- username being verified
  username text,
  -- time of log (unix epoch time)
  log_time integer,
  -- type of log: 1 for starting verification, 2 for successful, 3 for failed verification
  log_type integer
);
