CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  created INTEGER NOT NULL,
  title TEXT,
  data TEXT NOT NULL,
  device_count INTEGER DEFAULT 0,
  summary TEXT,
  comments INTEGER DEFAULT 0,
  reports INTEGER DEFAULT 0,
  hidden INTEGER DEFAULT 0,
  iph TEXT
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created);

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL,
  created INTEGER NOT NULL,
  body TEXT NOT NULL,
  iph TEXT
);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created);

CREATE TABLE IF NOT EXISTS rate (
  iph TEXT,
  action TEXT,
  ts INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rate ON rate(iph, action, ts);

CREATE TABLE IF NOT EXISTS bans (
  iph TEXT PRIMARY KEY,
  created INTEGER,
  reason TEXT
);

CREATE TABLE IF NOT EXISTS reports (
  post_id TEXT,
  iph TEXT,
  created INTEGER,
  PRIMARY KEY (post_id, iph)
);
