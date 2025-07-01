-- ユーザー情報
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);

-- 授業情報
CREATE TABLE classes (
  class_id SERIAL PRIMARY KEY,
  class_title TEXT NOT NULL,
  required BOOLEAN NOT NULL DEFAULT false,
  count INTEGER NOT NULL DEFAULT 0,
  user_id INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
