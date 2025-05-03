PRAGMA foreign_keys = off;

BEGIN TRANSACTION;

ALTER TABLE ratings RENAME TO ratings_old;

CREATE TABLE ratings (
  id         INTEGER PRIMARY KEY,
  rating     INTEGER    NULL,
  project_id INTEGER    NOT NULL REFERENCES projects(id),
  comment    TEXT       NULL,
  created_at DATETIME   DEFAULT CURRENT_TIMESTAMP,
  approved   BOOLEAN    DEFAULT 0 NOT NULL
);

INSERT INTO ratings (id, rating, project_id, comment, created_at, approved)
  SELECT id, rating, project_id, comment, created_at, approved
    FROM ratings_old;

DROP TABLE ratings_old;

COMMIT;

PRAGMA foreign_keys = on;
