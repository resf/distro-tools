-- migrate:up
create table api_keys (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  revoked_at timestamptz,
  name varchar(255) not null,
  key_hash varchar(255) not null,
  key_prefix varchar(32) not null,
  user_id bigint not null references users(id) on delete cascade,
  permissions jsonb not null default '[]'::jsonb,
  expires_at timestamptz,
  last_used_at timestamptz
);


-- migrate:down
drop table if exists api_keys;