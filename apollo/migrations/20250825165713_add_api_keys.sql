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

create index api_keys_user_id_idx on api_keys(user_id);
create index api_keys_key_prefix_idx on api_keys(key_prefix);
create index api_keys_revoked_at_idx on api_keys(revoked_at);
create index api_keys_expires_at_idx on api_keys(expires_at);

-- migrate:down
drop table if exists api_keys;