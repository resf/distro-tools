-- migrate:up
alter table red_hat_advisory_packages
  add column if not exists module_context text,
  add column if not exists module_name text,
  add column if not exists module_stream text,
  add column if not exists module_version text;


-- migrate:down
alter table red_hat_advisory_packages
  drop column if exists module_context,
  drop column if exists module_name,
  drop column if exists module_stream,
  drop column if exists module_version;
