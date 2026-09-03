-- migrate:up
create table cve_product_statuses (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  cve text not null,
  supported_product_id bigint not null references supported_products(id) on delete cascade,
  status varchar(64) not null,
  reason text,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete set null,
  advisory_id bigint references advisories(id) on delete set null,
  constraint cve_product_statuses_status_check
    check (status in ('fixed', 'not_shipped', 'under_investigation')),
  constraint cve_product_statuses_unique
    unique (cve, supported_product_id)
);

create index cve_product_statuses_cve_idx on cve_product_statuses (cve);
create index cve_product_statuses_status_idx on cve_product_statuses (status);
create index cve_product_statuses_product_idx on cve_product_statuses (supported_product_id);

-- migrate:down
drop table if exists cve_product_statuses;
