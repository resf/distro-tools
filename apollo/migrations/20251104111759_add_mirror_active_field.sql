-- migrate:up
alter table supported_products_rh_mirrors
add column active boolean not null default true;

create index supported_products_rh_mirrors_active_idx
on supported_products_rh_mirrors(active);


-- migrate:down
drop index if exists supported_products_rh_mirrors_active_idx;
alter table supported_products_rh_mirrors drop column active;
