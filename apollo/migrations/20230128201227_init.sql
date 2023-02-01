-- migrate:up
create table codes (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  archived_at timestamp,
  code text not null,
  description text not null
);

create table supported_products (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  eol_at timestamptz,
  variant text not null,
  name text not null unique,
  vendor text not null,
  code_id bigint references codes(id)
);
create index supported_products_eol_atx on supported_products(eol_at);
create index supported_products_variantx on supported_products(variant);
create index supported_products_namex on supported_products(name);

create table red_hat_index_state (
  id bigserial primary key,
  last_indexed_at timestamptz
);

create table red_hat_advisories (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  red_hat_issued_at timestamptz not null,
  name text not null unique,
  synopsis text not null,
  description text not null,
  kind text not null,
  severity text not null,
  topic text not null
);
create index red_hat_advisories_red_hat_issued_atx on red_hat_advisories(red_hat_issued_at);
create index red_hat_advisories_namex on red_hat_advisories(name);
create index red_hat_advisories_synopsisx on red_hat_advisories(synopsis);
create index red_hat_advisories_kindx on red_hat_advisories(kind);
create index red_hat_advisories_severityx on red_hat_advisories(severity);

create table red_hat_advisory_packages (
  id bigserial primary key,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete cascade,
  nevra text not null,

  unique (red_hat_advisory_id, nevra)
);
create index red_hat_advisory_packages_nevrax on red_hat_advisory_packages(nevra);

create table red_hat_advisory_cves (
  id bigserial primary key,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete cascade,
  cve text not null,
  cvss3_scoring_vector text,
  cvss3_base_score text,
  cwe text,

  unique (red_hat_advisory_id, cve)
);
create index red_hat_advisory_cvex on red_hat_advisory_cves(cve);

create table red_hat_advisory_bugzilla_bugs (
  id bigserial primary key,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete cascade,
  bugzilla_bug_id text not null,
  description text not null,

  unique (red_hat_advisory_id, bugzilla_bug_id)
);
create index red_hat_advisory_bugzilla_bugs_bugzilla_bug_idx on red_hat_advisory_bugzilla_bugs(bugzilla_bug_id);

create table red_hat_advisory_affected_products (
  id bigserial primary key,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete cascade,
  variant text not null,
  name text not null,
  major_version numeric not null,
  minor_version numeric,
  arch text not null,

  unique (red_hat_advisory_id, variant, name, major_version, minor_version, arch)
);
create index red_hat_advisory_affected_products_variantx on red_hat_advisory_affected_products(variant);
create index red_hat_advisory_affected_products_namex on red_hat_advisory_affected_products(name);
create index red_hat_advisory_affected_products_major_versionx on red_hat_advisory_affected_products(major_version);
create index red_hat_advisory_affected_products_minor_versionx on red_hat_advisory_affected_products(minor_version);
create index red_hat_advisory_affected_products_archx on red_hat_advisory_affected_products(arch);
create unique index red_hat_advisory_affected_products_variant_namex on red_hat_advisory_affected_products(red_hat_advisory_id, variant, name, major_version, minor_version, arch) where minor_version is not null;
create unique index red_hat_advisory_affected_products_variant_namenx on red_hat_advisory_affected_products(red_hat_advisory_id, variant, name, major_version, minor_version, arch) where minor_version is null;

insert into red_hat_index_state (last_indexed_at) values ('2019-05-06');

create table users (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  archived_at timestamp,
  email text not null unique,
  password text not null,
  name text not null,
  role text not null
);

create table settings (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  name text not null unique,
  value text not null
);
create index settings_namex on settings(name);

create table events (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  archived_at timestamp,
  description text not null,
  user_id bigint references users(id) on delete set null
);

create table supported_products_rh_mirrors (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  supported_product_id bigint references supported_products(id) on delete cascade,
  name text not null,
  match_variant text not null,
  match_major_version numeric not null,
  match_minor_version numeric,
  match_arch text not null
);
create index supported_products_rh_mirrors_supported_product_idx on supported_products_rh_mirrors(supported_product_id);
create index supported_products_rh_mirrors_match_variant_idx on supported_products_rh_mirrors(match_variant);
create index supported_products_rh_mirrors_match_major_version_idx on supported_products_rh_mirrors(match_major_version);
create index supported_products_rh_mirrors_match_minor_version_idx on supported_products_rh_mirrors(match_minor_version);
create index supported_products_rh_mirrors_match_arch_idx on supported_products_rh_mirrors(match_arch);

create table supported_products_rpm_repomds (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  supported_products_rh_mirror_id bigint references supported_products_rh_mirrors(id) on delete cascade,
  production boolean not null,
  arch text not null,
  url text not null,
  debug_url text not null,
  source_url text not null,
  repo_name text not null
);
create index supported_products_rpm_repomds_supporteds_rh_mirror_idx on supported_products_rpm_repomds(supported_products_rh_mirror_id);
create index supported_products_rpm_repomds_production_idx on supported_products_rpm_repomds(production);
create index supported_products_rpm_repomds_arch_idx on supported_products_rpm_repomds(arch);

create table supported_products_rpm_rh_overrides (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  supported_products_rh_mirror_id bigint references supported_products_rh_mirrors(id) on delete cascade,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete cascade
);
create index supported_products_rpm_rh_overrides_supported_products_rh_mirror_idx on supported_products_rpm_rh_overrides(supported_products_rh_mirror_id);
create index supported_products_rpm_rh_overrides_red_hat_advisory_idx on supported_products_rpm_rh_overrides(red_hat_advisory_id);

create table supported_products_rh_blocks (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  supported_products_rh_mirror_id bigint references supported_products_rh_mirrors(id) on delete cascade,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete cascade,

  unique (supported_products_rh_mirror_id, red_hat_advisory_id)
);
create index supported_products_rh_blocks_supported_products_rh_mirror_idx on supported_products_rh_blocks(supported_products_rh_mirror_id);
create index supported_products_rh_blocks_red_hat_advisory_idx on supported_products_rh_blocks(red_hat_advisory_id);

create table advisories (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  published_at timestamptz,
  name text not null unique,
  synopsis text not null,
  description text not null,
  kind text not null,
  severity text not null,
  topic text not null,
  red_hat_advisory_id bigint references red_hat_advisories(id) on delete cascade
);
create index advisories_published_atx on advisories(published_at);
create index advisories_namex on advisories(name);
create index advisories_synopsisx on advisories(synopsis);
create index advisories_kindx on advisories(kind);
create index advisories_severityx on advisories(severity);
create index advisories_red_hat_advisory_id on advisories(red_hat_advisory_id);

create table advisory_packages (
  id bigserial primary key,
  advisory_id bigint references advisories(id) on delete cascade,
  nevra text not null,
  checksum text not null,
  checksum_type text not null,
  module_context text,
  module_name text,
  module_stream text,
  module_version text,
  repo_name text not null,
  package_name text not null,
  supported_products_rh_mirror_id bigint references supported_products_rh_mirrors(id) on delete cascade,
  supported_product_id bigint references supported_products(id) on delete cascade,
  product_name text not null,

  unique (advisory_id, nevra, repo_name, supported_products_rh_mirror_id)
);
create index advisory_packages_advisory_id on advisory_packages(advisory_id);
create index advisory_packages_nevrax on advisory_packages(nevra);
create index advisory_packages_checksumx on advisory_packages(checksum);
create index advisory_packages_supported_products_rh_mirror_idx on advisory_packages(supported_products_rh_mirror_id);
create index advisory_packages_supported_product_idx on advisory_packages(supported_product_id);
create index advisory_packages_product_name_idx on advisory_packages(product_name);

create table advisory_cves (
  id bigserial primary key,
  advisory_id bigint references advisories(id) on delete cascade,
  cve text not null,
  cvss3_scoring_vector text,
  cvss3_base_score text,
  cwe text,

  unique (advisory_id, cve)
);
create index advisory_cvex on advisory_cves(cve);

create table advisory_fixes (
  id bigserial primary key,
  advisory_id bigint references advisories(id) on delete cascade,
  ticket_id text not null,
  source text not null,
  description text,

  unique (advisory_id, ticket_id)
);
create index advisory_fixes_advisory_id on advisory_fixes(advisory_id);
create index advisory_fixes_ticket_id on advisory_fixes(ticket_id);

create table advisory_affected_products (
  id bigserial primary key,
  advisory_id bigint references advisories(id) on delete cascade,
  variant text not null,
  name text not null,
  major_version numeric not null,
  minor_version numeric,
  arch text not null,
  supported_product_id bigint references supported_products(id) on delete cascade,

  unique (advisory_id, name)
);
create index advisory_affected_products_variantx on advisory_affected_products(variant);
create index advisory_affected_products_namex on advisory_affected_products(name);
create index advisory_affected_products_major_versionx on advisory_affected_products(major_version);
create index advisory_affected_products_minor_versionx on advisory_affected_products(minor_version);
create index advisory_affected_products_archx on advisory_affected_products(arch);
create index advisory_affected_products_supported_product_idx on advisory_affected_products(supported_product_id);

-- migrate:down