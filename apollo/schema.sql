SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisories (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    published_at timestamp with time zone,
    name text NOT NULL,
    synopsis text NOT NULL,
    description text NOT NULL,
    kind text NOT NULL,
    severity text NOT NULL,
    topic text NOT NULL,
    red_hat_advisory_id bigint
);


--
-- Name: advisories_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.advisories_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: advisories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.advisories_id_seq OWNED BY public.advisories.id;


--
-- Name: advisory_affected_products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisory_affected_products (
    id bigint NOT NULL,
    advisory_id bigint,
    variant text NOT NULL,
    name text NOT NULL,
    major_version numeric NOT NULL,
    minor_version numeric,
    arch text NOT NULL,
    supported_product_id bigint
);


--
-- Name: advisory_affected_products_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.advisory_affected_products_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: advisory_affected_products_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.advisory_affected_products_id_seq OWNED BY public.advisory_affected_products.id;


--
-- Name: advisory_cves; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisory_cves (
    id bigint NOT NULL,
    advisory_id bigint,
    cve text NOT NULL,
    cvss3_scoring_vector text,
    cvss3_base_score text,
    cwe text
);


--
-- Name: advisory_cves_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.advisory_cves_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: advisory_cves_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.advisory_cves_id_seq OWNED BY public.advisory_cves.id;


--
-- Name: advisory_fixes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisory_fixes (
    id bigint NOT NULL,
    advisory_id bigint,
    ticket_id text NOT NULL,
    source text NOT NULL,
    description text
);


--
-- Name: advisory_fixes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.advisory_fixes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: advisory_fixes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.advisory_fixes_id_seq OWNED BY public.advisory_fixes.id;


--
-- Name: advisory_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisory_packages (
    id bigint NOT NULL,
    advisory_id bigint,
    nevra text NOT NULL,
    checksum text NOT NULL,
    checksum_type text NOT NULL,
    module_context text,
    module_name text,
    module_stream text,
    module_version text,
    repo_name text NOT NULL,
    package_name text NOT NULL,
    supported_products_rh_mirror_id bigint,
    supported_product_id bigint,
    product_name text NOT NULL
);


--
-- Name: advisory_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.advisory_packages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: advisory_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.advisory_packages_id_seq OWNED BY public.advisory_packages.id;


--
-- Name: codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.codes (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    archived_at timestamp without time zone,
    code text NOT NULL,
    description text NOT NULL
);


--
-- Name: codes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.codes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: codes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.codes_id_seq OWNED BY public.codes.id;


--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    archived_at timestamp without time zone,
    description text NOT NULL,
    user_id bigint
);


--
-- Name: events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.events_id_seq OWNED BY public.events.id;


--
-- Name: red_hat_advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.red_hat_advisories (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    red_hat_issued_at timestamp with time zone NOT NULL,
    name text NOT NULL,
    synopsis text NOT NULL,
    description text NOT NULL,
    kind text NOT NULL,
    severity text NOT NULL,
    topic text NOT NULL
);


--
-- Name: red_hat_advisories_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.red_hat_advisories_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: red_hat_advisories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.red_hat_advisories_id_seq OWNED BY public.red_hat_advisories.id;


--
-- Name: red_hat_advisory_affected_products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.red_hat_advisory_affected_products (
    id bigint NOT NULL,
    red_hat_advisory_id bigint,
    variant text NOT NULL,
    name text NOT NULL,
    major_version numeric NOT NULL,
    minor_version numeric,
    arch text NOT NULL
);


--
-- Name: red_hat_advisory_affected_products_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.red_hat_advisory_affected_products_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: red_hat_advisory_affected_products_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.red_hat_advisory_affected_products_id_seq OWNED BY public.red_hat_advisory_affected_products.id;


--
-- Name: red_hat_advisory_bugzilla_bugs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.red_hat_advisory_bugzilla_bugs (
    id bigint NOT NULL,
    red_hat_advisory_id bigint,
    bugzilla_bug_id text NOT NULL,
    description text NOT NULL
);


--
-- Name: red_hat_advisory_bugzilla_bugs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.red_hat_advisory_bugzilla_bugs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: red_hat_advisory_bugzilla_bugs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.red_hat_advisory_bugzilla_bugs_id_seq OWNED BY public.red_hat_advisory_bugzilla_bugs.id;


--
-- Name: red_hat_advisory_cves; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.red_hat_advisory_cves (
    id bigint NOT NULL,
    red_hat_advisory_id bigint,
    cve text NOT NULL,
    cvss3_scoring_vector text,
    cvss3_base_score text,
    cwe text
);


--
-- Name: red_hat_advisory_cves_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.red_hat_advisory_cves_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: red_hat_advisory_cves_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.red_hat_advisory_cves_id_seq OWNED BY public.red_hat_advisory_cves.id;


--
-- Name: red_hat_advisory_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.red_hat_advisory_packages (
    id bigint NOT NULL,
    red_hat_advisory_id bigint,
    nevra text NOT NULL
);


--
-- Name: red_hat_advisory_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.red_hat_advisory_packages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: red_hat_advisory_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.red_hat_advisory_packages_id_seq OWNED BY public.red_hat_advisory_packages.id;


--
-- Name: red_hat_index_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.red_hat_index_state (
    id bigint NOT NULL,
    last_indexed_at timestamp with time zone
);


--
-- Name: red_hat_index_state_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.red_hat_index_state_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: red_hat_index_state_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.red_hat_index_state_id_seq OWNED BY public.red_hat_index_state.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version character varying(255) NOT NULL
);


--
-- Name: settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.settings (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    name text NOT NULL,
    value text NOT NULL
);


--
-- Name: settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.settings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.settings_id_seq OWNED BY public.settings.id;


--
-- Name: supported_products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supported_products (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    eol_at timestamp with time zone,
    variant text NOT NULL,
    name text NOT NULL,
    vendor text NOT NULL,
    code_id bigint
);


--
-- Name: supported_products_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.supported_products_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: supported_products_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.supported_products_id_seq OWNED BY public.supported_products.id;


--
-- Name: supported_products_rh_blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supported_products_rh_blocks (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    supported_products_rh_mirror_id bigint,
    red_hat_advisory_id bigint
);


--
-- Name: supported_products_rh_blocks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.supported_products_rh_blocks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: supported_products_rh_blocks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.supported_products_rh_blocks_id_seq OWNED BY public.supported_products_rh_blocks.id;


--
-- Name: supported_products_rh_mirrors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supported_products_rh_mirrors (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    supported_product_id bigint,
    name text NOT NULL,
    match_variant text NOT NULL,
    match_major_version numeric NOT NULL,
    match_minor_version numeric,
    match_arch text NOT NULL
);


--
-- Name: supported_products_rh_mirrors_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.supported_products_rh_mirrors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: supported_products_rh_mirrors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.supported_products_rh_mirrors_id_seq OWNED BY public.supported_products_rh_mirrors.id;


--
-- Name: supported_products_rpm_repomds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supported_products_rpm_repomds (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    supported_products_rh_mirror_id bigint,
    production boolean NOT NULL,
    arch text NOT NULL,
    url text NOT NULL,
    debug_url text NOT NULL,
    source_url text NOT NULL,
    repo_name text NOT NULL
);


--
-- Name: supported_products_rpm_repomds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.supported_products_rpm_repomds_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: supported_products_rpm_repomds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.supported_products_rpm_repomds_id_seq OWNED BY public.supported_products_rpm_repomds.id;


--
-- Name: supported_products_rpm_rh_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supported_products_rpm_rh_overrides (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    supported_products_rh_mirror_id bigint,
    red_hat_advisory_id bigint
);


--
-- Name: supported_products_rpm_rh_overrides_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.supported_products_rpm_rh_overrides_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: supported_products_rpm_rh_overrides_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.supported_products_rpm_rh_overrides_id_seq OWNED BY public.supported_products_rpm_rh_overrides.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    archived_at timestamp without time zone,
    email text NOT NULL,
    password text NOT NULL,
    name text NOT NULL,
    role text NOT NULL
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    revoked_at timestamp with time zone,
    name varchar(255) NOT NULL,
    key_hash varchar(255) NOT NULL,
    key_prefix varchar(32) NOT NULL,
    user_id bigint NOT NULL,
    permissions jsonb DEFAULT '[]'::jsonb NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone
);


--
-- Name: api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.api_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.api_keys_id_seq OWNED BY public.api_keys.id;


--
-- Name: advisories id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisories ALTER COLUMN id SET DEFAULT nextval('public.advisories_id_seq'::regclass);


--
-- Name: advisory_affected_products id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_affected_products ALTER COLUMN id SET DEFAULT nextval('public.advisory_affected_products_id_seq'::regclass);


--
-- Name: advisory_cves id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_cves ALTER COLUMN id SET DEFAULT nextval('public.advisory_cves_id_seq'::regclass);


--
-- Name: advisory_fixes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_fixes ALTER COLUMN id SET DEFAULT nextval('public.advisory_fixes_id_seq'::regclass);


--
-- Name: advisory_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_packages ALTER COLUMN id SET DEFAULT nextval('public.advisory_packages_id_seq'::regclass);


--
-- Name: codes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.codes ALTER COLUMN id SET DEFAULT nextval('public.codes_id_seq'::regclass);


--
-- Name: events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ALTER COLUMN id SET DEFAULT nextval('public.events_id_seq'::regclass);


--
-- Name: red_hat_advisories id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisories ALTER COLUMN id SET DEFAULT nextval('public.red_hat_advisories_id_seq'::regclass);


--
-- Name: red_hat_advisory_affected_products id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_affected_products ALTER COLUMN id SET DEFAULT nextval('public.red_hat_advisory_affected_products_id_seq'::regclass);


--
-- Name: red_hat_advisory_bugzilla_bugs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_bugzilla_bugs ALTER COLUMN id SET DEFAULT nextval('public.red_hat_advisory_bugzilla_bugs_id_seq'::regclass);


--
-- Name: red_hat_advisory_cves id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_cves ALTER COLUMN id SET DEFAULT nextval('public.red_hat_advisory_cves_id_seq'::regclass);


--
-- Name: red_hat_advisory_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_packages ALTER COLUMN id SET DEFAULT nextval('public.red_hat_advisory_packages_id_seq'::regclass);


--
-- Name: red_hat_index_state id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_index_state ALTER COLUMN id SET DEFAULT nextval('public.red_hat_index_state_id_seq'::regclass);


--
-- Name: settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings ALTER COLUMN id SET DEFAULT nextval('public.settings_id_seq'::regclass);


--
-- Name: supported_products id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products ALTER COLUMN id SET DEFAULT nextval('public.supported_products_id_seq'::regclass);


--
-- Name: supported_products_rh_blocks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_blocks ALTER COLUMN id SET DEFAULT nextval('public.supported_products_rh_blocks_id_seq'::regclass);


--
-- Name: supported_products_rh_mirrors id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_mirrors ALTER COLUMN id SET DEFAULT nextval('public.supported_products_rh_mirrors_id_seq'::regclass);


--
-- Name: supported_products_rpm_repomds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rpm_repomds ALTER COLUMN id SET DEFAULT nextval('public.supported_products_rpm_repomds_id_seq'::regclass);


--
-- Name: supported_products_rpm_rh_overrides id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rpm_rh_overrides ALTER COLUMN id SET DEFAULT nextval('public.supported_products_rpm_rh_overrides_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: api_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys ALTER COLUMN id SET DEFAULT nextval('public.api_keys_id_seq'::regclass);


--
-- Name: advisories advisories_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisories
    ADD CONSTRAINT advisories_name_key UNIQUE (name);


--
-- Name: advisories advisories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisories
    ADD CONSTRAINT advisories_pkey PRIMARY KEY (id);


--
-- Name: advisory_affected_products advisory_affected_products_advisory_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_affected_products
    ADD CONSTRAINT advisory_affected_products_advisory_id_name_key UNIQUE (advisory_id, name);


--
-- Name: advisory_affected_products advisory_affected_products_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_affected_products
    ADD CONSTRAINT advisory_affected_products_pkey PRIMARY KEY (id);


--
-- Name: advisory_cves advisory_cves_advisory_id_cve_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_cves
    ADD CONSTRAINT advisory_cves_advisory_id_cve_key UNIQUE (advisory_id, cve);


--
-- Name: advisory_cves advisory_cves_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_cves
    ADD CONSTRAINT advisory_cves_pkey PRIMARY KEY (id);


--
-- Name: advisory_fixes advisory_fixes_advisory_id_ticket_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_fixes
    ADD CONSTRAINT advisory_fixes_advisory_id_ticket_id_key UNIQUE (advisory_id, ticket_id);


--
-- Name: advisory_fixes advisory_fixes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_fixes
    ADD CONSTRAINT advisory_fixes_pkey PRIMARY KEY (id);


--
-- Name: advisory_packages advisory_packages_advisory_id_nevra_repo_name_supported_pro_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_packages
    ADD CONSTRAINT advisory_packages_advisory_id_nevra_repo_name_supported_pro_key UNIQUE (advisory_id, nevra, repo_name, supported_products_rh_mirror_id);


--
-- Name: advisory_packages advisory_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_packages
    ADD CONSTRAINT advisory_packages_pkey PRIMARY KEY (id);


--
-- Name: codes codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.codes
    ADD CONSTRAINT codes_pkey PRIMARY KEY (id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);


--
-- Name: red_hat_advisories red_hat_advisories_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisories
    ADD CONSTRAINT red_hat_advisories_name_key UNIQUE (name);


--
-- Name: red_hat_advisories red_hat_advisories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisories
    ADD CONSTRAINT red_hat_advisories_pkey PRIMARY KEY (id);


--
-- Name: red_hat_advisory_affected_products red_hat_advisory_affected_pro_red_hat_advisory_id_variant_n_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_affected_products
    ADD CONSTRAINT red_hat_advisory_affected_pro_red_hat_advisory_id_variant_n_key UNIQUE (red_hat_advisory_id, variant, name, major_version, minor_version, arch);


--
-- Name: red_hat_advisory_affected_products red_hat_advisory_affected_products_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_affected_products
    ADD CONSTRAINT red_hat_advisory_affected_products_pkey PRIMARY KEY (id);


--
-- Name: red_hat_advisory_bugzilla_bugs red_hat_advisory_bugzilla_bug_red_hat_advisory_id_bugzilla__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_bugzilla_bugs
    ADD CONSTRAINT red_hat_advisory_bugzilla_bug_red_hat_advisory_id_bugzilla__key UNIQUE (red_hat_advisory_id, bugzilla_bug_id);


--
-- Name: red_hat_advisory_bugzilla_bugs red_hat_advisory_bugzilla_bugs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_bugzilla_bugs
    ADD CONSTRAINT red_hat_advisory_bugzilla_bugs_pkey PRIMARY KEY (id);


--
-- Name: red_hat_advisory_cves red_hat_advisory_cves_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_cves
    ADD CONSTRAINT red_hat_advisory_cves_pkey PRIMARY KEY (id);


--
-- Name: red_hat_advisory_cves red_hat_advisory_cves_red_hat_advisory_id_cve_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_cves
    ADD CONSTRAINT red_hat_advisory_cves_red_hat_advisory_id_cve_key UNIQUE (red_hat_advisory_id, cve);


--
-- Name: red_hat_advisory_packages red_hat_advisory_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_packages
    ADD CONSTRAINT red_hat_advisory_packages_pkey PRIMARY KEY (id);


--
-- Name: red_hat_advisory_packages red_hat_advisory_packages_red_hat_advisory_id_nevra_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_packages
    ADD CONSTRAINT red_hat_advisory_packages_red_hat_advisory_id_nevra_key UNIQUE (red_hat_advisory_id, nevra);


--
-- Name: red_hat_index_state red_hat_index_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_index_state
    ADD CONSTRAINT red_hat_index_state_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: settings settings_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_name_key UNIQUE (name);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (id);


--
-- Name: supported_products supported_products_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products
    ADD CONSTRAINT supported_products_name_key UNIQUE (name);


--
-- Name: supported_products supported_products_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products
    ADD CONSTRAINT supported_products_pkey PRIMARY KEY (id);


--
-- Name: supported_products_rh_blocks supported_products_rh_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_blocks
    ADD CONSTRAINT supported_products_rh_blocks_pkey PRIMARY KEY (id);


--
-- Name: supported_products_rh_blocks supported_products_rh_blocks_supported_products_rh_mirror_i_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_blocks
    ADD CONSTRAINT supported_products_rh_blocks_supported_products_rh_mirror_i_key UNIQUE (supported_products_rh_mirror_id, red_hat_advisory_id);


--
-- Name: supported_products_rh_mirrors supported_products_rh_mirrors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_mirrors
    ADD CONSTRAINT supported_products_rh_mirrors_pkey PRIMARY KEY (id);


--
-- Name: supported_products_rpm_repomds supported_products_rpm_repomds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rpm_repomds
    ADD CONSTRAINT supported_products_rpm_repomds_pkey PRIMARY KEY (id);


--
-- Name: supported_products_rpm_rh_overrides supported_products_rpm_rh_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rpm_rh_overrides
    ADD CONSTRAINT supported_products_rpm_rh_overrides_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: advisories_kindx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisories_kindx ON public.advisories USING btree (kind);


--
-- Name: advisories_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisories_namex ON public.advisories USING btree (name);


--
-- Name: advisories_published_atx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisories_published_atx ON public.advisories USING btree (published_at);


--
-- Name: advisories_red_hat_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisories_red_hat_advisory_id ON public.advisories USING btree (red_hat_advisory_id);


--
-- Name: advisories_severityx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisories_severityx ON public.advisories USING btree (severity);


--
-- Name: advisories_synopsisx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisories_synopsisx ON public.advisories USING btree (synopsis);


--
-- Name: advisory_affected_products_archx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_affected_products_archx ON public.advisory_affected_products USING btree (arch);


--
-- Name: advisory_affected_products_major_versionx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_affected_products_major_versionx ON public.advisory_affected_products USING btree (major_version);


--
-- Name: advisory_affected_products_minor_versionx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_affected_products_minor_versionx ON public.advisory_affected_products USING btree (minor_version);


--
-- Name: advisory_affected_products_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_affected_products_namex ON public.advisory_affected_products USING btree (name);


--
-- Name: advisory_affected_products_supported_product_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_affected_products_supported_product_idx ON public.advisory_affected_products USING btree (supported_product_id);


--
-- Name: advisory_affected_products_variantx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_affected_products_variantx ON public.advisory_affected_products USING btree (variant);


--
-- Name: advisory_cvex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_cvex ON public.advisory_cves USING btree (cve);


--
-- Name: advisory_fixes_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_fixes_advisory_id ON public.advisory_fixes USING btree (advisory_id);


--
-- Name: advisory_fixes_ticket_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_fixes_ticket_id ON public.advisory_fixes USING btree (ticket_id);


--
-- Name: advisory_packages_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_packages_advisory_id ON public.advisory_packages USING btree (advisory_id);


--
-- Name: advisory_packages_checksumx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_packages_checksumx ON public.advisory_packages USING btree (checksum);


--
-- Name: advisory_packages_nevrax; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_packages_nevrax ON public.advisory_packages USING btree (nevra);


--
-- Name: advisory_packages_product_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_packages_product_name_idx ON public.advisory_packages USING btree (product_name);


--
-- Name: advisory_packages_supported_product_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_packages_supported_product_idx ON public.advisory_packages USING btree (supported_product_id);


--
-- Name: advisory_packages_supported_products_rh_mirror_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX advisory_packages_supported_products_rh_mirror_idx ON public.advisory_packages USING btree (supported_products_rh_mirror_id);


--
-- Name: red_hat_advisories_kindx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisories_kindx ON public.red_hat_advisories USING btree (kind);


--
-- Name: red_hat_advisories_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisories_namex ON public.red_hat_advisories USING btree (name);


--
-- Name: red_hat_advisories_red_hat_issued_atx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisories_red_hat_issued_atx ON public.red_hat_advisories USING btree (red_hat_issued_at);


--
-- Name: red_hat_advisories_severityx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisories_severityx ON public.red_hat_advisories USING btree (severity);


--
-- Name: red_hat_advisories_synopsisx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisories_synopsisx ON public.red_hat_advisories USING btree (synopsis);


--
-- Name: red_hat_advisory_affected_products_archx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_affected_products_archx ON public.red_hat_advisory_affected_products USING btree (arch);


--
-- Name: red_hat_advisory_affected_products_major_versionx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_affected_products_major_versionx ON public.red_hat_advisory_affected_products USING btree (major_version);


--
-- Name: red_hat_advisory_affected_products_minor_versionx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_affected_products_minor_versionx ON public.red_hat_advisory_affected_products USING btree (minor_version);


--
-- Name: red_hat_advisory_affected_products_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_affected_products_namex ON public.red_hat_advisory_affected_products USING btree (name);


--
-- Name: red_hat_advisory_affected_products_variant_namenx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX red_hat_advisory_affected_products_variant_namenx ON public.red_hat_advisory_affected_products USING btree (red_hat_advisory_id, variant, name, major_version, minor_version, arch) WHERE (minor_version IS NULL);


--
-- Name: red_hat_advisory_affected_products_variant_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX red_hat_advisory_affected_products_variant_namex ON public.red_hat_advisory_affected_products USING btree (red_hat_advisory_id, variant, name, major_version, minor_version, arch) WHERE (minor_version IS NOT NULL);


--
-- Name: red_hat_advisory_affected_products_variantx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_affected_products_variantx ON public.red_hat_advisory_affected_products USING btree (variant);


--
-- Name: red_hat_advisory_bugzilla_bugs_bugzilla_bug_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_bugzilla_bugs_bugzilla_bug_idx ON public.red_hat_advisory_bugzilla_bugs USING btree (bugzilla_bug_id);


--
-- Name: red_hat_advisory_cvex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_cvex ON public.red_hat_advisory_cves USING btree (cve);


--
-- Name: red_hat_advisory_packages_nevrax; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX red_hat_advisory_packages_nevrax ON public.red_hat_advisory_packages USING btree (nevra);


--
-- Name: settings_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX settings_namex ON public.settings USING btree (name);


--
-- Name: supported_products_eol_atx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_eol_atx ON public.supported_products USING btree (eol_at);


--
-- Name: supported_products_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_namex ON public.supported_products USING btree (name);


--
-- Name: supported_products_rh_blocks_red_hat_advisory_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rh_blocks_red_hat_advisory_idx ON public.supported_products_rh_blocks USING btree (red_hat_advisory_id);


--
-- Name: supported_products_rh_blocks_supported_products_rh_mirror_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rh_blocks_supported_products_rh_mirror_idx ON public.supported_products_rh_blocks USING btree (supported_products_rh_mirror_id);


--
-- Name: supported_products_rh_mirrors_match_arch_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rh_mirrors_match_arch_idx ON public.supported_products_rh_mirrors USING btree (match_arch);


--
-- Name: supported_products_rh_mirrors_match_major_version_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rh_mirrors_match_major_version_idx ON public.supported_products_rh_mirrors USING btree (match_major_version);


--
-- Name: supported_products_rh_mirrors_match_minor_version_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rh_mirrors_match_minor_version_idx ON public.supported_products_rh_mirrors USING btree (match_minor_version);


--
-- Name: supported_products_rh_mirrors_match_variant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rh_mirrors_match_variant_idx ON public.supported_products_rh_mirrors USING btree (match_variant);


--
-- Name: supported_products_rh_mirrors_supported_product_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rh_mirrors_supported_product_idx ON public.supported_products_rh_mirrors USING btree (supported_product_id);


--
-- Name: supported_products_rpm_repomds_arch_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rpm_repomds_arch_idx ON public.supported_products_rpm_repomds USING btree (arch);


--
-- Name: supported_products_rpm_repomds_production_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rpm_repomds_production_idx ON public.supported_products_rpm_repomds USING btree (production);


--
-- Name: supported_products_rpm_repomds_supporteds_rh_mirror_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rpm_repomds_supporteds_rh_mirror_idx ON public.supported_products_rpm_repomds USING btree (supported_products_rh_mirror_id);


--
-- Name: supported_products_rpm_rh_overrides_red_hat_advisory_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rpm_rh_overrides_red_hat_advisory_idx ON public.supported_products_rpm_rh_overrides USING btree (red_hat_advisory_id);


--
-- Name: supported_products_rpm_rh_overrides_supported_products_rh_mirro; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rpm_rh_overrides_supported_products_rh_mirro ON public.supported_products_rpm_rh_overrides USING btree (supported_products_rh_mirror_id);


--
-- Name: supported_products_variantx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_variantx ON public.supported_products USING btree (variant);


--
-- Name: advisories advisories_red_hat_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisories
    ADD CONSTRAINT advisories_red_hat_advisory_id_fkey FOREIGN KEY (red_hat_advisory_id) REFERENCES public.red_hat_advisories(id) ON DELETE CASCADE;


--
-- Name: advisory_affected_products advisory_affected_products_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_affected_products
    ADD CONSTRAINT advisory_affected_products_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES public.advisories(id) ON DELETE CASCADE;


--
-- Name: advisory_affected_products advisory_affected_products_supported_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_affected_products
    ADD CONSTRAINT advisory_affected_products_supported_product_id_fkey FOREIGN KEY (supported_product_id) REFERENCES public.supported_products(id) ON DELETE CASCADE;


--
-- Name: advisory_cves advisory_cves_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_cves
    ADD CONSTRAINT advisory_cves_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES public.advisories(id) ON DELETE CASCADE;


--
-- Name: advisory_fixes advisory_fixes_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_fixes
    ADD CONSTRAINT advisory_fixes_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES public.advisories(id) ON DELETE CASCADE;


--
-- Name: advisory_packages advisory_packages_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_packages
    ADD CONSTRAINT advisory_packages_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES public.advisories(id) ON DELETE CASCADE;


--
-- Name: advisory_packages advisory_packages_supported_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_packages
    ADD CONSTRAINT advisory_packages_supported_product_id_fkey FOREIGN KEY (supported_product_id) REFERENCES public.supported_products(id) ON DELETE CASCADE;


--
-- Name: advisory_packages advisory_packages_supported_products_rh_mirror_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisory_packages
    ADD CONSTRAINT advisory_packages_supported_products_rh_mirror_id_fkey FOREIGN KEY (supported_products_rh_mirror_id) REFERENCES public.supported_products_rh_mirrors(id) ON DELETE CASCADE;


--
-- Name: events events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: red_hat_advisory_affected_products red_hat_advisory_affected_products_red_hat_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_affected_products
    ADD CONSTRAINT red_hat_advisory_affected_products_red_hat_advisory_id_fkey FOREIGN KEY (red_hat_advisory_id) REFERENCES public.red_hat_advisories(id) ON DELETE CASCADE;


--
-- Name: red_hat_advisory_bugzilla_bugs red_hat_advisory_bugzilla_bugs_red_hat_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_bugzilla_bugs
    ADD CONSTRAINT red_hat_advisory_bugzilla_bugs_red_hat_advisory_id_fkey FOREIGN KEY (red_hat_advisory_id) REFERENCES public.red_hat_advisories(id) ON DELETE CASCADE;


--
-- Name: red_hat_advisory_cves red_hat_advisory_cves_red_hat_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_cves
    ADD CONSTRAINT red_hat_advisory_cves_red_hat_advisory_id_fkey FOREIGN KEY (red_hat_advisory_id) REFERENCES public.red_hat_advisories(id) ON DELETE CASCADE;


--
-- Name: red_hat_advisory_packages red_hat_advisory_packages_red_hat_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.red_hat_advisory_packages
    ADD CONSTRAINT red_hat_advisory_packages_red_hat_advisory_id_fkey FOREIGN KEY (red_hat_advisory_id) REFERENCES public.red_hat_advisories(id) ON DELETE CASCADE;


--
-- Name: supported_products supported_products_code_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products
    ADD CONSTRAINT supported_products_code_id_fkey FOREIGN KEY (code_id) REFERENCES public.codes(id);


--
-- Name: supported_products_rh_blocks supported_products_rh_blocks_red_hat_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_blocks
    ADD CONSTRAINT supported_products_rh_blocks_red_hat_advisory_id_fkey FOREIGN KEY (red_hat_advisory_id) REFERENCES public.red_hat_advisories(id) ON DELETE CASCADE;


--
-- Name: supported_products_rh_blocks supported_products_rh_blocks_supported_products_rh_mirror__fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_blocks
    ADD CONSTRAINT supported_products_rh_blocks_supported_products_rh_mirror__fkey FOREIGN KEY (supported_products_rh_mirror_id) REFERENCES public.supported_products_rh_mirrors(id) ON DELETE CASCADE;


--
-- Name: supported_products_rh_mirrors supported_products_rh_mirrors_supported_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rh_mirrors
    ADD CONSTRAINT supported_products_rh_mirrors_supported_product_id_fkey FOREIGN KEY (supported_product_id) REFERENCES public.supported_products(id) ON DELETE CASCADE;


--
-- Name: supported_products_rpm_repomds supported_products_rpm_repomd_supported_products_rh_mirror_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rpm_repomds
    ADD CONSTRAINT supported_products_rpm_repomd_supported_products_rh_mirror_fkey FOREIGN KEY (supported_products_rh_mirror_id) REFERENCES public.supported_products_rh_mirrors(id) ON DELETE CASCADE;


--
-- Name: supported_products_rpm_rh_overrides supported_products_rpm_rh_ove_supported_products_rh_mirror_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rpm_rh_overrides
    ADD CONSTRAINT supported_products_rpm_rh_ove_supported_products_rh_mirror_fkey FOREIGN KEY (supported_products_rh_mirror_id) REFERENCES public.supported_products_rh_mirrors(id) ON DELETE CASCADE;


--
-- Name: supported_products_rpm_rh_overrides supported_products_rpm_rh_overrides_red_hat_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products_rpm_rh_overrides
    ADD CONSTRAINT supported_products_rpm_rh_overrides_red_hat_advisory_id_fkey FOREIGN KEY (red_hat_advisory_id) REFERENCES public.red_hat_advisories(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


--
-- Dbmate schema migrations
--

INSERT INTO public.schema_migrations (version) VALUES
    ('20230128201227');
