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
-- Name: codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.codes (
    id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    archived_at timestamp without time zone,
    description text NOT NULL
);


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
    severity text NOT NULL
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
    bugzilla_bug_id text NOT NULL
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
    cve text NOT NULL
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
-- Name: supported_products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.supported_products (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    eol_at timestamp with time zone,
    name text NOT NULL,
    rhel_major_version numeric,
    rhel_minor_version numeric
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
-- Name: supported_products id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supported_products ALTER COLUMN id SET DEFAULT nextval('public.supported_products_id_seq'::regclass);


--
-- Name: codes codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.codes
    ADD CONSTRAINT codes_pkey PRIMARY KEY (id);


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
-- Name: supported_products_eol_atx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_eol_atx ON public.supported_products USING btree (eol_at);


--
-- Name: supported_products_namex; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_namex ON public.supported_products USING btree (name);


--
-- Name: supported_products_rhel_major_versionx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rhel_major_versionx ON public.supported_products USING btree (rhel_major_version);


--
-- Name: supported_products_rhel_minor_versionx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX supported_products_rhel_minor_versionx ON public.supported_products USING btree (rhel_minor_version);


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
-- PostgreSQL database dump complete
--


--
-- Dbmate schema migrations
--

INSERT INTO public.schema_migrations (version) VALUES
    ('20230128201227');
