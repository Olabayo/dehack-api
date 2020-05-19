--
-- PostgreSQL database dump
--

-- Dumped from database version 10.3
-- Dumped by pg_dump version 10.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: password_reset; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset (
    id integer NOT NULL,
    email character varying(120) NOT NULL,
    reset_key uuid NOT NULL,
    used boolean NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: password_reset_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.password_reset_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: password_reset_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.password_reset_id_seq OWNED BY public.password_reset.id;


--
-- Name: registration_profile; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.registration_profile (
    user_id uuid NOT NULL,
    activation_key uuid NOT NULL,
    used boolean NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid NOT NULL,
    email character varying(120) NOT NULL,
    password character varying(120) NOT NULL,
    first_name character varying(120) NOT NULL,
    last_name character varying(120) NOT NULL,
    status boolean NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: password_reset id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset ALTER COLUMN id SET DEFAULT nextval('public.password_reset_id_seq'::regclass);


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.alembic_version (version_num) FROM stdin;
3e82154ac8c4
\.


--
-- Data for Name: password_reset; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.password_reset (id, email, reset_key, used, created_at) FROM stdin;
\.


--
-- Data for Name: registration_profile; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.registration_profile (user_id, activation_key, used) FROM stdin;
3df32c2b-a6e1-4dc4-a8c5-e99b267525c6	607b739a-df13-4ba9-8750-370917b8a17a	t
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.users (id, email, password, first_name, last_name, status, created_at) FROM stdin;
3df32c2b-a6e1-4dc4-a8c5-e99b267525c6	dehack@yahoo.com	$5$rounds=535000$Nhokw1fiQhhEqbNA$6kSElKiA.HOviNsXubEQUsFZsdFwegyWdWOkkHRhpIA	Olabayo	Onile-Ere	t	2020-05-16 06:10:11.454402
\.


--
-- Name: password_reset_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.password_reset_id_seq', 1, false);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: password_reset password_reset_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset
    ADD CONSTRAINT password_reset_pkey PRIMARY KEY (id);


--
-- Name: password_reset password_reset_reset_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset
    ADD CONSTRAINT password_reset_reset_key_key UNIQUE (reset_key);


--
-- Name: registration_profile registration_profile_activation_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_profile
    ADD CONSTRAINT registration_profile_activation_key_key UNIQUE (activation_key);


--
-- Name: registration_profile registration_profile_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_profile
    ADD CONSTRAINT registration_profile_pkey PRIMARY KEY (activation_key);


--
-- Name: registration_profile registration_profile_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_profile
    ADD CONSTRAINT registration_profile_user_id_key UNIQUE (user_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_id_key UNIQUE (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

