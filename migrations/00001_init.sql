-- Baseline schema for a single-tenant application: one installation, many users,
-- global roles and permissions. There is no organization/tenant boundary here --
-- see the README for the multi-tenant version of this template if you need one.

-- +goose Up
--
-- PostgreSQL schema
--

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- Name: audit_log_is_append_only(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.audit_log_is_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Exactly ONE update is permitted, and it is not really a content change:
        -- audit_log.actor_user_id is ON DELETE SET NULL, so hard-deleting a user
        -- anonymises their entries rather than destroying them. That is deliberate,
        -- and it is how a right-to-erasure request is served without losing the
        -- record that the actions happened at all.
        --
        -- A blanket "no UPDATE" would make deleting a user impossible forever. So
        -- allow the anonymisation, and ONLY the anonymisation: every other column
        -- must be byte-for-byte identical, and actor_user_id may only go from set
        -- to NULL -- never the reverse, and never to somebody else.
        IF OLD.actor_user_id IS NOT NULL
           AND NEW.actor_user_id IS NULL
           AND NEW.id          =              OLD.id
           AND NEW.action      =              OLD.action
           AND NEW.target_type =              OLD.target_type
           AND NEW.target_id   =              OLD.target_id
           AND NEW.metadata    =              OLD.metadata
           AND NEW.request_id  =              OLD.request_id
           AND NEW.ip_address  IS NOT DISTINCT FROM OLD.ip_address
           AND NEW.user_agent  =              OLD.user_agent
           AND NEW.created_at  =              OLD.created_at
        THEN
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'audit_log is append-only: rows cannot be modified'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- DELETE is allowed only to deliberate audit maintenance, which announces
    -- itself by setting this GUC for the duration of its transaction: the
    -- retention sweep (`server purge`).
    --
    -- AND NOTE THE LIMIT: any role can set this GUC. This stops an ACCIDENT, not an
    -- ADVERSARY -- code already running as the app can set it and delete. Real
    -- tamper-resistance needs a second, restricted DB identity; see internal/audit.
    IF TG_OP = 'DELETE'
       AND coalesce(current_setting('app.audit_purge', true), 'off') <> 'on' THEN
        RAISE EXCEPTION 'audit_log is append-only: rows cannot be deleted except by the retention sweep'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN OLD; -- permit the DELETE
END;
$$;
-- +goose StatementEnd


--
-- Name: audit_log_no_truncate(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.audit_log_no_truncate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: it cannot be truncated'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
-- +goose StatementEnd




--
-- Name: api_key_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_key_permissions (
    api_key_id uuid NOT NULL,
    permission text NOT NULL
);


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    token_hash bytea NOT NULL,
    token_prefix text NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid DEFAULT uuidv7() NOT NULL,
    actor_user_id uuid,
    action text NOT NULL,
    target_type text DEFAULT ''::text NOT NULL,
    target_id text DEFAULT ''::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    request_id text DEFAULT ''::text NOT NULL,
    ip_address inet,
    user_agent text DEFAULT ''::text NOT NULL
);


--
-- Name: email_verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_verifications (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    email public.citext NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: invitations; Type: TABLE; Schema: public; Owner: -
--

-- An invitation offers a NOT-YET-EXISTING account a role. Accepting one is what
-- creates the user -- see identity.Service.AcceptInvitation. Inviting an email
-- that already has an account is refused; assign the role directly instead.
CREATE TABLE public.invitations (
    id uuid DEFAULT uuidv7() NOT NULL,
    email public.citext NOT NULL,
    token_hash bytea NOT NULL,
    invited_by uuid,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    role_id uuid NOT NULL
);


--
-- Name: password_resets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_resets (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ip_address inet,
    user_agent text DEFAULT ''::text NOT NULL
);


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    key text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
    role_id uuid NOT NULL,
    permission text NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

-- Roles are GLOBAL: there is one installation, so there is one set of roles.
-- is_system marks the two roles the application ships and depends on (admin,
-- member); everything else is a custom role an admin created at runtime.
CREATE TABLE public.roles (
    id uuid DEFAULT uuidv7() NOT NULL,
    key text NOT NULL,
    name text NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    user_agent text DEFAULT ''::text NOT NULL,
    ip_address inet,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT uuidv7() NOT NULL,
    email public.citext NOT NULL,
    password_hash text,
    full_name text DEFAULT ''::text NOT NULL,
    is_superuser boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    email_verified_at timestamp with time zone
);


--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: -
--

-- The direct assignment of roles to users. A user may hold several -- "member"
-- plus a custom "billing_manager" is a person who can do both, without anyone
-- inventing a "member who also does billing" role.
CREATE TABLE public.user_roles (
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: api_key_permissions api_key_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_key_permissions
    ADD CONSTRAINT api_key_permissions_pkey PRIMARY KEY (api_key_id, permission);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_token_hash_key UNIQUE (token_hash);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: email_verifications email_verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verifications
    ADD CONSTRAINT email_verifications_pkey PRIMARY KEY (id);


--
-- Name: email_verifications email_verifications_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verifications
    ADD CONSTRAINT email_verifications_token_hash_key UNIQUE (token_hash);


--
-- Name: invitations invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);


--
-- Name: invitations invitations_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_token_hash_key UNIQUE (token_hash);


--
-- Name: password_resets password_resets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_resets
    ADD CONSTRAINT password_resets_pkey PRIMARY KEY (id);


--
-- Name: password_resets password_resets_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_resets
    ADD CONSTRAINT password_resets_token_hash_key UNIQUE (token_hash);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (key);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: roles roles_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

-- Globally unique: there is one installation, so a role's key is unambiguous
-- with no scoping needed.
ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_key_key UNIQUE (key);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);


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
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: api_keys_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX api_keys_user_id_idx ON public.api_keys USING btree (user_id) WHERE (revoked_at IS NULL);


--
-- Name: audit_log_action_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_action_idx ON public.audit_log USING btree (action, id DESC);


--
-- Name: audit_log_actor_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_actor_idx ON public.audit_log USING btree (actor_user_id, id DESC);


--
-- Name: email_verifications_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_verifications_expires_at_idx ON public.email_verifications USING btree (expires_at);


--
-- Name: email_verifications_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_verifications_user_id_idx ON public.email_verifications USING btree (user_id);


--
-- Name: invitations_pending_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX invitations_pending_email_idx ON public.invitations USING btree (email) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL));


--
-- Name: password_resets_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX password_resets_expires_at_idx ON public.password_resets USING btree (expires_at);


--
-- Name: password_resets_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX password_resets_user_id_idx ON public.password_resets USING btree (user_id);


--
-- Name: user_roles_role_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_roles_role_id_idx ON public.user_roles USING btree (role_id);


--
-- Name: sessions_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_expires_at_idx ON public.sessions USING btree (expires_at);


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_id_idx ON public.sessions USING btree (user_id);


--
-- Name: audit_log audit_log_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_log_append_only BEFORE DELETE OR UPDATE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.audit_log_is_append_only();


--
-- Name: audit_log audit_log_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON public.audit_log FOR EACH STATEMENT EXECUTE FUNCTION public.audit_log_no_truncate();


--
-- Name: api_key_permissions api_key_permissions_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_key_permissions
    ADD CONSTRAINT api_key_permissions_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.api_keys(id) ON DELETE CASCADE;


--
-- Name: api_key_permissions api_key_permissions_permission_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_key_permissions
    ADD CONSTRAINT api_key_permissions_permission_fkey FOREIGN KEY (permission) REFERENCES public.permissions(key) ON DELETE RESTRICT;


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: audit_log audit_log_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: email_verifications email_verifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_verifications
    ADD CONSTRAINT email_verifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: invitations invitations_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: invitations invitations_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: password_resets password_resets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_resets
    ADD CONSTRAINT password_resets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_permission_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_fkey FOREIGN KEY (permission) REFERENCES public.permissions(key) ON DELETE RESTRICT;


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_roles user_roles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_roles user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

-- RESTRICT, not CASCADE: deleting a role that somebody still holds should fail
-- loudly (ErrRoleInUse), not silently strip their access.
ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE RESTRICT;


-- Seed data: the permission catalog and the two immutable system roles (admin,
-- member) with their permission grants.
INSERT INTO public.permissions VALUES ('users.read', 'View the users in this installation', now());
INSERT INTO public.permissions VALUES ('users.update', 'Change which roles a user holds, and activate or deactivate them', now());
INSERT INTO public.permissions VALUES ('invitations.read', 'View pending invitations', now());
INSERT INTO public.permissions VALUES ('invitations.create', 'Invite people to create an account', now());
INSERT INTO public.permissions VALUES ('invitations.delete', 'Revoke a pending invitation', now());
INSERT INTO public.permissions VALUES ('roles.read', 'View the roles this installation uses', now());
INSERT INTO public.permissions VALUES ('roles.create', 'Create custom roles', now());
INSERT INTO public.permissions VALUES ('roles.update', 'Edit custom roles', now());
INSERT INTO public.permissions VALUES ('roles.delete', 'Delete custom roles', now());
INSERT INTO public.permissions VALUES ('audit.read', 'Read the audit log', now());
INSERT INTO public.permissions VALUES ('apikeys.read', 'View API keys', now());
INSERT INTO public.permissions VALUES ('apikeys.create', 'Create API keys', now());
INSERT INTO public.permissions VALUES ('apikeys.delete', 'Revoke API keys', now());

INSERT INTO public.roles (id, key, name, is_system) VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'admin', 'Admin', true);
INSERT INTO public.roles (id, key, name, is_system) VALUES ('019f631b-c4ef-7225-a428-689600b42bc8', 'member', 'Member', true);

INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'users.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'users.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'invitations.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'invitations.create');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'invitations.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.create');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.update');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'roles.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'audit.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'apikeys.read');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'apikeys.create');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7214-8bd3-85b45843f531', 'apikeys.delete');
INSERT INTO public.role_permissions VALUES ('019f631b-c4ef-7225-a428-689600b42bc8', 'users.read');

-- +goose Down
DROP TABLE IF EXISTS public.api_key_permissions,public.api_keys,public.audit_log,public.email_verifications,public.invitations,public.password_resets,public.permissions,public.role_permissions,public.roles,public.sessions,public.users,public.user_roles CASCADE;
DROP FUNCTION IF EXISTS public.audit_log_is_append_only() CASCADE;
DROP FUNCTION IF EXISTS public.audit_log_no_truncate() CASCADE;
DROP EXTENSION IF EXISTS citext;
