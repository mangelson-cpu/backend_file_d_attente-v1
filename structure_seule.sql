--
-- PostgreSQL database dump
--

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

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--
CREATE SCHEMA IF NOT EXISTS public;
COMMENT ON SCHEMA public IS 'standard public schema';

--
-- Name: ticket_status; Type: TYPE; Schema: public; Owner: -
--
CREATE TYPE public.ticket_status AS ENUM (
    'waiting',
    'called',
    'done',
    'cancelled',
    'ready'
);

-- ============================================================
-- FUNCTIONS
-- ============================================================

-- Name: assign_role_secure(uuid, text, text, text, uuid); Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.assign_role_secure(p_new_user_id uuid, p_email text, p_nom_user text, p_role text, p_agence_id uuid) RETURNS text
LANGUAGE plpgsql
AS $$
declare
    current_role text;
begin
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    if current_role = 'user' then
        return 'Accès refusé : vous ne pouvez créer aucun utilisateur';
    elsif current_role = 'admin' and p_role <> 'user' then
        return 'Accès refusé : un admin ne peut créer que des users';
    end if;

    insert into public.users (id, email, nom_user, role, agence_id, created_at)
    values (p_new_user_id, p_email, p_nom_user, p_role, p_agence_id, now());

    return 'Utilisateur créé avec succès';
end;
$$;

-- Name: check_create_user_rights(text); Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.check_create_user_rights(p_role text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
AS $$
declare
    current_role text;
begin
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    if current_role = 'user' then
        return 'Accès refusé : vous ne pouvez créer aucun utilisateur';
    elsif current_role = 'admin' and p_role <> 'user' then
        return 'Accès refusé : un admin ne peut créer que des users';
    end if;

    return 'ok';
end;
$$;

-- Name: create_user_secure(text, text, text, text, uuid); Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.create_user_secure(p_email text, p_password text, p_nom_user text, p_role text, p_agence_id uuid DEFAULT NULL::uuid) RETURNS json
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'public', 'auth', 'extensions'
AS $$
DECLARE
  v_caller_id UUID;
  v_caller_role TEXT;
  v_new_user_id UUID;
BEGIN
  v_caller_id := auth.uid();
  IF v_caller_id IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Non authentifié');
  END IF;

  SELECT role INTO v_caller_role
  FROM public.users
  WHERE id = v_caller_id;

  IF v_caller_role IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Profil appelant introuvable');
  END IF;

  IF v_caller_role = 'user' THEN
    RETURN json_build_object('success', false, 'message', 'Les utilisateurs simples ne peuvent pas créer de comptes');
  END IF;

  IF v_caller_role = 'admin' AND p_role <> 'user' THEN
    RETURN json_build_object('success', false, 'message', 'Un admin ne peut créer que des utilisateurs de type "user"');
  END IF;

  IF v_caller_role = 'super_admin' AND p_role NOT IN ('admin', 'user') THEN
    RETURN json_build_object('success', false, 'message', 'Un super_admin ne peut créer que des admin ou des user');
  END IF;

  IF EXISTS (SELECT 1 FROM auth.users WHERE email = p_email) THEN
    RETURN json_build_object('success', false, 'message', 'Cet email est déjà utilisé');
  END IF;

  IF LENGTH(p_password) < 6 THEN
    RETURN json_build_object('success', false, 'message', 'Le mot de passe doit contenir au moins 6 caractères');
  END IF;

  v_new_user_id := gen_random_uuid();

  INSERT INTO auth.users (
    id, instance_id, email, encrypted_password, email_confirmed_at, confirmation_sent_at, confirmation_token, 
    recovery_token, email_change_token_new, email_change, aud, role, raw_app_meta_data, raw_user_meta_data, 
    is_super_admin, is_sso_user, created_at, updated_at
  ) VALUES (
    v_new_user_id, '00000000-0000-0000-0000-000000000000', p_email, crypt(p_password, gen_salt('bf')), NOW(), NOW(), '', '', '', '', 
    'authenticated', 'authenticated', 
    json_build_object('provider', 'email', 'providers', ARRAY['email'])::jsonb, 
    json_build_object('nom_user', p_nom_user)::jsonb, false, false, NOW(), NOW()
  );

  INSERT INTO auth.identities (
    id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
  ) VALUES (
    v_new_user_id, v_new_user_id, p_email, 
    json_build_object('sub', v_new_user_id::text, 'email', p_email, 'email_verified', true, 'provider', 'email')::jsonb, 
    'email', NOW(), NOW(), NOW()
  );

  INSERT INTO public.users (id, email, nom_user, role, agence_id, created_at)
  VALUES (v_new_user_id, p_email, p_nom_user, p_role, p_agence_id, NOW());

  RETURN json_build_object('success', true, 'message', 'Utilisateur créé avec succès', 'user_id', v_new_user_id);
EXCEPTION WHEN OTHERS THEN
  RETURN json_build_object('success', false, 'message', 'Erreur serveur: ' || SQLERRM);
END;
$$;

-- Name: update_user_secure; Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.update_user_secure(
  p_user_id UUID,
  p_email TEXT,
  p_password TEXT,
  p_nom_user TEXT,
  p_role TEXT,
  p_agence_id UUID DEFAULT NULL,
  p_old_password TEXT DEFAULT NULL
)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth, extensions
AS $$
DECLARE
  v_caller_id UUID;
  v_caller_role TEXT;
  v_caller_agence_id UUID;
  v_target_role TEXT;
  v_target_agence_id UUID;
  v_final_role TEXT;
  v_final_agence_id UUID;
  v_email_exists BOOLEAN;
  v_current_encrypted_password TEXT;
BEGIN
  v_caller_id := auth.uid();
  IF v_caller_id IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Non authentifié');
  END IF;

  SELECT role, agence_id INTO v_caller_role, v_caller_agence_id
  FROM public.users WHERE id = v_caller_id;

  IF v_caller_role IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Profil appelant introuvable');
  END IF;

  SELECT role, agence_id INTO v_target_role, v_target_agence_id
  FROM public.users WHERE id = p_user_id;

  IF v_target_role IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Utilisateur cible introuvable');
  END IF;

  v_final_role := p_role;
  v_final_agence_id := p_agence_id;

  IF v_caller_role = 'user' THEN
    IF p_user_id != v_caller_id THEN
      RETURN json_build_object('success', false, 'message', 'Non autorisé à modifier un autre utilisateur');
    END IF;
    v_final_role := v_target_role;
    v_final_agence_id := v_target_agence_id;
  ELSIF v_caller_role = 'admin' THEN
    IF p_user_id = v_caller_id THEN
      v_final_role := v_target_role;
      v_final_agence_id := v_target_agence_id;
    ELSE
      IF v_target_role IN ('super_admin', 'admin') THEN
        RETURN json_build_object('success', false, 'message', 'Un admin ne peut modifier que les utilisateurs simples');
      END IF;
      IF v_target_agence_id IS DISTINCT FROM v_caller_agence_id THEN
        RETURN json_build_object('success', false, 'message', 'Cet utilisateur n''est pas dans votre agence');
      END IF;
      IF p_role IN ('admin', 'super_admin') THEN
        RETURN json_build_object('success', false, 'message', 'Un admin ne peut pas attribuer de rôle supérieur');
      END IF;
      IF p_agence_id IS DISTINCT FROM v_caller_agence_id THEN
        RETURN json_build_object('success', false, 'message', 'Un admin ne peut assigner que sa propre agence');
      END IF;
    END IF;
  ELSIF v_caller_role = 'super_admin' THEN
    IF p_user_id != v_caller_id THEN
      IF v_target_role = 'super_admin' THEN
        RETURN json_build_object('success', false, 'message', 'Un super_admin ne peut pas modifier un autre super_admin');
      END IF;
    END IF;
    IF p_role NOT IN ('user', 'admin', 'super_admin') THEN
      RETURN json_build_object('success', false, 'message', 'Rôle invalide');
    END IF;
    IF p_user_id = v_caller_id AND p_role != 'super_admin' THEN
      RETURN json_build_object('success', false, 'message', 'Un super_admin ne peut pas se retirer ses propres privilèges');
    END IF;
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM auth.users WHERE email = p_email AND id != p_user_id
  ) INTO v_email_exists;

  IF v_email_exists THEN
    RETURN json_build_object('success', false, 'message', 'Cet email est déjà utilisé par un autre compte');
  END IF;

  IF p_password IS NOT NULL AND TRIM(p_password) != '' THEN
    IF LENGTH(p_password) < 6 THEN
      RETURN json_build_object('success', false, 'message', 'Le nouveau mot de passe doit contenir au moins 6 caractères');
    END IF;
    IF p_user_id = v_caller_id THEN
      IF p_old_password IS NULL OR TRIM(p_old_password) = '' THEN
        RETURN json_build_object('success', false, 'message', 'Veuillez saisir votre ancien mot de passe pour le modifier');
      END IF;
      SELECT encrypted_password INTO v_current_encrypted_password
      FROM auth.users WHERE id = p_user_id;
      IF crypt(p_old_password, v_current_encrypted_password) != v_current_encrypted_password THEN
        RETURN json_build_object('success', false, 'message', 'L''ancien mot de passe est incorrect');
      END IF;
    END IF;
  END IF;

  IF p_password IS NOT NULL AND TRIM(p_password) != '' THEN
    UPDATE auth.users
    SET email = p_email, encrypted_password = crypt(p_password, gen_salt('bf')),
        raw_user_meta_data = jsonb_set(COALESCE(raw_user_meta_data, '{}'::jsonb), '{nom_user}', to_jsonb(p_nom_user)),
        updated_at = NOW()
    WHERE id = p_user_id;
  ELSE
    UPDATE auth.users
    SET email = p_email,
        raw_user_meta_data = jsonb_set(COALESCE(raw_user_meta_data, '{}'::jsonb), '{nom_user}', to_jsonb(p_nom_user)),
        updated_at = NOW()
    WHERE id = p_user_id;
  END IF;

  UPDATE auth.identities
  SET identity_data = jsonb_set(identity_data, '{email}', to_jsonb(p_email)), updated_at = NOW()
  WHERE user_id = p_user_id AND provider = 'email';

  UPDATE public.users
  SET email = p_email, nom_user = p_nom_user, role = v_final_role, agence_id = v_final_agence_id
  WHERE id = p_user_id;

  RETURN json_build_object('success', true, 'message', 'Utilisateur mis à jour avec succès');
EXCEPTION WHEN OTHERS THEN
  RETURN json_build_object('success', false, 'message', 'Erreur serveur: ' || SQLERRM);
END;
$$;

-- Name: get_current_user_role(); Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.get_current_user_role() RETURNS text
LANGUAGE plpgsql
AS $$
declare
    current_role text;
begin
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    return current_role;
end;
$$;

-- Name: get_my_agence(); Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.get_my_agence() RETURNS uuid
LANGUAGE sql SECURITY DEFINER
SET search_path TO 'public'
AS $$
  SELECT agence_id FROM public.users WHERE id = auth.uid();
$$;

-- Name: get_my_role(); Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.get_my_role() RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path TO 'public'
AS $$
  SELECT role FROM public.users WHERE id = auth.uid();
$$;

-- Name: vote_satisfaction(uuid, character varying, integer, character varying); Type: FUNCTION; Schema: public; Owner: -
CREATE OR REPLACE FUNCTION public.vote_satisfaction(p_agence_id uuid, p_nom_guichet character varying, p_score integer, p_device_id character varying) RETURNS json
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
    v_ticket_numero VARCHAR;
BEGIN
    SELECT numero_ticket INTO v_ticket_numero
    FROM public.ticket
    WHERE agence_id = p_agence_id 
      AND nom_guichet = p_nom_guichet
      AND status = 'called'
    ORDER BY created_at DESC
    LIMIT 1;

    IF v_ticket_numero IS NULL THEN
        RETURN json_build_object('success', false, 'error', 'Aucun ticket n''est actuellement "En cours" ("called") sur ce guichet.');
    END IF;

    INSERT INTO public.evaluations (ticket_numero, device_id, score)
    VALUES (v_ticket_numero, p_device_id, p_score)
    ON CONFLICT (ticket_numero) 
    DO UPDATE SET 
        score = EXCLUDED.score,
        device_id = EXCLUDED.device_id,
        created_at = timezone('utc'::text, now());

    RETURN json_build_object('success', true, 'ticket_numero', v_ticket_numero, 'message', 'Vote pris en compte ou mis à jour avec succès.');
EXCEPTION WHEN OTHERS THEN
    RETURN json_build_object('success', false, 'error', SQLERRM);
END;
$$;

-- ============================================================
-- TABLES
-- ============================================================

SET default_tablespace = '';
SET default_table_access_method = heap;

CREATE TABLE public.active_guichets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_guichet text NOT NULL,
    agence_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_start timestamp with time zone DEFAULT now()
);

CREATE TABLE public.agence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom text NOT NULL,
    adresse text,
    created_at timestamp with time zone DEFAULT now(),
    slug text
);

CREATE TABLE public.evaluations (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    device_id character varying NOT NULL,
    ticket_numero character varying NOT NULL,
    score integer NOT NULL,
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
    CONSTRAINT evaluations_score_check CHECK ((score = ANY (ARRAY[1, 2, 3])))
);

CREATE TABLE public.guichet (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    nom_guichet text NOT NULL,
    appellation text,
    agence_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE public.guichet_service (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_guichet text NOT NULL,
    service_id uuid NOT NULL,
    agence_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE public.service (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_service text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE public.sous_service (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_sous_service text NOT NULL,
    service_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE public.ticket (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    numero_ticket text NOT NULL,
    agence_id uuid NOT NULL,
    service_id uuid NOT NULL,
    nom_guichet text,
    user_id uuid,
    niveau text DEFAULT 'normal'::text,
    status public.ticket_status DEFAULT 'waiting'::public.ticket_status NOT NULL,
    date_debut timestamp with time zone,
    date_fin timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sous_service_id uuid
);

CREATE TABLE public.users (
    id uuid NOT NULL,
    email text NOT NULL,
    nom_user text NOT NULL,
    role text NOT NULL,
    agence_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT users_role_check CHECK ((role = ANY (ARRAY['super_admin'::text, 'admin'::text, 'user'::text])))
);

-- ============================================================
-- CONSTRAINTS
-- ============================================================

ALTER TABLE ONLY public.active_guichets ADD CONSTRAINT active_guichets_nom_guichet_agence_id_key UNIQUE (nom_guichet, agence_id);
ALTER TABLE ONLY public.active_guichets ADD CONSTRAINT active_guichets_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.active_guichets ADD CONSTRAINT active_guichets_user_id_key UNIQUE (user_id);
ALTER TABLE ONLY public.agence ADD CONSTRAINT agence_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.agence ADD CONSTRAINT agence_slug_key UNIQUE (slug);
ALTER TABLE ONLY public.evaluations ADD CONSTRAINT evaluations_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.evaluations ADD CONSTRAINT evaluations_ticket_numero_key UNIQUE (ticket_numero);
ALTER TABLE ONLY public.guichet ADD CONSTRAINT guichet_nom_guichet_agence_id_key UNIQUE (nom_guichet, agence_id);
ALTER TABLE ONLY public.guichet ADD CONSTRAINT guichet_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.guichet_service ADD CONSTRAINT guichet_service_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.service ADD CONSTRAINT service_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.sous_service ADD CONSTRAINT sous_service_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.ticket ADD CONSTRAINT ticket_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id);

-- Foreign Keys
ALTER TABLE ONLY public.active_guichets ADD CONSTRAINT active_guichets_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.active_guichets ADD CONSTRAINT active_guichets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.guichet ADD CONSTRAINT guichet_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.guichet_service ADD CONSTRAINT guichet_service_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.guichet_service ADD CONSTRAINT guichet_service_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.sous_service ADD CONSTRAINT sous_service_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.ticket ADD CONSTRAINT ticket_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.ticket ADD CONSTRAINT ticket_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.ticket ADD CONSTRAINT ticket_sous_service_id_fkey FOREIGN KEY (sous_service_id) REFERENCES public.sous_service(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.ticket ADD CONSTRAINT ticket_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);
ALTER TABLE ONLY public.users ADD CONSTRAINT users_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id);
ALTER TABLE ONLY public.users ADD CONSTRAINT users_id_fkey FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE;

-- ============================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================

ALTER TABLE public.active_guichets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guichet ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guichet_service ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.service ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sous_service ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ticket ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY active_guichets_delete_policy ON public.active_guichets FOR DELETE USING (((auth.uid() = user_id) OR (( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = ANY (ARRAY['admin'::text, 'super_admin'::text]))));
CREATE POLICY active_guichets_insert_policy ON public.active_guichets FOR INSERT WITH CHECK ((auth.uid() = user_id));
CREATE POLICY active_guichets_select_policy ON public.active_guichets FOR SELECT USING (true);

CREATE POLICY agence_delete_policy ON public.agence FOR DELETE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY agence_insert_policy ON public.agence FOR INSERT WITH CHECK ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY agence_public_select_policy ON public.agence FOR SELECT USING (true);
CREATE POLICY agence_select_policy ON public.agence FOR SELECT USING (((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) OR (id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid())))));
CREATE POLICY agence_select_public_policy ON public.agence FOR SELECT USING (true);
CREATE POLICY agence_update_policy ON public.agence FOR UPDATE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));

CREATE POLICY "Allow admins to read evaluations" ON public.evaluations FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow tablet to insert evaluations" ON public.evaluations FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable insert/update for authenticated users" ON public.guichet TO authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Enable read access for authenticated users" ON public.guichet FOR SELECT TO authenticated USING (true);

CREATE POLICY guichet_service_modify_policy ON public.guichet_service USING (((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) OR ((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'admin'::text) AND (agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid()))))));
CREATE POLICY guichet_service_public_select_policy ON public.guichet_service FOR SELECT USING (true);
CREATE POLICY guichet_service_select_policy ON public.guichet_service FOR SELECT USING (((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) OR (agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid())))));

CREATE POLICY service_delete_policy ON public.service FOR DELETE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY service_insert_policy ON public.service FOR INSERT WITH CHECK ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY service_public_select_policy ON public.service FOR SELECT USING (true);
CREATE POLICY service_select_policy ON public.service FOR SELECT USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = ANY (ARRAY['super_admin'::text, 'admin'::text]))))));
CREATE POLICY service_select_public_policy ON public.service FOR SELECT USING (true);
CREATE POLICY service_update_policy ON public.service FOR UPDATE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));

CREATE POLICY sous_service_delete_policy ON public.sous_service FOR DELETE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY sous_service_insert_policy ON public.sous_service FOR INSERT WITH CHECK ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY sous_service_select_policy ON public.sous_service FOR SELECT USING (((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = ANY (ARRAY['super_admin'::text, 'admin'::text, 'agent'::text]))))) OR true));
CREATE POLICY sous_service_update_policy ON public.sous_service FOR UPDATE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));

CREATE POLICY ticket_insert_public_policy ON public.ticket FOR INSERT WITH CHECK (true);
CREATE POLICY ticket_select_policy ON public.ticket FOR SELECT USING (((agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid()))) OR (( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) OR true));
CREATE POLICY ticket_select_public_policy ON public.ticket FOR SELECT USING (true);
CREATE POLICY ticket_update_policy ON public.ticket FOR UPDATE USING ((agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid()))));

CREATE POLICY users_delete_policy ON public.users FOR DELETE USING (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence()) AND (auth.uid() <> id))));
CREATE POLICY users_insert_policy ON public.users FOR INSERT WITH CHECK (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence()))));
CREATE POLICY users_select_own ON public.users FOR SELECT USING ((auth.uid() = id));
CREATE POLICY users_select_policy ON public.users FOR SELECT USING (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence())) OR (auth.uid() = id)));
CREATE POLICY users_update_policy ON public.users FOR UPDATE USING (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence())) OR (auth.uid() = id))) WITH CHECK (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (role <> 'super_admin'::text) AND (agence_id = public.get_my_agence())) OR ((auth.uid() = id) AND (role = public.get_my_role()) AND ((agence_id = public.get_my_agence()) OR (public.get_my_role() = 'super_admin'::text)))));

-- Permissions
REVOKE ALL ON FUNCTION public.update_user_secure(UUID, TEXT, TEXT, TEXT, TEXT, UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.update_user_secure(UUID, TEXT, TEXT, TEXT, TEXT, UUID, TEXT) FROM anon;
GRANT EXECUTE ON FUNCTION public.update_user_secure(UUID, TEXT, TEXT, TEXT, TEXT, UUID, TEXT) TO authenticated;

-- PostgreSQL database dump complete
NOTIFY pgrst, 'reload schema';
