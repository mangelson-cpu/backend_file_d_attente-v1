--
-- PostgreSQL database dump
--

-- Dumped from database version 15.8
-- Dumped by pg_dump version 15.8

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

CREATE SCHEMA public;


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

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


--
-- Name: assign_role_secure(uuid, text, text, text, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.assign_role_secure(p_new_user_id uuid, p_email text, p_nom_user text, p_role text, p_agence_id uuid) RETURNS text
    LANGUAGE plpgsql
    AS $$
declare
    current_role text;
begin
    -- Récupérer le rôle de l'utilisateur connecté
    select role into current_role
    from public.users
    where id = auth.uid();

    if current_role is null then
        return 'Utilisateur non connecté';
    end if;

    -- Vérification des droits
    if current_role = 'user' then
        return 'Accès refusé : vous ne pouvez créer aucun utilisateur';
    elsif current_role = 'admin' and p_role <> 'user' then
        return 'Accès refusé : un admin ne peut créer que des users';
    end if;

    -- Insertion sécurisée dans public.users
    insert into public.users (
        id,
        email,
        nom_user,
        role,
        agence_id,
        created_at
    )
    values (
        p_new_user_id,
        p_email,
        p_nom_user,
        p_role,
        p_agence_id,
        now()
    );

    return 'Utilisateur créé avec succès';
end;
$$;


--
-- Name: check_create_user_rights(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_create_user_rights(p_role text) RETURNS text
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


--
-- Name: create_user_secure(text, text, text, text, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.create_user_secure(p_email text, p_password text, p_nom_user text, p_role text, p_agence_id uuid DEFAULT NULL::uuid) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'auth', 'extensions'
    AS $$
DECLARE
  v_caller_id UUID;
  v_caller_role TEXT;
  v_new_user_id UUID;
BEGIN
  -- 1. Vérifier que l'appelant est authentifié
  v_caller_id := auth.uid();
  IF v_caller_id IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Non authentifié');
  END IF;

  -- 2. Récupérer le rôle de l'appelant depuis public.users
  SELECT role INTO v_caller_role
  FROM public.users
  WHERE id = v_caller_id;

  IF v_caller_role IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Profil appelant introuvable');
  END IF;

  -- 3. Appliquer les règles métier de création
  --    user          → ne peut rien créer
  --    admin         → peut créer uniquement des "user"
  --    super_admin   → peut créer des "admin" et des "user"
  IF v_caller_role = 'user' THEN
    RETURN json_build_object('success', false, 'message', 'Les utilisateurs simples ne peuvent pas créer de comptes');
  END IF;

  IF v_caller_role = 'admin' AND p_role <> 'user' THEN
    RETURN json_build_object('success', false, 'message', 'Un admin ne peut créer que des utilisateurs de type "user"');
  END IF;

  IF v_caller_role = 'super_admin' AND p_role NOT IN ('admin', 'user') THEN
    RETURN json_build_object('success', false, 'message', 'Un super_admin ne peut créer que des admin ou des user');
  END IF;

  -- 4. Vérifier que l'email n'existe pas déjà
  IF EXISTS (SELECT 1 FROM auth.users WHERE email = p_email) THEN
    RETURN json_build_object('success', false, 'message', 'Cet email est déjà utilisé');
  END IF;

  -- 5. Valider le mot de passe (minimum 6 caractères)
  IF LENGTH(p_password) < 6 THEN
    RETURN json_build_object('success', false, 'message', 'Le mot de passe doit contenir au moins 6 caractères');
  END IF;

  -- 6. Générer un UUID pour le nouvel utilisateur
  v_new_user_id := gen_random_uuid();

  -- 7. Insérer dans auth.users (avec TOUS les champs requis par GoTrue)
  INSERT INTO auth.users (
    id,
    instance_id,
    email,
    encrypted_password,
    email_confirmed_at,
    confirmation_sent_at,
    confirmation_token,
    recovery_token,
    email_change_token_new,
    email_change,
    aud,
    role,
    raw_app_meta_data,
    raw_user_meta_data,
    is_super_admin,
    is_sso_user,
    created_at,
    updated_at
  ) VALUES (
    v_new_user_id,
    '00000000-0000-0000-0000-000000000000',
    p_email,
    crypt(p_password, gen_salt('bf')),
    NOW(),
    NOW(),
    '',        -- confirmation_token (vide car déjà confirmé)
    '',        -- recovery_token
    '',        -- email_change_token_new
    '',        -- email_change
    'authenticated',
    'authenticated',
    json_build_object(
      'provider', 'email',
      'providers', ARRAY['email']
    )::jsonb,
    json_build_object('nom_user', p_nom_user)::jsonb,
    false,     -- is_super_admin (géré par public.users)
    false,     -- is_sso_user
    NOW(),
    NOW()
  );

  -- 8. Créer l'identité email dans auth.identities
  --    (nécessaire pour que l'utilisateur puisse se connecter)
  INSERT INTO auth.identities (
    id,
    user_id,
    provider_id,
    identity_data,
    provider,
    last_sign_in_at,
    created_at,
    updated_at
  ) VALUES (
    v_new_user_id,
    v_new_user_id,
    p_email,
    json_build_object(
      'sub', v_new_user_id::text,
      'email', p_email,
      'email_verified', true,
      'provider', 'email'
    )::jsonb,
    'email',
    NOW(),
    NOW(),
    NOW()
  );

  -- 9. Insérer dans public.users
  INSERT INTO public.users (id, email, nom_user, role, agence_id, created_at)
  VALUES (v_new_user_id, p_email, p_nom_user, p_role, p_agence_id, NOW());

  -- 10. Retourner le succès
  RETURN json_build_object(
    'success', true,
    'message', 'Utilisateur créé avec succès',
    'user_id', v_new_user_id
  );

EXCEPTION WHEN OTHERS THEN
  RETURN json_build_object('success', false, 'message', 'Erreur serveur: ' || SQLERRM);
END;
$$;


--
-- Name: get_current_user_role(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_current_user_role() RETURNS text
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


--
-- Name: get_my_agence(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_my_agence() RETURNS uuid
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  SELECT agence_id FROM public.users WHERE id = auth.uid();
$$;


--
-- Name: get_my_role(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_my_role() RETURNS text
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
  SELECT role FROM public.users WHERE id = auth.uid();
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: active_guichets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.active_guichets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_guichet text NOT NULL,
    agence_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_start timestamp with time zone DEFAULT now()
);


--
-- Name: agence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom text NOT NULL,
    adresse text,
    created_at timestamp with time zone DEFAULT now(),
    slug text
);


--
-- Name: guichet; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.guichet (
    id uuid DEFAULT extensions.uuid_generate_v4() NOT NULL,
    nom_guichet text NOT NULL,
    appellation text,
    agence_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: guichet_service; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.guichet_service (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_guichet text NOT NULL,
    service_id uuid NOT NULL,
    agence_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: service; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_service text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: sous_service; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sous_service (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom_sous_service text NOT NULL,
    service_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: ticket; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid NOT NULL,
    email text NOT NULL,
    nom_user text NOT NULL,
    role text NOT NULL,
    agence_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT users_role_check CHECK ((role = ANY (ARRAY['super_admin'::text, 'admin'::text, 'user'::text])))
);


--
-- Name: active_guichets active_guichets_nom_guichet_agence_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.active_guichets
    ADD CONSTRAINT active_guichets_nom_guichet_agence_id_key UNIQUE (nom_guichet, agence_id);


--
-- Name: active_guichets active_guichets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.active_guichets
    ADD CONSTRAINT active_guichets_pkey PRIMARY KEY (id);


--
-- Name: active_guichets active_guichets_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.active_guichets
    ADD CONSTRAINT active_guichets_user_id_key UNIQUE (user_id);


--
-- Name: agence agence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agence
    ADD CONSTRAINT agence_pkey PRIMARY KEY (id);


--
-- Name: agence agence_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agence
    ADD CONSTRAINT agence_slug_key UNIQUE (slug);


--
-- Name: guichet guichet_nom_guichet_agence_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guichet
    ADD CONSTRAINT guichet_nom_guichet_agence_id_key UNIQUE (nom_guichet, agence_id);


--
-- Name: guichet guichet_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guichet
    ADD CONSTRAINT guichet_pkey PRIMARY KEY (id);


--
-- Name: guichet_service guichet_service_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guichet_service
    ADD CONSTRAINT guichet_service_pkey PRIMARY KEY (id);


--
-- Name: service service_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT service_pkey PRIMARY KEY (id);


--
-- Name: sous_service sous_service_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sous_service
    ADD CONSTRAINT sous_service_pkey PRIMARY KEY (id);


--
-- Name: ticket ticket_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket
    ADD CONSTRAINT ticket_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: active_guichets active_guichets_agence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.active_guichets
    ADD CONSTRAINT active_guichets_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;


--
-- Name: active_guichets active_guichets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.active_guichets
    ADD CONSTRAINT active_guichets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: guichet guichet_agence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guichet
    ADD CONSTRAINT guichet_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;


--
-- Name: guichet_service guichet_service_agence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guichet_service
    ADD CONSTRAINT guichet_service_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;


--
-- Name: guichet_service guichet_service_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guichet_service
    ADD CONSTRAINT guichet_service_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: sous_service sous_service_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sous_service
    ADD CONSTRAINT sous_service_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: ticket ticket_agence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket
    ADD CONSTRAINT ticket_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;


--
-- Name: ticket ticket_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket
    ADD CONSTRAINT ticket_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: ticket ticket_sous_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket
    ADD CONSTRAINT ticket_sous_service_id_fkey FOREIGN KEY (sous_service_id) REFERENCES public.sous_service(id) ON DELETE SET NULL;


--
-- Name: ticket ticket_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket
    ADD CONSTRAINT ticket_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: users users_agence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id);


--
-- Name: users users_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_id_fkey FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: guichet Enable insert/update for authenticated users; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Enable insert/update for authenticated users" ON public.guichet TO authenticated USING (true) WITH CHECK (true);


--
-- Name: guichet Enable read access for authenticated users; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Enable read access for authenticated users" ON public.guichet FOR SELECT TO authenticated USING (true);


--
-- Name: active_guichets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.active_guichets ENABLE ROW LEVEL SECURITY;

--
-- Name: active_guichets active_guichets_delete_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY active_guichets_delete_policy ON public.active_guichets FOR DELETE USING (((auth.uid() = user_id) OR (( SELECT users.role
   FROM public.users
  WHERE (users.id = auth.uid())) = ANY (ARRAY['admin'::text, 'super_admin'::text]))));


--
-- Name: active_guichets active_guichets_insert_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY active_guichets_insert_policy ON public.active_guichets FOR INSERT WITH CHECK ((auth.uid() = user_id));


--
-- Name: active_guichets active_guichets_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY active_guichets_select_policy ON public.active_guichets FOR SELECT USING (true);


--
-- Name: agence; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agence ENABLE ROW LEVEL SECURITY;

--
-- Name: agence agence_delete_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY agence_delete_policy ON public.agence FOR DELETE USING ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: agence agence_insert_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY agence_insert_policy ON public.agence FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: agence agence_public_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY agence_public_select_policy ON public.agence FOR SELECT USING (true);


--
-- Name: agence agence_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY agence_select_policy ON public.agence FOR SELECT USING (((( SELECT users.role
   FROM public.users
  WHERE (users.id = auth.uid())) = 'super_admin'::text) OR (id = ( SELECT users.agence_id
   FROM public.users
  WHERE (users.id = auth.uid())))));


--
-- Name: agence agence_select_public_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY agence_select_public_policy ON public.agence FOR SELECT USING (true);


--
-- Name: agence agence_update_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY agence_update_policy ON public.agence FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: guichet; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.guichet ENABLE ROW LEVEL SECURITY;

--
-- Name: guichet_service; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.guichet_service ENABLE ROW LEVEL SECURITY;

--
-- Name: guichet_service guichet_service_modify_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY guichet_service_modify_policy ON public.guichet_service USING (((( SELECT users.role
   FROM public.users
  WHERE (users.id = auth.uid())) = 'super_admin'::text) OR ((( SELECT users.role
   FROM public.users
  WHERE (users.id = auth.uid())) = 'admin'::text) AND (agence_id = ( SELECT users.agence_id
   FROM public.users
  WHERE (users.id = auth.uid()))))));


--
-- Name: guichet_service guichet_service_public_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY guichet_service_public_select_policy ON public.guichet_service FOR SELECT USING (true);


--
-- Name: guichet_service guichet_service_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY guichet_service_select_policy ON public.guichet_service FOR SELECT USING (((( SELECT users.role
   FROM public.users
  WHERE (users.id = auth.uid())) = 'super_admin'::text) OR (agence_id = ( SELECT users.agence_id
   FROM public.users
  WHERE (users.id = auth.uid())))));


--
-- Name: service; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.service ENABLE ROW LEVEL SECURITY;

--
-- Name: service service_delete_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY service_delete_policy ON public.service FOR DELETE USING ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: service service_insert_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY service_insert_policy ON public.service FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: service service_public_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY service_public_select_policy ON public.service FOR SELECT USING (true);


--
-- Name: service service_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY service_select_policy ON public.service FOR SELECT USING ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = ANY (ARRAY['super_admin'::text, 'admin'::text]))))));


--
-- Name: service service_select_public_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY service_select_public_policy ON public.service FOR SELECT USING (true);


--
-- Name: service service_update_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY service_update_policy ON public.service FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: sous_service; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.sous_service ENABLE ROW LEVEL SECURITY;

--
-- Name: sous_service sous_service_delete_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sous_service_delete_policy ON public.sous_service FOR DELETE USING ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: sous_service sous_service_insert_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sous_service_insert_policy ON public.sous_service FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: sous_service sous_service_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sous_service_select_policy ON public.sous_service FOR SELECT USING (((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = ANY (ARRAY['super_admin'::text, 'admin'::text, 'agent'::text]))))) OR true));


--
-- Name: sous_service sous_service_update_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY sous_service_update_policy ON public.sous_service FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM public.users
  WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));


--
-- Name: ticket; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ticket ENABLE ROW LEVEL SECURITY;

--
-- Name: ticket ticket_insert_public_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY ticket_insert_public_policy ON public.ticket FOR INSERT WITH CHECK (true);


--
-- Name: ticket ticket_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY ticket_select_policy ON public.ticket FOR SELECT USING (((agence_id = ( SELECT users.agence_id
   FROM public.users
  WHERE (users.id = auth.uid()))) OR (( SELECT users.role
   FROM public.users
  WHERE (users.id = auth.uid())) = 'super_admin'::text) OR true));


--
-- Name: ticket ticket_select_public_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY ticket_select_public_policy ON public.ticket FOR SELECT USING (true);


--
-- Name: ticket ticket_update_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY ticket_update_policy ON public.ticket FOR UPDATE USING ((agence_id = ( SELECT users.agence_id
   FROM public.users
  WHERE (users.id = auth.uid()))));


--
-- Name: users; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

--
-- Name: users users_delete_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY users_delete_policy ON public.users FOR DELETE USING (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence()) AND (auth.uid() <> id))));


--
-- Name: users users_insert_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY users_insert_policy ON public.users FOR INSERT WITH CHECK (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence()))));


--
-- Name: users users_select_own; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY users_select_own ON public.users FOR SELECT USING ((auth.uid() = id));


--
-- Name: users users_select_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY users_select_policy ON public.users FOR SELECT USING (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence())) OR (auth.uid() = id)));


--
-- Name: users users_update_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY users_update_policy ON public.users FOR UPDATE USING (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (agence_id = public.get_my_agence())) OR (auth.uid() = id))) WITH CHECK (((public.get_my_role() = 'super_admin'::text) OR ((public.get_my_role() = 'admin'::text) AND (role <> 'super_admin'::text) AND (agence_id = public.get_my_agence())) OR ((auth.uid() = id) AND (role = public.get_my_role()) AND ((agence_id = public.get_my_agence()) OR (public.get_my_role() = 'super_admin'::text)))));


--
-- PostgreSQL database dump complete
--

