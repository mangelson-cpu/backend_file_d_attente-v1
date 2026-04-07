-- Run this in your Supabase SQL Editor

-- 1. Create Priority table
CREATE TABLE public.priority (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    nom text NOT NULL,
    valeur integer NOT NULL,
    couleur text NOT NULL,
    icone text,
    created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE ONLY public.priority ADD CONSTRAINT priority_pkey PRIMARY KEY (id);

-- 2. Create Agence_Priority table for local activation
CREATE TABLE public.agence_priority (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agence_id uuid NOT NULL,
    priority_id uuid NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE ONLY public.agence_priority ADD CONSTRAINT agence_priority_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.agence_priority ADD CONSTRAINT agence_priority_unique UNIQUE (agence_id, priority_id);
ALTER TABLE ONLY public.agence_priority ADD CONSTRAINT agence_priority_agence_id_fkey FOREIGN KEY (agence_id) REFERENCES public.agence(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.agence_priority ADD CONSTRAINT agence_priority_priority_id_fkey FOREIGN KEY (priority_id) REFERENCES public.priority(id) ON DELETE CASCADE;

-- 3. Add priority_id to the existing ticket table
ALTER TABLE public.ticket ADD COLUMN priority_id uuid;
ALTER TABLE ONLY public.ticket ADD CONSTRAINT ticket_priority_id_fkey FOREIGN KEY (priority_id) REFERENCES public.priority(id) ON DELETE SET NULL;

-- 4. Enable Row Level Security (RLS)
ALTER TABLE public.priority ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agence_priority ENABLE ROW LEVEL SECURITY;

-- 5. Define Policies for priority
-- Anyone authenticated can read priorities (public select)
CREATE POLICY priority_select_public_policy ON public.priority FOR SELECT USING (true);
-- Only Super Admins can insert, update, delete
CREATE POLICY priority_insert_policy ON public.priority FOR INSERT WITH CHECK ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY priority_update_policy ON public.priority FOR UPDATE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));
CREATE POLICY priority_delete_policy ON public.priority FOR DELETE USING ((EXISTS ( SELECT 1 FROM public.users WHERE ((users.id = auth.uid()) AND (users.role = 'super_admin'::text)))));

-- 6. Define Policies for agence_priority
-- Anyone can read active priorities per agence
CREATE POLICY agence_priority_select_policy ON public.agence_priority FOR SELECT USING (true);
-- Super admins, and admins for their own agency, can insert/update/delete
CREATE POLICY agence_priority_insert_policy ON public.agence_priority FOR INSERT WITH CHECK (((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) OR ((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'admin'::text) AND (agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid()))))));
CREATE POLICY agence_priority_update_policy ON public.agence_priority FOR UPDATE USING (((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) OR ((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'admin'::text) AND (agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid()))))));
CREATE POLICY agence_priority_delete_policy ON public.agence_priority FOR DELETE USING (((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'super_admin'::text) OR ((( SELECT users.role FROM public.users WHERE (users.id = auth.uid())) = 'admin'::text) AND (agence_id = ( SELECT users.agence_id FROM public.users WHERE (users.id = auth.uid()))))));

-- Force schema reload to pick up new tables in PostgREST
NOTIFY pgrst, 'reload schema';

