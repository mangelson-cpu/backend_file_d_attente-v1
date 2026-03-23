-- ============================================================
-- POLITIQUES RLS MULTI-NIVEAUX POUR LA TABLE USERS
-- À exécuter dans le SQL Editor de Supabase
-- ============================================================

-- 1. Activer RLS
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- 2. Nettoyage des anciennes politiques
DROP POLICY IF EXISTS "users_select_policy" ON public.users;
DROP POLICY IF EXISTS "users_insert_policy" ON public.users;
DROP POLICY IF EXISTS "users_update_policy" ON public.users;
DROP POLICY IF EXISTS "users_delete_policy" ON public.users;

-- 3. Fonctions utilitaires pour éviter la récursion RLS
-- Ces fonctions sont 'SECURITY DEFINER' pour outrepasser RLS lors de la vérification des droits
CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT AS $$
  SELECT role FROM public.users WHERE id = auth.uid();
$$ LANGUAGE sql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.get_my_agence()
RETURNS UUID AS $$
  SELECT agence_id FROM public.users WHERE id = auth.uid();
$$ LANGUAGE sql SECURITY DEFINER SET search_path = public;

-- 4. Politique SELECT
-- - super_admin voit tout
-- - admin voit les gens de son agence
-- - user voit son propre profil
CREATE POLICY "users_select_policy" ON public.users
FOR SELECT
USING (
  get_my_role() = 'super_admin' 
  OR (get_my_role() = 'admin' AND agence_id = get_my_agence())
  OR (auth.uid() = id)
);

-- 5. Politique INSERT
-- - super_admin peut tout créer
-- - admin peut créer des users pour son agence uniquement
CREATE POLICY "users_insert_policy" ON public.users
FOR INSERT
WITH CHECK (
  get_my_role() = 'super_admin'
  OR (get_my_role() = 'admin' AND agence_id = get_my_agence())
);

-- 6. Politique UPDATE
-- - super_admin peut tout modifier
-- - admin peut modifier les utilisateurs de son agence
-- - l'utilisateur peut modifier son propre profil
CREATE POLICY "users_update_policy" ON public.users
FOR UPDATE
USING (
  get_my_role() = 'super_admin'
  OR (get_my_role() = 'admin' AND agence_id = get_my_agence())
  OR (auth.uid() = id)
)
WITH CHECK (
  -- Le super_admin n'a pas de restriction sur l'agence_id (null)
  (get_my_role() = 'super_admin')
  OR (
    get_my_role() = 'admin' 
    AND role <> 'super_admin' 
    AND agence_id = get_my_agence()
  )
  OR (
    auth.uid() = id 
    AND role = get_my_role() -- On ne peut pas changer son propre rôle
    AND (agence_id = get_my_agence() OR get_my_role() = 'super_admin')
  )
);

-- 7. Politique DELETE
-- - super_admin peut tout supprimer
-- - admin peut supprimer les utilisateurs de son agence
CREATE POLICY "users_delete_policy" ON public.users
FOR DELETE
USING (
  get_my_role() = 'super_admin'
  OR (
    get_my_role() = 'admin' 
    AND agence_id = get_my_agence() 
    AND auth.uid() <> id
  )
);
