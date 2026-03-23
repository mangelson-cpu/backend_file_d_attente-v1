-- 1. Activer RLS sur la table agence
ALTER TABLE public.agence ENABLE ROW LEVEL SECURITY;

-- 2. SELECT : super_admin uniquement
CREATE POLICY "agence_select_policy"
  ON public.agence
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- 3. INSERT : super_admin uniquement
CREATE POLICY "agence_insert_policy"
  ON public.agence
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- 4. UPDATE : super_admin uniquement
CREATE POLICY "agence_update_policy"
  ON public.agence
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- 5. DELETE : super_admin uniquement
CREATE POLICY "agence_delete_policy"
  ON public.agence
  FOR DELETE
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- Permettre à chaque utilisateur de lire SON PROPRE profil
CREATE POLICY "users_select_own"
  ON public.users
  FOR SELECT
  USING (auth.uid() = id);

  SELECT policyname, cmd, qual 
FROM pg_policies 
WHERE tablename = 'users';

