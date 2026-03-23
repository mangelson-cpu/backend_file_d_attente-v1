-- 1. Créer la table service
CREATE TABLE public.service (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  nom_service TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Activer RLS
ALTER TABLE public.service ENABLE ROW LEVEL SECURITY;

-- 3. SELECT : super_admin et admin peuvent lire
CREATE POLICY "service_select_policy"
  ON public.service
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role IN ('super_admin', 'admin')
    )
  );

-- 4. INSERT : super_admin uniquement
CREATE POLICY "service_insert_policy"
  ON public.service
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- 5. UPDATE : super_admin uniquement
CREATE POLICY "service_update_policy"
  ON public.service
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );

-- 6. DELETE : super_admin uniquement
CREATE POLICY "service_delete_policy"
  ON public.service
  FOR DELETE
  USING (
    EXISTS (
      SELECT 1 FROM public.users
      WHERE users.id = auth.uid()
      AND users.role = 'super_admin'
    )
  );
