CREATE TABLE public.spots (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  name text NOT NULL,
  url text NOT NULL,
  storage_path text NOT NULL,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- + Ajout des policies RLS appropriées :
-- Lecture publique pour tout le monde (agences)
-- Insertion/Suppression restreinte (idéalement pour le Super Admin)
