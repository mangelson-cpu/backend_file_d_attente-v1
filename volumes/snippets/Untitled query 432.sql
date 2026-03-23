-- 1️⃣ Créer un utilisateur dans auth.users
insert into auth.users (id, email, encrypted_password)
values (
  '00000000-0000-0000-0000-000000000001', -- UUID unique
  'ralobo@gmail.com',
  auth.hash_password('123456')    -- mot de passe temporaire
);

-- 2️⃣ Créer le profil dans public.users
insert into public.users (id, email, nom_user, role)
values (
  '00000000-0000-0000-0000-000000000001',
  'ralobo@gmail.com',
  'ANGELSON',
  'super_admin'
);

-- Lister toutes les fonctions
select routine_schema, routine_name
from information_schema.routines
where routine_name = 'create_user_with_role';