create table public.users (
  id uuid not null,
  email text not null,
  nom_user text not null,
  role text not null,
  agence_id uuid null,
  created_at timestamp with time zone null default now(),
  constraint users_pkey primary key (id),
  constraint users_id_fkey foreign KEY (id) references auth.users (id) on delete CASCADE,
  constraint users_agence_id_fkey foreign KEY (agence_id) references agence (id),
  constraint users_role_check check (
    (
      role = any (
        array['super_admin'::text, 'admin'::text, 'user'::text]
      )
    )
  )
) TABLESPACE pg_default;