INSERT INTO public.users (id, email, nom_user, role)
VALUES ('3d0d4bf8-76fc-4abc-b7f0-4aa4287e36a7', 'ralobo@gmail.com', 'Angelson', 'super_admin');

--supprime aussi le auth.users--
create or replace function public.delete_auth_user()
returns trigger
language plpgsql
as $$
begin
  delete from auth.users where id = OLD.id;
  return OLD;
end;
$$;

create trigger trg_delete_user
before delete on public.users
for each row
execute function public.delete_auth_user();