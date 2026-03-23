-- ============================================================
-- SQL : Activer Realtime pour les tables clés (Version Corrigée)
-- Permet la mise à jour automatique sans rafraîchissement
-- ============================================================

-- 1. On essaye d'ajouter les tables à la publication existante (supabase_realtime)
-- Si elles sont déjà présentes, PostgreSQL peut retourner un message 
-- de type "already in publication", ce qui est tout à fait normal.

ALTER PUBLICATION supabase_realtime ADD TABLE public.service;
ALTER PUBLICATION supabase_realtime ADD TABLE public.guichet_service;

-- Note : Assurez-vous que l'extension "Realtime" est bien activée 
-- dans votre tableau de bord Supabase (Database -> Replication).
