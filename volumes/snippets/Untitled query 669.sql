
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Active le realtime à l'avance (si possible)
ALTER TABLE public.app_settings REPLICA IDENTITY FULL;

-- Valeurs par défaut
INSERT INTO app_settings (key, value) VALUES
    ('primary_color', '#8b5cf6'),
    ('secondary_color', '#d4145a')
ON CONFLICT (key) DO NOTHING;

-- RLS
ALTER TABLE app_settings ENABLE ROW LEVEL SECURITY;

-- Lecture publique (tout le monde peut lire les paramètres)
CREATE POLICY "Public read app_settings"
    ON app_settings FOR SELECT
    USING (true);

-- Écriture réservée aux super_admin
CREATE POLICY "Super admin write app_settings"
    ON app_settings FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = auth.uid()
            AND users.role = 'super_admin'
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = auth.uid()
            AND users.role = 'super_admin'
        )
    );
