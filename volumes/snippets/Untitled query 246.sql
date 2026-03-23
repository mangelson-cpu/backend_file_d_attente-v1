CREATE POLICY "Public Access" ON storage.objects FOR ALL TO public USING (bucket_id = 'spots') WITH CHECK (bucket_id = 'spots');
