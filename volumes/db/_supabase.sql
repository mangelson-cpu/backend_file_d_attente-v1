\set pguser `echo "$POSTGRES_USER"`

CREATE DATABASE _supabase WITH OWNER :pguser;

\c _supabase
CREATE SCHEMA IF NOT EXISTS _analytics AUTHORIZATION supabase_admin;
