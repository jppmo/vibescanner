-- Supabase migration: initial schema

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    full_name text,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE posts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    title text NOT NULL,
    body text,
    published boolean DEFAULT false,
    created_at timestamptz DEFAULT now()
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_can_read_own_profile" ON users
  FOR SELECT TO authenticated
  USING (id = auth.uid());

ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_can_read_own_posts" ON posts
  FOR SELECT TO authenticated
  USING (user_id = auth.uid());
