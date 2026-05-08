-- Складской учёт: категории, товары, движения, фото в Storage
-- Выполните в SQL Editor проекта Supabase

create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now(),
  constraint categories_name_unique unique (name)
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  sku text not null default '',
  unit text not null default 'шт',
  category_id uuid references public.categories (id) on delete set null,
  note text not null default '',
  quantity integer not null default 0,
  photo_urls jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  constraint products_quantity_nonneg check (quantity >= 0)
);

create index if not exists idx_products_category_id on public.products (category_id);
create index if not exists idx_products_name_lower on public.products (lower(name));

create table if not exists public.stock_movements (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products (id) on delete cascade,
  type text not null check (type in ('receive', 'ship')),
  amount integer not null check (amount > 0),
  user_role text not null,
  note text not null default '',
  at timestamptz not null default now()
);

create index if not exists idx_stock_movements_at on public.stock_movements (at desc);
create index if not exists idx_stock_movements_product on public.stock_movements (product_id);

-- Публичный bucket для URL фото (загрузка с сервера через service role)
insert into storage.buckets (id, name, public)
values ('product-photos', 'product-photos', true)
on conflict (id) do nothing;

drop policy if exists "product_photos_public_read" on storage.objects;
create policy "product_photos_public_read"
  on storage.objects for select
  using (bucket_id = 'product-photos');

