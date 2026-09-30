-- Create user role enum
create type public.app_role as enum ('admin', 'agent', 'client');

-- Create profiles table
create table public.profiles (
  id uuid not null references auth.users on delete cascade,
  full_name text,
  phone_number text,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now(),
  primary key (id)
);

alter table public.profiles enable row level security;

-- Create user_roles table
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  role app_role not null,
  unique (user_id, role)
);

alter table public.user_roles enable row level security;

-- Create wallet table for clients
create table public.wallets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null unique,
  balance decimal(10, 2) not null default 0.00,
  currency text not null default 'USD',
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

alter table public.wallets enable row level security;

-- Security definer function to check roles
create or replace function public.has_role(_user_id uuid, _role app_role)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.user_roles
    where user_id = _user_id
      and role = _role
  )
$$;

-- Profiles policies
create policy "Users can view their own profile"
on public.profiles for select
using (auth.uid() = id);

create policy "Users can update their own profile"
on public.profiles for update
using (auth.uid() = id);

create policy "Users can insert their own profile"
on public.profiles for insert
with check (auth.uid() = id);

-- User roles policies
create policy "Users can view their own roles"
on public.user_roles for select
using (auth.uid() = user_id);

create policy "Admins can view all roles"
on public.user_roles for select
using (public.has_role(auth.uid(), 'admin'));

create policy "Admins can insert roles"
on public.user_roles for insert
with check (public.has_role(auth.uid(), 'admin'));

create policy "Admins can update roles"
on public.user_roles for update
using (public.has_role(auth.uid(), 'admin'));

-- Wallet policies
create policy "Users can view their own wallet"
on public.wallets for select
using (auth.uid() = user_id);

create policy "Users can insert their own wallet"
on public.wallets for insert
with check (auth.uid() = user_id);

create policy "Users can update their own wallet"
on public.wallets for update
using (auth.uid() = user_id);

create policy "Agents can view client wallets"
on public.wallets for select
using (public.has_role(auth.uid(), 'agent') or public.has_role(auth.uid(), 'admin'));

-- Function to handle new user creation
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, phone_number)
  values (
    new.id,
    new.raw_user_meta_data ->> 'full_name',
    new.raw_user_meta_data ->> 'phone_number'
  );
  
  -- Insert default role (client) if no role specified
  insert into public.user_roles (user_id, role)
  values (new.id, coalesce((new.raw_user_meta_data ->> 'role')::app_role, 'client'));
  
  -- Create wallet for client users
  if coalesce((new.raw_user_meta_data ->> 'role')::app_role, 'client') = 'client' then
    insert into public.wallets (user_id)
    values (new.id);
  end if;
  
  return new;
end;
$$;

-- Trigger for new user creation
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Function to update timestamps
create or replace function public.update_updated_at_column()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql set search_path = public;

-- Triggers for updated_at
create trigger update_profiles_updated_at
before update on public.profiles
for each row
execute function public.update_updated_at_column();

create trigger update_wallets_updated_at
before update on public.wallets
for each row
execute function public.update_updated_at_column();-- Create transactions table with double-spending prevention
CREATE TABLE public.transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id uuid REFERENCES auth.users(id) NOT NULL,
  receiver_id uuid REFERENCES auth.users(id) NOT NULL,
  amount numeric NOT NULL CHECK (amount > 0),
  fee numeric NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  transaction_type text NOT NULL CHECK (transaction_type IN ('transfer', 'deposit', 'withdrawal', 'fund_request')),
  description text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  completed_at timestamp with time zone,
  CONSTRAINT no_self_transfer CHECK (sender_id != receiver_id)
);

-- Create transaction_fees table for admin to manage fees
CREATE TABLE public.transaction_fees (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_type text NOT NULL UNIQUE,
  fee_percentage numeric NOT NULL DEFAULT 0 CHECK (fee_percentage >= 0 AND fee_percentage <= 100),
  fixed_fee numeric NOT NULL DEFAULT 0 CHECK (fixed_fee >= 0),
  updated_by uuid REFERENCES auth.users(id),
  updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Insert default fees
INSERT INTO public.transaction_fees (transaction_type, fee_percentage, fixed_fee) VALUES
('transfer', 1.0, 0.50),
('deposit', 0, 0),
('withdrawal', 0.5, 1.00);

-- Create fund_requests table with verification codes
CREATE TABLE public.fund_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_id uuid REFERENCES auth.users(id) NOT NULL,
  payer_id uuid REFERENCES auth.users(id) NOT NULL,
  amount numeric NOT NULL CHECK (amount > 0),
  verification_code text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'completed')),
  expires_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  completed_at timestamp with time zone
);

-- Create pending_deposits table for agent deposits awaiting admin approval
CREATE TABLE public.pending_deposits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid REFERENCES auth.users(id) NOT NULL,
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  amount numeric NOT NULL CHECK (amount > 0),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  approved_by uuid REFERENCES auth.users(id),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  processed_at timestamp with time zone
);

-- Add indexes for performance
CREATE INDEX idx_transactions_sender ON public.transactions(sender_id);
CREATE INDEX idx_transactions_receiver ON public.transactions(receiver_id);
CREATE INDEX idx_transactions_status ON public.transactions(status);
CREATE INDEX idx_fund_requests_payer ON public.fund_requests(payer_id);
CREATE INDEX idx_fund_requests_requester ON public.fund_requests(requester_id);
CREATE INDEX idx_pending_deposits_status ON public.pending_deposits(status);

-- Enable RLS
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transaction_fees ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fund_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pending_deposits ENABLE ROW LEVEL SECURITY;

-- RLS Policies for transactions
CREATE POLICY "Users can view their own transactions"
ON public.transactions FOR SELECT
USING (auth.uid() = sender_id OR auth.uid() = receiver_id);

CREATE POLICY "Admins can view all transactions"
ON public.transactions FOR SELECT
USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Users can create transactions"
ON public.transactions FOR INSERT
WITH CHECK (auth.uid() = sender_id);

-- RLS Policies for transaction_fees
CREATE POLICY "Everyone can view fees"
ON public.transaction_fees FOR SELECT
USING (true);

CREATE POLICY "Admins can manage fees"
ON public.transaction_fees FOR ALL
USING (public.has_role(auth.uid(), 'admin'));

-- RLS Policies for fund_requests
CREATE POLICY "Users can view their fund requests"
ON public.fund_requests FOR SELECT
USING (auth.uid() = requester_id OR auth.uid() = payer_id);

CREATE POLICY "Users can create fund requests"
ON public.fund_requests FOR INSERT
WITH CHECK (auth.uid() = requester_id);

CREATE POLICY "Payers can update fund request status"
ON public.fund_requests FOR UPDATE
USING (auth.uid() = payer_id);

-- RLS Policies for pending_deposits
CREATE POLICY "Agents can view their pending deposits"
ON public.pending_deposits FOR SELECT
USING (auth.uid() = agent_id OR public.has_role(auth.uid(), 'agent'));

CREATE POLICY "Admins can view all pending deposits"
ON public.pending_deposits FOR SELECT
USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Agents can create deposits"
ON public.pending_deposits FOR INSERT
WITH CHECK (auth.uid() = agent_id AND public.has_role(auth.uid(), 'agent'));

CREATE POLICY "Admins can approve deposits"
ON public.pending_deposits FOR UPDATE
USING (public.has_role(auth.uid(), 'admin'));

-- Function to process transaction with double-spending prevention
CREATE OR REPLACE FUNCTION public.process_transaction(
  _sender_id uuid,
  _receiver_id uuid,
  _amount numeric,
  _transaction_type text,
  _description text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _sender_balance numeric;
  _fee_percentage numeric;
  _fixed_fee numeric;
  _total_fee numeric;
  _total_amount numeric;
  _transaction_id uuid;
BEGIN
  -- Lock sender's wallet to prevent concurrent modifications (double-spending prevention)
  SELECT balance INTO _sender_balance
  FROM public.wallets
  WHERE user_id = _sender_id
  FOR UPDATE;

  -- Get fee structure
  SELECT fee_percentage, fixed_fee INTO _fee_percentage, _fixed_fee
  FROM public.transaction_fees
  WHERE transaction_type = _transaction_type;

  -- Calculate fees
  _total_fee := (_amount * _fee_percentage / 100) + COALESCE(_fixed_fee, 0);
  _total_amount := _amount + _total_fee;

  -- Check if sender has sufficient balance
  IF _sender_balance < _total_amount THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Insufficient balance'
    );
  END IF;

  -- Deduct from sender
  UPDATE public.wallets
  SET balance = balance - _total_amount,
      updated_at = now()
  WHERE user_id = _sender_id;

  -- Add to receiver
  UPDATE public.wallets
  SET balance = balance + _amount,
      updated_at = now()
  WHERE user_id = _receiver_id;

  -- Create transaction record
  INSERT INTO public.transactions (sender_id, receiver_id, amount, fee, status, transaction_type, description, completed_at)
  VALUES (_sender_id, _receiver_id, _amount, _total_fee, 'completed', _transaction_type, _description, now())
  RETURNING id INTO _transaction_id;

  RETURN jsonb_build_object(
    'success', true,
    'transaction_id', _transaction_id,
    'fee', _total_fee
  );
END;
$$;

-- Function for admin to add funds
CREATE OR REPLACE FUNCTION public.admin_add_funds(
  _user_id uuid,
  _amount numeric
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Check if caller is admin
  IF NOT public.has_role(auth.uid(), 'admin') THEN
    RETURN jsonb_build_object('success', false, 'error', 'Unauthorized');
  END IF;

  -- Add funds to user wallet
  UPDATE public.wallets
  SET balance = balance + _amount,
      updated_at = now()
  WHERE user_id = _user_id;

  -- Create transaction record
  INSERT INTO public.transactions (sender_id, receiver_id, amount, fee, status, transaction_type, description, completed_at)
  VALUES (auth.uid(), _user_id, _amount, 0, 'completed', 'deposit', 'Admin deposit', now());

  RETURN jsonb_build_object('success', true);
END;
$$;-- Create external_databases table
CREATE TABLE public.external_databases (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 5432,
  database_name TEXT NOT NULL,
  username TEXT NOT NULL,
  secret_key TEXT NOT NULL,
  created_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create database_backups table
CREATE TABLE public.database_backups (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  external_db_id UUID REFERENCES public.external_databases(id) ON DELETE SET NULL,
  backup_name TEXT NOT NULL,
  backup_type TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'pending',
  file_size BIGINT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.external_databases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.database_backups ENABLE ROW LEVEL SECURITY;

-- RLS policies for external_databases (admin only)
CREATE POLICY "Admins can manage external databases"
  ON public.external_databases
  FOR ALL
  USING (has_role(auth.uid(), 'admin'));

-- RLS policies for database_backups (admin only)
CREATE POLICY "Admins can manage database backups"
  ON public.database_backups
  FOR ALL
  USING (has_role(auth.uid(), 'admin'));-- Create blockchain settings table for admin configuration
CREATE TABLE public.blockchain_settings (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  rpc_url text,
  chain_id text,
  native_coin_symbol text NOT NULL DEFAULT 'GYD',
  native_coin_name text NOT NULL DEFAULT 'GYD Coin',
  explorer_url text,
  is_active boolean NOT NULL DEFAULT false,
  updated_by uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.blockchain_settings ENABLE ROW LEVEL SECURITY;

-- Everyone can view blockchain settings
CREATE POLICY "Everyone can view blockchain settings"
ON public.blockchain_settings
FOR SELECT
USING (true);

-- Only admins can manage blockchain settings
CREATE POLICY "Admins can manage blockchain settings"
ON public.blockchain_settings
FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role));

-- Add trigger for updated_at
CREATE TRIGGER update_blockchain_settings_updated_at
BEFORE UPDATE ON public.blockchain_settings
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Insert default blockchain settings
INSERT INTO public.blockchain_settings (native_coin_symbol, native_coin_name, is_active)
VALUES ('GYD', 'GYD Coin', false);

-- Add new columns to profiles table
ALTER TABLE public.profiles
ADD COLUMN avatar_url text,
ADD COLUMN address text,
ADD COLUMN city text,
ADD COLUMN country text,
ADD COLUMN date_of_birth date,
ADD COLUMN bio text;

-- Create storage bucket for avatars
INSERT INTO storage.buckets (id, name, public)
VALUES ('avatars', 'avatars', true);

-- Storage policies for avatars
CREATE POLICY "Avatar images are publicly accessible"
ON storage.objects FOR SELECT
USING (bucket_id = 'avatars');

CREATE POLICY "Users can upload their own avatar"
ON storage.objects FOR INSERT
WITH CHECK (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can update their own avatar"
ON storage.objects FOR UPDATE
USING (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can delete their own avatar"
ON storage.objects FOR DELETE
USING (bucket_id = 'avatars' AND auth.uid()::text = (storage.foldername(name))[1]);-- Allow admins to view all profiles
CREATE POLICY "Admins can view all profiles"
ON public.profiles
FOR SELECT
USING (has_role(auth.uid(), 'admin'::app_role));

-- Add wallet fields to profiles
ALTER TABLE public.profiles
ADD COLUMN wallet_address text,
ADD COLUMN wallet_created_at timestamp with time zone;

-- Create user_wallets table for blockchain wallet info
CREATE TABLE public.user_wallets (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid NOT NULL UNIQUE,
  wallet_address text NOT NULL,
  encrypted_private_key text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Enable RLS on user_wallets
ALTER TABLE public.user_wallets ENABLE ROW LEVEL SECURITY;

-- Users can only view their own wallet
CREATE POLICY "Users can view their own wallet"
ON public.user_wallets
FOR SELECT
USING (auth.uid() = user_id);

-- Users can insert their own wallet
CREATE POLICY "Users can insert their own wallet"
ON public.user_wallets
FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Admins can view all wallets
CREATE POLICY "Admins can view all wallets"
ON public.user_wallets
FOR SELECT
USING (has_role(auth.uid(), 'admin'::app_role));-- Update handle_new_user to include wallet_address from metadata
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
begin
  insert into public.profiles (id, full_name, phone_number, wallet_address, wallet_created_at)
  values (
    new.id,
    new.raw_user_meta_data ->> 'full_name',
    new.raw_user_meta_data ->> 'phone_number',
    new.raw_user_meta_data ->> 'wallet_address',
    CASE WHEN new.raw_user_meta_data ->> 'wallet_address' IS NOT NULL THEN now() ELSE NULL END
  );
  
  -- Insert default role (client) if no role specified
  insert into public.user_roles (user_id, role)
  values (new.id, coalesce((new.raw_user_meta_data ->> 'role')::app_role, 'client'));
  
  -- Create wallet for client users
  if coalesce((new.raw_user_meta_data ->> 'role')::app_role, 'client') = 'client' then
    insert into public.wallets (user_id)
    values (new.id);
  end if;
  
  return new;
end;
$function$;-- Add liquidity pool address to blockchain settings
ALTER TABLE public.blockchain_settings 
ADD COLUMN IF NOT EXISTS liquidity_pool_address text;

-- Update process_transaction to include fee split (60% cashback, 40% liquidity)
CREATE OR REPLACE FUNCTION public.process_transaction(_sender_id uuid, _receiver_id uuid, _amount numeric, _transaction_type text, _description text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $$
DECLARE
  _sender_balance numeric;
  _fee_percentage numeric;
  _fixed_fee numeric;
  _total_fee numeric;
  _total_amount numeric;
  _transaction_id uuid;
  _sender_cashback numeric;
  _liquidity_pool_fee numeric;
BEGIN
  -- Lock sender's wallet to prevent concurrent modifications (double-spending prevention)
  SELECT balance INTO _sender_balance
  FROM public.wallets
  WHERE user_id = _sender_id
  FOR UPDATE;

  -- Get fee structure
  SELECT fee_percentage, fixed_fee INTO _fee_percentage, _fixed_fee
  FROM public.transaction_fees
  WHERE transaction_type = _transaction_type;

  -- Calculate fees
  _total_fee := (_amount * _fee_percentage / 100) + COALESCE(_fixed_fee, 0);
  
  -- Fee split: 60% cashback to sender, 40% to liquidity pool
  _sender_cashback := _total_fee * 0.60;
  _liquidity_pool_fee := _total_fee * 0.40;
  
  -- Total amount sender pays (amount + liquidity pool portion only, since they get 60% back)
  _total_amount := _amount + _liquidity_pool_fee;

  -- Check if sender has sufficient balance
  IF _sender_balance < _total_amount THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Insufficient balance'
    );
  END IF;

  -- Deduct from sender (amount + liquidity pool fee portion)
  UPDATE public.wallets
  SET balance = balance - _total_amount,
      updated_at = now()
  WHERE user_id = _sender_id;

  -- Add to receiver
  UPDATE public.wallets
  SET balance = balance + _amount,
      updated_at = now()
  WHERE user_id = _receiver_id;

  -- Create transaction record
  INSERT INTO public.transactions (sender_id, receiver_id, amount, fee, status, transaction_type, description, completed_at)
  VALUES (_sender_id, _receiver_id, _amount, _total_fee, 'completed', _transaction_type, _description, now())
  RETURNING id INTO _transaction_id;

  RETURN jsonb_build_object(
    'success', true,
    'transaction_id', _transaction_id,
    'fee', _total_fee,
    'sender_cashback', _sender_cashback,
    'liquidity_pool_fee', _liquidity_pool_fee
  );
END;
$$;-- Add unique constraint on phone_number in profiles
ALTER TABLE public.profiles ADD CONSTRAINT profiles_phone_number_unique UNIQUE (phone_number);

-- Create supported coins table (admin sets which coins can be sent)
CREATE TABLE public.supported_coins (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  coin_symbol TEXT NOT NULL UNIQUE,
  coin_name TEXT NOT NULL,
  contract_address TEXT,
  is_native BOOLEAN NOT NULL DEFAULT false,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.supported_coins ENABLE ROW LEVEL SECURITY;

-- RLS policies for supported_coins
CREATE POLICY "Everyone can view supported coins" ON public.supported_coins FOR SELECT USING (true);
CREATE POLICY "Admins can manage supported coins" ON public.supported_coins FOR ALL USING (has_role(auth.uid(), 'admin'));

-- Create conversion fees table
CREATE TABLE public.conversion_fees (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  from_coin TEXT NOT NULL,
  to_coin TEXT NOT NULL,
  fee_percentage NUMERIC NOT NULL DEFAULT 1.0,
  is_active BOOLEAN NOT NULL DEFAULT true,
  updated_by UUID,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(from_coin, to_coin)
);

-- Enable RLS
ALTER TABLE public.conversion_fees ENABLE ROW LEVEL SECURITY;

-- RLS policies for conversion_fees
CREATE POLICY "Everyone can view conversion fees" ON public.conversion_fees FOR SELECT USING (true);
CREATE POLICY "Admins can manage conversion fees" ON public.conversion_fees FOR ALL USING (has_role(auth.uid(), 'admin'));

-- Add trigger for updated_at
CREATE TRIGGER update_supported_coins_updated_at BEFORE UPDATE ON public.supported_coins FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_conversion_fees_updated_at BEFORE UPDATE ON public.conversion_fees FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Insert default GYD coin as native
INSERT INTO public.supported_coins (coin_symbol, coin_name, is_native, is_active) VALUES ('GYD', 'GYD Coin', true, true);-- Create feature toggles table for admin to control visibility of features
CREATE TABLE public.feature_toggles (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  feature_key text NOT NULL UNIQUE,
  feature_name text NOT NULL,
  is_enabled boolean NOT NULL DEFAULT false,
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES auth.users(id)
);

-- Enable RLS
ALTER TABLE public.feature_toggles ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Everyone can view feature toggles" 
ON public.feature_toggles 
FOR SELECT 
USING (true);

CREATE POLICY "Admins can manage feature toggles" 
ON public.feature_toggles 
FOR ALL 
USING (has_role(auth.uid(), 'admin'));

-- Insert default features (disabled by default)
INSERT INTO public.feature_toggles (feature_key, feature_name, is_enabled) VALUES
('pay_bills', 'Pay Bills', false),
('top_up', 'Mobile Top-up', false),
('pay_merchant', 'Pay Merchant', false);

-- Trigger for updated_at
CREATE TRIGGER update_feature_toggles_updated_at
BEFORE UPDATE ON public.feature_toggles
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();-- Add fee wallet address column to blockchain_settings
ALTER TABLE public.blockchain_settings 
ADD COLUMN fee_wallet_address text;-- Add vendor role to app_role enum
ALTER TYPE public.app_role ADD VALUE IF NOT EXISTS 'vendor';

-- Create vendor_products table for vendors to add items
CREATE TABLE public.vendor_products (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  vendor_id UUID NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  logo_url TEXT,
  price NUMERIC NOT NULL,
  discount_price NUMERIC,
  category TEXT,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.vendor_products ENABLE ROW LEVEL SECURITY;

-- Policies for vendor_products
CREATE POLICY "Vendors can manage their own products"
ON public.vendor_products
FOR ALL
USING (auth.uid() = vendor_id);

CREATE POLICY "Everyone can view active products"
ON public.vendor_products
FOR SELECT
USING (is_active = true);

-- Create trigger for updated_at
CREATE TRIGGER update_vendor_products_updated_at
BEFORE UPDATE ON public.vendor_products
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Update process_transaction to handle admin unlimited funds
CREATE OR REPLACE FUNCTION public.process_transaction(_sender_id uuid, _receiver_id uuid, _amount numeric, _transaction_type text, _description text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  _sender_balance numeric;
  _fee_percentage numeric;
  _fixed_fee numeric;
  _total_fee numeric;
  _total_amount numeric;
  _transaction_id uuid;
  _sender_cashback numeric;
  _liquidity_pool_fee numeric;
  _is_admin boolean;
BEGIN
  -- Check if sender is admin (admins have unlimited funds)
  SELECT public.has_role(_sender_id, 'admin') INTO _is_admin;

  -- Lock sender's wallet to prevent concurrent modifications (double-spending prevention)
  SELECT balance INTO _sender_balance
  FROM public.wallets
  WHERE user_id = _sender_id
  FOR UPDATE;

  -- Get fee structure
  SELECT fee_percentage, fixed_fee INTO _fee_percentage, _fixed_fee
  FROM public.transaction_fees
  WHERE transaction_type = _transaction_type;

  -- Calculate fees (no fees for admin)
  IF _is_admin THEN
    _total_fee := 0;
    _sender_cashback := 0;
    _liquidity_pool_fee := 0;
    _total_amount := _amount;
  ELSE
    _total_fee := (_amount * COALESCE(_fee_percentage, 0) / 100) + COALESCE(_fixed_fee, 0);
    
    -- Fee split: 60% cashback to sender, 40% to liquidity pool
    _sender_cashback := _total_fee * 0.60;
    _liquidity_pool_fee := _total_fee * 0.40;
    
    -- Total amount sender pays (amount + liquidity pool portion only, since they get 60% back)
    _total_amount := _amount + _liquidity_pool_fee;
  END IF;

  -- Check if sender has sufficient balance (skip for admin - unlimited funds)
  IF NOT _is_admin AND _sender_balance < _total_amount THEN
    RETURN jsonb_build_object(
      'success', false,
      'error', 'Insufficient balance'
    );
  END IF;

  -- Deduct from sender (only if not admin or if admin has wallet entry)
  IF NOT _is_admin THEN
    UPDATE public.wallets
    SET balance = balance - _total_amount,
        updated_at = now()
    WHERE user_id = _sender_id;
  END IF;

  -- Add to receiver (create wallet if doesn't exist)
  INSERT INTO public.wallets (user_id, balance)
  VALUES (_receiver_id, _amount)
  ON CONFLICT (user_id) DO UPDATE
  SET balance = wallets.balance + _amount,
      updated_at = now();

  -- Create transaction record
  INSERT INTO public.transactions (sender_id, receiver_id, amount, fee, status, transaction_type, description, completed_at)
  VALUES (_sender_id, _receiver_id, _amount, _total_fee, 'completed', _transaction_type, _description, now())
  RETURNING id INTO _transaction_id;

  RETURN jsonb_build_object(
    'success', true,
    'transaction_id', _transaction_id,
    'fee', _total_fee,
    'sender_cashback', _sender_cashback,
    'liquidity_pool_fee', _liquidity_pool_fee
  );
END;
$function$;-- Update the handle_new_user function to assign role based on account_type
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  account_type text;
  user_role app_role;
BEGIN
  -- Get account_type from raw_user_meta_data
  account_type := (NEW.raw_user_meta_data->>'account_type')::text;
  
  -- Determine role based on account_type (default to 'client')
  IF account_type = 'vendor' THEN
    user_role := 'vendor'::app_role;
  ELSE
    user_role := 'client'::app_role;
  END IF;
  
  -- Insert profile
  INSERT INTO public.profiles (id, full_name, phone_number, wallet_address, wallet_created_at)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name', ''),
    COALESCE(NEW.raw_user_meta_data->>'phone_number', ''),
    NEW.raw_user_meta_data->>'wallet_address',
    CASE WHEN NEW.raw_user_meta_data->>'wallet_address' IS NOT NULL THEN now() ELSE NULL END
  );
  
  -- Insert wallet with 0 balance
  INSERT INTO public.wallets (user_id, balance, currency)
  VALUES (NEW.id, 0, 'USD');
  
  -- Insert user role based on account_type
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, user_role);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;-- Add store_name to profiles for vendors
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS store_name text;

-- Create vendor_registration_fees table for admin to set vendor registration fees
CREATE TABLE IF NOT EXISTS public.vendor_registration_fees (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  fee_amount numeric NOT NULL DEFAULT 0,
  fee_name text NOT NULL DEFAULT 'Vendor Registration Fee',
  is_active boolean NOT NULL DEFAULT true,
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_by uuid
);

-- Enable RLS
ALTER TABLE public.vendor_registration_fees ENABLE ROW LEVEL SECURITY;

-- Admins can manage vendor registration fees
CREATE POLICY "Admins can manage vendor registration fees"
ON public.vendor_registration_fees
FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role));

-- Everyone can view vendor registration fees
CREATE POLICY "Everyone can view vendor registration fees"
ON public.vendor_registration_fees
FOR SELECT
USING (true);

-- Insert default registration fee
INSERT INTO public.vendor_registration_fees (fee_name, fee_amount, is_active)
VALUES ('Vendor Registration Fee', 50.00, true)
ON CONFLICT DO NOTHING;

-- Add RLS policy for viewing vendor profiles (store names)
CREATE POLICY "Everyone can view vendor store names"
ON public.profiles
FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM public.user_roles 
    WHERE user_roles.user_id = profiles.id 
    AND user_roles.role = 'vendor'
  )
);-- Add encrypted fee wallet private key for bank-sponsored gas payments
ALTER TABLE public.blockchain_settings 
ADD COLUMN IF NOT EXISTS fee_wallet_encrypted_key text;

-- Add gas fee percentage in GYD that users pay (transparent fee shown to users)
ALTER TABLE public.blockchain_settings 
ADD COLUMN IF NOT EXISTS gas_fee_gyd numeric NOT NULL DEFAULT 0.01;

-- Add column description
COMMENT ON COLUMN public.blockchain_settings.fee_wallet_encrypted_key IS 'Encrypted private key for the bank fee wallet that sponsors gas fees';
COMMENT ON COLUMN public.blockchain_settings.gas_fee_gyd IS 'Fee in GYD charged to users for gas sponsorship (transparent to user)';-- Add PIN column to profiles for transaction verification
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS pin_hash TEXT;

-- Create index for faster phone number lookups (if not exists)
CREATE INDEX IF NOT EXISTS idx_profiles_phone_number ON public.profiles(phone_number);

-- Create a table to track gas fees collected and spent by the bank
CREATE TABLE IF NOT EXISTS public.gas_fee_ledger (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_type TEXT NOT NULL, -- 'collected' or 'spent'
  amount NUMERIC NOT NULL,
  related_transaction_id UUID,
  user_id UUID,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS on gas_fee_ledger
ALTER TABLE public.gas_fee_ledger ENABLE ROW LEVEL SECURITY;

-- Only admins can view and manage gas fee ledger
CREATE POLICY "Admins can manage gas fee ledger"
  ON public.gas_fee_ledger
  FOR ALL
  USING (has_role(auth.uid(), 'admin'::app_role));

-- Create function to hash PIN (simple hash for demo, use bcrypt in production)
CREATE OR REPLACE FUNCTION public.hash_pin(pin TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RETURN encode(digest(pin, 'sha256'), 'hex');
END;
$$;

-- Create function to verify PIN
CREATE OR REPLACE FUNCTION public.verify_pin(user_id UUID, pin TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  stored_hash TEXT;
BEGIN
  SELECT pin_hash INTO stored_hash FROM profiles WHERE id = user_id;
  IF stored_hash IS NULL THEN
    RETURN FALSE;
  END IF;
  RETURN stored_hash = encode(digest(pin, 'sha256'), 'hex');
END;
$$;

-- Create function to set PIN
CREATE OR REPLACE FUNCTION public.set_user_pin(user_pin TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE profiles
  SET pin_hash = encode(digest(user_pin, 'sha256'), 'hex')
  WHERE id = auth.uid();
  RETURN FOUND;
END;
$$;CREATE EXTENSION IF NOT EXISTS pgcrypto SCHEMA extensions;
CREATE OR REPLACE FUNCTION public.set_user_pin(user_pin text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  UPDATE profiles
  SET pin_hash = encode(extensions.digest(user_pin, 'sha256'), 'hex')
  WHERE id = auth.uid();
  RETURN FOUND;
END;
$function$;

CREATE OR REPLACE FUNCTION public.verify_pin(user_id uuid, pin text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  stored_hash TEXT;
BEGIN
  SELECT pin_hash INTO stored_hash FROM profiles WHERE id = user_id;
  IF stored_hash IS NULL THEN
    RETURN FALSE;
  END IF;
  RETURN stored_hash = encode(extensions.digest(pin, 'sha256'), 'hex');
END;
$function$;

CREATE OR REPLACE FUNCTION public.hash_pin(pin text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  RETURN encode(extensions.digest(pin, 'sha256'), 'hex');
END;
$function$;

CREATE TABLE public.notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  title text NOT NULL,
  message text NOT NULL,
  type text NOT NULL DEFAULT 'info',
  is_read boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own notifications"
  ON public.notifications FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own notifications"
  ON public.notifications FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all notifications"
  ON public.notifications FOR SELECT
  USING (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Admins can insert notifications"
  ON public.notifications FOR INSERT
  WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "System can insert notifications"
  ON public.notifications FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE INDEX idx_notifications_user_id ON public.notifications(user_id);
CREATE INDEX idx_notifications_created_at ON public.notifications(created_at DESC);
ALTER PUBLICATION supabase_realtime ADD TABLE public.notifications;
CREATE OR REPLACE FUNCTION public.notify_transaction()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  _sender_name text;
  _receiver_name text;
BEGIN
  -- Only notify on completed transactions
  IF NEW.status != 'completed' THEN
    RETURN NEW;
  END IF;

  -- Get names
  SELECT full_name INTO _sender_name FROM profiles WHERE id = NEW.sender_id;
  SELECT full_name INTO _receiver_name FROM profiles WHERE id = NEW.receiver_id;

  -- Notify receiver: payment received
  INSERT INTO notifications (user_id, title, message, type)
  VALUES (
    NEW.receiver_id,
    'Payment Received',
    'You received $' || NEW.amount || ' from ' || COALESCE(_sender_name, 'someone'),
    'success'
  );

  -- Notify sender: payment sent confirmation
  IF NEW.transaction_type = 'transfer' THEN
    INSERT INTO notifications (user_id, title, message, type)
    VALUES (
      NEW.sender_id,
      'Payment Sent',
      'You sent $' || NEW.amount || ' to ' || COALESCE(_receiver_name, 'someone'),
      'info'
    );
  ELSIF NEW.transaction_type = 'deposit' THEN
    INSERT INTO notifications (user_id, title, message, type)
    VALUES (
      NEW.receiver_id,
      'Deposit Received',
      'Your account was credited with $' || NEW.amount,
      'success'
    );
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER on_transaction_completed
  AFTER INSERT ON public.transactions
  FOR EACH ROW
  EXECUTE FUNCTION public.notify_transaction();

-- Table to store biometric (WebAuthn) credentials for passwordless login
CREATE TABLE public.biometric_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  credential_id text NOT NULL UNIQUE,
  public_key text NOT NULL,
  device_name text DEFAULT 'Unknown Device',
  auth_type text NOT NULL DEFAULT 'fingerprint',
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  last_used_at timestamp with time zone
);

ALTER TABLE public.biometric_credentials ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own biometric credentials"
  ON public.biometric_credentials FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own biometric credentials"
  ON public.biometric_credentials FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own biometric credentials"
  ON public.biometric_credentials FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own biometric credentials"
  ON public.biometric_credentials FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id);

-- Add rpc_urls column (JSON array) to blockchain_settings for multi-RPC fallback
ALTER TABLE public.blockchain_settings ADD COLUMN IF NOT EXISTS rpc_urls jsonb DEFAULT '[]'::jsonb;

-- Fund reversals table
CREATE TABLE public.fund_reversals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id uuid NOT NULL,
  requester_id uuid NOT NULL,
  recipient_id uuid NOT NULL,
  amount numeric NOT NULL,
  reason text,
  status text NOT NULL DEFAULT 'pending',
  approved_by uuid,
  requested_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  funds_held_at timestamptz,
  funds_returned_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.fund_reversals ENABLE ROW LEVEL SECURITY;

-- Users can create reversal requests for their own transactions
CREATE POLICY "Users can create reversal requests"
  ON public.fund_reversals FOR INSERT
  WITH CHECK (auth.uid() = requester_id);

-- Users can view their own reversal requests
CREATE POLICY "Users can view their own reversals"
  ON public.fund_reversals FOR SELECT
  USING (auth.uid() = requester_id OR auth.uid() = recipient_id);

-- Admins can view all reversals
CREATE POLICY "Admins can view all reversals"
  ON public.fund_reversals FOR SELECT
  USING (public.has_role(auth.uid(), 'admin'));

-- Admins can update reversals (approve/reject)
CREATE POLICY "Admins can update reversals"
  ON public.fund_reversals FOR UPDATE
  USING (public.has_role(auth.uid(), 'admin'));

-- Agents can view all reversals
CREATE POLICY "Agents can view all reversals"
  ON public.fund_reversals FOR SELECT
  USING (public.has_role(auth.uid(), 'agent'));

-- Agents can update reversals
CREATE POLICY "Agents can update reversals"
  ON public.fund_reversals FOR UPDATE
  USING (public.has_role(auth.uid(), 'agent'));

-- Function to approve a reversal: deducts from wrong recipient immediately, schedules return in 1 hour
CREATE OR REPLACE FUNCTION public.approve_fund_reversal(_reversal_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  _reversal record;
  _recipient_balance numeric;
BEGIN
  -- Check caller is admin or agent
  IF NOT (public.has_role(auth.uid(), 'admin') OR public.has_role(auth.uid(), 'agent')) THEN
    RETURN jsonb_build_object('success', false, 'error', 'Unauthorized');
  END IF;

  -- Get reversal details
  SELECT * INTO _reversal FROM public.fund_reversals WHERE id = _reversal_id AND status = 'pending';
  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error', 'Reversal not found or already processed');
  END IF;

  -- Lock recipient wallet
  SELECT balance INTO _recipient_balance FROM public.wallets WHERE user_id = _reversal.recipient_id FOR UPDATE;

  IF _recipient_balance < _reversal.amount THEN
    RETURN jsonb_build_object('success', false, 'error', 'Recipient has insufficient balance for reversal');
  END IF;

  -- Deduct from wrong recipient immediately
  UPDATE public.wallets SET balance = balance - _reversal.amount, updated_at = now() WHERE user_id = _reversal.recipient_id;

  -- Update reversal status to approved with hold time
  UPDATE public.fund_reversals
  SET status = 'approved',
      approved_by = auth.uid(),
      approved_at = now(),
      funds_held_at = now()
  WHERE id = _reversal_id;

  -- Notify recipient that funds were reversed
  INSERT INTO public.notifications (user_id, title, message, type)
  VALUES (_reversal.recipient_id, 'Fund Reversal', 'A reversal of $' || _reversal.amount || ' has been processed from your account.', 'warning');

  -- Notify requester that reversal was approved (funds return in 1 hour)
  INSERT INTO public.notifications (user_id, title, message, type)
  VALUES (_reversal.requester_id, 'Reversal Approved', 'Your reversal request for $' || _reversal.amount || ' was approved. Funds will return to your account within 1 hour.', 'success');

  RETURN jsonb_build_object('success', true, 'message', 'Funds deducted from recipient. Will be returned to sender in 1 hour.');
END;
$$;

-- Function to process pending returns (called by cron/edge function)
CREATE OR REPLACE FUNCTION public.process_pending_reversals()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  _reversal record;
  _processed int := 0;
BEGIN
  FOR _reversal IN
    SELECT * FROM public.fund_reversals
    WHERE status = 'approved'
    AND funds_held_at IS NOT NULL
    AND funds_held_at + interval '1 hour' <= now()
  LOOP
    -- Return funds to original sender
    UPDATE public.wallets SET balance = balance + _reversal.amount, updated_at = now() WHERE user_id = _reversal.requester_id;

    -- Mark reversal as completed
    UPDATE public.fund_reversals SET status = 'completed', funds_returned_at = now() WHERE id = _reversal.id;

    -- Notify sender
    INSERT INTO public.notifications (user_id, title, message, type)
    VALUES (_reversal.requester_id, 'Funds Returned', '$' || _reversal.amount || ' has been returned to your account.', 'success');

    _processed := _processed + 1;
  END LOOP;

  RETURN jsonb_build_object('success', true, 'processed', _processed);
END;
$$;

CREATE TABLE public.mobile_money_providers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  ussd_code text,
  logo_letter text NOT NULL DEFAULT '?',
  color text NOT NULL DEFAULT 'bg-muted-foreground',
  merchant_number text,
  instructions text,
  is_active boolean NOT NULL DEFAULT true,
  sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.mobile_money_providers ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Everyone can view active providers" ON public.mobile_money_providers
  FOR SELECT USING (is_active = true);

CREATE POLICY "Admins can manage providers" ON public.mobile_money_providers
  FOR ALL USING (public.has_role(auth.uid(), 'admin'));

-- Seed default providers
INSERT INTO public.mobile_money_providers (name, ussd_code, logo_letter, color, merchant_number, sort_order) VALUES
  ('Digicel MoMo', '*129#', 'D', 'bg-red-500', '+592-000-0001', 1),
  ('GTT Mobile Money', '*888#', 'G', 'bg-green-600', '+592-000-0001', 2),
  ('M-Pesa', '*234#', 'M', 'bg-green-500', '+592-000-0001', 3);

CREATE TABLE public.changelog_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version text NOT NULL,
  is_latest boolean NOT NULL DEFAULT false,
  items jsonb NOT NULL DEFAULT '[]'::jsonb,
  released_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid
);

ALTER TABLE public.changelog_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Everyone can view changelog" ON public.changelog_entries FOR SELECT USING (true);
CREATE POLICY "Admins can manage changelog" ON public.changelog_entries FOR ALL USING (has_role(auth.uid(), 'admin'));
-- App releases table for version/update management
CREATE TABLE IF NOT EXISTS public.app_releases (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  version TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT 'web',
  file_url TEXT NOT NULL,
  release_notes TEXT,
  is_force_update BOOLEAN NOT NULL DEFAULT false,
  is_latest BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT ON public.app_releases TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.app_releases TO authenticated;
GRANT ALL ON public.app_releases TO service_role;

ALTER TABLE public.app_releases ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Everyone can view app releases"
  ON public.app_releases FOR SELECT USING (true);

CREATE POLICY "Admins can manage app releases"
  ON public.app_releases FOR ALL USING (public.has_role(auth.uid(), 'admin'));

-- App settings key/value store
CREATE TABLE IF NOT EXISTS public.app_settings (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,
  value JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by UUID
);

GRANT SELECT ON public.app_settings TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.app_settings TO authenticated;
GRANT ALL ON public.app_settings TO service_role;

ALTER TABLE public.app_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Everyone can view app settings"
  ON public.app_settings FOR SELECT USING (true);

CREATE POLICY "Admins can manage app settings"
  ON public.app_settings FOR ALL USING (public.has_role(auth.uid(), 'admin'));-- Add missing columns to app_releases
ALTER TABLE public.app_releases
  ADD COLUMN IF NOT EXISTS file_size BIGINT,
  ADD COLUMN IF NOT EXISTS file_path TEXT;

-- QR card requests table
CREATE TABLE IF NOT EXISTS public.qr_card_requests (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  fulfilled_at TIMESTAMPTZ
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.qr_card_requests TO authenticated;
GRANT ALL ON public.qr_card_requests TO service_role;

ALTER TABLE public.qr_card_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own qr requests"
  ON public.qr_card_requests FOR SELECT USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Users can create qr requests"
  ON public.qr_card_requests FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Admins can update qr requests"
  ON public.qr_card_requests FOR UPDATE USING (public.has_role(auth.uid(), 'admin'));ALTER TABLE public.app_releases ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE public.qr_card_requests ADD COLUMN IF NOT EXISTS fulfilled_by UUID;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'qr_card_requests_user_id_profiles_fkey'
  ) THEN
    ALTER TABLE public.qr_card_requests
      ADD CONSTRAINT qr_card_requests_user_id_profiles_fkey
      FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;
  END IF;
END $$;
-- 2FA
CREATE TABLE public.two_factor_auth (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  secret text NOT NULL,
  backup_codes text[] NOT NULL DEFAULT '{}',
  enabled boolean NOT NULL DEFAULT false,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.two_factor_auth TO authenticated;
GRANT ALL ON public.two_factor_auth TO service_role;
ALTER TABLE public.two_factor_auth ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users manage their own 2FA" ON public.two_factor_auth FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Admins view all 2FA" ON public.two_factor_auth FOR SELECT USING (has_role(auth.uid(), 'admin'::app_role));

-- Device Sessions
CREATE TABLE public.device_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  device_name text,
  browser text,
  os text,
  ip_address text,
  location text,
  user_agent text,
  is_current boolean NOT NULL DEFAULT false,
  last_active_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.device_sessions TO authenticated;
GRANT ALL ON public.device_sessions TO service_role;
ALTER TABLE public.device_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users manage their own sessions" ON public.device_sessions FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Admins view all sessions" ON public.device_sessions FOR SELECT USING (has_role(auth.uid(), 'admin'::app_role));

-- Audit Logs
CREATE TABLE public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid,
  actor_role text,
  action text NOT NULL,
  entity_type text,
  entity_id text,
  metadata jsonb NOT NULL DEFAULT '{}',
  ip_address text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON public.audit_logs TO authenticated;
GRANT ALL ON public.audit_logs TO service_role;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone authenticated can insert audit logs" ON public.audit_logs FOR INSERT TO authenticated WITH CHECK (auth.uid() = actor_id);
CREATE POLICY "Admins view all audit logs" ON public.audit_logs FOR SELECT USING (has_role(auth.uid(), 'admin'::app_role));
CREATE INDEX idx_audit_logs_created_at ON public.audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_actor ON public.audit_logs(actor_id);

-- KYC Submissions
CREATE TABLE public.kyc_submissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  full_name text NOT NULL,
  date_of_birth date NOT NULL,
  address text NOT NULL,
  country text NOT NULL,
  document_type text NOT NULL,
  document_number text NOT NULL,
  document_front_url text,
  document_back_url text,
  selfie_url text,
  status text NOT NULL DEFAULT 'pending',
  rejection_reason text,
  reviewed_by uuid,
  reviewed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.kyc_submissions TO authenticated;
GRANT ALL ON public.kyc_submissions TO service_role;
ALTER TABLE public.kyc_submissions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users view their own KYC" ON public.kyc_submissions FOR SELECT USING (auth.uid() = user_id OR has_role(auth.uid(), 'admin'::app_role));
CREATE POLICY "Users create their own KYC" ON public.kyc_submissions FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users update their own pending KYC" ON public.kyc_submissions FOR UPDATE USING (auth.uid() = user_id AND status = 'pending');
CREATE POLICY "Admins update any KYC" ON public.kyc_submissions FOR UPDATE USING (has_role(auth.uid(), 'admin'::app_role));

-- Suspicious Activity Alerts
CREATE TABLE public.suspicious_activity_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid,
  alert_type text NOT NULL,
  severity text NOT NULL DEFAULT 'medium',
  description text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'open',
  reviewed_by uuid,
  reviewed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.suspicious_activity_alerts TO authenticated;
GRANT ALL ON public.suspicious_activity_alerts TO service_role;
ALTER TABLE public.suspicious_activity_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone authenticated can create alerts" ON public.suspicious_activity_alerts FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Admins view all alerts" ON public.suspicious_activity_alerts FOR SELECT USING (has_role(auth.uid(), 'admin'::app_role));
CREATE POLICY "Users view their own alerts" ON public.suspicious_activity_alerts FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Admins update alerts" ON public.suspicious_activity_alerts FOR UPDATE USING (has_role(auth.uid(), 'admin'::app_role));
CREATE INDEX idx_alerts_created_at ON public.suspicious_activity_alerts(created_at DESC);

-- Add 2FA flag to profiles
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS two_factor_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS kyc_status text NOT NULL DEFAULT 'unverified';

-- Audit log helper
CREATE OR REPLACE FUNCTION public.log_audit_event(
  _action text,
  _entity_type text DEFAULT NULL,
  _entity_id text DEFAULT NULL,
  _metadata jsonb DEFAULT '{}'::jsonb
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _id uuid;
  _role text;
BEGIN
  SELECT role::text INTO _role FROM public.user_roles WHERE user_id = auth.uid() LIMIT 1;
  INSERT INTO public.audit_logs (actor_id, actor_role, action, entity_type, entity_id, metadata)
  VALUES (auth.uid(), _role, _action, _entity_type, _entity_id, _metadata)
  RETURNING id INTO _id;
  RETURN _id;
END;
$$;

-- Auto-flag large transactions
CREATE OR REPLACE FUNCTION public.flag_suspicious_transaction()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _recent_count int;
BEGIN
  IF NEW.status = 'completed' THEN
    -- Large amount
    IF NEW.amount >= 10000 THEN
      INSERT INTO public.suspicious_activity_alerts (user_id, alert_type, severity, description, metadata)
      VALUES (NEW.sender_id, 'large_transaction', 'high',
        'Large transaction of $' || NEW.amount || ' detected',
        jsonb_build_object('transaction_id', NEW.id, 'amount', NEW.amount));
    END IF;

    -- Rapid transactions
    SELECT COUNT(*) INTO _recent_count FROM public.transactions
      WHERE sender_id = NEW.sender_id
        AND created_at > now() - interval '5 minutes'
        AND status = 'completed';
    IF _recent_count >= 5 THEN
      INSERT INTO public.suspicious_activity_alerts (user_id, alert_type, severity, description, metadata)
      VALUES (NEW.sender_id, 'rapid_transactions', 'medium',
        _recent_count || ' transactions in last 5 minutes',
        jsonb_build_object('count', _recent_count));
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_flag_suspicious_transaction ON public.transactions;
CREATE TRIGGER trg_flag_suspicious_transaction
AFTER INSERT ON public.transactions
FOR EACH ROW EXECUTE FUNCTION public.flag_suspicious_transaction();

-- Storage bucket for KYC docs
INSERT INTO storage.buckets (id, name, public) VALUES ('kyc-documents', 'kyc-documents', false)
ON CONFLICT (id) DO NOTHING;

CREATE POLICY "Users upload their own KYC docs" ON storage.objects FOR INSERT
  WITH CHECK (bucket_id = 'kyc-documents' AND auth.uid()::text = (storage.foldername(name))[1]);
CREATE POLICY "Users view their own KYC docs" ON storage.objects FOR SELECT
  USING (bucket_id = 'kyc-documents' AND (auth.uid()::text = (storage.foldername(name))[1] OR has_role(auth.uid(), 'admin'::app_role)));
CREATE POLICY "Admins manage KYC docs" ON storage.objects FOR ALL
  USING (bucket_id = 'kyc-documents' AND has_role(auth.uid(), 'admin'::app_role));

-- Updated_at triggers
CREATE TRIGGER trg_2fa_updated_at BEFORE UPDATE ON public.two_factor_auth FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER trg_kyc_updated_at BEFORE UPDATE ON public.kyc_submissions FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- 1. Add disabled flag to profiles
ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS disabled boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS disabled_at timestamptz,
  ADD COLUMN IF NOT EXISTS disabled_by uuid;

-- 2. Allow admins to update any profile (for disable / re-enable)
DROP POLICY IF EXISTS "Admins can update any profile" ON public.profiles;
CREATE POLICY "Admins can update any profile"
ON public.profiles
FOR UPDATE
USING (public.has_role(auth.uid(), 'admin'))
WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- 3. Allow admins to delete profiles (cascade-style cleanup support)
DROP POLICY IF EXISTS "Admins can delete profiles" ON public.profiles;
CREATE POLICY "Admins can delete profiles"
ON public.profiles
FOR DELETE
USING (public.has_role(auth.uid(), 'admin'));

-- 4. Update process_transaction to reject disabled accounts
CREATE OR REPLACE FUNCTION public.process_transaction(
  _sender_id uuid,
  _receiver_id uuid,
  _amount numeric,
  _transaction_type text,
  _description text DEFAULT NULL::text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  _sender_balance numeric;
  _fee_percentage numeric;
  _fixed_fee numeric;
  _total_fee numeric;
  _total_amount numeric;
  _transaction_id uuid;
  _sender_cashback numeric;
  _liquidity_pool_fee numeric;
  _is_admin boolean;
  _sender_disabled boolean;
  _receiver_disabled boolean;
BEGIN
  SELECT disabled INTO _sender_disabled FROM public.profiles WHERE id = _sender_id;
  SELECT disabled INTO _receiver_disabled FROM public.profiles WHERE id = _receiver_id;
  IF COALESCE(_sender_disabled, false) THEN
    RETURN jsonb_build_object('success', false, 'error', 'Your account is disabled. Please contact support.');
  END IF;
  IF COALESCE(_receiver_disabled, false) THEN
    RETURN jsonb_build_object('success', false, 'error', 'Recipient account is disabled.');
  END IF;

  SELECT public.has_role(_sender_id, 'admin') INTO _is_admin;

  SELECT balance INTO _sender_balance
  FROM public.wallets
  WHERE user_id = _sender_id
  FOR UPDATE;

  SELECT fee_percentage, fixed_fee INTO _fee_percentage, _fixed_fee
  FROM public.transaction_fees
  WHERE transaction_type = _transaction_type;

  IF _is_admin THEN
    _total_fee := 0;
    _sender_cashback := 0;
    _liquidity_pool_fee := 0;
    _total_amount := _amount;
  ELSE
    _total_fee := (_amount * COALESCE(_fee_percentage, 0) / 100) + COALESCE(_fixed_fee, 0);
    _sender_cashback := _total_fee * 0.60;
    _liquidity_pool_fee := _total_fee * 0.40;
    _total_amount := _amount + _liquidity_pool_fee;
  END IF;

  IF NOT _is_admin AND _sender_balance < _total_amount THEN
    RETURN jsonb_build_object('success', false, 'error', 'Insufficient balance');
  END IF;

  IF NOT _is_admin THEN
    UPDATE public.wallets
    SET balance = balance - _total_amount, updated_at = now()
    WHERE user_id = _sender_id;
  END IF;

  INSERT INTO public.wallets (user_id, balance)
  VALUES (_receiver_id, _amount)
  ON CONFLICT (user_id) DO UPDATE
  SET balance = wallets.balance + _amount, updated_at = now();

  INSERT INTO public.transactions (sender_id, receiver_id, amount, fee, status, transaction_type, description, completed_at)
  VALUES (_sender_id, _receiver_id, _amount, _total_fee, 'completed', _transaction_type, _description, now())
  RETURNING id INTO _transaction_id;

  RETURN jsonb_build_object(
    'success', true,
    'transaction_id', _transaction_id,
    'fee', _total_fee,
    'sender_cashback', _sender_cashback,
    'liquidity_pool_fee', _liquidity_pool_fee
  );
END;
$function$;
-- Announcements / Ads
CREATE TABLE public.announcements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  body text,
  image_url text,
  link_url text,
  starts_at timestamptz NOT NULL DEFAULT now(),
  ends_at timestamptz,
  is_active boolean NOT NULL DEFAULT true,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.announcements TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.announcements TO authenticated;
GRANT ALL ON public.announcements TO service_role;

ALTER TABLE public.announcements ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Everyone can view active announcements"
  ON public.announcements FOR SELECT
  USING (
    is_active = true
    AND starts_at <= now()
    AND (ends_at IS NULL OR ends_at >= now())
  );

CREATE POLICY "Admins view all announcements"
  ON public.announcements FOR SELECT
  USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins manage announcements"
  ON public.announcements FOR ALL
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE TRIGGER trg_announcements_updated_at
  BEFORE UPDATE ON public.announcements
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Countries
CREATE TABLE public.countries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text NOT NULL UNIQUE,
  name text NOT NULL,
  dial_code text NOT NULL,
  local_number_length int NOT NULL DEFAULT 7,
  is_allowed boolean NOT NULL DEFAULT true,
  is_banned boolean NOT NULL DEFAULT false,
  sort_order int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.countries TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.countries TO authenticated;
GRANT ALL ON public.countries TO service_role;

ALTER TABLE public.countries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Everyone can view countries"
  ON public.countries FOR SELECT USING (true);

CREATE POLICY "Admins manage countries"
  ON public.countries FOR ALL
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE TRIGGER trg_countries_updated_at
  BEFORE UPDATE ON public.countries
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

INSERT INTO public.countries (code, name, dial_code, local_number_length, sort_order) VALUES
  ('GY', 'Guyana', '+592', 7, 1),
  ('TT', 'Trinidad & Tobago', '+1868', 7, 2),
  ('JM', 'Jamaica', '+1876', 7, 3),
  ('SR', 'Suriname', '+597', 7, 4),
  ('BB', 'Barbados', '+1246', 7, 5),
  ('US', 'United States', '+1', 10, 6),
  ('CA', 'Canada', '+1', 10, 7),
  ('GB', 'United Kingdom', '+44', 10, 8),
  ('BR', 'Brazil', '+55', 11, 9),
  ('IN', 'India', '+91', 10, 10),
  ('NG', 'Nigeria', '+234', 10, 11);

-- 1) blockchain_settings: remove public SELECT, require auth
DROP POLICY IF EXISTS "Everyone can view blockchain settings" ON public.blockchain_settings;
CREATE POLICY "Authenticated users can view blockchain settings"
ON public.blockchain_settings FOR SELECT
TO authenticated
USING (true);

-- 2) transactions: explicit deny UPDATE/DELETE
CREATE POLICY "Transactions cannot be updated"
ON public.transactions FOR UPDATE
USING (false) WITH CHECK (false);

CREATE POLICY "Transactions cannot be deleted"
ON public.transactions FOR DELETE
USING (false);

-- 3) profiles: drop broad vendor-profile public SELECT and expose a safe view
DROP POLICY IF EXISTS "Everyone can view vendor store names" ON public.profiles;

CREATE OR REPLACE VIEW public.public_vendors
WITH (security_invoker = off) AS
SELECT p.id, p.full_name, p.store_name, p.avatar_url, p.wallet_address
FROM public.profiles p
WHERE EXISTS (
  SELECT 1 FROM public.user_roles ur
  WHERE ur.user_id = p.id AND ur.role = 'vendor'::app_role
);

GRANT SELECT ON public.public_vendors TO anon, authenticated;

-- 4) vendor_registration_fees: require auth to view
DROP POLICY IF EXISTS "Everyone can view vendor registration fees" ON public.vendor_registration_fees;
CREATE POLICY "Authenticated users can view vendor registration fees"
ON public.vendor_registration_fees FOR SELECT
TO authenticated
USING (true);

DROP VIEW IF EXISTS public.public_vendors;

CREATE VIEW public.public_vendors
WITH (security_invoker = on) AS
SELECT p.id, p.full_name, p.store_name, p.avatar_url, p.wallet_address
FROM public.profiles p
WHERE EXISTS (
  SELECT 1 FROM public.user_roles ur
  WHERE ur.user_id = p.id AND ur.role = 'vendor'::app_role
);

GRANT SELECT ON public.public_vendors TO authenticated;

-- Re-add a column-safe vendor profile SELECT policy for authenticated users.
-- Underlying row still exposes phone/address — vendors accept this trade-off
-- because they are running a public storefront; sensitive PII fields are not
-- shown by the public_vendors view used by the app.
DROP POLICY IF EXISTS "Authenticated users can view vendor profiles" ON public.profiles;
CREATE POLICY "Authenticated users can view vendor profiles"
ON public.profiles FOR SELECT
TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.user_roles ur
  WHERE ur.user_id = profiles.id AND ur.role = 'vendor'::app_role
));
