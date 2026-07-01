


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE EXTENSION IF NOT EXISTS "pg_cron" WITH SCHEMA "pg_catalog";






CREATE EXTENSION IF NOT EXISTS "pg_net" WITH SCHEMA "extensions";






COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pg_trgm" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE TYPE "public"."app_role" AS ENUM (
    'worker',
    'manager',
    'admin',
    'cjb_manager',
    'super_admin'
);


ALTER TYPE "public"."app_role" OWNER TO "postgres";


CREATE TYPE "public"."cost_invoice_status" AS ENUM (
    'pending_review',
    'reviewed',
    'rejected'
);


ALTER TYPE "public"."cost_invoice_status" OWNER TO "postgres";


CREATE TYPE "public"."cost_vat_treatment" AS ENUM (
    'standard_20',
    'reverse_charge',
    'zero_rated',
    'exempt',
    'unknown',
    'no_vat'
);


ALTER TYPE "public"."cost_vat_treatment" OWNER TO "postgres";


CREATE TYPE "public"."holiday_status" AS ENUM (
    'pending',
    'approved',
    'rejected'
);


ALTER TYPE "public"."holiday_status" OWNER TO "postgres";


CREATE TYPE "public"."invoice_vat_mode" AS ENUM (
    'reverse_charge',
    'add_vat'
);


ALTER TYPE "public"."invoice_vat_mode" OWNER TO "postgres";


CREATE TYPE "public"."permits_answer" AS ENUM (
    'yes',
    'no',
    'na'
);


ALTER TYPE "public"."permits_answer" OWNER TO "postgres";


CREATE TYPE "public"."submission_kind" AS ENUM (
    'plant_inspection',
    'vehicle_defect',
    'havs_log',
    'starter',
    'timesheet',
    'rams_briefing',
    'toolbox_talk',
    'daily_briefing'
);


ALTER TYPE "public"."submission_kind" OWNER TO "postgres";


CREATE TYPE "public"."submission_status" AS ENUM (
    'submitted',
    'approved',
    'rejected'
);


ALTER TYPE "public"."submission_status" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_set_vault_secret"("p_name" "text", "p_value" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_id uuid;
begin
  select id into v_id from vault.secrets where name = p_name;
  if v_id is null then
    perform vault.create_secret(p_value, p_name);
  else
    perform vault.update_secret(v_id, p_value);
  end if;
end;
$$;


ALTER FUNCTION "public"."admin_set_vault_secret"("p_name" "text", "p_value" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."bump_revision"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Only bump when this UPDATE is the top-level statement.
  -- pg_trigger_depth() > 1 means we're inside another trigger's cascading UPDATE
  -- (e.g. timesheet_days_touch_parent bumping approved_at), which shouldn't count
  -- as a user edit.
  IF pg_trigger_depth() > 1 THEN
    RETURN NEW;
  END IF;
  NEW.revision := COALESCE(OLD.revision, 1) + 1;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."bump_revision"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select case _kind
    when 'plant_inspection' then exists (select 1 from public.plant_inspections p where p.id = _submission_id and (p.worker_id = auth.uid() or public.is_staff(auth.uid())))
    when 'vehicle_defect' then exists (select 1 from public.vehicle_defects v where v.id = _submission_id and (v.worker_id = auth.uid() or public.is_staff(auth.uid())))
    when 'timesheet' then exists (select 1 from public.timesheets t where t.id = _submission_id and (t.worker_id = auth.uid() or public.is_staff(auth.uid())))
    when 'rams_briefing' then exists (select 1 from public.rams_briefings r where r.id = _submission_id and (r.briefer_id = auth.uid() or public.is_staff(auth.uid())))
    when 'starter' then exists (select 1 from public.employee_starters s where s.id = _submission_id and (s.user_id = auth.uid() or public.is_staff(auth.uid())))
    when 'havs_log' then exists (select 1 from public.havs_logs h where h.id = _submission_id and (h.worker_id = auth.uid() or public.is_staff(auth.uid())))
    when 'toolbox_talk' then exists (select 1 from public.toolbox_talks t where t.id = _submission_id and (t.briefer_id = auth.uid() or public.is_staff(auth.uid())))
    when 'daily_briefing' then exists (select 1 from public.daily_briefings d where d.id = _submission_id and (d.briefer_id = auth.uid() or public.is_staff(auth.uid())))
  end
$$;


ALTER FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT
    public.has_role(auth.uid(), 'admin')
    OR _worker_id = auth.uid()
    OR (
      public.has_role(auth.uid(), 'manager')
      AND public.user_subcontractor(auth.uid()) IS NOT NULL
      AND public.user_subcontractor(auth.uid()) = public.user_subcontractor(_worker_id)
    )
$$;


ALTER FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."company_match_key"("p_name" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $_$
  SELECT regexp_replace(
    regexp_replace(
      lower(
        regexp_replace(
          regexp_replace(
            regexp_replace(coalesce(p_name, ''), '\s+t\s*/?\s*a\s.*$', '', 'i'),
            '\s+trading\s+as\s.*$', '', 'i'
          ),
          '\(.*$', ''
        )
      ),
      '\ylimited\y', 'ltd', 'g'
    ),
    '[^a-z0-9]', '', 'g'
  )
$_$;


ALTER FUNCTION "public"."company_match_key"("p_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."continue_cost_scan"("p_url" "text", "p_apikey" "text") RETURNS bigint
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'net'
    AS $$
BEGIN
  -- Service-role / internal only (no end-user JWT).
  IF auth.uid() IS NOT NULL THEN
    RAISE EXCEPTION 'Not allowed to continue cost scan';
  END IF;
  IF position('/api/public/hooks/scan-costs-inbox' IN p_url) = 0 THEN
    RAISE EXCEPTION 'Invalid scan target URL';
  END IF;
  RETURN net.http_post(
    url := p_url,
    headers := jsonb_build_object('Content-Type', 'application/json', 'apikey', p_apikey),
    body := '{}'::jsonb,
    timeout_milliseconds := 120000
  );
END;
$$;


ALTER FUNCTION "public"."continue_cost_scan"("p_url" "text", "p_apikey" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoices_apply_canonical_company"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF NEW.company_name IS NOT NULL
     AND btrim(NEW.company_name) <> ''
     AND upper(btrim(NEW.company_name)) <> 'NA' THEN
    NEW.company_name := public.resolve_cost_company_canonical(NEW.company_name);
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."cost_invoices_apply_canonical_company"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."daily_briefing_autoapprove"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."daily_briefing_autoapprove"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_integration_secret"("p_name" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF NOT public.has_role(auth.uid(), 'super_admin') THEN
    RAISE EXCEPTION 'Only a super admin can delete integration secrets';
  END IF;
  DELETE FROM vault.secrets WHERE name = p_name;
END;
$$;


ALTER FUNCTION "public"."delete_integration_secret"("p_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."email_domain"("p_from" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $_$
  SELECT CASE
    WHEN p_from IS NULL OR position('@' in p_from) = 0 THEN NULL
    ELSE lower(btrim(regexp_replace(regexp_replace(p_from, '^.*@', ''), '[>"''\s;,]+$', '')))
  END
$_$;


ALTER FUNCTION "public"."email_domain"("p_from" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."force_approved_status"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.status := 'approved';
  IF NEW.approved_at IS NULL THEN NEW.approved_at := now(); END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."force_approved_status"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_integration_secret"("p_name" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_val text;
BEGIN
  -- Trusted server (service role, auth.uid() IS NULL) may always read.
  -- A signed-in end user may only read if they are a super admin.
  IF auth.uid() IS NOT NULL AND NOT public.has_role(auth.uid(), 'super_admin') THEN
    RAISE EXCEPTION 'Only a super admin can read integration secrets';
  END IF;
  SELECT decrypted_secret INTO v_val
    FROM vault.decrypted_secrets WHERE name = p_name;
  RETURN v_val;
END;
$$;


ALTER FUNCTION "public"."get_integration_secret"("p_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_username text;
  v_full_name text;
  v_other_count int;
begin
  v_username := coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1));
  v_full_name := coalesce(new.raw_user_meta_data->>'full_name', v_username);
  insert into public.profiles (id, username, full_name)
  values (new.id, v_username, v_full_name)
  on conflict (id) do nothing;
  insert into public.user_roles (user_id, role) values (new.id, 'worker')
  on conflict do nothing;

  -- Auto-assign new user to every project where all other existing users are already assigned.
  select count(*) into v_other_count from public.profiles where id <> new.id;
  if v_other_count > 0 then
    insert into public.project_assignments (project_id, user_id, assigned_by)
    select p.id, new.id, null
    from public.projects p
    where p.archived_at is null
      and (
        select count(distinct pa.user_id)
        from public.project_assignments pa
        where pa.project_id = p.id
          and pa.user_id <> new.id
      ) >= v_other_count
    on conflict (project_id, user_id) do nothing;
  end if;

  return new;
end;
$$;


ALTER FUNCTION "public"."handle_new_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select exists (
    select 1 from public.user_roles
    where user_id = _user_id
      and (role = _role or (role = 'super_admin' and _role = 'admin'))
  )
$$;


ALTER FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."havs_autoapprove"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$ BEGIN RETURN NEW; END; $$;


ALTER FUNCTION "public"."havs_autoapprove"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."holidays_amend_resets_status"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_changed boolean;
BEGIN
  v_changed := (NEW.start_date IS DISTINCT FROM OLD.start_date)
            OR (NEW.end_date   IS DISTINCT FROM OLD.end_date)
            OR (NEW.note       IS DISTINCT FROM OLD.note);

  IF NOT v_changed THEN
    RETURN NEW;
  END IF;

  -- Only admin-owned holidays remain auto-approved after an edit.
  IF public.has_role(NEW.user_id, 'admin') THEN
    NEW.status := 'approved';
    NEW.approved_at := now();
    NEW.approved_by := COALESCE(auth.uid(), NEW.user_id);
    NEW.rejection_reason := NULL;
    RETURN NEW;
  END IF;

  -- Every worker/manager/cjb_manager holiday edit goes back for approval.
  NEW.status := 'pending';
  NEW.approved_at := NULL;
  NEW.approved_by := NULL;
  NEW.rejection_reason := NULL;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."holidays_amend_resets_status"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."holidays_autoapprove"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Only holidays belonging to admins auto-approve automatically.
  IF public.has_role(NEW.user_id, 'admin') THEN
    NEW.status := 'approved';
    NEW.approved_at := COALESCE(NEW.approved_at, now());
    NEW.approved_by := COALESCE(NEW.approved_by, NEW.user_id);
    NEW.rejection_reason := NULL;
  ELSE
    NEW.status := 'pending';
    NEW.approved_at := NULL;
    NEW.approved_by := NULL;
    NEW.rejection_reason := NULL;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."holidays_autoapprove"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."holidays_enforce_status_change"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    -- A holiday amendment may reset the request back to pending.
    IF NEW.status = 'pending'
       AND (
         OLD.user_id = auth.uid()
         OR public.has_role(auth.uid(), 'admin')
         OR (
           public.has_role(auth.uid(), 'manager')
           AND NOT public.is_staff(OLD.user_id)
           AND public.user_subcontractor(auth.uid()) IS NOT NULL
           AND public.user_subcontractor(auth.uid()) = public.user_subcontractor(OLD.user_id)
         )
       ) THEN
      NEW.approved_by := NULL;
      NEW.approved_at := NULL;
      NEW.rejection_reason := NULL;
    ELSIF public.has_role(auth.uid(), 'admin') THEN
      NEW.approved_by := auth.uid();
      NEW.approved_at := now();
      IF NEW.status = 'approved' THEN
        NEW.rejection_reason := NULL;
      END IF;
    ELSIF public.has_role(auth.uid(), 'manager')
          AND NOT public.is_staff(OLD.user_id)
          AND public.user_subcontractor(auth.uid()) IS NOT NULL
          AND public.user_subcontractor(auth.uid()) = public.user_subcontractor(OLD.user_id) THEN
      NEW.approved_by := auth.uid();
      NEW.approved_at := now();
      IF NEW.status = 'approved' THEN
        NEW.rejection_reason := NULL;
      END IF;
    ELSE
      RAISE EXCEPTION 'Not allowed to change holiday status';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."holidays_enforce_status_change"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."invoices_before_insert"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_name text;
  v_addr text;
BEGIN
  IF NEW.invoice_number < 593 THEN
    RAISE EXCEPTION 'Invoice number must be >= 593';
  END IF;
  IF NEW.client_id IS NOT NULL
     AND (NEW.client_name_snapshot IS NULL OR NEW.client_name_snapshot = ''
       OR NEW.client_address_snapshot IS NULL OR NEW.client_address_snapshot = '') THEN
    SELECT name, address INTO v_name, v_addr FROM public.invoice_clients WHERE id = NEW.client_id;
    IF NEW.client_name_snapshot IS NULL OR NEW.client_name_snapshot = '' THEN
      NEW.client_name_snapshot := COALESCE(v_name, '');
    END IF;
    IF NEW.client_address_snapshot IS NULL OR NEW.client_address_snapshot = '' THEN
      NEW.client_address_snapshot := COALESCE(v_addr, '');
    END IF;
  END IF;
  IF NEW.created_by IS NULL THEN
    NEW.created_by := auth.uid();
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."invoices_before_insert"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.project_assignments
    WHERE project_id = _project_id AND user_id = _user_id
  )
$$;


ALTER FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_generic_email_domain"("p_domain" "text") RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT lower(coalesce(p_domain, '')) IN (
    'gmail.com','googlemail.com','outlook.com','hotmail.com','hotmail.co.uk',
    'live.com','live.co.uk','yahoo.com','yahoo.co.uk','ymail.com','icloud.com',
    'me.com','aol.com','msn.com','protonmail.com','proton.me','gmx.com','mail.com'
  )
$$;


ALTER FUNCTION "public"."is_generic_email_domain"("p_domain" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1
    FROM unnest(ARRAY[
      'causeway.com','basware.com','tungsten-network.com','tungstennetwork.com',
      'coupahost.com','coupamail.com','ariba.com','sap.com','transactionnetwork.com'
    ]) AS d
    WHERE lower(coalesce(p_domain, '')) = d
       OR lower(coalesce(p_domain, '')) LIKE '%.' || d
  )
$$;


ALTER FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_staff"("_user_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id
      AND role IN ('manager','admin','cjb_manager','super_admin')
  )
$$;


ALTER FUNCTION "public"."is_staff"("_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."match_subcontractor_by_company"("p_company" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
DECLARE
  v_key text;
  v_id uuid;
BEGIN
  IF p_company IS NULL OR btrim(p_company) = '' OR upper(btrim(p_company)) = 'NA' THEN
    RETURN NULL;
  END IF;
  v_key := public.company_match_key(p_company);
  IF v_key IS NULL OR v_key = '' THEN
    RETURN NULL;
  END IF;

  -- Exact normalised key wins.
  SELECT s.id
    INTO v_id
    FROM public.subcontractors s
    WHERE COALESCE(s.active, true) = true
      AND public.company_match_key(s.name) = v_key
    LIMIT 1;
  IF v_id IS NOT NULL THEN
    RETURN v_id;
  END IF;

  -- Fuzzy fallback against every active subcontractor name.
  SELECT s.id
    INTO v_id
    FROM public.subcontractors s
    WHERE COALESCE(s.active, true) = true
      AND public.company_match_key(s.name) <> ''
      AND similarity(public.company_match_key(s.name), v_key) >= 0.6
    ORDER BY similarity(public.company_match_key(s.name), v_key) DESC,
             char_length(public.company_match_key(s.name)) ASC
    LIMIT 1;

  RETURN v_id;
END;
$$;


ALTER FUNCTION "public"."match_subcontractor_by_company"("p_company" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select case _kind
    when 'plant_inspection' then exists (select 1 from public.plant_inspections p where p.id = _submission_id and p.worker_id = auth.uid())
    when 'vehicle_defect' then exists (select 1 from public.vehicle_defects v where v.id = _submission_id and v.worker_id = auth.uid())
    when 'timesheet' then exists (select 1 from public.timesheets t where t.id = _submission_id and t.worker_id = auth.uid())
    when 'rams_briefing' then exists (select 1 from public.rams_briefings r where r.id = _submission_id and r.briefer_id = auth.uid())
    when 'starter' then exists (select 1 from public.employee_starters s where s.id = _submission_id and s.user_id = auth.uid())
    when 'havs_log' then exists (select 1 from public.havs_logs h where h.id = _submission_id and h.worker_id = auth.uid())
    when 'toolbox_talk' then exists (select 1 from public.toolbox_talks t where t.id = _submission_id and t.briefer_id = auth.uid())
    when 'daily_briefing' then exists (select 1 from public.daily_briefings d where d.id = _submission_id and d.briefer_id = auth.uid())
  end
$$;


ALTER FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."profiles_guard_sensitive_self_update"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Allow service-role / internal callers (auth.uid() IS NULL) and admins to
  -- change any column. Everyone else cannot modify privilege-sensitive fields.
  IF auth.uid() IS NOT NULL AND NOT public.has_role(auth.uid(), 'admin') THEN
    NEW.subcontractor_id := OLD.subcontractor_id;
    NEW.must_reset_password := OLD.must_reset_password;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."profiles_guard_sensitive_self_update"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_cost_company_canonical"("p_name" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
DECLARE
  v_key text;
  v_canon text;
  v_match_canon text;
BEGIN
  IF p_name IS NULL OR btrim(p_name) = '' OR upper(btrim(p_name)) = 'NA' THEN
    RETURN p_name;
  END IF;
  v_key := public.company_match_key(p_name);
  IF v_key IS NULL OR v_key = '' THEN
    RETURN p_name;
  END IF;

  -- 1) Exact (normalised) key wins — fast path for known suppliers.
  SELECT canonical_name INTO v_canon FROM public.cost_company_aliases WHERE match_key = v_key;
  IF v_canon IS NOT NULL THEN
    RETURN v_canon;
  END IF;

  -- 2) Fuzzy fallback: check the new name against every existing supplier and
  --    reuse the closest one. The 0.62 threshold sits in the safe gap between
  --    genuinely different suppliers (observed max ~0.51) and real spelling
  --    variants of the same supplier (~0.72+).
  SELECT canonical_name
    INTO v_match_canon
    FROM public.cost_company_aliases
    WHERE similarity(match_key, v_key) >= 0.62
    ORDER BY similarity(match_key, v_key) DESC, char_length(match_key) ASC
    LIMIT 1;

  IF v_match_canon IS NOT NULL THEN
    INSERT INTO public.cost_company_aliases (match_key, canonical_name)
    VALUES (v_key, v_match_canon)
    ON CONFLICT (match_key) DO NOTHING;
    RETURN v_match_canon;
  END IF;

  -- 3) No confident match: record as a new supplier (first name wins).
  INSERT INTO public.cost_company_aliases (match_key, canonical_name)
  VALUES (v_key, btrim(p_name))
  ON CONFLICT (match_key) DO NOTHING;
  SELECT canonical_name INTO v_canon FROM public.cost_company_aliases WHERE match_key = v_key;
  RETURN coalesce(v_canon, btrim(p_name));
END;
$$;


ALTER FUNCTION "public"."resolve_cost_company_canonical"("p_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
DECLARE
  v_domain text;
  v_count int;
  v_canon text;
  v_resolved text;
  v_trusted boolean;
BEGIN
  v_domain := public.email_domain(p_from);
  v_trusted := v_domain IS NOT NULL AND v_domain <> ''
    AND NOT public.is_generic_email_domain(v_domain)
    AND NOT public.is_shared_invoice_portal_domain(v_domain);

  -- 1) Sender-domain identity: use it only if the domain maps to exactly one
  --    known canonical supplier. Reconcile the domain-derived name through the
  --    name-based canonicaliser so it matches EXACTLY what the insert trigger
  --    (cost_invoices_apply_canonical_company) will store on the row. Without
  --    this the file could be filed under the domain name while the table row
  --    shows the name-based canonical (e.g. "…Limited" vs "…Ltd").
  IF v_trusted THEN
    SELECT count(DISTINCT canonical_name), min(canonical_name)
      INTO v_count, v_canon
      FROM public.cost_company_domain_aliases
      WHERE domain = v_domain;
    IF v_count = 1 THEN
      RETURN public.resolve_cost_company_canonical(v_canon);
    END IF;
  END IF;

  -- 2) Fall back to name-based resolution (exact key, fuzzy >= 0.62, else new).
  v_resolved := public.resolve_cost_company_canonical(p_name);

  -- 3) Learn the domain -> canonical pairing for trusted domains so future
  --    invoices from this sender stay consistent regardless of printed name.
  IF v_trusted AND v_resolved IS NOT NULL
     AND btrim(v_resolved) <> '' AND upper(btrim(v_resolved)) <> 'NA' THEN
    INSERT INTO public.cost_company_domain_aliases (domain, canonical_name)
    VALUES (v_domain, btrim(v_resolved))
    ON CONFLICT (domain, canonical_name) DO NOTHING;
  END IF;

  RETURN v_resolved;
END;
$$;


ALTER FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."rls_auto_enable"() RETURNS "event_trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog'
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN
    SELECT *
    FROM pg_event_trigger_ddl_commands()
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
      AND object_type IN ('table','partitioned table')
  LOOP
     IF cmd.schema_name IS NOT NULL AND cmd.schema_name IN ('public') AND cmd.schema_name NOT IN ('pg_catalog','information_schema') AND cmd.schema_name NOT LIKE 'pg_toast%' AND cmd.schema_name NOT LIKE 'pg_temp%' THEN
      BEGIN
        EXECUTE format('alter table if exists %s enable row level security', cmd.object_identity);
        RAISE LOG 'rls_auto_enable: enabled RLS on %', cmd.object_identity;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE LOG 'rls_auto_enable: failed to enable RLS on %', cmd.object_identity;
      END;
     ELSE
        RAISE LOG 'rls_auto_enable: skip % (either system schema or not in enforced list: %.)', cmd.object_identity, cmd.schema_name;
     END IF;
  END LOOP;
END;
$$;


ALTER FUNCTION "public"."rls_auto_enable"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_id uuid;
BEGIN
  IF NOT public.has_role(auth.uid(), 'super_admin') THEN
    RAISE EXCEPTION 'Only a super admin can set integration secrets';
  END IF;
  IF p_name IS NULL OR btrim(p_name) = '' THEN
    RAISE EXCEPTION 'Secret name required';
  END IF;
  SELECT id INTO v_id FROM vault.secrets WHERE name = p_name;
  IF v_id IS NULL THEN
    PERFORM vault.create_secret(p_value, p_name);
  ELSE
    PERFORM vault.update_secret(v_id, p_value);
  END IF;
END;
$$;


ALTER FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END $$;


ALTER FUNCTION "public"."set_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_updated_at_havs_tools"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;


ALTER FUNCTION "public"."set_updated_at_havs_tools"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") RETURNS "uuid"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select case _kind
    when 'plant_inspection' then (select worker_id from public.plant_inspections where id = _id)
    when 'vehicle_defect' then (select worker_id from public.vehicle_defects where id = _id)
    when 'timesheet' then (select worker_id from public.timesheets where id = _id)
    when 'rams_briefing' then (select briefer_id from public.rams_briefings where id = _id)
    when 'starter' then (select user_id from public.employee_starters where id = _id)
    when 'havs_log' then (select worker_id from public.havs_logs where id = _id)
    when 'toolbox_talk' then (select briefer_id from public.toolbox_talks where id = _id)
    when 'daily_briefing' then (select briefer_id from public.daily_briefings where id = _id)
  end
$$;


ALTER FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."timesheet_days_touch_parent"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_id uuid;
BEGIN
  v_id := COALESCE(NEW.timesheet_id, OLD.timesheet_id);
  -- Re-snapshot by bumping approved_at on parent when it's approved (trigger above re-snapshots)
  UPDATE public.timesheets
    SET approved_at = now()
    WHERE id = v_id AND status = 'approved';
  RETURN COALESCE(NEW, OLD);
END;
$$;


ALTER FUNCTION "public"."timesheet_days_touch_parent"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."timesheets_snapshot_and_autoapprove"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_rate numeric(10,2);
  v_actor uuid;
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_actor := auth.uid();

    -- Admin's own timesheet always auto-approves.
    IF public.has_role(NEW.worker_id, 'admin') THEN
      NEW.status := 'approved';
      NEW.approved_at := COALESCE(NEW.approved_at, now());
      NEW.approved_by := COALESCE(NEW.approved_by, NEW.worker_id);

    -- Submitted by someone else on the worker's behalf:
    --   * admin → auto-approve
    --   * manager in same subcontractor as a non-staff worker → auto-approve
    ELSIF v_actor IS NOT NULL AND v_actor <> NEW.worker_id AND (
      public.has_role(v_actor, 'admin')
      OR (
        public.has_role(v_actor, 'manager')
        AND NOT public.is_staff(NEW.worker_id)
        AND public.user_subcontractor(v_actor) IS NOT NULL
        AND public.user_subcontractor(v_actor) = public.user_subcontractor(NEW.worker_id)
      )
    ) THEN
      NEW.status := 'approved';
      NEW.approved_at := COALESCE(NEW.approved_at, now());
      NEW.approved_by := COALESCE(NEW.approved_by, v_actor);
    END IF;
  END IF;

  IF NEW.status = 'approved' THEN
    SELECT shift_rate INTO v_rate FROM public.employee_pay WHERE user_id = NEW.worker_id;
    IF TG_OP = 'INSERT' THEN
      NEW.snapshot_shift_rate := COALESCE(v_rate, 0);
    ELSIF TG_OP = 'UPDATE' THEN
      IF OLD.status <> 'approved' OR OLD.snapshot_shift_rate IS NULL
         OR NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
        NEW.snapshot_shift_rate := COALESCE(v_rate, 0);
      END IF;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."timesheets_snapshot_and_autoapprove"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."toolbox_autoapprove"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."toolbox_autoapprove"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") RETURNS bigint
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'net'
    AS $$
BEGIN
  IF auth.uid() IS NOT NULL
     AND NOT public.has_role(auth.uid(), 'super_admin') THEN
    RAISE EXCEPTION 'Not allowed to trigger cost scan';
  END IF;

  IF position('/api/public/hooks/scan-costs-inbox' IN p_url) = 0 THEN
    RAISE EXCEPTION 'Invalid scan target URL';
  END IF;

  RETURN net.http_post(
    url := p_url,
    headers := jsonb_build_object('Content-Type', 'application/json', 'apikey', p_apikey),
    body := '{}'::jsonb,
    timeout_milliseconds := 120000
  );
END;
$$;


ALTER FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_updated_at_column"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."user_subcontractor"("_user_id" "uuid") RETURNS "uuid"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT subcontractor_id FROM public.profiles WHERE id = _user_id
$$;


ALTER FUNCTION "public"."user_subcontractor"("_user_id" "uuid") OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."app_settings" (
    "key" "text" NOT NULL,
    "value" "text" NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."app_settings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."clients" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_company_aliases" (
    "match_key" "text" NOT NULL,
    "canonical_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_company_aliases" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_company_domain_aliases" (
    "domain" "text" NOT NULL,
    "canonical_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_company_domain_aliases" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_company_subcontractors" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "canonical_company" "text" NOT NULL,
    "subcontractor_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_company_subcontractors" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_dated_scans" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "since_ms" bigint NOT NULL,
    "until_ms" bigint DEFAULT 0 NOT NULL,
    "cursor_uid" integer,
    "in_progress" boolean DEFAULT true NOT NULL,
    "lock_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "resume_count" integer DEFAULT 0 NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "last_error" "text",
    "failed_at" timestamp with time zone,
    "no_progress_count" integer DEFAULT 0 NOT NULL,
    "account_id" "uuid"
);


ALTER TABLE "public"."cost_dated_scans" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_invoice_splits" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "cost_invoice_id" "uuid" NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    "description" "text",
    "project_id" "uuid",
    "project_other" "text",
    "is_overhead" boolean DEFAULT false NOT NULL,
    "net_amount" numeric(12,2) DEFAULT 0 NOT NULL,
    "vat_amount" numeric(12,2),
    "cis_amount" numeric(12,2),
    "total_amount" numeric(12,2),
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_invoice_splits" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_invoices" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "status" "public"."cost_invoice_status" DEFAULT 'pending_review'::"public"."cost_invoice_status" NOT NULL,
    "company_name" "text",
    "company_name_raw" "text",
    "invoice_number" "text",
    "po_reference" "text",
    "invoice_date" "date",
    "due_date" "date",
    "due_date_rule" "text",
    "description" "text",
    "currency" "text" DEFAULT 'GBP'::"text" NOT NULL,
    "net_amount" numeric(12,2),
    "vat_amount" numeric(12,2),
    "total_amount" numeric(12,2),
    "vat_treatment" "public"."cost_vat_treatment" DEFAULT 'unknown'::"public"."cost_vat_treatment" NOT NULL,
    "nas_path" "text",
    "attachment_filename" "text",
    "attachment_sha256" "text",
    "source_email_from" "text",
    "source_subject" "text",
    "source_message_id" "text",
    "source_received_at" timestamp with time zone,
    "gemini_confidence" numeric(4,3),
    "is_duplicate" boolean DEFAULT false NOT NULL,
    "duplicate_of" "uuid",
    "notes" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "paid_at" timestamp with time zone,
    "cis_amount" numeric(12,2),
    "document_type" "text" DEFAULT 'invoice'::"text" NOT NULL,
    "nas_fallback_path" "text",
    "project_id" "uuid",
    "project_other" "text",
    "is_overhead" boolean DEFAULT false NOT NULL,
    "subcontractor_id" "uuid",
    "timesheet_check_status" "text" DEFAULT 'unchecked'::"text" NOT NULL,
    "timesheet_check_at" timestamp with time zone,
    "timesheet_check_detail" "text",
    "company_invoice_key" "text" GENERATED ALWAYS AS (NULLIF("lower"("regexp_replace"("btrim"(COALESCE("company_name", ''::"text")), '\s+'::"text", ' '::"text", 'g'::"text")), ''::"text")) STORED,
    "invoice_number_key" "text" GENERATED ALWAYS AS (NULLIF("upper"("regexp_replace"("btrim"(COALESCE("invoice_number", ''::"text")), '\s+'::"text", ''::"text", 'g'::"text")), ''::"text")) STORED,
    CONSTRAINT "cost_invoices_document_type_check" CHECK (("document_type" = ANY (ARRAY['invoice'::"text", 'credit_note'::"text"])))
);


ALTER TABLE "public"."cost_invoices" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_scan_skips" (
    "message_id" "text" NOT NULL,
    "reason" "text" NOT NULL,
    "subject" "text",
    "source_from" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "attempts" integer DEFAULT 1 NOT NULL,
    "next_retry_at" timestamp with time zone,
    "permanent" boolean DEFAULT false NOT NULL,
    "last_error" "text",
    "source_received_at" timestamp with time zone,
    "progress" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL
);


ALTER TABLE "public"."cost_scan_skips" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_scan_state" (
    "id" smallint NOT NULL,
    "last_uid_seen" bigint DEFAULT 0 NOT NULL,
    "last_run_at" timestamp with time zone,
    "last_success_at" timestamp with time zone,
    "last_error" "text",
    "last_result" "jsonb",
    "manual_catchup_since" timestamp with time zone,
    "scan_in_progress" boolean DEFAULT false NOT NULL,
    "scan_lock_at" timestamp with time zone,
    "scan_cursor_uid" bigint,
    "stop_requested" boolean DEFAULT false NOT NULL,
    "account_id" "uuid"
);


ALTER TABLE "public"."cost_scan_state" OWNER TO "postgres";


CREATE SEQUENCE IF NOT EXISTS "public"."cost_scan_state_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE "public"."cost_scan_state_id_seq" OWNER TO "postgres";


ALTER SEQUENCE "public"."cost_scan_state_id_seq" OWNED BY "public"."cost_scan_state"."id";



CREATE TABLE IF NOT EXISTS "public"."cost_skip_attachments" (
    "sha256" "text" NOT NULL,
    "filename" "text",
    "company_name" "text",
    "reason" "text",
    "source_message_id" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_skip_attachments" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."daily_briefing_attendees" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "briefing_id" "uuid" NOT NULL,
    "position" smallint NOT NULL,
    "user_id" "uuid",
    "name" "text" NOT NULL,
    "signature_url" "text"
);


ALTER TABLE "public"."daily_briefing_attendees" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."daily_briefing_hazards" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "briefing_id" "uuid" NOT NULL,
    "position" smallint NOT NULL,
    "hazard" "text" NOT NULL,
    "control_measure" "text"
);


ALTER TABLE "public"."daily_briefing_hazards" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."daily_briefings" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "briefer_id" "uuid",
    "client_id" "uuid",
    "project_id" "uuid",
    "time_delivered" timestamp with time zone DEFAULT "now"() NOT NULL,
    "work_outline" "text",
    "permits_to_work" "public"."permits_answer",
    "briefer_signature_url" "text",
    "status" "public"."submission_status" DEFAULT 'submitted'::"public"."submission_status" NOT NULL,
    "manager_comment" "text",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revision" integer DEFAULT 1 NOT NULL,
    "client_other" "text",
    "project_other" "text"
);


ALTER TABLE "public"."daily_briefings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."employee_pay" (
    "user_id" "uuid" NOT NULL,
    "shift_rate" numeric(10,2) DEFAULT 0 NOT NULL,
    "currency" "text" DEFAULT 'GBP'::"text" NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_by" "uuid"
);


ALTER TABLE "public"."employee_pay" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."employee_starters" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "full_name" "text" NOT NULL,
    "address" "text" NOT NULL,
    "ni_number" "text" NOT NULL,
    "date_of_birth" "date" NOT NULL,
    "phone" "text" NOT NULL,
    "driving_licence_front" "text",
    "driving_licence_back" "text",
    "nrswa_front" "text",
    "nrswa_back" "text",
    "swqr_number" "text",
    "nrswa_quals" "jsonb" DEFAULT '[]'::"jsonb" NOT NULL,
    "npors_front" "text",
    "npors_back" "text",
    "additional_quals_text" "text",
    "additional_front" "text",
    "additional_back" "text",
    "additional_rows" "jsonb" DEFAULT '[]'::"jsonb" NOT NULL,
    "submitted_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revision" integer DEFAULT 1 NOT NULL,
    "cscs_front" "text",
    "cscs_back" "text",
    "ssts_cert" "text"
);


ALTER TABLE "public"."employee_starters" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."havs_log_items" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "log_id" "uuid" NOT NULL,
    "position" smallint DEFAULT 0 NOT NULL,
    "equipment" "text" NOT NULL,
    "vibration_magnitude" numeric(6,2) NOT NULL,
    "minutes_used" integer DEFAULT 0 NOT NULL,
    "t_eav_hours" numeric(8,2),
    "t_elv_hours" numeric(8,2),
    "points" numeric(10,2) DEFAULT 0 NOT NULL
);


ALTER TABLE "public"."havs_log_items" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."havs_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "worker_id" "uuid",
    "client_id" "uuid",
    "project_id" "uuid",
    "worker_name" "text" NOT NULL,
    "log_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "total_points" numeric(10,2) DEFAULT 0 NOT NULL,
    "signature_url" "text",
    "status" "public"."submission_status" DEFAULT 'submitted'::"public"."submission_status" NOT NULL,
    "manager_comment" "text",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revision" integer DEFAULT 1 NOT NULL,
    "client_other" "text",
    "project_other" "text"
);


ALTER TABLE "public"."havs_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."havs_tools" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "magnitude" numeric(5,2) NOT NULL,
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "havs_tools_magnitude_check" CHECK (("magnitude" >= (0)::numeric))
);


ALTER TABLE "public"."havs_tools" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."holidays" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "start_date" "date" NOT NULL,
    "end_date" "date" NOT NULL,
    "note" "text",
    "status" "public"."holiday_status" DEFAULT 'pending'::"public"."holiday_status" NOT NULL,
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "rejection_reason" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "holidays_range_chk" CHECK (("end_date" >= "start_date"))
);


ALTER TABLE "public"."holidays" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."integration_email_accounts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "label" "text" NOT NULL,
    "email_address" "text" NOT NULL,
    "purpose" "text" DEFAULT 'scan'::"text" NOT NULL,
    "auth_method" "text" DEFAULT 'imap'::"text" NOT NULL,
    "imap_host" "text" DEFAULT 'imap.gmail.com'::"text" NOT NULL,
    "imap_port" integer DEFAULT 993 NOT NULL,
    "smtp_host" "text" DEFAULT 'smtp.gmail.com'::"text" NOT NULL,
    "smtp_port" integer DEFAULT 465 NOT NULL,
    "oauth_provider" "text" DEFAULT 'google'::"text" NOT NULL,
    "password_secret" "text",
    "refresh_token_secret" "text",
    "has_credentials" boolean DEFAULT false NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "last_test_ok" boolean,
    "last_test_at" timestamp with time zone,
    "last_test_error" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "integration_email_accounts_auth_method_check" CHECK (("auth_method" = ANY (ARRAY['imap'::"text", 'oauth2'::"text"]))),
    CONSTRAINT "integration_email_accounts_purpose_check" CHECK (("purpose" = ANY (ARRAY['scan'::"text", 'send'::"text", 'both'::"text"])))
);


ALTER TABLE "public"."integration_email_accounts" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."integration_oauth_providers" (
    "provider" "text" NOT NULL,
    "client_id" "text",
    "client_secret_secret" "text",
    "has_secret" boolean DEFAULT false NOT NULL,
    "scopes" "text" DEFAULT 'https://mail.google.com/'::"text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."integration_oauth_providers" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."integration_storage_backends" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "label" "text" NOT NULL,
    "type" "text" DEFAULT 'webdav'::"text" NOT NULL,
    "config" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "username_secret" "text",
    "password_secret" "text",
    "has_credentials" boolean DEFAULT false NOT NULL,
    "is_active" boolean DEFAULT false NOT NULL,
    "last_test_ok" boolean,
    "last_test_at" timestamp with time zone,
    "last_test_error" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "integration_storage_backends_type_check" CHECK (("type" = ANY (ARRAY['webdav'::"text", 's3'::"text"])))
);


ALTER TABLE "public"."integration_storage_backends" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."invoice_clients" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "address" "text" DEFAULT ''::"text" NOT NULL,
    "default_client_reference" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."invoice_clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."invoice_lines" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "invoice_id" "uuid" NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    "site_name" "text",
    "description" "text",
    "amount_net" numeric(12,2) DEFAULT 0 NOT NULL,
    "project_id" "uuid",
    "project_other" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."invoice_lines" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."invoices" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "invoice_number" integer NOT NULL,
    "invoice_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "due_date" "date" NOT NULL,
    "client_id" "uuid",
    "client_name_snapshot" "text" DEFAULT ''::"text" NOT NULL,
    "client_address_snapshot" "text" DEFAULT ''::"text" NOT NULL,
    "client_reference" "text",
    "purchase_order" "text",
    "site_name" "text",
    "description" "text",
    "amount_net" numeric(12,2) DEFAULT 0 NOT NULL,
    "vat_mode" "public"."invoice_vat_mode" DEFAULT 'reverse_charge'::"public"."invoice_vat_mode" NOT NULL,
    "nas_path" "text",
    "nas_pushed_at" timestamp with time zone,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."invoices" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."nas_sync_queue" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "kind" "text" NOT NULL,
    "submission_id" "uuid" NOT NULL,
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "attempts" integer DEFAULT 0 NOT NULL,
    "last_error" "text",
    "last_attempt_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "nas_sync_queue_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'synced'::"text", 'failed'::"text"])))
);


ALTER TABLE "public"."nas_sync_queue" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."password_recovery_tokens" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "token_hash" "text" NOT NULL,
    "expires_at" timestamp with time zone NOT NULL,
    "used_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."password_recovery_tokens" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."plant" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "description" "text" NOT NULL,
    "serial_no" "text",
    "next_service_due" "date",
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."plant" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."plant_inspection_items" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "inspection_id" "uuid" NOT NULL,
    "position" smallint NOT NULL,
    "item_label" "text" NOT NULL,
    "has_fault" boolean DEFAULT false NOT NULL,
    "fault_description" "text",
    "repaired_at" timestamp with time zone,
    "repaired_by" "uuid"
);


ALTER TABLE "public"."plant_inspection_items" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."plant_inspections" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "worker_id" "uuid",
    "client_id" "uuid",
    "plant_id" "uuid",
    "plant_description" "text",
    "plant_serial_no" "text",
    "next_service_due" "date",
    "clock_hours" numeric,
    "checker_name" "text",
    "inspection_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "signature_url" "text",
    "status" "public"."submission_status" DEFAULT 'submitted'::"public"."submission_status" NOT NULL,
    "manager_comment" "text",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revision" integer DEFAULT 1 NOT NULL,
    "project_id" "uuid",
    "client_other" "text",
    "project_other" "text"
);


ALTER TABLE "public"."plant_inspections" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."profiles" (
    "id" "uuid" NOT NULL,
    "username" "text" NOT NULL,
    "full_name" "text",
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "subcontractor_id" "uuid",
    "must_reset_password" boolean DEFAULT true NOT NULL,
    "last_active_at" timestamp with time zone,
    "recovery_email" "text",
    "mfa_enabled" boolean DEFAULT false NOT NULL
);


ALTER TABLE "public"."profiles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."project_assignments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "project_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "assigned_by" "uuid",
    "assigned_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."project_assignments" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."projects" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "client_id" "uuid",
    "code" "text" NOT NULL,
    "description" "text",
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "latitude" numeric(9,6),
    "longitude" numeric(9,6),
    "location_label" "text",
    "nas_folder_url" "text",
    "archived_at" timestamp with time zone
);


ALTER TABLE "public"."projects" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."rams_attendees" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "briefing_id" "uuid" NOT NULL,
    "position" smallint NOT NULL,
    "name" "text" NOT NULL,
    "signature_url" "text",
    "user_id" "uuid"
);


ALTER TABLE "public"."rams_attendees" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."rams_briefings" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "briefer_id" "uuid",
    "client_id" "uuid",
    "project_id" "uuid",
    "method_statement_title" "text",
    "revision_date" "date",
    "briefing_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "briefer_signature_url" "text",
    "status" "public"."submission_status" DEFAULT 'submitted'::"public"."submission_status" NOT NULL,
    "manager_comment" "text",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revision" integer DEFAULT 1 NOT NULL,
    "client_other" "text",
    "project_other" "text"
);


ALTER TABLE "public"."rams_briefings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."subcontractors" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."subcontractors" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."submission_photos" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "kind" "public"."submission_kind" NOT NULL,
    "submission_id" "uuid" NOT NULL,
    "item_id" "uuid",
    "storage_path" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."submission_photos" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."timesheet_days" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "timesheet_id" "uuid" NOT NULL,
    "day_of_week" smallint NOT NULL,
    "project_id" "uuid",
    "project_text" "text",
    "shifts" numeric(4,2) DEFAULT 0 NOT NULL
);


ALTER TABLE "public"."timesheet_days" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."timesheets" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "worker_id" "uuid",
    "week_ending" "date" NOT NULL,
    "signature_url" "text",
    "status" "public"."submission_status" DEFAULT 'submitted'::"public"."submission_status" NOT NULL,
    "manager_comment" "text",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "snapshot_shift_rate" numeric(10,2),
    "rejection_reason" "text",
    "revision" integer DEFAULT 1 NOT NULL,
    "change_requested_at" timestamp with time zone,
    "change_requested_by" "uuid"
);


ALTER TABLE "public"."timesheets" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."toolbox_attendees" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "talk_id" "uuid" NOT NULL,
    "position" smallint NOT NULL,
    "user_id" "uuid",
    "name" "text" NOT NULL,
    "signature_url" "text"
);


ALTER TABLE "public"."toolbox_attendees" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."toolbox_talks" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "briefer_id" "uuid",
    "client_id" "uuid",
    "project_id" "uuid",
    "topic" "text" NOT NULL,
    "talk_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "briefer_signature_url" "text",
    "status" "public"."submission_status" DEFAULT 'submitted'::"public"."submission_status" NOT NULL,
    "manager_comment" "text",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revision" integer DEFAULT 1 NOT NULL,
    "client_other" "text",
    "project_other" "text"
);


ALTER TABLE "public"."toolbox_talks" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_roles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "role" "public"."app_role" NOT NULL
);


ALTER TABLE "public"."user_roles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_defect_items" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "defect_id" "uuid" NOT NULL,
    "position" smallint NOT NULL,
    "item_label" "text" NOT NULL,
    "has_defect" boolean DEFAULT false NOT NULL,
    "defect_description" "text",
    "repaired_at" timestamp with time zone,
    "repaired_by" "uuid"
);


ALTER TABLE "public"."vehicle_defect_items" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_defects" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "worker_id" "uuid",
    "vehicle_id" "uuid",
    "vehicle_registration" "text",
    "inspection_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "odometer" integer,
    "comments" "text",
    "signature_url" "text",
    "status" "public"."submission_status" DEFAULT 'submitted'::"public"."submission_status" NOT NULL,
    "manager_comment" "text",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revision" integer DEFAULT 1 NOT NULL
);


ALTER TABLE "public"."vehicle_defects" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "registration" "text" NOT NULL,
    "description" "text",
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."vehicles" OWNER TO "postgres";


ALTER TABLE ONLY "public"."cost_scan_state" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."cost_scan_state_id_seq"'::"regclass");



ALTER TABLE ONLY "public"."app_settings"
    ADD CONSTRAINT "app_settings_pkey" PRIMARY KEY ("key");



ALTER TABLE ONLY "public"."clients"
    ADD CONSTRAINT "clients_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."clients"
    ADD CONSTRAINT "clients_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_company_aliases"
    ADD CONSTRAINT "cost_company_aliases_pkey" PRIMARY KEY ("match_key");



ALTER TABLE ONLY "public"."cost_company_domain_aliases"
    ADD CONSTRAINT "cost_company_domain_aliases_pkey" PRIMARY KEY ("domain", "canonical_name");



ALTER TABLE ONLY "public"."cost_company_subcontractors"
    ADD CONSTRAINT "cost_company_subcontractors_canonical_company_key" UNIQUE ("canonical_company");



ALTER TABLE ONLY "public"."cost_company_subcontractors"
    ADD CONSTRAINT "cost_company_subcontractors_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_dated_scans"
    ADD CONSTRAINT "cost_dated_scans_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_dated_scans"
    ADD CONSTRAINT "cost_dated_scans_since_ms_until_ms_key" UNIQUE ("since_ms", "until_ms");



ALTER TABLE ONLY "public"."cost_invoice_splits"
    ADD CONSTRAINT "cost_invoice_splits_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_invoices"
    ADD CONSTRAINT "cost_invoices_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_scan_skips"
    ADD CONSTRAINT "cost_scan_skips_pkey" PRIMARY KEY ("message_id");



ALTER TABLE ONLY "public"."cost_scan_state"
    ADD CONSTRAINT "cost_scan_state_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_skip_attachments"
    ADD CONSTRAINT "cost_skip_attachments_pkey" PRIMARY KEY ("sha256");



ALTER TABLE ONLY "public"."daily_briefing_attendees"
    ADD CONSTRAINT "daily_briefing_attendees_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."daily_briefing_hazards"
    ADD CONSTRAINT "daily_briefing_hazards_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."daily_briefings"
    ADD CONSTRAINT "daily_briefings_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."employee_pay"
    ADD CONSTRAINT "employee_pay_pkey" PRIMARY KEY ("user_id");



ALTER TABLE ONLY "public"."employee_starters"
    ADD CONSTRAINT "employee_starters_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."employee_starters"
    ADD CONSTRAINT "employee_starters_user_id_key" UNIQUE ("user_id");



ALTER TABLE ONLY "public"."havs_log_items"
    ADD CONSTRAINT "havs_log_items_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."havs_logs"
    ADD CONSTRAINT "havs_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."havs_logs"
    ADD CONSTRAINT "havs_logs_worker_day_unique" UNIQUE ("worker_id", "log_date");



ALTER TABLE ONLY "public"."havs_tools"
    ADD CONSTRAINT "havs_tools_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."havs_tools"
    ADD CONSTRAINT "havs_tools_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."holidays"
    ADD CONSTRAINT "holidays_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."integration_email_accounts"
    ADD CONSTRAINT "integration_email_accounts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."integration_oauth_providers"
    ADD CONSTRAINT "integration_oauth_providers_pkey" PRIMARY KEY ("provider");



ALTER TABLE ONLY "public"."integration_storage_backends"
    ADD CONSTRAINT "integration_storage_backends_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."invoice_clients"
    ADD CONSTRAINT "invoice_clients_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."invoice_lines"
    ADD CONSTRAINT "invoice_lines_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."invoices"
    ADD CONSTRAINT "invoices_invoice_number_key" UNIQUE ("invoice_number");



ALTER TABLE ONLY "public"."invoices"
    ADD CONSTRAINT "invoices_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."nas_sync_queue"
    ADD CONSTRAINT "nas_sync_queue_kind_submission_unique" UNIQUE ("kind", "submission_id");



ALTER TABLE ONLY "public"."nas_sync_queue"
    ADD CONSTRAINT "nas_sync_queue_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."password_recovery_tokens"
    ADD CONSTRAINT "password_recovery_tokens_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."plant_inspection_items"
    ADD CONSTRAINT "plant_inspection_items_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."plant_inspections"
    ADD CONSTRAINT "plant_inspections_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."plant"
    ADD CONSTRAINT "plant_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."plant"
    ADD CONSTRAINT "plant_serial_no_key" UNIQUE ("serial_no");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_username_key" UNIQUE ("username");



ALTER TABLE ONLY "public"."project_assignments"
    ADD CONSTRAINT "project_assignments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."project_assignments"
    ADD CONSTRAINT "project_assignments_project_id_user_id_key" UNIQUE ("project_id", "user_id");



ALTER TABLE ONLY "public"."projects"
    ADD CONSTRAINT "projects_client_id_code_key" UNIQUE ("client_id", "code");



ALTER TABLE ONLY "public"."projects"
    ADD CONSTRAINT "projects_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."rams_attendees"
    ADD CONSTRAINT "rams_attendees_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."rams_briefings"
    ADD CONSTRAINT "rams_briefings_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subcontractors"
    ADD CONSTRAINT "subcontractors_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."subcontractors"
    ADD CONSTRAINT "subcontractors_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."submission_photos"
    ADD CONSTRAINT "submission_photos_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."timesheet_days"
    ADD CONSTRAINT "timesheet_days_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."timesheets"
    ADD CONSTRAINT "timesheets_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."toolbox_attendees"
    ADD CONSTRAINT "toolbox_attendees_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."toolbox_talks"
    ADD CONSTRAINT "toolbox_talks_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_role_key" UNIQUE ("user_id", "role");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_unique" UNIQUE ("user_id");



ALTER TABLE ONLY "public"."vehicle_defect_items"
    ADD CONSTRAINT "vehicle_defect_items_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicle_defects"
    ADD CONSTRAINT "vehicle_defects_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_registration_key" UNIQUE ("registration");



CREATE INDEX "cost_invoices_company_idx" ON "public"."cost_invoices" USING "btree" ("lower"("company_name"));



CREATE INDEX "cost_invoices_document_type_idx" ON "public"."cost_invoices" USING "btree" ("document_type");



CREATE INDEX "cost_invoices_invoice_date_idx" ON "public"."cost_invoices" USING "btree" ("invoice_date" DESC);



CREATE UNIQUE INDEX "cost_invoices_msgid_unique" ON "public"."cost_invoices" USING "btree" ("source_message_id", "attachment_filename", COALESCE("invoice_number", ''::"text")) WHERE ("source_message_id" IS NOT NULL);



CREATE INDEX "cost_invoices_paid_idx" ON "public"."cost_invoices" USING "btree" ("paid_at");



CREATE UNIQUE INDEX "cost_invoices_sha_unique" ON "public"."cost_invoices" USING "btree" ("attachment_sha256") WHERE ("attachment_sha256" IS NOT NULL);



CREATE INDEX "cost_invoices_status_idx" ON "public"."cost_invoices" USING "btree" ("status");



CREATE UNIQUE INDEX "cost_invoices_unique_company_invoice_number" ON "public"."cost_invoices" USING "btree" ("company_invoice_key", "invoice_number_key") WHERE (("company_invoice_key" IS NOT NULL) AND ("invoice_number_key" IS NOT NULL) AND ("invoice_number_key" <> ALL (ARRAY['NA'::"text", 'N/A'::"text", 'NO-NUMBER'::"text", 'NONUMBER'::"text", 'NO_NUMBER'::"text"])));



CREATE UNIQUE INDEX "cost_scan_state_account_uniq" ON "public"."cost_scan_state" USING "btree" ("account_id");



CREATE INDEX "daily_briefings_briefer_id_time_delivered_idx" ON "public"."daily_briefings" USING "btree" ("briefer_id", "time_delivered" DESC);



CREATE INDEX "havs_log_items_log_idx" ON "public"."havs_log_items" USING "btree" ("log_id");



CREATE INDEX "havs_logs_worker_date_idx" ON "public"."havs_logs" USING "btree" ("worker_id", "log_date" DESC);



CREATE INDEX "holidays_dates_idx" ON "public"."holidays" USING "btree" ("start_date", "end_date");



CREATE INDEX "holidays_user_start_idx" ON "public"."holidays" USING "btree" ("user_id", "start_date");



CREATE INDEX "idx_cost_invoice_splits_cost_invoice_id" ON "public"."cost_invoice_splits" USING "btree" ("cost_invoice_id");



CREATE INDEX "idx_cost_invoice_splits_project_id" ON "public"."cost_invoice_splits" USING "btree" ("project_id");



CREATE INDEX "idx_invoice_lines_invoice_id" ON "public"."invoice_lines" USING "btree" ("invoice_id");



CREATE INDEX "idx_invoice_lines_project_id" ON "public"."invoice_lines" USING "btree" ("project_id");



CREATE UNIQUE INDEX "integration_storage_active_uniq" ON "public"."integration_storage_backends" USING "btree" ("is_active") WHERE "is_active";



CREATE INDEX "invoices_client_id_idx" ON "public"."invoices" USING "btree" ("client_id");



CREATE INDEX "invoices_invoice_date_idx" ON "public"."invoices" USING "btree" ("invoice_date" DESC);



CREATE INDEX "nas_sync_queue_status_idx" ON "public"."nas_sync_queue" USING "btree" ("status", "created_at");



CREATE INDEX "password_recovery_tokens_hash_idx" ON "public"."password_recovery_tokens" USING "btree" ("token_hash");



CREATE INDEX "password_recovery_tokens_user_idx" ON "public"."password_recovery_tokens" USING "btree" ("user_id");



CREATE INDEX "plant_inspections_project_id_idx" ON "public"."plant_inspections" USING "btree" ("project_id");



CREATE INDEX "plant_inspections_worker_id_inspection_date_idx" ON "public"."plant_inspections" USING "btree" ("worker_id", "inspection_date" DESC);



CREATE INDEX "project_assignments_project_idx" ON "public"."project_assignments" USING "btree" ("project_id");



CREATE INDEX "project_assignments_user_idx" ON "public"."project_assignments" USING "btree" ("user_id");



CREATE INDEX "rams_briefings_briefer_id_briefing_date_idx" ON "public"."rams_briefings" USING "btree" ("briefer_id", "briefing_date" DESC);



CREATE INDEX "submission_photos_kind_submission_id_idx" ON "public"."submission_photos" USING "btree" ("kind", "submission_id");



CREATE INDEX "timesheet_days_timesheet_id_day_idx" ON "public"."timesheet_days" USING "btree" ("timesheet_id", "day_of_week");



CREATE INDEX "timesheets_worker_id_week_ending_idx" ON "public"."timesheets" USING "btree" ("worker_id", "week_ending" DESC);



CREATE UNIQUE INDEX "timesheets_worker_week_unique" ON "public"."timesheets" USING "btree" ("worker_id", "week_ending");



CREATE INDEX "toolbox_talks_briefer_id_talk_date_idx" ON "public"."toolbox_talks" USING "btree" ("briefer_id", "talk_date" DESC);



CREATE INDEX "vehicle_defects_worker_id_inspection_date_idx" ON "public"."vehicle_defects" USING "btree" ("worker_id", "inspection_date" DESC);



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."daily_briefings" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."havs_logs" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."plant_inspections" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."rams_briefings" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."timesheets" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."toolbox_talks" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."vehicle_defects" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "cost_invoices_canonical_company" BEFORE INSERT OR UPDATE OF "company_name" ON "public"."cost_invoices" FOR EACH ROW EXECUTE FUNCTION "public"."cost_invoices_apply_canonical_company"();



CREATE OR REPLACE TRIGGER "cost_invoices_set_updated_at" BEFORE UPDATE ON "public"."cost_invoices" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "daily_briefing_autoapprove_t" BEFORE INSERT ON "public"."daily_briefings" FOR EACH ROW EXECUTE FUNCTION "public"."daily_briefing_autoapprove"();



CREATE OR REPLACE TRIGGER "employee_pay_set_updated_at" BEFORE UPDATE ON "public"."employee_pay" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "employee_starters_updated_at" BEFORE UPDATE ON "public"."employee_starters" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "havs_logs_autoapprove" BEFORE INSERT ON "public"."havs_logs" FOR EACH ROW EXECUTE FUNCTION "public"."havs_autoapprove"();



CREATE OR REPLACE TRIGGER "havs_logs_updated_at" BEFORE UPDATE ON "public"."havs_logs" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "havs_tools_updated_at" BEFORE UPDATE ON "public"."havs_tools" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at_havs_tools"();



CREATE OR REPLACE TRIGGER "holidays_before_insert_autoapprove" BEFORE INSERT ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_autoapprove"();



CREATE OR REPLACE TRIGGER "holidays_before_update_amend_resets_status" BEFORE UPDATE OF "start_date", "end_date", "note" ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_amend_resets_status"();



CREATE OR REPLACE TRIGGER "holidays_before_update_status_guard" BEFORE UPDATE OF "status" ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_enforce_status_change"();



CREATE OR REPLACE TRIGGER "holidays_set_updated_at" BEFORE UPDATE ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "profiles_guard_sensitive_self_update" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."profiles_guard_sensitive_self_update"();



CREATE OR REPLACE TRIGGER "set_cost_company_aliases_updated_at" BEFORE UPDATE ON "public"."cost_company_aliases" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_cost_company_subcontractors_updated_at" BEFORE UPDATE ON "public"."cost_company_subcontractors" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_cost_invoice_splits_updated_at" BEFORE UPDATE ON "public"."cost_invoice_splits" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_invoice_lines_updated_at" BEFORE UPDATE ON "public"."invoice_lines" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_nas_sync_queue_updated_at" BEFORE UPDATE ON "public"."nas_sync_queue" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "toolbox_autoapprove_t" BEFORE INSERT ON "public"."toolbox_talks" FOR EACH ROW EXECUTE FUNCTION "public"."toolbox_autoapprove"();



CREATE OR REPLACE TRIGGER "trg_integration_email_accounts_updated" BEFORE UPDATE ON "public"."integration_email_accounts" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "trg_integration_oauth_providers_updated" BEFORE UPDATE ON "public"."integration_oauth_providers" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "trg_integration_storage_backends_updated" BEFORE UPDATE ON "public"."integration_storage_backends" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "trg_invoice_clients_updated" BEFORE UPDATE ON "public"."invoice_clients" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "trg_invoices_before_insert" BEFORE INSERT ON "public"."invoices" FOR EACH ROW EXECUTE FUNCTION "public"."invoices_before_insert"();



CREATE OR REPLACE TRIGGER "trg_invoices_updated" BEFORE UPDATE ON "public"."invoices" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "trg_timesheet_days_touch_parent" AFTER INSERT OR DELETE OR UPDATE ON "public"."timesheet_days" FOR EACH ROW EXECUTE FUNCTION "public"."timesheet_days_touch_parent"();



CREATE OR REPLACE TRIGGER "trg_timesheets_snapshot" BEFORE INSERT OR UPDATE ON "public"."timesheets" FOR EACH ROW EXECUTE FUNCTION "public"."timesheets_snapshot_and_autoapprove"();



CREATE OR REPLACE TRIGGER "update_app_settings_updated_at" BEFORE UPDATE ON "public"."app_settings" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_cost_company_domain_aliases_updated_at" BEFORE UPDATE ON "public"."cost_company_domain_aliases" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_cost_dated_scans_updated_at" BEFORE UPDATE ON "public"."cost_dated_scans" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



ALTER TABLE ONLY "public"."cost_company_subcontractors"
    ADD CONSTRAINT "cost_company_subcontractors_subcontractor_id_fkey" FOREIGN KEY ("subcontractor_id") REFERENCES "public"."subcontractors"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."cost_invoice_splits"
    ADD CONSTRAINT "cost_invoice_splits_cost_invoice_id_fkey" FOREIGN KEY ("cost_invoice_id") REFERENCES "public"."cost_invoices"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."cost_invoice_splits"
    ADD CONSTRAINT "cost_invoice_splits_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."cost_invoices"
    ADD CONSTRAINT "cost_invoices_duplicate_of_fkey" FOREIGN KEY ("duplicate_of") REFERENCES "public"."cost_invoices"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."cost_invoices"
    ADD CONSTRAINT "cost_invoices_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."cost_invoices"
    ADD CONSTRAINT "cost_invoices_subcontractor_id_fkey" FOREIGN KEY ("subcontractor_id") REFERENCES "public"."subcontractors"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."daily_briefing_attendees"
    ADD CONSTRAINT "daily_briefing_attendees_briefing_id_fkey" FOREIGN KEY ("briefing_id") REFERENCES "public"."daily_briefings"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."daily_briefing_attendees"
    ADD CONSTRAINT "daily_briefing_attendees_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."daily_briefing_hazards"
    ADD CONSTRAINT "daily_briefing_hazards_briefing_id_fkey" FOREIGN KEY ("briefing_id") REFERENCES "public"."daily_briefings"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."daily_briefings"
    ADD CONSTRAINT "daily_briefings_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."daily_briefings"
    ADD CONSTRAINT "daily_briefings_briefer_id_fkey" FOREIGN KEY ("briefer_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."daily_briefings"
    ADD CONSTRAINT "daily_briefings_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id");



ALTER TABLE ONLY "public"."daily_briefings"
    ADD CONSTRAINT "daily_briefings_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id");



ALTER TABLE ONLY "public"."employee_pay"
    ADD CONSTRAINT "employee_pay_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."employee_pay"
    ADD CONSTRAINT "employee_pay_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."employee_starters"
    ADD CONSTRAINT "employee_starters_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."havs_log_items"
    ADD CONSTRAINT "havs_log_items_log_id_fkey" FOREIGN KEY ("log_id") REFERENCES "public"."havs_logs"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."havs_logs"
    ADD CONSTRAINT "havs_logs_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."havs_logs"
    ADD CONSTRAINT "havs_logs_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id");



ALTER TABLE ONLY "public"."havs_logs"
    ADD CONSTRAINT "havs_logs_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id");



ALTER TABLE ONLY "public"."havs_logs"
    ADD CONSTRAINT "havs_logs_worker_id_fkey" FOREIGN KEY ("worker_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."holidays"
    ADD CONSTRAINT "holidays_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."holidays"
    ADD CONSTRAINT "holidays_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."invoice_lines"
    ADD CONSTRAINT "invoice_lines_invoice_id_fkey" FOREIGN KEY ("invoice_id") REFERENCES "public"."invoices"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."invoice_lines"
    ADD CONSTRAINT "invoice_lines_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."invoices"
    ADD CONSTRAINT "invoices_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."invoice_clients"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."invoices"
    ADD CONSTRAINT "invoices_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."password_recovery_tokens"
    ADD CONSTRAINT "password_recovery_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."plant_inspection_items"
    ADD CONSTRAINT "plant_inspection_items_inspection_id_fkey" FOREIGN KEY ("inspection_id") REFERENCES "public"."plant_inspections"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."plant_inspection_items"
    ADD CONSTRAINT "plant_inspection_items_repaired_by_fkey" FOREIGN KEY ("repaired_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."plant_inspections"
    ADD CONSTRAINT "plant_inspections_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."plant_inspections"
    ADD CONSTRAINT "plant_inspections_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id");



ALTER TABLE ONLY "public"."plant_inspections"
    ADD CONSTRAINT "plant_inspections_plant_id_fkey" FOREIGN KEY ("plant_id") REFERENCES "public"."plant"("id");



ALTER TABLE ONLY "public"."plant_inspections"
    ADD CONSTRAINT "plant_inspections_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."plant_inspections"
    ADD CONSTRAINT "plant_inspections_worker_id_fkey" FOREIGN KEY ("worker_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY ("id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_subcontractor_id_fkey" FOREIGN KEY ("subcontractor_id") REFERENCES "public"."subcontractors"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."project_assignments"
    ADD CONSTRAINT "project_assignments_assigned_by_fkey" FOREIGN KEY ("assigned_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."project_assignments"
    ADD CONSTRAINT "project_assignments_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."project_assignments"
    ADD CONSTRAINT "project_assignments_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."projects"
    ADD CONSTRAINT "projects_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."rams_attendees"
    ADD CONSTRAINT "rams_attendees_briefing_id_fkey" FOREIGN KEY ("briefing_id") REFERENCES "public"."rams_briefings"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."rams_attendees"
    ADD CONSTRAINT "rams_attendees_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."rams_briefings"
    ADD CONSTRAINT "rams_briefings_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."rams_briefings"
    ADD CONSTRAINT "rams_briefings_briefer_id_fkey" FOREIGN KEY ("briefer_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."rams_briefings"
    ADD CONSTRAINT "rams_briefings_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id");



ALTER TABLE ONLY "public"."rams_briefings"
    ADD CONSTRAINT "rams_briefings_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id");



ALTER TABLE ONLY "public"."timesheet_days"
    ADD CONSTRAINT "timesheet_days_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."timesheet_days"
    ADD CONSTRAINT "timesheet_days_timesheet_id_fkey" FOREIGN KEY ("timesheet_id") REFERENCES "public"."timesheets"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."timesheets"
    ADD CONSTRAINT "timesheets_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."timesheets"
    ADD CONSTRAINT "timesheets_worker_id_fkey" FOREIGN KEY ("worker_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."toolbox_attendees"
    ADD CONSTRAINT "toolbox_attendees_talk_id_fkey" FOREIGN KEY ("talk_id") REFERENCES "public"."toolbox_talks"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."toolbox_attendees"
    ADD CONSTRAINT "toolbox_attendees_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."toolbox_talks"
    ADD CONSTRAINT "toolbox_talks_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."toolbox_talks"
    ADD CONSTRAINT "toolbox_talks_briefer_id_fkey" FOREIGN KEY ("briefer_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."toolbox_talks"
    ADD CONSTRAINT "toolbox_talks_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id");



ALTER TABLE ONLY "public"."toolbox_talks"
    ADD CONSTRAINT "toolbox_talks_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_defect_items"
    ADD CONSTRAINT "vehicle_defect_items_defect_id_fkey" FOREIGN KEY ("defect_id") REFERENCES "public"."vehicle_defects"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_defect_items"
    ADD CONSTRAINT "vehicle_defect_items_repaired_by_fkey" FOREIGN KEY ("repaired_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."vehicle_defects"
    ADD CONSTRAINT "vehicle_defects_approved_by_fkey" FOREIGN KEY ("approved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicle_defects"
    ADD CONSTRAINT "vehicle_defects_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id");



ALTER TABLE ONLY "public"."vehicle_defects"
    ADD CONSTRAINT "vehicle_defects_worker_id_fkey" FOREIGN KEY ("worker_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



CREATE POLICY "Admins can delete havs_tools" ON "public"."havs_tools" FOR DELETE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins can insert havs_tools" ON "public"."havs_tools" FOR INSERT TO "authenticated" WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins can read dated scans" ON "public"."cost_dated_scans" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins can update havs_tools" ON "public"."havs_tools" FOR UPDATE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins delete cost invoices" ON "public"."cost_invoices" FOR DELETE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins insert app settings" ON "public"."app_settings" FOR INSERT TO "authenticated" WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins manage cost company aliases" ON "public"."cost_company_aliases" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins manage cost company domain aliases" ON "public"."cost_company_domain_aliases" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins read cost invoices" ON "public"."cost_invoices" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins read cost_scan_skips" ON "public"."cost_scan_skips" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins read cost_skip_attachments" ON "public"."cost_skip_attachments" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins read scan state" ON "public"."cost_scan_state" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins update app settings" ON "public"."app_settings" FOR UPDATE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins update cost invoices" ON "public"."cost_invoices" FOR UPDATE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins update scan state" ON "public"."cost_scan_state" FOR UPDATE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Anyone signed in can read havs_tools" ON "public"."havs_tools" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "Authenticated read app settings" ON "public"."app_settings" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "Insert holidays for self or managed worker" ON "public"."holidays" FOR INSERT TO "authenticated" WITH CHECK ((("user_id" = "auth"."uid"()) OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND (NOT "public"."is_staff"("user_id")) AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("user_id")))));



CREATE POLICY "No direct client access" ON "public"."password_recovery_tokens" TO "authenticated", "anon" USING (false) WITH CHECK (false);



CREATE POLICY "Owner admin or manager delete holidays" ON "public"."holidays" FOR DELETE TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND (NOT "public"."is_staff"("user_id")) AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("user_id")))));



CREATE POLICY "Owner admin or manager update holidays" ON "public"."holidays" FOR UPDATE TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND (NOT "public"."is_staff"("user_id")) AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("user_id"))))) WITH CHECK ((("user_id" = "auth"."uid"()) OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND (NOT "public"."is_staff"("user_id")) AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("user_id")))));



CREATE POLICY "Staff can view NAS sync queue" ON "public"."nas_sync_queue" FOR SELECT TO "authenticated" USING ("public"."is_staff"("auth"."uid"()));



CREATE POLICY "Staff oversight view holidays" ON "public"."holidays" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("user_id")))));



CREATE POLICY "Users view own holidays" ON "public"."holidays" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."app_settings" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "assignments admin write" ON "public"."project_assignments" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "assignments manager delete" ON "public"."project_assignments" FOR DELETE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id") AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("user_id"))));



CREATE POLICY "assignments manager insert" ON "public"."project_assignments" FOR INSERT TO "authenticated" WITH CHECK (("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id") AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("user_id"))));



CREATE POLICY "assignments read" ON "public"."project_assignments" FOR SELECT TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id"))));



ALTER TABLE "public"."clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "clients admin write" ON "public"."clients" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "clients read authed" ON "public"."clients" FOR SELECT TO "authenticated" USING (true);



ALTER TABLE "public"."cost_company_aliases" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_company_domain_aliases" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_company_subcontractors" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "cost_company_subcontractors admin all" ON "public"."cost_company_subcontractors" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



ALTER TABLE "public"."cost_dated_scans" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_invoice_splits" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "cost_invoice_splits admin all" ON "public"."cost_invoice_splits" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



ALTER TABLE "public"."cost_invoices" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_scan_skips" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_scan_state" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_skip_attachments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."daily_briefing_attendees" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."daily_briefing_hazards" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."daily_briefings" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "db admin delete" ON "public"."daily_briefings" FOR DELETE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "db assigned read" ON "public"."daily_briefings" FOR SELECT TO "authenticated" USING ((("project_id" IS NOT NULL) AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id")));



CREATE POLICY "db cjb_manager read" ON "public"."daily_briefings" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "db owner insert" ON "public"."daily_briefings" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "db owner update" ON "public"."daily_briefings" FOR UPDATE TO "authenticated" USING ((("briefer_id" = "auth"."uid"()) OR "public"."can_manage_submission"("briefer_id"))) WITH CHECK ((("briefer_id" = "auth"."uid"()) OR "public"."can_manage_submission"("briefer_id")));



CREATE POLICY "db read scope" ON "public"."daily_briefings" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "db staff update" ON "public"."daily_briefings" FOR UPDATE TO "authenticated" USING ("public"."is_staff"("auth"."uid"())) WITH CHECK ("public"."is_staff"("auth"."uid"()));



CREATE POLICY "db_att owner write" ON "public"."daily_briefing_attendees" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."daily_briefings" "b"
  WHERE (("b"."id" = "daily_briefing_attendees"."briefing_id") AND "public"."can_manage_submission"("b"."briefer_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."daily_briefings" "b"
  WHERE (("b"."id" = "daily_briefing_attendees"."briefing_id") AND "public"."can_manage_submission"("b"."briefer_id")))));



CREATE POLICY "db_att read" ON "public"."daily_briefing_attendees" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."daily_briefings" "b"
  WHERE (("b"."id" = "daily_briefing_attendees"."briefing_id") AND (("b"."briefer_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()))))));



CREATE POLICY "db_haz owner write" ON "public"."daily_briefing_hazards" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."daily_briefings" "b"
  WHERE (("b"."id" = "daily_briefing_hazards"."briefing_id") AND "public"."can_manage_submission"("b"."briefer_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."daily_briefings" "b"
  WHERE (("b"."id" = "daily_briefing_hazards"."briefing_id") AND "public"."can_manage_submission"("b"."briefer_id")))));



CREATE POLICY "db_haz read" ON "public"."daily_briefing_hazards" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."daily_briefings" "b"
  WHERE (("b"."id" = "daily_briefing_hazards"."briefing_id") AND (("b"."briefer_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()))))));



ALTER TABLE "public"."employee_pay" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "employee_pay admin all" ON "public"."employee_pay" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



ALTER TABLE "public"."employee_starters" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "havs assigned read" ON "public"."havs_logs" FOR SELECT TO "authenticated" USING ((("project_id" IS NOT NULL) AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id")));



CREATE POLICY "havs cjb_manager read" ON "public"."havs_logs" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "havs delete admin or manager scope" ON "public"."havs_logs" FOR DELETE TO "authenticated" USING ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "havs insert self or staff scope" ON "public"."havs_logs" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "havs select self or staff scope" ON "public"."havs_logs" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "havs update self or staff scope" ON "public"."havs_logs" FOR UPDATE TO "authenticated" USING ("public"."can_manage_submission"("worker_id")) WITH CHECK ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "havs_items cjb_manager read" ON "public"."havs_log_items" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "havs_items read" ON "public"."havs_log_items" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."havs_logs" "h"
  WHERE (("h"."id" = "havs_log_items"."log_id") AND "public"."can_manage_submission"("h"."worker_id")))));



CREATE POLICY "havs_items write" ON "public"."havs_log_items" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."havs_logs" "h"
  WHERE (("h"."id" = "havs_log_items"."log_id") AND "public"."can_manage_submission"("h"."worker_id") AND (("h"."status" = 'submitted'::"public"."submission_status") OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."havs_logs" "h"
  WHERE (("h"."id" = "havs_log_items"."log_id") AND "public"."can_manage_submission"("h"."worker_id") AND (("h"."status" = 'submitted'::"public"."submission_status") OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"))))));



ALTER TABLE "public"."havs_log_items" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."havs_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."havs_tools" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."holidays" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."integration_email_accounts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."integration_oauth_providers" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."integration_storage_backends" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."invoice_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "invoice_clients admin all" ON "public"."invoice_clients" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



ALTER TABLE "public"."invoice_lines" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "invoice_lines admin all" ON "public"."invoice_lines" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



ALTER TABLE "public"."invoices" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "invoices admin all" ON "public"."invoices" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



ALTER TABLE "public"."nas_sync_queue" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."password_recovery_tokens" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "photos manage by parent manager" ON "public"."submission_photos" TO "authenticated" USING ("public"."can_manage_submission"("public"."submission_owner"("kind", "submission_id"))) WITH CHECK ("public"."can_manage_submission"("public"."submission_owner"("kind", "submission_id")));



CREATE POLICY "photos read" ON "public"."submission_photos" FOR SELECT TO "authenticated" USING ("public"."can_access_submission"("kind", "submission_id"));



CREATE POLICY "pi assigned read" ON "public"."plant_inspections" FOR SELECT TO "authenticated" USING ((("project_id" IS NOT NULL) AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id")));



CREATE POLICY "pi cjb_manager read" ON "public"."plant_inspections" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "pi delete admin or manager scope" ON "public"."plant_inspections" FOR DELETE TO "authenticated" USING ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "pi manage update" ON "public"."plant_inspections" FOR UPDATE TO "authenticated" USING ("public"."can_manage_submission"("worker_id")) WITH CHECK ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "pi owner insert" ON "public"."plant_inspections" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "pi read scope" ON "public"."plant_inspections" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "pi_items owner write" ON "public"."plant_inspection_items" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."plant_inspections" "p"
  WHERE (("p"."id" = "plant_inspection_items"."inspection_id") AND "public"."can_manage_submission"("p"."worker_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."plant_inspections" "p"
  WHERE (("p"."id" = "plant_inspection_items"."inspection_id") AND "public"."can_manage_submission"("p"."worker_id")))));



CREATE POLICY "pi_items read" ON "public"."plant_inspection_items" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."plant_inspections" "p"
  WHERE (("p"."id" = "plant_inspection_items"."inspection_id") AND (("p"."worker_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()))))));



ALTER TABLE "public"."plant" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "plant admin write" ON "public"."plant" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "plant read authed" ON "public"."plant" FOR SELECT TO "authenticated" USING (true);



ALTER TABLE "public"."plant_inspection_items" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."plant_inspections" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "profiles admin all" ON "public"."profiles" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "profiles self read" ON "public"."profiles" FOR SELECT TO "authenticated" USING ((("id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"())));



CREATE POLICY "profiles self update" ON "public"."profiles" FOR UPDATE TO "authenticated" USING (("id" = "auth"."uid"())) WITH CHECK (("id" = "auth"."uid"()));



ALTER TABLE "public"."project_assignments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."projects" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "projects admin update" ON "public"."projects" FOR UPDATE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "projects admin write" ON "public"."projects" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "projects read" ON "public"."projects" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role") OR ("archived_at" IS NULL)));



CREATE POLICY "rams assigned read" ON "public"."rams_briefings" FOR SELECT TO "authenticated" USING ((("project_id" IS NOT NULL) AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id")));



CREATE POLICY "rams cjb_manager read" ON "public"."rams_briefings" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "rams delete admin or manager scope" ON "public"."rams_briefings" FOR DELETE TO "authenticated" USING ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "rams manage update" ON "public"."rams_briefings" FOR UPDATE TO "authenticated" USING ("public"."can_manage_submission"("briefer_id")) WITH CHECK ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "rams owner insert" ON "public"."rams_briefings" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "rams read scope" ON "public"."rams_briefings" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "rams_att owner write" ON "public"."rams_attendees" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."rams_briefings" "b"
  WHERE (("b"."id" = "rams_attendees"."briefing_id") AND "public"."can_manage_submission"("b"."briefer_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."rams_briefings" "b"
  WHERE (("b"."id" = "rams_attendees"."briefing_id") AND "public"."can_manage_submission"("b"."briefer_id")))));



CREATE POLICY "rams_att read" ON "public"."rams_attendees" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."rams_briefings" "b"
  WHERE (("b"."id" = "rams_attendees"."briefing_id") AND (("b"."briefer_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()))))));



ALTER TABLE "public"."rams_attendees" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."rams_briefings" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "starter delete admin or manager scope" ON "public"."employee_starters" FOR DELETE TO "authenticated" USING ("public"."can_manage_submission"("user_id"));



CREATE POLICY "starter insert (self or manager scope)" ON "public"."employee_starters" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("user_id"));



CREATE POLICY "starter read scope" ON "public"."employee_starters" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("user_id"));



CREATE POLICY "starter update (self or manager scope)" ON "public"."employee_starters" FOR UPDATE TO "authenticated" USING ("public"."can_manage_submission"("user_id")) WITH CHECK ("public"."can_manage_submission"("user_id"));



ALTER TABLE "public"."subcontractors" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "subcontractors admin write" ON "public"."subcontractors" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "subcontractors read" ON "public"."subcontractors" FOR SELECT TO "authenticated" USING (true);



ALTER TABLE "public"."submission_photos" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "super_admin manage email accounts" ON "public"."integration_email_accounts" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"));



CREATE POLICY "super_admin manage oauth providers" ON "public"."integration_oauth_providers" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"));



CREATE POLICY "super_admin manage storage backends" ON "public"."integration_storage_backends" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"));



CREATE POLICY "tbx admin delete" ON "public"."toolbox_talks" FOR DELETE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "tbx assigned read" ON "public"."toolbox_talks" FOR SELECT TO "authenticated" USING ((("project_id" IS NOT NULL) AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id")));



CREATE POLICY "tbx cjb_manager read" ON "public"."toolbox_talks" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "tbx owner insert" ON "public"."toolbox_talks" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "tbx owner update" ON "public"."toolbox_talks" FOR UPDATE TO "authenticated" USING ((("briefer_id" = "auth"."uid"()) OR "public"."can_manage_submission"("briefer_id"))) WITH CHECK ((("briefer_id" = "auth"."uid"()) OR "public"."can_manage_submission"("briefer_id")));



CREATE POLICY "tbx read scope" ON "public"."toolbox_talks" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "tbx staff update" ON "public"."toolbox_talks" FOR UPDATE TO "authenticated" USING ("public"."is_staff"("auth"."uid"())) WITH CHECK ("public"."is_staff"("auth"."uid"()));



CREATE POLICY "tbx_att owner write" ON "public"."toolbox_attendees" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."toolbox_talks" "t"
  WHERE (("t"."id" = "toolbox_attendees"."talk_id") AND "public"."can_manage_submission"("t"."briefer_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."toolbox_talks" "t"
  WHERE (("t"."id" = "toolbox_attendees"."talk_id") AND "public"."can_manage_submission"("t"."briefer_id")))));



CREATE POLICY "tbx_att read" ON "public"."toolbox_attendees" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."toolbox_talks" "t"
  WHERE (("t"."id" = "toolbox_attendees"."talk_id") AND (("t"."briefer_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()))))));



ALTER TABLE "public"."timesheet_days" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "timesheet_days owner write unapproved" ON "public"."timesheet_days" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."timesheets" "t"
  WHERE (("t"."id" = "timesheet_days"."timesheet_id") AND ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR (("t"."worker_id" = "auth"."uid"()) AND (("t"."status" <> 'approved'::"public"."submission_status") OR "public"."is_staff"("auth"."uid"()) OR ("t"."change_requested_at" IS NOT NULL))) OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("t"."worker_id")))))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."timesheets" "t"
  WHERE (("t"."id" = "timesheet_days"."timesheet_id") AND ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR (("t"."worker_id" = "auth"."uid"()) AND (("t"."status" <> 'approved'::"public"."submission_status") OR "public"."is_staff"("auth"."uid"()) OR ("t"."change_requested_at" IS NOT NULL))) OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("t"."worker_id"))))))));



CREATE POLICY "timesheet_days read" ON "public"."timesheet_days" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."timesheets" "t"
  WHERE (("t"."id" = "timesheet_days"."timesheet_id") AND (("t"."worker_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()))))));



ALTER TABLE "public"."timesheets" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "timesheets delete admin owner-unapproved or manager scope" ON "public"."timesheets" FOR DELETE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR (("worker_id" = "auth"."uid"()) AND ("status" <> 'approved'::"public"."submission_status")) OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND (NOT "public"."is_staff"("worker_id")) AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("worker_id")))));



CREATE POLICY "timesheets insert owner or manager scope" ON "public"."timesheets" FOR INSERT TO "authenticated" WITH CHECK ((("worker_id" = "auth"."uid"()) OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("worker_id")))));



CREATE POLICY "timesheets read scope" ON "public"."timesheets" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "timesheets update owner unapproved or staff" ON "public"."timesheets" FOR UPDATE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR (("worker_id" = "auth"."uid"()) AND (("status" <> 'approved'::"public"."submission_status") OR ("change_requested_at" IS NOT NULL))) OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND (NOT "public"."is_staff"("worker_id")) AND ("public"."user_subcontractor"("auth"."uid"()) IS NOT NULL) AND ("public"."user_subcontractor"("auth"."uid"()) = "public"."user_subcontractor"("worker_id")))));



ALTER TABLE "public"."toolbox_attendees" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."toolbox_talks" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "user_roles admin all" ON "public"."user_roles" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "user_roles self read" ON "public"."user_roles" FOR SELECT TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"())));



CREATE POLICY "vd cjb_manager read" ON "public"."vehicle_defects" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "vd delete admin or manager scope" ON "public"."vehicle_defects" FOR DELETE TO "authenticated" USING ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "vd manage update" ON "public"."vehicle_defects" FOR UPDATE TO "authenticated" USING ("public"."can_manage_submission"("worker_id")) WITH CHECK ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "vd owner insert" ON "public"."vehicle_defects" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "vd read scope" ON "public"."vehicle_defects" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("worker_id"));



CREATE POLICY "vd_items owner write" ON "public"."vehicle_defect_items" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."vehicle_defects" "v"
  WHERE (("v"."id" = "vehicle_defect_items"."defect_id") AND "public"."can_manage_submission"("v"."worker_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."vehicle_defects" "v"
  WHERE (("v"."id" = "vehicle_defect_items"."defect_id") AND "public"."can_manage_submission"("v"."worker_id")))));



CREATE POLICY "vd_items read" ON "public"."vehicle_defect_items" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."vehicle_defects" "v"
  WHERE (("v"."id" = "vehicle_defect_items"."defect_id") AND (("v"."worker_id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()))))));



ALTER TABLE "public"."vehicle_defect_items" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicle_defects" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicles admin write" ON "public"."vehicles" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "vehicles read authed" ON "public"."vehicles" FOR SELECT TO "authenticated" USING (true);





ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";


SET SESSION AUTHORIZATION "postgres";
RESET SESSION AUTHORIZATION;






GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";








































































































































































































































































REVOKE ALL ON FUNCTION "public"."admin_set_vault_secret"("p_name" "text", "p_value" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."admin_set_vault_secret"("p_name" "text", "p_value" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."bump_revision"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."bump_revision"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."company_match_key"("p_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."company_match_key"("p_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."company_match_key"("p_name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."continue_cost_scan"("p_url" "text", "p_apikey" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."continue_cost_scan"("p_url" "text", "p_apikey" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."cost_invoices_apply_canonical_company"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cost_invoices_apply_canonical_company"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."daily_briefing_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."daily_briefing_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."delete_integration_secret"("p_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."delete_integration_secret"("p_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_integration_secret"("p_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."email_domain"("p_from" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."email_domain"("p_from" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."email_domain"("p_from" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."force_approved_status"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."force_approved_status"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_integration_secret"("p_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_integration_secret"("p_name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."handle_new_user"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") TO "authenticated";
GRANT ALL ON FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") TO "service_role";



REVOKE ALL ON FUNCTION "public"."havs_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."havs_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."holidays_amend_resets_status"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."holidays_amend_resets_status"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."holidays_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."holidays_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."holidays_enforce_status_change"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."holidays_enforce_status_change"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."invoices_before_insert"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."invoices_before_insert"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_generic_email_domain"("p_domain" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_generic_email_domain"("p_domain" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_generic_email_domain"("p_domain" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_staff"("_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_staff"("_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_staff"("_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."match_subcontractor_by_company"("p_company" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."match_subcontractor_by_company"("p_company" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."profiles_guard_sensitive_self_update"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."profiles_guard_sensitive_self_update"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."resolve_cost_company_canonical"("p_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."resolve_cost_company_canonical"("p_name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."rls_auto_enable"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_updated_at"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_updated_at_havs_tools"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_updated_at_havs_tools"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."timesheet_days_touch_parent"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."timesheet_days_touch_parent"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."timesheets_snapshot_and_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."timesheets_snapshot_and_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."toolbox_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."toolbox_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") TO "service_role";
GRANT ALL ON FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") TO "authenticated";



GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."user_subcontractor"("_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."user_subcontractor"("_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."user_subcontractor"("_user_id" "uuid") TO "service_role";
























GRANT ALL ON TABLE "public"."app_settings" TO "anon";
GRANT ALL ON TABLE "public"."app_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."app_settings" TO "service_role";



GRANT ALL ON TABLE "public"."clients" TO "anon";
GRANT ALL ON TABLE "public"."clients" TO "authenticated";
GRANT ALL ON TABLE "public"."clients" TO "service_role";



GRANT ALL ON TABLE "public"."cost_company_aliases" TO "anon";
GRANT ALL ON TABLE "public"."cost_company_aliases" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_company_aliases" TO "service_role";



GRANT ALL ON TABLE "public"."cost_company_domain_aliases" TO "anon";
GRANT ALL ON TABLE "public"."cost_company_domain_aliases" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_company_domain_aliases" TO "service_role";



GRANT ALL ON TABLE "public"."cost_company_subcontractors" TO "anon";
GRANT ALL ON TABLE "public"."cost_company_subcontractors" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_company_subcontractors" TO "service_role";



GRANT ALL ON TABLE "public"."cost_dated_scans" TO "anon";
GRANT ALL ON TABLE "public"."cost_dated_scans" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_dated_scans" TO "service_role";



GRANT ALL ON TABLE "public"."cost_invoice_splits" TO "anon";
GRANT ALL ON TABLE "public"."cost_invoice_splits" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_invoice_splits" TO "service_role";



GRANT ALL ON TABLE "public"."cost_invoices" TO "anon";
GRANT ALL ON TABLE "public"."cost_invoices" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_invoices" TO "service_role";



GRANT ALL ON TABLE "public"."cost_scan_skips" TO "anon";
GRANT ALL ON TABLE "public"."cost_scan_skips" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_scan_skips" TO "service_role";



GRANT ALL ON TABLE "public"."cost_scan_state" TO "anon";
GRANT ALL ON TABLE "public"."cost_scan_state" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_scan_state" TO "service_role";



GRANT ALL ON SEQUENCE "public"."cost_scan_state_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."cost_scan_state_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."cost_scan_state_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."cost_skip_attachments" TO "anon";
GRANT ALL ON TABLE "public"."cost_skip_attachments" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_skip_attachments" TO "service_role";



GRANT ALL ON TABLE "public"."daily_briefing_attendees" TO "anon";
GRANT ALL ON TABLE "public"."daily_briefing_attendees" TO "authenticated";
GRANT ALL ON TABLE "public"."daily_briefing_attendees" TO "service_role";



GRANT ALL ON TABLE "public"."daily_briefing_hazards" TO "anon";
GRANT ALL ON TABLE "public"."daily_briefing_hazards" TO "authenticated";
GRANT ALL ON TABLE "public"."daily_briefing_hazards" TO "service_role";



GRANT ALL ON TABLE "public"."daily_briefings" TO "anon";
GRANT ALL ON TABLE "public"."daily_briefings" TO "authenticated";
GRANT ALL ON TABLE "public"."daily_briefings" TO "service_role";



GRANT ALL ON TABLE "public"."employee_pay" TO "anon";
GRANT ALL ON TABLE "public"."employee_pay" TO "authenticated";
GRANT ALL ON TABLE "public"."employee_pay" TO "service_role";



GRANT ALL ON TABLE "public"."employee_starters" TO "anon";
GRANT ALL ON TABLE "public"."employee_starters" TO "authenticated";
GRANT ALL ON TABLE "public"."employee_starters" TO "service_role";



GRANT ALL ON TABLE "public"."havs_log_items" TO "anon";
GRANT ALL ON TABLE "public"."havs_log_items" TO "authenticated";
GRANT ALL ON TABLE "public"."havs_log_items" TO "service_role";



GRANT ALL ON TABLE "public"."havs_logs" TO "anon";
GRANT ALL ON TABLE "public"."havs_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."havs_logs" TO "service_role";



GRANT ALL ON TABLE "public"."havs_tools" TO "anon";
GRANT ALL ON TABLE "public"."havs_tools" TO "authenticated";
GRANT ALL ON TABLE "public"."havs_tools" TO "service_role";



GRANT ALL ON TABLE "public"."holidays" TO "anon";
GRANT ALL ON TABLE "public"."holidays" TO "authenticated";
GRANT ALL ON TABLE "public"."holidays" TO "service_role";



GRANT ALL ON TABLE "public"."integration_email_accounts" TO "anon";
GRANT ALL ON TABLE "public"."integration_email_accounts" TO "authenticated";
GRANT ALL ON TABLE "public"."integration_email_accounts" TO "service_role";



GRANT ALL ON TABLE "public"."integration_oauth_providers" TO "anon";
GRANT ALL ON TABLE "public"."integration_oauth_providers" TO "authenticated";
GRANT ALL ON TABLE "public"."integration_oauth_providers" TO "service_role";



GRANT ALL ON TABLE "public"."integration_storage_backends" TO "anon";
GRANT ALL ON TABLE "public"."integration_storage_backends" TO "authenticated";
GRANT ALL ON TABLE "public"."integration_storage_backends" TO "service_role";



GRANT ALL ON TABLE "public"."invoice_clients" TO "anon";
GRANT ALL ON TABLE "public"."invoice_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."invoice_clients" TO "service_role";



GRANT ALL ON TABLE "public"."invoice_lines" TO "anon";
GRANT ALL ON TABLE "public"."invoice_lines" TO "authenticated";
GRANT ALL ON TABLE "public"."invoice_lines" TO "service_role";



GRANT ALL ON TABLE "public"."invoices" TO "anon";
GRANT ALL ON TABLE "public"."invoices" TO "authenticated";
GRANT ALL ON TABLE "public"."invoices" TO "service_role";



GRANT ALL ON TABLE "public"."nas_sync_queue" TO "anon";
GRANT ALL ON TABLE "public"."nas_sync_queue" TO "authenticated";
GRANT ALL ON TABLE "public"."nas_sync_queue" TO "service_role";



GRANT ALL ON TABLE "public"."password_recovery_tokens" TO "anon";
GRANT ALL ON TABLE "public"."password_recovery_tokens" TO "authenticated";
GRANT ALL ON TABLE "public"."password_recovery_tokens" TO "service_role";



GRANT ALL ON TABLE "public"."plant" TO "anon";
GRANT ALL ON TABLE "public"."plant" TO "authenticated";
GRANT ALL ON TABLE "public"."plant" TO "service_role";



GRANT ALL ON TABLE "public"."plant_inspection_items" TO "anon";
GRANT ALL ON TABLE "public"."plant_inspection_items" TO "authenticated";
GRANT ALL ON TABLE "public"."plant_inspection_items" TO "service_role";



GRANT ALL ON TABLE "public"."plant_inspections" TO "anon";
GRANT ALL ON TABLE "public"."plant_inspections" TO "authenticated";
GRANT ALL ON TABLE "public"."plant_inspections" TO "service_role";



GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE "public"."profiles" TO "anon";
GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE "public"."profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."profiles" TO "service_role";



GRANT SELECT("id") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("id") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("username") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("username") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("full_name") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("full_name") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("active") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("active") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("created_at") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("created_at") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("subcontractor_id") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("subcontractor_id") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("must_reset_password") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("must_reset_password") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("last_active_at") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("last_active_at") ON TABLE "public"."profiles" TO "authenticated";



GRANT SELECT("mfa_enabled") ON TABLE "public"."profiles" TO "anon";
GRANT SELECT("mfa_enabled") ON TABLE "public"."profiles" TO "authenticated";



GRANT ALL ON TABLE "public"."project_assignments" TO "anon";
GRANT ALL ON TABLE "public"."project_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."project_assignments" TO "service_role";



GRANT ALL ON TABLE "public"."projects" TO "anon";
GRANT ALL ON TABLE "public"."projects" TO "authenticated";
GRANT ALL ON TABLE "public"."projects" TO "service_role";



GRANT ALL ON TABLE "public"."rams_attendees" TO "anon";
GRANT ALL ON TABLE "public"."rams_attendees" TO "authenticated";
GRANT ALL ON TABLE "public"."rams_attendees" TO "service_role";



GRANT ALL ON TABLE "public"."rams_briefings" TO "anon";
GRANT ALL ON TABLE "public"."rams_briefings" TO "authenticated";
GRANT ALL ON TABLE "public"."rams_briefings" TO "service_role";



GRANT ALL ON TABLE "public"."subcontractors" TO "anon";
GRANT ALL ON TABLE "public"."subcontractors" TO "authenticated";
GRANT ALL ON TABLE "public"."subcontractors" TO "service_role";



GRANT ALL ON TABLE "public"."submission_photos" TO "anon";
GRANT ALL ON TABLE "public"."submission_photos" TO "authenticated";
GRANT ALL ON TABLE "public"."submission_photos" TO "service_role";



GRANT ALL ON TABLE "public"."timesheet_days" TO "anon";
GRANT ALL ON TABLE "public"."timesheet_days" TO "authenticated";
GRANT ALL ON TABLE "public"."timesheet_days" TO "service_role";



GRANT ALL ON TABLE "public"."timesheets" TO "anon";
GRANT ALL ON TABLE "public"."timesheets" TO "authenticated";
GRANT ALL ON TABLE "public"."timesheets" TO "service_role";



GRANT ALL ON TABLE "public"."toolbox_attendees" TO "anon";
GRANT ALL ON TABLE "public"."toolbox_attendees" TO "authenticated";
GRANT ALL ON TABLE "public"."toolbox_attendees" TO "service_role";



GRANT ALL ON TABLE "public"."toolbox_talks" TO "anon";
GRANT ALL ON TABLE "public"."toolbox_talks" TO "authenticated";
GRANT ALL ON TABLE "public"."toolbox_talks" TO "service_role";



GRANT ALL ON TABLE "public"."user_roles" TO "anon";
GRANT ALL ON TABLE "public"."user_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_roles" TO "service_role";



GRANT ALL ON TABLE "public"."vehicle_defect_items" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_defect_items" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_defect_items" TO "service_role";



GRANT ALL ON TABLE "public"."vehicle_defects" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_defects" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_defects" TO "service_role";



GRANT ALL ON TABLE "public"."vehicles" TO "anon";
GRANT ALL ON TABLE "public"."vehicles" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicles" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";



































