


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


CREATE OR REPLACE FUNCTION "public"."aggregate_cost_invoices"("p_f_text" "text" DEFAULT ''::"text", "p_f_description" "text" DEFAULT ''::"text", "p_f_treatment" "text" DEFAULT ''::"text", "p_f_status" "text" DEFAULT ''::"text", "p_f_doc_type" "text" DEFAULT ''::"text", "p_f_company" "text" DEFAULT ''::"text", "p_f_from" "date" DEFAULT NULL::"date", "p_f_to" "date" DEFAULT NULL::"date", "p_f_po" "text" DEFAULT ''::"text", "p_f_due_from" "date" DEFAULT NULL::"date", "p_f_due_to" "date" DEFAULT NULL::"date", "p_f_paid" "text" DEFAULT ''::"text", "p_f_cis" "text" DEFAULT ''::"text", "p_f_project" "text" DEFAULT ''::"text", "p_f_check" "text" DEFAULT ''::"text", "p_dup_only" boolean DEFAULT false, "p_missing_due_date" boolean DEFAULT false, "p_payment_month" "text" DEFAULT NULL::"text") RETURNS "jsonb"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
  WITH filtered AS (
    SELECT ci.*
    FROM public.cost_invoices ci
    WHERE public.cost_invoice_passes_filters(
      ci,
      p_f_text, p_f_description, p_f_treatment, p_f_status, p_f_doc_type, p_f_company,
      p_f_from, p_f_to, p_f_po, p_f_due_from, p_f_due_to, p_f_paid, p_f_cis,
      p_f_project, p_f_check, p_dup_only, p_missing_due_date
    )
  ),
  filtered_for_missing_count AS (
    SELECT ci.*
    FROM public.cost_invoices ci
    WHERE public.cost_invoice_passes_filters(
      ci,
      p_f_text, p_f_description, p_f_treatment, p_f_status, p_f_doc_type, p_f_company,
      p_f_from, p_f_to, p_f_po, p_f_due_from, p_f_due_to, p_f_paid, p_f_cis,
      p_f_project, p_f_check, p_dup_only,
      false
    )
  ),
  missing_due_date_count AS (
    SELECT count(*)::bigint AS cnt
    FROM filtered_for_missing_count f
    WHERE f.due_date IS NULL
  ),
  payment_end AS (
    SELECT CASE
      WHEN p_payment_month IS NULL OR p_payment_month !~ '^\d{4}-\d{2}$' THEN NULL::date
      ELSE (
        (split_part(p_payment_month, '-', 1) || '-' || split_part(p_payment_month, '-', 2) || '-01')::date
        + interval '1 month'
        - interval '1 day'
      )::date
    END AS end_date
  ),
  split_qty AS (
    SELECT coalesce(sum(s.quantity), 0) AS split_quantity_total
    FROM filtered f
    INNER JOIN public.cost_invoice_splits s ON s.cost_invoice_id = f.id
    WHERE cardinality(public.parse_description_filter_terms(p_f_description)) > 0
      AND public.split_line_matches_description_filter(s.description, p_f_description)
  ),
  summary AS (
    SELECT
      coalesce(sum(coalesce(f.total_amount, f.net_amount + coalesce(f.vat_amount, 0))), 0) AS spend,
      coalesce(sum(CASE WHEN f.vat_treatment = 'standard_20' THEN coalesce(f.vat_amount, 0) ELSE 0 END), 0) AS input_vat,
      coalesce(sum(CASE WHEN f.vat_treatment = 'reverse_charge' THEN coalesce(f.net_amount, 0) ELSE 0 END), 0) AS rc_net,
      coalesce(sum(coalesce(f.cis_amount, 0)), 0) AS cis,
      count(*) FILTER (WHERE f.status = 'pending_review') AS pending,
      count(*) FILTER (WHERE f.is_duplicate OR f.has_duplicate_siblings) AS dupes,
      coalesce(sum(coalesce(f.net_amount, 0)), 0) AS net,
      count(*) FILTER (WHERE f.paid_at IS NULL) AS unpaid_count
    FROM filtered f
  ),
  company_rows AS (
    SELECT
      coalesce(f.company_name, 'NA') AS company,
      coalesce(f.net_amount, 0) AS net,
      coalesce(f.vat_amount, 0) AS vat,
      coalesce(f.cis_amount, 0) AS cis,
      coalesce(f.total_amount, coalesce(f.net_amount, 0) + coalesce(f.vat_amount, 0)) AS total,
      f.paid_at,
      f.status,
      f.due_date,
      f.payment_reminded_at,
      f.payment_reminder_dismissed_at
    FROM filtered f
  ),
  company_groups AS (
    SELECT
      cr.company,
      sum(cr.net) AS net,
      sum(cr.vat) AS vat,
      sum(cr.cis) AS cis,
      sum(cr.total) AS total,
      sum(cr.total) FILTER (WHERE cr.paid_at IS NOT NULL) AS total_paid,
      sum(cr.total) FILTER (WHERE cr.paid_at IS NULL) AS total_unpaid,
      sum(cr.total) FILTER (
        WHERE cr.status = 'reviewed'
          AND cr.paid_at IS NULL
          AND cr.due_date IS NOT NULL
          AND (SELECT end_date FROM payment_end) IS NOT NULL
          AND cr.due_date <= (SELECT end_date FROM payment_end)
      ) AS payment_due,
      count(*) FILTER (
        WHERE cr.status = 'reviewed'
          AND cr.paid_at IS NULL
          AND cr.due_date IS NOT NULL
          AND (SELECT end_date FROM payment_end) IS NOT NULL
          AND cr.due_date <= (SELECT end_date FROM payment_end)
      ) AS payment_due_count,
      count(*) FILTER (WHERE cr.status = 'pending_review') AS pending,
      count(*) FILTER (WHERE cr.status = 'reviewed') AS reviewed,
      count(*) FILTER (WHERE cr.status = 'rejected') AS rejected,
      count(*) AS count,
      count(*) FILTER (WHERE cr.paid_at IS NOT NULL) AS paid_count,
      bool_or(cr.payment_reminded_at IS NOT NULL AND cr.paid_at IS NULL) AS payment_reminded,
      bool_or(cr.payment_reminder_dismissed_at IS NOT NULL AND cr.paid_at IS NULL) AS payment_reminder_dismissed
    FROM company_rows cr
    GROUP BY cr.company
  )
  SELECT jsonb_build_object(
    'summary', (
      SELECT jsonb_build_object(
        'spend', s.spend,
        'inputVat', s.input_vat,
        'rcNet', s.rc_net,
        'cis', s.cis,
        'pending', s.pending,
        'dupes', s.dupes,
        'net', s.net,
        'unpaidCount', s.unpaid_count,
        'missingDueDateCount', (SELECT cnt FROM missing_due_date_count),
        'splitQuantityTotal', (SELECT split_quantity_total FROM split_qty)
      )
      FROM summary s
    ),
    'groups', coalesce(
      (
        SELECT jsonb_agg(
          jsonb_build_object(
            'company', g.company,
            'net', g.net,
            'vat', g.vat,
            'cis', g.cis,
            'total', g.total,
            'totalPaid', g.total_paid,
            'totalUnpaid', g.total_unpaid,
            'paymentDue', g.payment_due,
            'paymentDueCount', g.payment_due_count,
            'pending', g.pending,
            'reviewed', g.reviewed,
            'rejected', g.rejected,
            'count', g.count,
            'paidCount', g.paid_count,
            'paymentReminded', g.payment_reminded,
            'paymentReminderDismissed', g.payment_reminder_dismissed,
            'allPaid', g.count > 0 AND g.paid_count = g.count
          )
          ORDER BY g.total DESC
        )
        FROM company_groups g
      ),
      '[]'::jsonb
    ),
    'totals', (
      SELECT jsonb_build_object(
        'net', coalesce(sum(g.net), 0),
        'vat', coalesce(sum(g.vat), 0),
        'cis', coalesce(sum(g.cis), 0),
        'total', coalesce(sum(g.total), 0),
        'totalPaid', coalesce(sum(g.total_paid), 0),
        'totalUnpaid', coalesce(sum(g.total_unpaid), 0),
        'paymentDue', coalesce(sum(g.payment_due), 0),
        'paymentDueCount', coalesce(sum(g.payment_due_count), 0),
        'pending', coalesce(sum(g.pending), 0),
        'reviewed', coalesce(sum(g.reviewed), 0),
        'rejected', coalesce(sum(g.rejected), 0),
        'count', coalesce(sum(g.count), 0),
        'paidCount', coalesce(sum(g.paid_count), 0),
        'allPaid', coalesce(sum(g.count), 0) > 0 AND coalesce(sum(g.paid_count), 0) = coalesce(sum(g.count), 0)
      )
      FROM company_groups g
    )
  );
$_$;


ALTER FUNCTION "public"."aggregate_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_payment_month" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."aggregate_invoices"("p_f_text" "text" DEFAULT ''::"text", "p_f_client" "uuid" DEFAULT NULL::"uuid", "p_f_from" "date" DEFAULT NULL::"date", "p_f_to" "date" DEFAULT NULL::"date", "p_f_vat" "text" DEFAULT ''::"text", "p_f_project" "uuid" DEFAULT NULL::"uuid") RETURNS "jsonb"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  WITH filtered AS (
    SELECT i.*
    FROM public.invoices i
    WHERE public.outgoing_invoice_passes_filters(
      i, p_f_text, p_f_client, p_f_from, p_f_to, p_f_vat, p_f_project
    )
  ),
  invoice_nets AS (
    SELECT
      f.id,
      coalesce(nullif(trim(f.client_name_snapshot), ''), '—') AS client_name,
      CASE
        WHEN p_f_project IS NOT NULL THEN (
          SELECT coalesce(sum(il.amount_net), 0)
          FROM public.invoice_lines il
          WHERE il.invoice_id = f.id
            AND il.project_id = p_f_project
        )
        ELSE coalesce(f.amount_net, 0)
      END AS net
    FROM filtered f
  ),
  client_groups AS (
    SELECT
      n.client_name,
      count(*)::bigint AS invoice_count,
      coalesce(sum(n.net), 0) AS net_total
    FROM invoice_nets n
    GROUP BY n.client_name
  )
  SELECT jsonb_build_object(
    'count', (SELECT count(*)::bigint FROM filtered),
    'totalNet', (SELECT coalesce(sum(net), 0) FROM invoice_nets),
    'byClient', coalesce(
      (
        SELECT jsonb_agg(
          jsonb_build_object(
            'name', g.client_name,
            'count', g.invoice_count,
            'net', g.net_total
          )
          ORDER BY g.net_total DESC, g.client_name ASC
        )
        FROM client_groups g
      ),
      '[]'::jsonb
    )
  );
$$;


ALTER FUNCTION "public"."aggregate_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."auto_assign_todo_list_creator"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF NEW.created_by IS NOT NULL THEN
    INSERT INTO public.todo_list_assignments (list_id, user_id, assigned_by)
    VALUES (NEW.id, NEW.created_by, NEW.created_by)
    ON CONFLICT (list_id, user_id) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."auto_assign_todo_list_creator"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."backfill_todo_list_subcontractor_sync"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  INSERT INTO public.todo_list_assignments (list_id, user_id, assigned_by)
  SELECT NEW.list_id, p.id, NEW.synced_by
  FROM public.profiles p
  WHERE p.subcontractor_id = NEW.subcontractor_id
    AND COALESCE(p.active, true)
  ON CONFLICT (list_id, user_id) DO NOTHING;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."backfill_todo_list_subcontractor_sync"() OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."can_access_todo_item"("_user_id" "uuid", "_item_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.todo_items ti
    WHERE ti.id = _item_id
      AND public.can_access_todo_list(_user_id, ti.list_id)
  )
$$;


ALTER FUNCTION "public"."can_access_todo_item"("_user_id" "uuid", "_item_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_access_todo_list"("_user_id" "uuid", "_list_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT public.has_role(_user_id, 'super_admin'::app_role)
  OR (
    EXISTS (
      SELECT 1 FROM public.todo_lists
      WHERE id = _list_id AND archived_at IS NULL
    )
    AND public.is_assigned_to_todo_list(_user_id, _list_id)
  )
$$;


ALTER FUNCTION "public"."can_access_todo_list"("_user_id" "uuid", "_list_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_assign_todo_list"("_assigner_id" "uuid", "_list_id" "uuid", "_target_user_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT
    public.has_role(_assigner_id, 'super_admin'::app_role)
    OR (
      public.has_role(_assigner_id, 'admin'::app_role)
      AND (
        public.is_assigned_to_todo_list(_assigner_id, _list_id)
        OR EXISTS (
          SELECT 1 FROM public.todo_lists
          WHERE id = _list_id AND created_by = _assigner_id
        )
      )
    )
    OR (
      public.has_role(_assigner_id, 'cjb_manager'::app_role)
      AND (
        public.is_assigned_to_todo_list(_assigner_id, _list_id)
        OR EXISTS (
          SELECT 1 FROM public.todo_lists
          WHERE id = _list_id AND created_by = _assigner_id
        )
      )
    )
    OR (
      public.has_role(_assigner_id, 'manager'::app_role)
      AND (
        public.is_assigned_to_todo_list(_assigner_id, _list_id)
        OR EXISTS (
          SELECT 1 FROM public.todo_lists
          WHERE id = _list_id AND created_by = _assigner_id
        )
      )
      AND (
        (
          public.user_subcontractor(_assigner_id) IS NOT NULL
          AND public.user_subcontractor(_assigner_id) = public.user_subcontractor(_target_user_id)
        )
        OR public.has_role(_target_user_id, 'manager'::app_role)
      )
    )
$$;


ALTER FUNCTION "public"."can_assign_todo_list"("_assigner_id" "uuid", "_list_id" "uuid", "_target_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_complete_todo_item"("_user_id" "uuid", "_item_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.todo_items ti
    WHERE ti.id = _item_id
      AND public.can_access_todo_list(_user_id, ti.list_id)
  )
$$;


ALTER FUNCTION "public"."can_complete_todo_item"("_user_id" "uuid", "_item_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_delete_todo_list"("_user_id" "uuid", "_list_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT
    public.has_role(_user_id, 'super_admin'::app_role)
    OR (
      public.has_role(_user_id, 'admin'::app_role)
      AND public.is_assigned_to_todo_list(_user_id, _list_id)
    )
    OR (
      public.has_role(_user_id, 'manager'::app_role)
      AND public.is_assigned_to_todo_list(_user_id, _list_id)
      AND public.user_subcontractor(_user_id) IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM public.todo_list_assignments tla
        WHERE tla.list_id = _list_id
      )
      AND NOT EXISTS (
        SELECT 1
        FROM public.todo_list_assignments tla
        JOIN public.profiles p ON p.id = tla.user_id
        WHERE tla.list_id = _list_id
          AND (
            p.subcontractor_id IS NULL
            OR p.subcontractor_id <> public.user_subcontractor(_user_id)
          )
      )
    )
$$;


ALTER FUNCTION "public"."can_delete_todo_list"("_user_id" "uuid", "_list_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_manage_rams_briefing"("_briefer_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT
    public.can_manage_submission(_briefer_id)
    OR public.has_role(auth.uid(), 'cjb_manager')
$$;


ALTER FUNCTION "public"."can_manage_rams_briefing"("_briefer_id" "uuid") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."can_modify_todo_item"("_user_id" "uuid", "_item_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.todo_items ti
    WHERE ti.id = _item_id
      AND (
        public.has_role(_user_id, 'super_admin'::app_role)
        OR (
          public.can_access_todo_list(_user_id, ti.list_id)
          AND (
            public.has_role(_user_id, 'admin'::app_role)
            OR (
              public.has_role(_user_id, 'worker'::app_role)
              AND ti.created_by = _user_id
            )
            OR (
              public.has_role(_user_id, 'cjb_manager'::app_role)
              AND ti.created_by = _user_id
            )
            OR (
              public.has_role(_user_id, 'manager'::app_role)
              AND (
                ti.created_by = _user_id
                OR (
                  ti.created_by IS NOT NULL
                  AND public.has_role(ti.created_by, 'worker'::app_role)
                  AND public.user_subcontractor(_user_id) IS NOT NULL
                  AND public.user_subcontractor(_user_id) = public.user_subcontractor(ti.created_by)
                )
              )
            )
          )
        )
      )
  )
$$;


ALTER FUNCTION "public"."can_modify_todo_item"("_user_id" "uuid", "_item_id" "uuid") OWNER TO "postgres";


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

SET default_tablespace = '';

SET default_table_access_method = "heap";


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
    "supplier_email_domain" "text",
    "invoice_format_key" "text",
    "supplier_id" "uuid",
    "supplier_vat_number" "text",
    "supplier_company_reg_number" "text",
    "payment_reminded_at" timestamp with time zone,
    "full_field_dedupe_key" "text",
    "has_duplicate_siblings" boolean DEFAULT false NOT NULL,
    "search_document" "tsvector",
    "payment_reminder_month" "text",
    "payment_reminder_dismissed_at" timestamp with time zone,
    CONSTRAINT "cost_invoices_document_type_check" CHECK (("document_type" = ANY (ARRAY['invoice'::"text", 'credit_note'::"text"])))
);


ALTER TABLE "public"."cost_invoices" OWNER TO "postgres";


COMMENT ON COLUMN "public"."cost_invoices"."payment_reminder_month" IS 'YYYY-MM payment month when a payment reminder was sent (costs notify-to-pay).';



COMMENT ON COLUMN "public"."cost_invoices"."payment_reminder_dismissed_at" IS 'When a payment reminder was dismissed without marking invoices paid.';



CREATE OR REPLACE FUNCTION "public"."cost_invoice_build_search_document"("p_row" "public"."cost_invoices") RETURNS "tsvector"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT to_tsvector(
    'english',
    concat_ws(
      ' ',
      p_row.company_name,
      p_row.invoice_number,
      p_row.po_reference,
      p_row.description,
      p_row.source_subject
    )
  );
$$;


ALTER FUNCTION "public"."cost_invoice_build_search_document"("p_row" "public"."cost_invoices") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_ci_dedupe_key"("p_company_invoice_key" "text", "p_invoice_number_key" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT CASE
    WHEN p_company_invoice_key IS NULL OR btrim(p_company_invoice_key) = ''
      OR p_invoice_number_key IS NULL
      OR p_invoice_number_key IN ('NA','N/A','NO-NUMBER','NONUMBER','NO_NUMBER')
    THEN NULL ELSE p_company_invoice_key || '|' || p_invoice_number_key END;
$$;


ALTER FUNCTION "public"."cost_invoice_ci_dedupe_key"("p_company_invoice_key" "text", "p_invoice_number_key" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_full_field_dedupe_key"("p_company_name" "text", "p_invoice_number" "text", "p_po_reference" "text", "p_invoice_date" "date", "p_due_date" "date", "p_description" "text", "p_net_amount" numeric, "p_vat_amount" numeric, "p_total_amount" numeric, "p_vat_treatment" "text", "p_currency" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT nullif(regexp_replace(concat_ws('|',
    public.cost_invoice_norm_text(p_company_name),
    public.cost_invoice_norm_text(p_invoice_number),
    public.cost_invoice_norm_text(p_po_reference),
    public.cost_invoice_norm_text(to_char(p_invoice_date, 'YYYY-MM-DD')),
    public.cost_invoice_norm_text(to_char(p_due_date, 'YYYY-MM-DD')),
    public.cost_invoice_norm_text(p_description),
    public.cost_invoice_norm_amount(p_net_amount),
    public.cost_invoice_norm_amount(p_vat_amount),
    public.cost_invoice_norm_amount(p_total_amount),
    public.cost_invoice_norm_text(p_vat_treatment),
    public.cost_invoice_norm_text(p_currency)
  ), '\|', '', 'g'), '');
$$;


ALTER FUNCTION "public"."cost_invoice_full_field_dedupe_key"("p_company_name" "text", "p_invoice_number" "text", "p_po_reference" "text", "p_invoice_date" "date", "p_due_date" "date", "p_description" "text", "p_net_amount" numeric, "p_vat_amount" numeric, "p_total_amount" numeric, "p_vat_treatment" "text", "p_currency" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_invoice_project_label"("p_project_id" "uuid", "p_project_other" "text", "p_is_overhead" boolean, "p_project_code" "text", "p_project_description" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT CASE
    WHEN coalesce(p_is_overhead, false) THEN 'Overhead'
    WHEN p_project_id IS NOT NULL THEN
      CASE
        WHEN coalesce(p_project_description, '') <> '' THEN p_project_code || ' — ' || p_project_description
        ELSE p_project_code
      END
    ELSE nullif(p_project_other, '')
  END;
$$;


ALTER FUNCTION "public"."cost_invoice_invoice_project_label"("p_project_id" "uuid", "p_project_other" "text", "p_is_overhead" boolean, "p_project_code" "text", "p_project_description" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_matches_project"("p_invoice" "public"."cost_invoices", "p_split_project_id" "uuid", "p_split_project_other" "text", "p_split_is_overhead" boolean, "p_f_project" "text") RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT CASE
    WHEN coalesce(nullif(trim(p_f_project), ''), NULL) IS NULL THEN true
    WHEN left(p_f_project, 6) = 'other:' THEN
      (
        p_invoice.project_id IS NULL
        AND NOT coalesce(p_invoice.is_overhead, false)
        AND coalesce(p_invoice.project_other, '') = substring(p_f_project FROM 7)
      )
      OR (
        p_split_project_id IS NULL
        AND NOT coalesce(p_split_is_overhead, false)
        AND coalesce(p_split_project_other, '') = substring(p_f_project FROM 7)
      )
    ELSE
      p_invoice.project_id::text = p_f_project
      OR p_split_project_id::text = p_f_project
  END;
$$;


ALTER FUNCTION "public"."cost_invoice_matches_project"("p_invoice" "public"."cost_invoices", "p_split_project_id" "uuid", "p_split_project_other" "text", "p_split_is_overhead" boolean, "p_f_project" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_norm_amount"("p_value" numeric) RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT CASE
    WHEN p_value IS NULL THEN ''
    ELSE to_char(p_value, 'FM999999990.00')
  END;
$$;


ALTER FUNCTION "public"."cost_invoice_norm_amount"("p_value" numeric) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_norm_text"("p_value" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT lower(trim(coalesce(p_value, '')));
$$;


ALTER FUNCTION "public"."cost_invoice_norm_text"("p_value" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_passes_filters"("p_ci" "public"."cost_invoices", "p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean) RETURNS boolean
    LANGUAGE "sql" STABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT
    (NOT p_dup_only OR p_ci.is_duplicate OR p_ci.has_duplicate_siblings)
    AND (NOT p_missing_due_date OR p_ci.due_date IS NULL)
    AND (coalesce(nullif(trim(p_f_treatment), ''), NULL) IS NULL OR p_ci.vat_treatment::text = p_f_treatment)
    AND (coalesce(nullif(trim(p_f_status), ''), NULL) IS NULL OR p_ci.status::text = p_f_status)
    AND (
      coalesce(nullif(trim(p_f_doc_type), ''), NULL) IS NULL
      OR (p_f_doc_type = 'invoice' AND (p_ci.document_type = 'invoice' OR p_ci.document_type IS NULL))
      OR (p_f_doc_type <> 'invoice' AND p_ci.document_type = p_f_doc_type)
    )
    AND (
      coalesce(nullif(trim(p_f_company), ''), NULL) IS NULL
      OR p_ci.company_name ILIKE p_f_company
    )
    AND (p_f_from IS NULL OR p_ci.invoice_date >= p_f_from)
    AND (p_f_to IS NULL OR p_ci.invoice_date <= p_f_to)
    AND (
      coalesce(nullif(trim(p_f_po), ''), NULL) IS NULL
      OR p_ci.po_reference ILIKE '%' || trim(p_f_po) || '%'
    )
    AND (p_f_due_from IS NULL OR p_ci.due_date >= p_f_due_from)
    AND (p_f_due_to IS NULL OR p_ci.due_date <= p_f_due_to)
    AND (
      coalesce(nullif(trim(p_f_paid), ''), NULL) IS NULL
      OR (p_f_paid = 'paid' AND p_ci.paid_at IS NOT NULL)
      OR (p_f_paid = 'unpaid' AND p_ci.paid_at IS NULL)
    )
    AND (
      coalesce(nullif(trim(p_f_cis), ''), NULL) IS NULL
      OR (p_f_cis = 'has' AND coalesce(p_ci.cis_amount, 0) > 0)
      OR (p_f_cis = 'none' AND (p_ci.cis_amount IS NULL OR p_ci.cis_amount = 0))
    )
    AND (
      coalesce(nullif(trim(p_f_check), ''), NULL) IS NULL
      OR (p_f_check = 'match' AND p_ci.timesheet_check_status = 'match')
      OR (p_f_check = 'mismatch' AND p_ci.timesheet_check_status = 'mismatch')
      OR (
        p_f_check = 'unchecked'
        AND (p_ci.timesheet_check_status IS NULL OR p_ci.timesheet_check_status = 'unchecked')
      )
    )
    AND (
      coalesce(nullif(trim(p_f_project), ''), NULL) IS NULL
      OR public.cost_invoice_matches_project(p_ci, NULL, NULL, false, p_f_project)
      OR EXISTS (
        SELECT 1
        FROM public.cost_invoice_splits s
        WHERE s.cost_invoice_id = p_ci.id
          AND public.cost_invoice_matches_project(
            p_ci, s.project_id, s.project_other, s.is_overhead, p_f_project
          )
      )
    )
    AND (
      coalesce(nullif(trim(p_f_text), ''), NULL) IS NULL
      OR p_ci.search_document @@ plainto_tsquery('english', trim(p_f_text))
      OR EXISTS (
        SELECT 1
        FROM public.cost_invoice_splits s
        LEFT JOIN public.projects sp ON sp.id = s.project_id
        WHERE s.cost_invoice_id = p_ci.id
          AND lower(
            concat_ws(
              ' ',
              s.description,
              public.cost_invoice_invoice_project_label(
                s.project_id, s.project_other, s.is_overhead, sp.code, sp.description
              )
            )
          ) LIKE '%' || lower(trim(p_f_text)) || '%'
      )
      OR EXISTS (
        SELECT 1
        FROM public.projects ip
        WHERE ip.id = p_ci.project_id
          AND lower(
            public.cost_invoice_invoice_project_label(
              p_ci.project_id, p_ci.project_other, p_ci.is_overhead, ip.code, ip.description
            )
          ) LIKE '%' || lower(trim(p_f_text)) || '%'
      )
    )
    AND (
      cardinality(public.parse_description_filter_terms(p_f_description)) = 0
      OR EXISTS (
        SELECT 1
        FROM public.cost_invoice_splits s
        WHERE s.cost_invoice_id = p_ci.id
          AND public.split_line_matches_description_filter(s.description, p_f_description)
      )
    );
$$;


ALTER FUNCTION "public"."cost_invoice_passes_filters"("p_ci" "public"."cost_invoices", "p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoice_sort_value"("p_row" "public"."cost_invoices", "p_sort_key" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT CASE p_sort_key
    WHEN 'received' THEN p_row.source_received_at::text
    WHEN 'invoice_date' THEN p_row.invoice_date::text
    WHEN 'due_date' THEN p_row.due_date::text
    WHEN 'paid' THEN p_row.paid_at::text
    WHEN 'net_amount' THEN p_row.net_amount::text
    WHEN 'vat_amount' THEN p_row.vat_amount::text
    WHEN 'cis_amount' THEN p_row.cis_amount::text
    WHEN 'total_amount' THEN p_row.total_amount::text
    WHEN 'company_name' THEN
      CASE
        WHEN p_row.company_name IS NULL OR btrim(p_row.company_name) = '' OR upper(btrim(p_row.company_name)) = 'NA'
        THEN NULL
        ELSE lower(btrim(p_row.company_name))
      END
    WHEN 'invoice_number' THEN
      CASE
        WHEN p_row.invoice_number IS NULL OR btrim(p_row.invoice_number) = '' OR upper(btrim(p_row.invoice_number)) = 'NA'
        THEN NULL
        ELSE lower(btrim(p_row.invoice_number))
      END
    WHEN 'po_reference' THEN
      CASE
        WHEN p_row.po_reference IS NULL OR btrim(p_row.po_reference) = '' OR upper(btrim(p_row.po_reference)) = 'NA'
        THEN NULL
        ELSE lower(btrim(p_row.po_reference))
      END
    WHEN 'description' THEN
      CASE
        WHEN p_row.description IS NULL OR btrim(p_row.description) = '' OR upper(btrim(p_row.description)) = 'NA'
        THEN NULL
        ELSE lower(btrim(p_row.description))
      END
    WHEN 'vat_treatment' THEN lower(p_row.vat_treatment::text)
    WHEN 'status' THEN lower(p_row.status::text)
    ELSE NULL
  END;
$$;


ALTER FUNCTION "public"."cost_invoice_sort_value"("p_row" "public"."cost_invoices", "p_sort_key" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoices_after_write_refresh_duplicate_flags"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_full_keys text[] := ARRAY[]::text[];
  v_ci_keys text[] := ARRAY[]::text[];
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.full_field_dedupe_key IS NOT NULL THEN
      v_full_keys := array_append(v_full_keys, OLD.full_field_dedupe_key);
    END IF;
    IF public.cost_invoice_ci_dedupe_key(OLD.company_invoice_key, OLD.invoice_number_key) IS NOT NULL THEN
      v_ci_keys := array_append(
        v_ci_keys,
        public.cost_invoice_ci_dedupe_key(OLD.company_invoice_key, OLD.invoice_number_key)
      );
    END IF;
  ELSE
    IF NEW.full_field_dedupe_key IS NOT NULL THEN
      v_full_keys := array_append(v_full_keys, NEW.full_field_dedupe_key);
    END IF;
    IF public.cost_invoice_ci_dedupe_key(NEW.company_invoice_key, NEW.invoice_number_key) IS NOT NULL THEN
      v_ci_keys := array_append(
        v_ci_keys,
        public.cost_invoice_ci_dedupe_key(NEW.company_invoice_key, NEW.invoice_number_key)
      );
    END IF;
    IF TG_OP = 'UPDATE' THEN
      IF OLD.full_field_dedupe_key IS DISTINCT FROM NEW.full_field_dedupe_key
         AND OLD.full_field_dedupe_key IS NOT NULL THEN
        v_full_keys := array_append(v_full_keys, OLD.full_field_dedupe_key);
      END IF;
      IF public.cost_invoice_ci_dedupe_key(OLD.company_invoice_key, OLD.invoice_number_key)
         IS DISTINCT FROM public.cost_invoice_ci_dedupe_key(NEW.company_invoice_key, NEW.invoice_number_key)
         AND public.cost_invoice_ci_dedupe_key(OLD.company_invoice_key, OLD.invoice_number_key) IS NOT NULL THEN
        v_ci_keys := array_append(
          v_ci_keys,
          public.cost_invoice_ci_dedupe_key(OLD.company_invoice_key, OLD.invoice_number_key)
        );
      END IF;
    END IF;
  END IF;

  PERFORM public.refresh_cost_invoice_duplicate_flags(
    (SELECT coalesce(array_agg(DISTINCT k), ARRAY[]::text[]) FROM unnest(v_full_keys) AS k WHERE k IS NOT NULL),
    (SELECT coalesce(array_agg(DISTINCT k), ARRAY[]::text[]) FROM unnest(v_ci_keys) AS k WHERE k IS NOT NULL)
  );

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."cost_invoices_after_write_refresh_duplicate_flags"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoices_apply_canonical_company"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE v_supplier_id uuid; v_canonical text;
BEGIN
  NEW.supplier_email_domain := public.trusted_supplier_email_domain(NEW.source_email_from);
  NEW.invoice_format_key := public.invoice_format_key(NEW.invoice_number);
  IF NEW.company_name IS NOT NULL AND btrim(NEW.company_name) <> '' AND upper(btrim(NEW.company_name)) <> 'NA' THEN
    SELECT r.supplier_id, r.canonical_name INTO v_supplier_id, v_canonical FROM public.resolve_cost_supplier_for_invoice(NEW.supplier_vat_number, NEW.supplier_company_reg_number, NEW.company_name, NEW.source_email_from, NEW.invoice_number, NEW.id) r LIMIT 1;
    IF v_canonical IS NOT NULL THEN NEW.company_name := v_canonical; NEW.supplier_id := v_supplier_id;
    ELSE NEW.company_name := public.resolve_cost_company_for_invoice(NEW.company_name, NEW.source_email_from, NEW.invoice_number); END IF;
  END IF;
  RETURN NEW;
END; $$;


ALTER FUNCTION "public"."cost_invoices_apply_canonical_company"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoices_search_document_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.search_document := public.cost_invoice_build_search_document(NEW);
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."cost_invoices_search_document_trigger"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cost_invoices_set_full_field_dedupe_key_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.full_field_dedupe_key := public.cost_invoice_full_field_dedupe_key(
    NEW.company_name,
    NEW.invoice_number,
    NEW.po_reference,
    NEW.invoice_date,
    NEW.due_date,
    NEW.description,
    NEW.net_amount,
    NEW.vat_amount,
    NEW.total_amount,
    NEW.vat_treatment::text,
    NEW.currency
  );
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."cost_invoices_set_full_field_dedupe_key_trigger"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."count_pending_timesheet_reviews"() RETURNS bigint
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_sub uuid;
  v_count bigint;
BEGIN
  IF v_uid IS NULL THEN
    RETURN 0;
  END IF;

  IF NOT (
    public.has_role(v_uid, 'manager'::public.app_role)
    OR public.has_role(v_uid, 'admin'::public.app_role)
    OR public.has_role(v_uid, 'super_admin'::public.app_role)
  ) THEN
    RETURN 0;
  END IF;

  IF public.has_role(v_uid, 'admin'::public.app_role)
     OR public.has_role(v_uid, 'super_admin'::public.app_role) THEN
    SELECT count(*)::bigint INTO v_count
    FROM public.timesheets t
    WHERE t.status = 'submitted'::public.submission_status
      AND t.worker_id <> v_uid
      AND NOT EXISTS (
        SELECT 1
        FROM public.user_roles ur
        WHERE ur.user_id = t.worker_id
          AND ur.role IN ('admin'::public.app_role, 'super_admin'::public.app_role)
      );
    RETURN v_count;
  END IF;

  SELECT p.subcontractor_id INTO v_sub
  FROM public.profiles p
  WHERE p.id = v_uid;

  IF v_sub IS NULL THEN
    RETURN 0;
  END IF;

  SELECT count(*)::bigint INTO v_count
  FROM public.timesheets t
  JOIN public.profiles p ON p.id = t.worker_id
  WHERE t.status = 'submitted'::public.submission_status
    AND p.subcontractor_id = v_sub
    AND t.worker_id <> v_uid
    AND NOT EXISTS (
      SELECT 1
      FROM public.user_roles ur
      WHERE ur.user_id = t.worker_id
        AND ur.role IN ('admin'::public.app_role, 'super_admin'::public.app_role)
    );

  RETURN v_count;
END;
$$;


ALTER FUNCTION "public"."count_pending_timesheet_reviews"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."daily_briefing_autoapprove"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."daily_briefing_autoapprove"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_cost_payment_remittances_for_invoices"("p_invoice_ids" "uuid"[]) RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  deleted_count integer;
BEGIN
  IF p_invoice_ids IS NULL OR cardinality(p_invoice_ids) = 0 THEN
    RETURN 0;
  END IF;

  WITH doomed AS (
    SELECT r.id
    FROM public.cost_payment_remittances r
    WHERE EXISTS (
      SELECT 1
      FROM jsonb_array_elements(r.lines) elem
      WHERE (elem->>'invoice_id')::uuid = ANY (p_invoice_ids)
    )
  )
  DELETE FROM public.cost_payment_remittances r
  USING doomed d
  WHERE r.id = d.id;

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$;


ALTER FUNCTION "public"."delete_cost_payment_remittances_for_invoices"("p_invoice_ids" "uuid"[]) OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."enforce_todo_item_update_permissions"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  _uid uuid := auth.uid();
BEGIN
  IF public.can_modify_todo_item(_uid, OLD.id) THEN
    RETURN NEW;
  END IF;

  IF NOT public.can_complete_todo_item(_uid, OLD.id) THEN
    RAISE EXCEPTION 'Forbidden';
  END IF;

  IF NEW.list_id IS DISTINCT FROM OLD.list_id
     OR NEW.title IS DISTINCT FROM OLD.title
     OR NEW.notes IS DISTINCT FROM OLD.notes
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION 'Forbidden';
  END IF;

  IF NEW.remind_at IS DISTINCT FROM OLD.remind_at
     AND NOT (OLD.remind_at IS NOT NULL AND NEW.remind_at IS NULL)
  THEN
    RAISE EXCEPTION 'Forbidden';
  END IF;

  IF NEW.reminder_sent_at IS DISTINCT FROM OLD.reminder_sent_at
     AND NOT (OLD.reminder_sent_at IS NOT NULL AND NEW.reminder_sent_at IS NULL)
  THEN
    RAISE EXCEPTION 'Forbidden';
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."enforce_todo_item_update_permissions"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."find_or_create_cost_supplier"("p_canonical_name" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE v_name text; v_key text; v_id uuid;
BEGIN
  v_name := btrim(coalesce(p_canonical_name, ''));
  IF v_name = '' OR upper(v_name) = 'NA' THEN RETURN NULL; END IF;
  SELECT id INTO v_id FROM public.cost_suppliers WHERE canonical_name = v_name LIMIT 1;
  IF v_id IS NOT NULL THEN RETURN v_id; END IF;
  v_key := public.company_match_key(v_name);
  IF v_key IS NOT NULL AND v_key <> '' THEN
    SELECT cs.id INTO v_id FROM public.cost_suppliers cs WHERE public.company_match_key(cs.canonical_name) = v_key ORDER BY cs.created_at ASC LIMIT 1;
    IF v_id IS NOT NULL THEN RETURN v_id; END IF;
  END IF;
  INSERT INTO public.cost_suppliers (canonical_name) VALUES (v_name) ON CONFLICT (canonical_name) DO NOTHING RETURNING id INTO v_id;
  IF v_id IS NULL THEN SELECT id INTO v_id FROM public.cost_suppliers WHERE canonical_name = v_name LIMIT 1; END IF;
  RETURN v_id;
END;
$$;


ALTER FUNCTION "public"."find_or_create_cost_supplier"("p_canonical_name" "text") OWNER TO "postgres";


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
DECLARE
  v_username text;
  v_full_name text;
  v_other_count int;
BEGIN
  v_username := coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1));
  v_full_name := coalesce(new.raw_user_meta_data->>'full_name', v_username);
  INSERT INTO public.profiles (id, username, full_name)
  VALUES (new.id, v_username, v_full_name)
  ON CONFLICT (id) DO NOTHING;
  INSERT INTO public.user_roles (user_id, role) VALUES (new.id, 'worker')
  ON CONFLICT DO NOTHING;
  INSERT INTO public.notification_preferences (user_id)
  VALUES (new.id)
  ON CONFLICT (user_id) DO NOTHING;

  SELECT count(*) INTO v_other_count FROM public.profiles WHERE id <> new.id;
  IF v_other_count > 0 THEN
    INSERT INTO public.project_assignments (project_id, user_id, assigned_by)
    SELECT p.id, new.id, null
    FROM public.projects p
    WHERE p.archived_at IS NULL
      AND (
        SELECT count(distinct pa.user_id)
        FROM public.project_assignments pa
        WHERE pa.project_id = p.id
          AND pa.user_id <> new.id
      ) >= v_other_count
    ON CONFLICT (project_id, user_id) DO NOTHING;
  END IF;

  RETURN new;
END;
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


CREATE OR REPLACE FUNCTION "public"."holidays_prevent_overlap"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF NEW.user_id IS NULL THEN
    RETURN NEW;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.holidays h
    WHERE h.user_id = NEW.user_id
      AND h.status IN ('pending', 'approved')
      AND h.id IS DISTINCT FROM NEW.id
      AND h.start_date <= NEW.end_date
      AND h.end_date >= NEW.start_date
  ) THEN
    RAISE EXCEPTION 'Holiday dates overlap an existing booking for this user';
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."holidays_prevent_overlap"() OWNER TO "postgres";


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
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "search_document" "tsvector"
);


ALTER TABLE "public"."invoices" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."invoice_build_search_document"("p_row" "public"."invoices") RETURNS "tsvector"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT to_tsvector(
    'english',
    concat_ws(
      ' ',
      p_row.invoice_number::text,
      p_row.client_name_snapshot,
      p_row.client_reference,
      p_row.purchase_order,
      p_row.site_name,
      p_row.description
    )
  );
$$;


ALTER FUNCTION "public"."invoice_build_search_document"("p_row" "public"."invoices") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."invoice_format_key"("p_invoice_number" "text") RETURNS "text"
    LANGUAGE "plpgsql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $_$
DECLARE v_norm text; v_alpha text;
BEGIN
  v_norm := upper(regexp_replace(coalesce(p_invoice_number, ''), '[^A-Z0-9]', '', 'g'));
  IF v_norm = '' OR v_norm IN ('NA', 'N/A', 'NONUMBER', 'NO_NUMBER') THEN RETURN NULL; END IF;
  IF v_norm ~ '^\d+$' AND length(v_norm) >= 5 THEN
    RETURN 'NUM:' || length(v_norm)::text || '-' || left(v_norm, 3);
  END IF;
  v_alpha := upper(substring(v_norm from '^([A-Z]+)'));
  IF v_alpha IS NOT NULL AND length(v_alpha) >= 2 THEN RETURN 'ALPHA:' || v_alpha; END IF;
  RETURN NULL;
END; $_$;


ALTER FUNCTION "public"."invoice_format_key"("p_invoice_number" "text") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."invoices_search_document_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.search_document := public.invoice_build_search_document(NEW);
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."invoices_search_document_trigger"() OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."is_assigned_to_todo_list"("_user_id" "uuid", "_list_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.todo_list_assignments
    WHERE list_id = _list_id AND user_id = _user_id
  )
$$;


ALTER FUNCTION "public"."is_assigned_to_todo_list"("_user_id" "uuid", "_list_id" "uuid") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."is_legal_entity_name"("p_name" "text") RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT coalesce(p_name, '') ~* '\m(ltd|limited|plc|llp)\M'
$$;


ALTER FUNCTION "public"."is_legal_entity_name"("p_name" "text") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."is_staff_relay_domain"("p_domain" "text") RETURNS boolean
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_domain text;
  v_config text;
  v_entry text;
BEGIN
  v_domain := lower(btrim(coalesce(p_domain, '')));
  IF v_domain = '' THEN RETURN false; END IF;
  IF v_domain = 'cjbce.co.uk' OR v_domain LIKE '%.cjbce.co.uk' THEN RETURN true; END IF;
  SELECT value INTO v_config FROM public.app_settings WHERE key = 'cost_relay_email_domains';
  IF v_config IS NULL OR btrim(v_config) = '' THEN RETURN false; END IF;
  FOR v_entry IN SELECT lower(btrim(jsonb_array_elements_text(v_config::jsonb))) LOOP
    IF v_entry = '' THEN CONTINUE; END IF;
    IF v_domain = v_entry OR v_domain LIKE '%.' || v_entry THEN RETURN true; END IF;
  END LOOP;
  RETURN false;
END;
$$;


ALTER FUNCTION "public"."is_staff_relay_domain"("p_domain" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_cost_duplicate_id_sets"() RETURNS TABLE("dup_ids" "uuid"[], "original_ids" "uuid"[])
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT
    coalesce(array_agg(id) FILTER (WHERE is_duplicate), '{}'::uuid[]),
    coalesce(array_agg(id) FILTER (WHERE has_duplicate_siblings), '{}'::uuid[])
  FROM public.cost_invoices
$$;


ALTER FUNCTION "public"."list_cost_duplicate_id_sets"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_cost_invoice_ids_filtered"("p_f_text" "text" DEFAULT ''::"text", "p_f_description" "text" DEFAULT ''::"text", "p_f_treatment" "text" DEFAULT ''::"text", "p_f_status" "text" DEFAULT ''::"text", "p_f_doc_type" "text" DEFAULT ''::"text", "p_f_company" "text" DEFAULT ''::"text", "p_f_from" "date" DEFAULT NULL::"date", "p_f_to" "date" DEFAULT NULL::"date", "p_f_po" "text" DEFAULT ''::"text", "p_f_due_from" "date" DEFAULT NULL::"date", "p_f_due_to" "date" DEFAULT NULL::"date", "p_f_paid" "text" DEFAULT ''::"text", "p_f_cis" "text" DEFAULT ''::"text", "p_f_project" "text" DEFAULT ''::"text", "p_f_check" "text" DEFAULT ''::"text", "p_dup_only" boolean DEFAULT false, "p_missing_due_date" boolean DEFAULT false, "p_sort_key" "text" DEFAULT 'received'::"text", "p_sort_dir" "text" DEFAULT 'desc'::"text", "p_f_company_exact" "text" DEFAULT NULL::"text") RETURNS TABLE("id" "uuid")
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT ci.id
  FROM public.cost_invoices ci
  WHERE public.cost_invoice_passes_filters(
    ci,
    p_f_text, p_f_description, p_f_treatment, p_f_status, p_f_doc_type,
    coalesce(p_f_company_exact, p_f_company),
    p_f_from, p_f_to, p_f_po, p_f_due_from, p_f_due_to, p_f_paid, p_f_cis,
    p_f_project, p_f_check, p_dup_only, p_missing_due_date
  )
  ORDER BY
    CASE WHEN public.cost_invoice_sort_value(ci, p_sort_key) IS NULL THEN 1 ELSE 0 END,
    CASE WHEN p_sort_dir = 'asc' THEN public.cost_invoice_sort_value(ci, p_sort_key) END ASC NULLS LAST,
    CASE WHEN p_sort_dir = 'desc' THEN public.cost_invoice_sort_value(ci, p_sort_key) END DESC NULLS LAST,
    CASE WHEN p_sort_key = 'received' THEN ci.created_at END DESC NULLS LAST,
    ci.id ASC;
$$;


ALTER FUNCTION "public"."list_cost_invoice_ids_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_f_company_exact" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_cost_invoices"("p_f_text" "text" DEFAULT ''::"text", "p_f_description" "text" DEFAULT ''::"text", "p_f_treatment" "text" DEFAULT ''::"text", "p_f_status" "text" DEFAULT ''::"text", "p_f_doc_type" "text" DEFAULT ''::"text", "p_f_company" "text" DEFAULT ''::"text", "p_f_from" "date" DEFAULT NULL::"date", "p_f_to" "date" DEFAULT NULL::"date", "p_f_po" "text" DEFAULT ''::"text", "p_f_due_from" "date" DEFAULT NULL::"date", "p_f_due_to" "date" DEFAULT NULL::"date", "p_f_paid" "text" DEFAULT ''::"text", "p_f_cis" "text" DEFAULT ''::"text", "p_f_project" "text" DEFAULT ''::"text", "p_f_check" "text" DEFAULT ''::"text", "p_dup_only" boolean DEFAULT false, "p_missing_due_date" boolean DEFAULT false, "p_sort_key" "text" DEFAULT 'received'::"text", "p_sort_dir" "text" DEFAULT 'desc'::"text", "p_limit" integer DEFAULT 20, "p_offset" integer DEFAULT 0, "p_unpaginated" boolean DEFAULT false, "p_cursor_sort_value" "text" DEFAULT NULL::"text", "p_cursor_id" "uuid" DEFAULT NULL::"uuid") RETURNS TABLE("id" "uuid", "status" "public"."cost_invoice_status", "company_name" "text", "company_name_raw" "text", "invoice_number" "text", "po_reference" "text", "invoice_date" "date", "due_date" "date", "due_date_rule" "text", "description" "text", "currency" "text", "net_amount" numeric, "vat_amount" numeric, "total_amount" numeric, "vat_treatment" "public"."cost_vat_treatment", "nas_path" "text", "nas_fallback_path" "text", "attachment_filename" "text", "attachment_sha256" "text", "source_email_from" "text", "source_subject" "text", "source_message_id" "text", "source_received_at" timestamp with time zone, "gemini_confidence" numeric, "is_duplicate" boolean, "duplicate_of" "uuid", "has_duplicate_siblings" boolean, "notes" "text", "created_at" timestamp with time zone, "updated_at" timestamp with time zone, "paid_at" timestamp with time zone, "cis_amount" numeric, "document_type" "text", "project_id" "uuid", "project_other" "text", "is_overhead" boolean, "subcontractor_id" "uuid", "timesheet_check_status" "text", "timesheet_check_at" timestamp with time zone, "timesheet_check_detail" "text", "company_invoice_key" "text", "invoice_number_key" "text", "invoice_format_key" "text", "supplier_email_domain" "text", "supplier_id" "uuid", "supplier_vat_number" "text", "supplier_company_reg_number" "text", "payment_reminded_at" timestamp with time zone, "full_field_dedupe_key" "text", "total_count" bigint)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  WITH filtered AS (
    SELECT ci.*
    FROM public.cost_invoices ci
    WHERE public.cost_invoice_passes_filters(
      ci,
      p_f_text, p_f_description, p_f_treatment, p_f_status, p_f_doc_type, p_f_company,
      p_f_from, p_f_to, p_f_po, p_f_due_from, p_f_due_to, p_f_paid, p_f_cis,
      p_f_project, p_f_check, p_dup_only, p_missing_due_date
    )
  ),
  ranked AS (
    SELECT
      f.*,
      count(*) OVER () AS total_count,
      public.cost_invoice_sort_value(f, p_sort_key) AS sort_value
    FROM filtered f
  ),
  ordered AS (
    SELECT r.*
    FROM ranked r
    WHERE (
      p_cursor_sort_value IS NULL
      AND p_cursor_id IS NULL
      AND NOT p_unpaginated
    )
    OR p_unpaginated
    OR (
      p_sort_dir = 'desc'
      AND (
        r.sort_value < p_cursor_sort_value
        OR (r.sort_value IS NOT DISTINCT FROM p_cursor_sort_value AND r.id > p_cursor_id)
        OR (r.sort_value IS NULL AND p_cursor_sort_value IS NOT NULL)
        OR (r.sort_value IS NULL AND p_cursor_sort_value IS NULL AND r.id > p_cursor_id)
      )
    )
    OR (
      p_sort_dir = 'asc'
      AND (
        r.sort_value > p_cursor_sort_value
        OR (r.sort_value IS NOT DISTINCT FROM p_cursor_sort_value AND r.id > p_cursor_id)
        OR (r.sort_value IS NOT NULL AND p_cursor_sort_value IS NULL)
        OR (r.sort_value IS NULL AND p_cursor_sort_value IS NULL AND r.id > p_cursor_id)
      )
    )
    ORDER BY
      CASE WHEN r.sort_value IS NULL THEN 1 ELSE 0 END,
      CASE WHEN p_sort_dir = 'asc' THEN r.sort_value END ASC NULLS LAST,
      CASE WHEN p_sort_dir = 'desc' THEN r.sort_value END DESC NULLS LAST,
      CASE WHEN p_sort_key = 'received' THEN r.created_at END DESC NULLS LAST,
      r.id ASC
  )
  SELECT
    o.id, o.status, o.company_name, o.company_name_raw, o.invoice_number, o.po_reference,
    o.invoice_date, o.due_date, o.due_date_rule, o.description, o.currency,
    o.net_amount, o.vat_amount, o.total_amount, o.vat_treatment,
    o.nas_path, o.nas_fallback_path, o.attachment_filename, o.attachment_sha256,
    o.source_email_from, o.source_subject, o.source_message_id, o.source_received_at,
    o.gemini_confidence, o.is_duplicate, o.duplicate_of, o.has_duplicate_siblings,
    o.notes, o.created_at, o.updated_at, o.paid_at, o.cis_amount, o.document_type,
    o.project_id, o.project_other, o.is_overhead, o.subcontractor_id,
    o.timesheet_check_status, o.timesheet_check_at, o.timesheet_check_detail,
    o.company_invoice_key, o.invoice_number_key, o.invoice_format_key,
    o.supplier_email_domain, o.supplier_id, o.supplier_vat_number,
    o.supplier_company_reg_number, o.payment_reminded_at, o.full_field_dedupe_key,
    o.total_count
  FROM ordered o
  LIMIT CASE WHEN p_unpaginated THEN NULL ELSE GREATEST(p_limit, 0) END
  OFFSET CASE
    WHEN p_unpaginated THEN 0
    WHEN p_cursor_sort_value IS NOT NULL OR p_cursor_id IS NOT NULL THEN 0
    ELSE GREATEST(p_offset, 0)
  END;
$$;


ALTER FUNCTION "public"."list_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer, "p_unpaginated" boolean, "p_cursor_sort_value" "text", "p_cursor_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_cost_payment_remittances"("p_company" "text" DEFAULT ''::"text", "p_paid_from" "date" DEFAULT NULL::"date", "p_paid_to" "date" DEFAULT NULL::"date", "p_limit" integer DEFAULT 20, "p_offset" integer DEFAULT 0) RETURNS TABLE("id" "uuid", "company_name" "text", "paid_at" timestamp with time zone, "nas_path" "text", "total_net" numeric, "total_vat" numeric, "total_amount" numeric, "invoice_count" integer, "lines" "jsonb", "created_at" timestamp with time zone, "total_count" bigint)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  WITH filtered AS (
    SELECT r.*
    FROM public.cost_payment_remittances r
    WHERE
      (coalesce(nullif(trim(p_company), ''), NULL) IS NULL OR r.company_name = trim(p_company))
      AND (p_paid_from IS NULL OR r.paid_at::date >= p_paid_from)
      AND (p_paid_to IS NULL OR r.paid_at::date <= p_paid_to)
  ),
  counted AS (
    SELECT count(*)::bigint AS cnt FROM filtered
  )
  SELECT
    f.id,
    f.company_name,
    f.paid_at,
    f.nas_path,
    f.total_net,
    f.total_vat,
    f.total_amount,
    f.invoice_count,
    f.lines,
    f.created_at,
    c.cnt AS total_count
  FROM filtered f
  CROSS JOIN counted c
  ORDER BY f.paid_at DESC, f.id DESC
  LIMIT greatest(coalesce(p_limit, 20), 0)
  OFFSET greatest(coalesce(p_offset, 0), 0);
$$;


ALTER FUNCTION "public"."list_cost_payment_remittances"("p_company" "text", "p_paid_from" "date", "p_paid_to" "date", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_invoices"("p_f_text" "text" DEFAULT ''::"text", "p_f_client" "uuid" DEFAULT NULL::"uuid", "p_f_from" "date" DEFAULT NULL::"date", "p_f_to" "date" DEFAULT NULL::"date", "p_f_vat" "text" DEFAULT ''::"text", "p_f_project" "uuid" DEFAULT NULL::"uuid", "p_sort_dir" "text" DEFAULT 'desc'::"text", "p_limit" integer DEFAULT 20, "p_offset" integer DEFAULT 0) RETURNS TABLE("id" "uuid", "invoice_number" integer, "invoice_date" "date", "due_date" "date", "client_id" "uuid", "client_name_snapshot" "text", "client_reference" "text", "purchase_order" "text", "site_name" "text", "description" "text", "amount_net" numeric, "display_net" numeric, "vat_mode" "public"."invoice_vat_mode", "nas_path" "text", "nas_pushed_at" timestamp with time zone, "created_at" timestamp with time zone, "line_count" integer, "total_count" bigint)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  WITH filtered AS (
    SELECT i.*
    FROM public.invoices i
    WHERE public.outgoing_invoice_passes_filters(
      i, p_f_text, p_f_client, p_f_from, p_f_to, p_f_vat, p_f_project
    )
  ),
  ranked AS (
    SELECT
      f.*,
      count(*) OVER () AS total_count,
      CASE
        WHEN p_f_project IS NOT NULL THEN (
          SELECT coalesce(sum(il.amount_net), 0)
          FROM public.invoice_lines il
          WHERE il.invoice_id = f.id
            AND il.project_id = p_f_project
        )
        ELSE coalesce(f.amount_net, 0)
      END AS display_net,
      (
        SELECT count(*)::integer
        FROM public.invoice_lines il
        WHERE il.invoice_id = f.id
      ) AS line_count
    FROM filtered f
  )
  SELECT
    r.id,
    r.invoice_number,
    r.invoice_date,
    r.due_date,
    r.client_id,
    r.client_name_snapshot,
    r.client_reference,
    r.purchase_order,
    r.site_name,
    r.description,
    r.amount_net,
    r.display_net,
    r.vat_mode,
    r.nas_path,
    r.nas_pushed_at,
    r.created_at,
    r.line_count,
    r.total_count
  FROM ranked r
  ORDER BY
    CASE WHEN p_sort_dir = 'asc' THEN r.invoice_number END ASC NULLS LAST,
    CASE WHEN p_sort_dir = 'desc' THEN r.invoice_number END DESC NULLS LAST,
    r.id ASC
  LIMIT GREATEST(p_limit, 0)
  OFFSET GREATEST(p_offset, 0);
$$;


ALTER FUNCTION "public"."list_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid" DEFAULT NULL::"uuid", "p_group" "text" DEFAULT NULL::"text", "p_client" "uuid" DEFAULT NULL::"uuid", "p_search" "text" DEFAULT NULL::"text", "p_allowed_worker_ids" "uuid"[] DEFAULT NULL::"uuid"[], "p_limit" integer DEFAULT 20, "p_offset" integer DEFAULT 0) RETURNS TABLE("kind" "text", "id" "uuid", "worker_id" "uuid", "who" "text", "group_name" "text", "label" "text", "status" "text", "when_at" timestamp with time zone, "client_id" "uuid", "client_ids" "uuid"[], "repaired" boolean, "total_count" bigint)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  WITH base AS (
    SELECT
      'timesheet'::text AS kind,
      t.id,
      t.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown') AS who,
      s.name AS group_name,
      'Week ending ' || to_char(t.week_ending::date, 'DD Mon YYYY') AS label,
      t.status::text AS status,
      t.created_at AS when_at,
      NULL::uuid AS client_id,
      COALESCE((
        SELECT array_agg(DISTINCT pr.client_id) FILTER (WHERE pr.client_id IS NOT NULL)
        FROM public.timesheet_days td
        JOIN public.projects pr ON pr.id = td.project_id
        WHERE td.timesheet_id = t.id
      ), ARRAY[]::uuid[]) AS client_ids,
      false AS repaired
    FROM public.timesheets t
    LEFT JOIN public.profiles p ON p.id = t.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE t.week_ending >= p_from
      AND t.week_ending <= p_to
      AND ('timesheet' = ANY (p_kinds))

    UNION ALL

    SELECT
      'plant_inspection',
      pi.id,
      pi.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Plant: ' || COALESCE(pi.plant_description, ''),
      pi.status::text,
      pi.created_at,
      pi.client_id,
      CASE WHEN pi.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[pi.client_id] END,
      EXISTS (
        SELECT 1 FROM public.plant_inspection_items pii
        WHERE pii.inspection_id = pi.id AND pii.repaired_at IS NOT NULL
      )
    FROM public.plant_inspections pi
    LEFT JOIN public.profiles p ON p.id = pi.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE pi.inspection_date >= p_from
      AND pi.inspection_date <= p_to
      AND ('plant_inspection' = ANY (p_kinds))

    UNION ALL

    SELECT
      'vehicle_defect',
      vd.id,
      vd.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Vehicle: ' || COALESCE(vd.vehicle_registration, ''),
      vd.status::text,
      vd.created_at,
      NULL::uuid,
      ARRAY[]::uuid[],
      EXISTS (
        SELECT 1 FROM public.vehicle_defect_items vdi
        WHERE vdi.defect_id = vd.id AND vdi.repaired_at IS NOT NULL
      )
    FROM public.vehicle_defects vd
    LEFT JOIN public.profiles p ON p.id = vd.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE vd.inspection_date >= p_from
      AND vd.inspection_date <= p_to
      AND ('vehicle_defect' = ANY (p_kinds))

    UNION ALL

    SELECT
      'rams_briefing',
      rb.id,
      rb.briefer_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'RAMS: ' || COALESCE(rb.method_statement_title, ''),
      rb.status::text,
      rb.created_at,
      rb.client_id,
      CASE WHEN rb.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[rb.client_id] END,
      false
    FROM public.rams_briefings rb
    LEFT JOIN public.profiles p ON p.id = rb.briefer_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE rb.briefing_date >= p_from
      AND rb.briefing_date <= p_to
      AND ('rams_briefing' = ANY (p_kinds))

    UNION ALL

    SELECT
      'havs_log',
      hl.id,
      hl.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'HAVS · ' || COALESCE(hl.total_points::text, '0') || ' pts',
      hl.status::text,
      hl.created_at,
      hl.client_id,
      CASE WHEN hl.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[hl.client_id] END,
      false
    FROM public.havs_logs hl
    LEFT JOIN public.profiles p ON p.id = hl.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE hl.log_date >= p_from
      AND hl.log_date <= p_to
      AND ('havs_log' = ANY (p_kinds))

    UNION ALL

    SELECT
      'toolbox_talk',
      tt.id,
      tt.briefer_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Toolbox: ' || COALESCE(tt.topic, ''),
      tt.status::text,
      tt.created_at,
      tt.client_id,
      CASE WHEN tt.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[tt.client_id] END,
      false
    FROM public.toolbox_talks tt
    LEFT JOIN public.profiles p ON p.id = tt.briefer_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE tt.talk_date >= p_from
      AND tt.talk_date <= p_to
      AND ('toolbox_talk' = ANY (p_kinds))

    UNION ALL

    SELECT
      'daily_briefing',
      db.id,
      db.briefer_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Daily Briefing · ' || to_char(db.time_delivered, 'DD Mon YYYY HH24:MI'),
      db.status::text,
      db.created_at,
      db.client_id,
      CASE WHEN db.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[db.client_id] END,
      false
    FROM public.daily_briefings db
    LEFT JOIN public.profiles p ON p.id = db.briefer_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE db.time_delivered >= (p_from::timestamptz)
      AND db.time_delivered <= ((p_to::text || 'T23:59:59')::timestamptz)
      AND ('daily_briefing' = ANY (p_kinds))

    UNION ALL

    SELECT
      'starter',
      es.id,
      es.user_id,
      CASE
        WHEN es.user_id IS NULL THEN '(deleted user)'
        ELSE COALESCE(p.full_name, p.username, 'Unknown')
      END,
      s.name,
      'Starter form · ' || COALESCE(es.full_name, '') || ' (v' || COALESCE(es.revision, 1)::text || ')',
      CASE WHEN es.submitted_at IS NOT NULL THEN 'submitted' ELSE 'draft' END,
      COALESCE(es.submitted_at, es.created_at),
      NULL::uuid,
      ARRAY[]::uuid[],
      false
    FROM public.employee_starters es
    LEFT JOIN public.profiles p ON p.id = es.user_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE es.created_at >= p_from::timestamptz
      AND es.created_at <= ((p_to::text || 'T23:59:59')::timestamptz)
      AND ('starter' = ANY (p_kinds))
  ),
  filtered AS (
    SELECT *
    FROM base b
    WHERE (p_worker_id IS NULL OR b.worker_id = p_worker_id)
      AND (p_allowed_worker_ids IS NULL OR b.worker_id = ANY (p_allowed_worker_ids))
      AND (COALESCE(NULLIF(trim(p_group), ''), NULL) IS NULL OR b.group_name = p_group)
      AND (
        p_client IS NULL
        OR (b.kind = 'timesheet' AND p_client = ANY (b.client_ids))
        OR (b.kind <> 'timesheet' AND b.client_id = p_client)
      )
      AND (
        COALESCE(NULLIF(trim(p_search), ''), NULL) IS NULL
        OR lower(b.label || ' ' || b.who || ' ' || COALESCE(b.group_name, '')) LIKE '%' || lower(trim(p_search)) || '%'
      )
  ),
  ranked AS (
    SELECT
      f.*,
      count(*) OVER () AS total_count
    FROM filtered f
    ORDER BY f.when_at DESC
    LIMIT GREATEST(p_limit, 0)
    OFFSET GREATEST(p_offset, 0)
  )
  SELECT
    r.kind,
    r.id,
    r.worker_id,
    r.who,
    r.group_name,
    r.label,
    r.status,
    r.when_at,
    r.client_id,
    r.client_ids,
    r.repaired,
    r.total_count
  FROM ranked r;
$$;


ALTER FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid" DEFAULT NULL::"uuid", "p_group" "text" DEFAULT NULL::"text", "p_client" "uuid" DEFAULT NULL::"uuid", "p_search" "text" DEFAULT NULL::"text", "p_allowed_worker_ids" "uuid"[] DEFAULT NULL::"uuid"[], "p_limit" integer DEFAULT 20, "p_offset" integer DEFAULT 0, "p_sensitive_owner_id" "uuid" DEFAULT NULL::"uuid") RETURNS TABLE("kind" "text", "id" "uuid", "worker_id" "uuid", "who" "text", "group_name" "text", "label" "text", "status" "text", "when_at" timestamp with time zone, "client_id" "uuid", "client_ids" "uuid"[], "repaired" boolean, "total_count" bigint)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  WITH base AS (
    SELECT
      'timesheet'::text AS kind,
      t.id,
      t.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown') AS who,
      s.name AS group_name,
      'Week ending ' || to_char(t.week_ending::date, 'DD Mon YYYY') AS label,
      t.status::text AS status,
      t.created_at AS when_at,
      NULL::uuid AS client_id,
      COALESCE((
        SELECT array_agg(DISTINCT pr.client_id) FILTER (WHERE pr.client_id IS NOT NULL)
        FROM public.timesheet_days td
        JOIN public.projects pr ON pr.id = td.project_id
        WHERE td.timesheet_id = t.id
      ), ARRAY[]::uuid[]) AS client_ids,
      false AS repaired
    FROM public.timesheets t
    LEFT JOIN public.profiles p ON p.id = t.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE t.week_ending >= p_from
      AND t.week_ending <= p_to
      AND ('timesheet' = ANY (p_kinds))

    UNION ALL

    SELECT
      'plant_inspection',
      pi.id,
      pi.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Plant: ' || COALESCE(pi.plant_description, ''),
      pi.status::text,
      pi.created_at,
      pi.client_id,
      CASE WHEN pi.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[pi.client_id] END,
      EXISTS (
        SELECT 1 FROM public.plant_inspection_items pii
        WHERE pii.inspection_id = pi.id AND pii.repaired_at IS NOT NULL
      )
    FROM public.plant_inspections pi
    LEFT JOIN public.profiles p ON p.id = pi.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE pi.inspection_date >= p_from
      AND pi.inspection_date <= p_to
      AND ('plant_inspection' = ANY (p_kinds))

    UNION ALL

    SELECT
      'vehicle_defect',
      vd.id,
      vd.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Vehicle: ' || COALESCE(vd.vehicle_registration, ''),
      vd.status::text,
      vd.created_at,
      NULL::uuid,
      ARRAY[]::uuid[],
      EXISTS (
        SELECT 1 FROM public.vehicle_defect_items vdi
        WHERE vdi.defect_id = vd.id AND vdi.repaired_at IS NOT NULL
      )
    FROM public.vehicle_defects vd
    LEFT JOIN public.profiles p ON p.id = vd.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE vd.inspection_date >= p_from
      AND vd.inspection_date <= p_to
      AND ('vehicle_defect' = ANY (p_kinds))

    UNION ALL

    SELECT
      'rams_briefing',
      rb.id,
      rb.briefer_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'RAMS: ' || COALESCE(rb.method_statement_title, ''),
      rb.status::text,
      rb.created_at,
      rb.client_id,
      CASE WHEN rb.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[rb.client_id] END,
      false
    FROM public.rams_briefings rb
    LEFT JOIN public.profiles p ON p.id = rb.briefer_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE rb.briefing_date >= p_from
      AND rb.briefing_date <= p_to
      AND ('rams_briefing' = ANY (p_kinds))

    UNION ALL

    SELECT
      'havs_log',
      hl.id,
      hl.worker_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'HAVS · ' || COALESCE(hl.total_points::text, '0') || ' pts',
      hl.status::text,
      hl.created_at,
      hl.client_id,
      CASE WHEN hl.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[hl.client_id] END,
      false
    FROM public.havs_logs hl
    LEFT JOIN public.profiles p ON p.id = hl.worker_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE hl.log_date >= p_from
      AND hl.log_date <= p_to
      AND ('havs_log' = ANY (p_kinds))

    UNION ALL

    SELECT
      'toolbox_talk',
      tt.id,
      tt.briefer_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Toolbox: ' || COALESCE(tt.topic, ''),
      tt.status::text,
      tt.created_at,
      tt.client_id,
      CASE WHEN tt.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[tt.client_id] END,
      false
    FROM public.toolbox_talks tt
    LEFT JOIN public.profiles p ON p.id = tt.briefer_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE tt.talk_date >= p_from
      AND tt.talk_date <= p_to
      AND ('toolbox_talk' = ANY (p_kinds))

    UNION ALL

    SELECT
      'daily_briefing',
      db.id,
      db.briefer_id,
      COALESCE(p.full_name, p.username, 'Unknown'),
      s.name,
      'Daily Briefing · ' || to_char(db.time_delivered, 'DD Mon YYYY HH24:MI'),
      db.status::text,
      db.created_at,
      db.client_id,
      CASE WHEN db.client_id IS NULL THEN ARRAY[]::uuid[] ELSE ARRAY[db.client_id] END,
      false
    FROM public.daily_briefings db
    LEFT JOIN public.profiles p ON p.id = db.briefer_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE db.time_delivered >= (p_from::timestamptz)
      AND db.time_delivered <= ((p_to::text || 'T23:59:59')::timestamptz)
      AND ('daily_briefing' = ANY (p_kinds))

    UNION ALL

    SELECT
      'starter',
      es.id,
      es.user_id,
      CASE
        WHEN es.user_id IS NULL THEN '(deleted user)'
        ELSE COALESCE(p.full_name, p.username, 'Unknown')
      END,
      s.name,
      'Starter form · ' || COALESCE(es.full_name, '') || ' (v' || COALESCE(es.revision, 1)::text || ')',
      CASE WHEN es.submitted_at IS NOT NULL THEN 'submitted' ELSE 'draft' END,
      COALESCE(es.submitted_at, es.created_at),
      NULL::uuid,
      ARRAY[]::uuid[],
      false
    FROM public.employee_starters es
    LEFT JOIN public.profiles p ON p.id = es.user_id
    LEFT JOIN public.subcontractors s ON s.id = p.subcontractor_id
    WHERE es.created_at >= p_from::timestamptz
      AND es.created_at <= ((p_to::text || 'T23:59:59')::timestamptz)
      AND ('starter' = ANY (p_kinds))
  ),
  filtered AS (
    SELECT *
    FROM base b
    WHERE (p_worker_id IS NULL OR b.worker_id = p_worker_id)
      AND (p_allowed_worker_ids IS NULL OR b.worker_id = ANY (p_allowed_worker_ids))
      AND (
        p_sensitive_owner_id IS NULL
        OR b.kind NOT IN ('timesheet', 'starter')
        OR b.worker_id = p_sensitive_owner_id
      )
      AND (COALESCE(NULLIF(trim(p_group), ''), NULL) IS NULL OR b.group_name = p_group)
      AND (
        p_client IS NULL
        OR (b.kind = 'timesheet' AND p_client = ANY (b.client_ids))
        OR (b.kind <> 'timesheet' AND b.client_id = p_client)
      )
      AND (
        COALESCE(NULLIF(trim(p_search), ''), NULL) IS NULL
        OR lower(b.label || ' ' || b.who || ' ' || COALESCE(b.group_name, '')) LIKE '%' || lower(trim(p_search)) || '%'
      )
  ),
  ranked AS (
    SELECT
      f.*,
      count(*) OVER () AS total_count
    FROM filtered f
    ORDER BY f.when_at DESC
    LIMIT GREATEST(p_limit, 0)
    OFFSET GREATEST(p_offset, 0)
  )
  SELECT
    r.kind,
    r.id,
    r.worker_id,
    r.who,
    r.group_name,
    r.label,
    r.status,
    r.when_at,
    r.client_id,
    r.client_ids,
    r.repaired,
    r.total_count
  FROM ranked r;
$$;


ALTER FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer, "p_sensitive_owner_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."lookup_cost_supplier_by_identifiers"("p_vat" "text", "p_company_reg" "text", "p_name" "text") RETURNS TABLE("supplier_id" "uuid", "canonical_name" "text")
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE v_key text;
BEGIN
  v_key := public.normalize_vat_number(p_vat);
  IF v_key IS NOT NULL THEN
    RETURN QUERY SELECT cs.id, cs.canonical_name FROM public.cost_supplier_identifiers csi JOIN public.cost_suppliers cs ON cs.id = csi.supplier_id WHERE csi.identifier_type = 'vat' AND csi.identifier_key = v_key LIMIT 1;
    IF FOUND THEN RETURN; END IF;
  END IF;
  v_key := public.normalize_company_registration(p_company_reg);
  IF v_key IS NOT NULL THEN
    RETURN QUERY SELECT cs.id, cs.canonical_name FROM public.cost_supplier_identifiers csi JOIN public.cost_suppliers cs ON cs.id = csi.supplier_id WHERE csi.identifier_type = 'company_registration' AND csi.identifier_key = v_key LIMIT 1;
    IF FOUND THEN RETURN; END IF;
  END IF;
  IF p_name IS NOT NULL AND btrim(p_name) <> '' AND upper(btrim(p_name)) <> 'NA' THEN
    v_key := public.supplier_legal_name_key(p_name);
    IF v_key IS NOT NULL THEN
      RETURN QUERY SELECT cs.id, cs.canonical_name FROM public.cost_supplier_identifiers csi JOIN public.cost_suppliers cs ON cs.id = csi.supplier_id WHERE csi.identifier_type = 'legal_name' AND csi.identifier_key = v_key LIMIT 1;
    END IF;
  END IF;
END; $$;


ALTER FUNCTION "public"."lookup_cost_supplier_by_identifiers"("p_vat" "text", "p_company_reg" "text", "p_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mark_cost_invoices_paid_filtered"("p_f_text" "text" DEFAULT ''::"text", "p_f_description" "text" DEFAULT ''::"text", "p_f_treatment" "text" DEFAULT ''::"text", "p_f_status" "text" DEFAULT ''::"text", "p_f_doc_type" "text" DEFAULT ''::"text", "p_f_company" "text" DEFAULT ''::"text", "p_f_from" "date" DEFAULT NULL::"date", "p_f_to" "date" DEFAULT NULL::"date", "p_f_po" "text" DEFAULT ''::"text", "p_f_due_from" "date" DEFAULT NULL::"date", "p_f_due_to" "date" DEFAULT NULL::"date", "p_f_paid" "text" DEFAULT 'unpaid'::"text", "p_f_cis" "text" DEFAULT ''::"text", "p_f_project" "text" DEFAULT ''::"text", "p_f_check" "text" DEFAULT ''::"text", "p_dup_only" boolean DEFAULT false, "p_missing_due_date" boolean DEFAULT false, "p_paid" boolean DEFAULT true, "p_selected_ids" "uuid"[] DEFAULT NULL::"uuid"[]) RETURNS TABLE("updated_count" bigint, "snapshot" "jsonb")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_now timestamptz := now();
BEGIN
  RETURN QUERY
  WITH targets AS (
    SELECT ci.id, ci.paid_at, ci.company_name
    FROM public.cost_invoices ci
    WHERE ci.paid_at IS NULL
      AND (p_selected_ids IS NULL OR ci.id = ANY (p_selected_ids))
      AND public.cost_invoice_passes_filters(
        ci,
        p_f_text, p_f_description, p_f_treatment, p_f_status, p_f_doc_type, p_f_company,
        p_f_from, p_f_to, p_f_po, p_f_due_from, p_f_due_to, p_f_paid, p_f_cis,
        p_f_project, p_f_check, p_dup_only, p_missing_due_date
      )
  ),
  snap AS (
    SELECT coalesce(
      jsonb_agg(jsonb_build_object('id', t.id, 'paid_at', t.paid_at)),
      '[]'::jsonb
    ) AS entries
    FROM targets t
  ),
  upd AS (
    UPDATE public.cost_invoices ci
    SET paid_at = CASE WHEN p_paid THEN v_now ELSE NULL END
    FROM targets t
    WHERE ci.id = t.id
    RETURNING ci.id
  ),
  clear_reminders AS (
    UPDATE public.cost_invoices ci
    SET
      payment_reminded_at = NULL,
      payment_reminder_month = NULL,
      payment_reminder_dismissed_at = NULL
    FROM targets t
    WHERE p_paid AND ci.id = t.id
    RETURNING ci.id
  )
  SELECT
    (SELECT count(*)::bigint FROM upd),
    (SELECT entries FROM snap);
END;
$$;


ALTER FUNCTION "public"."mark_cost_invoices_paid_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_paid" boolean, "p_selected_ids" "uuid"[]) OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."most_common_cost_company_name"("p_match_key" "text") RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT ci.company_name FROM public.cost_invoices ci
   WHERE p_match_key IS NOT NULL AND p_match_key <> ''
     AND public.company_match_key(ci.company_name) = p_match_key
     AND ci.company_name IS NOT NULL AND btrim(ci.company_name) <> ''
     AND upper(btrim(ci.company_name)) <> 'NA'
   GROUP BY ci.company_name
   ORDER BY count(*) DESC, max(ci.created_at) DESC LIMIT 1
$$;


ALTER FUNCTION "public"."most_common_cost_company_name"("p_match_key" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."normalize_company_registration"("p_reg" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT NULLIF(upper(regexp_replace(btrim(coalesce(p_reg, '')), '[^A-Z0-9]', '', 'g')), '')
$$;


ALTER FUNCTION "public"."normalize_company_registration"("p_reg" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."normalize_vat_number"("p_vat" "text") RETURNS "text"
    LANGUAGE "plpgsql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v text;
BEGIN
  IF p_vat IS NULL OR btrim(p_vat) = '' THEN
    RETURN NULL;
  END IF;
  v := upper(regexp_replace(btrim(p_vat), '[^A-Z0-9]', '', 'g'));
  IF v = '' THEN
    RETURN NULL;
  END IF;
  IF v LIKE 'GB%' AND length(v) > 2 THEN
    v := substring(v from 3);
  END IF;
  RETURN NULLIF(v, '');
END;
$$;


ALTER FUNCTION "public"."normalize_vat_number"("p_vat" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."outgoing_invoice_passes_filters"("p_inv" "public"."invoices", "p_f_text" "text" DEFAULT ''::"text", "p_f_client" "uuid" DEFAULT NULL::"uuid", "p_f_from" "date" DEFAULT NULL::"date", "p_f_to" "date" DEFAULT NULL::"date", "p_f_vat" "text" DEFAULT ''::"text", "p_f_project" "uuid" DEFAULT NULL::"uuid") RETURNS boolean
    LANGUAGE "sql" STABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT
    (p_f_client IS NULL OR p_inv.client_id = p_f_client)
    AND (p_f_from IS NULL OR p_inv.invoice_date >= p_f_from)
    AND (p_f_to IS NULL OR p_inv.invoice_date <= p_f_to)
    AND (
      coalesce(trim(p_f_vat), '') = ''
      OR p_inv.vat_mode::text = trim(p_f_vat)
    )
    AND (
      p_f_project IS NULL
      OR EXISTS (
        SELECT 1
        FROM public.invoice_lines il
        WHERE il.invoice_id = p_inv.id
          AND il.project_id = p_f_project
      )
    )
    AND (
      coalesce(trim(p_f_text), '') = ''
      OR p_inv.search_document @@ plainto_tsquery('english', trim(p_f_text))
      OR p_inv.invoice_number::text ILIKE '%' || trim(p_f_text) || '%'
      OR EXISTS (
        SELECT 1
        FROM public.invoice_lines il
        LEFT JOIN public.projects p ON p.id = il.project_id
        WHERE il.invoice_id = p_inv.id
          AND (
            il.site_name ILIKE '%' || trim(p_f_text) || '%'
            OR il.description ILIKE '%' || trim(p_f_text) || '%'
            OR il.project_other ILIKE '%' || trim(p_f_text) || '%'
            OR p.code ILIKE '%' || trim(p_f_text) || '%'
            OR p.description ILIKE '%' || trim(p_f_text) || '%'
          )
      )
    );
$$;


ALTER FUNCTION "public"."outgoing_invoice_passes_filters"("p_inv" "public"."invoices", "p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."parse_description_filter_terms"("p_f_description" "text") RETURNS "text"[]
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT CASE
    WHEN coalesce(nullif(trim(p_f_description), ''), NULL) IS NULL THEN ARRAY[]::text[]
    WHEN left(trim(p_f_description), 1) = '[' THEN (
      SELECT coalesce(array_agg(trim(elem)), ARRAY[]::text[])
      FROM jsonb_array_elements_text(p_f_description::jsonb) AS elem
      WHERE trim(elem) <> ''
    )
    ELSE ARRAY[trim(p_f_description)]
  END;
$$;


ALTER FUNCTION "public"."parse_description_filter_terms"("p_f_description" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."pick_domain_canonical"("p_domain" "text") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_canon text;
BEGIN
  SELECT d.canonical_name
    INTO v_canon
    FROM public.cost_company_domain_aliases d
    LEFT JOIN (
      SELECT ci.company_name, count(*) AS cnt
        FROM public.cost_invoices ci
       WHERE public.email_domain(ci.source_email_from) = p_domain
         AND ci.company_name IS NOT NULL
         AND btrim(ci.company_name) <> ''
         AND upper(btrim(ci.company_name)) <> 'NA'
       GROUP BY ci.company_name
    ) inv ON inv.company_name = d.canonical_name
   WHERE d.domain = p_domain
   ORDER BY
     CASE WHEN public.is_legal_entity_name(d.canonical_name) THEN 0 ELSE 1 END,
     coalesce(inv.cnt, 0) DESC,
     char_length(public.company_match_key(d.canonical_name)) DESC,
     d.canonical_name ASC
   LIMIT 1;
  RETURN v_canon;
END;
$$;


ALTER FUNCTION "public"."pick_domain_canonical"("p_domain" "text") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."refresh_cost_invoice_duplicate_flags"("p_full_keys" "text"[] DEFAULT NULL::"text"[], "p_ci_keys" "text"[] DEFAULT NULL::"text"[]) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_full_keys text[];
  v_ci_keys text[];
  v_full_refresh boolean;
BEGIN
  v_full_refresh := p_full_keys IS NULL AND p_ci_keys IS NULL;

  IF v_full_refresh THEN
    v_full_keys := NULL;
    v_ci_keys := NULL;
  ELSE
    v_full_keys := (
      SELECT coalesce(array_agg(DISTINCT k), ARRAY[]::text[])
      FROM unnest(coalesce(p_full_keys, ARRAY[]::text[])) AS k
      WHERE k IS NOT NULL
    );
    v_ci_keys := (
      SELECT coalesce(array_agg(DISTINCT k), ARRAY[]::text[])
      FROM unnest(coalesce(p_ci_keys, ARRAY[]::text[])) AS k
      WHERE k IS NOT NULL
    );
    IF cardinality(v_full_keys) = 0 AND cardinality(v_ci_keys) = 0 THEN
      RETURN;
    END IF;
  END IF;

  UPDATE public.cost_invoices ci
  SET
    is_duplicate = false,
    duplicate_of = NULL,
    has_duplicate_siblings = false
  WHERE v_full_refresh
     OR ci.full_field_dedupe_key = ANY (v_full_keys)
     OR public.cost_invoice_ci_dedupe_key(ci.company_invoice_key, ci.invoice_number_key) = ANY (v_ci_keys);

  WITH full_ranked AS (
    SELECT
      ci.id,
      first_value(ci.id) OVER w AS keeper_id,
      count(*) OVER w AS grp_size
    FROM public.cost_invoices ci
    WHERE ci.full_field_dedupe_key IS NOT NULL
      AND (
        v_full_refresh
        OR ci.full_field_dedupe_key = ANY (v_full_keys)
      )
    WINDOW w AS (
      PARTITION BY ci.full_field_dedupe_key
      ORDER BY ci.created_at ASC NULLS LAST, ci.id ASC
    )
  ),
  ci_ranked AS (
    SELECT
      ci.id,
      first_value(ci.id) OVER w AS keeper_id,
      count(*) OVER w AS grp_size
    FROM public.cost_invoices ci
    WHERE public.cost_invoice_ci_dedupe_key(ci.company_invoice_key, ci.invoice_number_key) IS NOT NULL
      AND (
        v_full_refresh
        OR public.cost_invoice_ci_dedupe_key(ci.company_invoice_key, ci.invoice_number_key) = ANY (v_ci_keys)
      )
    WINDOW w AS (
      PARTITION BY public.cost_invoice_ci_dedupe_key(ci.company_invoice_key, ci.invoice_number_key)
      ORDER BY ci.created_at ASC NULLS LAST, ci.id ASC
    )
  ),
  duplicate_rows AS (
    SELECT fr.id, fr.keeper_id
    FROM full_ranked fr
    WHERE fr.grp_size >= 2 AND fr.id <> fr.keeper_id
    UNION
    SELECT cr.id, cr.keeper_id
    FROM ci_ranked cr
    WHERE cr.grp_size >= 2 AND cr.id <> cr.keeper_id
  ),
  keeper_rows AS (
    SELECT fr.keeper_id AS id
    FROM full_ranked fr
    WHERE fr.grp_size >= 2
    UNION
    SELECT cr.keeper_id AS id
    FROM ci_ranked cr
    WHERE cr.grp_size >= 2
  ),
  dup_targets AS (
    SELECT DISTINCT ON (dr.id)
      dr.id,
      dr.keeper_id
    FROM duplicate_rows dr
    ORDER BY dr.id, dr.keeper_id
  ),
  mark_duplicates AS (
    UPDATE public.cost_invoices ci
    SET
      is_duplicate = true,
      duplicate_of = dt.keeper_id
    FROM dup_targets dt
    WHERE ci.id = dt.id
    RETURNING ci.id
  )
  UPDATE public.cost_invoices ci
  SET has_duplicate_siblings = true
  WHERE ci.id IN (SELECT kr.id FROM keeper_rows kr);
END;
$$;


ALTER FUNCTION "public"."refresh_cost_invoice_duplicate_flags"("p_full_keys" "text"[], "p_ci_keys" "text"[]) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_company_from_costs_table"("p_domain" "text", "p_format_key" "text", "p_pdf_name" "text" DEFAULT NULL::"text") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE v_pdf_key text; v_resolved text; v_total bigint; v_winner_cnt bigint; v_winner_name text; v_distinct int;
BEGIN
  IF p_pdf_name IS NOT NULL AND btrim(p_pdf_name) <> '' AND upper(btrim(p_pdf_name)) <> 'NA' THEN
    v_pdf_key := public.company_match_key(p_pdf_name);
    IF v_pdf_key IS NOT NULL AND v_pdf_key <> '' THEN
      v_resolved := public.most_common_cost_company_name(v_pdf_key);
      IF v_resolved IS NOT NULL THEN RETURN v_resolved; END IF;
    END IF;
  END IF;
  IF p_domain IS NOT NULL AND btrim(p_domain) <> '' AND p_format_key IS NOT NULL AND btrim(p_format_key) <> '' THEN
    SELECT ci.company_name INTO v_resolved FROM public.cost_invoices ci
     WHERE ci.supplier_email_domain = p_domain AND ci.invoice_format_key = p_format_key
       AND ci.company_name IS NOT NULL AND btrim(ci.company_name) <> '' AND upper(btrim(ci.company_name)) <> 'NA'
     GROUP BY ci.company_name ORDER BY count(*) DESC, max(ci.created_at) DESC LIMIT 1;
    IF v_resolved IS NOT NULL THEN RETURN v_resolved; END IF;
  END IF;
  IF p_format_key IS NOT NULL AND btrim(p_format_key) <> '' THEN
    SELECT count(*)::bigint, count(DISTINCT ci.company_name)::int INTO v_total, v_distinct
      FROM public.cost_invoices ci
     WHERE ci.invoice_format_key = p_format_key AND ci.supplier_email_domain IS NOT NULL
       AND ci.company_name IS NOT NULL AND btrim(ci.company_name) <> '' AND upper(btrim(ci.company_name)) <> 'NA';
    IF v_total >= 2 THEN
      SELECT ci.company_name, count(*)::bigint INTO v_winner_name, v_winner_cnt
        FROM public.cost_invoices ci
       WHERE ci.invoice_format_key = p_format_key AND ci.supplier_email_domain IS NOT NULL
         AND ci.company_name IS NOT NULL AND btrim(ci.company_name) <> '' AND upper(btrim(ci.company_name)) <> 'NA'
       GROUP BY ci.company_name ORDER BY count(*) DESC, max(ci.created_at) DESC LIMIT 1;
      IF v_winner_name IS NOT NULL AND v_winner_cnt::numeric / v_total::numeric >= 0.8
         AND (v_distinct = 1 OR v_winner_cnt = v_total) THEN
        IF p_pdf_name IS NULL OR btrim(p_pdf_name) = '' OR upper(btrim(p_pdf_name)) = 'NA'
           OR public.company_match_key(p_pdf_name) = public.company_match_key(v_winner_name) THEN
          RETURN v_winner_name;
        END IF;
      END IF;
    END IF;
  END IF;
  RETURN NULL;
END; $$;


ALTER FUNCTION "public"."resolve_company_from_costs_table"("p_domain" "text", "p_format_key" "text", "p_pdf_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_company_from_invoice_series"("p_from" "text", "p_invoice_number" "text") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
DECLARE
  v_domain text;
  v_num text;
  v_prefix text;
  v_canon text;
BEGIN
  v_domain := public.email_domain(p_from);
  IF v_domain IS NULL OR v_domain = ''
     OR public.is_generic_email_domain(v_domain)
     OR public.is_shared_invoice_portal_domain(v_domain) THEN
    RETURN NULL;
  END IF;

  v_num := upper(regexp_replace(coalesce(p_invoice_number, ''), '[^A-Z0-9]', '', 'g'));
  IF v_num = '' OR length(v_num) < 5 THEN
    RETURN NULL;
  END IF;

  IF v_num ~ '^\d+$' THEN
    v_prefix := left(v_num, 3);
    SELECT ci.company_name
      INTO v_canon
      FROM public.cost_invoices ci
     WHERE public.email_domain(ci.source_email_from) = v_domain
       AND ci.company_name IS NOT NULL
       AND btrim(ci.company_name) <> ''
       AND upper(btrim(ci.company_name)) <> 'NA'
       AND ci.invoice_number_key IS NOT NULL
       AND left(ci.invoice_number_key, 3) = v_prefix
     GROUP BY ci.company_name
     ORDER BY count(*) DESC, max(ci.created_at) DESC
     LIMIT 1;
    RETURN v_canon;
  END IF;

  RETURN NULL;
END;
$_$;


ALTER FUNCTION "public"."resolve_company_from_invoice_series"("p_from" "text", "p_invoice_number" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_cost_company_canonical"("p_name" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE v_key text; v_canon text; v_table text;
BEGIN
  IF p_name IS NULL OR btrim(p_name) = '' OR upper(btrim(p_name)) = 'NA' THEN RETURN p_name; END IF;
  v_key := public.company_match_key(p_name);
  IF v_key IS NULL OR v_key = '' THEN RETURN btrim(p_name); END IF;
  SELECT canonical_name INTO v_canon FROM public.cost_company_aliases WHERE match_key = v_key;
  IF v_canon IS NOT NULL THEN RETURN v_canon; END IF;
  v_table := public.most_common_cost_company_name(v_key);
  IF v_table IS NOT NULL THEN
    INSERT INTO public.cost_company_aliases (match_key, canonical_name) VALUES (v_key, v_table) ON CONFLICT (match_key) DO NOTHING;
    RETURN v_table;
  END IF;
  INSERT INTO public.cost_company_aliases (match_key, canonical_name) VALUES (v_key, btrim(p_name)) ON CONFLICT (match_key) DO NOTHING;
  SELECT canonical_name INTO v_canon FROM public.cost_company_aliases WHERE match_key = v_key;
  RETURN coalesce(v_canon, btrim(p_name));
END; $$;


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


CREATE OR REPLACE FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text", "p_invoice_number" "text" DEFAULT NULL::"text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE v_domain text; v_format_key text; v_resolved text; v_has_pdf_name boolean; v_domain_only text; v_domain_cnt int;
BEGIN
  v_domain := public.trusted_supplier_email_domain(p_from);
  v_format_key := public.invoice_format_key(p_invoice_number);
  v_has_pdf_name := p_name IS NOT NULL AND btrim(p_name) <> '' AND upper(btrim(p_name)) <> 'NA';
  v_resolved := public.resolve_company_from_costs_table(v_domain, v_format_key, p_name);
  IF v_resolved IS NOT NULL THEN RETURN v_resolved; END IF;
  IF v_has_pdf_name THEN RETURN btrim(p_name); END IF;
  IF v_domain IS NOT NULL THEN
    SELECT count(DISTINCT ci.company_name) INTO v_domain_cnt FROM public.cost_invoices ci
     WHERE ci.supplier_email_domain = v_domain AND ci.company_name IS NOT NULL
       AND btrim(ci.company_name) <> '' AND upper(btrim(ci.company_name)) <> 'NA';
    IF v_domain_cnt = 1 THEN
      SELECT min(ci.company_name) INTO v_domain_only FROM public.cost_invoices ci
       WHERE ci.supplier_email_domain = v_domain AND ci.company_name IS NOT NULL
         AND btrim(ci.company_name) <> '' AND upper(btrim(ci.company_name)) <> 'NA';
      RETURN v_domain_only;
    ELSIF v_domain_cnt > 1 THEN
      SELECT ci.company_name INTO v_domain_only FROM public.cost_invoices ci
       WHERE ci.supplier_email_domain = v_domain AND ci.company_name IS NOT NULL
         AND btrim(ci.company_name) <> '' AND upper(btrim(ci.company_name)) <> 'NA'
       GROUP BY ci.company_name ORDER BY count(*) DESC, max(ci.created_at) DESC LIMIT 1;
      IF v_domain_only IS NOT NULL THEN RETURN v_domain_only; END IF;
    END IF;
  END IF;
  RETURN NULL;
END; $$;


ALTER FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text", "p_invoice_number" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_cost_supplier_for_invoice"("p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_from" "text", "p_invoice_number" "text" DEFAULT NULL::"text", "p_source_invoice_id" "uuid" DEFAULT NULL::"uuid") RETURNS TABLE("supplier_id" "uuid", "canonical_name" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE v_supplier_id uuid; v_canonical text; v_fallback text;
BEGIN
  SELECT l.supplier_id, l.canonical_name INTO v_supplier_id, v_canonical FROM public.lookup_cost_supplier_by_identifiers(p_vat, p_company_reg, p_name) l LIMIT 1;
  IF v_supplier_id IS NOT NULL THEN
    PERFORM public.upsert_cost_supplier_identifiers(v_supplier_id, p_vat, p_company_reg, p_name, p_source_invoice_id);
    RETURN QUERY SELECT v_supplier_id, v_canonical; RETURN;
  END IF;
  v_fallback := public.resolve_cost_company_for_invoice(p_name, p_from, p_invoice_number);
  IF v_fallback IS NULL OR btrim(v_fallback) = '' OR upper(btrim(v_fallback)) = 'NA' THEN RETURN; END IF;
  v_supplier_id := public.find_or_create_cost_supplier(v_fallback);
  IF v_supplier_id IS NULL THEN RETURN; END IF;
  SELECT cs.canonical_name INTO v_canonical FROM public.cost_suppliers cs WHERE cs.id = v_supplier_id;
  PERFORM public.upsert_cost_supplier_identifiers(v_supplier_id, p_vat, p_company_reg, p_name, p_source_invoice_id);
  RETURN QUERY SELECT v_supplier_id, v_canonical;
END; $$;


ALTER FUNCTION "public"."resolve_cost_supplier_for_invoice"("p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_from" "text", "p_invoice_number" "text", "p_source_invoice_id" "uuid") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."set_updated_by"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.updated_by := auth.uid();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."set_updated_by"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."shares_synced_subcontractor_staff_profile"("_viewer_id" "uuid", "_profile_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT
    public.user_subcontractor(_viewer_id) IS NOT NULL
    AND public.is_staff(_profile_id)
    AND EXISTS (
      SELECT 1
      FROM public.profiles p
      WHERE p.id = _profile_id
        AND p.subcontractor_id = public.user_subcontractor(_viewer_id)
    )
    AND EXISTS (
      SELECT 1
      FROM public.todo_list_subcontractor_syncs tls
      JOIN public.todo_list_assignments viewer_a
        ON viewer_a.list_id = tls.list_id
       AND viewer_a.user_id = _viewer_id
      JOIN public.todo_list_assignments staff_a
        ON staff_a.list_id = tls.list_id
       AND staff_a.user_id = _profile_id
      WHERE tls.subcontractor_id = public.user_subcontractor(_viewer_id)
    )
$$;


ALTER FUNCTION "public"."shares_synced_subcontractor_staff_profile"("_viewer_id" "uuid", "_profile_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."shares_todo_list_with"("_user_id" "uuid", "_other_user_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.todo_list_assignments a
    JOIN public.todo_list_assignments b ON a.list_id = b.list_id
    WHERE a.user_id = _user_id
      AND b.user_id = _other_user_id
  )
$$;


ALTER FUNCTION "public"."shares_todo_list_with"("_user_id" "uuid", "_other_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."split_line_matches_description_filter"("p_split_description" "text", "p_f_description" "text") RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1
    FROM unnest(public.parse_description_filter_terms(p_f_description)) AS term
    WHERE lower(coalesce(p_split_description, '')) LIKE '%' || lower(term) || '%'
  );
$$;


ALTER FUNCTION "public"."split_line_matches_description_filter"("p_split_description" "text", "p_f_description" "text") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."supplier_legal_name_key"("p_name" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT NULLIF(
    lower(btrim(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g'))),
    ''
  )
$$;


ALTER FUNCTION "public"."supplier_legal_name_key"("p_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sync_todo_list_assignments_for_profile"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.subcontractor_id IS NOT NULL AND COALESCE(NEW.active, true) THEN
      INSERT INTO public.todo_list_assignments (list_id, user_id, assigned_by)
      SELECT tls.list_id, NEW.id, tls.synced_by
      FROM public.todo_list_subcontractor_syncs tls
      WHERE tls.subcontractor_id = NEW.subcontractor_id
      ON CONFLICT (list_id, user_id) DO NOTHING;
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF COALESCE(NEW.active, true) = false AND COALESCE(OLD.active, true) = true THEN
      DELETE FROM public.todo_list_assignments tla
      USING public.todo_list_subcontractor_syncs tls
      WHERE tla.list_id = tls.list_id
        AND tla.user_id = NEW.id
        AND tls.subcontractor_id = COALESCE(OLD.subcontractor_id, NEW.subcontractor_id);
    END IF;

    IF OLD.subcontractor_id IS NOT NULL
       AND (NEW.subcontractor_id IS DISTINCT FROM OLD.subcontractor_id OR COALESCE(NEW.active, true) = false) THEN
      DELETE FROM public.todo_list_assignments tla
      USING public.todo_list_subcontractor_syncs tls
      WHERE tla.list_id = tls.list_id
        AND tla.user_id = NEW.id
        AND tls.subcontractor_id = OLD.subcontractor_id;
    END IF;

    IF NEW.subcontractor_id IS NOT NULL
       AND COALESCE(NEW.active, true)
       AND NEW.subcontractor_id IS DISTINCT FROM OLD.subcontractor_id THEN
      INSERT INTO public.todo_list_assignments (list_id, user_id, assigned_by)
      SELECT tls.list_id, NEW.id, tls.synced_by
      FROM public.todo_list_subcontractor_syncs tls
      WHERE tls.subcontractor_id = NEW.subcontractor_id
      ON CONFLICT (list_id, user_id) DO NOTHING;
    END IF;

    RETURN NEW;
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."sync_todo_list_assignments_for_profile"() OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."trusted_supplier_email_domain"("p_from" "text") RETURNS "text"
    LANGUAGE "sql" STABLE
    SET "search_path" TO 'public'
    AS $$
  SELECT CASE
    WHEN public.email_domain(p_from) IS NULL OR btrim(public.email_domain(p_from)) = ''
      OR public.is_generic_email_domain(public.email_domain(p_from))
      OR public.is_shared_invoice_portal_domain(public.email_domain(p_from))
      OR public.is_staff_relay_domain(public.email_domain(p_from))
    THEN NULL ELSE public.email_domain(p_from) END
$$;


ALTER FUNCTION "public"."trusted_supplier_email_domain"("p_from" "text") OWNER TO "postgres";


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


CREATE OR REPLACE FUNCTION "public"."upsert_cost_supplier_identifiers"("p_supplier_id" "uuid", "p_vat" "text" DEFAULT NULL::"text", "p_company_reg" "text" DEFAULT NULL::"text", "p_name" "text" DEFAULT NULL::"text", "p_source_invoice_id" "uuid" DEFAULT NULL::"uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_vat_key text;
  v_reg_key text;
  v_name_key text;
  v_existing_supplier uuid;
BEGIN
  IF p_supplier_id IS NULL THEN RETURN; END IF;
  v_vat_key := public.normalize_vat_number(p_vat);
  IF v_vat_key IS NOT NULL THEN
    SELECT supplier_id INTO v_existing_supplier FROM public.cost_supplier_identifiers WHERE identifier_type = 'vat' AND identifier_key = v_vat_key;
    IF v_existing_supplier IS NULL OR v_existing_supplier = p_supplier_id THEN
      INSERT INTO public.cost_supplier_identifiers (supplier_id, identifier_type, identifier_key, raw_value, source_invoice_id)
      VALUES (p_supplier_id, 'vat', v_vat_key, nullif(btrim(p_vat), ''), p_source_invoice_id)
      ON CONFLICT (identifier_type, identifier_key) DO NOTHING;
    END IF;
  END IF;
  v_reg_key := public.normalize_company_registration(p_company_reg);
  IF v_reg_key IS NOT NULL THEN
    SELECT supplier_id INTO v_existing_supplier FROM public.cost_supplier_identifiers WHERE identifier_type = 'company_registration' AND identifier_key = v_reg_key;
    IF v_existing_supplier IS NULL OR v_existing_supplier = p_supplier_id THEN
      INSERT INTO public.cost_supplier_identifiers (supplier_id, identifier_type, identifier_key, raw_value, source_invoice_id)
      VALUES (p_supplier_id, 'company_registration', v_reg_key, nullif(btrim(p_company_reg), ''), p_source_invoice_id)
      ON CONFLICT (identifier_type, identifier_key) DO NOTHING;
    END IF;
  END IF;
  IF p_name IS NOT NULL AND btrim(p_name) <> '' AND upper(btrim(p_name)) <> 'NA' THEN
    v_name_key := public.supplier_legal_name_key(p_name);
    IF v_name_key IS NOT NULL THEN
      SELECT supplier_id INTO v_existing_supplier FROM public.cost_supplier_identifiers WHERE identifier_type = 'legal_name' AND identifier_key = v_name_key;
      IF v_existing_supplier IS NULL OR v_existing_supplier = p_supplier_id THEN
        INSERT INTO public.cost_supplier_identifiers (supplier_id, identifier_type, identifier_key, raw_value, source_invoice_id)
        VALUES (p_supplier_id, 'legal_name', v_name_key, btrim(p_name), p_source_invoice_id)
        ON CONFLICT (identifier_type, identifier_key) DO NOTHING;
      END IF;
    END IF;
  END IF;
END;
$$;


ALTER FUNCTION "public"."upsert_cost_supplier_identifiers"("p_supplier_id" "uuid", "p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_source_invoice_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."user_subcontractor"("_user_id" "uuid") RETURNS "uuid"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT subcontractor_id FROM public.profiles WHERE id = _user_id
$$;


ALTER FUNCTION "public"."user_subcontractor"("_user_id" "uuid") OWNER TO "postgres";


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


CREATE TABLE IF NOT EXISTS "public"."cost_company_brand_aliases" (
    "brand_key" "text" NOT NULL,
    "canonical_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_company_brand_aliases" OWNER TO "postgres";


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
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "quantity" numeric
);


ALTER TABLE "public"."cost_invoice_splits" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_payment_remittances" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "company_name" "text" NOT NULL,
    "paid_at" timestamp with time zone NOT NULL,
    "nas_path" "text" NOT NULL,
    "total_net" numeric(12,2),
    "total_vat" numeric(12,2),
    "total_amount" numeric(12,2) DEFAULT 0 NOT NULL,
    "invoice_count" integer DEFAULT 0 NOT NULL,
    "lines" "jsonb" DEFAULT '[]'::"jsonb" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_payment_remittances" OWNER TO "postgres";


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
    "account_id" "uuid",
    "scan_paused" boolean DEFAULT false NOT NULL
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


CREATE TABLE IF NOT EXISTS "public"."cost_supplier_identifiers" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "supplier_id" "uuid" NOT NULL,
    "identifier_type" "text" NOT NULL,
    "identifier_key" "text" NOT NULL,
    "raw_value" "text",
    "source_invoice_id" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "cost_supplier_identifiers_identifier_type_check" CHECK (("identifier_type" = ANY (ARRAY['vat'::"text", 'company_registration'::"text", 'legal_name'::"text"])))
);


ALTER TABLE "public"."cost_supplier_identifiers" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cost_suppliers" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "canonical_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."cost_suppliers" OWNER TO "postgres";


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


CREATE TABLE IF NOT EXISTS "public"."notification_preferences" (
    "user_id" "uuid" NOT NULL,
    "timesheet_review" boolean DEFAULT true NOT NULL,
    "timesheet_outcome" boolean DEFAULT true NOT NULL,
    "holiday_review" boolean DEFAULT true NOT NULL,
    "holiday_outcome" boolean DEFAULT true NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "cost_payment" boolean DEFAULT true NOT NULL,
    "cost_review" boolean DEFAULT true NOT NULL,
    "timesheet_review_roles" "jsonb" DEFAULT '{"admin": true, "worker": true, "manager": true, "cjb_manager": true, "super_admin": true}'::"jsonb" NOT NULL,
    "holiday_review_roles" "jsonb" DEFAULT '{"admin": true, "worker": true, "manager": true, "cjb_manager": true, "super_admin": true}'::"jsonb" NOT NULL,
    "timesheet_decision" boolean DEFAULT true NOT NULL,
    "holiday_decision" boolean DEFAULT true NOT NULL,
    "todo_updates" boolean DEFAULT true NOT NULL,
    "timesheet_decision_roles" "jsonb" DEFAULT '{"admin": true, "worker": true, "manager": true, "cjb_manager": true, "super_admin": true}'::"jsonb" NOT NULL,
    "holiday_decision_roles" "jsonb" DEFAULT '{"admin": true, "worker": true, "manager": true, "cjb_manager": true, "super_admin": true}'::"jsonb" NOT NULL,
    "defect_review" boolean DEFAULT true NOT NULL,
    "defect_closed" boolean DEFAULT true NOT NULL,
    "defect_review_roles" "jsonb" DEFAULT '{"admin": true, "worker": true, "manager": true, "cjb_manager": true, "super_admin": true}'::"jsonb" NOT NULL,
    "job_assigned" boolean DEFAULT true NOT NULL,
    "vehicle_defect_submit_reminder" boolean DEFAULT true NOT NULL,
    "timesheet_submit_reminder" boolean DEFAULT true NOT NULL,
    "havs_submit_reminder" boolean DEFAULT true NOT NULL,
    "vehicle_service_due" boolean DEFAULT true NOT NULL,
    "todo_reminder" boolean DEFAULT true NOT NULL
);


ALTER TABLE "public"."notification_preferences" OWNER TO "postgres";


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
    "mfa_enabled" boolean DEFAULT false NOT NULL,
    "notification_prompt_seen" boolean DEFAULT false NOT NULL
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


CREATE TABLE IF NOT EXISTS "public"."push_subscriptions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "endpoint" "text" NOT NULL,
    "p256dh" "text" NOT NULL,
    "auth" "text" NOT NULL,
    "user_agent" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "last_used_at" timestamp with time zone
);


ALTER TABLE "public"."push_subscriptions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."rams_attendees" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "briefing_id" "uuid" NOT NULL,
    "position" smallint NOT NULL,
    "name" "text" NOT NULL,
    "signature_url" "text",
    "user_id" "uuid",
    "briefed_by_name" "text" NOT NULL,
    "briefing_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "briefer_signature_url" "text",
    "briefed_by_user_id" "uuid"
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


CREATE TABLE IF NOT EXISTS "public"."todo_item_attachments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "item_id" "uuid" NOT NULL,
    "nas_path" "text" NOT NULL,
    "filename" "text",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE ONLY "public"."todo_item_attachments" REPLICA IDENTITY FULL;


ALTER TABLE "public"."todo_item_attachments" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."todo_items" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "list_id" "uuid" NOT NULL,
    "title" "text" NOT NULL,
    "notes" "text",
    "completed_at" timestamp with time zone,
    "completed_by" "uuid",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_by" "uuid",
    "remind_at" timestamp with time zone,
    "reminder_sent_at" timestamp with time zone
);

ALTER TABLE ONLY "public"."todo_items" REPLICA IDENTITY FULL;


ALTER TABLE "public"."todo_items" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."todo_list_assignments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "list_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "assigned_by" "uuid",
    "assigned_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE ONLY "public"."todo_list_assignments" REPLICA IDENTITY FULL;


ALTER TABLE "public"."todo_list_assignments" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."todo_list_subcontractor_syncs" (
    "list_id" "uuid" NOT NULL,
    "subcontractor_id" "uuid" NOT NULL,
    "synced_by" "uuid",
    "synced_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."todo_list_subcontractor_syncs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."todo_lists" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "title" "text" NOT NULL,
    "description" "text",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "archived_at" timestamp with time zone,
    "pdf_revision" integer DEFAULT 1 NOT NULL,
    "updated_by" "uuid",
    "pdf_nas_path" "text",
    "pdf_content_hash" "text",
    "remind_at" timestamp with time zone,
    "reminder_sent_at" timestamp with time zone,
    "information_only" boolean DEFAULT false NOT NULL
);

ALTER TABLE ONLY "public"."todo_lists" REPLICA IDENTITY FULL;


ALTER TABLE "public"."todo_lists" OWNER TO "postgres";


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


CREATE TABLE IF NOT EXISTS "public"."user_notifications" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "preference" "text" NOT NULL,
    "title" "text" NOT NULL,
    "body" "text" NOT NULL,
    "url" "text" DEFAULT '/'::"text" NOT NULL,
    "read_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE ONLY "public"."user_notifications" REPLICA IDENTITY FULL;


ALTER TABLE "public"."user_notifications" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_roles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "role" "public"."app_role" NOT NULL
);


ALTER TABLE "public"."user_roles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_assignments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "assigned_by" "uuid",
    "assigned_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."vehicle_assignments" OWNER TO "postgres";


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
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "service_due_date" "date",
    "service_due_mileage" integer,
    "current_mileage" integer,
    "mot_due_date" "date",
    "tax_due_date" "date",
    "mot_reminded_at" timestamp with time zone,
    "tax_reminded_at" timestamp with time zone
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



ALTER TABLE ONLY "public"."cost_company_brand_aliases"
    ADD CONSTRAINT "cost_company_brand_aliases_pkey" PRIMARY KEY ("brand_key");



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



ALTER TABLE ONLY "public"."cost_payment_remittances"
    ADD CONSTRAINT "cost_payment_remittances_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_scan_skips"
    ADD CONSTRAINT "cost_scan_skips_pkey" PRIMARY KEY ("message_id");



ALTER TABLE ONLY "public"."cost_scan_state"
    ADD CONSTRAINT "cost_scan_state_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_skip_attachments"
    ADD CONSTRAINT "cost_skip_attachments_pkey" PRIMARY KEY ("sha256");



ALTER TABLE ONLY "public"."cost_supplier_identifiers"
    ADD CONSTRAINT "cost_supplier_identifiers_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cost_supplier_identifiers"
    ADD CONSTRAINT "cost_supplier_identifiers_type_key_unique" UNIQUE ("identifier_type", "identifier_key");



ALTER TABLE ONLY "public"."cost_suppliers"
    ADD CONSTRAINT "cost_suppliers_canonical_name_unique" UNIQUE ("canonical_name");



ALTER TABLE ONLY "public"."cost_suppliers"
    ADD CONSTRAINT "cost_suppliers_pkey" PRIMARY KEY ("id");



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



ALTER TABLE ONLY "public"."notification_preferences"
    ADD CONSTRAINT "notification_preferences_pkey" PRIMARY KEY ("user_id");



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



ALTER TABLE ONLY "public"."push_subscriptions"
    ADD CONSTRAINT "push_subscriptions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."push_subscriptions"
    ADD CONSTRAINT "push_subscriptions_user_endpoint_unique" UNIQUE ("user_id", "endpoint");



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



ALTER TABLE ONLY "public"."todo_item_attachments"
    ADD CONSTRAINT "todo_item_attachments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."todo_items"
    ADD CONSTRAINT "todo_items_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."todo_list_assignments"
    ADD CONSTRAINT "todo_list_assignments_list_id_user_id_key" UNIQUE ("list_id", "user_id");



ALTER TABLE ONLY "public"."todo_list_assignments"
    ADD CONSTRAINT "todo_list_assignments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."todo_list_subcontractor_syncs"
    ADD CONSTRAINT "todo_list_subcontractor_syncs_pkey" PRIMARY KEY ("list_id", "subcontractor_id");



ALTER TABLE ONLY "public"."todo_lists"
    ADD CONSTRAINT "todo_lists_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."toolbox_attendees"
    ADD CONSTRAINT "toolbox_attendees_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."toolbox_talks"
    ADD CONSTRAINT "toolbox_talks_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_notifications"
    ADD CONSTRAINT "user_notifications_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_role_key" UNIQUE ("user_id", "role");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_unique" UNIQUE ("user_id");



ALTER TABLE ONLY "public"."vehicle_assignments"
    ADD CONSTRAINT "vehicle_assignments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicle_assignments"
    ADD CONSTRAINT "vehicle_assignments_vehicle_id_key" UNIQUE ("vehicle_id");



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



CREATE INDEX "cost_invoices_duplicate_flags_idx" ON "public"."cost_invoices" USING "btree" ("id") WHERE ("is_duplicate" OR "has_duplicate_siblings");



CREATE INDEX "cost_invoices_full_field_dedupe_key_idx" ON "public"."cost_invoices" USING "btree" ("full_field_dedupe_key") WHERE ("full_field_dedupe_key" IS NOT NULL);



CREATE INDEX "cost_invoices_invoice_date_idx" ON "public"."cost_invoices" USING "btree" ("invoice_date" DESC);



CREATE UNIQUE INDEX "cost_invoices_msgid_unique" ON "public"."cost_invoices" USING "btree" ("source_message_id", "attachment_filename", COALESCE("invoice_number", ''::"text")) WHERE ("source_message_id" IS NOT NULL);



CREATE INDEX "cost_invoices_paid_idx" ON "public"."cost_invoices" USING "btree" ("paid_at");



CREATE INDEX "cost_invoices_search_document_idx" ON "public"."cost_invoices" USING "gin" ("search_document");



CREATE UNIQUE INDEX "cost_invoices_sha_unique" ON "public"."cost_invoices" USING "btree" ("attachment_sha256") WHERE ("attachment_sha256" IS NOT NULL);



CREATE INDEX "cost_invoices_source_received_at_idx" ON "public"."cost_invoices" USING "btree" ("source_received_at" DESC);



CREATE INDEX "cost_invoices_status_idx" ON "public"."cost_invoices" USING "btree" ("status");



CREATE UNIQUE INDEX "cost_invoices_unique_company_invoice_number" ON "public"."cost_invoices" USING "btree" ("company_invoice_key", "invoice_number_key") WHERE (("company_invoice_key" IS NOT NULL) AND ("invoice_number_key" IS NOT NULL) AND ("invoice_number_key" <> ALL (ARRAY['NA'::"text", 'N/A'::"text", 'NO-NUMBER'::"text", 'NONUMBER'::"text", 'NO_NUMBER'::"text"])));



CREATE INDEX "cost_payment_remittances_company_name_idx" ON "public"."cost_payment_remittances" USING "btree" ("company_name");



CREATE INDEX "cost_payment_remittances_paid_at_idx" ON "public"."cost_payment_remittances" USING "btree" ("paid_at" DESC);



CREATE UNIQUE INDEX "cost_scan_state_account_uniq" ON "public"."cost_scan_state" USING "btree" ("account_id");



CREATE INDEX "daily_briefings_briefer_id_time_delivered_idx" ON "public"."daily_briefings" USING "btree" ("briefer_id", "time_delivered" DESC);



CREATE INDEX "havs_log_items_log_idx" ON "public"."havs_log_items" USING "btree" ("log_id");



CREATE INDEX "havs_logs_worker_date_idx" ON "public"."havs_logs" USING "btree" ("worker_id", "log_date" DESC);



CREATE INDEX "holidays_dates_idx" ON "public"."holidays" USING "btree" ("start_date", "end_date");



CREATE INDEX "holidays_user_start_idx" ON "public"."holidays" USING "btree" ("user_id", "start_date");



CREATE INDEX "idx_cost_invoice_splits_cost_invoice_id" ON "public"."cost_invoice_splits" USING "btree" ("cost_invoice_id");



CREATE INDEX "idx_cost_invoice_splits_project_id" ON "public"."cost_invoice_splits" USING "btree" ("project_id");



CREATE INDEX "idx_cost_invoices_format_key" ON "public"."cost_invoices" USING "btree" ("invoice_format_key") WHERE ("invoice_format_key" IS NOT NULL);



CREATE INDEX "idx_cost_invoices_supplier_domain_format" ON "public"."cost_invoices" USING "btree" ("supplier_email_domain", "invoice_format_key") WHERE (("supplier_email_domain" IS NOT NULL) AND ("invoice_format_key" IS NOT NULL));



CREATE INDEX "idx_cost_invoices_supplier_id" ON "public"."cost_invoices" USING "btree" ("supplier_id") WHERE ("supplier_id" IS NOT NULL);



CREATE INDEX "idx_cost_supplier_identifiers_lookup" ON "public"."cost_supplier_identifiers" USING "btree" ("identifier_type", "identifier_key");



CREATE INDEX "idx_cost_supplier_identifiers_supplier" ON "public"."cost_supplier_identifiers" USING "btree" ("supplier_id");



CREATE INDEX "idx_invoice_lines_invoice_id" ON "public"."invoice_lines" USING "btree" ("invoice_id");



CREATE INDEX "idx_invoice_lines_project_id" ON "public"."invoice_lines" USING "btree" ("project_id");



CREATE INDEX "idx_push_subscriptions_user_id" ON "public"."push_subscriptions" USING "btree" ("user_id");



CREATE UNIQUE INDEX "integration_storage_active_uniq" ON "public"."integration_storage_backends" USING "btree" ("is_active") WHERE "is_active";



CREATE INDEX "invoices_client_id_idx" ON "public"."invoices" USING "btree" ("client_id");



CREATE INDEX "invoices_invoice_date_idx" ON "public"."invoices" USING "btree" ("invoice_date" DESC);



CREATE INDEX "invoices_invoice_number_idx" ON "public"."invoices" USING "btree" ("invoice_number" DESC);



CREATE INDEX "invoices_search_document_idx" ON "public"."invoices" USING "gin" ("search_document");



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



CREATE INDEX "todo_item_attachments_item_idx" ON "public"."todo_item_attachments" USING "btree" ("item_id");



CREATE INDEX "todo_items_due_reminder_idx" ON "public"."todo_items" USING "btree" ("remind_at") WHERE (("remind_at" IS NOT NULL) AND ("reminder_sent_at" IS NULL) AND ("completed_at" IS NULL));



CREATE INDEX "todo_items_list_idx" ON "public"."todo_items" USING "btree" ("list_id");



CREATE INDEX "todo_list_assignments_list_idx" ON "public"."todo_list_assignments" USING "btree" ("list_id");



CREATE INDEX "todo_list_assignments_user_idx" ON "public"."todo_list_assignments" USING "btree" ("user_id");



CREATE INDEX "todo_list_subcontractor_syncs_sub_idx" ON "public"."todo_list_subcontractor_syncs" USING "btree" ("subcontractor_id");



CREATE INDEX "todo_lists_due_reminder_idx" ON "public"."todo_lists" USING "btree" ("remind_at") WHERE (("remind_at" IS NOT NULL) AND ("reminder_sent_at" IS NULL) AND ("archived_at" IS NULL));



CREATE INDEX "toolbox_talks_briefer_id_talk_date_idx" ON "public"."toolbox_talks" USING "btree" ("briefer_id", "talk_date" DESC);



CREATE INDEX "user_notifications_user_created_idx" ON "public"."user_notifications" USING "btree" ("user_id", "created_at" DESC);



CREATE INDEX "user_notifications_user_unread_idx" ON "public"."user_notifications" USING "btree" ("user_id", "created_at" DESC) WHERE ("read_at" IS NULL);



CREATE INDEX "vehicle_assignments_user_idx" ON "public"."vehicle_assignments" USING "btree" ("user_id");



CREATE INDEX "vehicle_assignments_vehicle_idx" ON "public"."vehicle_assignments" USING "btree" ("vehicle_id");



CREATE INDEX "vehicle_defects_worker_id_inspection_date_idx" ON "public"."vehicle_defects" USING "btree" ("worker_id", "inspection_date" DESC);



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."daily_briefings" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."havs_logs" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."plant_inspections" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."rams_briefings" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."timesheets" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."toolbox_talks" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "bump_revision_trg" BEFORE UPDATE ON "public"."vehicle_defects" FOR EACH ROW EXECUTE FUNCTION "public"."bump_revision"();



CREATE OR REPLACE TRIGGER "cost_invoices_after_write_refresh_duplicate_flags" AFTER INSERT OR DELETE OR UPDATE OF "company_name", "invoice_number", "po_reference", "invoice_date", "due_date", "description", "net_amount", "vat_amount", "total_amount", "vat_treatment", "currency" ON "public"."cost_invoices" FOR EACH ROW EXECUTE FUNCTION "public"."cost_invoices_after_write_refresh_duplicate_flags"();



CREATE OR REPLACE TRIGGER "cost_invoices_canonical_company" BEFORE INSERT OR UPDATE OF "company_name", "source_email_from", "invoice_number", "supplier_vat_number", "supplier_company_reg_number" ON "public"."cost_invoices" FOR EACH ROW EXECUTE FUNCTION "public"."cost_invoices_apply_canonical_company"();



CREATE OR REPLACE TRIGGER "cost_invoices_search_document" BEFORE INSERT OR UPDATE OF "company_name", "invoice_number", "po_reference", "description", "source_subject" ON "public"."cost_invoices" FOR EACH ROW EXECUTE FUNCTION "public"."cost_invoices_search_document_trigger"();



CREATE OR REPLACE TRIGGER "cost_invoices_set_full_field_dedupe_key" BEFORE INSERT OR UPDATE OF "company_name", "invoice_number", "po_reference", "invoice_date", "due_date", "description", "net_amount", "vat_amount", "total_amount", "vat_treatment", "currency" ON "public"."cost_invoices" FOR EACH ROW EXECUTE FUNCTION "public"."cost_invoices_set_full_field_dedupe_key_trigger"();



CREATE OR REPLACE TRIGGER "cost_invoices_set_updated_at" BEFORE UPDATE ON "public"."cost_invoices" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "daily_briefing_autoapprove_t" BEFORE INSERT ON "public"."daily_briefings" FOR EACH ROW EXECUTE FUNCTION "public"."daily_briefing_autoapprove"();



CREATE OR REPLACE TRIGGER "employee_pay_set_updated_at" BEFORE UPDATE ON "public"."employee_pay" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "employee_starters_updated_at" BEFORE UPDATE ON "public"."employee_starters" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "havs_logs_autoapprove" BEFORE INSERT ON "public"."havs_logs" FOR EACH ROW EXECUTE FUNCTION "public"."havs_autoapprove"();



CREATE OR REPLACE TRIGGER "havs_logs_updated_at" BEFORE UPDATE ON "public"."havs_logs" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "havs_tools_updated_at" BEFORE UPDATE ON "public"."havs_tools" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at_havs_tools"();



CREATE OR REPLACE TRIGGER "holidays_before_insert_autoapprove" BEFORE INSERT ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_autoapprove"();



CREATE OR REPLACE TRIGGER "holidays_before_insert_overlap" BEFORE INSERT ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_prevent_overlap"();



CREATE OR REPLACE TRIGGER "holidays_before_update_amend_resets_status" BEFORE UPDATE OF "start_date", "end_date", "note" ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_amend_resets_status"();



CREATE OR REPLACE TRIGGER "holidays_before_update_overlap" BEFORE UPDATE OF "start_date", "end_date", "user_id", "status" ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_prevent_overlap"();



CREATE OR REPLACE TRIGGER "holidays_before_update_status_guard" BEFORE UPDATE OF "status" ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."holidays_enforce_status_change"();



CREATE OR REPLACE TRIGGER "holidays_set_updated_at" BEFORE UPDATE ON "public"."holidays" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "invoices_search_document" BEFORE INSERT OR UPDATE OF "invoice_number", "client_name_snapshot", "client_reference", "purchase_order", "site_name", "description" ON "public"."invoices" FOR EACH ROW EXECUTE FUNCTION "public"."invoices_search_document_trigger"();



CREATE OR REPLACE TRIGGER "profiles_guard_sensitive_self_update" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."profiles_guard_sensitive_self_update"();



CREATE OR REPLACE TRIGGER "profiles_sync_todo_list_assignments" AFTER INSERT OR UPDATE OF "subcontractor_id", "active" ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."sync_todo_list_assignments_for_profile"();



CREATE OR REPLACE TRIGGER "set_cost_company_aliases_updated_at" BEFORE UPDATE ON "public"."cost_company_aliases" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_cost_company_brand_aliases_updated_at" BEFORE UPDATE ON "public"."cost_company_brand_aliases" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_cost_company_subcontractors_updated_at" BEFORE UPDATE ON "public"."cost_company_subcontractors" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_cost_invoice_splits_updated_at" BEFORE UPDATE ON "public"."cost_invoice_splits" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_invoice_lines_updated_at" BEFORE UPDATE ON "public"."invoice_lines" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "set_nas_sync_queue_updated_at" BEFORE UPDATE ON "public"."nas_sync_queue" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "todo_items_enforce_update_permissions" BEFORE UPDATE ON "public"."todo_items" FOR EACH ROW EXECUTE FUNCTION "public"."enforce_todo_item_update_permissions"();



CREATE OR REPLACE TRIGGER "todo_items_set_updated_at" BEFORE UPDATE ON "public"."todo_items" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "todo_items_set_updated_by" BEFORE UPDATE ON "public"."todo_items" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_by"();



CREATE OR REPLACE TRIGGER "todo_list_subcontractor_syncs_backfill" AFTER INSERT ON "public"."todo_list_subcontractor_syncs" FOR EACH ROW EXECUTE FUNCTION "public"."backfill_todo_list_subcontractor_sync"();



CREATE OR REPLACE TRIGGER "todo_lists_auto_assign_creator" AFTER INSERT ON "public"."todo_lists" FOR EACH ROW EXECUTE FUNCTION "public"."auto_assign_todo_list_creator"();



CREATE OR REPLACE TRIGGER "todo_lists_set_updated_by" BEFORE UPDATE ON "public"."todo_lists" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_by"();



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



ALTER TABLE ONLY "public"."cost_invoices"
    ADD CONSTRAINT "cost_invoices_supplier_id_fkey" FOREIGN KEY ("supplier_id") REFERENCES "public"."cost_suppliers"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."cost_supplier_identifiers"
    ADD CONSTRAINT "cost_supplier_identifiers_source_invoice_id_fkey" FOREIGN KEY ("source_invoice_id") REFERENCES "public"."cost_invoices"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."cost_supplier_identifiers"
    ADD CONSTRAINT "cost_supplier_identifiers_supplier_id_fkey" FOREIGN KEY ("supplier_id") REFERENCES "public"."cost_suppliers"("id") ON DELETE CASCADE;



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



ALTER TABLE ONLY "public"."notification_preferences"
    ADD CONSTRAINT "notification_preferences_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



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



ALTER TABLE ONLY "public"."push_subscriptions"
    ADD CONSTRAINT "push_subscriptions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."rams_attendees"
    ADD CONSTRAINT "rams_attendees_briefed_by_user_id_fkey" FOREIGN KEY ("briefed_by_user_id") REFERENCES "public"."profiles"("id");



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



ALTER TABLE ONLY "public"."todo_item_attachments"
    ADD CONSTRAINT "todo_item_attachments_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."todo_item_attachments"
    ADD CONSTRAINT "todo_item_attachments_item_id_fkey" FOREIGN KEY ("item_id") REFERENCES "public"."todo_items"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."todo_items"
    ADD CONSTRAINT "todo_items_completed_by_fkey" FOREIGN KEY ("completed_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."todo_items"
    ADD CONSTRAINT "todo_items_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."todo_items"
    ADD CONSTRAINT "todo_items_list_id_fkey" FOREIGN KEY ("list_id") REFERENCES "public"."todo_lists"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."todo_items"
    ADD CONSTRAINT "todo_items_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."todo_list_assignments"
    ADD CONSTRAINT "todo_list_assignments_assigned_by_fkey" FOREIGN KEY ("assigned_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."todo_list_assignments"
    ADD CONSTRAINT "todo_list_assignments_list_id_fkey" FOREIGN KEY ("list_id") REFERENCES "public"."todo_lists"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."todo_list_assignments"
    ADD CONSTRAINT "todo_list_assignments_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."todo_list_subcontractor_syncs"
    ADD CONSTRAINT "todo_list_subcontractor_syncs_list_id_fkey" FOREIGN KEY ("list_id") REFERENCES "public"."todo_lists"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."todo_list_subcontractor_syncs"
    ADD CONSTRAINT "todo_list_subcontractor_syncs_subcontractor_id_fkey" FOREIGN KEY ("subcontractor_id") REFERENCES "public"."subcontractors"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."todo_list_subcontractor_syncs"
    ADD CONSTRAINT "todo_list_subcontractor_syncs_synced_by_fkey" FOREIGN KEY ("synced_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."todo_lists"
    ADD CONSTRAINT "todo_lists_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."todo_lists"
    ADD CONSTRAINT "todo_lists_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



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



ALTER TABLE ONLY "public"."user_notifications"
    ADD CONSTRAINT "user_notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_assignments"
    ADD CONSTRAINT "vehicle_assignments_assigned_by_fkey" FOREIGN KEY ("assigned_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicle_assignments"
    ADD CONSTRAINT "vehicle_assignments_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_assignments"
    ADD CONSTRAINT "vehicle_assignments_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



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



CREATE POLICY "Admins delete cost payment remittances" ON "public"."cost_payment_remittances" FOR DELETE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins insert app settings" ON "public"."app_settings" FOR INSERT TO "authenticated" WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins manage cost company aliases" ON "public"."cost_company_aliases" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins manage cost company brand aliases" ON "public"."cost_company_brand_aliases" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins manage cost company domain aliases" ON "public"."cost_company_domain_aliases" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins manage cost_supplier_identifiers" ON "public"."cost_supplier_identifiers" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins manage cost_suppliers" ON "public"."cost_suppliers" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "Admins read cost invoices" ON "public"."cost_invoices" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "Admins read cost payment remittances" ON "public"."cost_payment_remittances" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



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


ALTER TABLE "public"."cost_company_brand_aliases" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_company_domain_aliases" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_company_subcontractors" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "cost_company_subcontractors admin all" ON "public"."cost_company_subcontractors" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



ALTER TABLE "public"."cost_dated_scans" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_invoice_splits" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "cost_invoice_splits admin all" ON "public"."cost_invoice_splits" TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role"))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



ALTER TABLE "public"."cost_invoices" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_payment_remittances" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_scan_skips" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_scan_state" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_skip_attachments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_supplier_identifiers" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cost_suppliers" ENABLE ROW LEVEL SECURITY;


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


ALTER TABLE "public"."notification_preferences" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "notification_preferences self insert" ON "public"."notification_preferences" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "notification_preferences self read" ON "public"."notification_preferences" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



CREATE POLICY "notification_preferences self update" ON "public"."notification_preferences" FOR UPDATE TO "authenticated" USING (("user_id" = "auth"."uid"())) WITH CHECK (("user_id" = "auth"."uid"()));



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



CREATE POLICY "profiles self read" ON "public"."profiles" FOR SELECT TO "authenticated" USING ((("id" = "auth"."uid"()) OR "public"."is_staff"("auth"."uid"()) OR "public"."shares_todo_list_with"("auth"."uid"(), "id") OR "public"."shares_synced_subcontractor_staff_profile"("auth"."uid"(), "id")));



CREATE POLICY "profiles self update" ON "public"."profiles" FOR UPDATE TO "authenticated" USING (("id" = "auth"."uid"())) WITH CHECK (("id" = "auth"."uid"()));



ALTER TABLE "public"."project_assignments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."projects" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "projects admin update" ON "public"."projects" FOR UPDATE TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "projects admin write" ON "public"."projects" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "projects read" ON "public"."projects" FOR SELECT TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role") OR ("archived_at" IS NULL)));



ALTER TABLE "public"."push_subscriptions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "push_subscriptions self delete" ON "public"."push_subscriptions" FOR DELETE TO "authenticated" USING (("user_id" = "auth"."uid"()));



CREATE POLICY "push_subscriptions self insert" ON "public"."push_subscriptions" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "push_subscriptions self read" ON "public"."push_subscriptions" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



CREATE POLICY "rams assigned read" ON "public"."rams_briefings" FOR SELECT TO "authenticated" USING ((("project_id" IS NOT NULL) AND "public"."is_assigned_to_project"("auth"."uid"(), "project_id")));



CREATE POLICY "rams cjb_manager read" ON "public"."rams_briefings" FOR SELECT TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role"));



CREATE POLICY "rams delete admin or manager scope" ON "public"."rams_briefings" FOR DELETE TO "authenticated" USING ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "rams manage delete" ON "public"."rams_briefings" FOR DELETE TO "authenticated" USING ("public"."can_manage_rams_briefing"("briefer_id"));



CREATE POLICY "rams manage update" ON "public"."rams_briefings" FOR UPDATE TO "authenticated" USING ("public"."can_manage_rams_briefing"("briefer_id")) WITH CHECK ("public"."can_manage_rams_briefing"("briefer_id"));



CREATE POLICY "rams owner insert" ON "public"."rams_briefings" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "rams read scope" ON "public"."rams_briefings" FOR SELECT TO "authenticated" USING ("public"."can_manage_submission"("briefer_id"));



CREATE POLICY "rams_att owner write" ON "public"."rams_attendees" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."rams_briefings" "b"
  WHERE (("b"."id" = "rams_attendees"."briefing_id") AND "public"."can_manage_rams_briefing"("b"."briefer_id"))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."rams_briefings" "b"
  WHERE (("b"."id" = "rams_attendees"."briefing_id") AND "public"."can_manage_rams_briefing"("b"."briefer_id")))));



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



CREATE POLICY "todo assignments delete" ON "public"."todo_list_assignments" FOR DELETE TO "authenticated" USING ("public"."can_assign_todo_list"("auth"."uid"(), "list_id", "user_id"));



CREATE POLICY "todo assignments insert" ON "public"."todo_list_assignments" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_assign_todo_list"("auth"."uid"(), "list_id", "user_id"));



CREATE POLICY "todo assignments read" ON "public"."todo_list_assignments" FOR SELECT TO "authenticated" USING (("public"."is_assigned_to_todo_list"("auth"."uid"(), "list_id") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "todo attachments delete" ON "public"."todo_item_attachments" FOR DELETE TO "authenticated" USING ("public"."can_modify_todo_item"("auth"."uid"(), "item_id"));



CREATE POLICY "todo attachments insert" ON "public"."todo_item_attachments" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_modify_todo_item"("auth"."uid"(), "item_id"));



CREATE POLICY "todo attachments read" ON "public"."todo_item_attachments" FOR SELECT TO "authenticated" USING ("public"."can_access_todo_item"("auth"."uid"(), "item_id"));



CREATE POLICY "todo items delete" ON "public"."todo_items" FOR DELETE TO "authenticated" USING ("public"."can_modify_todo_item"("auth"."uid"(), "id"));



CREATE POLICY "todo items insert" ON "public"."todo_items" FOR INSERT TO "authenticated" WITH CHECK ("public"."can_access_todo_list"("auth"."uid"(), "list_id"));



CREATE POLICY "todo items read" ON "public"."todo_items" FOR SELECT TO "authenticated" USING ("public"."can_access_todo_list"("auth"."uid"(), "list_id"));



CREATE POLICY "todo items update" ON "public"."todo_items" FOR UPDATE TO "authenticated" USING (("public"."can_modify_todo_item"("auth"."uid"(), "id") OR "public"."can_complete_todo_item"("auth"."uid"(), "id"))) WITH CHECK (("public"."can_modify_todo_item"("auth"."uid"(), "id") OR "public"."can_complete_todo_item"("auth"."uid"(), "id")));



CREATE POLICY "todo list sync delete" ON "public"."todo_list_subcontractor_syncs" FOR DELETE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND "public"."is_assigned_to_todo_list"("auth"."uid"(), "list_id") AND ("public"."user_subcontractor"("auth"."uid"()) = "subcontractor_id")) OR ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") AND "public"."is_assigned_to_todo_list"("auth"."uid"(), "list_id"))));



CREATE POLICY "todo list sync insert" ON "public"."todo_list_subcontractor_syncs" FOR INSERT TO "authenticated" WITH CHECK (("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") AND "public"."is_assigned_to_todo_list"("auth"."uid"(), "list_id") AND ("public"."user_subcontractor"("auth"."uid"()) = "subcontractor_id")) OR ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") AND "public"."is_assigned_to_todo_list"("auth"."uid"(), "list_id"))));



CREATE POLICY "todo list sync read" ON "public"."todo_list_subcontractor_syncs" FOR SELECT TO "authenticated" USING (("public"."is_assigned_to_todo_list"("auth"."uid"(), "list_id") OR "public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role")));



CREATE POLICY "todo lists delete" ON "public"."todo_lists" FOR DELETE TO "authenticated" USING ("public"."can_delete_todo_list"("auth"."uid"(), "id"));



CREATE POLICY "todo lists insert" ON "public"."todo_lists" FOR INSERT TO "authenticated" WITH CHECK (("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'manager'::"public"."app_role") OR "public"."has_role"("auth"."uid"(), 'cjb_manager'::"public"."app_role")));



CREATE POLICY "todo lists read" ON "public"."todo_lists" FOR SELECT TO "authenticated" USING ("public"."can_access_todo_list"("auth"."uid"(), "id"));



CREATE POLICY "todo lists update" ON "public"."todo_lists" FOR UPDATE TO "authenticated" USING (("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") AND "public"."is_assigned_to_todo_list"("auth"."uid"(), "id")))) WITH CHECK (("public"."has_role"("auth"."uid"(), 'super_admin'::"public"."app_role") OR ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role") AND "public"."is_assigned_to_todo_list"("auth"."uid"(), "id"))));



ALTER TABLE "public"."todo_item_attachments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."todo_items" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."todo_list_assignments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."todo_list_subcontractor_syncs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."todo_lists" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."toolbox_attendees" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."toolbox_talks" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_notifications" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "user_notifications self delete" ON "public"."user_notifications" FOR DELETE TO "authenticated" USING (("user_id" = "auth"."uid"()));



CREATE POLICY "user_notifications self read" ON "public"."user_notifications" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



CREATE POLICY "user_notifications self update" ON "public"."user_notifications" FOR UPDATE TO "authenticated" USING (("user_id" = "auth"."uid"())) WITH CHECK (("user_id" = "auth"."uid"()));



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



CREATE POLICY "vehicle assignments admin write" ON "public"."vehicle_assignments" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "vehicle assignments read" ON "public"."vehicle_assignments" FOR SELECT TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR "public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")));



ALTER TABLE "public"."vehicle_assignments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicle_defect_items" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicle_defects" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicles admin write" ON "public"."vehicles" TO "authenticated" USING ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role")) WITH CHECK ("public"."has_role"("auth"."uid"(), 'admin'::"public"."app_role"));



CREATE POLICY "vehicles read authed" ON "public"."vehicles" FOR SELECT TO "authenticated" USING (true);





ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";






ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."todo_item_attachments";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."todo_items";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."todo_list_assignments";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."todo_lists";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."user_notifications";



SET SESSION AUTHORIZATION "postgres";
RESET SESSION AUTHORIZATION;






GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";








































































































































































































































































REVOKE ALL ON FUNCTION "public"."admin_set_vault_secret"("p_name" "text", "p_value" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."admin_set_vault_secret"("p_name" "text", "p_value" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."aggregate_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_payment_month" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."aggregate_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_payment_month" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."aggregate_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_payment_month" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."aggregate_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_payment_month" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."aggregate_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."aggregate_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."aggregate_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."aggregate_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."auto_assign_todo_list_creator"() TO "anon";
GRANT ALL ON FUNCTION "public"."auto_assign_todo_list_creator"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."auto_assign_todo_list_creator"() TO "service_role";



GRANT ALL ON FUNCTION "public"."backfill_todo_list_subcontractor_sync"() TO "anon";
GRANT ALL ON FUNCTION "public"."backfill_todo_list_subcontractor_sync"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."backfill_todo_list_subcontractor_sync"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."bump_revision"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."bump_revision"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_access_todo_item"("_user_id" "uuid", "_item_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_access_todo_item"("_user_id" "uuid", "_item_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_todo_item"("_user_id" "uuid", "_item_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_access_todo_list"("_user_id" "uuid", "_list_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_access_todo_list"("_user_id" "uuid", "_list_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_todo_list"("_user_id" "uuid", "_list_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_assign_todo_list"("_assigner_id" "uuid", "_list_id" "uuid", "_target_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_assign_todo_list"("_assigner_id" "uuid", "_list_id" "uuid", "_target_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_assign_todo_list"("_assigner_id" "uuid", "_list_id" "uuid", "_target_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_complete_todo_item"("_user_id" "uuid", "_item_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_complete_todo_item"("_user_id" "uuid", "_item_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_complete_todo_item"("_user_id" "uuid", "_item_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_delete_todo_list"("_user_id" "uuid", "_list_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_delete_todo_list"("_user_id" "uuid", "_list_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_delete_todo_list"("_user_id" "uuid", "_list_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_manage_rams_briefing"("_briefer_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_manage_rams_briefing"("_briefer_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_manage_rams_briefing"("_briefer_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_manage_submission"("_worker_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."can_modify_todo_item"("_user_id" "uuid", "_item_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."can_modify_todo_item"("_user_id" "uuid", "_item_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_modify_todo_item"("_user_id" "uuid", "_item_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."company_match_key"("p_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."company_match_key"("p_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."company_match_key"("p_name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."continue_cost_scan"("p_url" "text", "p_apikey" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."continue_cost_scan"("p_url" "text", "p_apikey" "text") TO "service_role";



GRANT ALL ON TABLE "public"."cost_invoices" TO "anon";
GRANT ALL ON TABLE "public"."cost_invoices" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_invoices" TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_build_search_document"("p_row" "public"."cost_invoices") TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_build_search_document"("p_row" "public"."cost_invoices") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_build_search_document"("p_row" "public"."cost_invoices") TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_ci_dedupe_key"("p_company_invoice_key" "text", "p_invoice_number_key" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_ci_dedupe_key"("p_company_invoice_key" "text", "p_invoice_number_key" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_ci_dedupe_key"("p_company_invoice_key" "text", "p_invoice_number_key" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_full_field_dedupe_key"("p_company_name" "text", "p_invoice_number" "text", "p_po_reference" "text", "p_invoice_date" "date", "p_due_date" "date", "p_description" "text", "p_net_amount" numeric, "p_vat_amount" numeric, "p_total_amount" numeric, "p_vat_treatment" "text", "p_currency" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_full_field_dedupe_key"("p_company_name" "text", "p_invoice_number" "text", "p_po_reference" "text", "p_invoice_date" "date", "p_due_date" "date", "p_description" "text", "p_net_amount" numeric, "p_vat_amount" numeric, "p_total_amount" numeric, "p_vat_treatment" "text", "p_currency" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_full_field_dedupe_key"("p_company_name" "text", "p_invoice_number" "text", "p_po_reference" "text", "p_invoice_date" "date", "p_due_date" "date", "p_description" "text", "p_net_amount" numeric, "p_vat_amount" numeric, "p_total_amount" numeric, "p_vat_treatment" "text", "p_currency" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_invoice_project_label"("p_project_id" "uuid", "p_project_other" "text", "p_is_overhead" boolean, "p_project_code" "text", "p_project_description" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_invoice_project_label"("p_project_id" "uuid", "p_project_other" "text", "p_is_overhead" boolean, "p_project_code" "text", "p_project_description" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_invoice_project_label"("p_project_id" "uuid", "p_project_other" "text", "p_is_overhead" boolean, "p_project_code" "text", "p_project_description" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_matches_project"("p_invoice" "public"."cost_invoices", "p_split_project_id" "uuid", "p_split_project_other" "text", "p_split_is_overhead" boolean, "p_f_project" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_matches_project"("p_invoice" "public"."cost_invoices", "p_split_project_id" "uuid", "p_split_project_other" "text", "p_split_is_overhead" boolean, "p_f_project" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_matches_project"("p_invoice" "public"."cost_invoices", "p_split_project_id" "uuid", "p_split_project_other" "text", "p_split_is_overhead" boolean, "p_f_project" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_norm_amount"("p_value" numeric) TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_norm_amount"("p_value" numeric) TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_norm_amount"("p_value" numeric) TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_norm_text"("p_value" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_norm_text"("p_value" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_norm_text"("p_value" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_passes_filters"("p_ci" "public"."cost_invoices", "p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean) TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_passes_filters"("p_ci" "public"."cost_invoices", "p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_passes_filters"("p_ci" "public"."cost_invoices", "p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean) TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoice_sort_value"("p_row" "public"."cost_invoices", "p_sort_key" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoice_sort_value"("p_row" "public"."cost_invoices", "p_sort_key" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoice_sort_value"("p_row" "public"."cost_invoices", "p_sort_key" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoices_after_write_refresh_duplicate_flags"() TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoices_after_write_refresh_duplicate_flags"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoices_after_write_refresh_duplicate_flags"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."cost_invoices_apply_canonical_company"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cost_invoices_apply_canonical_company"() TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoices_search_document_trigger"() TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoices_search_document_trigger"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoices_search_document_trigger"() TO "service_role";



GRANT ALL ON FUNCTION "public"."cost_invoices_set_full_field_dedupe_key_trigger"() TO "anon";
GRANT ALL ON FUNCTION "public"."cost_invoices_set_full_field_dedupe_key_trigger"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cost_invoices_set_full_field_dedupe_key_trigger"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."count_pending_timesheet_reviews"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."count_pending_timesheet_reviews"() TO "anon";
GRANT ALL ON FUNCTION "public"."count_pending_timesheet_reviews"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."count_pending_timesheet_reviews"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."daily_briefing_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."daily_briefing_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."delete_cost_payment_remittances_for_invoices"("p_invoice_ids" "uuid"[]) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."delete_cost_payment_remittances_for_invoices"("p_invoice_ids" "uuid"[]) TO "anon";
GRANT ALL ON FUNCTION "public"."delete_cost_payment_remittances_for_invoices"("p_invoice_ids" "uuid"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_cost_payment_remittances_for_invoices"("p_invoice_ids" "uuid"[]) TO "service_role";



REVOKE ALL ON FUNCTION "public"."delete_integration_secret"("p_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."delete_integration_secret"("p_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_integration_secret"("p_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."email_domain"("p_from" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."email_domain"("p_from" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."email_domain"("p_from" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."enforce_todo_item_update_permissions"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."enforce_todo_item_update_permissions"() TO "service_role";



GRANT ALL ON FUNCTION "public"."find_or_create_cost_supplier"("p_canonical_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."find_or_create_cost_supplier"("p_canonical_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."find_or_create_cost_supplier"("p_canonical_name" "text") TO "service_role";



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



REVOKE ALL ON FUNCTION "public"."holidays_prevent_overlap"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."holidays_prevent_overlap"() TO "service_role";



GRANT ALL ON TABLE "public"."invoices" TO "anon";
GRANT ALL ON TABLE "public"."invoices" TO "authenticated";
GRANT ALL ON TABLE "public"."invoices" TO "service_role";



GRANT ALL ON FUNCTION "public"."invoice_build_search_document"("p_row" "public"."invoices") TO "anon";
GRANT ALL ON FUNCTION "public"."invoice_build_search_document"("p_row" "public"."invoices") TO "authenticated";
GRANT ALL ON FUNCTION "public"."invoice_build_search_document"("p_row" "public"."invoices") TO "service_role";



GRANT ALL ON FUNCTION "public"."invoice_format_key"("p_invoice_number" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."invoice_format_key"("p_invoice_number" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."invoice_format_key"("p_invoice_number" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."invoices_before_insert"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."invoices_before_insert"() TO "service_role";



GRANT ALL ON FUNCTION "public"."invoices_search_document_trigger"() TO "anon";
GRANT ALL ON FUNCTION "public"."invoices_search_document_trigger"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."invoices_search_document_trigger"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_assigned_to_project"("_user_id" "uuid", "_project_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_assigned_to_todo_list"("_user_id" "uuid", "_list_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_assigned_to_todo_list"("_user_id" "uuid", "_list_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_assigned_to_todo_list"("_user_id" "uuid", "_list_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_generic_email_domain"("p_domain" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_generic_email_domain"("p_domain" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_generic_email_domain"("p_domain" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_legal_entity_name"("p_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_legal_entity_name"("p_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_legal_entity_name"("p_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_shared_invoice_portal_domain"("p_domain" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_staff"("_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_staff"("_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_staff"("_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_staff_relay_domain"("p_domain" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_staff_relay_domain"("p_domain" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_staff_relay_domain"("p_domain" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."list_cost_duplicate_id_sets"() TO "anon";
GRANT ALL ON FUNCTION "public"."list_cost_duplicate_id_sets"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_cost_duplicate_id_sets"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."list_cost_invoice_ids_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_f_company_exact" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."list_cost_invoice_ids_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_f_company_exact" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."list_cost_invoice_ids_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_f_company_exact" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_cost_invoice_ids_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_f_company_exact" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."list_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer, "p_unpaginated" boolean, "p_cursor_sort_value" "text", "p_cursor_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."list_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer, "p_unpaginated" boolean, "p_cursor_sort_value" "text", "p_cursor_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."list_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer, "p_unpaginated" boolean, "p_cursor_sort_value" "text", "p_cursor_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_cost_invoices"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_sort_key" "text", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer, "p_unpaginated" boolean, "p_cursor_sort_value" "text", "p_cursor_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."list_cost_payment_remittances"("p_company" "text", "p_paid_from" "date", "p_paid_to" "date", "p_limit" integer, "p_offset" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."list_cost_payment_remittances"("p_company" "text", "p_paid_from" "date", "p_paid_to" "date", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."list_cost_payment_remittances"("p_company" "text", "p_paid_from" "date", "p_paid_to" "date", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_cost_payment_remittances"("p_company" "text", "p_paid_from" "date", "p_paid_to" "date", "p_limit" integer, "p_offset" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."list_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."list_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."list_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_invoices"("p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid", "p_sort_dir" "text", "p_limit" integer, "p_offset" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer, "p_sensitive_owner_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer, "p_sensitive_owner_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer, "p_sensitive_owner_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_submissions_browser"("p_from" "date", "p_to" "date", "p_kinds" "text"[], "p_worker_id" "uuid", "p_group" "text", "p_client" "uuid", "p_search" "text", "p_allowed_worker_ids" "uuid"[], "p_limit" integer, "p_offset" integer, "p_sensitive_owner_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."lookup_cost_supplier_by_identifiers"("p_vat" "text", "p_company_reg" "text", "p_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."lookup_cost_supplier_by_identifiers"("p_vat" "text", "p_company_reg" "text", "p_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."lookup_cost_supplier_by_identifiers"("p_vat" "text", "p_company_reg" "text", "p_name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."mark_cost_invoices_paid_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_paid" boolean, "p_selected_ids" "uuid"[]) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."mark_cost_invoices_paid_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_paid" boolean, "p_selected_ids" "uuid"[]) TO "anon";
GRANT ALL ON FUNCTION "public"."mark_cost_invoices_paid_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_paid" boolean, "p_selected_ids" "uuid"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."mark_cost_invoices_paid_filtered"("p_f_text" "text", "p_f_description" "text", "p_f_treatment" "text", "p_f_status" "text", "p_f_doc_type" "text", "p_f_company" "text", "p_f_from" "date", "p_f_to" "date", "p_f_po" "text", "p_f_due_from" "date", "p_f_due_to" "date", "p_f_paid" "text", "p_f_cis" "text", "p_f_project" "text", "p_f_check" "text", "p_dup_only" boolean, "p_missing_due_date" boolean, "p_paid" boolean, "p_selected_ids" "uuid"[]) TO "service_role";



REVOKE ALL ON FUNCTION "public"."match_subcontractor_by_company"("p_company" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."match_subcontractor_by_company"("p_company" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."most_common_cost_company_name"("p_match_key" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."most_common_cost_company_name"("p_match_key" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."most_common_cost_company_name"("p_match_key" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."normalize_company_registration"("p_reg" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."normalize_company_registration"("p_reg" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."normalize_company_registration"("p_reg" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."normalize_vat_number"("p_vat" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."normalize_vat_number"("p_vat" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."normalize_vat_number"("p_vat" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."outgoing_invoice_passes_filters"("p_inv" "public"."invoices", "p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."outgoing_invoice_passes_filters"("p_inv" "public"."invoices", "p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."outgoing_invoice_passes_filters"("p_inv" "public"."invoices", "p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."outgoing_invoice_passes_filters"("p_inv" "public"."invoices", "p_f_text" "text", "p_f_client" "uuid", "p_f_from" "date", "p_f_to" "date", "p_f_vat" "text", "p_f_project" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."owns_submission"("_kind" "public"."submission_kind", "_submission_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."parse_description_filter_terms"("p_f_description" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."parse_description_filter_terms"("p_f_description" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."parse_description_filter_terms"("p_f_description" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."pick_domain_canonical"("p_domain" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."pick_domain_canonical"("p_domain" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."pick_domain_canonical"("p_domain" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."profiles_guard_sensitive_self_update"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."profiles_guard_sensitive_self_update"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."refresh_cost_invoice_duplicate_flags"("p_full_keys" "text"[], "p_ci_keys" "text"[]) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."refresh_cost_invoice_duplicate_flags"("p_full_keys" "text"[], "p_ci_keys" "text"[]) TO "anon";
GRANT ALL ON FUNCTION "public"."refresh_cost_invoice_duplicate_flags"("p_full_keys" "text"[], "p_ci_keys" "text"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."refresh_cost_invoice_duplicate_flags"("p_full_keys" "text"[], "p_ci_keys" "text"[]) TO "service_role";



GRANT ALL ON FUNCTION "public"."resolve_company_from_costs_table"("p_domain" "text", "p_format_key" "text", "p_pdf_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."resolve_company_from_costs_table"("p_domain" "text", "p_format_key" "text", "p_pdf_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_company_from_costs_table"("p_domain" "text", "p_format_key" "text", "p_pdf_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."resolve_company_from_invoice_series"("p_from" "text", "p_invoice_number" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."resolve_company_from_invoice_series"("p_from" "text", "p_invoice_number" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_company_from_invoice_series"("p_from" "text", "p_invoice_number" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."resolve_cost_company_canonical"("p_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."resolve_cost_company_canonical"("p_name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text", "p_invoice_number" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text", "p_invoice_number" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_cost_company_for_invoice"("p_name" "text", "p_from" "text", "p_invoice_number" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."resolve_cost_supplier_for_invoice"("p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_from" "text", "p_invoice_number" "text", "p_source_invoice_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."resolve_cost_supplier_for_invoice"("p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_from" "text", "p_invoice_number" "text", "p_source_invoice_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_cost_supplier_for_invoice"("p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_from" "text", "p_invoice_number" "text", "p_source_invoice_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."rls_auto_enable"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."rls_auto_enable"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_integration_secret"("p_name" "text", "p_value" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_updated_at"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_updated_at_havs_tools"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_updated_at_havs_tools"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_updated_by"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_updated_by"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."shares_synced_subcontractor_staff_profile"("_viewer_id" "uuid", "_profile_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."shares_synced_subcontractor_staff_profile"("_viewer_id" "uuid", "_profile_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."shares_synced_subcontractor_staff_profile"("_viewer_id" "uuid", "_profile_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."shares_todo_list_with"("_user_id" "uuid", "_other_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."shares_todo_list_with"("_user_id" "uuid", "_other_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."shares_todo_list_with"("_user_id" "uuid", "_other_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."split_line_matches_description_filter"("p_split_description" "text", "p_f_description" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."split_line_matches_description_filter"("p_split_description" "text", "p_f_description" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."split_line_matches_description_filter"("p_split_description" "text", "p_f_description" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."submission_owner"("_kind" "public"."submission_kind", "_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."supplier_legal_name_key"("p_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."supplier_legal_name_key"("p_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."supplier_legal_name_key"("p_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."sync_todo_list_assignments_for_profile"() TO "anon";
GRANT ALL ON FUNCTION "public"."sync_todo_list_assignments_for_profile"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sync_todo_list_assignments_for_profile"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."timesheet_days_touch_parent"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."timesheet_days_touch_parent"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."timesheets_snapshot_and_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."timesheets_snapshot_and_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."toolbox_autoapprove"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."toolbox_autoapprove"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") TO "service_role";
GRANT ALL ON FUNCTION "public"."trigger_cost_scan"("p_url" "text", "p_apikey" "text") TO "authenticated";



GRANT ALL ON FUNCTION "public"."trusted_supplier_email_domain"("p_from" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."trusted_supplier_email_domain"("p_from" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."trusted_supplier_email_domain"("p_from" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "service_role";



GRANT ALL ON FUNCTION "public"."upsert_cost_supplier_identifiers"("p_supplier_id" "uuid", "p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_source_invoice_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."upsert_cost_supplier_identifiers"("p_supplier_id" "uuid", "p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_source_invoice_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."upsert_cost_supplier_identifiers"("p_supplier_id" "uuid", "p_vat" "text", "p_company_reg" "text", "p_name" "text", "p_source_invoice_id" "uuid") TO "service_role";



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



GRANT ALL ON TABLE "public"."cost_company_brand_aliases" TO "anon";
GRANT ALL ON TABLE "public"."cost_company_brand_aliases" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_company_brand_aliases" TO "service_role";



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



GRANT ALL ON TABLE "public"."cost_payment_remittances" TO "anon";
GRANT ALL ON TABLE "public"."cost_payment_remittances" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_payment_remittances" TO "service_role";



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



GRANT ALL ON TABLE "public"."cost_supplier_identifiers" TO "anon";
GRANT ALL ON TABLE "public"."cost_supplier_identifiers" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_supplier_identifiers" TO "service_role";



GRANT ALL ON TABLE "public"."cost_suppliers" TO "anon";
GRANT ALL ON TABLE "public"."cost_suppliers" TO "authenticated";
GRANT ALL ON TABLE "public"."cost_suppliers" TO "service_role";



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



GRANT ALL ON TABLE "public"."nas_sync_queue" TO "anon";
GRANT ALL ON TABLE "public"."nas_sync_queue" TO "authenticated";
GRANT ALL ON TABLE "public"."nas_sync_queue" TO "service_role";



GRANT ALL ON TABLE "public"."notification_preferences" TO "anon";
GRANT ALL ON TABLE "public"."notification_preferences" TO "authenticated";
GRANT ALL ON TABLE "public"."notification_preferences" TO "service_role";



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



GRANT SELECT("notification_prompt_seen") ON TABLE "public"."profiles" TO "authenticated";



GRANT ALL ON TABLE "public"."project_assignments" TO "anon";
GRANT ALL ON TABLE "public"."project_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."project_assignments" TO "service_role";



GRANT ALL ON TABLE "public"."projects" TO "anon";
GRANT ALL ON TABLE "public"."projects" TO "authenticated";
GRANT ALL ON TABLE "public"."projects" TO "service_role";



GRANT ALL ON TABLE "public"."push_subscriptions" TO "anon";
GRANT ALL ON TABLE "public"."push_subscriptions" TO "authenticated";
GRANT ALL ON TABLE "public"."push_subscriptions" TO "service_role";



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



GRANT ALL ON TABLE "public"."todo_item_attachments" TO "anon";
GRANT ALL ON TABLE "public"."todo_item_attachments" TO "authenticated";
GRANT ALL ON TABLE "public"."todo_item_attachments" TO "service_role";



GRANT ALL ON TABLE "public"."todo_items" TO "anon";
GRANT ALL ON TABLE "public"."todo_items" TO "authenticated";
GRANT ALL ON TABLE "public"."todo_items" TO "service_role";



GRANT ALL ON TABLE "public"."todo_list_assignments" TO "anon";
GRANT ALL ON TABLE "public"."todo_list_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."todo_list_assignments" TO "service_role";



GRANT ALL ON TABLE "public"."todo_list_subcontractor_syncs" TO "anon";
GRANT ALL ON TABLE "public"."todo_list_subcontractor_syncs" TO "authenticated";
GRANT ALL ON TABLE "public"."todo_list_subcontractor_syncs" TO "service_role";



GRANT ALL ON TABLE "public"."todo_lists" TO "anon";
GRANT ALL ON TABLE "public"."todo_lists" TO "authenticated";
GRANT ALL ON TABLE "public"."todo_lists" TO "service_role";



GRANT ALL ON TABLE "public"."toolbox_attendees" TO "anon";
GRANT ALL ON TABLE "public"."toolbox_attendees" TO "authenticated";
GRANT ALL ON TABLE "public"."toolbox_attendees" TO "service_role";



GRANT ALL ON TABLE "public"."toolbox_talks" TO "anon";
GRANT ALL ON TABLE "public"."toolbox_talks" TO "authenticated";
GRANT ALL ON TABLE "public"."toolbox_talks" TO "service_role";



GRANT ALL ON TABLE "public"."user_notifications" TO "anon";
GRANT ALL ON TABLE "public"."user_notifications" TO "authenticated";
GRANT ALL ON TABLE "public"."user_notifications" TO "service_role";



GRANT ALL ON TABLE "public"."user_roles" TO "anon";
GRANT ALL ON TABLE "public"."user_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_roles" TO "service_role";



GRANT ALL ON TABLE "public"."vehicle_assignments" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_assignments" TO "service_role";



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



































