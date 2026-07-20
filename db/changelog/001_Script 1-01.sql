-- ============================================================================
-- Script:   1-01 create_schema_tms_app.sql
-- Purpose:  Create the Carrier TMS application schema (workspace parsing schema)
-- Run as:   ADMIN on CarrierTMS_DEV
-- Rerun:    NO (one-time). Guard included.
-- ============================================================================
declare
  l_cnt number;
begin
  select count(*) into l_cnt from dba_users where username = 'TMS_APP';
  if l_cnt > 0 then
    raise_application_error(-20000, 'TMS_APP already exists - aborting.');
  end if;
end;
/
 
create user tms_app identified by "&&tms_app_password"
  default tablespace data
  quota unlimited on data;
 
-- Base privileges: what a schema-owning application layer needs, nothing more.
grant create session        to tms_app;
grant create table          to tms_app;
grant create view           to tms_app;
grant create sequence       to tms_app;
grant create procedure      to tms_app;
grant create trigger        to tms_app;   -- identity backfill only; no business triggers (TDS naming std §7)
grant create job            to tms_app;   -- DBMS_SCHEDULER jobs (session sweep, purges)
grant create materialized view to tms_app; -- later phases (dashboards)
grant create synonym        to tms_app;
 
-- Security infrastructure required by the design:
grant create any context    to tms_app;   -- APP_CTX application context (TDS section 3.1)
grant execute on dbms_crypto  to tms_app; -- password hashing (TDS section 9.2)
grant execute on dbms_rls     to tms_app; -- VPD policy registration (TDS section 3.1)
grant execute on dbms_session to tms_app; -- context management
 
-- Make the schema usable by APEX/ORDS (enables it for REST and APEX assignment):
begin
  ords_admin.enable_schema(
    p_enabled             => true,
    p_schema              => 'TMS_APP',
    p_url_mapping_type    => 'BASE_PATH',
    p_url_mapping_pattern => 'tmsapp',
    p_auto_rest_auth      => true );  -- nothing auto-published without auth
end;