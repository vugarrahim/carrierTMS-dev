create or replace view v_active_users as
select u.user_id, u.user_guid, u.tenant_id, u.email,
 u.first_name, u.last_name,
 coalesce(u.display_name, u.first_name || ' ' || u.last_name) as display_name,
 u.phone, u.user_type, u.status, u.is_locked_yn, u.locked_at, u.lock_reason,
 u.failed_login_count, u.last_login_at, u.must_change_password_yn,
 u.password_expires_at, u.timezone, u.locale, u.created_at
from app_users u
where u.deleted_yn = 'N';
comment on table v_active_users is 'Admin user list source: non-deleted users, computed display name. 
No hash/salt/MFA columns exposed - the UI layer can never leak what it cannot select.';
create or replace view v_user_roles_expanded as
select ur.user_role_id, ur.user_id, ur.tenant_id,
 r.role_id, r.role_code, r.role_name, r.realm,
 ur.granted_at, ur.granted_by, ur.expires_at,
 case when ur.expires_at is not null and ur.expires_at < systimestamp
 then 'Y' else 'N' end as is_expired_yn
from user_roles ur
join roles r on r.role_id = ur.role_id
where r.is_active_yn = 'Y';
create or replace view v_user_permissions as
select distinct ur.user_id, p.permission_code, p.module_code
from user_roles ur
join roles r on r.role_id = ur.role_id
 and r.is_active_yn = 'Y'
join role_permissions rp on rp.role_id = ur.role_id
join permissions p on p.permission_id = rp.permission_id
 and p.is_active_yn = 'Y'
where (ur.expires_at is null or ur.expires_at >= systimestamp);
comment on table v_user_permissions is 'Effective permission set (union over roles, expired grants 
excluded). PKG_SECURITY caches this per session; do not query per page.';
create or replace view v_tenant_config_effective as
select sc.config_code,
 coalesce(tc.config_value, sc.config_value) as effective_value,
 sc.data_type,
 case when tc.tenant_config_id is not null then 'TENANT' else 'SYSTEM' end
 as value_source,
 sc.is_tenant_overridable_yn, sc.is_sensitive_yn, sc.description
from system_config sc
left join tenant_config tc
 on tc.config_code = sc.config_code
 and tc.tenant_id = to_number(sys_context('app_ctx','tenant_id'));
comment on table v_tenant_config_effective is 'Effective configuration for the SESSION tenant (override 
else default). Context-dependent by design.';
create or replace view v_my_sessions as
select s.session_id, s.session_guid, s.status, s.login_at, s.last_activity_at,
 s.ended_at, s.end_reason, s.ip_address, s.device_type,
 case when s.apex_session_id =
 to_number(sys_context('app_ctx','apex_session_id'))
 then 'Y' else 'N' end as is_current_yn
from app_sessions s
where s.user_id = to_number(sys_context('app_ctx','user_id'));
comment on table v_my_sessions is 'Self-service device list (TDS 12.2). Row scope by context user - an 
example of dynamic authorization as data condition (TDS 10).';
create or replace view v_login_history_recent as
select lh.login_id, lh.tenant_id, lh.user_id, lh.email_attempted,
 lh.event_type, lh.ip_address, lh.user_agent, lh.event_at
from login_history lh
where lh.event_at >= systimestamp - interval '90' day;
comment on table v_login_history_recent is 'Admin login audit view, 90-day window. FAIL_REASON 
deliberately NOT exposed to tenant admins (internal forensics only, rule A-02).';
