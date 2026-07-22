merge into roles r using (
 select 'SYS_ADMIN' c,'System Administrator' n,'PLATFORM' rl, 10 so from dual union all
 select 'TENANT_ADMIN','Tenant Administrator','TENANT', 20 from dual union all
 select 'DISPATCHER','Dispatcher','TENANT', 30 from dual union all
 select 'FLEET_MANAGER','Fleet Manager','TENANT', 40 from dual union all
 select 'DRIVER_MANAGER','Driver Manager','TENANT', 50 from dual union all
 select 'WAREHOUSE','Warehouse','TENANT', 60 from dual union all
 select 'BILLING','Billing','TENANT', 70 from dual union all
 select 'ACCOUNTING','Accounting','TENANT', 80 from dual union all
 select 'CUSTOMER_SERVICE','Customer Service','TENANT', 90 from dual union all
 select 'READ_ONLY','Read Only','TENANT', 100 from dual union all
 select 'API_USER','API Integration User','TENANT', 110 from dual union all
 select 'DRIVER','Driver','TENANT', 120 from dual
) v on (nvl(r.tenant_id,0) = 0 and r.role_code = v.c)
when matched then update set role_name = v.n, realm = v.rl, sort_order = v.so
when not matched then insert (role_code, role_name, realm, is_system_yn, sort_order)
values (v.c, v.n, v.rl, 'Y', v.so);
-- Permissions (TDS 5.3 Phase-2 set).
merge into permissions p using (
 select 'ADMIN.MANAGE_TENANTS' c,'Manage Tenants' n,'ADMIN' m from dual union all
 select 'ADMIN.MANAGE_SYSTEM_CONFIG','Manage System Configuration','ADMIN' from dual union all
 select 'TENANT.MANAGE_USERS','Manage Users','TENANT' from dual union all
 select 'TENANT.MANAGE_CONFIG','Manage Tenant Settings','TENANT' from dual union all
 select 'TENANT.MANAGE_SUBSCRIPTION','Manage Subscription','TENANT' from dual union all
 select 'TENANT.VIEW_AUDIT','View Audit Log','TENANT' from dual union all
 select 'SECURITY.UNLOCK_USERS','Unlock Users','SECURITY' from dual union all
 select 'SECURITY.FORCE_LOGOUT','Force Logout','SECURITY' from dual union all
 select 'SESSION.VIEW_OWN','View Own Sessions','SESSION' from dual union all
 select 'SESSION.VIEW_ALL','View All Sessions','SESSION' from dual union all
 select 'PROFILE.EDIT_SELF','Edit Own Profile','PROFILE' from dual
) v on (p.permission_code = v.c)
when matched then update set permission_name = v.n, module_code = v.m
when not matched then insert (permission_code, permission_name, module_code)
values (v.c, v.n, v.m);
-- Matrix (TDS 5.4) - dogfooding pkg_permissions (idempotent MERGE inside).
begin
  

-- 7-04-u basdan sona yeniden icra et (idempotent MERGE-ler, tekrar tehlukesizdir)
 pkg_security.init_system_context('seed_rbac matrix');
 -- SYS_ADMIN: everything.
 for p in (select permission_code from permissions where is_active_yn = 'Y') loop
 pkg_permissions.grant_to_role('SYS_ADMIN', p.permission_code);
 end loop;
 -- TENANT_ADMIN: all tenant-realm capabilities.
 for p in (select column_value pc from table(apex_string.split(
 'TENANT.MANAGE_USERS:TENANT.MANAGE_CONFIG:TENANT.MANAGE_SUBSCRIPTION:'
 || 'TENANT.VIEW_AUDIT:SECURITY.UNLOCK_USERS:SECURITY.FORCE_LOGOUT:'
 || 'SESSION.VIEW_OWN:SESSION.VIEW_ALL:PROFILE.EDIT_SELF', ':'))) loop
 pkg_permissions.grant_to_role('TENANT_ADMIN', p.pc);
 end loop;
 -- Standard staff roles: self-service baseline.
 for r in (select column_value rc from table(apex_string.split(
 'DISPATCHER:FLEET_MANAGER:DRIVER_MANAGER:WAREHOUSE:BILLING:'
 || 'ACCOUNTING:CUSTOMER_SERVICE:DRIVER', ':'))) loop
 pkg_permissions.grant_to_role(r.rc, 'SESSION.VIEW_OWN');
 pkg_permissions.grant_to_role(r.rc, 'PROFILE.EDIT_SELF');
 end loop;
 -- READ_ONLY: audit visibility + self baseline.
 pkg_permissions.grant_to_role('READ_ONLY', 'TENANT.VIEW_AUDIT');
 pkg_permissions.grant_to_role('READ_ONLY', 'SESSION.VIEW_OWN');
 pkg_permissions.grant_to_role('READ_ONLY', 'PROFILE.EDIT_SELF');
 -- API_USER: no interactive permissions in Phase 2 (module scopes later).
 pkg_security.clear_context;
end;
