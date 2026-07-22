create or replace function fn_vpd_tenant_predicate (
 p_schema in varchar2,
 p_object in varchar2 )
 return varchar2
 deterministic
is
begin
 -- Platform-operator sessions: PKG_SECURITY sets ADMIN_MODE='Y' (audited).
 if sys_context('app_ctx','admin_mode') = 'Y' then
 return null; -- no restriction
 end if;
 -- Normal session: restrict to the session tenant.
 -- No context (job misconfigured, direct SQL, forgotten init) => deny all.
 -- Fail-closed is the entire point of database-enforced isolation.
 if sys_context('app_ctx','tenant_id') is null then
 return '1=0';
 end if;
 return 'tenant_id = sys_context(''app_ctx'',''tenant_id'')';
end fn_vpd_tenant_predicate;
/
declare
 -- (table_name : statement_types) - journals are SELECT-only (see 4.2).
 type t_tabs is table of varchar2(30) index by varchar2(30);
 l_tabs t_tabs;
 procedure add_pol (p_table in varchar2, p_stmts in varchar2) is
 begin
 begin
 dbms_rls.drop_policy(object_schema => 'TMS_APP',
 object_name => p_table,
 policy_name => p_table || '_TENANT_POL');
 exception when others then null; -- first run: nothing to drop
 end;
 dbms_rls.add_policy(
 object_schema => 'TMS_APP',
 object_name => p_table,
 policy_name => p_table || '_TENANT_POL',
 function_schema => 'TMS_APP',
 policy_function => 'FN_VPD_TENANT_PREDICATE',
 statement_types => p_stmts,
 update_check => true, -- INSERT/UPDATE must satisfy the predicate
 policy_type => dbms_rls.static, -- predicate cached; context still
 -- evaluated per query at runtime
 enable => false ); -- <-- switched on by Script 4-07
 end add_pol;
begin
 add_pol('APP_USERS', 'select,insert,update,delete');
 add_pol('USER_ROLES', 'select,insert,update,delete');
 add_pol('TENANT_CONFIG', 'select,insert,update,delete');
 add_pol('APP_SESSIONS', 'select,insert,update,delete');
 add_pol('PASSWORD_RESETS', 'select,insert,update,delete');
 add_pol('NOTIFICATIONS', 'select,insert,update,delete');
 add_pol('LOGIN_HISTORY', 'select'); -- journal: pre-auth inserts allowed
 add_pol('AUDIT_LOG', 'select'); -- journal: written by PKG_AUDIT
end;
