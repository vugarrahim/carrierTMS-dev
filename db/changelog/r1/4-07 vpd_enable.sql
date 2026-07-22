alter session disable parallel query;

begin
  for p in (select object_name, policy_name
 from user_policies
 where policy_name like '%_TENANT_POL') loop
 dbms_rls.enable_policy(object_schema => 'TMS_APP',
 object_name => p.object_name,
 policy_name => p.policy_name,
 enable => true);
 end loop;
end;
/
-- Immediate verification block (safe to run; uses throwaway rows):
declare
 l_t1 number; l_t2 number; l_u1 number; l_cnt number; 
begin
 pkg_security.init_system_context('vpd_enable self-test');
 insert into tenants (tenant_code, company_name, trial_ends_at)
  values ('VPDT1','VPD Test 1', systimestamp + interval '1' day)
    returning tenant_id into l_t1;

  insert into tenants (tenant_code, company_name, trial_ends_at)
  values ('VPDT2','VPD Test 2', systimestamp + interval '1' day)
    returning tenant_id into l_t2;
 insert into app_users (tenant_id, email, first_name, last_name)
 values (l_t1, 'vpd1@test.local', 'V', 'One') returning user_id into l_u1;
 -- 1) Tenant-1 context must see exactly its own user.
 pkg_security.init_context(l_u1);
 select count(*) into l_cnt from app_users;
 if l_cnt <> 1 then
 raise_application_error(-20000, 'VPD FAIL: tenant sees ' || l_cnt || ' users');
 end if;
 -- 2) Cross-tenant INSERT must be rejected (update_check => true).
 begin
 insert into app_users (tenant_id, email, first_name, last_name)
 values (l_t2, 'evil@test.local', 'E', 'Vil');
 raise_application_error(-20000, 'VPD FAIL: cross-tenant insert allowed');
 exception when others then
 if sqlcode not in (-28115, -28113) then raise; end if; -- policy violation = pass
 end;
 -- 3) No context => zero rows (fail-closed).
 pkg_security.clear_context;
 select count(*) into l_cnt from app_users;
 if l_cnt <> 0 then
 raise_application_error(-20000, 'VPD FAIL: contextless session sees rows');
 end if;
 -- Cleanup under system context.
 pkg_security.init_system_context('vpd_enable self-test cleanup');
 delete from app_users where email like '%@test.local';
 delete from tenants where tenant_code in ('VPDT1','VPDT2');
 pkg_security.clear_context;
 commit;
 dbms_output.put_line('VPD self-test PASSED');
end;
