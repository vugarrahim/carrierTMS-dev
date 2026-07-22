declare
  l_uid app_users.user_id%type;
begin
  pkg_security.init_system_context('seed platform admin');
  begin
    select user_id
      into l_uid
      from app_users
     where upper(email) = 'SYSADMIN@CARRIERTMS.EXAMPLE'
       and deleted_yn = 'N';
  exception
    when no_data_found then
      insert into app_users
        (tenant_id, email, first_name, last_name, user_type, status)
      values
        (null,
         'sysadmin@carriertms.example',
         'System',
         'Administrator',
         'PLATFORM',
         'ACTIVE')
      returning user_id into l_uid;
      pkg_roles.grant_role(l_uid, 'SYS_ADMIN');
  end;
  pkg_security.set_password(l_uid, '&&sysadmin_password');
  update app_users
     set must_change_password_yn = 'N',
         email_verified_yn       = 'Y',
         email_verified_at       = systimestamp
   where user_id = l_uid;
  pkg_security.clear_context;
end;
/
-- Demo tenant + users. Guarded: refuses to run outside DEV/TEST.
declare l_env varchar2(10);
l_tenant_id tenants.tenant_id%type;
l_uid app_users.user_id%type;
procedure demo_user(p_email in varchar2,
                    p_first in varchar2,
                    p_last in varchar2,
                    p_roles in varchar2) is l_id number;
begin
  begin
    select user_id
      into l_id
      from app_users
     where tenant_id = l_tenant_id
       and upper(email) = upper(p_email);
  exception
    when no_data_found then
      l_id := pkg_users.invite_user(p_email,
                                    p_first,
                                    p_last,
                                    p_roles,
                                    p_tenant_id => l_tenant_id);
  end;
  -- DEV convenience: activate directly instead of walking the invite link.
  pkg_security.set_password(l_id, '&&demo_password');
  update app_users
     set status                  = 'ACTIVE',
         email_verified_yn       = 'Y',
         email_verified_at       = systimestamp,
         must_change_password_yn = 'N'
   where user_id = l_id;
end;
begin
  l_env := pkg_config.get_text('APP.ENVIRONMENT');
  if l_env not in ('DEV', 'TEST') then
    raise_application_error(-20000,
                            'Demo seed refused: APP.ENVIRONMENT = ' ||
                            l_env);
  end if;
  pkg_security.init_system_context('seed demo tenant');
  begin
    select tenant_id
      into l_tenant_id
      from tenants
     where company_name = 'Acme Auto Transport (Demo)'
       and deleted_yn = 'N';
  exception
    when no_data_found then
      l_tenant_id := pkg_tenants.provision_tenant(p_company_name => 'Acme Auto Transport (Demo)',
                                                  p_usdot_number => '9999999',
                                                  p_admin_email  => 'admin@acme.demo',
                                                  p_admin_first  => 'Alice',
                                                  p_admin_last   => 'Admin');
    
      update tenants
         set seats_purchased = 25,
             updated_at      = systimestamp,
             updated_by      = -1,
             row_version     = row_version + 1
       where tenant_id = l_tenant_id;
    
  end;
  demo_user('admin@acme.demo', 'Alice', 'Admin', 'TENANT_ADMIN');
  demo_user('dispatch@acme.demo', 'Diego', 'Dispatcher', 'DISPATCHER');
  demo_user('billing@acme.demo', 'Bella', 'Billing', 'BILLING:ACCOUNTING');
  demo_user('readonly@acme.demo', 'Rita', 'Reader', 'READ_ONLY');
  pkg_security.clear_context;
  commit;
end;
