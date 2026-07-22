create or replace package pkg_tenants as
  -- ==========================================================================
  -- Package: PKG_TENANTS (TDS 8.2)
  -- Purpose: Tenant provisioning, status machine, soft delete. Operator-realm
  -- operations (run under admin/system context).
  -- ==========================================================================
  function provision_tenant(p_company_name in varchar2,
                            p_usdot_number in varchar2,
                            p_admin_email  in varchar2,
                            p_admin_first  in varchar2,
                            p_admin_last   in varchar2) return number;
  procedure change_status(p_tenant_id  in number,
                          p_new_status in varchar2,
                          p_reason     in varchar2);
  procedure deactivate(p_tenant_id in number, p_reason in varchar2);
  function is_active(p_tenant_id in number) return boolean;
end pkg_tenants;
/
create or replace package body pkg_tenants as
  procedure assert_operator is
  begin
    if not (pkg_security.has_role('SYS_ADMIN') or
        sys_context('app_ctx', 'admin_mode') = 'Y') then
      pkg_error.raise_business('TMS-1002');
    end if;
  end;
  -- Tenant status machine (TDS Phase-1 9.2), table-free CASE form: at four
  -- statuses x few moves, WORKFLOW_TRANSITIONS machinery is Phase-3 scope.
  function transition_ok(p_from in varchar2, p_to in varchar2) return boolean is
  begin
    return case when p_from = 'TRIAL' and p_to in('ACTIVE', 'TERMINATED') then true when p_from = 'ACTIVE' and p_to in('PAST_DUE',
                                                                                                                       'SUSPENDED',
                                                                                                                       'TERMINATED') then true when p_from = 'PAST_DUE' and p_to in('ACTIVE',
                                                                                                                                                                                    'RESTRICTED',
                                                                                                                                                                                    'TERMINATED') then true when p_from = 'RESTRICTED' and p_to in('ACTIVE',
                                                                                                                                                                                                                                                   'TERMINATED') then true when p_from = 'SUSPENDED' and p_to in('ACTIVE',
                                                                                                                                                                                                                                                                                                                 'TERMINATED') then true else false end;
  end;
  function provision_tenant(p_company_name in varchar2,
                            p_usdot_number in varchar2,
                            p_admin_email  in varchar2,
                            p_admin_first  in varchar2,
                            p_admin_last   in varchar2) return number is
    l_tenant_id  tenants.tenant_id%type;
    l_trial_days pls_integer := pkg_config.get_number('TENANT.TRIAL_DAYS');
    l_dup        number;
    l_ignore     number;
  begin
    assert_operator;
    -- FR-TEN-02: USDOT unique among live tenants. Friendly check first;
    -- TENANTS_UK1 + dup handler is the race backstop.
    if p_usdot_number is not null then
      select count(*)
        into l_dup
        from tenants
       where usdot_number = p_usdot_number
         and status <> 'TERMINATED'
         and deleted_yn = 'N';
      if l_dup > 0 then
        pkg_error.raise_business('TMS-2004', p_usdot_number);
      end if;
    end if;
    insert into tenants
      (tenant_code, company_name, usdot_number, status, trial_ends_at)
    values
      (substr(rawtohex(sys_guid()), 1, 20), -- placeholder, replaced below
       trim(p_company_name),
       p_usdot_number,
       'TRIAL',
       systimestamp + numtodsinterval(l_trial_days, 'DAY'))
    returning tenant_id into l_tenant_id;
    update tenants
       set tenant_code = 'T' || lpad(l_tenant_id, 6, '0')
     where tenant_id = l_tenant_id;
    -- Tenant admin: explicit tenant id (we are in operator context).
    l_ignore := pkg_users.invite_user(p_email      => p_admin_email,
                                      p_first_name => p_admin_first,
                                      p_last_name  => p_admin_last,
                                      p_role_codes => 'TENANT_ADMIN',
                                      p_tenant_id  => l_tenant_id);
    pkg_audit.log_action('TENANT',
                         l_tenant_id,
                         'INSERT',
                         trim(p_company_name));
    return l_tenant_id;
  exception
    when dup_val_on_index then
      pkg_error.raise_business('TMS-2004', p_usdot_number);
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_tenants.provision_tenant');
  end;
  procedure change_status(p_tenant_id  in number,
                          p_new_status in varchar2,
                          p_reason     in varchar2) is
    l_old tenants.status%type;
  begin
    assert_operator;
    select status
      into l_old
      from tenants
     where tenant_id = p_tenant_id
       for update;
    if not transition_ok(l_old, upper(p_new_status)) then
      pkg_error.raise_business('TMS-2007', l_old, upper(p_new_status));
    end if;
    update tenants
       set status        = upper(p_new_status),
           terminated_at = case
                             when upper(p_new_status) = 'TERMINATED' then
                              systimestamp
                             else
                              terminated_at
                           end,
           updated_at    = systimestamp,
           updated_by    = pkg_security.get_user_id,
           row_version   = row_version + 1
     where tenant_id = p_tenant_id;
    pkg_audit.chg_init;
    pkg_audit.chg_add('STATUS', l_old, upper(p_new_status));
    pkg_audit.log_changes('TENANT',
                          p_tenant_id,
                          'STATUS_CHANGE',
                          substr(p_reason, 1, 200));
  exception
    when no_data_found then
      pkg_error.raise_business('TMS-1001');
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_tenants.change_status');
  end;
  procedure deactivate(p_tenant_id in number, p_reason in varchar2) is
  begin
    assert_operator;
    update tenants
       set deleted_yn  = 'Y',
           deleted_at  = systimestamp,
           deleted_by  = pkg_security.get_user_id,
           updated_at  = systimestamp,
           updated_by  = pkg_security.get_user_id,
           row_version = row_version + 1
     where tenant_id = p_tenant_id
       and deleted_yn = 'N';
    if sql%rowcount > 0 then
      pkg_audit.log_action('TENANT',
                           p_tenant_id,
                           'DELETE',
                           substr(p_reason, 1, 200));
    end if;
  end;
  function is_active(p_tenant_id in number) return boolean is
    l_status tenants.status%type;
  begin
    select status
      into l_status
      from tenants
     where tenant_id = p_tenant_id
       and deleted_yn = 'N';
    return l_status in('TRIAL', 'ACTIVE', 'PAST_DUE');
  exception
    when no_data_found then
      return false;
  end;
end pkg_tenants;
/
