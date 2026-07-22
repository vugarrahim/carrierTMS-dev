create or replace package pkg_config as
  -- ==========================================================================
  -- Package: PKG_CONFIG
  -- Purpose: Typed configuration reads with tenant-override resolution and
  -- per-session caching; validated writes with audit (TDS 8.2).
  -- Resolution: TENANT_CONFIG (session tenant) overrides SYSTEM_CONFIG when
  -- the key is flagged overridable; TENANT.* keys are tenant-only.
  -- Errors: TMS-3001 unknown key, TMS-3002 bad value for type,
  -- TMS-3003 key not overridable.
  -- ==========================================================================
  function get_text(p_code in varchar2) return varchar2;
  function get_number(p_code in varchar2) return number;
  function get_flag(p_code in varchar2) return boolean;
  function get_json(p_code in varchar2) return varchar2; -- validated JSON text
  procedure set_system_value(p_code in varchar2, p_value in varchar2);
  procedure set_tenant_value(p_code in varchar2, p_value in varchar2);
  procedure clear_tenant_value(p_code in varchar2);
  -- Drop the session cache (called by writers; harmless anywhere).
  procedure refresh_cache;
end pkg_config;
/
create or replace package body pkg_config as
  -- Session cache: key = '<tenant>|<code>'. TTL keeps multi-node/app-server
  -- deployments honest without cross-session invalidation machinery.
  type t_entry is record(
    val    varchar2(4000),
    typ    varchar2(10),
    loaded date);
  type t_cache is table of t_entry index by varchar2(120);
  g_cache t_cache;
  c_ttl_seconds constant pls_integer := 60;
  function cache_key(p_code in varchar2) return varchar2 is
  begin
    return nvl(sys_context('app_ctx', 'tenant_id'), '0') || '|' || upper(p_code);
  end;
  function fetch_system(p_code in varchar2) return system_config%rowtype is
    l_row system_config%rowtype;
  begin
    select *
      into l_row
      from system_config
     where config_code = upper(p_code);
    return l_row;
  exception
    when no_data_found then
      l_row.config_code := null;
      return l_row;
  end;
  -- Core resolution (TDS 6.9 / view V_TENANT_CONFIG_EFFECTIVE, but callable
  -- and cached). Returns value + declared type.
  procedure resolve(p_code in varchar2,
                    o_val  out varchar2,
                    o_typ  out varchar2) is
    l_key  varchar2(120) := cache_key(p_code);
    l_sys  system_config%rowtype;
    l_tval tenant_config.config_value%type;
    l_tid  number := to_number(sys_context('app_ctx', 'tenant_id'));
  begin
    if g_cache.exists(l_key) and g_cache(l_key)
      .loaded > sysdate - (c_ttl_seconds / 86400) then
      o_val := g_cache(l_key).val;
      o_typ := g_cache(l_key).typ;
      return;
    end if;
    l_sys := fetch_system(p_code);
    -- Tenant override (only meaningful inside a tenant context).
    if l_tid is not null and (l_sys.is_tenant_overridable_yn = 'Y' or
       upper(p_code) like 'TENANT.%') then
      begin
        select config_value
          into l_tval
          from tenant_config
         where tenant_id = l_tid
           and config_code = upper(p_code);
      exception
        when no_data_found then
          l_tval := null;
      end;
    end if;
    if l_tval is null and l_sys.config_code is null then
      pkg_error.raise_business('TMS-3001', upper(p_code));
    end if;
    o_val := nvl(l_tval, l_sys.config_value);
    o_typ := nvl(l_sys.data_type, 'TEXT'); -- TENANT.* keys default to TEXT
    g_cache(l_key).val := o_val;
    g_cache(l_key).typ := o_typ;
    g_cache(l_key).loaded := sysdate;
  end;
  function get_text(p_code in varchar2) return varchar2 is
    l_v varchar2(4000);
    l_t varchar2(10);
  begin
    resolve(p_code, l_v, l_t);
    return l_v;
  end;
  function get_number(p_code in varchar2) return number is
    l_v varchar2(4000);
    l_t varchar2(10);
  begin
    resolve(p_code, l_v, l_t);
    return to_number(l_v);
  exception
    when value_error or invalid_number then
      pkg_error.raise_business('TMS-3002', upper(p_code), 'NUMBER');
  end;
  function get_flag(p_code in varchar2) return boolean is
    l_v varchar2(4000);
    l_t varchar2(10);
  begin
    resolve(p_code, l_v, l_t);
    return pkg_util.parse_yn(l_v);
  end;
  function get_json(p_code in varchar2) return varchar2 is
    l_v varchar2(4000);
    l_t varchar2(10);
    l_j json_element_t;
  begin
    resolve(p_code, l_v, l_t);
    l_j := json_element_t.parse(l_v); -- raises on malformed JSON
    return l_v;
  exception
    when others then
      pkg_error.raise_business('TMS-3002', upper(p_code), 'JSON');
  end;
  procedure validate_value(p_type  in varchar2,
                           p_code  in varchar2,
                           p_value in varchar2) is
    l_n number;
    l_j json_element_t;
  begin
    case p_type
      when 'NUMBER' then
        l_n := to_number(p_value);
      when 'FLAG' then
        if upper(p_value) not in ('Y', 'N') then
          raise value_error;
        end if;
      when 'JSON' then
        l_j := json_element_t.parse(p_value);
      else
        null; -- TEXT: anything goes
    end case;
  exception
    when others then
      pkg_error.raise_business('TMS-3002', upper(p_code), p_type);
  end;
  procedure set_system_value(p_code in varchar2, p_value in varchar2) is
    l_sys system_config%rowtype := fetch_system(p_code);
  begin
    if l_sys.config_code is null then
      pkg_error.raise_business('TMS-3001', upper(p_code)); -- keys are born in migrations
    end if;
    validate_value(l_sys.data_type, p_code, p_value);
    pkg_audit.chg_init;
    pkg_audit.chg_add('CONFIG_VALUE', l_sys.config_value, p_value);
    update system_config
       set config_value = p_value,
           updated_at   = systimestamp,
           updated_by   = to_number(sys_context('app_ctx', 'user_id')),
           row_version  = row_version + 1
     where config_code = l_sys.config_code;
    pkg_audit.log_changes('CONFIG',
                          l_sys.config_id,
                          'CONFIG_CHANGE',
                          l_sys.config_code);
    refresh_cache;
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_config.set_system_value');
  end;
  procedure set_tenant_value(p_code in varchar2, p_value in varchar2) is
    l_sys system_config%rowtype := fetch_system(p_code);
    l_tid number := to_number(sys_context('app_ctx', 'tenant_id'));
    l_old tenant_config.config_value%type;
  begin
    if l_sys.config_code is not null and
       l_sys.is_tenant_overridable_yn = 'N' and
       upper(p_code) not like 'TENANT.%' then
      pkg_error.raise_business('TMS-3003', upper(p_code));
    end if;
    if l_sys.config_code is null and upper(p_code) not like 'TENANT.%' then
      pkg_error.raise_business('TMS-3001', upper(p_code));
    end if;
    validate_value(nvl(l_sys.data_type, 'TEXT'), p_code, p_value);
    begin
      select config_value
        into l_old
        from tenant_config
       where tenant_id = l_tid
         and config_code = upper(p_code);
    exception
      when no_data_found then
        l_old := null;
    end;
    merge into tenant_config tc
    using (select l_tid t, upper(p_code) c from dual) s
    on (tc.tenant_id = s.t and tc.config_code = s.c)
    when matched then
      update
         set config_value = p_value,
             updated_at   = systimestamp,
             updated_by   = to_number(sys_context('app_ctx', 'user_id')),
             row_version  = row_version + 1
    when not matched then
      insert
        (tenant_id, config_code, config_value)
      values
        (s.t, s.c, p_value);
    pkg_audit.chg_init;
    pkg_audit.chg_add('CONFIG_VALUE', l_old, p_value);
    pkg_audit.log_changes('TENANT_CONFIG',
                          null,
                          'CONFIG_CHANGE',
                          upper(p_code));
    refresh_cache;
  exception
    when others then
      if sqlcode = pkg_error.c_business_errnum then
        raise;
      end if;
      pkg_error.handle_unexpected('pkg_config.set_tenant_value');
  end;
  procedure clear_tenant_value(p_code in varchar2) is
  begin
    delete from tenant_config
     where tenant_id = to_number(sys_context('app_ctx', 'tenant_id'))
       and config_code = upper(p_code);
    if sql%rowcount > 0 then
      pkg_audit.log_action('TENANT_CONFIG',
                           null,
                           'CONFIG_CHANGE',
                           upper(p_code) || ' (cleared)');
    end if;
    refresh_cache;
  end;
  procedure refresh_cache is
  begin
    g_cache.delete;
  end;
end pkg_config;
/
