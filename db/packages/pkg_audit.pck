create or replace package pkg_audit as
  -- ==========================================================================
  -- Package: PKG_AUDIT
  -- Purpose: Sole write path for AUDIT_LOG (TDS 13). Field-level change
  -- collection with sensitive-value masking. Writes participate in
  -- the business transaction (no autonomous txn - fail together).
  -- Design: Reads identity from SYS_CONTEXT('APP_CTX') directly (refinement
  -- of TDS 8.2: avoids depending on PKG_SECURITY, no cycles).
  -- ==========================================================================
  -- Simple semantic action without field changes.
  procedure log_action(p_entity_code  in varchar2,
                       p_entity_id    in number,
                       p_action_code  in varchar2,
                       p_entity_label in varchar2 default null);
  -- Change-set collection pattern for UPDATE audits:
  -- chg_init; chg_add('STATUS', old, new); ... ; log_changes(...);
  procedure chg_init;
  procedure chg_add(p_field in varchar2,
                    p_old   in varchar2,
                    p_new   in varchar2);
  procedure chg_add(p_field in varchar2,
                    p_old   in timestamp with time zone,
                    p_new   in timestamp with time zone);
  procedure log_changes(p_entity_code  in varchar2,
                        p_entity_id    in number,
                        p_action_code  in varchar2 default 'UPDATE',
                        p_entity_label in varchar2 default null);
  -- Security-relevant one-liners (lockouts, admin-mode entry, forced logout).
  procedure log_security_event(p_action_code in varchar2,
                               p_detail      in varchar2 default null);
end pkg_audit;
/
create or replace package body pkg_audit as
  g_changes json_array_t;
  -- Sensitive field registry (TDS 13.2): values masked, never stored.
  function is_sensitive(p_field in varchar2) return boolean is
  begin
    return upper(p_field) in('PASSWORD_HASH',
                             'PASSWORD_SALT',
                             'PASSWORD_ITERATIONS',
                             'MFA_SECRET',
                             'TOKEN_HASH');
  end;
  function context_json return json_object_t is
    l_ctx json_object_t := json_object_t();
  begin
    l_ctx.put('ip', sys_context('app_ctx', 'ip_address'));
    l_ctx.put('apexSessionId', sys_context('app_ctx', 'apex_session_id'));
    l_ctx.put('channel', nvl(sys_context('app_ctx', 'channel'), 'UI'));
    l_ctx.put('dbSession', sys_context('userenv', 'sid'));
    return l_ctx;
  end;
  procedure write_row(p_entity_code  in varchar2,
                      p_entity_id    in number,
                      p_action_code  in varchar2,
                      p_entity_label in varchar2,
                      p_changes      in json_array_t) is
    l_changes clob;
    l_context clob;
  begin
    if p_changes is not null and p_changes.get_size > 0 then
      l_changes := p_changes.to_clob;
    end if;
    l_context := context_json().to_clob;
  
    insert into audit_log
      (tenant_id,
       user_id,
       action_code,
       entity_code,
       entity_id,
       entity_label,
       field_changes,
       context_info)
    values
      (to_number(sys_context('app_ctx', 'tenant_id')),
       to_number(sys_context('app_ctx', 'user_id')),
       upper(p_action_code),
       upper(p_entity_code),
       p_entity_id,
       substr(p_entity_label, 1, 200),
       l_changes,
       l_context);
  end;
  procedure log_action(p_entity_code  in varchar2,
                       p_entity_id    in number,
                       p_action_code  in varchar2,
                       p_entity_label in varchar2 default null) is
  begin
    write_row(p_entity_code,
              p_entity_id,
              p_action_code,
              p_entity_label,
              null);
  end;
  procedure chg_init is
  begin
    g_changes := json_array_t();
  end;
  procedure chg_add(p_field in varchar2,
                    p_old   in varchar2,
                    p_new   in varchar2) is
    l_o json_object_t;
  begin
    if g_changes is null then
      chg_init;
    end if;
    -- Record only real changes; NULL-safe comparison.
    if (p_old is null and p_new is null) or p_old = p_new then
      return;
    end if;
    l_o := json_object_t();
    l_o.put('field', upper(p_field));
    if is_sensitive(p_field) then
      l_o.put('old', case when p_old is not null then '***' end);
      l_o.put('new', case when p_new is not null then '***' end);
    else
      l_o.put('old', substr(p_old, 1, 500));
      l_o.put('new', substr(p_new, 1, 500));
    end if;
    g_changes.append(l_o);
  end;
  procedure chg_add(p_field in varchar2,
                    p_old   in timestamp with time zone,
                    p_new   in timestamp with time zone) is
  begin
    chg_add(p_field,
            to_char(p_old, 'YYYY-MM-DD"T"HH24:MI:SS.FF3 TZR'),
            to_char(p_new, 'YYYY-MM-DD"T"HH24:MI:SS.FF3 TZR'));
  end;
  procedure log_changes(p_entity_code  in varchar2,
                        p_entity_id    in number,
                        p_action_code  in varchar2 default 'UPDATE',
                        p_entity_label in varchar2 default null) is
  begin
    if g_changes is null or g_changes.get_size = 0 then
      g_changes := null;
      return; -- nothing changed: no noise row
    end if;
    write_row(p_entity_code,
              p_entity_id,
              p_action_code,
              p_entity_label,
              g_changes);
    g_changes := null; -- always reset collector state
  end;
  procedure log_security_event(p_action_code in varchar2,
                               p_detail      in varchar2 default null) is
  begin
    write_row('SECURITY',
              null,
              p_action_code,
              substr(p_detail, 1, 200),
              null);
  end;
end pkg_audit;
/
