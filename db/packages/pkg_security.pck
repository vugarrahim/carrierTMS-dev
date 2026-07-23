create or replace package pkg_security as
 -- ==========================================================================
 -- Package: PKG_SECURITY
 -- Purpose: APP_CTX context engine, per-session permission cache, password
 -- hashing (PBKDF2-HMAC-SHA512), token primitives, admin mode
 -- (TDS 8.2, 9.2). This is the ONLY package that can write APP_CTX
 -- (context created USING pkg_security, Script 3-01).
 -- ==========================================================================
 -- ---- session context -----------------------------------------------------
 -- Establish identity for an authenticated user (post-auth / sentry / REST).
 procedure init_context (p_user_id in number,
 p_ip_address in varchar2 default null,
 p_apex_session_id in number default null,
 p_channel in varchar2 default 'UI');
 -- Audited system identity for jobs, migrations, provisioning (admin mode ON).
 procedure init_system_context (p_reason in varchar2);
 procedure clear_context;
 -- Platform-operator data access across tenants (SYS_ADMIN only; audited).
 procedure set_admin_mode (p_on in boolean, p_reason in varchar2 default null);
 function get_user_id return number;
 function get_tenant_id return number;
 -- ---- authorization -------------------------------------------------------
 function has_permission (p_code in varchar2) return boolean;
 function has_role (p_code in varchar2) return boolean;
 -- 'Y'/'N' wrappers for APEX authorization schemes / SQL.
function has_permission_yn (p_code in varchar2) return varchar2;
 -- Rebuild the cached permission/role sets (PKG_ROLES calls after grants).
 procedure invalidate_authz_cache;
 -- ---- password & token primitives ----------------------------------------
 -- Set/replace a user's password hash (policy checks live in PKG_AUTH).
 procedure set_password (p_user_id in number, p_password in varchar2);
 function verify_password (p_user_id in number,
 p_password in varchar2) return boolean;
 -- Equalize timing for unknown-user login attempts (rule A-04).
 procedure burn_dummy_hash;
 function random_token return varchar2; -- 64 hex chars (32 bytes)
 function hash_token (p_raw_token in varchar2) return varchar2; -- SHA-256 hex
end pkg_security;
/
create or replace package body pkg_security as
 c_key_bytes constant pls_integer := 64; -- SHA-512 output size
 -- Per-DB-session authz cache. DB sessions are SHARED across application
 -- users by APEX/ORDS pooling, so every read re-checks g_cache_user_id
 -- against the context and reloads on mismatch. See handbook 6.2.
 type t_set is table of boolean index by varchar2(60);
 g_perms t_set;
 g_roles t_set;
 g_cache_user_id number := null;
 procedure set_ctx (p_name in varchar2, p_value in varchar2) is
 begin
 dbms_session.set_context('app_ctx', p_name, p_value);
 end;
 -- ---- context -------------------------------------------------------------
 procedure load_authz_cache (p_user_id in number) is
 begin
 g_perms.delete; g_roles.delete;
 for r in (select permission_code from v_user_permissions
 where user_id = p_user_id) loop
 g_perms(r.permission_code) := true;
 end loop;
 for r in (select role_code from v_user_roles_expanded
 where user_id = p_user_id and is_expired_yn = 'N') loop
 g_roles(r.role_code) := true;
 end loop;
 g_cache_user_id := p_user_id;
 end;
 procedure init_context (p_user_id in number,
 p_ip_address in varchar2 default null,
 p_apex_session_id in number default null,
 p_channel in varchar2 default 'UI') is
 l_tenant_id app_users.tenant_id%type;
 begin
 -- Direct read (not the view): must work regardless of VPD/context state.
 select tenant_id into l_tenant_id
 from app_users
 where user_id = p_user_id and deleted_yn = 'N';
 set_ctx('user_id', to_char(p_user_id));
 set_ctx('tenant_id', to_char(l_tenant_id)); -- NULL for PLATFORM
 set_ctx('admin_mode', 'N');
 set_ctx('ip_address', substr(p_ip_address, 1, 45));
 set_ctx('apex_session_id', to_char(p_apex_session_id));
 set_ctx('channel', p_channel);
 load_authz_cache(p_user_id);
 exception
 when no_data_found then
 -- Unknown/deleted user must never obtain a context.
 clear_context;
 pkg_error.raise_business('TMS-1001');
 end;
 procedure init_system_context (p_reason in varchar2) is
 begin
 set_ctx('user_id', '-1'); -- reserved SYSTEM id
 set_ctx('tenant_id', null);
 set_ctx('admin_mode', 'Y');
 set_ctx('channel', 'JOB');
 g_perms.delete; g_roles.delete; g_cache_user_id := -1;
 pkg_audit.log_security_event('SYSTEM_CONTEXT',
 substr(nvl(p_reason,'(no reason given)'), 1, 200));
 end;
 procedure clear_context is
 begin
 dbms_session.clear_all_context('app_ctx');
 g_perms.delete; g_roles.delete; g_cache_user_id := null;
 end;
 procedure set_admin_mode (p_on in boolean, p_reason in varchar2 default null) is
 begin
 if not has_role('SYS_ADMIN') then
 pkg_error.raise_business('TMS-1002'); -- not authorized
 end if;
 set_ctx('admin_mode', case when p_on then 'Y' else 'N' end);
 pkg_audit.log_security_event(
 case when p_on then 'ADMIN_MODE_ON' else 'ADMIN_MODE_OFF' end,
 substr(p_reason, 1, 200));
 end;
 function get_user_id return number is
 begin
 return to_number(sys_context('app_ctx','user_id'));
 end;
 function get_tenant_id return number is
 begin
 return to_number(sys_context('app_ctx','tenant_id'));
 end;
 -- ---- authorization -------------------------------------------------------
 procedure ensure_cache is
 l_ctx_user number := get_user_id;
 begin
 if l_ctx_user is null then
 g_perms.delete; g_roles.delete; g_cache_user_id := null;
 elsif g_cache_user_id is null or g_cache_user_id <> l_ctx_user then
 load_authz_cache(l_ctx_user); -- pooled-session guard
 end if;
 end;
 function has_permission (p_code in varchar2) return boolean is
 begin
 ensure_cache;
 return g_perms.exists(upper(p_code));
 end;
 function has_role (p_code in varchar2) return boolean is
 begin
 ensure_cache;
 return g_roles.exists(upper(p_code));
 end;
 function has_permission_yn (p_code in varchar2) return varchar2 is
 begin
 return case when has_permission(p_code) then 'Y' else 'N' end;
 end;
 procedure invalidate_authz_cache is
 begin
 g_cache_user_id := null; -- next check reloads
 end;
 -- ---- password & tokens ---------------------------------------------------
 function compute_hash (p_password   in varchar2,
                         p_salt       in raw,
                         p_iterations in pls_integer) return varchar2 is
    -- PBKDF2-HMAC-SHA512, dkLen = hLen (64 bayt) => yalniz Block 1 (RFC 8018).
    l_pwd   raw(2000) := utl_raw.cast_to_raw(p_password);
    l_u     raw(64);
    l_block raw(64);
  begin
    -- U1 = HMAC(password, salt || INT_32_BE(1))
    l_u := dbms_crypto.mac(
             src => utl_raw.concat(p_salt, hextoraw('00000001')),
             typ => dbms_crypto.hmac_sh512,
             key => l_pwd);
    l_block := l_u;
    -- U2..Un; netice = U1 xor U2 xor ... xor Un
    for i in 2 .. p_iterations loop
      l_u     := dbms_crypto.mac(src => l_u,
                                 typ => dbms_crypto.hmac_sh512,
                                 key => l_pwd);
      l_block := utl_raw.bit_xor(l_block, l_u);
    end loop;
    return rawtohex(l_block);
  end;
 -- Constant-time comparison: XOR-accumulate over full length, no early exit.
 function same_hash (p_a in varchar2, p_b in varchar2) return boolean is
 l_a raw(200) := hextoraw(p_a);
 l_b raw(200) := hextoraw(p_b);
 l_acc pls_integer := 0;
 begin
 if utl_raw.length(l_a) <> utl_raw.length(l_b) then
 return false;
 end if;
 for i in 1 .. utl_raw.length(l_a) loop
 l_acc := l_acc + case when utl_raw.substr(l_a, i, 1)
 = utl_raw.substr(l_b, i, 1) then 0 else 1 end;
 end loop;
 return l_acc = 0;
 end;
 procedure set_password (p_user_id in number, p_password in varchar2) is
    l_salt raw(32)       := dbms_crypto.randombytes(32);
    l_iter pls_integer   := pkg_config.get_number('AUTH.HASH_ITERATIONS');
    l_life pls_integer   := pkg_config.get_number('AUTH.PASSWORD_LIFETIME_DAYS');
    l_hash varchar2(500);
  begin
    l_hash := compute_hash(p_password, l_salt, l_iter);

    update app_users
       set password_hash       = l_hash,
           password_salt       = l_salt,
           password_iterations = l_iter,
           password_changed_at = systimestamp,
           password_expires_at = case when l_life > 0
                                      then systimestamp + numtodsinterval(l_life,'DAY') end,
           updated_at  = systimestamp,
           updated_by  = nvl(get_user_id, -1),
           row_version = row_version + 1
     where user_id = p_user_id;
   if sql%rowcount = 0 then
     pkg_error.raise_business('TMS-1001');
   end if;
   -- Audit the event, never the values (masked registry backstops anyway).
   pkg_audit.log_action('USER', p_user_id, 'PASSWORD_SET');
 end;
 function verify_password (p_user_id in number,
 p_password in varchar2) return boolean is
 l_hash app_users.password_hash%type;
 l_salt app_users.password_salt%type;
 l_iter app_users.password_iterations%type;
 begin
 select password_hash, password_salt, password_iterations
 into l_hash, l_salt, l_iter
 from app_users
 where user_id = p_user_id;
 if l_hash is null or l_salt is null or l_iter is null then
 return false; -- INVITED / SSO-only
 end if;
 return same_hash(l_hash, compute_hash(p_password, l_salt, l_iter));
 exception when no_data_found then
 return false;
 end;
 procedure burn_dummy_hash is
 l_ignore varchar2(200);
 begin
 -- Same cost as a real verification; result discarded (rule A-04).
 l_ignore := compute_hash('timing-equalizer',
 hextoraw('5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A'),
 pkg_config.get_number('AUTH.HASH_ITERATIONS'));
 end;
 function random_token return varchar2 is
 begin
 return rawtohex(dbms_crypto.randombytes(32));
 end;
 function hash_token (p_raw_token in varchar2) return varchar2 is
 begin
 return rawtohex(dbms_crypto.hash(
 utl_raw.cast_to_raw(upper(p_raw_token)), dbms_crypto.hash_sh256));
 end;
end pkg_security;
/
