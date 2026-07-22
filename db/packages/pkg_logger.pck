create or replace package pkg_logger as
 -- ==========================================================================
 -- Package: PKG_LOGGER
 -- Purpose: Technical logging to APP_LOG (TDS 8.2). Autonomous transactions
 -- so log rows survive business rollbacks.
 -- Design: Reads LOG.LEVEL directly from SYSTEM_CONFIG (cached 60s) instead
 -- of PKG_CONFIG, to avoid the LOGGER->CONFIG->ERROR->LOGGER cycle.
 -- ==========================================================================
 -- Optional module tag for subsequent log rows in this session.
 procedure set_module (p_module in varchar2);
 procedure error (p_message in varchar2, p_detail in clob default null);
 procedure warn (p_message in varchar2, p_detail in clob default null);
 procedure info (p_message in varchar2, p_detail in clob default null);
 procedure debug (p_message in varchar2, p_detail in clob default null);
 -- Like error(), but returns the APP_LOG.LOG_ID for user-facing reference IDs.
 function error_ref (p_message in varchar2,
 p_detail in clob default null) return number;
 function is_debug_enabled return boolean;
end pkg_logger;
/
create or replace package body pkg_logger as
 g_module varchar2(100);
 g_level pls_integer := 1; -- 1=ERROR 2=WARN 3=INFO 4=DEBUG
 g_level_loaded_at date;
 function level_num (p_level in varchar2) return pls_integer is
 begin
 return case p_level when 'ERROR' then 1 when 'WARN' then 2
 when 'INFO' then 3 when 'DEBUG' then 4 else 1 end;
 end;
 procedure refresh_level is
 l_val system_config.config_value%type;
 begin
 -- Cheap cached read; missing key or any error => safest level (ERROR).
 if g_level_loaded_at is null or g_level_loaded_at < sysdate - (60/86400) then
 begin
 select config_value into l_val
 from system_config where config_code = 'LOG.LEVEL';
 g_level := level_num(l_val);
 exception when others then
 g_level := 1;
 end;
 g_level_loaded_at := sysdate;
 end if;
 end;
 function write_log (p_level in varchar2, p_message in varchar2,
 p_detail in clob) return number is
 pragma autonomous_transaction; -- survives caller rollback
 l_id app_log.log_id%type;
 begin
 insert into app_log
 (log_level, module_name, message, detail,
 tenant_id, user_id, apex_session_id)
 values
 (p_level, g_module, substr(p_message, 1, 4000), p_detail,
 to_number(sys_context('app_ctx','tenant_id')),
 to_number(sys_context('app_ctx','user_id')),
 to_number(sys_context('app_ctx','apex_session_id')))
 returning log_id into l_id;
 commit; -- mandatory in autonomous txn
 return l_id;
 exception
 when others then
 rollback; -- logging must NEVER kill callers
 return null;
 end;
 procedure set_module (p_module in varchar2) is
 begin
 g_module := substr(p_module, 1, 100);
 end;
 procedure error (p_message in varchar2, p_detail in clob default null) is
 l_ignore number;
 begin
 l_ignore := write_log('ERROR', p_message, p_detail);
 end;
 function error_ref (p_message in varchar2,
 p_detail in clob default null) return number is
 begin
 return write_log('ERROR', p_message, p_detail);
 end;
 procedure warn (p_message in varchar2, p_detail in clob default null) is
 l_ignore number;
 begin
 refresh_level;
 if g_level >= 2 then l_ignore := write_log('WARN', p_message, p_detail); end if;
 end;
 procedure info (p_message in varchar2, p_detail in clob default null) is
 l_ignore number;
 begin
 refresh_level;
 if g_level >= 3 then l_ignore := write_log('INFO', p_message, p_detail); end if;
 end;
 procedure debug (p_message in varchar2, p_detail in clob default null) is
 l_ignore number;
 begin
 refresh_level;
 if g_level >= 4 then l_ignore := write_log('DEBUG', p_message, p_detail); end if;
 end;
 function is_debug_enabled return boolean is
 begin
 refresh_level;
 return g_level >= 4;
 end;
end pkg_logger;
/
