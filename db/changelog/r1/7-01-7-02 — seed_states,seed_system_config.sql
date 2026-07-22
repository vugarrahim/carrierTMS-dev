merge into states s using (
 select 'AL' c, 'Alabama' n, 'US' k from dual union all
 select 'AK', 'Alaska', 'US' from dual union all
 select 'AZ', 'Arizona', 'US' from dual union all
 select 'TX', 'Texas', 'US' from dual union all
 select 'ON', 'Ontario', 'CA' from dual
 -- ... complete list in /seed/seed_states.sql
) v on (s.state_code = v.c)
when not matched then insert (state_code, state_name, country_code)
values (v.c, v.n, v.k);
-- 7-02: SYSTEM_CONFIG - every key the packages read, with sane defaults.
merge into system_config sc using (
 select 'AUTH.MAX_FAILED_LOGINS' code, '5' val, 'NUMBER' typ, 'N' ovr, 'Lock after N 
consecutive bad passwords (A-03).' des from dual union all
 select 'AUTH.MIN_PASSWORD_LENGTH', '12', 'NUMBER', 'N', 'Policy A-07 minimum length.' from dual 
union all
 select 'AUTH.PASSWORD_LIFETIME_DAYS','90', 'NUMBER', 'Y', 'Password expiry; 0 = never (A-05).' 
from dual union all
 select 'AUTH.PASSWORD_HISTORY_COUNT','0', 'NUMBER', 'N', 'Reuse prevention depth; 0 disables 
(deferred).' from dual union all
 select 'AUTH.HASH_ITERATIONS', '210000', 'NUMBER', 'N', 'PBKDF2 work factor; benchmarked value 
from 6.6.' from dual union all
 select 'AUTH.RESET_TOKEN_MINUTES', '60', 'NUMBER', 'N', 'Reset link lifetime (invites: fixed 7 
days).' from dual union all
 select 'AUTH.THROTTLE_ATTEMPTS', '10', 'NUMBER', 'N', 'Failures per window before THROTTLED.' 
from dual union all
 select 'AUTH.THROTTLE_WINDOW_MIN', '15', 'NUMBER', 'N', 'Throttle window (minutes).' from dual 
union all
 select 'SESSION.IDLE_TIMEOUT_MIN', '30', 'NUMBER', 'Y', 'Idle timeout; tenant-overridable 10-
120.' from dual union all
 select 'SESSION.MAX_LIFE_HOURS', '12', 'NUMBER', 'N', 'Maximum session length.' from dual 
union all
 select 'SESSION.CONCURRENCY_MODE', 'ALLOW', 'TEXT', 'Y', 'ALLOW / LIMIT_N / SINGLE (TDS 12.2).' 
from dual union all
 select 'SESSION.MAX_CONCURRENT', '3', 'NUMBER', 'Y', 'Limit for LIMIT_N mode.' from dual 
union all
 select 'LOG.LEVEL', 'ERROR', 'TEXT', 'N', 'ERROR/WARN/INFO/DEBUG runtime log 
level.' from dual union all
 select 'LOG.RETENTION_DAYS', '90', 'NUMBER', 'N', 'APP_LOG purge horizon.' from dual 
union all
 select 'MAIL.FROM_ADDRESS', 'no-reply@carriertms.example', 'TEXT', 'N', 'Outbound From address.' from 
dual union all 
 select 'APP.BASE_URL', 'https://dev.example.com/ords', 'TEXT', 'N', 'Base URL for e-mailed deep 
links. SET PER ENVIRONMENT.' from dual union all
 select 'APP.ENVIRONMENT', 'DEV', 'TEXT', 'N', 'DEV/TEST/PROD - guards demo-only seed 
behavior.' from dual union all
 select 'TENANT.TRIAL_DAYS', '14', 'NUMBER', 'N', 'Trial length at provisioning.' from 
dual
) v on (sc.config_code = v.code)
when matched then update set description = v.des,
 is_tenant_overridable_yn = v.ovr,
 data_type = v.typ
when not matched then insert
 (config_code, config_value, data_type, is_tenant_overridable_yn, description)
values (v.code, v.val, v.typ, v.ovr, v.des);
