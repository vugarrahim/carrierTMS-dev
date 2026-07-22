create table app_log ( 
  log_id       number(18) generated always as identity not null, 
  log_level    varchar2(5)                        not null, -- ERROR/WARN/INFO/DEBUG 
  module_name  varchar2(100), 
  message      varchar2(4000)                     not null, 
  detail       clob,                              -- stacks, context dump 
  tenant_id    number(18),                        -- soft ref (context may be absent) 
  user_id      number(18),                        -- soft ref 
  apex_session_id number(18), 
  logged_at    timestamp with time zone default systimestamp not null, 
  constraint app_log_pk  primary key (log_id), 
  constraint app_log_ck1 check (log_level in ('ERROR','WARN','INFO','DEBUG')) 
); 
  
comment on table app_log is 
  'Technical log (PKG_LOGGER). No FKs by design: logging must never fail because a referenced row 
changed, and rows outlive users. Purged by JOB_LOG_PURGE per LOG.RETENTION_DAYS.'; 
  
create index app_log_ix1 on app_log (log_level, logged_at); 
create index app_log_ix2 on app_log (logged_at); 
