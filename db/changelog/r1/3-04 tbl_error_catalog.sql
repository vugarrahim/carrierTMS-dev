create table error_catalog ( 
  error_code         varchar2(10)                      not null, -- 'TMS-1001' 
  user_message       varchar2(500)                     not null, -- %1..%3 params 
  developer_message  varchar2(1000)                    not null, 
  severity           varchar2(10)  default 'ERROR'     not null, 
  constraint_name    varchar2(128),                    -- maps ORA-1/2290/2292 by name 
  created_at   timestamp with time zone default systimestamp not null, 
  created_by   number(18) 
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1) 
                                                       not null, 
  updated_at   timestamp with time zone, 
  updated_by   number(18), 
  row_version  number(9)    default 1                  not null, 
  constraint error_catalog_pk  primary key (error_code), 
  constraint error_catalog_ck1 check (severity in ('ERROR','WARNING','INFO')), 
  constraint error_catalog_ck2 check (error_code like 'TMS-%') 
); 
  
comment on table  error_catalog is 
  'Business error registry (codes TMS-1000..TMS-9999). PKG_ERROR renders user_message; 
developer_message goes to APP_LOG only.'; 
comment on column error_catalog.constraint_name is 
  'Optional DB constraint name this code translates (unique/check/FK violations that escape package 
validation).'; 
  
create unique index error_catalog_uk1 
  on error_catalog ( case when constraint_name is not null then constraint_name end ); 
