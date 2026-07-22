create table roles ( 
  role_id       number(18) generated always as identity not null, 
  role_code     varchar2(30)                       not null, 
  role_name     varchar2(100)                      not null, 
  description   varchar2(500), 
  realm         varchar2(10) default 'TENANT'      not null, 
  tenant_id     number(18),                        -- NULL = system role 
  is_system_yn  varchar2(1)  default 'Y'           not null, 
  is_active_yn  varchar2(1)  default 'Y'           not null, 
  sort_order    number(4)    default 0             not null, 
  created_at   timestamp with time zone default systimestamp not null, 
  created_by   number(18) 
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null, 
  updated_at   timestamp with time zone, 
  updated_by   number(18), 
  row_version  number(9)    default 1              not null, 
  constraint roles_pk  primary key (role_id), 
  constraint roles_fk1_tenants foreign key (tenant_id) references tenants (tenant_id), 
  constraint roles_ck1 check (realm in ('TENANT','PLATFORM','EXTERNAL')), 
  constraint roles_ck2 check (is_system_yn in ('Y','N')), 
  constraint roles_ck3 check (is_active_yn in ('Y','N')), 
  -- System roles are global; only future tenant custom roles carry a tenant. 
  constraint roles_ck4 check (is_system_yn = 'N' or tenant_id is null) 
); 
create unique index roles_uk1 on roles (nvl(tenant_id, 0), role_code); 
create index roles_ix1 on roles (realm, is_active_yn); 
comment on table roles is 
  'Role catalog = named permission bundles (TDS 5.1). Flat model; no hierarchy by design. Writes via 
PKG_ROLES.'; 
  
create table permissions ( 
  permission_id    number(18) generated always as identity not null, 
  permission_code  varchar2(60)                    not null, 
  permission_name  varchar2(150)                   not null, 
  module_code      varchar2(30)                    not null, 
  description      varchar2(500), 
  is_active_yn     varchar2(1)  default 'Y'        not null, 
  created_at   timestamp with time zone default systimestamp not null, 
  created_by   number(18) 
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null, 
  updated_at   timestamp with time zone, 
  updated_by   number(18), 
  row_version  number(9)    default 1              not null, 
  constraint permissions_pk  primary key (permission_id), 
  constraint permissions_uk1 unique (permission_code), 
  constraint permissions_ck1 check (is_active_yn in ('Y','N')), 
  constraint permissions_ck2 check (permission_code = upper(permission_code) 
                                    and instr(permission_code, '.') > 1) 
); 
create index permissions_ix1 on permissions (module_code); 
comment on table permissions is 
  'Capability catalog, codes <MODULE>.<ACTION> (TDS 5.3). Pages/guards check permissions, never role 
names.'; 
  
create table role_permissions ( 
  role_permission_id number(18) generated always as identity not null, 
  role_id            number(18)                    not null, 
  permission_id      number(18)                    not null, 
  granted_by         number(18), 
  granted_at         timestamp with time zone default systimestamp not null, 
  created_at   timestamp with time zone default systimestamp not null, 
  created_by   number(18) 
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null, 
  constraint role_permissions_pk  primary key (role_permission_id), 
  constraint role_permissions_uk1 unique (role_id, permission_id), 
  constraint role_permissions_fk1_roles       foreign key (role_id) 
             references roles (role_id), 
  constraint role_permissions_fk2_permissions foreign key (permission_id) 
             references permissions (permission_id) 
); 
create index role_permissions_ix1 on role_permissions (permission_id); 
comment on table role_permissions is 
  'Machine-readable permission matrix (TDS 5.4). Seeded by migration; operator-editable later.'; 
  
create table user_roles ( 
  user_role_id  number(18) generated always as identity not null, 
  tenant_id     number(18),                        -- denormalized from user (VPD scoping) 
  user_id       number(18)                         not null, 
  role_id       number(18)                         not null, 
  granted_by    number(18), 
  granted_at    timestamp with time zone default systimestamp not null, 
  expires_at    timestamp with time zone, 
  created_at   timestamp with time zone default systimestamp not null, 
  created_by   number(18) 
               default coalesce(to_number(sys_context('app_ctx','user_id')), -1) not null, 
  updated_at   timestamp with time zone, 
  updated_by   number(18), 
  row_version  number(9)    default 1              not null, 
  constraint user_roles_pk  primary key (user_role_id), 
  constraint user_roles_uk1 unique (user_id, role_id), 
  constraint user_roles_fk1_app_users foreign key (user_id) 
             references app_users (user_id), 
  constraint user_roles_fk2_roles     foreign key (role_id) 
             references roles (role_id), 
  constraint user_roles_fk3_tenants   foreign key (tenant_id) 
             references tenants (tenant_id) 
); 
create index user_roles_ix1 on user_roles (role_id); 
create index user_roles_ix2 on user_roles (tenant_id); 
comment on table user_roles is 
  'Role assignments. Realm match user<->role enforced in PKG_ROLES (cross-table rule, not declarable). 
EXPIRES_AT = time-boxed grants.';
