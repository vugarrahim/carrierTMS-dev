create or replace package pkg_util as
  -- ==========================================================================
  -- Package: PKG_UTIL
  -- Purpose: Pure, stateless helpers shared by all packages (TDS 8.2).
  -- No table access, no context writes, no dependencies. Leaf.
  -- ==========================================================================
  -- Lower-cases and trims an e-mail for comparison/storage of lookup keys.
  function normalize_email(p_email in varchar2) return varchar2 deterministic;
  -- Basic RFC-style shape check (server backstop; UI validates first).
  function is_valid_email(p_email in varchar2) return boolean deterministic;
  -- Digits-only US/CA numbers to E.164 (+1XXXXXXXXXX); returns NULL if not
  -- normalizable so callers can raise a registered business error.
  function normalize_phone_e164(p_phone in varchar2) return varchar2
    deterministic;
  -- 'Y'/'N' (case-insensitive, also accepts YES/NO/TRUE/FALSE/1/0) -> boolean.
  function parse_yn(p_value in varchar2) return boolean deterministic;
  -- Render a UTC timestamp in the given IANA timezone for display.
  function format_ts(p_ts  in timestamp with time zone,
                     p_tz  in varchar2 default 'UTC',
                     p_fmt in varchar2 default 'YYYY-MM-DD HH24:MI')
    return varchar2;
  -- "First Last", collapsed whitespace.
  function gen_display_name(p_first in varchar2, p_last in varchar2)
    return varchar2 deterministic;
end pkg_util;
/
create or replace package body pkg_util as
function normalize_email(p_email in varchar2) return varchar2
  deterministic is
begin
return lower(trim(p_email));
end; function is_valid_email(p_email in varchar2) return boolean
  deterministic is
begin
-- Deliberately permissive: one @, something either side, a dot in the
-- domain, no spaces. Full RFC validation causes false rejections.
return p_email is
not null and length(p_email) <= 320 and regexp_like(p_email, '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$');
end; function normalize_phone_e164(p_phone in varchar2) return varchar2
  deterministic is
l_digits varchar2(30);
begin
if p_phone is
null then return null;
end if; l_digits := regexp_replace(p_phone, '[^0-9]', ''); if length(l_digits) = 10 then -- US/CA national
return '+1' || l_digits; elsif length(l_digits) = 11 and l_digits like '1%' then return '+' || l_digits;
end if; return null; -- caller decides how to fail
end; function parse_yn(p_value in varchar2) return boolean deterministic is
begin
return upper(trim(p_value)) in ('Y', 'YES', 'TRUE', '1');
end; function format_ts(p_ts in timestamp with time zone, p_tz in varchar2 default 'UTC', p_fmt in varchar2 default 'YYYY-MM-DD HH24:MI') return varchar2 is
begin
if p_ts is
null then return null;
end if; return to_char(p_ts at time zone nvl(p_tz, 'UTC'), p_fmt);
exception
when others then -- unknown TZ name etc.
return to_char(p_ts at time zone 'UTC', p_fmt) || ' UTC';
end; function gen_display_name(p_first in varchar2, p_last in varchar2) return varchar2
  deterministic is
begin
return trim(regexp_replace(p_first || ' ' || p_last, '[[:space:]]+', ' '));
end;
end pkg_util;
/
