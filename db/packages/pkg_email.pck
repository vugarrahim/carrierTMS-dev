create or replace package pkg_email as
  -- v2: adds dispatch of QUEUED/FAILED outbox rows via APEX_MAIL.
  function queue_mail(p_to        in varchar2,
                      p_subject   in varchar2,
                      p_body_html in clob,
                      p_template  in varchar2 default null) return number;
  procedure dispatch_queued; -- JOB_EMAIL_RETRY entry point
end pkg_email;
/
create or replace package body pkg_email as
  function queue_mail(p_to        in varchar2,
                      p_subject   in varchar2,
                      p_body_html in clob,
                      p_template  in varchar2 default null) return number is
    l_id email_outbox.outbox_id%type;
  begin
    if not pkg_util.is_valid_email(p_to) then
      pkg_error.raise_business('TMS-2001', p_to);
    end if;
    insert into email_outbox
      (tenant_id, to_addr, subject_text, body_html, template_code)
    values
      (pkg_security.get_tenant_id,
       lower(trim(p_to)),
       substr(p_subject, 1, 500),
       p_body_html,
       p_template)
    returning outbox_id into l_id;
    return l_id;
  end;
  procedure dispatch_queued is
    c_max_attempts constant pls_integer := 5;
    l_from varchar2(320);
    l_body clob;
    l_err  varchar2(1000);
  
  begin
    -- Scheduler jobs have no APEX context; APEX_MAIL needs the workspace.
    apex_util.set_workspace('TMS_DEV');
    l_from := pkg_config.get_text('MAIL.FROM_ADDRESS');
    for r in (select outbox_id, to_addr, subject_text, body_html
                from email_outbox
               where status in ('QUEUED', 'FAILED')
                 and attempts < c_max_attempts
               order by outbox_id
                 for update skip locked) loop
      -- job overlap safe
      begin
        l_body := to_clob('Please view this message in an HTML-capable client.');
      
        apex_mail.send(p_to        => r.to_addr,
                       p_from      => l_from,
                       p_subj      => r.subject_text,
                       p_body      => l_body,
                       p_body_html => r.body_html);
        update email_outbox
           set status      = 'SENT',
               sent_at     = systimestamp,
               attempts    = attempts + 1,
               last_error  = null,
               updated_at  = systimestamp,
               row_version = row_version + 1
         where outbox_id = r.outbox_id;
      exception
        when others then
          l_err := substr(sqlerrm, 1, 1000);
        
          update email_outbox
             set status      = 'FAILED',
                 attempts    = attempts + 1,
                 last_error  = l_err,
                 updated_at  = systimestamp,
                 row_version = row_version + 1
           where outbox_id = r.outbox_id;
          pkg_logger.warn('Mail dispatch failed for outbox ' ||
                          r.outbox_id,
                          to_clob(sqlerrm));
      end;
    end loop;
    apex_mail.push_queue;
    commit;
  end;
end pkg_email;
/
