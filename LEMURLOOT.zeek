https://try.zeek.org/#/tryzeek/saved/16ab5dbf12954c5d98d015cfc7b625c6


@load base/frameworks/notice
@load base/protocols/http
@load base/frameworks/analyzer/dpd

module LEMURLOOT;

export {
  ## Notice types
  redef enum Notice::Type += {
    LEMURLOOT_Handshake,
    LEMURLOOT_CmdGzip
  };

  ## Toggle:T = Use the port list 
  ##        F (default) = rely on DPD to discover HTTP on any port
  option force_http_port_registration = F &redef;

  ## Curated list of common admin/alt HTTP ports (Use when above set to T).
  option forced_http_ports: set[port] = {
    80/tcp, 8000/tcp, 8008/tcp, 8080/tcp, 8081/tcp, 8088/tcp,
    8010/tcp, 8020/tcp, 8021/tcp, 8888/tcp, 8002/tcp
  } &redef;

  ## Matching patterns (redefinable)
  const GUID_PAT: pattern = /^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$/ &redef;
  const GZIP_PAT: pattern = /gzip/i &redef;

  ## Whether to raise a notice on handshake alone
  option alert_on_handshake_only = T &redef;
}

## Register ports only if you flip the switch to T.
event zeek_init()
  {
  if ( LEMURLOOT::force_http_port_registration && |LEMURLOOT::forced_http_ports| > 0 )
    Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP, LEMURLOOT::forced_http_ports);
  }

## Light de-dup
redef Notice::type_suppression_intervals += {
  [LEMURLOOT_Handshake] = 5mins,
  [LEMURLOOT_CmdGzip]   = 5mins
};

## --- State keyed by connection UID ---
global hs_req_seen:  table[string] of bool   &default=F;  # saw GUID in request
global hs_guid:      table[string] of string;             # GUID (check "uid in hs_guid")
global ack_seen:     table[string] of bool   &default=F;  # server echoed "comment"
global resp_gzip:    table[string] of bool   &default=F;  # response had gzip
global pending_cmd:  table[string] of string;             # concatenated Step1/2/3=...

## Notice helper
function try_fire_cmd(c: connection)
  {
  local uid = c$uid;

  if ( resp_gzip[uid] && uid in pending_cmd && hs_req_seen[uid] && ack_seen[uid] )
    {
    local details = pending_cmd[uid];
    local guid = (uid in hs_guid) ? hs_guid[uid] : "<unknown-guid>";

    local n: Notice::Info = [
      $note       = LEMURLOOT_CmdGzip,
      $msg        = fmt("LEMURLOOT-style command with gzip on %s -> %s (uid=%s, guid=%s, %s)",
                        c$id$orig_h, c$id$resp_h, uid, guid, details),
      $conn       = c,
      $identifier = cat("LL-CMD|", uid)
    ];
    NOTICE(n);

    delete pending_cmd[uid];
    delete resp_gzip[uid];
    delete ack_seen[uid];
    if ( uid in hs_guid ) delete hs_guid[uid];
    hs_req_seen[uid] = F;
    }
  }

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
  {
  if ( is_orig )
    {
    if ( name == "X-SILOCK-COMMENT" && value == GUID_PAT )
      {
      hs_req_seen[c$uid] = T;
      hs_guid[c$uid] = value;
      }

    if ( name == "X-SILOCK-STEP1" || name == "X-SILOCK-STEP2" || name == "X-SILOCK-STEP3" )
      {
      local key  = name == "X-SILOCK-STEP1" ? "Step1"
                 : name == "X-SILOCK-STEP2" ? "Step2" : "Step3";
      local prev = c$uid in pending_cmd ? pending_cmd[c$uid] : "";
      local agg  = prev == "" ? fmt("%s=%s", key, value) : fmt("%s,%s=%s", prev, key, value);
      pending_cmd[c$uid] = agg;
      }
    }
  else
    {
    if ( name == "X-SILOCK-COMMENT" && to_lower(value) == "comment" )
      {
      ack_seen[c$uid] = T;

      if ( LEMURLOOT::alert_on_handshake_only && hs_req_seen[c$uid] )
        {
        local guid = (c$uid in hs_guid) ? hs_guid[c$uid] : "<unknown-guid>";
        local n: Notice::Info = [
          $note       = LEMURLOOT_Handshake,
          $msg        = fmt("LEMURLOOT-style handshake on %s -> %s (uid=%s, guid=%s)",
                            c$id$orig_h, c$id$resp_h, c$uid, guid),
          $conn       = c,
          $identifier = cat("LL-HS|", c$uid)
        ];
        NOTICE(n);
        }
      }

    if ( name == "CONTENT-ENCODING" && value == GZIP_PAT )
      {
      resp_gzip[c$uid] = T;
      try_fire_cmd(c);
      }
    }
  }

event connection_state_remove(c: connection)
  {
  delete hs_req_seen[c$uid];
  if ( c$uid in hs_guid )     delete hs_guid[c$uid];
  if ( c$uid in ack_seen )    delete ack_seen[c$uid];
  if ( c$uid in resp_gzip )   delete resp_gzip[c$uid];
  if ( c$uid in pending_cmd ) delete pending_cmd[c$uid];
  }
