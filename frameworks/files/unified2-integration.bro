@load base/files/unified2


export {
    # Add connection ID to unified2 log	
    redef record Unified2::Info += 
    {
        uid: string &optional &log;
    };
}

event log_unified2 ( rec: Unified2::Info )
{
	  # The following fields are required in the Info record. No need to check
    local c = lookup_connection([
      $orig_h=rec$id$src_ip, 
      $orig_p=rec$id$src_p, 
      $resp_h=rec$id$dst_ip, 
      $resp_p=rec$id$dst_p
    ]);

    if ( c?$id )
    {
        # Add conn info to event
        rec$uid = c$uid;
    }
}

