# Copyright (C) 2016, Missouri Cyber Team
# All Rights Reserved
# See the file "LICENSE" in the main distribution directory for details

# This policy adds integration of Snort and Bro as implemented in ROCK
# Namely, it populates the `unified2` bro log with alerts detected by Snort
# It also will attempt to add connection info to the unified2 log

@load base/files/unified2

# ROCK-specific paths
redef Unified2::classification_config = "/etc/snort/classification.config";
redef Unified2::gen_msg = "/etc/snort/gen-msg.map";
redef Unified2::sid_msg = "/etc/snort/sid-msg.map";
redef Unified2::watch_dir = "/data/snort/";

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
