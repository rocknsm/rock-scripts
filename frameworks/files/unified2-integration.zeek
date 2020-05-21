# Copyright (C) 2016-2020, RockNSM Foundation
#
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

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
