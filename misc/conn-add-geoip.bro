# Copyright (C) 2016, Missouri Cyber Team
# All Rights Reserved
# See the file "LICENSE" in the main distribution directory for details

##! Add geo_location for the originator and responder of a connection
##! to the connection logs.

module Conn;

export
{
  redef record Conn::Info +=
  {
    orig_location: string &optional &log;
    resp_location: string &optional &log;
  };
}

event connection_state_remove(c: connection)
{
  local orig_loc = lookup_location(c$id$orig_h);
  if (orig_loc?$longitude && orig_loc?$latitude)
    c$conn$orig_location= cat(orig_loc$latitude,",",orig_loc$longitude);
  local resp_loc = lookup_location(c$id$resp_h);
  if (resp_loc?$longitude && resp_loc?$latitude)
    c$conn$resp_location= cat(resp_loc$latitude,",",resp_loc$longitude);
}
