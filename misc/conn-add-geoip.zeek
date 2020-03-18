# Copyright (C) 2016-2018 RockNSM
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##! Add geo_location for the originator and responder of a connection
##! to the connection logs.

module Conn;

export
{
  redef record Conn::Info +=
  {
    orig_location: string &optional &log;
    resp_location: string &optional &log;
    orig_country_code: string &optional &log;
    resp_country_code: string &optional &log;
    orig_asn: count &log &optional;
    resp_asn: count &log &optional;
  };
}

event connection_state_remove(c: connection)
{
  local orig_loc = lookup_location(c$id$orig_h);
  if (orig_loc?$longitude && orig_loc?$latitude)
    c$conn$orig_location= cat(orig_loc$latitude,",",orig_loc$longitude);
  local orig_ccode = lookup_location(c$id$orig_h);
  if (orig_ccode?$country_code)
    c$conn$orig_country_code= cat(orig_ccode$country_code);
  c$conn$orig_asn= lookup_asn(c$id$orig_h);
  local resp_loc = lookup_location(c$id$resp_h);
  if (resp_loc?$longitude && resp_loc?$latitude)
    c$conn$resp_location= cat(resp_loc$latitude,",",resp_loc$longitude);
  local resp_ccode = lookup_location(c$id$resp_h);
  if (resp_ccode?$country_code)
    c$conn$resp_country_code= cat(resp_ccode$country_code);
  c$conn$resp_asn= lookup_asn(c$id$resp_h);
}

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
