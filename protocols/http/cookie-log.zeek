# Copyright (C) 2016-2020 RockNSM
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
module Cookie;

export {
  # The fully resolve name for this will be LocationExtract::LOG
  redef enum Log::ID += { LOG };
  type Info: record {
    ts:     time    &log;
    uid:    string &log;
    id:     conn_id  &log;
    cookie: string &log;
    cookie_unesc: string &log;
  };
}

event zeek_init() &priority=5 {
  Log::create_stream(Cookie::LOG, [$columns=Info]);
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5 {
  if ( is_orig && name == "COOKIE") {
    local unesc_cookie = unescape_URI(value);
    local log_rec: Cookie::Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $cookie=value, $cookie_unesc=unesc_cookie];
    Log::write(Cookie::LOG, log_rec);
  }
}
