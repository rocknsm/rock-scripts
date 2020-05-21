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
# This policy extracts all SMTP bodies (from client side) seen in traffic.

# NOTE: On a heavy SMTP segment, this will generate a lot of files!
event protocol_confirmation (c: connection, atype: Analyzer::Tag, aid: count)
{
  if ( atype == Analyzer::ANALYZER_SMTP )
  {
    local body_file = generate_extraction_filename(Conn::extraction_prefix, c, "client.txt");
    local body_f = open(body_file);
    set_contents_file(c$id, CONTENTS_ORIG, body_f);
  }
}
