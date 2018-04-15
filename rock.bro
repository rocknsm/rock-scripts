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

module ROCK;

export {
  const sensor_id = gethostname() &redef;
}

#=== Bro built-ins ===================================

# Collect on SMB protocol
@load policy/protocols/smb

# Enable VLAN Logging
@load policy/protocols/conn/vlan-logging

# Log MAC addresses
@load policy/protocols/conn/mac-logging

#== ROCK specific scripts ============================
# Add empty Intel framework database
@load ./frameworks/intel

# Load integration with FSF
@load ./frameworks/files/extract2fsf

# Load file extraction
@load ./frameworks/files/extraction
redef FileExtract::prefix = "/data/bro/logs/extract_files/";
redef FileExtract::default_limit = 1048576000;

# Add sensor and log meta information to each log
@load ./frameworks/logging/extension

### Sensor specific scripts ######################

# Configure AF_PACKET, if in use
@load ./plugins/afpacket
