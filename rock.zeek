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

module ROCK;

export {
  const sensor_id = gethostname() &redef;
}

#=== Bro built-ins ===================================

# Enable VLAN Logging
@load policy/protocols/conn/vlan-logging

# Log MAC addresses
@load policy/protocols/conn/mac-logging

# Log (All) Client and Server HTTP Headers
@load policy/protocols/http/header-names

#== ROCK specific scripts ============================
# Add empty Intel framework database
@load ./frameworks/intel

# Load integration with FSF
@load ./frameworks/files/extract2fsf

# Load file extraction
@load ./frameworks/files/extraction
redef FileExtract::prefix = "/data/zeek/logs/extract_files/";
redef FileExtract::default_limit = 1048576000;

# Add sensor and log meta information to each log
@load ./frameworks/logging/extension

# Log all orig and resp cert hashes in ssl log
@load ./protocols/ssl/ssl-add-cert-hash

# Enable pop3 logging
@load ./protocols/pop3

# Notice on all recently created certs
# @load ./protocols/ssl/new-certs

# Generate log of all unique DNS queries with answers
# @load ./protocols/dns/known_domains

# Generate log of all URLs seen in an SMTP body
# @load ./protocols/smtp/smtp-url

# Generate log of local systems using unencrypted protocols
# @load ./frameworks/compliance/detect-insecure-protos

#== 3rd Party Scripts =================================
# Add Salesforce's JA3 SSL fingerprinting
@load ./misc/ja3

# Add Salesforce's HASSH SSH fingerprinting
@load ./misc/hassh

# Add community_id to all network logs
@load ./plugins/community_id

### Sensor specific scripts ######################

# Configure AF_PACKET, if in use
@load ./plugins/afpacket
