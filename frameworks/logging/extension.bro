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

## Setup event extension to include sensor and probe name
type Extension: record {
    ## The log stream that this log was written to.
    stream:   string &log;
    ## The name of the system that wrote this log. This
    ## is defined in the  const so that
    ## a system running lots of processes can give the
    ## same value for any process that writes a log.
    system:   string &log;
    ## The name of the process that wrote the log. In
    ## clusters, this will typically be the name of the
    ## worker that wrote the log.
    proc:     string &log;
};

function add_log_extension(path: string): Extension
{
    return Extension($stream = path,
                     $system = ROCK::sensor_id,
                     $proc   = peer_description);
}

redef Log::default_ext_func   = add_log_extension;
redef Log::default_ext_prefix = "@";
redef Log::default_scope_sep  = "_";
