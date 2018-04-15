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

##! Hooks to forward notices to [SCOT](https://github.com/sandialabs/scot)
# This will forward all notices by default. Add notice types to
# `SCOT::exclude_notice_types` that you wish to filter out.

# NOTE: This is on hold until the upstream fixes a glitch in the matrix

# Load all of the other scripts this script depends on.  Try to be careful to
# not load more than necessary, but it's good practice to be sure that all
# dependencies are loaded so that users only need to load this single script.
@load base/frameworks/notice
@load base/utils/active-http

# This is ROCK specific
@load ../../utils/json

redef exit_only_after_terminate = T;

# Define your namespace where all of your locally defined functions and
# variables will reside.
module SCOT;

redef enum Notice::Action += {
	ACTION_LOG
};

# The export section contains the external interface for customizing your
# script and accessing useful internal state.  Consts defined here should
# be used for changing the behavior of the script and *MUST* have the &redef
# attribute.  Globals should be used for storing information which
# is used by this script, but may be useful to another script at runtime.
export {
	#============================#
	# Configuration variables    #
	#============================#
  type Info: record {
    tags: set[string] &optional &log;
    sources: set[string] &optional &log;
    subject: string &log;
    data: Notice::Info &log;
    readgroups: set[string] &optional &log;
    modifygroups: set[string] &optional &log;
  };

  # URL that notice will be POSTed to for alarm
  # This should be configured without the scheme (i.e. no https://)
	const alarm_api = "localhost/scot/alertgroup" &redef;

  # Username for authentication to SCOT
  const username = "admin" &redef;

  # Password for authentication to SCOT
  const passwd = "" &redef;

	# Add notice types from Notice::Type enum to exclude from being sent.
  # By default ACTION_LOG will send all notices as alarms.
	const exclude_notice_types = set() &redef;

  # This is a set of strings used to tag the source for the alarm in SCOT
  # This defaults to "bro" but might also be useful to use a unique sensor name
  const alarm_source = set("bro") &redef;
}

hook Notice::notice(n: Notice::Info)
	{
	if ( SCOT::ACTION_LOG in n$actions )
		{
      local data = Info(
        $sources = alarm_source,
        $subject = n$msg,
        $data=n
      );

      local post_data = JSON::convert(data, $log_only=T);

      local r = ActiveHTTP::Request(
        $url=cat("https://",
          username, ":", passwd,
          "@", SCOT::alarm_api),
        $method="POST",
        $client_data=post_data,
        $max_time=60 secs,
        $addl_curl_args="-k"
        );

      #print r;
      when( local resp = ActiveHTTP::request(r) )
        {
          #print resp;
        }

		}
	}



#############


redef enum Notice::Type += {
  ## The hash value of a file transferred over HTTP matched in the
  ## malware hash registry.
  SCOT::JSON_Alert
};

hook Notice::policy(n: Notice::Info)
  {
    add n$actions[SCOT::ACTION_LOG];
  }

event bro_init()
{
  local message = fmt("bad things happened");

  NOTICE([$ts=network_time(),
          $note=SCOT::JSON_Alert,
          $msg=message,
          $identifier=cat("127.0.0.1")]);
}

redef SCOT::alarm_api = "52.12.122.162/scot/alertgroup";
redef SCOT::passwd = "admin";
