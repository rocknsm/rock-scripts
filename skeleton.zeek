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

##! Short description of what this file is about
#  This file provides a rough sketch of a bro script

# Load all of the other scripts this script depends on.  Try to be careful to
# not load more than necessary, but it's good practice to be sure that all
# dependencies are loaded so that users only need to load this single script.
@load base/frameworks/notice

# Define your namespace where all of your locally defined functions and
# variables will reside.
module Skeleton;

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
	const alarm_api = "localhost/skeleton/api/v1/" &redef;

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

event zeek_init()
{
  # Add any initalization logic here
}

# Add events, hooks, and other logic here
