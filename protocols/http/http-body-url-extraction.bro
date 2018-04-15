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

# This scans the body of HTTP-served html documents for urls that may be
# loaded in the intel database
#
@load base/frameworks/intel
@load base/protocols/http
@load base/utils/urls

export {
        redef enum Intel::Where += {
                HTTP::BODY,
        };
}

event intel_http_body(f: fa_file, data: string)
	{
	if ( ! f?$conns )
		return;

	if ( ! f?$info || ! f$info?$mime_type || f$info$mime_type != "text/html" )
		return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];
		local urls = find_all_urls_without_scheme(data);
		for ( url in urls )
			{
			Intel::seen([$indicator=url,
			             $indicator_type=Intel::URL,
			             $conn=c,
			             $where=HTTP::BODY]);
			}
		}
	}

event file_sniff(f: fa_file, meta: fa_metadata )
	{
	if ( f$is_orig == T )
		return;

	if ( f$source == "HTTP" )
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=intel_http_body]);
	}
