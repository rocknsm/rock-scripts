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

module SSL;

export {
  redef record SSL::Info += {
    orig_certificate_sha1: string &optional &log;
    resp_certificate_sha1: string &optional &log;
  };
}

event file_hash(f: fa_file, kind: string, hash: string) {
  if (! ( kind == "sha1" && f?$source && f$source == "SSL" ))
    return;

	if ( |f$conns| != 1 )
		return;

	if ( ! f?$info || ! f$info?$mime_type )
		return;

	if ( ! ( f$info$mime_type == "application/x-x509-ca-cert" || f$info$mime_type == "application/x-x509-user-cert"
		 || f$info$mime_type == "application/pkix-cert" ) )
		return;

	local c: connection;

	for ( cid in f$conns )
	{
    c = f$conns[cid];

		if ( ! c?$ssl )
			return;

  	local chain: vector of string;

  	if ( f$is_orig )
  		chain = c$ssl$client_cert_chain_fuids;
  	else
  		chain = c$ssl$cert_chain_fuids;

  	if ( |chain| == 0 )
  		{
  		Reporter::warning(fmt("Certificate not in chain? (fuid %s)", f$id));
  		return;
  		}

  	# Check if this is the host certificate, if so, log hash by direction
  	if ( f$id == chain[0] ) {
      if ( f$is_orig )
        c$ssl$orig_certificate_sha1 = hash;
      else
        c$ssl$resp_certificate_sha1 = hash;
    }
	}

}
