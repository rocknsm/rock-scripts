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

# take extracted files and submit to FSF

event file_state_remove(f: fa_file)
    {
        if ( f$info?$extracted )
        {
               # invoke the FSF-CLIENT and add the source metadata of ROCK01 (sensorID), we're suppressing the returned report
               # becuase we don't need that
               local script_path = cat(@DIR, "/fsf-client/fsf_client.py");
	       local scan_cmd = fmt("python %s --suppress-report --archive none --source %s %s%s", script_path, ROCK::sensor_id, FileExtract::prefix, f$info$extracted);
               system(scan_cmd);
         }
}
