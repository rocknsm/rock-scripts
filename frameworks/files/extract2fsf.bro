# knifehands
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
