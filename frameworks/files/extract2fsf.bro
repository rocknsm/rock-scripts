# knifehands
# take extracted files and submit to FSF
 
event file_state_remove(f: fa_file)
    {
        if ( f$info?$extracted )
        {
               # invoke the FSF-CLIENT and add the source metadata of ROCK01 (sensorID), we're suppressing the returned report
               # becuase we don't need that
               local scan_cmd = fmt("%s %s/%s", "/opt/bro/share/bro/site/scripts/fsf-client/fsf_client.py" --source <sensorname> --suppress-report --archive none", FileExtract::prefix, f$info$extracted);
               system(scan_cmd);
         }
}