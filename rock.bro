# Copyright (C) 2016, Missouri Cyber Team
# All Rights Reserved
# See the file "LICENSE" in the main distribution directory for details

module ROCK;

export {
  const sensor_id = "sensor001-001" &redef;
}

# Add empty Intel framework database
@load ./frameworks/intel

# Load integration with Snort on ROCK
@load ./frameworks/files/unified2-integration

# Load integration with FSF
@load ./frameworks/files/extract2fsf

# Load file extraction
@load ./frameworks/files/extraction
redef FileExtract::prefix = "/data/bro/logs/extract_files/";
redef FileExtract::default_limit = 1048576000;


# Add GeoIP info to conn log
@load ./misc/conn-add-geoip

# Add sensor and log meta information to each log
@load ./frameworks/logging/extension
