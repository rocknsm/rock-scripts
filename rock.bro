# Copyright (C) 2016, Missouri Cyber Team
# All Rights Reserved
# See the file "LICENSE" in the main distribution directory for details

module ROCK;

export {
  const sensor_id = "sensor001-001" &redef;
}

# Load integration with Snort on ROCK
@load ./frameworks/files/unified2-integration

# Load integration with FSF
@load ./frameworks/files/extract2fsf

# Load file extraction
@load ./frameworks/files/extraction
redef FileExtract::prefix = "/data/bro/logs/extract_files/";
redef FileExtract::default_limit = 1048576000;

# Configure Kafka output
# Bro Kafka Output (plugin must be loaded!)
@load Kafka/KafkaWriter/logs-to-kafka
redef KafkaLogger::topic_name = "bro_raw";
redef KafkaLogger::sensor_name = ROCK::sensor_id;

# Add GeoIP info to conn log
@load ./misc/conn-add-geoip

