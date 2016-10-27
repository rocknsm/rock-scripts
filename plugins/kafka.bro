
## Setup Kafka output
@load Bro/Kafka/logs-to-kafka

redef Kafka::topic_name = "bro_raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json = T;

## Setup event extension to include sensor and probe name
type Extension: record {
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
    return Extension($system = ROCK::sensor_id,
                     $proc   = peer_description);
}

redef Log::default_ext_func   = add_log_extension;
redef Log::default_ext_prefix = "@";
redef Log::default_scope_sep  = "_";
