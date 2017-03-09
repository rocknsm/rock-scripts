
## Setup Kafka output
@load Bro/Kafka/logs-to-kafka

redef Kafka::topic_name = "bro-raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json = F;

