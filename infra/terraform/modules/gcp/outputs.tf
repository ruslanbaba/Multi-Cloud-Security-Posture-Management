output "function_name" { value = google_cloudfunctions2_function.forwarder.name }
output "topic_name" { value = google_pubsub_topic.scc_findings.name }
