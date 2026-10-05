"""Prometheus metrics."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS = Counter("znids_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram(
    "znids_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
RATE_LIMITED = Counter("znids_rate_limited_total", "Requests rejected by rate limiting", ["scope"])
EVENTS_INGESTED = Counter("znids_events_ingested_total", "Events accepted by ingestion", ["source"])
EVENTS_REJECTED = Counter("znids_events_rejected_total", "Events rejected by validation", ["source"])
EVENTS_PROCESSED = Counter("znids_events_processed_total", "Events through the detection pipeline", ["classification"])
PIPELINE_LATENCY = Histogram(
    "znids_pipeline_batch_seconds",
    "Detection pipeline batch duration",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
DETECTION_LATENCY = Histogram(
    "znids_detection_latency_seconds",
    "Event timestamp to verdict latency",
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 300),
)
ALERTS_CREATED = Counter("znids_alerts_created_total", "Alerts created", ["severity"])
INCIDENTS_CREATED = Counter("znids_incidents_created_total", "Incidents created")
WS_CONNECTIONS = Gauge("znids_websocket_connections", "Open WebSocket connections")
NOTIFICATIONS = Counter("znids_notifications_total", "Notification deliveries", ["channel", "status"])
