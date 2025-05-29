# Prometheus Configuration for Agentic-IAM
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'agentic-iam'
    replica: 'prometheus'

# Rules for alerting
rule_files:
  - "alert_rules.yml"

# Alert manager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

# Scrape configurations
scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
    metrics_path: /metrics

  # Agentic-IAM Application
  - job_name: 'agentic-iam'
    static_configs:
      - targets: ['agentic-iam:9090']
    scrape_interval: 15s
    metrics_path: /metrics
    honor_labels: true
    params:
      format: ['prometheus']
    
    # Relabeling for better metric organization
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'agentic_iam_(.*)'
        target_label: __name__
        replacement: 'agentic_${1}'

  # PostgreSQL Exporter
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
    scrape_interval: 30s

  # Redis Exporter
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
    scrape_interval: 30s

  # Node Exporter (for system metrics)
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 30s

  # Nginx Exporter
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']
    scrape_interval: 30s

  # Kubernetes API Server
  - job_name: 'kubernetes-api-server'
    kubernetes_sd_configs:
      - role: endpoints
        namespaces:
          names:
            - default
    scheme: https
    tls_config:
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      insecure_skip_verify: true
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    relabel_configs:
      - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
        action: keep
        regex: default;kubernetes;https

  # Kubernetes Nodes
  - job_name: 'kubernetes-nodes'
    kubernetes_sd_configs:
      - role: node
    scheme: https
    tls_config:
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      insecure_skip_verify: true
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)

  # Kubernetes Pods
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - agentic-iam
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: kubernetes_pod_name

  # Custom Agentic-IAM specific metrics
  - job_name: 'agentic-iam-agents'
    static_configs:
      - targets: ['agentic-iam:8000']
    metrics_path: /api/v1/metrics/agents
    scrape_interval: 60s

  - job_name: 'agentic-iam-auth'
    static_configs:
      - targets: ['agentic-iam:8000']
    metrics_path: /api/v1/metrics/authentication
    scrape_interval: 30s

  - job_name: 'agentic-iam-sessions'
    static_configs:
      - targets: ['agentic-iam:8000']
    metrics_path: /api/v1/metrics/sessions
    scrape_interval: 30s

  - job_name: 'agentic-iam-trust'
    static_configs:
      - targets: ['agentic-iam:8000']
    metrics_path: /api/v1/metrics/trust-scores
    scrape_interval: 120s

  - job_name: 'agentic-iam-audit'
    static_configs:
      - targets: ['agentic-iam:8000']
    metrics_path: /api/v1/metrics/audit
    scrape_interval: 60s

# Remote write configuration (for long-term storage)
remote_write:
  - url: "http://thanos-receive:19291/api/v1/receive"
    queue_config:
      max_samples_per_send: 1000
      max_shards: 200
      capacity: 2500