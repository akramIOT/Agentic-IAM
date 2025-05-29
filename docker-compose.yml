# Docker Compose for Agentic-IAM Development and Production
version: '3.8'

services:
  # Main Agentic-IAM Application
  agentic-iam:
    build:
      context: .
      dockerfile: Dockerfile
      target: production
    container_name: agentic-iam-app
    restart: unless-stopped
    ports:
      - "8000:8000"   # API server
      - "8501:8501"   # Dashboard
    environment:
      # Core Configuration
      - AGENTIC_IAM_ENVIRONMENT=production
      - AGENTIC_IAM_API_HOST=0.0.0.0
      - AGENTIC_IAM_API_PORT=8000
      - AGENTIC_IAM_DASHBOARD_HOST=0.0.0.0
      - AGENTIC_IAM_DASHBOARD_PORT=8501
      
      # Database Configuration
      - AGENTIC_IAM_DATABASE_URL=postgresql://agentic_user:agentic_password@postgres:5432/agentic_iam
      - AGENTIC_IAM_REDIS_URL=redis://redis:6379/0
      
      # Security Configuration
      - AGENTIC_IAM_SECRET_KEY=${SECRET_KEY:-your-secret-key-change-in-production}
      - AGENTIC_IAM_ENCRYPTION_KEY=${ENCRYPTION_KEY:-your-encryption-key-32-chars-long!}
      - AGENTIC_IAM_JWT_SECRET_KEY=${JWT_SECRET_KEY:-jwt-secret-key-change-in-production}
      - AGENTIC_IAM_CREDENTIAL_ENCRYPTION_KEY=${CREDENTIAL_ENCRYPTION_KEY:-credential-encryption-key-32-chars!}
      
      # Feature Flags
      - AGENTIC_IAM_ENABLE_TRUST_SCORING=true
      - AGENTIC_IAM_ENABLE_AUDIT_LOGGING=true
      - AGENTIC_IAM_ENABLE_MFA=true
      - AGENTIC_IAM_ENABLE_FEDERATED_AUTH=false
      - AGENTIC_IAM_ENABLE_ANOMALY_DETECTION=true
      
      # Logging
      - AGENTIC_IAM_LOG_LEVEL=INFO
      - AGENTIC_IAM_LOG_FILE=/app/logs/agentic_iam.log
      
      # Performance
      - AGENTIC_IAM_RATE_LIMIT_REQUESTS_PER_MINUTE=1000
      - AGENTIC_IAM_SESSION_TTL=3600
      - AGENTIC_IAM_JWT_TOKEN_TTL=3600
      
      # Monitoring
      - AGENTIC_IAM_ENABLE_METRICS=true
      - AGENTIC_IAM_PROMETHEUS_ENABLED=true
    
    volumes:
      - agentic_logs:/app/logs
      - agentic_data:/app/data
    
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    
    networks:
      - agentic-network
    
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.agentic-api.rule=Host(`api.agentic-iam.local`)"
      - "traefik.http.routers.agentic-api.service=agentic-api"
      - "traefik.http.services.agentic-api.loadbalancer.server.port=8000"
      - "traefik.http.routers.agentic-dashboard.rule=Host(`dashboard.agentic-iam.local`)"
      - "traefik.http.routers.agentic-dashboard.service=agentic-dashboard"
      - "traefik.http.services.agentic-dashboard.loadbalancer.server.port=8501"

  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: agentic-iam-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=agentic_iam
      - POSTGRES_USER=agentic_user
      - POSTGRES_PASSWORD=agentic_password
      - POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
    
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
    
    ports:
      - "5432:5432"
    
    networks:
      - agentic-network
    
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U agentic_user -d agentic_iam"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    
    command: >
      postgres
      -c shared_preload_libraries=pg_stat_statements
      -c pg_stat_statements.track=all
      -c max_connections=200
      -c log_statement=all
      -c log_duration=on
      -c log_line_prefix='%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '

  # Redis for Session Storage and Caching
  redis:
    image: redis:7-alpine
    container_name: agentic-iam-redis
    restart: unless-stopped
    command: >
      redis-server
      --appendonly yes
      --appendfsync everysec
      --maxmemory 512mb
      --maxmemory-policy allkeys-lru
      --save 900 1
      --save 300 10
      --save 60 10000
    
    volumes:
      - redis_data:/data
    
    ports:
      - "6379:6379"
    
    networks:
      - agentic-network
    
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 10s

  # Prometheus for Metrics Collection
  prometheus:
    image: prom/prometheus:latest
    container_name: agentic-iam-prometheus
    restart: unless-stopped
    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --storage.tsdb.path=/prometheus
      - --web.console.libraries=/etc/prometheus/console_libraries
      - --web.console.templates=/etc/prometheus/consoles
      - --storage.tsdb.retention.time=15d
      - --web.enable-lifecycle
    
    volumes:
      - ./monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    
    ports:
      - "9090:9090"
    
    networks:
      - agentic-network
    
    depends_on:
      - agentic-iam

  # Grafana for Monitoring Dashboard
  grafana:
    image: grafana/grafana:latest
    container_name: agentic-iam-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin_password_change_me
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources
    
    ports:
      - "3000:3000"
    
    networks:
      - agentic-network
    
    depends_on:
      - prometheus

  # Nginx Reverse Proxy (Optional)
  nginx:
    image: nginx:alpine
    container_name: agentic-iam-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - nginx_logs:/var/log/nginx
    
    networks:
      - agentic-network
    
    depends_on:
      - agentic-iam

  # Log Aggregation with ELK Stack (Optional)
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    container_name: agentic-iam-elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    
    ports:
      - "9200:9200"
    
    networks:
      - agentic-network
    
    profiles:
      - elk

  logstash:
    image: docker.elastic.co/logstash/logstash:8.8.0
    container_name: agentic-iam-logstash
    restart: unless-stopped
    volumes:
      - ./monitoring/logstash/pipeline:/usr/share/logstash/pipeline
      - agentic_logs:/app/logs:ro
    
    networks:
      - agentic-network
    
    depends_on:
      - elasticsearch
    
    profiles:
      - elk

  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    container_name: agentic-iam-kibana
    restart: unless-stopped
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    
    ports:
      - "5601:5601"
    
    networks:
      - agentic-network
    
    depends_on:
      - elasticsearch
    
    profiles:
      - elk

# Named Volumes for Persistence
volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  agentic_logs:
    driver: local
  agentic_data:
    driver: local
  prometheus_data:
    driver: local
  grafana_data:
    driver: local
  elasticsearch_data:
    driver: local
  nginx_logs:
    driver: local

# Network Configuration
networks:
  agentic-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16