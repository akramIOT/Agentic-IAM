# Production Deployment Guide

This guide covers deploying Agentic-IAM to production environments with enterprise-grade security, monitoring, and scalability.

## 🚀 Quick Production Setup

### Prerequisites

- **Infrastructure**: Kubernetes cluster or Docker Swarm
- **Database**: PostgreSQL 15+ (recommended) or MySQL 8+
- **Cache**: Redis 7+
- **Storage**: Persistent volumes for data and logs
- **Secrets**: Kubernetes secrets or external secret management
- **Monitoring**: Prometheus and Grafana (optional but recommended)
- **Load Balancer**: Nginx, HAProxy, or cloud load balancer

### 1. Security Configuration

Before deployment, ensure all security measures are in place:

```bash
# Generate production secrets
python scripts/security_hardening.py --generate-secrets

# Validate security configuration
python scripts/security_hardening.py --validate

# Apply security hardening
python scripts/security_hardening.py --harden
```

### 2. Database Setup

```bash
# Run database migrations
python scripts/migrate.py --action migrate

# Create admin user
python scripts/create_admin.py --username admin --email admin@company.com

# Verify database health
python scripts/migrate.py --action status
```

### 3. Docker Deployment

#### Using Docker Compose (Simple Setup)

```bash
# Generate SSL certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/tls.key -out ssl/tls.crt \
  -subj "/C=US/ST=CA/L=SF/O=Company/CN=agentic-iam.local"

# Set environment variables
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(64))")
export ENCRYPTION_KEY=$(python -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(64))")

# Deploy with Docker Compose
docker-compose -f docker-compose.yml up -d

# Verify deployment
curl -k https://localhost/health
```

#### Using Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml agentic-iam

# Check services
docker service ls
```

### 4. Kubernetes Deployment

#### Prerequisites Setup

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Create secrets (update with your values)
kubectl create secret generic agentic-iam-secrets \
  --from-literal=secret-key="your-production-secret-key" \
  --from-literal=encryption-key="your-32-char-encryption-key" \
  --from-literal=jwt-secret-key="your-jwt-secret-key" \
  --from-literal=credential-encryption-key="your-credential-key" \
  --from-literal=postgres-password="your-postgres-password" \
  -n agentic-iam

# Create TLS certificate secret
kubectl create secret tls agentic-iam-tls \
  --cert=ssl/tls.crt \
  --key=ssl/tls.key \
  -n agentic-iam
```

#### Deploy Core Components

```bash
# Apply configurations
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml

# Deploy PostgreSQL
kubectl apply -f k8s/postgres.yaml

# Deploy Redis
kubectl apply -f k8s/redis.yaml

# Wait for databases
kubectl wait --for=condition=ready pod -l app=postgres -n agentic-iam --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis -n agentic-iam --timeout=300s

# Deploy main application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Wait for deployment
kubectl rollout status deployment/agentic-iam-deployment -n agentic-iam
```

#### Verify Deployment

```bash
# Check pod status
kubectl get pods -n agentic-iam

# Check services
kubectl get svc -n agentic-iam

# Check ingress
kubectl get ingress -n agentic-iam

# Test health endpoint
kubectl port-forward svc/agentic-iam-service 8080:8000 -n agentic-iam &
curl http://localhost:8080/health
```

## 🔒 Production Security Checklist

### Critical Security Configuration

- [ ] **Change all default secrets** - Never use default keys in production
- [ ] **Enable TLS/HTTPS** - All communication must be encrypted
- [ ] **Configure proper CORS** - Restrict origins to known domains
- [ ] **Enable audit logging** - All activities must be logged
- [ ] **Set up secrets management** - Use Kubernetes secrets or external systems
- [ ] **Configure rate limiting** - Prevent abuse and DoS attacks
- [ ] **Enable MFA** - Multi-factor authentication for admin access
- [ ] **Set proper file permissions** - Restrict access to sensitive files
- [ ] **Enable security headers** - HSTS, CSRF protection, etc.
- [ ] **Configure network policies** - Restrict pod-to-pod communication

### Security Validation

```bash
# Run security compliance check
python scripts/security_hardening.py --compliance-check

# Scan for vulnerabilities
docker run --rm -v $(pwd):/workspace \
  aquasec/trivy fs /workspace

# Check for secrets in code
docker run --rm -v $(pwd):/workspace \
  trufflesecurity/trufflehog filesystem /workspace
```

## 📊 Monitoring and Observability

### Prometheus Metrics

The platform exposes comprehensive metrics on `/metrics`:

- **Request metrics**: HTTP request rates, latencies, error rates
- **Authentication metrics**: Auth attempts, success rates, method distribution
- **Session metrics**: Active sessions, session duration
- **Trust metrics**: Trust score calculations, anomaly detection
- **System metrics**: CPU, memory, disk usage
- **Database metrics**: Connection counts, query performance

### Grafana Dashboards

Pre-built dashboards are available in `monitoring/grafana/dashboards/`:

- **System Overview**: High-level platform health
- **Authentication Analytics**: Auth patterns and security events
- **Trust Score Analytics**: Trust scoring trends and anomalies
- **Performance Monitoring**: Response times and throughput
- **Security Dashboard**: Security events and threats

### Log Aggregation

Configure centralized logging:

```yaml
# Example Fluent Bit configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         1
        Log_Level     info
        Daemon        off
        Parsers_File  parsers.conf

    [INPUT]
        Name              tail
        Path              /var/log/containers/*agentic-iam*.log
        Parser            docker
        Tag               agentic-iam.*
        Refresh_Interval  5

    [OUTPUT]
        Name  es
        Match *
        Host  elasticsearch.monitoring.svc.cluster.local
        Port  9200
        Index agentic-iam-logs
```

## 🔄 CI/CD Integration

### GitHub Actions

The platform includes a comprehensive CI/CD pipeline (`.github/workflows/ci-cd.yml`):

- **Testing**: Unit tests, integration tests, security scans
- **Building**: Docker image building and pushing
- **Deployment**: Automated deployment to staging and production
- **Monitoring**: Performance testing and health checks

### Deployment Environments

1. **Development**: Local development with hot reloading
2. **Testing**: Automated testing environment
3. **Staging**: Pre-production environment for validation
4. **Production**: Live production environment

### Release Process

```bash
# Create and push release tag
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0

# GitHub Actions will automatically:
# 1. Run full test suite
# 2. Build and scan Docker images
# 3. Deploy to staging
# 4. Run smoke tests
# 5. Deploy to production (manual approval)
# 6. Create GitHub release
```

## 📈 Performance Optimization

### Database Optimization

```sql
-- Add database indexes for performance
CREATE INDEX CONCURRENTLY idx_audit_events_timestamp_agent ON audit_events(timestamp, agent_id);
CREATE INDEX CONCURRENTLY idx_sessions_expires_agent ON sessions(expires_at, agent_id);
CREATE INDEX CONCURRENTLY idx_trust_scores_agent_calculated ON trust_scores(agent_id, calculated_at);

-- Optimize PostgreSQL settings
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
SELECT pg_reload_conf();
```

### Redis Configuration

```redis
# Redis optimization for session storage
maxmemory 512mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec
```

### Application Performance

```python
# Enable performance optimizations in settings
AGENTIC_IAM_ENABLE_CACHING=true
AGENTIC_IAM_CACHE_TTL=300
AGENTIC_IAM_POOL_SIZE=20
AGENTIC_IAM_MAX_OVERFLOW=30
AGENTIC_IAM_POOL_RECYCLE=3600
```

## 🔧 Scaling and High Availability

### Horizontal Scaling

```yaml
# Kubernetes HPA configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: agentic-iam-hpa
  namespace: agentic-iam
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: agentic-iam-deployment
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Database High Availability

```yaml
# PostgreSQL cluster with Patroni
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgres-cluster
  namespace: agentic-iam
spec:
  instances: 3
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
      effective_cache_size: "1GB"
  storage:
    size: 100Gi
    storageClass: fast-ssd
```

### Load Balancing

```nginx
upstream agentic_iam_backend {
    least_conn;
    server agentic-iam-1:8000 max_fails=3 fail_timeout=30s;
    server agentic-iam-2:8000 max_fails=3 fail_timeout=30s;
    server agentic-iam-3:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name api.agentic-iam.com;
    
    location / {
        proxy_pass http://agentic_iam_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check
        proxy_next_upstream error timeout http_500 http_502 http_503;
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
}
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Database Connection Issues

```bash
# Check database connectivity
kubectl exec -it deployment/agentic-iam-deployment -n agentic-iam -- \
  python -c "
from config.settings import Settings
import asyncpg
import asyncio

async def test_db():
    settings = Settings()
    conn = await asyncpg.connect(settings.database_url)
    result = await conn.fetchval('SELECT 1')
    print(f'Database test result: {result}')
    await conn.close()

asyncio.run(test_db())
"
```

#### 2. Redis Connection Issues

```bash
# Test Redis connectivity
kubectl exec -it deployment/agentic-iam-deployment -n agentic-iam -- \
  python -c "
import redis
from config.settings import Settings

settings = Settings()
r = redis.from_url(settings.redis_url)
r.ping()
print('Redis connection successful')
"
```

#### 3. SSL/TLS Issues

```bash
# Check certificate validity
openssl x509 -in ssl/tls.crt -text -noout

# Test HTTPS endpoint
curl -k https://localhost/health -v
```

#### 4. Performance Issues

```bash
# Check resource usage
kubectl top pods -n agentic-iam

# Check logs for errors
kubectl logs -f deployment/agentic-iam-deployment -n agentic-iam

# Run performance benchmark
python scripts/performance_metrics.py --benchmark
```

### Log Analysis

```bash
# Search for errors in logs
kubectl logs deployment/agentic-iam-deployment -n agentic-iam | grep ERROR

# Check audit logs
kubectl exec -it deployment/agentic-iam-deployment -n agentic-iam -- \
  tail -f /app/logs/audit.log

# Monitor real-time metrics
kubectl port-forward svc/prometheus 9090:9090 -n monitoring &
open http://localhost:9090
```

## 🔄 Backup and Recovery

### Database Backup

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
DATABASE_URL="postgresql://user:pass@host:5432/agentic_iam"

# Create backup
pg_dump $DATABASE_URL | gzip > $BACKUP_DIR/agentic_iam_$DATE.sql.gz

# Upload to cloud storage (example with AWS S3)
aws s3 cp $BACKUP_DIR/agentic_iam_$DATE.sql.gz s3://backups/agentic-iam/

# Cleanup old backups (keep last 30 days)
find $BACKUP_DIR -name "agentic_iam_*.sql.gz" -mtime +30 -delete
```

### Disaster Recovery

```bash
# Complete system restore procedure
# 1. Restore database
gunzip -c backup_file.sql.gz | psql $DATABASE_URL

# 2. Restore secrets
kubectl apply -f backup/secrets.yaml

# 3. Restore configurations
kubectl apply -f backup/configmaps.yaml

# 4. Redeploy application
kubectl apply -f k8s/deployment.yaml

# 5. Verify system health
python scripts/health_check.py --comprehensive
```

## 📞 Support and Maintenance

### Health Monitoring

Set up automated health checks:

```yaml
# Kubernetes liveness and readiness probes
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 30
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 3
```

### Alerting Rules

```yaml
# Prometheus alerting rules
groups:
- name: agentic-iam-alerts
  rules:
  - alert: HighErrorRate
    expr: rate(agentic_iam_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    annotations:
      summary: "High error rate detected"
      
  - alert: DatabaseConnectionFailed
    expr: agentic_iam_db_connections == 0
    for: 1m
    annotations:
      summary: "Database connection failed"
      
  - alert: TrustScoreAnomalies
    expr: increase(agentic_iam_anomalies_detected_total[1h]) > 10
    for: 5m
    annotations:
      summary: "High number of trust score anomalies"
```

### Maintenance Windows

```bash
# Graceful maintenance procedure
# 1. Scale down to single replica
kubectl scale deployment agentic-iam-deployment --replicas=1 -n agentic-iam

# 2. Enable maintenance mode
kubectl patch configmap agentic-iam-config -n agentic-iam \
  --patch '{"data":{"AGENTIC_IAM_MAINTENANCE_MODE":"true"}}'

# 3. Perform maintenance tasks
python scripts/migrate.py --action backup
python scripts/maintenance.py --cleanup-sessions --vacuum-db

# 4. Disable maintenance mode and scale up
kubectl patch configmap agentic-iam-config -n agentic-iam \
  --patch '{"data":{"AGENTIC_IAM_MAINTENANCE_MODE":"false"}}'
kubectl scale deployment agentic-iam-deployment --replicas=3 -n agentic-iam
```

---

## 📋 Production Checklist

Before going live, ensure all items are completed:

### Pre-Deployment
- [ ] All secrets changed from defaults
- [ ] SSL/TLS certificates configured
- [ ] Database properly configured and backed up
- [ ] Security hardening applied
- [ ] Monitoring and alerting configured
- [ ] Load testing completed
- [ ] Security scan passed
- [ ] Documentation updated

### Post-Deployment
- [ ] Health checks passing
- [ ] Metrics collection working
- [ ] Backup procedures tested
- [ ] Alerting rules validated
- [ ] Performance baselines established
- [ ] Security monitoring active
- [ ] Team trained on operations procedures

### Ongoing Operations
- [ ] Regular security updates
- [ ] Performance monitoring
- [ ] Backup verification
- [ ] Capacity planning
- [ ] Incident response procedures
- [ ] Regular security audits
- [ ] Documentation maintenance

This production deployment guide ensures your Agentic-IAM platform is deployed with enterprise-grade security, monitoring, and operational excellence.