"""
Production Performance Metrics and Monitoring

Comprehensive performance monitoring, metrics collection, and alerting
for the Agentic-IAM platform.
"""
import asyncio
import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from collections import defaultdict, deque
import logging

from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server
import redis
from sqlalchemy import create_engine, text


@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: Dict[str, int]
    database_connections: int
    redis_connections: int
    active_sessions: int
    request_rate: float
    response_time_avg: float
    error_rate: float


class MetricsCollector:
    """Centralized metrics collection and monitoring"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger("metrics")
        
        # Prometheus metrics
        self.setup_prometheus_metrics()
        
        # Performance tracking
        self.response_times = deque(maxlen=1000)
        self.request_counts = defaultdict(int)
        self.error_counts = defaultdict(int)
        self.start_time = time.time()
        
        # System monitoring
        self.system_metrics = []
        self.monitoring_active = False
        
        # Database and Redis connections
        self.db_engine = None
        self.redis_client = None
        
        # Initialize connections
        self.initialize_connections()
    
    def setup_prometheus_metrics(self):
        """Setup Prometheus metrics"""
        
        # Request metrics
        self.request_counter = Counter(
            'agentic_iam_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status']
        )
        
        self.request_duration = Histogram(
            'agentic_iam_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint']
        )
        
        # Authentication metrics
        self.auth_attempts = Counter(
            'agentic_iam_auth_attempts_total',
            'Total authentication attempts',
            ['method', 'result']
        )
        
        self.auth_duration = Histogram(
            'agentic_iam_auth_duration_seconds',
            'Authentication duration in seconds',
            ['method']
        )
        
        # Session metrics
        self.active_sessions = Gauge(
            'agentic_iam_active_sessions',
            'Number of active sessions'
        )
        
        self.session_duration = Histogram(
            'agentic_iam_session_duration_seconds',
            'Session duration in seconds'
        )
        
        # Agent metrics
        self.total_agents = Gauge(
            'agentic_iam_agents_total',
            'Total number of registered agents'
        )
        
        self.active_agents = Gauge(
            'agentic_iam_agents_active',
            'Number of active agents'
        )
        
        # Trust scoring metrics
        self.trust_score_calculations = Counter(
            'agentic_iam_trust_calculations_total',
            'Total trust score calculations'
        )
        
        self.avg_trust_score = Gauge(
            'agentic_iam_avg_trust_score',
            'Average trust score across all agents'
        )
        
        # Database metrics
        self.db_connections = Gauge(
            'agentic_iam_db_connections',
            'Number of database connections'
        )
        
        self.db_query_duration = Histogram(
            'agentic_iam_db_query_duration_seconds',
            'Database query duration in seconds',
            ['query_type']
        )
        
        # Redis metrics
        self.redis_connections = Gauge(
            'agentic_iam_redis_connections',
            'Number of Redis connections'
        )
        
        self.redis_operations = Counter(
            'agentic_iam_redis_operations_total',
            'Total Redis operations',
            ['operation']
        )
        
        # System metrics
        self.cpu_usage = Gauge(
            'agentic_iam_cpu_usage_percent',
            'CPU usage percentage'
        )
        
        self.memory_usage = Gauge(
            'agentic_iam_memory_usage_bytes',
            'Memory usage in bytes'
        )
        
        self.disk_usage = Gauge(
            'agentic_iam_disk_usage_percent',
            'Disk usage percentage'
        )
        
        # Error metrics
        self.error_counter = Counter(
            'agentic_iam_errors_total',
            'Total number of errors',
            ['error_type', 'component']
        )
        
        # Audit metrics
        self.audit_events = Counter(
            'agentic_iam_audit_events_total',
            'Total audit events',
            ['event_type', 'severity']
        )
        
        # Application info
        self.app_info = Info(
            'agentic_iam_app_info',
            'Application information'
        )
        
        # Set application info
        self.app_info.info({
            'version': '1.0.0',
            'environment': self.settings.environment,
            'python_version': '3.11'
        })
    
    def initialize_connections(self):
        """Initialize database and Redis connections for monitoring"""
        try:
            # Database connection
            if self.settings.database_url:
                self.db_engine = create_engine(
                    self.settings.database_url,
                    pool_pre_ping=True,
                    pool_recycle=3600
                )
            
            # Redis connection
            if self.settings.redis_url:
                self.redis_client = redis.from_url(
                    self.settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring connections: {e}")
    
    def start_monitoring(self):
        """Start background monitoring"""
        self.monitoring_active = True
        
        # Start Prometheus metrics server
        start_http_server(9090)
        self.logger.info("Prometheus metrics server started on port 9090")
        
        # Start system monitoring thread
        monitoring_thread = threading.Thread(target=self._monitor_system, daemon=True)
        monitoring_thread.start()
        
        # Start database monitoring thread
        db_monitoring_thread = threading.Thread(target=self._monitor_database, daemon=True)
        db_monitoring_thread.start()
        
        # Start Redis monitoring thread
        redis_monitoring_thread = threading.Thread(target=self._monitor_redis, daemon=True)
        redis_monitoring_thread.start()
        
        self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring_active = False
        self.logger.info("Performance monitoring stopped")
    
    def _monitor_system(self):
        """Monitor system resources"""
        while self.monitoring_active:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                self.cpu_usage.set(cpu_percent)
                
                # Memory usage
                memory = psutil.virtual_memory()
                self.memory_usage.set(memory.used)
                
                # Disk usage
                disk = psutil.disk_usage('/')
                disk_percent = (disk.used / disk.total) * 100
                self.disk_usage.set(disk_percent)
                
                # Store for historical tracking
                metrics = PerformanceMetrics(
                    timestamp=datetime.utcnow(),
                    cpu_usage=cpu_percent,
                    memory_usage=memory.used,
                    disk_usage=disk_percent,
                    network_io=dict(psutil.net_io_counters()._asdict()),
                    database_connections=self._get_db_connections(),
                    redis_connections=self._get_redis_connections(),
                    active_sessions=0,  # Would be updated by session manager
                    request_rate=self._calculate_request_rate(),
                    response_time_avg=self._calculate_avg_response_time(),
                    error_rate=self._calculate_error_rate()
                )
                
                self.system_metrics.append(metrics)
                
                # Keep only last 1000 entries
                if len(self.system_metrics) > 1000:
                    self.system_metrics.pop(0)
                
                time.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                self.logger.error(f"System monitoring error: {e}")
                time.sleep(30)
    
    def _monitor_database(self):
        """Monitor database performance"""
        while self.monitoring_active:
            try:
                if self.db_engine:
                    # Database connections
                    with self.db_engine.connect() as conn:
                        # Get connection count
                        result = conn.execute(text(
                            "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'"
                        ))
                        active_connections = result.scalar()
                        self.db_connections.set(active_connections)
                        
                        # Query performance test
                        start_time = time.time()
                        conn.execute(text("SELECT 1"))
                        query_time = time.time() - start_time
                        self.db_query_duration.labels(query_type='health_check').observe(query_time)
                
                time.sleep(60)  # Monitor every minute
                
            except Exception as e:
                self.logger.error(f"Database monitoring error: {e}")
                time.sleep(60)
    
    def _monitor_redis(self):
        """Monitor Redis performance"""
        while self.monitoring_active:
            try:
                if self.redis_client:
                    # Redis info
                    info = self.redis_client.info()
                    self.redis_connections.set(info.get('connected_clients', 0))
                    
                    # Redis performance test
                    start_time = time.time()
                    self.redis_client.ping()
                    ping_time = time.time() - start_time
                    
                    # Track as operation
                    self.redis_operations.labels(operation='ping').inc()
                
                time.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Redis monitoring error: {e}")
                time.sleep(30)
    
    def _get_db_connections(self) -> int:
        """Get current database connection count"""
        try:
            if self.db_engine:
                return self.db_engine.pool.size()
            return 0
        except:
            return 0
    
    def _get_redis_connections(self) -> int:
        """Get current Redis connection count"""
        try:
            if self.redis_client:
                info = self.redis_client.info()
                return info.get('connected_clients', 0)
            return 0
        except:
            return 0
    
    def _calculate_request_rate(self) -> float:
        """Calculate requests per second"""
        try:
            current_time = time.time()
            time_window = 60  # 1 minute window
            
            recent_requests = sum(
                count for timestamp, count in self.request_counts.items()
                if current_time - timestamp < time_window
            )
            
            return recent_requests / time_window
        except:
            return 0.0
    
    def _calculate_avg_response_time(self) -> float:
        """Calculate average response time"""
        try:
            if self.response_times:
                return sum(self.response_times) / len(self.response_times)
            return 0.0
        except:
            return 0.0
    
    def _calculate_error_rate(self) -> float:
        """Calculate error rate percentage"""
        try:
            current_time = time.time()
            time_window = 300  # 5 minute window
            
            total_requests = sum(
                count for timestamp, count in self.request_counts.items()
                if current_time - timestamp < time_window
            )
            
            total_errors = sum(
                count for timestamp, count in self.error_counts.items()
                if current_time - timestamp < time_window
            )
            
            if total_requests > 0:
                return (total_errors / total_requests) * 100
            return 0.0
        except:
            return 0.0
    
    # Metric recording methods
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request metrics"""
        # Prometheus metrics
        self.request_counter.labels(method=method, endpoint=endpoint, status=str(status_code)).inc()
        self.request_duration.labels(method=method, endpoint=endpoint).observe(duration)
        
        # Internal tracking
        current_time = time.time()
        self.request_counts[current_time] += 1
        self.response_times.append(duration)
        
        # Track errors
        if status_code >= 400:
            self.error_counts[current_time] += 1
    
    def record_authentication(self, method: str, result: str, duration: float):
        """Record authentication metrics"""
        self.auth_attempts.labels(method=method, result=result).inc()
        self.auth_duration.labels(method=method).observe(duration)
    
    def record_session_created(self):
        """Record session creation"""
        # This would be called by the session manager
        pass
    
    def record_session_terminated(self, duration: float):
        """Record session termination"""
        self.session_duration.observe(duration)
    
    def update_active_sessions(self, count: int):
        """Update active sessions count"""
        self.active_sessions.set(count)
    
    def update_agent_counts(self, total: int, active: int):
        """Update agent counts"""
        self.total_agents.set(total)
        self.active_agents.set(active)
    
    def record_trust_calculation(self, score: float):
        """Record trust score calculation"""
        self.trust_score_calculations.inc()
        # Update average (simplified - in production, use proper averaging)
        current_avg = self.avg_trust_score._value._value
        if current_avg == 0:
            self.avg_trust_score.set(score)
        else:
            new_avg = (current_avg + score) / 2
            self.avg_trust_score.set(new_avg)
    
    def record_error(self, error_type: str, component: str):
        """Record error occurrence"""
        self.error_counter.labels(error_type=error_type, component=component).inc()
    
    def record_audit_event(self, event_type: str, severity: str):
        """Record audit event"""
        self.audit_events.labels(event_type=event_type, severity=severity).inc()
    
    def record_db_query(self, query_type: str, duration: float):
        """Record database query performance"""
        self.db_query_duration.labels(query_type=query_type).observe(duration)
    
    def record_redis_operation(self, operation: str):
        """Record Redis operation"""
        self.redis_operations.labels(operation=operation).inc()
    
    # Health check methods
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        try:
            current_metrics = self.system_metrics[-1] if self.system_metrics else None
            
            health_status = {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "uptime": time.time() - self.start_time,
                "system": {
                    "cpu_usage": current_metrics.cpu_usage if current_metrics else 0,
                    "memory_usage": current_metrics.memory_usage if current_metrics else 0,
                    "disk_usage": current_metrics.disk_usage if current_metrics else 0,
                },
                "database": {
                    "connected": self.db_engine is not None,
                    "connections": self._get_db_connections()
                },
                "redis": {
                    "connected": self.redis_client is not None,
                    "connections": self._get_redis_connections()
                },
                "metrics": {
                    "requests_per_second": self._calculate_request_rate(),
                    "avg_response_time": self._calculate_avg_response_time(),
                    "error_rate": self._calculate_error_rate()
                }
            }
            
            # Determine overall health
            if current_metrics:
                if (current_metrics.cpu_usage > 90 or 
                    current_metrics.disk_usage > 95 or
                    self._calculate_error_rate() > 10):
                    health_status["status"] = "unhealthy"
                elif (current_metrics.cpu_usage > 70 or 
                      current_metrics.disk_usage > 80 or
                      self._calculate_error_rate() > 5):
                    health_status["status"] = "degraded"
            
            return health_status
            
        except Exception as e:
            self.logger.error(f"Health check error: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary for the last hour"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            recent_metrics = [
                m for m in self.system_metrics 
                if m.timestamp > cutoff_time
            ]
            
            if not recent_metrics:
                return {"message": "No recent metrics available"}
            
            # Calculate averages
            avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
            avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
            avg_response_time = sum(m.response_time_avg for m in recent_metrics) / len(recent_metrics)
            
            # Find peaks
            max_cpu = max(m.cpu_usage for m in recent_metrics)
            max_memory = max(m.memory_usage for m in recent_metrics)
            max_response_time = max(m.response_time_avg for m in recent_metrics)
            
            return {
                "time_period": "last_hour",
                "averages": {
                    "cpu_usage": round(avg_cpu, 2),
                    "memory_usage": avg_memory,
                    "response_time": round(avg_response_time, 3)
                },
                "peaks": {
                    "cpu_usage": round(max_cpu, 2),
                    "memory_usage": max_memory,
                    "response_time": round(max_response_time, 3)
                },
                "data_points": len(recent_metrics)
            }
            
        except Exception as e:
            self.logger.error(f"Performance summary error: {e}")
            return {"error": str(e)}


# Performance testing utilities
class PerformanceTester:
    """Performance testing and benchmarking utilities"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.logger = logging.getLogger("performance_test")
    
    async def benchmark_authentication(self, iam_instance, iterations: int = 100) -> Dict[str, float]:
        """Benchmark authentication performance"""
        self.logger.info(f"Starting authentication benchmark with {iterations} iterations")
        
        durations = []
        successful = 0
        
        for i in range(iterations):
            start_time = time.time()
            try:
                # Mock authentication test
                result = await iam_instance.authenticate(
                    agent_id=f"agent:benchmark-{i}",
                    credentials={"method": "test"},
                    method="jwt"
                )
                if result and result.success:
                    successful += 1
            except Exception as e:
                self.logger.error(f"Auth benchmark error: {e}")
            
            duration = time.time() - start_time
            durations.append(duration)
        
        return {
            "iterations": iterations,
            "successful": successful,
            "success_rate": successful / iterations,
            "avg_duration": sum(durations) / len(durations),
            "min_duration": min(durations),
            "max_duration": max(durations),
            "total_time": sum(durations)
        }
    
    async def benchmark_trust_scoring(self, iam_instance, iterations: int = 50) -> Dict[str, float]:
        """Benchmark trust scoring performance"""
        self.logger.info(f"Starting trust scoring benchmark with {iterations} iterations")
        
        durations = []
        successful = 0
        
        for i in range(iterations):
            start_time = time.time()
            try:
                # Mock trust score calculation
                score = await iam_instance.calculate_trust_score(f"agent:benchmark-{i}")
                if score:
                    successful += 1
            except Exception as e:
                self.logger.error(f"Trust scoring benchmark error: {e}")
            
            duration = time.time() - start_time
            durations.append(duration)
        
        return {
            "iterations": iterations,
            "successful": successful,
            "success_rate": successful / iterations,
            "avg_duration": sum(durations) / len(durations),
            "min_duration": min(durations),
            "max_duration": max(durations),
            "total_time": sum(durations)
        }


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None

def get_metrics_collector() -> Optional[MetricsCollector]:
    """Get global metrics collector instance"""
    return _metrics_collector

def initialize_metrics(settings) -> MetricsCollector:
    """Initialize global metrics collector"""
    global _metrics_collector
    _metrics_collector = MetricsCollector(settings)
    _metrics_collector.start_monitoring()
    return _metrics_collector

def shutdown_metrics():
    """Shutdown global metrics collector"""
    global _metrics_collector
    if _metrics_collector:
        _metrics_collector.stop_monitoring()
        _metrics_collector = None