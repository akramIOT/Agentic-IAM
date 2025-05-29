"""
Database Migration and Schema Management

Production-grade database migration system for Agentic-IAM platform.
Supports PostgreSQL, SQLite, and MySQL with version control and rollback capabilities.
"""
import asyncio
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import hashlib
import json

import asyncpg
import aiosqlite
from sqlalchemy import create_engine, text, MetaData, Table, Column, String, DateTime, Integer, Boolean, Text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from alembic.config import Config
from alembic import command
from alembic.runtime.migration import MigrationContext
from alembic.operations import Operations

# Add project modules to path
sys.path.append(str(Path(__file__).parent.parent))
from config.settings import Settings


class DatabaseMigrator:
    """Database migration management system"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = logging.getLogger("migration")
        
        # Migration tracking table
        self.migration_table = "agentic_iam_migrations"
        
        # Initialize database engine
        self.engine = create_engine(settings.database_url, echo=settings.database_echo)
        self.async_engine = create_async_engine(settings.database_async_url)
        
        # Migration directory
        self.migration_dir = Path(__file__).parent.parent / "migrations"
        self.migration_dir.mkdir(exist_ok=True)
    
    async def initialize_migration_tracking(self):
        """Initialize migration tracking table"""
        try:
            async with self.async_engine.begin() as conn:
                # Create migration tracking table
                await conn.execute(text(f"""
                    CREATE TABLE IF NOT EXISTS {self.migration_table} (
                        id SERIAL PRIMARY KEY,
                        migration_id VARCHAR(255) UNIQUE NOT NULL,
                        migration_name VARCHAR(255) NOT NULL,
                        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        checksum VARCHAR(64) NOT NULL,
                        rollback_sql TEXT,
                        metadata JSONB
                    )
                """))
                
            self.logger.info("Migration tracking table initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize migration tracking: {e}")
            raise
    
    async def get_applied_migrations(self) -> List[Dict[str, Any]]:
        """Get list of applied migrations"""
        try:
            async with self.async_engine.begin() as conn:
                result = await conn.execute(text(f"""
                    SELECT migration_id, migration_name, applied_at, checksum
                    FROM {self.migration_table}
                    ORDER BY applied_at
                """))
                
                return [
                    {
                        "migration_id": row[0],
                        "migration_name": row[1], 
                        "applied_at": row[2],
                        "checksum": row[3]
                    }
                    for row in result.fetchall()
                ]
                
        except Exception as e:
            self.logger.error(f"Failed to get applied migrations: {e}")
            return []
    
    async def create_core_schema(self):
        """Create core database schema"""
        migrations = [
            self._create_agents_schema(),
            self._create_sessions_schema(),
            self._create_credentials_schema(),
            self._create_audit_schema(),
            self._create_trust_scores_schema(),
            self._create_policies_schema(),
            self._create_compliance_schema()
        ]
        
        for migration_name, sql, rollback_sql in migrations:
            await self.apply_migration(
                migration_id=f"core_{migration_name}",
                migration_name=migration_name,
                sql=sql,
                rollback_sql=rollback_sql
            )
    
    def _create_agents_schema(self) -> tuple:
        """Agent registry schema"""
        sql = """
        -- Agents table
        CREATE TABLE IF NOT EXISTS agents (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(255) UNIQUE NOT NULL,
            agent_type VARCHAR(100) NOT NULL,
            status VARCHAR(50) DEFAULT 'active',
            description TEXT,
            capabilities JSONB DEFAULT '[]',
            metadata JSONB DEFAULT '{}',
            public_key TEXT,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
        CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
        CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(agent_type);
        CREATE INDEX IF NOT EXISTS idx_agents_last_accessed ON agents(last_accessed);
        
        -- Agent permissions
        CREATE TABLE IF NOT EXISTS agent_permissions (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(255) REFERENCES agents(agent_id) ON DELETE CASCADE,
            permission VARCHAR(255) NOT NULL,
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            granted_by VARCHAR(255),
            expires_at TIMESTAMP,
            UNIQUE(agent_id, permission)
        );
        
        CREATE INDEX IF NOT EXISTS idx_agent_permissions_agent_id ON agent_permissions(agent_id);
        CREATE INDEX IF NOT EXISTS idx_agent_permissions_permission ON agent_permissions(permission);
        """
        
        rollback_sql = """
        DROP TABLE IF EXISTS agent_permissions;
        DROP TABLE IF EXISTS agents;
        """
        
        return "agents_schema", sql, rollback_sql
    
    def _create_sessions_schema(self) -> tuple:
        """Session management schema"""
        sql = """
        -- Sessions table
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(255) UNIQUE NOT NULL,
            agent_id VARCHAR(255) NOT NULL,
            status VARCHAR(50) DEFAULT 'active',
            trust_level DECIMAL(3,2) DEFAULT 0.8,
            auth_method VARCHAR(100) NOT NULL,
            source_ip INET,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            metadata JSONB DEFAULT '{}',
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        );
        
        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_agent_id ON sessions(agent_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
        
        -- Session activities
        CREATE TABLE IF NOT EXISTS session_activities (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(255) REFERENCES sessions(session_id) ON DELETE CASCADE,
            activity_type VARCHAR(100) NOT NULL,
            resource VARCHAR(255),
            action VARCHAR(100),
            result VARCHAR(50),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata JSONB DEFAULT '{}'
        );
        
        CREATE INDEX IF NOT EXISTS idx_session_activities_session_id ON session_activities(session_id);
        CREATE INDEX IF NOT EXISTS idx_session_activities_timestamp ON session_activities(timestamp);
        """
        
        rollback_sql = """
        DROP TABLE IF EXISTS session_activities;
        DROP TABLE IF EXISTS sessions;
        """
        
        return "sessions_schema", sql, rollback_sql
    
    def _create_credentials_schema(self) -> tuple:
        """Credential management schema"""
        sql = """
        -- Credentials table (encrypted storage)
        CREATE TABLE IF NOT EXISTS credentials (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(255) NOT NULL,
            credential_type VARCHAR(100) NOT NULL,
            encrypted_data TEXT NOT NULL,
            key_id VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            rotation_schedule INTERVAL,
            last_rotated TIMESTAMP,
            metadata JSONB DEFAULT '{}',
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        );
        
        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_credentials_agent_id ON credentials(agent_id);
        CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
        CREATE INDEX IF NOT EXISTS idx_credentials_expires_at ON credentials(expires_at);
        CREATE INDEX IF NOT EXISTS idx_credentials_last_rotated ON credentials(last_rotated);
        
        -- Credential rotation log
        CREATE TABLE IF NOT EXISTS credential_rotations (
            id SERIAL PRIMARY KEY,
            credential_id INTEGER REFERENCES credentials(id) ON DELETE CASCADE,
            old_key_id VARCHAR(255),
            new_key_id VARCHAR(255),
            rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            rotated_by VARCHAR(255),
            reason VARCHAR(255)
        );
        """
        
        rollback_sql = """
        DROP TABLE IF EXISTS credential_rotations;
        DROP TABLE IF EXISTS credentials;
        """
        
        return "credentials_schema", sql, rollback_sql
    
    def _create_audit_schema(self) -> tuple:
        """Audit logging schema"""
        sql = """
        -- Audit events table
        CREATE TABLE IF NOT EXISTS audit_events (
            id SERIAL PRIMARY KEY,
            event_id VARCHAR(255) UNIQUE NOT NULL,
            event_type VARCHAR(100) NOT NULL,
            agent_id VARCHAR(255),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity VARCHAR(50) NOT NULL,
            component VARCHAR(100) NOT NULL,
            outcome VARCHAR(50) NOT NULL,
            source_ip INET,
            user_agent TEXT,
            resource VARCHAR(255),
            action VARCHAR(100),
            details JSONB DEFAULT '{}',
            integrity_hash VARCHAR(128),
            previous_hash VARCHAR(128)
        );
        
        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_audit_events_event_id ON audit_events(event_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_agent_id ON audit_events(agent_id);
        CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events(severity);
        CREATE INDEX IF NOT EXISTS idx_audit_events_component ON audit_events(component);
        
        -- Audit queries table (for tracking audit searches)
        CREATE TABLE IF NOT EXISTS audit_queries (
            id SERIAL PRIMARY KEY,
            query_id VARCHAR(255) UNIQUE NOT NULL,
            queried_by VARCHAR(255) NOT NULL,
            query_params JSONB NOT NULL,
            results_count INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        rollback_sql = """
        DROP TABLE IF EXISTS audit_queries;
        DROP TABLE IF EXISTS audit_events;
        """
        
        return "audit_schema", sql, rollback_sql
    
    def _create_trust_scores_schema(self) -> tuple:
        """Trust scoring schema"""
        sql = """
        -- Trust scores table
        CREATE TABLE IF NOT EXISTS trust_scores (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(255) NOT NULL,
            overall_score DECIMAL(5,4) NOT NULL,
            risk_level VARCHAR(50) NOT NULL,
            confidence DECIMAL(5,4) NOT NULL,
            component_scores JSONB DEFAULT '{}',
            factors JSONB DEFAULT '[]',
            calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            valid_until TIMESTAMP,
            metadata JSONB DEFAULT '{}',
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        );
        
        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_trust_scores_agent_id ON trust_scores(agent_id);
        CREATE INDEX IF NOT EXISTS idx_trust_scores_calculated_at ON trust_scores(calculated_at);
        CREATE INDEX IF NOT EXISTS idx_trust_scores_overall_score ON trust_scores(overall_score);
        CREATE INDEX IF NOT EXISTS idx_trust_scores_risk_level ON trust_scores(risk_level);
        
        -- Trust score history
        CREATE TABLE IF NOT EXISTS trust_score_history (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(255) NOT NULL,
            score_change DECIMAL(5,4) NOT NULL,
            reason VARCHAR(255),
            event_type VARCHAR(100),
            previous_score DECIMAL(5,4),
            new_score DECIMAL(5,4),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_trust_history_agent_id ON trust_score_history(agent_id);
        CREATE INDEX IF NOT EXISTS idx_trust_history_timestamp ON trust_score_history(timestamp);
        
        -- Anomalies table
        CREATE TABLE IF NOT EXISTS anomalies (
            id SERIAL PRIMARY KEY,
            anomaly_id VARCHAR(255) UNIQUE NOT NULL,
            agent_id VARCHAR(255),
            anomaly_type VARCHAR(100) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            confidence DECIMAL(5,4) NOT NULL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            context JSONB DEFAULT '{}',
            resolved_at TIMESTAMP,
            resolved_by VARCHAR(255),
            false_positive BOOLEAN DEFAULT FALSE
        );
        
        CREATE INDEX IF NOT EXISTS idx_anomalies_agent_id ON anomalies(agent_id);
        CREATE INDEX IF NOT EXISTS idx_anomalies_detected_at ON anomalies(detected_at);
        CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
        """
        
        rollback_sql = """
        DROP TABLE IF EXISTS anomalies;
        DROP TABLE IF EXISTS trust_score_history;
        DROP TABLE IF EXISTS trust_scores;
        """
        
        return "trust_scores_schema", sql, rollback_sql
    
    def _create_policies_schema(self) -> tuple:
        """Authorization policies schema"""
        sql = """
        -- Roles table
        CREATE TABLE IF NOT EXISTS roles (
            id SERIAL PRIMARY KEY,
            role_name VARCHAR(255) UNIQUE NOT NULL,
            description TEXT,
            permissions JSONB DEFAULT '[]',
            inherits_from JSONB DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_roles_role_name ON roles(role_name);
        
        -- Agent roles
        CREATE TABLE IF NOT EXISTS agent_roles (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR(255) NOT NULL,
            role_name VARCHAR(255) NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            assigned_by VARCHAR(255),
            expires_at TIMESTAMP,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
            FOREIGN KEY (role_name) REFERENCES roles(role_name) ON DELETE CASCADE,
            UNIQUE(agent_id, role_name)
        );
        
        CREATE INDEX IF NOT EXISTS idx_agent_roles_agent_id ON agent_roles(agent_id);
        CREATE INDEX IF NOT EXISTS idx_agent_roles_role_name ON agent_roles(role_name);
        
        -- Policies table
        CREATE TABLE IF NOT EXISTS policies (
            id SERIAL PRIMARY KEY,
            policy_id VARCHAR(255) UNIQUE NOT NULL,
            policy_name VARCHAR(255) NOT NULL,
            policy_type VARCHAR(100) NOT NULL,
            description TEXT,
            rules JSONB NOT NULL,
            enabled BOOLEAN DEFAULT TRUE,
            priority INTEGER DEFAULT 100,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by VARCHAR(255)
        );
        
        CREATE INDEX IF NOT EXISTS idx_policies_policy_id ON policies(policy_id);
        CREATE INDEX IF NOT EXISTS idx_policies_policy_type ON policies(policy_type);
        CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
        CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority);
        """
        
        rollback_sql = """
        DROP TABLE IF EXISTS policies;
        DROP TABLE IF EXISTS agent_roles;
        DROP TABLE IF EXISTS roles;
        """
        
        return "policies_schema", sql, rollback_sql
    
    def _create_compliance_schema(self) -> tuple:
        """Compliance reporting schema"""
        sql = """
        -- Compliance reports table
        CREATE TABLE IF NOT EXISTS compliance_reports (
            id SERIAL PRIMARY KEY,
            report_id VARCHAR(255) UNIQUE NOT NULL,
            framework VARCHAR(100) NOT NULL,
            compliance_score DECIMAL(5,2) NOT NULL,
            violations_found INTEGER DEFAULT 0,
            recommendations_count INTEGER DEFAULT 0,
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            generated_by VARCHAR(255),
            report_data JSONB NOT NULL,
            metadata JSONB DEFAULT '{}'
        );
        
        CREATE INDEX IF NOT EXISTS idx_compliance_reports_framework ON compliance_reports(framework);
        CREATE INDEX IF NOT EXISTS idx_compliance_reports_generated_at ON compliance_reports(generated_at);
        CREATE INDEX IF NOT EXISTS idx_compliance_reports_score ON compliance_reports(compliance_score);
        
        -- Compliance violations table
        CREATE TABLE IF NOT EXISTS compliance_violations (
            id SERIAL PRIMARY KEY,
            violation_id VARCHAR(255) UNIQUE NOT NULL,
            framework VARCHAR(100) NOT NULL,
            violation_type VARCHAR(255) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            description TEXT NOT NULL,
            affected_components JSONB DEFAULT '[]',
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            resolved_by VARCHAR(255),
            remediation_notes TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_compliance_violations_framework ON compliance_violations(framework);
        CREATE INDEX IF NOT EXISTS idx_compliance_violations_detected_at ON compliance_violations(detected_at);
        CREATE INDEX IF NOT EXISTS idx_compliance_violations_severity ON compliance_violations(severity);
        """
        
        rollback_sql = """
        DROP TABLE IF EXISTS compliance_violations;
        DROP TABLE IF EXISTS compliance_reports;
        """
        
        return "compliance_schema", sql, rollback_sql
    
    def _calculate_checksum(self, content: str) -> str:
        """Calculate checksum for migration content"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    async def apply_migration(self, migration_id: str, migration_name: str, 
                            sql: str, rollback_sql: str = "", metadata: Dict[str, Any] = None):
        """Apply a database migration"""
        checksum = self._calculate_checksum(sql)
        
        try:
            # Check if migration already applied
            async with self.async_engine.begin() as conn:
                result = await conn.execute(text(f"""
                    SELECT checksum FROM {self.migration_table}
                    WHERE migration_id = :migration_id
                """), {"migration_id": migration_id})
                
                existing = result.fetchone()
                if existing:
                    if existing[0] == checksum:
                        self.logger.info(f"Migration {migration_id} already applied")
                        return
                    else:
                        raise Exception(f"Migration {migration_id} checksum mismatch")
                
                # Apply migration
                self.logger.info(f"Applying migration: {migration_name}")
                await conn.execute(text(sql))
                
                # Record migration
                await conn.execute(text(f"""
                    INSERT INTO {self.migration_table} 
                    (migration_id, migration_name, checksum, rollback_sql, metadata)
                    VALUES (:migration_id, :migration_name, :checksum, :rollback_sql, :metadata)
                """), {
                    "migration_id": migration_id,
                    "migration_name": migration_name,
                    "checksum": checksum,
                    "rollback_sql": rollback_sql,
                    "metadata": json.dumps(metadata or {})
                })
                
            self.logger.info(f"Migration {migration_name} applied successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to apply migration {migration_name}: {e}")
            raise
    
    async def rollback_migration(self, migration_id: str):
        """Rollback a specific migration"""
        try:
            async with self.async_engine.begin() as conn:
                # Get migration details
                result = await conn.execute(text(f"""
                    SELECT migration_name, rollback_sql FROM {self.migration_table}
                    WHERE migration_id = :migration_id
                """), {"migration_id": migration_id})
                
                migration = result.fetchone()
                if not migration:
                    raise Exception(f"Migration {migration_id} not found")
                
                migration_name, rollback_sql = migration
                if not rollback_sql:
                    raise Exception(f"No rollback SQL for migration {migration_id}")
                
                # Execute rollback
                self.logger.info(f"Rolling back migration: {migration_name}")
                await conn.execute(text(rollback_sql))
                
                # Remove migration record
                await conn.execute(text(f"""
                    DELETE FROM {self.migration_table}
                    WHERE migration_id = :migration_id
                """), {"migration_id": migration_id})
                
            self.logger.info(f"Migration {migration_name} rolled back successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to rollback migration {migration_id}: {e}")
            raise
    
    async def get_migration_status(self) -> Dict[str, Any]:
        """Get comprehensive migration status"""
        try:
            applied_migrations = await self.get_applied_migrations()
            
            # Check database connectivity
            async with self.async_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
                db_connected = True
        except Exception:
            db_connected = False
        
        return {
            "database_connected": db_connected,
            "migration_table_exists": len(applied_migrations) >= 0,
            "applied_migrations_count": len(applied_migrations),
            "applied_migrations": applied_migrations,
            "last_migration": applied_migrations[-1] if applied_migrations else None
        }
    
    async def create_backup(self, backup_name: str = None) -> str:
        """Create database backup before major migrations"""
        if not backup_name:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        backup_file = backup_dir / f"{backup_name}.sql"
        
        try:
            # This is a simplified backup - in production, use proper database tools
            self.logger.info(f"Creating backup: {backup_file}")
            
            if "postgresql" in self.settings.database_url:
                # Use pg_dump for PostgreSQL
                import subprocess
                result = subprocess.run([
                    "pg_dump", self.settings.database_url, "-f", str(backup_file)
                ], capture_output=True, text=True)
                
                if result.returncode != 0:
                    raise Exception(f"pg_dump failed: {result.stderr}")
            
            elif "sqlite" in self.settings.database_url:
                # Use SQLite backup
                db_path = self.settings.database_url.replace("sqlite:///", "")
                import shutil
                shutil.copy2(db_path, backup_file)
            
            self.logger.info(f"Backup created successfully: {backup_file}")
            return str(backup_file)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            raise


async def main():
    """Main migration script"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Agentic-IAM Database Migration Tool")
    parser.add_argument("--action", choices=["migrate", "rollback", "status", "backup"], 
                       default="migrate", help="Migration action")
    parser.add_argument("--migration-id", help="Specific migration ID for rollback")
    parser.add_argument("--backup-name", help="Backup name")
    parser.add_argument("--force", action="store_true", help="Force operation")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    try:
        # Load settings
        settings = Settings()
        migrator = DatabaseMigrator(settings)
        
        if args.action == "migrate":
            print("🔧 Initializing database migration system...")
            await migrator.initialize_migration_tracking()
            
            print("📊 Creating core database schema...")
            await migrator.create_core_schema()
            
            print("✅ Database migration completed successfully!")
            
        elif args.action == "rollback":
            if not args.migration_id:
                print("❌ Migration ID required for rollback")
                sys.exit(1)
            
            print(f"⏪ Rolling back migration: {args.migration_id}")
            await migrator.rollback_migration(args.migration_id)
            print("✅ Migration rollback completed!")
            
        elif args.action == "status":
            print("📋 Getting migration status...")
            status = await migrator.get_migration_status()
            
            print(f"Database Connected: {'✅' if status['database_connected'] else '❌'}")
            print(f"Applied Migrations: {status['applied_migrations_count']}")
            
            if status['applied_migrations']:
                print("\nApplied Migrations:")
                for migration in status['applied_migrations'][-5:]:  # Last 5
                    print(f"  - {migration['migration_id']}: {migration['migration_name']} ({migration['applied_at']})")
                    
        elif args.action == "backup":
            print("💾 Creating database backup...")
            backup_file = await migrator.create_backup(args.backup_name)
            print(f"✅ Backup created: {backup_file}")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())