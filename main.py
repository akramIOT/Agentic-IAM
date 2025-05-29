"""
Agentic-IAM: Main Application Entry Point

Central orchestrator that manages the Agentic-IAM platform, integrating all
components including the FastAPI backend, Streamlit dashboard, and core
Agent Identity Framework modules.
"""
import asyncio
import signal
import sys
import logging
from pathlib import Path
from typing import Optional
import multiprocessing as mp
import uvicorn
import subprocess

# Add core modules to path
sys.path.append(str(Path(__file__).parent / "core"))
sys.path.append(str(Path(__file__).parent.parent))

from core.agentic_iam import AgenticIAM
from config.settings import Settings
from utils.logger import setup_logging


class AgenticIAMPlatform:
    """Main platform orchestrator"""
    
    def __init__(self):
        self.settings = Settings()
        self.logger = setup_logging(
            log_level=self.settings.log_level,
            log_file=self.settings.log_file,
            enable_console=True
        )
        self.iam: Optional[AgenticIAM] = None
        self.api_process: Optional[mp.Process] = None
        self.dashboard_process: Optional[mp.Process] = None
        self.running = False
        
    async def initialize(self):
        """Initialize the platform"""
        self.logger.info("Initializing Agentic-IAM Platform...")
        
        # Initialize core IAM system
        self.iam = AgenticIAM(self.settings)
        await self.iam.initialize()
        
        self.logger.info("Platform initialization complete")
        
    def start_api_server(self):
        """Start the FastAPI server"""
        try:
            uvicorn.run(
                "api.main:app",
                host=self.settings.api_host,
                port=self.settings.api_port,
                log_level=self.settings.log_level.lower(),
                access_log=True
            )
        except Exception as e:
            self.logger.error(f"API server error: {e}")
            
    def start_dashboard_server(self):
        """Start the Streamlit dashboard"""
        try:
            import subprocess
            cmd = [
                sys.executable, "-m", "streamlit", "run",
                "dashboard/main.py",
                "--server.port", str(self.settings.dashboard_port),
                "--server.address", self.settings.dashboard_host,
                "--browser.gatherUsageStats", "false"
            ]
            subprocess.run(cmd, cwd=Path(__file__).parent)
        except Exception as e:
            self.logger.error(f"Dashboard server error: {e}")
    
    async def start(self):
        """Start the complete platform"""
        await self.initialize()
        
        self.running = True
        self.logger.info("Starting Agentic-IAM Platform...")
        
        # Start API server in separate process
        if self.settings.enable_api:
            self.api_process = mp.Process(target=self.start_api_server)
            self.api_process.start()
            self.logger.info(f"API server started on {self.settings.api_host}:{self.settings.api_port}")
        
        # Start dashboard in separate process
        if self.settings.enable_dashboard:
            self.dashboard_process = mp.Process(target=self.start_dashboard_server)
            self.dashboard_process.start()
            self.logger.info(f"Dashboard started on {self.settings.dashboard_host}:{self.settings.dashboard_port}")
        
        self.logger.info("Platform started successfully")
        
        # Wait for processes
        try:
            while self.running:
                await asyncio.sleep(1)
                
                # Check if processes are still alive
                if self.api_process and not self.api_process.is_alive():
                    self.logger.error("API server process died")
                    self.running = False
                    
                if self.dashboard_process and not self.dashboard_process.is_alive():
                    self.logger.error("Dashboard process died")
                    self.running = False
                    
        except KeyboardInterrupt:
            self.logger.info("Shutdown signal received")
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("Shutting down Agentic-IAM Platform...")
        self.running = False
        
        # Terminate processes
        if self.api_process:
            self.api_process.terminate()
            self.api_process.join(timeout=5)
            if self.api_process.is_alive():
                self.api_process.kill()
        
        if self.dashboard_process:
            self.dashboard_process.terminate()
            self.dashboard_process.join(timeout=5)
            if self.dashboard_process.is_alive():
                self.dashboard_process.kill()
        
        # Shutdown IAM system
        if self.iam:
            await self.iam.shutdown()
        
        self.logger.info("Platform shutdown complete")


async def main():
    """Main entry point"""
    platform = AgenticIAMPlatform()
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        platform.logger.info(f"Received signal {sig}")
        asyncio.create_task(platform.shutdown())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await platform.start()
    except Exception as e:
        platform.logger.error(f"Platform error: {e}")
        await platform.shutdown()
        sys.exit(1)


if __name__ == "__main__":
    # Set multiprocessing start method
    if sys.platform.startswith('darwin'):  # macOS
        mp.set_start_method('spawn', force=True)
    
    asyncio.run(main())