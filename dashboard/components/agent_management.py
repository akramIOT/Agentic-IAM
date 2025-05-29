"""
Agentic-IAM: Agent Management Dashboard Component

Streamlit components for comprehensive agent lifecycle management,
registration, monitoring, and administration.
"""
import asyncio
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from core.agentic_iam import AgenticIAM
from dashboard.utils import (
    safe_async_run, format_datetime, get_status_color, format_trust_score,
    create_metric_card, show_alert, paginate_data, render_pagination,
    validate_agent_id, handle_error
)


def show_agent_management(iam: Optional[AgenticIAM]):
    """
    Display agent management interface
    
    Provides comprehensive agent management functionality including registration,
    monitoring, status updates, and detailed agent information.
    """
    
    if not iam or not iam.is_initialized:
        st.error("❌ IAM system not initialized")
        return
    
    st.header("👥 Agent Management")
    
    # Tabs for different management functions
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Agent Overview", 
        "➕ Register Agent", 
        "📊 Agent Details", 
        "⚙️ Bulk Operations"
    ])
    
    with tab1:
        show_agent_overview(iam)
    
    with tab2:
        show_agent_registration(iam)
    
    with tab3:
        show_agent_details(iam)
    
    with tab4:
        show_bulk_operations(iam)


def show_agent_overview(iam: AgenticIAM):
    """Display agent overview and statistics"""
    
    try:
        # Get agent list
        agents = iam.agent_registry.list_agents()
        
        if not agents:
            show_alert("No agents registered yet. Use the 'Register Agent' tab to add your first agent.", "info")
            return
        
        # Calculate statistics
        total_agents = len(agents)
        active_agents = len([a for a in agents if a.status.value == "active"])
        inactive_agents = len([a for a in agents if a.status.value == "inactive"])
        suspended_agents = len([a for a in agents if a.status.value == "suspended"])
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Agents", total_agents)
        
        with col2:
            st.metric("Active", active_agents, delta=f"{(active_agents/total_agents*100):.1f}%")
        
        with col3:
            st.metric("Inactive", inactive_agents)
        
        with col4:
            st.metric("Suspended", suspended_agents)
        
        # Agent status distribution chart
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Agent Status Distribution")
            
            status_data = {
                "Status": ["Active", "Inactive", "Suspended"],
                "Count": [active_agents, inactive_agents, suspended_agents],
                "Color": ["#28a745", "#6c757d", "#ffc107"]
            }
            
            if sum(status_data["Count"]) > 0:
                fig = px.pie(
                    values=status_data["Count"],
                    names=status_data["Status"],
                    color_discrete_sequence=status_data["Color"]
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No status data available")
        
        with col2:
            st.subheader("🧠 Trust Score Distribution")
            
            # Get trust scores
            trust_scores = []
            for agent in agents:
                try:
                    score = safe_async_run(iam.calculate_trust_score(agent.agent_id))
                    if score:
                        trust_scores.append(score.overall_score)
                except:
                    pass
            
            if trust_scores:
                # Create trust score histogram
                trust_ranges = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"]
                trust_counts = [0, 0, 0, 0, 0]
                
                for score in trust_scores:
                    if score <= 0.2:
                        trust_counts[0] += 1
                    elif score <= 0.4:
                        trust_counts[1] += 1
                    elif score <= 0.6:
                        trust_counts[2] += 1
                    elif score <= 0.8:
                        trust_counts[3] += 1
                    else:
                        trust_counts[4] += 1
                
                fig = px.bar(
                    x=trust_ranges,
                    y=trust_counts,
                    labels={'x': 'Trust Score Range', 'y': 'Number of Agents'},
                    color=trust_counts,
                    color_continuous_scale='RdYlGn'
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No trust score data available")
        
        # Agent table with filtering and pagination
        st.subheader("📋 Agent Directory")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status_filter = st.selectbox("Filter by Status", ["All", "Active", "Inactive", "Suspended"])
        
        with col2:
            search_query = st.text_input("Search Agent ID", placeholder="agent:...")
        
        with col3:
            sort_by = st.selectbox("Sort by", ["Last Accessed", "Registration Date", "Trust Score"])
        
        # Apply filters
        filtered_agents = agents.copy()
        
        if status_filter != "All":
            filtered_agents = [a for a in filtered_agents if a.status.value.title() == status_filter]
        
        if search_query:
            filtered_agents = [a for a in filtered_agents if search_query.lower() in a.agent_id.lower()]
        
        # Prepare table data
        agent_data = []
        for agent in filtered_agents:
            try:
                # Get trust score
                trust_score = safe_async_run(iam.calculate_trust_score(agent.agent_id))
                trust_display = format_trust_score(trust_score.overall_score) if trust_score else "N/A"
                
                # Get active sessions
                sessions = iam.session_manager.session_store.get_agent_sessions(agent.agent_id)
                active_sessions = len([s for s in sessions if s.is_active()])
                
                agent_data.append({
                    "Agent ID": agent.agent_id,
                    "Status": f"{get_status_color(agent.status.value)} {agent.status.value.title()}",
                    "Trust Score": trust_display,
                    "Active Sessions": active_sessions,
                    "Last Accessed": format_datetime(agent.last_accessed),
                    "Registered": format_datetime(agent.registration_date)
                })
            except Exception as e:
                st.error(f"Error processing agent {agent.agent_id}: {str(e)}")
        
        # Pagination
        page_size = 10
        page_number = st.session_state.get("agent_page", 1)
        
        if agent_data:
            pagination = paginate_data(agent_data, page_size, page_number)
            
            # Display table
            df = pd.DataFrame(pagination["data"])
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Pagination controls
            render_pagination(pagination, "agent")
        else:
            st.info("No agents match the current filters")
        
        # Quick actions
        st.subheader("⚡ Quick Actions")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("🔄 Refresh Data"):
                st.experimental_rerun()
        
        with col2:
            if st.button("📊 Generate Report"):
                show_alert("Agent report generation would be implemented here", "info")
        
        with col3:
            if st.button("📤 Export Data"):
                # Convert to CSV for download
                if agent_data:
                    csv_data = pd.DataFrame(agent_data).to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv_data,
                        file_name=f"agents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
        
        with col4:
            if st.button("🧹 Cleanup Inactive"):
                show_alert("Inactive agent cleanup would be implemented here", "warning")
        
    except Exception as e:
        handle_error(e, "loading agent overview")


def show_agent_registration(iam: AgenticIAM):
    """Display agent registration interface"""
    
    st.subheader("➕ Register New Agent")
    
    # Registration form
    with st.form("agent_registration"):
        col1, col2 = st.columns(2)
        
        with col1:
            agent_id = st.text_input(
                "Agent ID*", 
                placeholder="agent:my-agent-001",
                help="Unique identifier for the agent (e.g., agent:service-name)"
            )
            
            agent_type = st.selectbox(
                "Agent Type*",
                ["service", "user", "system", "external", "api"],
                help="Type of agent being registered"
            )
            
            description = st.text_area(
                "Description",
                placeholder="Brief description of the agent's purpose",
                height=100
            )
        
        with col2:
            capabilities = st.multiselect(
                "Capabilities",
                ["read", "write", "execute", "admin", "audit", "monitor"],
                help="Select the capabilities this agent should have"
            )
            
            initial_permissions = st.multiselect(
                "Initial Permissions",
                ["agent:read", "agent:write", "system:status", "data:read"],
                help="Initial permissions to grant to the agent"
            )
            
            trust_level = st.slider(
                "Initial Trust Level",
                min_value=0.0,
                max_value=1.0,
                value=0.8,
                step=0.1,
                help="Initial trust level for the agent"
            )
        
        # Advanced options
        with st.expander("🔧 Advanced Options"):
            enable_mfa = st.checkbox("Require Multi-Factor Authentication")
            enable_monitoring = st.checkbox("Enable Enhanced Monitoring", value=True)
            auto_approve = st.checkbox("Auto-approve registration", value=True)
            
            # Metadata
            st.write("**Additional Metadata:**")
            metadata_key = st.text_input("Metadata Key", placeholder="environment")
            metadata_value = st.text_input("Metadata Value", placeholder="production")
        
        # Submit button
        submitted = st.form_submit_button("🚀 Register Agent", type="primary")
        
        if submitted:
            try:
                # Validate input
                if not agent_id:
                    st.error("Agent ID is required")
                    return
                
                if not validate_agent_id(agent_id):
                    st.error("Invalid Agent ID format. Should start with 'agent:' and be at least 8 characters long")
                    return
                
                # Check if agent already exists
                existing = iam.agent_registry.get_agent(agent_id)
                if existing:
                    st.error(f"Agent {agent_id} already exists")
                    return
                
                # Create agent identity
                from agent_identity import AgentIdentity
                
                metadata = {
                    "type": agent_type,
                    "description": description,
                    "capabilities": capabilities,
                    "trust_level": trust_level,
                    "mfa_enabled": enable_mfa,
                    "monitoring_enabled": enable_monitoring
                }
                
                if metadata_key and metadata_value:
                    metadata[metadata_key] = metadata_value
                
                # Generate agent identity
                agent_identity = AgentIdentity.generate(
                    agent_id=agent_id,
                    metadata=metadata
                )
                
                # Register agent
                registration_id = safe_async_run(
                    iam.register_agent(agent_identity, initial_permissions)
                )
                
                st.success(f"✅ Agent registered successfully!")
                st.info(f"Registration ID: {registration_id}")
                
                # Display agent details
                with st.expander("📋 Agent Details"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Agent ID:** {agent_id}")
                        st.write(f"**Type:** {agent_type}")
                        st.write(f"**Trust Level:** {trust_level}")
                        st.write(f"**MFA Enabled:** {enable_mfa}")
                    
                    with col2:
                        st.write(f"**Capabilities:** {', '.join(capabilities)}")
                        st.write(f"**Permissions:** {len(initial_permissions)}")
                        st.write(f"**Monitoring:** {enable_monitoring}")
                        st.write(f"**Registration ID:** {registration_id}")
                
                # Show public key
                public_key = agent_identity.get_public_key()
                if public_key:
                    st.write("**Public Key (for verification):**")
                    st.code(public_key.decode() if isinstance(public_key, bytes) else str(public_key))
                
            except Exception as e:
                handle_error(e, "registering agent")


def show_agent_details(iam: AgenticIAM):
    """Display detailed agent information"""
    
    st.subheader("📊 Agent Details")
    
    # Agent selection
    agents = iam.agent_registry.list_agents()
    if not agents:
        st.info("No agents registered yet")
        return
    
    agent_ids = [agent.agent_id for agent in agents]
    selected_agent_id = st.selectbox("Select Agent", agent_ids)
    
    if not selected_agent_id:
        return
    
    try:
        # Get agent details
        agent_entry = iam.agent_registry.get_agent(selected_agent_id)
        if not agent_entry:
            st.error("Agent not found")
            return
        
        # Basic information
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("### 📋 Basic Information")
            st.write(f"**Agent ID:** {agent_entry.agent_id}")
            st.write(f"**Status:** {get_status_color(agent_entry.status.value)} {agent_entry.status.value.title()}")
            st.write(f"**Registration Date:** {format_datetime(agent_entry.registration_date)}")
            st.write(f"**Last Accessed:** {format_datetime(agent_entry.last_accessed)}")
            st.write(f"**Registration ID:** {agent_entry.registration_id}")
        
        with col2:
            st.write("### 🏷️ Metadata")
            metadata = agent_entry.agent_identity.get_metadata()
            for key, value in metadata.items():
                st.write(f"**{key.title()}:** {value}")
        
        # Trust Score
        st.write("### 🧠 Trust Score Analysis")
        
        try:
            trust_score = safe_async_run(iam.calculate_trust_score(selected_agent_id))
            if trust_score:
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric(
                        "Overall Score", 
                        f"{trust_score.overall_score:.3f}",
                        help="Overall trust score (0.0 - 1.0)"
                    )
                
                with col2:
                    st.metric(
                        "Risk Level", 
                        trust_score.risk_level.value.title(),
                        help="Risk assessment based on trust score"
                    )
                
                with col3:
                    st.metric(
                        "Confidence", 
                        f"{trust_score.confidence:.2f}",
                        help="Confidence in the trust score calculation"
                    )
                
                # Component scores
                if trust_score.component_scores:
                    st.write("**Component Scores:**")
                    components_df = pd.DataFrame([
                        {"Component": k, "Score": v} 
                        for k, v in trust_score.component_scores.items()
                    ])
                    
                    fig = px.bar(
                        components_df, 
                        x="Component", 
                        y="Score",
                        color="Score",
                        color_continuous_scale="RdYlGn"
                    )
                    fig.update_layout(height=300)
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Trust score not available")
        except Exception as e:
            st.warning(f"Could not load trust score: {str(e)}")
        
        # Active Sessions
        st.write("### 🔐 Active Sessions")
        
        try:
            sessions = iam.session_manager.session_store.get_agent_sessions(selected_agent_id)
            active_sessions = [s for s in sessions if s.is_active()]
            
            if active_sessions:
                session_data = []
                for session in active_sessions:
                    session_data.append({
                        "Session ID": session.session_id[:16] + "...",
                        "Auth Method": session.auth_method,
                        "Trust Level": f"{session.trust_level:.2f}",
                        "Created": format_datetime(session.created_at),
                        "Expires": format_datetime(session.expires_at),
                        "Source IP": session.metadata.get("source_ip", "N/A")
                    })
                
                sessions_df = pd.DataFrame(session_data)
                st.dataframe(sessions_df, use_container_width=True, hide_index=True)
            else:
                st.info("No active sessions")
        except Exception as e:
            st.warning(f"Could not load sessions: {str(e)}")
        
        # Permissions & Roles
        st.write("### 🔑 Permissions & Roles")
        
        try:
            if iam.authorization_manager:
                # Get permissions
                permissions = safe_async_run(
                    iam.authorization_manager.get_agent_permissions(selected_agent_id)
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Direct Permissions:**")
                    if permissions.get("direct_permissions"):
                        for perm in permissions["direct_permissions"]:
                            st.write(f"• {perm}")
                    else:
                        st.write("None")
                
                with col2:
                    st.write("**Roles:**")
                    if permissions.get("roles"):
                        for role in permissions["roles"]:
                            st.write(f"• {role}")
                    else:
                        st.write("None")
        except Exception as e:
            st.warning(f"Could not load permissions: {str(e)}")
        
        # Agent Actions
        st.write("### ⚙️ Agent Actions")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("🔄 Refresh Agent"):
                st.experimental_rerun()
        
        with col2:
            if st.button("⏸️ Suspend Agent"):
                if st.confirm("Are you sure you want to suspend this agent?"):
                    try:
                        # Suspend agent (implementation would be added)
                        show_alert("Agent suspension would be implemented here", "warning")
                    except Exception as e:
                        handle_error(e, "suspending agent")
        
        with col3:
            if st.button("🔄 Reactivate Agent"):
                try:
                    # Reactivate agent (implementation would be added)
                    show_alert("Agent reactivation would be implemented here", "info")
                except Exception as e:
                    handle_error(e, "reactivating agent")
        
        with col4:
            if st.button("🗑️ Delete Agent"):
                if st.confirm("Are you sure you want to delete this agent? This action cannot be undone."):
                    try:
                        # Delete agent (implementation would be added)
                        show_alert("Agent deletion would be implemented here", "error")
                    except Exception as e:
                        handle_error(e, "deleting agent")
        
    except Exception as e:
        handle_error(e, "loading agent details")


def show_bulk_operations(iam: AgenticIAM):
    """Display bulk operations interface"""
    
    st.subheader("⚙️ Bulk Operations")
    
    # Get agent list
    agents = iam.agent_registry.list_agents()
    if not agents:
        st.info("No agents available for bulk operations")
        return
    
    # Operation selection
    operation = st.selectbox(
        "Select Operation",
        [
            "Update Status",
            "Assign Permissions",
            "Revoke Permissions", 
            "Update Trust Levels",
            "Terminate Sessions",
            "Export Agent Data"
        ]
    )
    
    # Agent selection
    agent_ids = [agent.agent_id for agent in agents]
    selected_agents = st.multiselect(
        "Select Agents",
        agent_ids,
        help="Choose agents for bulk operation"
    )
    
    if not selected_agents:
        st.warning("Please select at least one agent")
        return
    
    st.write(f"**Selected {len(selected_agents)} agent(s):**")
    for agent_id in selected_agents:
        st.write(f"• {agent_id}")
    
    # Operation-specific parameters
    if operation == "Update Status":
        new_status = st.selectbox("New Status", ["active", "inactive", "suspended"])
        reason = st.text_input("Reason for status change")
        
        if st.button("Update Status"):
            with st.spinner("Updating agent statuses..."):
                try:
                    # Implementation would update statuses
                    show_alert(f"Status update for {len(selected_agents)} agents would be implemented here", "info")
                except Exception as e:
                    handle_error(e, "updating agent statuses")
    
    elif operation == "Assign Permissions":
        permissions = st.multiselect(
            "Permissions to Assign",
            ["agent:read", "agent:write", "system:status", "data:read", "data:write", "admin:access"]
        )
        
        if st.button("Assign Permissions"):
            with st.spinner("Assigning permissions..."):
                try:
                    # Implementation would assign permissions
                    show_alert(f"Permission assignment for {len(selected_agents)} agents would be implemented here", "info")
                except Exception as e:
                    handle_error(e, "assigning permissions")
    
    elif operation == "Export Agent Data":
        export_format = st.selectbox("Export Format", ["JSON", "CSV", "Excel"])
        include_sessions = st.checkbox("Include Session Data")
        include_permissions = st.checkbox("Include Permission Data")
        
        if st.button("Export Data"):
            with st.spinner("Preparing export..."):
                try:
                    # Create export data
                    export_data = []
                    for agent_id in selected_agents:
                        agent_entry = iam.agent_registry.get_agent(agent_id)
                        if agent_entry:
                            agent_info = {
                                "agent_id": agent_entry.agent_id,
                                "status": agent_entry.status.value,
                                "registration_date": agent_entry.registration_date.isoformat(),
                                "last_accessed": agent_entry.last_accessed.isoformat(),
                                "metadata": agent_entry.agent_identity.get_metadata()
                            }
                            export_data.append(agent_info)
                    
                    if export_format == "JSON":
                        import json
                        json_data = json.dumps(export_data, indent=2, default=str)
                        st.download_button(
                            label="Download JSON",
                            data=json_data,
                            file_name=f"agents_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                    elif export_format == "CSV":
                        # Flatten data for CSV
                        flattened_data = []
                        for item in export_data:
                            flat_item = {k: v for k, v in item.items() if k != "metadata"}
                            flat_item.update(item.get("metadata", {}))
                            flattened_data.append(flat_item)
                        
                        csv_data = pd.DataFrame(flattened_data).to_csv(index=False)
                        st.download_button(
                            label="Download CSV",
                            data=csv_data,
                            file_name=f"agents_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )
                    
                    show_alert(f"Export prepared for {len(export_data)} agents", "success")
                    
                except Exception as e:
                    handle_error(e, "exporting agent data")