import subprocess
import time
import psycopg2
from psycopg2 import sql
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("cd-db")
import ollama
import asyncio
import re
import ast

table_names = ['auto_remediation_event', 'anomaly_detection_config', 'acs_integration', 'acs_integration_token', 'anomaly_detection_file_ticker', 'anomaly_detection_scan_history', 'aws_compliance_ignore_list', 'aws_control_immediate_parent', 'azure_compliance_ignore_list', 'azure_mod_control_copy', 'azure_global_suppression_list', 'aws_global_suppression_list', 'azure_active_control_immediate_parent', 'azure_mod_control', 'aws_mod_control', 'azuread_device', 'azuread_directory_audit_report', 'azuread_directory_setting', 'azuread_security_defaults_policy', 'cs_policy_exception_config', 'cnapp_alert', 'cloud_shield_group_policy', 'cnapp_cs_alert_mapping', 'cs_policy_exception_details', 'cron_job_tracker', 'custom_report', 'forget_password', 'gcp_active_control_immediate_parent', 'databasechangelog', 'databasechangeloglock', 'business_unit_user_access', 'compliance_ticket', 'client_cloud_shield_policy', 'gcp_mod_benchmark', 'integration_config', 'gcp_compliance_ignore_list', 'gcp_global_suppression_list', 'gcp_violation_task_audit_log', 'hackerview_cloud_assets', 'hackerview_dnsx', 'hackerview_domains', 'hackerview_httpx', 'hackerview_nuclei', 'hackerview_port_scan', 'hackerview_scan_status', 'hackerview_scan_time', 'gcp_mod_control', 'jira_story', 'job_status', 'komiser_scan_status', 'lacework_last_alert_fetch_track', 'login_trace', 'kubernetes_mod_control', 'misconfiguration_report_track', 'notification_list', 'novelty_data', 'notification_preference', 'jira_account', 'oci_mod_control', 'organization_contact', 'otp_data', 'otp_provider', 'oci_active_control_immediate_parent', 'platform_configuration', 'oci_compliance_ignore_list', 'oci_global_suppression_list', 'scan_phase', 'securonix_data_push_state', 'scan_resource_count_metrics', 'team_account_mapping', 'tenant_alert_config', 'spring_session_attributes', 'sso_configuration', 'user_audit_log', 'user_authorization', 'user_account_setting', 'violation_task_audit_log', 'snapshot_version_notification_status', 'ses_email', 'slack_integration', 'gcp_control_immediate_parent', 'aws_control_benchmark_mapping', 'cloud_shield_group_account', 'notification', 'slack_filter', 'user', 'alert_type', 'api_client', 'aws_benchmark', 'aws_control', 'aws_control_aliases', 'aws_mod_benchmark', 'azure_control_immediate_parent', 'azure_mod_benchmark', 'cloud_shield_group', 'cloud_shield_policy', 'integrations', 'komiser_copy', 'mssp_provider', 'notification_channel', 'oci_control_immediate_parent', 'oci_mod_benchmark', 'organization', 'role', 'spring_session', 'team', 'user_authority', 'user_preference']
auto_remediation_event = ['id', 'account_policy_id', 'policy_id', 'cloud_type', 'account_id', 'arn_info', 'arn', 'status', 'created_at', 'event_type', 'remediation_type', 'remediated_at', 'policy_code', 'audit_log_event_id', 'existing_resource']
anomaly_detection_config = ['id', 'account_id', 'bucket_name', 'context', 'log_dir_path', 'region']
acs_integration = ['id', 'acs_organization_id', 'team_id']
acs_integration_token = ['id', 'acs_organization_id', 'confirm_time', 'create_time', 'created_by', 'is_used', 'team_id', 'team_name', 'token', 'acs_integration_config_id']
anomaly_detection_file_ticker = ['id', 'account_id', 'date', 'last_scanned_file', 'month', 'region', 'year']
anomaly_detection_scan_history = ['id', 'account_id', 'job_name', 'status', 'timestamp']
aws_compliance_ignore_list = ['id', 'arn', 'cd_id', 'is_active', 'reason', 'control_name', 'resource_name', 'account_id', 'duration', 'creation_date', 'expiry_date', 'aws_control_id', 'is_deleted', 'suppressed_by', 'suppression_type']
aws_control_immediate_parent = ['id', 'control_level', 'custom_aws_mod_control_resource_name', 'custom_severity', 'is_active', 'severity', 'severity_order', 'account_id', 'aws_mod_benchmark_resource_name', 'aws_mod_control_resource_name', 'immediate_parent_resource_name', 'family_name', 'title', 'aws_control_id', 'aws_benchmark_id', 'immediate_parent_benchmark_id']
azure_compliance_ignore_list = ['id', 'control_name', 'is_active', 'reason', 'resource_name', 'azure_account_id', 'resource', 'duration', 'creation_date', 'expiry_date', 'is_deleted', 'suppressed_by', 'suppression_type']
azure_mod_control_copy = ['resource_name', 'args', 'auto_generated', 'description', 'documentation', 'end_line_number', 'file_name', 'index', 'is_anonymous', 'mod_name', 'params', 'prepared_statement_name', 'search_path', 'search_path_prefix', 'severity', 'source_definition', 'sql', 'start_line_number', 'tags', 'title', 'type', 'width', 'control_level', 'created_at', 'remediation_available']
azure_global_suppression_list = ['id', 'azure_account_id', 'control_name', 'is_active', 'reason', 'duration', 'creation_date', 'expiry_date', 'is_deleted', 'suppressed_by', 'suppression_type']
aws_global_suppression_list = ['id', 'account_id', 'control_name', 'aws_control_id', 'is_active', 'reason', 'duration', 'creation_date', 'expiry_date', 'is_deleted', 'suppressed_by', 'suppression_type']
azure_active_control_immediate_parent = ['id', 'azure_account_id', 'active_mod_benchmark_list']
azure_mod_control = ['resource_name', 'args', 'auto_generated', 'description', 'documentation', 'end_line_number', 'file_name', 'index', 'is_anonymous', 'mod_name', 'params', 'prepared_statement_name', 'search_path', 'search_path_prefix', 'severity', 'source_definition', 'sql', 'start_line_number', 'tags', 'title', 'type', 'width', 'control_level', 'created_at', 'remediation_available']
aws_mod_control = ['resource_name', 'args', 'auto_generated', 'control_level', 'description', 'documentation', 'end_line_number', 'file_name', 'index', 'mod_name', 'params', 'prepared_statement_name', 'remediation_available', 'search_path', 'search_path_prefix', 'severity', 'source_definition', 'sql', 'start_line_number', 'tags', 'title', 'created_at', 'type']
azuread_device = ['cd_id', 'account_enabled', 'approximate_last_sign_in_date_time', 'cd_akas_arn', 'cd_orgid', 'cd_resource_id', 'cd_resource_type', 'cd_service', 'cd_snapshot_timestamp', 'cd_snapshot_version', 'device_id', 'display_name', 'extension_attributes', 'filter', 'id', 'is_compliant', 'is_managed', 'mdm_app_id', 'member_of', 'operating_system', 'operating_system_version', 'profile_type', 'tenant_id', 'title', 'trust_type']
azuread_directory_audit_report = ['cd_id', 'activity_date_time', 'activity_display_name', 'additional_details', 'category', 'cd_akas_arn', 'cd_orgid', 'cd_resource_id', 'cd_resource_type', 'cd_service', 'cd_snapshot_timestamp', 'cd_snapshot_version', 'correlation_id', 'filter', 'id', 'initiated_by', 'logged_by_service', 'operation_type', 'result', 'result_reason', 'target_resources', 'tenant_id', 'title']
azuread_directory_setting = ['cd_id', 'cd_akas_arn', 'cd_orgid', 'cd_resource_id', 'cd_resource_type', 'cd_service', 'cd_snapshot_timestamp', 'cd_snapshot_version', 'display_name', 'id', 'name', 'template_id', 'tenant_id', 'title', 'value']
azuread_security_defaults_policy = ['cd_id', 'cd_akas_arn', 'cd_orgid', 'cd_resource_id', 'cd_resource_type', 'cd_service', 'cd_snapshot_timestamp', 'cd_snapshot_version', 'description', 'display_name', 'id', 'is_enabled', 'tenant_id', 'title']
cs_policy_exception_config = ['id', 'policy_id', 'cloud_type', 'input_type', 'input_value_type', 'created_at']
cnapp_alert = ['id', 'alert', 'cnapp_provider', 'account', 'account_id', 'alert_status', 'severity', 'resource_type', 'resource_region', 'cloud_type', 'alert_time', 'tenant_id']
cloud_shield_group_policy = ['id', 'group_id', 'policy_id']
cnapp_cs_alert_mapping = ['id', 'cnapp_provider', 'cloud_type', 'policy_name', 'policy_id', 'created_at', 'updated_at', 'created_by', 'updated_by', 'company_id']
cs_policy_exception_details = ['id', 'cloud_type', 'exception_value', 'account_id', 'is_active', 'policy_id', 'exception_config_id', 'created_at', 'created_by', 'reason', 'duration', 'expiry_timestamp']
cron_job_tracker = ['id', 'account_id', 'end_time', 'exception', 'name', 'reason', 'start_time', 'status', 'type']
custom_report = ['id', 'account_id', 'created_at', 'detail', 'modified_at', 'name', 'type', 'user_id', 'last_opened', 'pinned', 'preview', 'report_type', 'downloadable_report_id']
forget_password = ['id', 'ctime', 'token', 'user_id', 'last_mail_sent_timings']
gcp_active_control_immediate_parent = ['id', 'gcp_account_id', 'active_mod_benchmark_list']
databasechangelog = ['id', 'author', 'filename', 'dateexecuted', 'orderexecuted', 'exectype', 'md5sum', 'description', 'comments', 'tag', 'liquibase', 'contexts', 'labels', 'deployment_id']
databasechangeloglock = ['id', 'locked', 'lockgranted', 'lockedby']
business_unit_user_access = ['id', 'role', 'business_unit_id', 'user_id', 'company_id', 'is_active']
compliance_ticket = ['id', 'compliance_id', 'ticket_link', 'notification_channel_id', 'account_id', 'control_name', 'resource', 'assignee', 'created_on', 'ticket_id', 'status', 'integration_id', 'aws_control_id']
client_cloud_shield_policy = ['id', 'account_id', 'policy_id', 'cloud_type', 'title', 'description', 'resource_type', 'enforce', 'created_at', 'detection', 'exception', 'enforcement_type', 'company_id', 'is_custom']
gcp_mod_benchmark = ['resource_name', 'account_id', 'auto_generated', 'children', 'description', 'documentation', 'index', 'is_active', 'mod_name', 'modified_children', 'parent', 'tags', 'title', 'project_id']
integration_config = ['id', 'enabled', 'tenant_id', 'type', 'configuration', 'integration_name', 'account_ids', 'severities', 'is_integration_valid', 's3_bucket']
gcp_compliance_ignore_list = ['id', 'control_name', 'full_resource_name', 'is_active', 'reason', 'resource_name', 'gcp_account_id', 'duration', 'creation_date', 'expiry_date', 'is_deleted', 'suppressed_by', 'suppression_type']
gcp_global_suppression_list = ['id', 'gcp_account_id', 'control_name', 'is_active', 'reason', 'duration', 'creation_date', 'expiry_date', 'is_deleted', 'suppressed_by', 'suppression_type']
gcp_violation_task_audit_log = ['id', 'changed_by', 'status', 'updated_at', 'user_id', 'violation_task_id']
hackerview_cloud_assets = ['id', 'dnsname', 'domain', 'ip', 'prefix', 'provider', 'region', 'scanid', 'service', 'account_id']
hackerview_dnsx = ['id', 'scan_id', 'host', 'ips', 'status_code', 'cname', 'account_id']
hackerview_domains = ['id', 'domain', 'account_id', 'status']
hackerview_httpx = ['id', 'scan_id', 'sub_domain', 'web_server', 'tech', 'scheme', 'cname', 'ip_address', 'content_type', 'cves', 'account_id']
hackerview_nuclei = ['id', 'scan_id', 'template', 'template_url', 'template_id', 'type', 'host', 'matched_at', 'extracted_results', 'ip', 'curl_command', 'severity', 'account_id']
hackerview_port_scan = ['id', 'conf', 'cpe', 'extrainfo', 'ip', 'name', 'port', 'product', 'reason', 'scanid', 'state', 'version', 'account_id']
hackerview_scan_status = ['id', 'status', 'account_id', 'time', 'init_status', 'asset_status', 'tech_status', 'port_status', 'vuln_status', 'end_time']
hackerview_scan_time = ['id', 'account_id', 'scan_id', 'snapshot_version', 'target', 'time']
gcp_mod_control = ['resource_name', 'args', 'auto_generated', 'description', 'documentation', 'end_line_number', 'file_name', 'index', 'is_anonymous', 'mod_name', 'params', 'path', 'qualified_name', 'query', 'severity', 'source_definition', 'sql', 'start_line_number', 'tags', 'title', 'control_level', 'created_at', 'remediation_available', 'type']
jira_story = ['id', 'account_id', 'description', 'summary', 'ticket_id', 'ticket_key', 'ticket_link']
job_status = ['finished_at', 'started_at', 'id', 'job_status', 'job_type']
komiser_scan_status = ['account_id', 'provider', 'is_credentials_valid', 'expiration_date', 'credential_file_name', 'scan_progress', 'process_id']
lacework_last_alert_fetch_track = ['id', 'last_fetch_time', 'integration_id', 'tenant_id', 'counter']
login_trace = ['id', 'email', 'user_agent', 'ip_address']
kubernetes_mod_control = ['resource_name', 'args', 'auto_generated', 'description', 'documentation', 'end_line_number', 'file_name', 'index', 'is_anonymous', 'mod_name', 'params', 'path', 'qualified_name', 'query', 'severity', 'source_definition', 'sql', 'start_line_number', 'tags', 'title', 'created_at', 'remediation_available']
misconfiguration_report_track = ['id', 'account_id', 'name', 'cloud_type', 'created_date_time', 'completed_date_time', 'created_by', 'status', 'file_location', 'file_deleted', 'custom_report_id']
notification_list = ['id', 'account_id', 'created_at', 'channels', 'notification_type', 'payload']
novelty_data = ['id', 'access_key_id', 'account_id', 'arn', 'aws_region', 'event_time', 'info_content', 'most_novel_component', 'observation', 'probability', 'score', 'sequence', 'tag', 'total_obs_score', 'uniqueness', 'username']
notification_preference = ['id', 'is_active', 'tenant_id', 'alert_type_id']
jira_account = ['id', 'account_id', 'api_token', 'domain', 'email', 'parent_key', 'project_key']
oci_mod_control = ['index', 'args', 'type', 'auto_generated', 'description', 'documentation', 'end_line_number', 'file_name', 'mod_name', 'params', 'resource_name', 'severity', 'source_definition', 'sql', 'start_line_number', 'tags', 'title', 'is_anonymous', 'path', 'qualified_name', 'query', 'control_level', 'created_at', 'remediation_available']
organization_contact = ['id', 'address', 'city', 'company_name', 'country', 'phone_number', 'root_user_email', 'state', 'zipcode', 'logo_image', 'cnapp_subscribed', 'cloudshield_subscribed', 'mssp_provider_id']
otp_data = ['id', 'ctime', 'new_email', 'token', 'user_id']
otp_provider = ['id', 'auth', 'create_time', 'email', 'otp']
oci_active_control_immediate_parent = ['id', 'active_mod_benchmark_list', 'oci_account_id']
platform_configuration = ['id', 'config_key', 'config_value']
oci_compliance_ignore_list = ['id', 'oci_account_id', 'resource_name', 'control_name', 'is_active', 'reason', 'resource', 'duration', 'creation_date', 'expiry_date', 'is_deleted', 'suppressed_by', 'suppression_type']
oci_global_suppression_list = ['id', 'oci_account_id', 'control_name', 'is_active', 'reason', 'duration', 'creation_date', 'expiry_date', 'is_deleted', 'suppressed_by', 'suppression_type']
scan_phase = ['id', 'snapshot_version_history_id', 'phase', 'start_at', 'end_time', 'status_of_step']
securonix_data_push_state = ['id', 'account_id', 'cloud_type', 'data_pushed', 'snapshot_version']
scan_resource_count_metrics = ['id', 'account_id', 'resource_type', 'region', 'steam_pipe_count', 'aws_cli_count', 'db_count', 'steampipe_db_delta', 'cli_db_delta', 'current_snapshot_version', 'memgraph_count']
team_account_mapping = ['team_id', 'account_id', 'cloud_type']
tenant_alert_config = ['id', 'is_active', 'tenant_id', 'alert_type_id', 'notification_channel_id']
spring_session_attributes = ['session_primary_id', 'attribute_name', 'attribute_bytes']
sso_configuration = ['id', 'organization_id', 'domain']
user_audit_log = ['cd_id', 'account_name', 'actor', 'event_info', 'event_type', 'target', 'time', 'user_id', 'ip_address']
user_authorization = ['id', 'account_id', 'invite_id', 'is_active', 'organization_id', 'role', 'type', 'user_id', 'parent', 'blocked_time', 'invite_sent_count', 'is_invite_blocked', 'deletion_time', 'company_id']
user_account_setting = ['id', 'attack_path_setting', 'user_id']
violation_task_audit_log = ['id', 'status', 'updated_at', 'user_id', 'violation_task_id', 'changed_by']
snapshot_version_notification_status = ['id', 'account_id', 'last_snapshot_version']
ses_email = ['id', 'html_body', 'subject']
slack_integration = ['id', 'name', 'webhook_url', 'is_active', 'tenant_id']
gcp_control_immediate_parent = ['id', 'control_level', 'family_name', 'is_active', 'severity', 'severity_order', 'title', 'account_id', 'gcp_mod_benchmark_resource_name', 'gcp_mod_control_resource_name', 'immediate_parent_resource_name']
aws_control_benchmark_mapping = ['id', 'control_id', 'benchmark_id']
cloud_shield_group_account = ['id', 'group_id', 'account_id', 'cloud_type']
notification = ['id', 'compliance', 'created_at', 'email', 'name', 'user_id', 'account_id', 'organization_id']
slack_filter = ['id', 'filter_type', 'filter_value', 'slack_integration_id']
user = ['id', 'last_login_time', 'email', 'first_name', 'invite_id', 'is_active', 'is_blocked', 'is_invite_accepted', 'last_name', 'mfa', 'mobile_number', 'password', 'role', 'system_name', 'username', 'total_link_generation_count', 'mfa_config', 'mfa_configured', 'mfa_secret', 'last_password_update_time', 'deletion_time', 'invited_by', 'super_admin', 'mssp_provider_id']
alert_type = ['id', 'display_name', 'name']
api_client = ['client_id', 'client_name', 'created_at', 'created_by', 'is_active', 'secret_id', 'status', 'account_id', 'organization_id', 'role_id']
aws_benchmark = ['id', 'resource_name', 'account_id', 'description', 'is_active', 'mod_name', 'title', 'parent_id']
aws_control = ['id', 'resource_name', 'description', 'mod_name', 'remediation_available', 'severity', 'sql', 'title', 'created_at']
aws_control_aliases = ['id', 'control_id', 'alias']
aws_mod_benchmark = ['resource_name', 'account_id', 'auto_generated', 'children', 'description', 'documentation', 'end_line_number', 'file_name', 'index', 'is_active', 'mod_name', 'modified_children', 'parent', 'source_definition', 'start_line_number', 'tags', 'title']
azure_control_immediate_parent = ['id', 'custom_azure_mod_control_resource_name', 'custom_severity', 'is_active', 'severity', 'severity_order', 'azure_account_id', 'azure_mod_benchmark_resource_name', 'azure_mod_control_resource_name', 'immediate_parent_resource_name', 'family_name', 'title', 'control_level']
azure_mod_benchmark = ['resource_name', 'auto_generated', 'children', 'description', 'documentation', 'end_line_number', 'file_name', 'index', 'is_anonymous', 'mod_name', 'modified_children', 'parent', 'path', 'source_definition', 'start_line_number', 'tags', 'title', 'type', 'width', 'account_id', 'is_active']
cloud_shield_group = ['id', 'name', 'tenant_id', 'description', 'created_at', 'created_by']
cloud_shield_policy = ['id', 'title', 'description', 'aws_policy_json', 'gcp_policy_json', 'azure_policy_json', 'aws_resource_type', 'gcp_resource_type', 'azure_resource_type', 'created_at', 'aws_auto_remediation_available', 'gcp_auto_remediation_available', 'azure_auto_remediation_available', 'tag', 'cd_code', 'company_id', 'is_custom', 'aws_policy_version', 'azure_policy_version', 'gcp_policy_version', 'aws_action', 'gcp_action', 'azure_action', 'applicable_company', 'applicable_account', 'applied', 'updated_at', 'created_by', 'updated_by', 'oci_policy_json', 'oci_resource_type', 'oci_auto_remediation_available', 'oci_policy_version', 'oci_action', 'aws_detection_only', 'azure_detection_only', 'gcp_detection_only']
integrations = ['id', 'categories', 'description', 'display_name', 'name']
komiser_copy = ['id', 'resource_id', 'provider', 'account', 'account_id', 'service', 'region', 'name', 'created_at', 'fetched_at', 'cost', 'metadata', 'relations', 'tags', 'link', 'snapshot_timestamp', 'snapshot_version']
mssp_provider = ['id', 'name']
notification_channel = ['id', 'name']
oci_control_immediate_parent = ['id', 'is_active', 'account_id', 'oci_mod_control_resource_name', 'oci_mod_benchmark_resource_name', 'immediate_parent_resource_name', 'severity', 'control_level', 'family_name', 'severity_order', 'title']
oci_mod_benchmark = ['index', 'auto_generated', 'children', 'description', 'documentation', 'mod_name', 'resource_name', 'tags', 'title', 'modified_children', 'parent', 'is_active', 'account_id']
organization = ['id', 'is_active', 'name']
role = ['id', 'name']
spring_session = ['primary_id', 'session_id', 'creation_time', 'last_access_time', 'max_inactive_interval', 'expiry_time', 'principal_name']
team = ['id', 'team_name', 'org_id', 'created_by_user_id', 'team_description', 'created_on', 'is_active']
user_authority = ['id', 'team_id', 'user_id', 'role_id']
user_preference = ['id', 'account_id', 'account_type', 'dashboard_config', 'user_id', 'company_id']
def gcloud_ssh_tunnel():
    print("[*] Starting gcloud SSH tunnel...")
    tunnel_cmd = [
        "gcloud", "compute", "ssh", "qa-db-vm",
        "--tunnel-through-iap",
        "--project=cd-production",
        "--zone=us-west1-a",
        "--ssh-flag=-L 5432:localhost:5432",
        "--quiet"
    ]
    process = subprocess.Popen(tunnel_cmd)
    print("[*] Waiting for tunnel to establish...")
    time.sleep(10)
    return process
print("[*] Connecting to PostgreSQL...")
def connect_postgres():
    try:
        conn = psycopg2.connect(
            host="localhost",
            port=5432,
            dbname="acs",
            user="postgres",
            password="5eSy64OkWk950HWa" 
        )
        print("[+] Connected successfully!")
        cur = conn.cursor()
        cur.execute("SELECT NOW();")
        print("Current Time:", cur.fetchone())
    except Exception as e:
        print("[-] Failed to connect:", e)

def clean_sql_output(response_text):
    """Strip markdown formatting like ```sql ... ``` and convert to single-line SQL."""
    cleaned = re.sub(r"```(?:sql)?\s*\n?([\s\S]*?)\n?\s*```", r"\1", response_text)
    single_line = re.sub(r"\s+", " ", cleaned)
    return single_line.strip()

@mcp.tool()
def data(user_input: str) -> str:
    """This tool returns data based on user input. It requires the entire user input to be passed in.
    Args:
        user_input: str: The entire input of the user with nothing cut out.
    Returns:
        str:"Table: Column: Data"
    """
    try:
        conn = psycopg2.connect(
            host="localhost",
            port=5432,
            dbname="acs",
            user="postgres",
            password="5eSy64OkWk950HWa"
        )
        cur = conn.cursor()
        prompt_1 = f"""You are a helpful agent that makes prompts for SQL queries. 
        You are going to generate a prompt that when provided to a large language model will generate a SQL query. 
        Look at the information provided and find the important information. 
        Use that information to create a prompt that will generate a SQL query.
        Make sure to stress on the important information and make it clear to the LLM if the important information is, for example but not limited to, the table name, column name and so on. Always use "public" as the schema name.
        Information: {user_input}"""
        response_1 = ollama.chat(
            model='gemma3:latest',
            messages=[
                {'role': 'user', 'content': prompt_1}
            ]
        )
        print("response 1:",response_1['message']['content'])

        prompt_2 = f"""You are a helpful assistant. Do not return an sql query. I want you to do one thing and one thing only.
        You are going to look through all the tables in the provided list and find which are the most appropriate table name/table names to the table name/ table names required by the user input.
        If, according to the user input, you see only one appropriate table name, return that table name.
        If you see multiple appropriate table names, return all of them. The final query that will be generated from these name/names can be complex queries requiring multiple tables.
        Read carefully and choose the right names. Return it in the following format:
        ["table_name_1", "table_name_2", "table_name_3", ...]
        User_prompt: {prompt_1}
        Tables: {table_names}"""
        response_2 = ollama.chat(
            model='gemma3:latest',
            messages=[
                {'role': 'user', 'content': prompt_2}
            ]
        )
        print("Selected tables:", response_2['message']['content'])
        selected_tables = ast.literal_eval(response_2['message']['content'].strip())
        table_column_info = ""

        for table in selected_tables:
            if table in globals():
                column_names = globals()[table]
                print(f"Columns of {table}:", column_names)
                formatted_cols = ", ".join(column_names)
                table_column_info += f"[{table}: {formatted_cols},]"
            else:
                print(f"Table '{table}' not found in globals.")
        prompt_3 = f"""You are a helpful assistant. Based on the table name and the user input provided, look through the column names of all the tables that have been provided. 
        Understand what the user expects and choose the column name/column names that are most appropriate to the user input.
        If, according to the user input, you see only one appropriate column name, return that column name.
        If you see multiple appropriate column names, return all of them. The final query that will be generated from these name/names can be complex queries requiring multiple columns.
        Imagine you look at the column names of a particular table and you see that the columns in that table are not relevant to the query, you can ignore that table.
        Return the correct column name/names and corrected table names in the format below.
        ["table_name_1": "column_name_1", "column_name_2",],["table_name_2": "column_name_3", "column_name_4",] ...

        User_prompt: {prompt_1}
        {table_column_info}"""
        response_3 = ollama.chat(
            model='gemma3:latest',
            messages=[
                {'role': 'user', 'content': prompt_3}
            ]
        )
        print("response 3:", response_3['message']['content'])
        prompt_4 = f"""You are a helpful SQL assistant. 
        Based on the information below, create a SQL statement that can be used to query the database. Always use "public" as the schema name
        Provide only the SQL statement, no other text.
        Column name: {response_3['message']['content']}
        Table name: {response_2['message']['content']}
        user input: {user_input}"""
        response_4 = ollama.chat(
            model='gemma3:latest',
            messages=[
                {'role': 'user', 'content': prompt_4}
            ]
        )   
        print("response 4:",response_4['message']['content'])  

        cur.execute(clean_sql_output(response_4['message']['content']))
        results = cur.fetchall()
        result_str = str(results)
        return result_str

    except Exception as e:
        return f"Error querying database: {e}"

if __name__ == "__main__":
    ssh_proc = gcloud_ssh_tunnel()
    connect_postgres()
    mcp.run(transport="stdio")