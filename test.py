import subprocess
import time
import psycopg2
from psycopg2 import sql  # Added the missing import
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("cd-db")
import ollama
import asyncio
import re
import ast

def clean_sql_output(response_text):
    """Strip markdown formatting like ```sql ... ``` and convert to single-line SQL."""
    # Remove triple backticks and optional 'sql' specifier
    cleaned = re.sub(r"```(?:sql)?\s*\n?([\s\S]*?)\n?\s*```", r"\1", response_text)
    # Replace newlines and tabs with spaces, and collapse multiple spaces
    single_line = re.sub(r"\s+", " ", cleaned)
    return single_line.strip()

table_uses = {
    'auto_remediation_event': 'Stores details about automated remediation actions triggered by policies on cloud resources. Includes remediation status, timestamps, and policy references.',
    
    'anomaly_detection_config': 'Holds configuration settings for anomaly detection jobs, such as bucket names, log directory paths, account and region context.',
    
    'acs_integration': 'Manages the integration mapping between the system and an external ACS (Access Control System) by storing organization and team identifiers.',
    
    'acs_integration_token': 'Stores authentication tokens for ACS integrations, including metadata like creation time, who created it, whether it was used, and which team it belongs to.',
    
    'anomaly_detection_file_ticker': 'Tracks the last scanned log files for anomaly detection purposes by date, region, and account, useful for resuming scans and audit purposes.',
    
    'anomaly_detection_scan_history': 'Logs historical information about anomaly detection jobs such as job names, statuses, and execution timestamps.',
    
    'scan_resource_count_metrics': 'Captures statistics about scanned resources including counts by type (e.g., SteamPipe, AWS CLI), deltas between tools, and snapshot versions.',
    
    'user': '''Stores user account data including login credentials, MFA configuration, contact info, roles, and account activity like invite status and deletions.
    Fields:
    id: uuid,
    last_login_time: timestamp without time zone,
    email: character varying,
    first_name: character varying,
    invite_id: character varying,
    is_active: boolean,
    is_blocked: boolean,
    is_invite_accepted: boolean,
    last_name: character varying,
    mfa: boolean,
    mobile_number: character varying,
    password: character varying,
    role: character varying,
    system_name: character varying,
    username: character varying,
    total_link_generation_count: integer,
    mfa_config: jsonb,
    mfa_configured: boolean,
    mfa_secret: character varying,
    last_password_update_time: timestamp without time zone,
    deletion_time: timestamp without time zone,
    invited_by: uuid,
    super_admin: boolean,
    mssp_provider_id: uuid
'''

}
table_names = ['auto_remediation_event', 'anomaly_detection_config', 'acs_integration', 'acs_integration_token', 'anomaly_detection_file_ticker', 'anomaly_detection_scan_history', 'scan_resource_count_metrics', 'user']
auto_remediation_event = ['id', 'account_policy_id', 'policy_id', 'cloud_type', 'account_id', 'arn_info', 'arn', 'status', 'created_at', 'event_type', 'remediation_type', 'remediated_at', 'policy_code', 'audit_log_event_id', 'existing_resource']
anomaly_detection_config = ['id', 'account_id', 'bucket_name', 'context', 'log_dir_path', 'region']
acs_integration = ['id', 'acs_organization_id', 'team_id']
acs_integration_token = ['id', 'acs_organization_id', 'confirm_time', 'create_time', 'created_by', 'is_used', 'team_id', 'team_name', 'token', 'acs_integration_config_id']
anomaly_detection_file_ticker = ['id', 'account_id', 'date', 'last_scanned_file', 'month', 'region', 'year']
anomaly_detection_scan_history = ['id', 'account_id', 'job_name', 'status', 'timestamp']
scan_resource_count_metrics = ['id', 'account_id', 'resource_type', 'region', 'steam_pipe_count', 'aws_cli_count', 'db_count', 'steampipe_db_delta', 'cli_db_delta', 'current_snapshot_version', 'memgraph_count']
user = ['id', 'last_login_time', 'email', 'first_name', 'invite_id', 'is_active', 'is_blocked', 'is_invite_accepted', 'last_name', 'mfa', 'mobile_number', 'password', 'role', 'system_name', 'username', 'total_link_generation_count', 'mfa_config', 'mfa_configured', 'mfa_secret', 'last_password_update_time', 'deletion_time', 'invited_by', 'super_admin', 'mssp_provider_id']

user_input = "Do more users update password in the morning or in the evening? Only use the time. Please provide the number of users for each time period."
# Safely format the identifiers (schema, table, column)
# Connect to the PostgreSQL database
conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="acs",
    user="postgres",
    password="5eSy64OkWk950HWa"  # Remove this later
)
cur = conn.cursor()

# Safely format the identifiers (schema, table, column)
prompt_1 = f"""Convert the user input into a more expanded, polite query. 
Ignore specific examples they give. Just focus on the intent of the query.
Imagine you are the user making a query. 
Try to understand what the user is asking for and phrase it better and more polite. 
If they give generalised examples like johndoe@example.com or stuff like that, just ignore it.
Do not make it part of your query.
Information: {user_input}"""
response_1 = ollama.chat(
    model='gemma3:latest',  # or another model like 'mistral'
    messages=[
        {'role': 'user', 'content': prompt_1}
    ]
)
print("response 1:",response_1['message']['content'])  # to get the actual reply

prompt_2 = f"""You are a helpful assistant. Do not return an sql query. I want you to do one thing and one thing only.
You are going to look through all the tables in the provided list and find which are the most appropriate table name/table names to the table name/ table names required by the user input.
If, according to the user input, you see only one appropriate table name, return that table name. I have also provided you with the uses of each table. Use that to choose the right table name/names.
If you see multiple appropriate table names, return all of them. The final query that will be generated from these name/names can be complex queries requiring multiple tables.
Read carefully and choose the right names. Return it in the following format:
["table_name_1", "table_name_2", "table_name_3", ...]
User_prompt: {response_1['message']['content']}
Tables: {table_names}
Table Uses: {table_uses}"""
response_2 = ollama.chat(
    model='gemma3:latest',  # or another model like 'mistral'
    messages=[
        {'role': 'user', 'content': prompt_2}
    ]
)
print("Selected tables:", response_2['message']['content'])

selected_tables = ast.literal_eval(response_2['message']['content'].strip())

# Step 2: Build up the string that holds table and column info
table_column_info = ""

for table in selected_tables:
    if table in globals():
        column_names = globals()[table]
        print(f"Columns of {table}:", column_names)
        # Format for prompt: [table_name: col1, col2,]
        formatted_cols = ", ".join(column_names)
        table_column_info += f"[{table}: {formatted_cols},]"
    else:
        print(f"Table '{table}' not found in globals.")

# Step 3: Construct prompt for LLM
prompt_3 = f"""You are a helpful assistant. Based on the table name and the user input provided, look through the column names of all the tables that have been provided. 
Understand what the user expects and choose the column name/column names that are most appropriate to the user input.
If, according to the user input, you see only one appropriate column name, return that column name.
If you see multiple appropriate column names, return all of them. The final query that will be generated from these name/names can be complex queries requiring multiple columns.
Imagine you look at the column names of a particular table and you see that the columns in that table are not relevant to the query, you can ignore that table.
Return the correct column name/names and corrected table names in the format below.
["table_name_1": "column_name_1", "column_name_2",],["table_name_2": "column_name_3", "column_name_4",] ...

User_prompt: {response_1['message']['content']}
Table and Column Information:
{table_column_info}"""

# Step 4: Send prompt to model
response_3 = ollama.chat(
    model='gemma3:latest',
    messages=[
        {'role': 'user', 'content': prompt_3}
    ]
)
print("response 3:", response_3['message']['content'])

prompt_4 = f"""You are a helpful SQL assistant. The database is PostgreSQL.
Based on the information below, create a SQL statement that can be used to query the database. Always use "public" as the schema name
Provide only the SQL statement, no other text. 
Read through the data type provided in the explanation of the tables in table uses to produce the SQL statement.
Please, CHECK THE DATA TYPE OF THE COLUMN YOU ARE TRYING TO QUERY.
CHECK THE DATA TYPE OF THE COLUMN YOU ARE TRYING TO QUERY.
MAKE THE QUERY BASED ON THE DATA TYPE OF THE COLUMN YOU ARE TRYING TO QUERY.
Table and Column Information: {response_3['message']['content']}
user input: {response_1['message']['content']}
table uses: {table_uses}"""
response_4 = ollama.chat(
    model='gemma3:latest',  # or another model like 'mistral'
    messages=[
        {'role': 'user', 'content': prompt_4}
    ]
)   
print("response 4:",response_4['message']['content'])  

prompt_5 = f"""You are a helpful SQL assistant.The database is PostgreSQL.
Based on the SQL statement provided, check whether it is a valid SQL statement.
Check syntax, table names, column names, and any other potential issues.
Check for syntax errors, carefully. 
CHECK FOR SYNTAX ERRORS. 
CHECK IF THE RIGHT DATA TYPES ARE USED WHEN QUERYING THE COLUMNS.
If the SQL statement is valid, return the statement as is.
If the SQL statement is invalid, return the corrected SQL statement.
Only return the SQL statement, no other text. 
NOTHING ELSE. I ONLY WANT THE SQL STATEMENT.
SQL Statement: {response_4['message']['content']}
table names: {selected_tables}
column names: {response_3['message']['content']}
table uses: {table_uses}"""
response_5 = ollama.chat(
    model='gemma3:latest',
    messages=[
        {'role': 'user', 'content': prompt_5}
    ]
)
print("response 5:", response_5['message']['content'])

cur.execute(clean_sql_output(response_5['message']['content']))
results = cur.fetchall()

# Format output string
result_str = str(results)
prompt_6 = f"""You are a helpful assistant.
Based on the SQL query results provided and the user input, create a short explanation of the data returned from the database.
If the results are empty or there's an error, return a message saying "No data found or an error occurred."
SQL Query Results: {result_str}
User Input: {response_1['message']['content']}"""
# cur.close()
# conn.close()
response_6 = ollama.chat(
    model='gemma3:latest',
    messages=[
        {'role': 'user', 'content': prompt_6}
    ]
)
print("response 6:", response_6['message']['content'])