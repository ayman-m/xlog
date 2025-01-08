import asyncio
import os
import datetime
import logging
import strawberry
import json
import yaml

from fastapi import FastAPI
from strawberry.asgi import GraphQL
from strawberry.scalars import JSON
from enum import Enum
from typing import Optional, List
from pathlib import Path
from dotenv import load_dotenv
from rosetta import Events, Observables, Sender

PARAMS = demisto.params()
XSIAM_URL = PARAMS.get("XSIAM_URL")
XSIAM_ID = PARAMS.get("XSIAM_ID")
XSIAM_KEY = PARAMS.get("XSIAM_KEY")
WORKERS_NUMBER = PARAMS.get("WORKERS_NUMBER")
XSIAM_MANDATORY_PARSED_FIELDS = PARAMS.get("XSIAM_MANDATORY_PARSED_FIELDS")
XSIAM_OPTIONAL_PARSED_FIELDS = PARAMS.get("XSIAM_OPTIONAL_PARSED_FIELDS")


#region Types

#region DataFaker Types
@strawberry.enum(description="Enum representing the types of required fields.")
class RequiredFieldEnum(Enum):
    LOCAL_IP = "local_ip"
    REMOTE_IP = "remote_ip"
    SRC_HOST = "src_host"
    DST_HOST = "dst_host"
    SENDER_EMAIL = "sender_email"
    RECIPIENT_EMAIL = "recipient_email"
    LOCAL_IP_V6 = "local_ip_v6"
    REMOTE_IP_V6 = "remote_ip_v6"
    SRC_DOMAIN = "src_domain"
    DST_DOMAIN = "dst_domain"
    EMAIL_SUBJECT = "email_subject"
    EMAIL_BODY = "email_body"
    URL = "url"
    LOCAL_PORT = "local_port"
    REMOTE_PORT = "remote_port"
    PROTOCOL = "protocol"
    INBOUND_BYTES = "inbound_bytes"
    OUTBOUND_BYTES = "outbound_bytes"
    APP = "app"
    OS = "os"
    USER = "user"
    CVE = "cve"
    FILE_NAME = "file_name"
    FILE_HASH = "file_hash"
    WIN_CMD = "win_cmd"
    UNIX_CMD = "unix_cmd"
    WIN_PROCESS = "win_process"
    WIN_CHILD_PROCESS = "win_child_process"
    UNIX_PROCESS = "unix_process"
    UNIX_CHILD_PROCESS = "unix_child_process"
    TECHNIQUE = "technique"
    ENTRY_TYPE = "entry_type"
    SEVERITY = "severity"
    SENSOR = "sensor"
    ACTION = "action"
    EVENT_ID = "event_id"
    ERROR_CODE = "error_code"
    TERMS = "terms"
    INCIDENT_TYPES = "incident_types"
    ANALYSTS = "analysts"
    ALERT_TYPES = "alert_types"
    ALERT_NAME = "alert_name"
    ACTION_STATUS = "action_status"
    QUERY_TYPE = "query_type"
    DATABASE_NAME = "database_name"
    QUERY = "query"
    USER_AGENT = "user_agent"
    REFERER = "referer"
    RESPONSE_CODE = "response_code"
    RESPONSE_SIZE = "response_size"
    ATTACK_TYPE = "attack_type"
    COOKIES = "cookies"
    GUID = "guid"
    TRANSMITTED_SERVICES = "transmitted_services"
    PROCESS_ID = "process_id"
    NEW_PROCESS_ID = "new_process_id"
    THREAD_ID = "thread_id"
    TARGET_PID = "target_pid"
    SUBJECT_LOGIN_ID = "subject_login_id"
    WIN_USER_ID = "win_user_id"
    DESTINATION_LOGIN_ID = "destination_login_id"
    PRIVILEGE_LIST = "privilege_list"
    EVENT_RECORD_ID = "event_record_id"
    SPAM_SCORE = "spam_score"
    SOURCE_NETWORK_ADDRESS = "source_network_address"
    ATTACHMENT_HASH = "attachment_hash"
    DURATION = "duration"
    LOG_ID = "log_id"
    PID = "pid"
    RULE_ID = "rule_id"
    DST_URL = "dst_url"
    METHOD = "method"
@strawberry.enum(description="Enum representing the types of fake data.")
class FakerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    Incident = 'incident'
    XSIAM_Parsed = 'xsiam_parsed'
    XSIAM_CEF = 'xsiam_cef'
@strawberry.input(description="Data observables dictionary.")
class ObservablesInput:
    local_ip: Optional[List[str]] = None
    remote_ip: Optional[List[str]] = None
    local_ip_v6: Optional[List[str]] = None
    remote_ip_v6: Optional[List[str]] = None
    src_host: Optional[List[str]] = None
    dst_host: Optional[List[str]] = None
    src_domain: Optional[List[str]] = None
    dst_domain: Optional[List[str]] = None
    sender_email: Optional[List[str]] = None
    recipient_email: Optional[List[str]] = None
    email_subject: Optional[List[str]] = None
    email_body: Optional[List[str]] = None
    url: Optional[List[str]] = None
    source_port: Optional[List[str]] = None
    remote_port: Optional[List[str]] = None
    protocol: Optional[List[str]] = None
    inbound_bytes: Optional[List[str]] = None
    outbound_bytes: Optional[List[str]] = None
    app: Optional[List[str]] = None
    os: Optional[List[str]] = None
    user: Optional[List[str]] = None
    cve: Optional[List[str]] = None
    file_name: Optional[List[str]] = None
    file_hash: Optional[List[str]] = None
    win_cmd: Optional[List[str]] = None
    unix_cmd: Optional[List[str]] = None
    win_process: Optional[List[str]] = None
    win_child_process: Optional[List[str]] = None
    unix_process: Optional[List[str]] = None
    unix_child_process: Optional[List[str]] = None
    technique: Optional[List[str]] = None
    entry_type: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    sensor: Optional[List[str]] = None
    action: Optional[List[str]] = None
    event_id: Optional[List[str]] = None
    error_code: Optional[List[str]] = None
    terms: Optional[List[str]] = None
    incident_types: Optional[List[str]] = None
    analysts: Optional[List[str]] = None
    alert_types: Optional[List[str]] = None
    alert_name: Optional[List[str]] = None
    action_status: Optional[List[str]] = None
    query_type: Optional[List[str]] = None
    database_name: Optional[List[str]] = None
    query: Optional[List[str]] = None
@strawberry.input(description="Input object for generating fake data.")
class DataFakerInput:
    type: FakerTypeEnum
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    count: Optional[int] = 1
    datetime_iso: Optional[str] = None
    fields: Optional[str] = None
    observables_dict: Optional[ObservablesInput] = None
    required_fields: Optional[List[RequiredFieldEnum]] = None
@strawberry.type(description="Output object containing the generated fake data.")
class DataFakerOutput:
    data: List[JSON]
    type: str
    count: int
@strawberry.input(description="Scenario step object for generating fake scenario data.")
class DetailedScenarioStep:
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    technique: Optional[str] = None
    technique_id:Optional[str] = None
    procedure:Optional[str] = None
    type: Optional[str] = None
    logs: List[DataFakerInput]
@strawberry.input(description="Scenario input object for generating fake scenario data.")
class DetailedScenarioInput:
    name: str
    tags:  Optional[List[str]] = None
    steps: List[DetailedScenarioStep]
@strawberry.type(description="Output object containing the generated fake data.")
class DetailedScenarioOutput:
    steps: List[JSON]
    name: str
    tags: Optional[List[str]] = None
#endregion

#region Scenarios Types
@strawberry.type
class TacticInput:
    name: str
    description: Optional[str] = None
    type: str  # e.g., 'CEF', 'JSON', etc.
    count: int
    interval: int
    required_fields: Optional[str] = None
    fields: Optional[str] = None
    observables: Optional[dict] = None
@strawberry.type
class ScenarioInput:
    name: str
    description: Optional[str] = None
    tactics: List[TacticInput]
#endregion

#region Sender Types
@strawberry.input(description="Data observables dictionary.")
class WorkerObservablesInput:
    local_ip: Optional[List[str]] = None
    remote_ip: Optional[List[str]] = None
    local_ip_v6: Optional[List[str]] = None
    remote_ip_v6: Optional[List[str]] = None
    src_host: Optional[List[str]] = None
    dst_host: Optional[List[str]] = None
    src_domain: Optional[List[str]] = None
    dst_domain: Optional[List[str]] = None
    sender_email: Optional[List[str]] = None
    recipient_email: Optional[List[str]] = None
    email_subject: Optional[List[str]] = None
    email_body: Optional[List[str]] = None
    url: Optional[List[str]] = None
    source_port: Optional[List[str]] = None
    remote_port: Optional[List[str]] = None
    protocol: Optional[List[str]] = None
    inbound_bytes: Optional[List[str]] = None
    outbound_bytes: Optional[List[str]] = None
    app: Optional[List[str]] = None
    os: Optional[List[str]] = None
    user: Optional[List[str]] = None
    cve: Optional[List[str]] = None
    file_name: Optional[List[str]] = None
    file_hash: Optional[List[str]] = None
    win_cmd: Optional[List[str]] = None
    unix_cmd: Optional[List[str]] = None
    win_process: Optional[List[str]] = None
    win_child_process: Optional[List[str]] = None
    unix_process: Optional[List[str]] = None
    unix_child_process: Optional[List[str]] = None
    technique: Optional[List[str]] = None
    entry_type: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    sensor: Optional[List[str]] = None
    action: Optional[List[str]] = None
    event_id: Optional[List[str]] = None
    error_code: Optional[List[str]] = None
    terms: Optional[List[str]] = None
    incident_types: Optional[List[str]] = None
    analysts: Optional[List[str]] = None
    alert_types: Optional[List[str]] = None
    alert_name: Optional[List[str]] = None
    action_status: Optional[List[str]] = None
    query_type: Optional[List[str]] = None
    database_name: Optional[List[str]] = None
    query: Optional[List[str]] = None
@strawberry.enum(description="Enum representing the types of required fields.")
class WorkerRequiredFieldEnum(Enum):
    LOCAL_IP = "local_ip"
    REMOTE_IP = "remote_ip"
    SRC_HOST = "src_host"
    DST_HOST = "dst_host"
    SENDER_EMAIL = "sender_email"
    RECIPIENT_EMAIL = "recipient_email"
    LOCAL_IP_V6 = "local_ip_v6"
    REMOTE_IP_V6 = "remote_ip_v6"
    SRC_DOMAIN = "src_domain"
    DST_DOMAIN = "dst_domain"
    EMAIL_SUBJECT = "email_subject"
    EMAIL_BODY = "email_body"
    URL = "url"
    LOCAL_PORT = "local_port"
    REMOTE_PORT = "remote_port"
    PROTOCOL = "protocol"
    INBOUND_BYTES = "inbound_bytes"
    OUTBOUND_BYTES = "outbound_bytes"
    APP = "app"
    OS = "os"
    USER = "user"
    CVE = "cve"
    FILE_NAME = "file_name"
    FILE_HASH = "file_hash"
    WIN_CMD = "win_cmd"
    UNIX_CMD = "unix_cmd"
    WIN_PROCESS = "win_process"
    WIN_CHILD_PROCESS = "win_child_process"
    UNIX_PROCESS = "unix_process"
    UNIX_CHILD_PROCESS = "unix_child_process"
    TECHNIQUE = "technique"
    ENTRY_TYPE = "entry_type"
    SEVERITY = "severity"
    SENSOR = "sensor"
    ACTION = "action"
    EVENT_ID = "event_id"
    ERROR_CODE = "error_code"
    TERMS = "terms"
    INCIDENT_TYPES = "incident_types"
    ANALYSTS = "analysts"
    ALERT_TYPES = "alert_types"
    ALERT_NAME = "alert_name"
    ACTION_STATUS = "action_status"
    QUERY_TYPE = "query_type"
    DATABASE_NAME = "database_name"
    QUERY = "query"
    USER_AGENT = "user_agent"
    REFERER = "referer"
    RESPONSE_CODE = "response_code"
    RESPONSE_SIZE = "response_size"
    ATTACK_TYPE = "attack_type"
    COOKIES = "cookies"
    GUID = "guid"
    TRANSMITTED_SERVICES = "transmitted_services"
    PROCESS_ID = "process_id"
    NEW_PROCESS_ID = "new_process_id"
    THREAD_ID = "thread_id"
    TARGET_PID = "target_pid"
    SUBJECT_LOGIN_ID = "subject_login_id"
    WIN_USER_ID = "win_user_id"
    DESTINATION_LOGIN_ID = "destination_login_id"
    PRIVILEGE_LIST = "privilege_list"
    EVENT_RECORD_ID = "event_record_id"
    SPAM_SCORE = "spam_score"
    SOURCE_NETWORK_ADDRESS = "source_network_address"
    ATTACHMENT_HASH = "attachment_hash"
    DURATION = "duration"
    LOG_ID = "log_id"
    PID = "pid"
    RULE_ID = "rule_id"
    DST_URL = "dst_url"
    METHOD = "method"
@strawberry.enum(description="Enum representing the types of workers.")
class WorkerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    Incident = 'incident'
    XSIAM_Parsed = 'xsiam_parsed'
    XSIAM_CEF = 'xsiam_cef'
@strawberry.enum(description="Enum representing the actions for a worker.")
class WorkerActionEnum(Enum):
    STOP = 'stop'
    STATUS = 'status'
@strawberry.input(description="Input object for creating a data worker.")
class DataWorkerCreateInput:
    type: WorkerTypeEnum
    count: int = 1
    interval: int = 2
    destination: str
    fields: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    observables_dict: Optional[JSON] = None
    required_fields: Optional[str] = None
    datetime_iso: Optional[str] = None
    verify_ssl: Optional[bool] = False
@strawberry.input(description="Input object for creating a scenario worker.")
class ScenarioWorkerCreateInput:
    count: int = 1
    interval: int = 2
    scenario: str
    destination: str
    vendor: Optional[str] = None
    datetime_iso: Optional[str] = None
    verify_ssl: Optional[bool] = False
@strawberry.input(description="Input object for performing an action on a data worker.")
class DataWorkerActionInput:
    worker: str
    action: WorkerActionEnum
@strawberry.type(description="Output object containing information about a data worker.")
class WorkerOutput:
    type: str
    worker: str
    status: str
    count: str
    interval: str
    verifySsl: str
    destination: str
    createdAt: str
@strawberry.type(description="Output object containing status information about a data worker.")
class WorkerStatusOutput:
    worker: str
    status: str
@strawberry.input(description="Input object for generating fake data.")
class WorkerFakerInput:
    type: WorkerTypeEnum
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    count: int = 1
    interval: int = 2
    datetime_iso: Optional[str] = None
    fields: Optional[str] = None
    observables_dict: Optional[WorkerObservablesInput] = None
    required_fields: Optional[List[WorkerRequiredFieldEnum]] = None
    verify_ssl: Optional[bool] = False
@strawberry.input(description="Scenario step object for generating fake scenario data.")
class DetailedQueryScenarioStep:
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    technique: Optional[str] = None
    technique_id:Optional[str] = None
    procedure:Optional[str] = None
    type: Optional[str] = None
    logs: List[WorkerFakerInput]
@strawberry.input(description="Input object for creating a scenario worker from a query.")
class ScenarioQueryWorkerCreateInput:
    name: str
    destination: str
    tags:  Optional[List[str]] = None
    steps: List[DetailedQueryScenarioStep]
#endregion

#endregion

#region HelperFunctions
def scenario_sender_data(scenario: str, destination: str, vendor: str, datetime_obj: datetime):
    try:
        with open(f'scenarios/ready/{scenario}.json', 'r') as file:
            scenario_tactics = json.load(file)['tactics']
    except FileNotFoundError:
        raise FileNotFoundError(f"The scenario: '{scenario}' file does not exist.")
    except json.JSONDecodeError as e:
        raise ValueError(f"Error decoding JSON in scenario file '{scenario}.json': {str(e)}")
    sender_data_objects = []
    if scenario_tactics:
        for tactic in scenario_tactics:
            observables_init = Observables()
            observables = tactic['log'].get('observables')
            if observables:
                observables_data = {}
                for key, value in observables.items():
                    if value is not None and key in observables_init.__dict__:
                        observables_data[key] = value
                observables_obj = Observables(**observables_data)
            else:
                observables_obj = None
            tactic["destination"] = destination
            if tactic.get("type") == "SYSLOG":
                tactic["data"] = Events.syslog(count=tactic['count'], datetime_iso=datetime_obj,
                                               observables=observables_obj,
                                               required_fields=tactic['log'].get('required_fields'))
                sender_data_objects.append(tactic)
            elif tactic.get("type") == "CEF":
                tactic["data"] = Events.cef(count=tactic['count'], datetime_iso=datetime_obj,
                                            observables=observables_obj,
                                            required_fields=tactic['log'].get('required_fields'), vendor=vendor,
                                            product=tactic['log'].get('product'),
                                            version=tactic['log'].get('version'))
                sender_data_objects.append(tactic)
            elif tactic.get("type") == "LEEF":
                tactic["data"] = Events.leef(count=tactic['count'], datetime_iso=datetime_obj,
                                             observables=observables_obj,
                                             required_fields=tactic['log'].get('required_fields'), vendor=vendor,
                                             product=tactic['log'].get('product'),
                                             version=tactic['log'].get('version'))
                sender_data_objects.append(tactic)
        return sender_data_objects
    else:
        return None
#endregion




app = FastAPI()

# Example route
@app.get("/")
async def read_root():
    demisto.info("Received a request on /")
    return {"message": "Hello, XSOAR!"}


# Long-running thread
async def run_fastapi_server():
    import uvicorn
    demisto.info("Starting FastAPI server")
    config = uvicorn.Config(app, host="0.0.0.0", port=8999, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

# Long-running integration function
def long_running_main():
    demisto.info("Starting long-running integration")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_fastapi_server())
    except Exception as e:
        demisto.error(f"An error occurred: {str(e)}")
    finally:
        loop.stop()
        loop.close()


def test_module():
    try:
        demisto.results('ok')
    except Exception as e:
        demisto.error(f"Health check failed: {str(e)}")



def main() -> None:
    commands = {
        'test-module': test_module,
        'long-running-execution': long_running_main
    }

    command_name: str = demisto.command()

    try:
        demisto.info(f'{command_name} started.')
        command_func = commands[command_name]
        support_multithreading()
        command_func()
    except Exception as e:
        return_error(str(e))
    finally:
        demisto.info(f'{command_name} completed.')  # type: ignore


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()