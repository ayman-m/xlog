
#region Imports
import os
import datetime
import logging
import strawberry
import os
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
XSIAM_MANDATORY_PARSED_FIELDS = 'remote_ip,remote_port,local_ip,local_port,event_timestamp,severity,alert_name'
XSIAM_OPTIONAL_PARSED_FIELDS = 'optional_parsed_fields,alert_description,action_status,local_ip_v6,remote_ip_v6'
#endregion

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

@strawberry.type(description="Root query type.")
class Query:
    @strawberry.field(description="Generate fake data.")
    def generate_fake_data(self, request_input: DataFakerInput) -> DataFakerOutput:
        """
        Generate fake data based on the provided input.
        Args:
            request_input: Input object containing the type of fake data to generate and additional options.
        Returns:
            DataFakerOutput: Output object containing the generated fake data.
        """
        data = []
        vendor = request_input.vendor or "XLog"
        if request_input.datetime_iso:
            datetime_obj = datetime.datetime.strptime(request_input.datetime_iso, "%Y-%m-%d %H:%M:%S")
        else:
            datetime_obj = None
        observables_init = Observables()
        observables = request_input.observables_dict
        required_fields = request_input.observables_dict
        if required_fields:
            required_fields = ",".join([field.value for field in request_input.required_fields])
        if observables:
            observables_data = {}
            for key, value in observables.__dict__.items():
                if value is not None and key in observables_init.__dict__:
                    observables_data[key] = value
            observables_obj = Observables(**observables_data)
        else:
            observables_obj = None
        if request_input.type == FakerTypeEnum.SYSLOG:
            data = Events.syslog(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                required_fields=required_fields)
        elif request_input.type == FakerTypeEnum.CEF:
            data = Events.cef(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                            vendor=vendor, product=request_input.product, version=request_input.version,
                            required_fields=required_fields)
        elif request_input.type == FakerTypeEnum.LEEF:
            data = Events.leef(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                            vendor=vendor, product=request_input.product, version=request_input.version,
                            required_fields=required_fields)
        elif request_input.type == FakerTypeEnum.WINEVENT:
            data = Events.winevent(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj)
        elif request_input.type == FakerTypeEnum.JSON:
            data = Events.json(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                            vendor=vendor, product=request_input.product, version=request_input.version,
                            required_fields=required_fields)
        elif request_input.type == FakerTypeEnum.Incident:
            data = Events.incidents(count=request_input.count, fields=request_input.fields, datetime_iso=datetime_obj,
                                    observables=observables_obj, vendor=vendor, product=request_input.product,
                                    version=request_input.version, required_fields=required_fields)
        elif request_input.type == FakerTypeEnum.XSIAM_Parsed:
            xsiam_alerts = []
            mandatory_fields = Config.XSIAM_MANDATORY_PARSED_FIELDS
            optional_fields = Config.XSIAM_OPTIONAL_PARSED_FIELDS
            total_fields = mandatory_fields+","+optional_fields+",vendor,product,event_timestamp"
            raw_data = Events.json(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                vendor=vendor, product=request_input.product, version=request_input.version,
                                required_fields=mandatory_fields)
            for item in raw_data:
                if "datetime_iso" in item:
                    timestamp = item.pop("datetime_iso")
                    datetime_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
                    event_timestamp = int(datetime_obj.timestamp() * 1000)
                    item["event_timestamp"] = event_timestamp
                new_item = {}
                for key in item.keys():
                    if key in total_fields.split(","):
                        new_item[key] = item[key]
                xsiam_alerts.append(new_item)
            data = xsiam_alerts

        # Log each entry generated
        logger.info(f"Generated {len(data)} {request_input.type} log entries.")

        return DataFakerOutput(
            data=data,
            type=request_input.type,
            count=request_input.count
        )

    @strawberry.field(description="Generate fake scenario data based on the provided input.")
    def generate_scenario_fake_data(self, request_input: DetailedScenarioInput) -> DetailedScenarioOutput:
        """
        Generate fake data for a scenario with multiple steps and logs.
        
        Args:
            request_input: The input object containing the scenario details and log steps.
        
        Returns:
            DetailedScenarioOutput: The output object containing the generated fake data.
        """
        scenario_steps = []

        # Iterate over each step in the scenario
        for step in request_input.steps:
            step_data = {}
            step_data['tactic'] = step.tactic
            step_data['tactic_id'] = step.tactic_id
            step_data['technique'] = step.technique
            step_data['technique_id'] = step.technique_id
            step_data['procedure'] = step.procedure
            step_data['type'] = step.type
            step_data["logs"] = []

            # For each log in the step, generate fake data
            for log_input in step.logs:
                data = []
                vendor = log_input.vendor or "XLog"
                if log_input.datetime_iso:
                    datetime_obj = datetime.datetime.strptime(log_input.datetime_iso, "%Y-%m-%d %H:%M:%S")
                else:
                    datetime_obj = None
                observables_init = Observables()
                observables = log_input.observables_dict
                required_fields = ",".join([field.value for field in log_input.required_fields])
                if observables:
                    observables_data = {}
                    for key, value in observables.__dict__.items():
                        if value is not None and key in observables_init.__dict__:
                            observables_data[key] = value
                    observables_obj = Observables(**observables_data)
                else:
                    observables_obj = None
                if log_input.type == FakerTypeEnum.SYSLOG:
                    data = Events.syslog(count=log_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                        required_fields=required_fields)
                elif log_input.type == FakerTypeEnum.CEF:
                    data = Events.cef(count=log_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                    vendor=vendor, product=log_input.product, version=log_input.version,
                                    required_fields=required_fields)
                elif log_input.type == FakerTypeEnum.LEEF:
                    data = Events.leef(count=log_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                    vendor=vendor, product=log_input.product, version=log_input.version,
                                    required_fields=required_fields)
                elif log_input.type == FakerTypeEnum.WINEVENT:
                    data = Events.winevent(count=log_input.count, datetime_iso=datetime_obj, observables=observables_obj)
                elif log_input.type == FakerTypeEnum.JSON:
                    data = Events.json(count=log_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                    vendor=vendor, product=log_input.product, version=log_input.version,
                                    required_fields=required_fields)
                elif log_input.type == FakerTypeEnum.Incident:
                    data = Events.incidents(count=log_input.count, fields=log_input.fields, datetime_iso=datetime_obj,
                                            observables=observables_obj, vendor=vendor, product=log_input.product,
                                            version=log_input.version, required_fields=required_fields)
                elif log_input.type == FakerTypeEnum.XSIAM_Parsed:
                    xsiam_alerts = []
                    mandatory_fields = Config.XSIAM_MANDATORY_PARSED_FIELDS
                    optional_fields = Config.XSIAM_OPTIONAL_PARSED_FIELDS
                    total_fields = mandatory_fields+","+optional_fields+",vendor,product,event_timestamp"
                    raw_data = Events.json(count=log_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                        vendor=vendor, product=log_input.product, version=log_input.version,
                                        required_fields=mandatory_fields)
                    for item in raw_data:
                        if "datetime_iso" in item:
                            timestamp = item.pop("datetime_iso")
                            datetime_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
                            event_timestamp = int(datetime_obj.timestamp() * 1000)
                            item["event_timestamp"] = event_timestamp
                        new_item = {}
                        for key in item.keys():
                            if key in total_fields.split(","):
                                new_item[key] = item[key]
                        xsiam_alerts.append(new_item)
                    data = xsiam_alerts

                logger.info(f"Generated {len(data)} {log_input.type} log entries of scenario: {request_input.name}.")

                # Append the generated fake data to the step data
                step_data["logs"].append(data)
            
            # Add step data to the scenario data
            scenario_steps.append(step_data)

        return DetailedScenarioOutput(
            name=request_input.name,
            tags=request_input.tags,
            steps=scenario_steps
        )

    @strawberry.field(description="Create a data worker.")
    def create_data_worker(self, request_input: DataWorkerCreateInput) -> WorkerOutput:
        """
        Create a data worker for sending fake data.

        Args:
            request_input: Input object containing the options for creating a data worker.

        Returns:
            DataWorkerOutput: Output object containing information about the created data worker.

        """
        global workers
        active_workers = {}
        for worker_id, worker in workers.items():
            if worker.status == 'Running':
                active_workers[worker_id] = worker
        workers = active_workers
        if len(workers.keys()) >= int(Config.WORKERS_NUMBER):
            raise Exception("All workers are busy, please stop a running worker.")
        now = datetime.datetime.now()
        worker_name = f"worker_{now.strftime('%Y%m%d%H%M%S')}"

        if request_input.datetime_iso:
            datetime_obj = datetime.datetime.strptime(request_input.datetime_iso, "%Y-%m-%d %H:%M:%S")
        else:
            datetime_obj = None
        observables_init = Observables()
        observables = request_input.observables_dict
        if observables:
            observables_data = {}
            for key, value in observables.items():
                if value is not None and key in observables_init.__dict__:
                    observables_data[key] = value
            observables_obj = Observables(**observables_data)
        else:
            observables_obj = None
        required_fields = request_input.required_fields
        vendor = request_input.vendor or "XLog"
        if request_input.destination == "XSIAM":
            headers = {
                "Authorization": XSIAM_KEY,
                "x-xdr-auth-id": XSIAM_ID
            }
            xsiam_alerts = []
            if request_input.type == WorkerTypeEnum.JSON:

                xsiam_destination = XSIAM_URL + "/public_api/v1/alerts/insert_parsed_alerts"
                mandatory_fields = Config.XSIAM_MANDATORY_PARSED_FIELDS
                optional_fields = Config.XSIAM_OPTIONAL_PARSED_FIELDS
                total_fields = mandatory_fields+","+optional_fields+",vendor,product,event_timestamp"
                raw_data = Events.json(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                                    vendor=vendor, product=request_input.product, version=request_input.version,
                                    required_fields=mandatory_fields)
                for item in raw_data:
                    if "datetime_iso" in item:
                        timestamp = item.pop("datetime_iso")
                        datetime_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
                        event_timestamp = int(datetime_obj.timestamp() * 1000)
                        item["event_timestamp"] = event_timestamp
                    new_item = {}
                    for key in item.keys():
                        if key in total_fields.split(","):
                            new_item[key] = item[key]
                    xsiam_alerts.append(new_item)
                data_json = {
                    "request_data": {
                        "alerts": xsiam_alerts
                    }
                }
                data_worker = Sender(worker_name=worker_name, data_type="JSON",
                                     destination=xsiam_destination, data_json=data_json,
                                     verify_ssl=request_input.verify_ssl, headers=headers)
            else:
                xsiam_destination = XSIAM_URL + "/public_api/v1/alerts/insert_cef_alerts"
                xsiam_alerts = Events.cef(count=request_input.count, datetime_iso=datetime_obj,
                                          observables=observables_obj, vendor=vendor, product=request_input.product,
                                          version=request_input.version, required_fields=request_input.required_fields)
                data_json = {
                    "request_data": {
                        "alerts": xsiam_alerts
                    }
                }
                data_worker = Sender(worker_name=worker_name, data_type="JSON",
                                     destination=xsiam_destination, data_json=data_json,
                                     verify_ssl=request_input.verify_ssl, headers=headers)
        else:
            data_worker = Sender(worker_name=worker_name, data_type=request_input.type.name,
                                 count=int(request_input.count), destination=request_input.destination,
                                 vendor=vendor, product=request_input.product, version=request_input.version,
                                 observables=observables_obj, interval=int(request_input.interval),
                                 datetime_obj=datetime_obj, required_fields=required_fields,
                                 fields=request_input.fields, verify_ssl=request_input.verify_ssl)
        workers[worker_name] = data_worker
        data_worker.start()
        return WorkerOutput(type=data_worker.data_type, worker=data_worker.worker_name, status=data_worker.status,
                            count=data_worker.count, interval=data_worker.interval,
                            destination=data_worker.destination, verifySsl=str(data_worker.verify_ssl),
                            createdAt=str(data_worker.created_at))

    @strawberry.field(description="Create a scenario worker from file.")
    def create_scenario_worker(self, request_input: ScenarioWorkerCreateInput) -> List[WorkerOutput]:
        """
        Create a scenario worker for sending fake data.

        Args:
            request_input: Input object containing the options for creating a data worker.

        Returns:
            WorkerOutput: Output object containing information about the created data worker.

        """
        global workers
        scenario_workers_output = []
        active_workers = {}
        for worker_id, worker in workers.items():
            if worker.status == 'Running':
                active_workers[worker_id] = worker
        workers = active_workers
        if len(workers.keys()) >= int(Config.WORKERS_NUMBER):
            raise Exception("All workers are busy, please stop a running worker.")
        if request_input.datetime_iso:
            datetime_obj = datetime.datetime.strptime(request_input.datetime_iso, "%Y-%m-%d %H:%M:%S")
        else:
            datetime_obj = None
        vendor = request_input.vendor or "XLog"
        try:
            with open(f'scenarios/ready/{request_input.scenario}.json', 'r') as file:
                scenario_tactics = json.load(file)['tactics']
        except FileNotFoundError:
            raise FileNotFoundError(f"The scenario: '{request_input.scenario}' file does not exist.")
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding JSON in scenario file '{request_input.scenario}.json': {str(e)}")

        if scenario_tactics:
            for tactic in scenario_tactics:
                now = datetime.datetime.now()
                worker_name = f"worker_{now.strftime('%Y%m%d%H%M%S')}"
                interval = tactic.get('interval') or 1
                count = tactic.get('count') or 1
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
                logger.info(f"Creating worker for type={tactic.get('type')}, count={count}, destination={request_input.destination}")
                logger.info(f"Observables: {observables_obj}, Required Fields: {tactic.get('required_fields')}")
                scenario_worker = Sender(worker_name=worker_name, data_type=tactic['type'],
                                         count=count, destination=request_input.destination,
                                         vendor=vendor, product=tactic['log'].get('product'),
                                         version=tactic['log'].get('version'), observables=observables_obj,
                                         interval=interval, datetime_obj=datetime_obj,
                                         required_fields=tactic.get('required_fields'),
                                         fields=tactic.get('fields'))
                workers[worker_name] = scenario_worker
                scenario_worker.start()
                scenario_workers_output.append(WorkerOutput(type=scenario_worker.data_type,
                                                            worker=scenario_worker.worker_name,
                                                            status=scenario_worker.status,
                                                            count=scenario_worker.count,
                                                            interval=scenario_worker.interval,
                                                            destination=scenario_worker.destination,
                                                            verifySsl=str(scenario_worker.verify_ssl),
                                                            createdAt=str(scenario_worker.created_at)))
        return scenario_workers_output

    @strawberry.field(description="Create a scenario worker from query.")
    def create_scenario_worker_from_query(self, request_input: ScenarioQueryWorkerCreateInput) -> List[WorkerOutput]:
        """
        Create scenario workers for sending fake data based on scenario steps provided in the request input.

        Args:
            request_input: Input object containing the options for creating data workers, including scenario steps.

        Returns:
            List[WorkerOutput]: Output list containing information about the created data workers.
        """

        global workers
        scenario_workers_output = []
        active_workers = {}

        # Clean up inactive workers
        for worker_id, worker in workers.items():
            if worker.status == 'Running':
                active_workers[worker_id] = worker
        workers = active_workers

        # Check if maximum number of workers is reached
        if len(workers.keys()) >= int(Config.WORKERS_NUMBER):
            raise Exception("All workers are busy, please stop a running worker.")

        # Get scenario steps from request_input
        scenario_steps = request_input.steps

        if scenario_steps:
            for step in scenario_steps:
                # Each step may have multiple logs
                for log_input in step.logs:
                    now = datetime.datetime.now()
                    worker_name = f"worker_{now.strftime('%Y%m%d%H%M%S')}"

                    interval = log_input.interval or 1
                    count = log_input.count or 1

                    # Parse datetime if provided
                    if log_input.datetime_iso:
                        datetime_obj = datetime.datetime.strptime(log_input.datetime_iso, "%Y-%m-%d %H:%M:%S")
                    else:
                        datetime_obj = None

                    # Obtain vendor from log_input
                    vendor = log_input.vendor or "XLog"

                    # Initialize observables
                    observables_init = Observables()
                    observables = log_input.observables_dict
                    if observables:
                        observables_data = {}
                        for key, value in observables.__dict__.items():
                            if value is not None and key in observables_init.__dict__:
                                observables_data[key] = value
                        observables_obj = Observables(**observables_data)
                    else:
                        observables_obj = None

                    # Prepare required fields
                    required_fields = ",".join([field.value for field in log_input.required_fields])

                    logger.info(f"Creating worker for type={log_input.type.name}, count={count}, destination={request_input.destination}")
                    logger.info(f"Observables: {observables_obj}, Required Fields: {required_fields}")
                    
                    # Create a worker for this log input
                    scenario_worker = Sender(
                        worker_name=worker_name,
                        data_type=log_input.type.name,
                        count=count,
                        destination=request_input.destination,
                        vendor=vendor,
                        product=log_input.product,
                        version=log_input.version,
                        observables=observables_obj,
                        interval=interval,
                        datetime_obj=datetime_obj,
                        required_fields=required_fields,
                        fields=log_input.fields
                    )

                    # Store and start the worker
                    workers[worker_name] = scenario_worker
                    scenario_worker.start()

                    # Collect output information
                    scenario_workers_output.append(
                        WorkerOutput(
                            type=scenario_worker.data_type,
                            worker=scenario_worker.worker_name,
                            status=scenario_worker.status,
                            count=scenario_worker.count,
                            interval=scenario_worker.interval,
                            destination=scenario_worker.destination,
                            verifySsl=str(scenario_worker.verify_ssl),
                            createdAt=str(scenario_worker.created_at)
                        )
                    )
        else:
            raise ValueError("No scenario steps provided in the request input.")

        return scenario_workers_output

    @strawberry.field(description="Get a list of data workers.")
    def list_workers(self) -> List[WorkerOutput]:
        """
        Get a list of active data workers.

        Returns:
            List[DataWorkerOutput]: List of data worker objects containing information about each worker.

        """
        workers_data = []
        for worker in workers.keys():
            workers_data.append(WorkerOutput(type=workers[worker].data_type, worker=workers[worker].worker_name,
                                             status=workers[worker].status, count=workers[worker].count,
                                             interval=workers[worker].interval,
                                             verifySsl=workers[worker].verify_ssl,
                                             destination=workers[worker].destination,
                                             createdAt=str(workers[worker].created_at)))
        return workers_data

    @strawberry.field(description="Perform an action on a data worker.")
    def action_worker(self, request_input: DataWorkerActionInput) -> WorkerStatusOutput:
        """
        Perform an action on a data worker, such as stopping it.

        Args:
            request_input: Input object containing the worker ID and the action to perform.

        Returns:
            WorkerStatusOutput: Output object containing the worker ID and the status after the action.

        """
        if workers.get(request_input.worker):
            if request_input.action == WorkerActionEnum.STOP:
                workers[request_input.worker].stop()
                workers.pop(request_input.worker)
                return WorkerStatusOutput(worker=request_input.worker,
                                              status='Stopped')
            return WorkerStatusOutput(worker=workers[request_input.worker].worker_name,
                                          status=workers[request_input.worker].status)
        return WorkerStatusOutput(worker=request_input.worker, status="Worker not found.")

schema = strawberry.Schema(query=Query)


app = FastAPI()
app.add_route("/", GraphQL(schema=schema))

workers = {}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="info")
