import datetime
import logging
import strawberry
import os
import json

from typing import List
from pathlib import Path
from dotenv import load_dotenv
from app.config import Config
from rosetta import Events, Observables, Sender

from app.types.datafaker import FakerTypeEnum, DataFakerInput, DataFakerOutput, DetailedScenarioStep, DetailedScenarioInput, DetailedScenarioOutput
from app.types.sender import WorkerActionEnum, DataWorkerCreateInput, DataWorkerActionInput, WorkerOutput, \
    WorkerStatusOutput, ScenarioWorkerCreateInput, WorkerTypeEnum, ScenarioQueryWorkerCreateInput
from app.types.scenarios import ScenarioInput

from app.helper import scenario_sender_data

# Load environment variables from .env file if it exists
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()
XSIAM_URL = os.environ.get("XSIAM_URL")
XSIAM_ID = os.environ.get("XSIAM_ID")
XSIAM_KEY = os.environ.get("XSIAM_KEY")

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

workers = {}


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
        required_fields = request_input.required_fields
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
        elif request_input.type == FakerTypeEnum.JSON:
            data = Events.json(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj,
                            vendor=vendor, product=request_input.product, version=request_input.version,
                            required_fields=required_fields)
        elif request_input.type == FakerTypeEnum.WINEVENT:
            data = Events.winevent(count=request_input.count, datetime_iso=datetime_obj, observables=observables_obj)
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
                    datetime_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
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

