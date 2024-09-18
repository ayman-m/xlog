import datetime
import strawberry
import os
import json

from typing import List
from pathlib import Path
from dotenv import load_dotenv
from app.config import Config
from rosetta import Events, Observables, Sender

from app.types.datafaker import FakerTypeEnum, DataFakerInput, DataFakerOutput
from app.types.sender import WorkerActionEnum, DataWorkerCreateInput, DataWorkerActionInput, WorkerOutput, \
    WorkerStatusOutput, ScenarioWorkerCreateInput, WorkerTypeEnum
from app.types.scenarios import ScenarioInput

from app.helper import scenario_sender_data

# Load environment variables from .env file if it exists
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()
XSIAM_URL = os.environ.get("XSIAM_URL")
XSIAM_ID = os.environ.get("XSIAM_ID")
XSIAM_KEY = os.environ.get("XSIAM_KEY")


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
        if observables:
            observables_data = {}
            for key, value in observables.items():
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

        return DataFakerOutput(
            data=data,
            type=request_input.type,
            count=request_input.count
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

    @strawberry.field(description="Create a scenario worker.")
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
            if request_input.action == WorkerActionEnum.Stop:
                workers[request_input.worker].stop()
                workers.pop(request_input.worker)
                return WorkerStatusOutput(worker=request_input.worker,
                                              status='Stopped')
            return WorkerStatusOutput(worker=workers[request_input.worker].worker_name,
                                          status=workers[request_input.worker].status)
        return WorkerStatusOutput(worker=request_input.worker, status="Worker not found.")

@strawberry.type(description="Root mutation type.")
class Mutation:
    @strawberry.mutation(description="Create a new scenario.")
    def create_scenario(self, scenario_input: ScenarioInput) -> str:
        """
        Create a new scenario based on the provided input.

        Args:
            scenario_input: Input object containing the scenario details.

        Returns:
            str: A message indicating the scenario was created successfully.
        """
        # Implement logic to save the scenario, e.g., to a database or file.
        # For simplicity, let's save it as a JSON file.
        scenario_data = {
            'name': scenario_input.name,
            'description': scenario_input.description,
            'tactics': [tactic.__dict__ for tactic in scenario_input.tactics]
        }
        scenario_file = f'scenarios/ready/{scenario_input.name}.json'
        with open(scenario_file, 'w') as file:
            json.dump(scenario_data, file, indent=4)
        return f"Scenario '{scenario_input.name}' created successfully."

    @strawberry.mutation(description="Delete an existing scenario.")
    def delete_scenario(self, name: str) -> str:
        """
        Delete a scenario by name.

        Args:
            name: The name of the scenario to delete.

        Returns:
            str: A message indicating the scenario was deleted successfully.
        """
        scenario_file = f'scenarios/ready/{name}.json'
        if os.path.exists(scenario_file):
            os.remove(scenario_file)
            return f"Scenario '{name}' deleted successfully."
        else:
            return f"Scenario '{name}' does not exist."


schema = strawberry.Schema(query=Query, mutation=Mutation)

