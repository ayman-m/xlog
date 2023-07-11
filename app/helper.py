import json
import datetime
from rosetta import Events, Observables, Sender

from app.config import Config
from app.types.datafaker import FakerTypeEnum, DataFakerInput, DataFakerOutput
from app.types.sender import WorkerActionEnum, DataWorkerCreateInput, DataWorkerActionInput, WorkerOutput, \
    WorkerStatusOutput, ScenarioWorkerCreateInput


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
