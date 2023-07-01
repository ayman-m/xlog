import datetime
from typing import List
import strawberry

from app.config import Config
from rosetta import Events, Observables, Sender

from app.types.datafaker import FakerTypeEnum, DataFakerInput, DataFakerOutput
from app.types.sender import WorkerActionEnum, DataWorkerCreateInput, DataWorkerActionInput, DataWorkerOutput, \
    DataWorkerStatusOutput

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
        if request_input.timestamp:
            datetime_obj = datetime.datetime.strptime(request_input.timestamp, "%Y-%m-%d %H:%M:%S")
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
        if request_input.type == FakerTypeEnum.SYSLOG:
            data = Events.syslog(count=request_input.count, timestamp=datetime_obj, observables=observables_obj)
        elif request_input.type == FakerTypeEnum.CEF:
            data = Events.cef(count=request_input.count, timestamp=datetime_obj, observables=observables_obj,
                              vendor=vendor, product=request_input.product, version=request_input.version)
        elif request_input.type == FakerTypeEnum.LEEF:
            data = Events.leef(count=request_input.count, timestamp=datetime_obj, observables=observables_obj,
                               vendor=vendor, product=request_input.product, version=request_input.version)
        elif request_input.type == FakerTypeEnum.WINEVENT:
            data = Events.winevent(count=request_input.count, timestamp=datetime_obj, observables=observables_obj)
        elif request_input.type == FakerTypeEnum.JSON:
            data = Events.json(count=request_input.count, timestamp=datetime_obj, observables=observables_obj,
                               vendor=vendor, product=request_input.product, version=request_input.version)
        elif request_input.type == FakerTypeEnum.Incident:
            data = Events.incidents(count=request_input.count, fields=request_input.fields, timestamp=datetime_obj,
                                    observables=observables_obj, vendor=vendor, product=request_input.product,
                                    version=request_input.version)
        return DataFakerOutput(
            data=data,
            type=request_input.type,
            count=request_input.count
        )

    @strawberry.field(description="Create a data worker.")
    def data_worker_create(self, request_input: DataWorkerCreateInput) -> DataWorkerOutput:
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
        observables_obj = None
        if request_input.timestamp:
            datetime_obj = datetime.datetime.strptime(request_input.timestamp, "%Y-%m-%d %H:%M:%S")
        else:
            datetime_obj = None
        worker_name = f"worker_{now.strftime('%Y%m%d%H%M%S')}"
        observables = request_input.observables_dict
        vendor = request_input.vendor or "XLog"
        if request_input.observables_dict:
            incident_types, analysts, severity, terms, src_host, user, process, cmd, dst_ip, protocol, url, \
                dst_port, action, event_id, src_ip, file_hash, techniques, error_code, file_name, cve = \
                observables.get('incident_types', None), observables.get('analysts', None),\
                observables.get('severity', None), observables.get('terms', None), \
                observables.get('src_host', None), observables.get('user', None), observables.get('process', None), \
                observables.get('cmd', None), observables.get('dst_ip', None), observables.get('protocol', None), \
                observables.get('url', None), observables.get('dst_port', None), observables.get('action', None), \
                observables.get('event_id', None), observables.get('src_ip', None), \
                observables.get('file_hash', None), observables.get('techniques', None), \
                observables.get('error_code', None), observables.get('file_name', None), \
                observables.get('cve', None)
            observables_obj = Observables(incident_types=incident_types, analysts=analysts, severity=severity,
                                          terms=terms, src_host=src_host, user=user, process=process, cmd=cmd,
                                          dst_ip=dst_ip, protocol=protocol, url=url, port=dst_port, action=action,
                                          event_id=event_id, src_ip=src_ip, file_hash=file_hash,
                                          technique=techniques, error_code=error_code, file_name=file_name, cve=cve)
        print (vendor)
        data_worker = Sender(worker_name=worker_name, data_type=request_input.type.name,
                             count=int(request_input.count), destination=request_input.destination,
                             vendor=vendor, product=request_input.product, version=request_input.version,
                             observables=observables_obj, interval=int(request_input.interval),
                             datetime_obj=datetime_obj, fields=request_input.fields,
                             verify_ssl=request_input.verify_ssl)
        workers[worker_name] = data_worker
        data_worker.start()
        return DataWorkerOutput(type=data_worker.data_type, worker=data_worker.worker_name, status=data_worker.status,
                                count=data_worker.count, interval=data_worker.interval,
                                destination=data_worker.destination, verifySsl=str(data_worker.verify_ssl),
                                createdAt=str(data_worker.created_at))

    @strawberry.field(description="Get a list of data workers.")
    def data_worker_list(self) -> List[DataWorkerOutput]:
        """
        Get a list of active data workers.

        Returns:
            List[DataWorkerOutput]: List of data worker objects containing information about each worker.

        """
        workers_data = []
        for worker in workers.keys():
            workers_data.append(DataWorkerOutput(type=workers[worker].data_type, worker=workers[worker].worker_name,
                                                 status=workers[worker].status, count=workers[worker].count,
                                                 interval=workers[worker].interval,
                                                 verifySsl=workers[worker].verify_ssl,
                                                 destination=workers[worker].destination,
                                                 createdAt=str(workers[worker].created_at)))
        return workers_data

    @strawberry.field(description="Perform an action on a data worker.")
    def data_worker_action(self, request_input: DataWorkerActionInput) -> DataWorkerStatusOutput:
        """
        Perform an action on a data worker, such as stopping it.

        Args:
            request_input: Input object containing the worker ID and the action to perform.

        Returns:
            DataWorkerStatusOutput: Output object containing the worker ID and the status after the action.

        """
        if workers.get(request_input.worker):
            if request_input.action == WorkerActionEnum.Stop:
                workers[request_input.worker].stop()
                workers.pop(request_input.worker)
                return DataWorkerStatusOutput(worker=request_input.worker,
                                              status='Stopped')
            return DataWorkerStatusOutput(worker=workers[request_input.worker].worker_name,
                                          status=workers[request_input.worker].status)
        return DataWorkerStatusOutput(worker=request_input.worker, status="Worker not found.")


schema = strawberry.Schema(query=Query)
