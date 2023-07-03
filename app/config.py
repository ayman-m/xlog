import yaml


class Config:
    with open('config.yml', 'r') as file:
        config = yaml.safe_load(file)
    WORKERS_NUMBER = config.get('workers', {}).get('number', '25')
    LOGGING_DIR = config.get('logging', {}).get('directory', 'logs')
    LOGGING_STORAGE_SIZE = config.get('logging', {}).get('storage', '10M')
    LOGGING_TRUNCATE_LIMIT = config.get('logging', {}).get('truncate', '100')
    XSIAM_MANDATORY_PARSED_FIELDS = config.get('xsiam', {}).get('mandatory_parsed_fields', 'remote_ip,remote_port,'
                                                                                           'local_ip,local_port,'
                                                                                           'event_timestamp,'
                                                                                           'severity,alert_name')
    XSIAM_OPTIONAL_PARSED_FIELDS = config.get('xsiam', {}).get('optional_parsed_fields', 'alert_description,action_'
                                                                                         'status,local_ip_v6,'
                                                                                         'remote_ip_v6')
