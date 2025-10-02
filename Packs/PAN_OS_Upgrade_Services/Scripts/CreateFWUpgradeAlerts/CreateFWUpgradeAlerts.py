import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import signal
import json
import re
import time

XQL = 'panosnetworkoperationsxql'
TARGET_FW = 'panosnetworkoperationstargetngfwsoftware'
TARGET_PAN = 'panosnetworkoperationstargetpanoramasoftware'
AUTO_UPGRD = 'panosnetworkoperationsautomaticupgrade'

TARGET_FW_WR = 'pan_os_network_operations_target_ngfw_software'
TARGET_PAN_WR = 'pan_os_network_operations_target_panorama_software'
AUTO_UP_WR = 'pan_os_network_operations_automatic_upgrade'
XQL_WR = 'pan_os_network_operations_xql'

# we need to have this retry wrapper, since we commonly have issues with XSIAM api calls failing.
def execute_command_with_retries(command, args, extract_contents=True, retries=3):
    errors = ""

    for attempt in range(retries):
        try:
            res = execute_command(command, args, extract_contents=extract_contents)
            demisto.debug(f'Attempt {attempt + 1}/{retries} successful: "{command}"')
            break

        except Exception as e:
            errors += str(e)
            demisto.debug(f'Attempt {attempt + 1}/{retries} failed: "{command}" Error: {e}')
            time.sleep(2 ** attempt)
    else:
        raise DemistoException(f'All {retries} attempts to execute "{command}" have failed. errors: {errors}')

    return res

def create_xql_for_serial(base_xql:str, serial:str) -> str:
    '''
    This takes the XQL for the batch alert and a device serial and creates a new XQL for that device
    '''
    match = re.match(r'\s*dataset\s*=\s*([\w_]+)', base_xql)
    dataset = match.group(1)
    return(f'dataset = {dataset} | filter serial = "{serial}"')

def get_playbook_id(playbook_name) -> str:
    '''
    Find the playbook id for the upgrade device playbook
    '''
    meta_response = demisto.internalHttpRequest(method='GET', uri='/playbooks/metadata')
    data = json.loads(meta_response.get('body'))

    for meta in data:
        if meta.get('name') == playbook_name:
            return meta.get('id')

def create_alert_dict(serial:str, xql:str, incident:str, domain:str, pbid:str, ver:str, auto:str, devtype:str) -> dict:
    '''
    Creates the alert dictionary for create_alert api call
    '''
    alert_xql = create_xql_for_serial(xql, serial)
    target_fld = TARGET_FW_WR
    if devtype == 'Panorama':
        target_fld = TARGET_PAN_WR
    alert_data = {
        'request_data': {
            'alert': {
                'vendor': 'PANW',
                'product': 'XSIAM Manual',
                'severity': 'medium',
                'category': 'PANOS Upgrade',
                'alert_name': f'PANOS Upgrade {serial}',
                'alert_domain': domain,
                'playbook': pbid,
                'description': f'{incident} - Upgrade for {serial}',
                XQL_WR: alert_xql,
                AUTO_UP_WR: auto,
                target_fld: ver
            }
        }
    }
    return alert_data

def main():

    args = demisto.args()

    devices = args.get('TargetDevices')
    version = args.get('TargetVersion')
    devtype = args.get('DeviceType', 'NGFW')
    domain = args.get('Domain', '')
    pb = args.get('Playbook', 'PAN-OS Network Operations - Device Upgrade')
    auto_up = argToBoolean(args.get('Auto', False))

    # get alert
    alert = demisto.alert()
    custom_fields = alert.get('CustomFields', {})

    # get current xql to find table name
    currentXql = custom_fields.get(XQL)

    # get parent incident id and domain
    if not domain:
        domain = custom_fields.get('alert_domain')
    incident = alert.get('parentXDRIncident')
    # auto_up = custom_fields.get(AUTO_UPGRD)

    # get playbook id - PAN-OS Network Operations - Device Upgrade
    pbid = get_playbook_id(pb)

    # convert devices into list
    devlist = []
    if isinstance(devices, str) and ',' in devices and '[' in devices:
        devlist = json.loads(devices)
    elif isinstance(devices, str) and ',' in devices:
        devlist = devices.split(',')
    else:
        devlist.extend(argToList(devices))

    # create alerts
    ext_ids = []
    alert_data = {}
    for dev in devlist:
        # create alert data for each serial
        alert_data = create_alert_dict(serial=dev, xql=currentXql, incident=incident, domain=domain, pbid=pbid, ver=version, auto=auto_up, devtype=devtype)

        # create alert
        result = execute_command_with_retries('core-api-post', args={'uri': '/public_api/v1/alerts/create_alert', 'body': json.dumps(alert_data), 'timeout': 1})

        # add external id to list
        extid = result.get('response').get('reply')
        ext_ids.append(extid)

    demisto.debug(f'created external ids: {ext_ids}')

    # The create alerts API returns external IDs, so find the internal IDs
    ext_query_filter = {
        "request_data": {
            "filters": [
                    {
                        "field": "external_id_list",
                        "value": ext_ids,
                        "operator": "in"
                    }
                ]
            }
        }

    # sometimes it takes a bit for the alerts to be queriable
    time.sleep(30)

    # query for internal ids
    get_alerts_response = execute_command_with_retries('core-api-post', {'uri': '/public_api/v2/alerts/get_alerts_multi_events', 'body': json.dumps(ext_query_filter), 'timeout': 3})

    demisto.debug(f'response from get alerts: {get_alerts_response}')

    # get the alert ids for outputs
    alert_ids = []
    for aid in get_alerts_response.get('response').get('reply').get('alerts'):
        alert_ids.append(aid.get('alert_id'))

    demisto.debug(f'Output devtype: {devtype}, alert_ids: {alert_ids}')

    return_results(
        CommandResults(
            outputs_prefix=f'CreatedAlertIDs',
            outputs={devtype: alert_ids}
        )
    )

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


