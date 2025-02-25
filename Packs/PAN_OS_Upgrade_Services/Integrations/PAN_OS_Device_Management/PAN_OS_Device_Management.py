import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import requests
from typing import List
import time, hashlib, urllib.parse, random, string

from panos.panorama import Panorama
from panos.firewall import Firewall
from urllib.parse import urlparse, urlunparse
import xml.etree.ElementTree as ET

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

class Client(BaseClient):
    """Client class to interact with the service API

    From Cortex XDR - XQL Query integration

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def add_xql_lookup_data(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/lookups/add_data', json_data=data)
        return res
    def remove_xql_lookup_data(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/lookups/remove_data', json_data=data)
        return res
    def get_xql_lookup_data(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/lookups/get_data', json_data=data)
        return res
    def add_dataset(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/add_dataset', json_data=data)
        return res
    def delete_dataset(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/delete_dataset/', json_data=data)
        return res
    def get_datasets(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/get_datasets', json_data=data)
        return res

def get_standard_auth_headers(key:str, auth_id:str) -> dict:
    return {
                'Authorization': key,
                'x-xdr-auth-id': auth_id,
                'Accept': 'application/json'
            }

def get_adv_auth_headers(key:str, auth_id:str) -> dict:
    nonce = ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))
    timestamp = str(int(time.time() * 1000))
    auth_key = key + nonce + timestamp
    auth_key = urllib.parse.quote(auth_key, safe='')
    auth_key_hash = hashlib.sha256(auth_key.encode()).hexdigest()

    return {
                'x-xdr-timestamp': timestamp,
                'x-xdr-nonce': nonce,
                'x-xdr-auth-id': auth_id,
                'Authorization': auth_key_hash,
                'Accept': 'application/json'
            }

class PANOSCommands:
    SHOW_SYSTEM_INFO = "show system info"
    SHOW_DEVICES_ALL = "show devices all"
    SHOW_DEVICE_GROUPS = "show devicegroups"

class FieldMap:
    """Maps data from the PAN-OS responses into their associated indicator fields."""
    field_map = {
        "swversion": "softwareversion",
        "avversion": "antivirusversion",
        "model": "devicemodel",
        "operationalmode": "devicestatus",
        "lastcommitallstatesp": "lastcommitstate"
    }

    @staticmethod
    def replace(field_name):
        """Swap the name with it's mapped XSOAR name if it exists in the map"""
        return FieldMap.field_map.get(field_name, field_name)

def flatten_xml_to_dict(element, object_dict: dict):
    """
    Given an XML element, a dictionary, and a class, flattens the XML into the class.
    This is a recursive function that will resolve child elements.
    :param element: XML element object
    :param object_dict: A dictionary to populate with the XML tag text
    :param class_type: The class type that this XML will be converted to - filters the XML tags by it's attributes
    """
    for child_element in element:
        tag = child_element.tag

        # Replace hyphens in tags with underscores to match python attributes
        tag = tag.replace("-", "_")
        if child_element.text:
            object_dict[tag] = child_element.text

        if len(child_element) > 0:
            # Create a new dict and add it at this tag

            items = flatten_xml_to_dict(child_element, {})
            if items:
                if object_dict.get(tag):
                    if not isinstance(object_dict.get(tag), list):
                        object_dict[tag] = [object_dict[tag], items]
                    else:
                        object_dict[tag].append(items)
                else:
                    object_dict[tag] = items

    return object_dict

def handle_ha_field(ha_settings: dict):
    """Converts the HA settings into fields objects"""
    field_data = {}
    if not ha_settings:
        field_data["hastatus"] = "active"

        return field_data

    field_data["hastatus"] = ha_settings.get("state")
    field_data["hapeerdevice"] = ha_settings.get("peer").get('serial')
    return field_data

def system_to_json(data: dict) -> dict:
    """
    Convert a dictionary representation of the PAN-OS system xml to be added to a lookup table.
    """
    family = data.get("family", "unknown").lower()
    model = data.get("model", "unknown").lower()
    system_mode = data.get("system_mode", "unknown").lower()

    field_data = {}
    # Sub out the underscores and map if required
    for field, value in data.items():
        field_name = FieldMap.replace(field.replace("_", ""))
        if isinstance(value, dict) or isinstance(value, list):
            # lookup tables can't accept nested objects, to convert to json string -
            field_data[field_name] = json.dumps(value)
        else:
            field_data[field_name] = value

    field_data = {**field_data, **handle_ha_field(data.get("ha"))}

    # Add model
    field_data["devicevendor"] = "Palo Alto Networks"
    return field_data

def get_devicegroups(panorama: Panorama):
    """Gets the device-groups and the devices that belong to each"""
    device_dict = {}
    device_groups = panorama.op(PANOSCommands.SHOW_DEVICE_GROUPS).findall("./result/devicegroups/entry")
    for device_group in device_groups:
        device_group_name = device_group.attrib.get("name")
        devices = device_group.findall("./devices/entry")
        for device in devices:
            device_json = {
                "device_group_name": device_group_name
            }
            device_json = flatten_xml_to_dict(device, device_json)
            device_dict[device_json.get("serial")] = device_json

    return device_dict

def fetch_devices(panorama: Panorama, panos_instance: str) -> List[dict]:
    """
    Queries the Panorama system for managed devices and parses them. Also queries Panorama
    itself for it's details and parses it as well.
    """
    parsed_devices = []
    panorama_data = flatten_xml_to_dict(panorama.op(PANOSCommands.SHOW_SYSTEM_INFO).find('./result/system'), {})
    panorama_data = system_to_json(panorama_data)
    # Panorama device used by this integration is always considered connected
    panorama_data['connected'] = 'yes'
    # Panorama device used by this integration is always considered HA status Active
    panorama_data['hastatus'] = 'active'
    # Also set the Panorama IP; this is used as the target for many use cases and may differ from what Panorama says is it's own
    # IP.
    panorama_data['panoramahostname'] = panorama.hostname
    # Set the panos instance
    panorama_data['panoramainstance'] = panos_instance

    devices = panorama.op(PANOSCommands.SHOW_DEVICES_ALL).findall('./result/devices/entry')
    device_groups = get_devicegroups(panorama)

    for device in devices:
        demisto.debug(f'Device returned from pano - {ET.tostring(device, encoding="unicode")}')
        device_data = flatten_xml_to_dict(device, {})
        device_group = device_groups.get(device_data.get('serial'))
        # If the device is a member of a DG, then merge the fields
        if device_group:
            device_data = {**device_data, **device_group}
            # Set the tag field to the name of the DG
            device_data['devicetags'] = [device_data.get('device_group_name')]

        device_data = system_to_json(device_data)
        # Set the panos instance
        device_data['panoramainstance'] = panos_instance
        parsed_devices.append(
            device_data
        )

    parsed_devices.append(panorama_data)
    return parsed_devices

def generate_table_schema(table_data:list) -> dict:
    '''
    Takes the table data and generates a schema
    '''
    # create a new dict with all text keys
    all_keys = sorted({key for d in table_data for key in d})
    schema = {key: 'text' for key in all_keys}

    return schema

def update_lookuptable(client:BaseClient, table_name:str, table_data: list) -> None:
    '''
    This will update  the firewall info lookup table
    '''
    # wipe existing lookup table if it exists - this is needed in case there are any differences in fields
    query_result = client.get_datasets({'request': {}}).get('reply')
    for dataset_info in query_result:
        if dataset_info.get('Type') == 'LOOKUP' and dataset_info.get('Dataset Name') == table_name.lower():
            # lookup table found, delete it
            delete_data = {
                # 'request': { # this doesn't match the API docs
                    'dataset_name': table_name.lower(),
                    'force': True
                # }
            }
            delete_res = client.delete_dataset(delete_data)

    # create the lookup table
    create_data = {
            'request': {
                'dataset_name': table_name.lower(),
                'dataset_type': 'lookup',
                'dataset_schema': generate_table_schema(table_data=table_data)
            }
        }
    create_result = client.add_dataset(create_data)

    # add the fw data to the lookup table
    add_data = {
        "request": {
            "dataset_name": table_name,
            "data": table_data,
            "key_fields": ["serial"]
        }
    }
    add_result = client.add_xql_lookup_data(add_data)

def test_module(panorama: Panorama, xsiam_client:BaseClient) -> str:
    '''
    Tests this integration is configured correctly by
        Panorama - connecting to panorama and running an op command.
                   Also validates this is indeed connecting to Panorama,
                   as this is required for this integration to work.

        XSIAM - connects and runs the 'healthcheck' API call

    '''
    panroama_pass = False
    result = panorama.op(PANOSCommands.SHOW_SYSTEM_INFO)
    result_dict = flatten_xml_to_dict(result.find('./result/system'), {})
    family = result_dict.get('family', 'unknown').lower()
    model = result_dict.get('model', 'unknown').lower()
    if family == "pc" or model == "panorama":
        panorama_pass = True

    if family == "m" or model in ["m-500", "m-600"]:
        panorama_pass = True

    if not panorama_pass:
        raise ValueError(f"Incorrect model type; got family {family} and model {model} but must be panorama.")

    try:
        x_result = xsiam_client._http_request(method='POST', url_suffix='/public_api/v1/healthcheck')
        if x_result.get('status') == 'available':
            return 'ok'
    except Exception as e:
        return(f"Failed XSIAM API Auth --- {e}")

def main():
    """Main entrypoint for script"""

    # base params
    params = demisto.params()
    api_key = str(params.get('credentials', {}).get('password', ''))
    table_name = params.get('lookupTableName', 'panorama_firewall_inventory')
    parsed_url = urlparse(params.get("url"))
    port = params.get('port', '443')
    hostname = parsed_url.hostname
    panos_instance = str(params.get('panosIntegrationName', ''))

    # get the api xsiam url, keys and headers
    xsiam_parsed = urlparse(demisto.demistoUrls().get('server'))
    xsiam_parsed = xsiam_parsed._replace(netloc=f'api-{xsiam_parsed.netloc}')
    xsiam_url = urlunparse(xsiam_parsed)
    xsiam_key_id = str(params.get('xsiam_apikey', {}).get('identifier', ''))
    xsiam_key = str(params.get('xsiam_apikey', {}).get('password', ''))

    headers = {}
    if params.get('auth_method') == 'Standard':
        headers = get_standard_auth_headers(key=xsiam_key, auth_id=xsiam_key_id)
    else:
        headers = get_adv_auth_headers(key=xsiam_key, auth_id=xsiam_key_id)

    handle_proxy()

    # Panorama connection
    panorama = Panorama.create_from_device(
        hostname=hostname,
        api_key=api_key,
        port=port
    )

    # XSIAM client for lookup table commands
    xsiam_client = Client(
        base_url=xsiam_url+'/public_api/v1',
        proxy=params.get('proxy'),
        verify=not demisto.params().get('insecure', False),
        headers=headers,
        timeout=120,
    )

    command_name = demisto.command()
    if command_name == 'test-module':
        return_results(test_module(panorama, xsiam_client))
    elif command_name == 'fetch-indicators':
        devices = fetch_devices(panorama, panos_instance)
        update_lookuptable(client=xsiam_client, table_name=table_name, table_data=devices)

if __name__ == "__builtin__" or __name__ == "builtins":
    main()

