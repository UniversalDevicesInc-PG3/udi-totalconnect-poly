#!/usr/bin/env python3

import udi_interface
import sys
import re
import schedule
import time
from distutils.util import strtobool
from total_connect_client import TotalConnectClient
from security_panel_node import SecurityPanel
from zone_node import Zone

LOGGER = udi_interface.LOGGER
VALID_DEVICES = ['Security Panel',
                 'Security System',
                 'L5100-WiFi',
                 'Lynx Touch-WiFi',
                 'ILP5',
                 'LTE-XV',
                 'GSMX4G',
                 'GSMVLP5-4G',
                 '7874i',
                 'GSMV4G',
                 'VISTA-21IP4G'
                 ]


class Controller(udi_interface.Node):
    def __init__(self, polyglot, primary, address, name):
        super(Controller, self).__init__(polyglot, primary, address, name)
        self.poly = polyglot
        self.name = "Total Connect Controller"
        self.user = ""
        self.password = ""
        self.include_non_bypassable_zones = False
        self.allow_disarming = False
        self.refresh_auth_interval = "120"
        self.zone_query_delay_ms = "500"
        self.tc = None
        self.filter_regex = r'[^a-zA-Z0-9_\- \t\n\r\f\v]+'

        polyglot.subscribe(polyglot.START, self.start, address)
        polyglot.subscribe(polyglot.CUSTOMPARAMS, self.parameterHandler)
        polyglot.subscribe(polyglot.POLL, self.poll)

        polyglot.ready()
        polyglot.addNode(self, conn_status="ST")

        # Don't enable in deployed node server. I use these so I can run/debug directly in IntelliJ.
        # LOGGER.debug("Profile Num: " + os.environ.get('PROFILE_NUM'))
        # LOGGER.debug("MQTT Host: " + os.environ.get('MQTT_HOST'))
        # LOGGER.debug("MQTT Port: " + os.environ.get('MQTT_PORT'))
        # LOGGER.debug("Token: " + os.environ.get('TOKEN'))

    def parameterHandler(self, params):
        self.poly.Notices.clear()

        if 'user' in params:
            self.user = params['user']
        else:
            LOGGER.error('check_params: user not defined in customParams, please add it.  Using {}'.format(self.user))

        if 'password' in params:
            self.password = params['password']
        else:
            LOGGER.error('check_params: password not defined in customParams, please add it.  Using {}'.format(self.password))

        if 'include_non_bypassable_zones' in params:
            self.include_non_bypassable_zones = params['include_non_bypassable_zones']

        if 'allow_disarming' in params:
            self.allow_disarming = params['allow_disarming']

        if 'refresh_auth_interval' in params:
            self.refresh_auth_interval = params['refresh_auth_interval']

        if 'zone_query_delay_ms' in params:
            self.zone_query_delay_ms = params['zone_query_delay_ms']

        if self.user == "" or self.password == "":
            self.poly.Notices['mynotice'] = 'Please set proper user and password in configuration page, and restart this nodeserver'
            return False

        self.discover()

    def start(self):
        LOGGER.info('Started Total Connect Nodeserver')
        while self.password == "" or self.user == "":
            time.sleep(1)

        schedule.every(int(self.refresh_auth_interval)).minutes.do(self.authenticate)
        self.setDriver('ST', 1)

    def poll(self, polltype):
        if 'shortPoll' in polltype:
            timeout = int(self.zone_query_delay_ms)
            for node in self.poly.nodes():
                if isinstance(node, SecurityPanel):
                    node.query()
                    node.reportDrivers()
                    time.sleep(timeout / 1000)
        else:
            timeout = int(self.zone_query_delay_ms)
            schedule.run_pending()
            for node in self.poly.nodes():
                if isinstance(node, Zone):
                    node.query()
                    node.reportDrivers()
                    time.sleep(timeout / 1000)

    def query(self):
        timeout = int(self.zone_query_delay_ms)
        for node in self.poly.nodes():
            if node is not self:
                node.query()
                node.reportDrivers()
                time.sleep(timeout / 1000)
            else:
                self.reportDrivers()

    def authenticate(self):
        try:
            LOGGER.info("Re-authenticating")
            self.tc.authenticate()
        except Exception as ex:
            LOGGER.exception("Could not re-authenticate %s", ex)

    def discover(self, *args, **kwargs):
        try:
            LOGGER.debug("Starting discovery")
            # If this is a re-discover than update=True
            update = len(args) > 0

            self.tc = TotalConnectClient.TotalConnectClient(self.user, self.password)
            locations = self.tc.request("GetSessionDetails(self.token, self.applicationId, self.applicationVersion)")["Locations"]["LocationInfoBasic"]
            for location in locations:
                loc_id = location['LocationID']
                loc_name = re.sub(self.filter_regex, '', location['LocationName'])

                LOGGER.debug("Adding devices for location {} with name {}".format(loc_id, loc_name))

                devices = location['DeviceList']['DeviceInfoBasic']

                if devices is None:
                    raise Exception("No devices were found for location {} - {} \n{}".format(loc_name, loc_id, location))

                # Create devices in location
                for device in devices:
                    LOGGER.debug("Found device %s in location %s", device['DeviceName'], loc_name)

                    if device['DeviceName'].lower() == 'automation' or device['DeviceName'].lower() == 'video doorbell':
                        continue

                    # Add security devices.
                    # PanelType appears to only show up for security panels
                    if device['DeviceName'] in VALID_DEVICES or (device['DeviceFlags'] is not None and 'PanelType' in device['DeviceFlags']):
                        self.add_security_device(loc_id, loc_name, device, update)
                    else:
                        LOGGER.warn("Device {} in location {} is not a valid security device".format(device['DeviceName'], loc_name))

                    # If we wanted to support other device types it would go here
        except Exception as ex:
            self.poly.Notices['discovery_failed'] = 'Discovery failed please check logs for a more detailed error.'
            LOGGER.exception("Discovery failed with error %s", ex)

    def add_security_device(self, loc_id, loc_name, device, update):
        device_name = re.sub(self.filter_regex, '', device['DeviceName'])
        device_addr = "panel_" + str(device['DeviceID'])
        LOGGER.debug("Adding security device {} with name {} for location {}".format(device_addr, device_name, loc_name))

        if not self.poly.getNode(device_addr):
            self.poly.addNode(SecurityPanel(self.poly, device_addr, device_addr, loc_name + " - " + device_name, self.tc, loc_name, loc_id, self.allow_disarming), update)

        # create zone nodes
        # We are using GetPanelMetaDataAndFullStatusEx_V1 because we want the extended zone info
        panel_data = self.tc.soapClient.service.GetPanelMetaDataAndFullStatusEx_V1(self.tc.token, loc_id, 0, 0, 1)
        if panel_data['ResultCode'] == 0:
            LOGGER.debug("Getting zones for panel {}".format(device_addr))
            zones = panel_data['PanelMetadataAndStatus']['Zones']['ZoneInfoEx']

            if zones is None:
                raise Exception("No zones were found for {} - {} \n{}".format(device_name, device_addr, panel_data))

            for zone in zones:
                if not bool(zone.CanBeBypassed) and not self.include_non_bypassable_zones:
                    LOGGER.debug("Skipping zone {} with name {}".format(zone.ZoneID, zone.ZoneDescription))
                    continue

                self.add_zone(loc_id, loc_name, device_addr, device['DeviceID'], zone, update)
        else:
            LOGGER.warn("Unable to get extended panel information, code {} data {}".format(panel_data["ResultCode"], panel_data["ResultData"]))

    def add_zone(self, loc_id, loc_name, device_addr, device_id, zone, update):
        zone_name = re.sub(self.filter_regex, '', loc_name + " - " + zone.ZoneDescription)
        zone_addr = "z_{}_{}".format(device_id, str(zone.ZoneID))

        LOGGER.debug("Adding zone {} with name {} for location {}".format(zone_addr, zone_name, loc_name))
        if not self.poly.getNode(zone_addr):
            self.poly.addNode(Zone(self.poly, device_addr, zone_addr, zone_name, zone.ZoneID, self.tc, loc_name, loc_id), update)

    def delete(self):
        LOGGER.info('Total Connect NS Deleted')

    def stop(self):
        LOGGER.debug('Total Connect NS stopped.')


    id = 'controller'
    commands = {
        'DISCOVER': discover,
        'QUERY': query
    }

    drivers = [{'driver': 'ST', 'value': 0, 'uom': 2}]


if __name__ == "__main__":
    try:
        polyglot = udi_interface.Interface([])
        polyglot.start('2.0.3')
        polyglot.updateProfile()
        polyglot.setCustomParamsDoc()
        Controller(polyglot, 'controller', 'controller', 'TotalConnect')
        polyglot.runForever()
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
