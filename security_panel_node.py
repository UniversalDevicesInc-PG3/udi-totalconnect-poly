import udi_interface
from total_connect_client import TotalConnectClient
from enum import Enum

LOGGER = udi_interface.LOGGER


class ArmStatus(Enum):
    DISARMED = 10200
    DISARMED_BYPASS = 10211
    ARMED_AWAY = 10201
    ARMED_AWAY_BYPASS = 10202
    ARMED_AWAY_INSTANT = 10205
    ARMED_AWAY_INSTANT_BYPASS = 10206
    ARMED_CUSTOM_BYPASS = 10223
    ARMED_STAY = 10203
    ARMED_STAY_BYPASS = 10204
    ARMED_STAY_INSTANT = 10209
    ARMED_STAY_INSTANT_BYPASS = 10210
    ARMED_STAY_NIGHT = 10218
    ARMING = 10307
    DISARMING = 10308
    ALARM = 10207
    ALARM_FIRE = 10212
    ALARM_CARBON = 10213  # Not sure if this is right
    UNKNOWN = 0


armStatusMap = {
    ArmStatus.DISARMED: 1,
    ArmStatus.DISARMED_BYPASS: 2,
    ArmStatus.ARMED_AWAY: 3,
    ArmStatus.ARMED_AWAY_BYPASS: 4,
    ArmStatus.ARMED_AWAY_INSTANT: 5,
    ArmStatus.ARMED_AWAY_INSTANT_BYPASS: 6,
    ArmStatus.ARMED_CUSTOM_BYPASS: 7,
    ArmStatus.ARMED_STAY: 8,
    ArmStatus.ARMED_STAY_BYPASS: 9,
    ArmStatus.ARMED_STAY_INSTANT: 10,
    ArmStatus.ARMED_STAY_INSTANT_BYPASS: 11,
    ArmStatus.ARMED_STAY_NIGHT: 12,
    ArmStatus.ARMING: 13,
    ArmStatus.DISARMING: 14,
    ArmStatus.ALARM: 15,
    ArmStatus.ALARM_FIRE: 16,
    ArmStatus.ALARM_CARBON: 17,
    ArmStatus.UNKNOWN: 18
}


class SecurityPanel(udi_interface.Node):

    def __init__(self, controller, primary, address, name, tc, loc_name, loc_id, allow_disarming=False):
        super(SecurityPanel, self).__init__(controller, primary, address, name)
        self.tc = tc
        self.loc_name = loc_name
        self.loc_id = loc_id
        self.allow_disarming = allow_disarming

        controller.subscribe(controller.START, self.start, address)

    def start(self):
        self.query()

    def armStay(self, command):
        try:
            self.tc.keep_alive()
            self.tc.arm_stay(self.loc_id)
        except Exception as ex:
            LOGGER.error("Arming panel {0} failed {1}".format(self.address, ex))

    def armStayNight(self, command):
        try:
            self.tc.keep_alive()
            self.tc.arm_stay_night(self.loc_id)
        except Exception as ex:
            LOGGER.error("Arming panel {0} failed {1}".format(self.address, ex))

    def armAway(self, command):
        try:
            self.tc.keep_alive()
            self.tc.arm_away(self.loc_id)
        except Exception as ex:
            LOGGER.error("Arming panel {0} failed {1}".format(self.address, ex))

    def disarm(self, command):
        try:
            self.tc.keep_alive()

            if self.allow_disarming:
                self.tc.disarm(self.loc_id)
            else:
                LOGGER.warn("Disarming panel is disabled")
                self.controller.addNotice({'mynotice': 'The ability to disarm is disabled for security reasons. To enable set allow_disarming to true in the configuration parameters and restart this nodeserver.'})
        except Exception as ex:
            LOGGER.error("Disarming panel {0} failed {1}".format(self.address, ex))

    def query(self):
        try:
            LOGGER.debug("Query zone {}".format(self.address))
            self.tc.keep_alive()
            self.tc.get_panel_meta_data(self.loc_id)
            panel_meta_data = self.tc.locations[self.loc_id]
            alarm_code = self.tc.locations[self.loc_id].arming_state
            low_battery = self.tc.locations[self.loc_id].is_low_battery()
            ac_loss = self.tc.locations[self.loc_id].is_ac_loss()

            # TODO Add IsCoverTampered
            # self.tc.locations[self.loc_id].is_cover_tampered()

            self.setDriver('GV0', armStatusMap[ArmStatus(alarm_code)])
            self.setDriver('GV1', int(low_battery))
            self.setDriver('GV2', int(ac_loss))
        except Exception as ex:
            LOGGER.error("Refreshing panel {0} failed {1}".format(self.address, ex))
            self.setDriver('GV0', armStatusMap[ArmStatus.UNKNOWN])

        self.reportDrivers()

    drivers = [
        {'driver': 'GV0', 'value': armStatusMap[ArmStatus.UNKNOWN], 'uom': 25},
        {'driver': 'GV1', 'value': int(False), 'uom': 2},
        {'driver': 'GV2', 'value': int(False), 'uom': 2}
    ]

    id = 'tc_panel'
    commands = {
        'ARM_STAY': armStay, 'ARM_STAY_NIGHT': armStayNight, 'ARM_AWAY': armAway, 'DISARM': disarm, 'QUERY': query
    }
