import cobra.mit.access
import cobra.mit.naming
import cobra.mit.request
import cobra.mit.session
import cobra.model.infra
import cobra.model.fabric
import cobra.model.pol
import cobra.model.lacp
import cobra.model.cdp
import cobra.model.lldp
from cobra.internal.codec.xmlcodec import toXMLStr
import requests.packages.urllib3
from os import listdir, getcwd
from os.path import isfile, join
import csv
import re
import logging
import argparse


def connect_aci(url, username, password):
    logger1.debug('Login to controller')

    try:
        requests.packages.urllib3.disable_warnings()
        ls = cobra.mit.session.LoginSession(url, username, password, secure=False, timeout=60)
        md = cobra.mit.access.MoDirectory(ls)
        md.login()

        return md

    except Exception as e:
        logger1.exception('Failed to connect to the controller')


def config_parser(fd):
    csv_file = csv.reader(fd, delimiter=',')

    for line_id, line in enumerate(csv_file):
        if len(line) >= 9:
            result = dict()
            result['line_id'] = line_id + 1
            result['line'] = line
            result['switch_profile'] = line[0]
            result['interface_profile'] = line[1]
            result['interface_pgr'] = line[2]
            result['aep'] = line[3]
            result['physical_interface'] = line[4]
            result['physical_interface_speed'] = line[11]
            result['interface_description'] = line[5]
            result['pgr_settings'] = line[6]
            result['pgr_description'] = line[7]
            result['device_name'] = line[8]

            yield(result)

        else:
            logger1.warning("Line {0} doesnt contain necessary information. Skipping... : {1}".format(line_id + 1, line))


def config_sanity_check(config_parser):
    for config in config_parser:
        if config['switch_profile'] == '':
            logger1.warning("Line {0} doesnt come with a valid switch profile. Skipping... : {1}".format(config['line_id'], config['line']))

        elif config['interface_profile'] == '':
            logger1.warning("Line {0} doesnt come with a valid interface profile. Skipping... : {1}".format(config['line_id'], config['line']))

        elif config['interface_pgr'] == '':
            logger1.warning("Line {0} doesnt come with a valid interface policy group. Skipping... : {1}".format(config['line_id'], config['line']))

        elif config['aep'] == '':
            logger1.warning("Line {0} doesnt come with a valid attach entity profile. Skipping... : {1}".format(config['line_id'], config['line']))

        elif not re.match('e[0-9]/[0-9]+', config['physical_interface']):
            logger1.warning("Line {0} doesnt come with a valid interface. Skipping... : {1}".format(config['line_id'], config['line']))
            logger1.warning("Expected interface syntax: e<x>/<y>")


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-c', action='store', dest='config_file', help='csv config file')
    parser.add_argument('-s', action='store', dest='ip', help='APIC URL')
    parser.add_argument('-u', action='store', dest='username', help='Username to login to APIC')
    parser.add_argument('-p', action='store', dest='password', help='Password to login to APIC')

    parser_result = parser.parse_args()

    if parser_result.config_file and parser_result.ip and parser_result.username and parser_result.password:
        md = connect_aci(parser_result.ip, parser_result.username, parser_result.password)

        for file in [f for f in listdir(getcwd()) if isfile(join(getcwd(), f))]:
            if re.match(parser_result.config_file, file):
                logger1.warning('Opening file {0}'.format(file))

                with open(file, 'r') as fd:
                    config_sanity_check(config_parser(fd))

    else:
        logger1.critical('Invalid argument provided')



if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logger1.setLevel(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()