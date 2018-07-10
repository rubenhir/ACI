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


class ConfigParser:
    def __init__(self, filename):
        self._filename = filename


    def _config_parser(self, fd):
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
                result['pgr_type'] = line[6]
                result['pgr_description'] = line[7]
                result['device_name'] = line[8]

                yield (result)

            else:
                logger1.warning(
                    "Line {0} doesnt contain necessary information. Skipping... : {1}".format(line_id + 1, line))


    def _config_sanity_check(self, gen):

        for config in gen:

            if config['switch_profile'] == '':
                logger1.debug(
                    "Line {0} doesnt come with a valid switch profile. Skipping... : {1}".format(config['line_id'],
                                                                                                 config['line']))

            elif config['interface_profile'] == '':
                logger1.debug(
                    "Line {0} doesnt come with a valid interface profile. Skipping... : {1}".format(config['line_id'],
                                                                                                    config['line']))

            elif config['interface_pgr'] == '':
                logger1.debug("Line {0} doesnt come with a valid interface policy group. Skipping... : {1}".format(
                    config['line_id'], config['line']))

            elif config['aep'] == '':
                logger1.debug("Line {0} doesnt come with a valid attach entity profile. Skipping... : {1}".format(
                    config['line_id'], config['line']))

            elif not re.match('e[0-9]/[0-9]+', config['physical_interface']):
                logger1.debug("Line {0} doesnt come with a valid interface. Skipping... : {1}".format(config['line_id'],
                                                                                                      config['line']))
                logger1.debug("Expected interface syntax: e<x>/<y>")

            elif not re.search('(10G|1G|100M)', config['physical_interface_speed']):
                logger1.debug(
                    "Line {0} doesnt come with a valid interface speed. Skipping... : {1}".format(config['line_id'],
                                                                                                  config['line']))
                logger1.debug('Expected interface speed: 10G, 1G or 100M')

            elif not re.search('(vPC_LACP|vPC_ON|PC_LACP|PC_ON|Access)', config['pgr_type']):
                logger1.debug(
                    "Line {0} doesnt come with a valid policy group type. Skipping... : {1}".format(config['line_id'],
                                                                                                    config['line']))
                logger1.debug('Expected policy group type: vPC_LACP, vPC_ON, PC_LACP, PC_ON or Access')

            else:
                yield config


    def __iter__(self):
        for file in [f for f in listdir(getcwd()) if isfile(join(getcwd(), f))]:
            if re.match(self._filename, file):
                logger1.warning('Opening file {0}'.format(file))

                with open(file, 'r') as fd:
                    for config in self._config_sanity_check(self._config_parser(fd)):
                        yield config


class AciMo:
    def __init__(self, url, username, password, secure=False, timeout=60):
        self._url = url
        self._username = username
        self._password = password
        self._secure = secure
        self._timeout = timeout

        requests.packages.urllib3.disable_warnings()
        ls = cobra.mit.session.LoginSession(self._url, self._username, self._password, secure=self._secure,
                                            timeout=self._timeout)
        self._md = cobra.mit.access.MoDirectory(ls)
        self._md.login()


    def _create_aep(self, config):


    def _create_pgr(self, config):

        polUni = cobra.model.pol.Uni('')
        infraInfra = cobra.model.infra.Infra(polUni)
        infraFuncP = cobra.model.infra.FuncP(infraInfra)

        if re.match('PC_LACP', config['pgr_type']):
            logger1.warning('Creating LACP PC policy-group {0}'.format(config['interface_pgr']))
            infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='link')

        elif re.match('vPC_LACP', config['pgr_type']):
            logger1.warning('Creating LACP vPC policy-group {0}'.format(config['interface_pgr']))
            infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='node')

        elif re.match('PC_ON', config['pgr_type']):
            logger1.warning('Creating PC policy-group {0}'.format(config['interface_pgr']))
            infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='link')

        elif re.match('vPC_ON', config['pgr_type']):
            logger1.warning('Creating vPC policy-group {0}'.format(config['interface_pgr']))
            infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='node')

        elif re.match('Access', config['pgr_type']):
            logger1.warning('Creating Access policy-group {0}'.format(config['interface_pgr']))
            infraAccGrp = cobra.model.infra.AccPortGrp(infraFuncP, name=config['interface_pgr'])

        config['interface_pgr_dn'] = infraAccGrp.dn
        infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccGrp, tDn='uni/infra/attentp-' + config['aep'])

        if self._md.lookupByDn(infraAccGrp.dn):
            logger1.warning('Interface Policy Group {0} exist already. Skiping...'.format(config['interface_pgr']))

        else:
            logger1.debug(toXMLStr(infraFuncP))
            c = cobra.mit.request.ConfigRequest()
            c.addMo(infraFuncP)
            self._md.commit(c)

        return config


    def _create_intf_prof(self, config):

        already_attached = False
        logger1.warning('Creating interface profile {0} with interface {1}, interface description {2} and linked to policy group {3}'.format(config['interface_profile'], config['physical_interface'], config['interface_description'], config['interface_pgr']))

        port_name = config['physical_interface'].split('/')[0] + '-' + config['physical_interface'].split('/')[1]
        port_nbr = config['physical_interface'].split('/')[1]

        polUni = cobra.model.pol.Uni('')
        infraInfra = cobra.model.infra.Infra(polUni)

        infraAccPortP = cobra.model.infra.AccPortP(infraInfra, name=config['interface_profile'])
        infraHPortS = cobra.model.infra.HPortS(infraAccPortP, type='range', name=port_name, descr=config['interface_description'])
        infraRsAccBaseGrp = cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId='101', tDn=config['interface_pgr_dn'])
        infraPortBlk = cobra.model.infra.PortBlk(infraHPortS, name='block2', descr='', fromPort=port_nbr, fromCard='1', toPort=port_nbr, toCard='1')

        config['interface_profile_dn'] = infraAccPortP.dn

        for selector in self._md.lookupByClass('infra.HPortS', infraAccPortP.dn):
            for block in self._md.lookupByClass('infra.PortBlk', selector.dn):
                if block.fromPort <= port_nbr and block.toPort >= port_nbr:
                    already_attached = True
                    break

        if already_attached:
            logger1.warning('Interface Profile {0} already has port {1}'.format(config['interface_profile'], config['physical_interface']))

        else:
            logger1.debug(toXMLStr(infraInfra))
            c = cobra.mit.request.ConfigRequest()
            c.addMo(infraInfra)
            self._md.commit(c)

        return config


    def _attach_intf_prof(self, config):

        already_attached = False
        for rs in self._md.lookupByClass('infra.RsAccPortP'):
            if rs.tDn == config['interface_profile_dn']:
                already_attached = True
                break

        if already_attached:
            logger1.warning('Interface Profile {0} already attached to a switch profile. Skipping...'.format(config['interface_profile']))

        else:
            polUni = cobra.model.pol.Uni('')
            infraInfra = cobra.model.infra.Infra(polUni)

            infraNodeP = cobra.model.infra.NodeP(infraInfra, name=config['switch_profile'], descr='')
            infraRsAccPortP = cobra.model.infra.RsAccPortP(infraNodeP, tDn=config['interface_profile_dn'])

            logger1.debug(toXMLStr(infraInfra))
            c = cobra.mit.request.ConfigRequest()
            c.addMo(infraInfra)
            self._md.commit(c)

        return config


    def __call__(self, config):

        logger1.debug('Getting config {0}'.format(config))
        self._attach_intf_prof(self._create_intf_prof(self._create_pgr(config)))


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-c', action='store', dest='config_file', help='csv config file')
    parser.add_argument('-s', action='store', dest='url', help='APIC URL')
    parser.add_argument('-u', action='store', dest='username', help='Username to login to APIC')
    parser.add_argument('-p', action='store', dest='password', help='Password to login to APIC')

    parser_result = parser.parse_args()

    if parser_result.config_file and parser_result.url and parser_result.username and parser_result.password:

        apic1 = AciMo(parser_result.url, parser_result.username, parser_result.password)

        for config in ConfigParser(parser_result.config_file):
            apic1(config)

    else:
        logger1.critical('Invalid argument provided')



if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.WARNING, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()