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


def create_intf_prof(md, config):

    logger1.warning('Creating interface profile {0} with interface {1}, interface description {2} and policy group {3}'
                    .format(config['interface_profile'], config['physical_interface'], config['interface_description'], config['interface_pgr']))

    port_name = config['physical_interface'].split('/')[0] + '-' + config['physical_interface'].split('/')[1]
    port_nbr = config['physical_interface'].split('/')[1]

    '''
    topDn = cobra.mit.naming.Dn.fromString('uni/infra/accportprof-' + config['interface_profile'])
    topParentDn = topDn.getParent()
    topMo = md.lookupByDn(topParentDn)
    '''

    polUni = cobra.model.pol.Uni('')
    infraInfra = cobra.model.infra.Infra(polUni)

    infraAccPortP = cobra.model.infra.AccPortP(infraInfra, name=config['interface_profile'])
    infraHPortS = cobra.model.infra.HPortS(infraAccPortP, type='range', name=port_name, descr=config['interface_description'])
    infraRsAccBaseGrp = cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId='101', tDn=config['interface_pgr_dn'])
    infraPortBlk = cobra.model.infra.PortBlk(infraHPortS, name='block2', descr='', fromPort=port_nbr, fromCard='1', toPort=port_nbr, toCard='1')


    config['interface_profile_dn'] = infraAccPortP.dn

    #print toXMLStr(infraInfra)
    c = cobra.mit.request.ConfigRequest()
    c.addMo(infraInfra)
    #md.commit(c)


def create_pgr(md, config):

    polUni = cobra.model.pol.Uni('')
    infraInfra = cobra.model.infra.Infra(polUni)
    infraFuncP = cobra.model.infra.FuncP(infraInfra)

    if re.match('PC_LACP', config['pgr_type']):
        logger1.warning('Creating interface policy-group {0}'.format(config['interface_pgr']))
        infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='link')

    elif re.match('vPC_LACP', config['pgr_type']):
        infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='node')

    elif re.match('PC_ON', config['pgr_type']):
        logger1.warning('Creating interface policy-group {0}'.format(config['interface_pgr']))
        infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='link')

    elif re.match('vPC_ON', config['pgr_type']):
        infraAccGrp = cobra.model.infra.AccBndlGrp(infraFuncP, name=config['interface_pgr'], lagT='node')

    elif re.match('Access', config['pgr_type']):
        infraAccGrp = cobra.model.infra.AccPortGrp(infraFuncP, name=config['interface_pgr'])

    config['interface_pgr_dn'] = infraAccGrp.dn
    infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccGrp, tDn='uni/infra/attentp-' + config['aep'])

    #print toXMLStr(infraFuncP)
    c = cobra.mit.request.ConfigRequest()
    c.addMo(infraFuncP)
    #md.commit(c)


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
            result['pgr_type'] = line[6]
            result['pgr_description'] = line[7]
            result['device_name'] = line[8]

            yield(result)

        else:
            logger1.warning("Line {0} doesnt contain necessary information. Skipping... : {1}".format(line_id + 1, line))


def config_sanity_check(gen):
    for config in gen:
        if config['switch_profile'] == '':
            logger1.debug("Line {0} doesnt come with a valid switch profile. Skipping... : {1}".format(config['line_id'], config['line']))

        elif config['interface_profile'] == '':
            logger1.debug("Line {0} doesnt come with a valid interface profile. Skipping... : {1}".format(config['line_id'], config['line']))

        elif config['interface_pgr'] == '':
            logger1.debug("Line {0} doesnt come with a valid interface policy group. Skipping... : {1}".format(config['line_id'], config['line']))

        elif config['aep'] == '':
            logger1.debug("Line {0} doesnt come with a valid attach entity profile. Skipping... : {1}".format(config['line_id'], config['line']))

        elif not re.match('e[0-9]/[0-9]+', config['physical_interface']):
            logger1.debug("Line {0} doesnt come with a valid interface. Skipping... : {1}".format(config['line_id'], config['line']))
            logger1.debug("Expected interface syntax: e<x>/<y>")

        elif not re.search('(10G|1G|100M)', config['physical_interface_speed']):
            logger1.debug("Line {0} doesnt come with a valid interface speed. Skipping... : {1}".format(config['line_id'], config['line']))
            logger1.debug('Expected interface speed: 10G, 1G or 100M')

        elif not re.search('(vPC_LACP|vPC_ON|PC_LACP|PC_ON|Access)', config['pgr_type']):
            logger1.debug("Line {0} doesnt come with a valid policy group type. Skipping... : {1}".format(config['line_id'], config['line']))
            logger1.debug('Expected policy group type: vPC_LACP, vPC_ON, PC_LACP, PC_ON or Access')

        else:
            yield config


def apply_config(md, gen):

    for config in gen:
        create_pgr(md, config)
        create_intf_prof(md, config)



def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-c', action='store', dest='config_file', help='csv config file')
    parser.add_argument('-s', action='store', dest='ip', help='APIC URL')
    parser.add_argument('-u', action='store', dest='username', help='Username to login to APIC')
    parser.add_argument('-p', action='store', dest='password', help='Password to login to APIC')

    parser_result = parser.parse_args()

    if parser_result.config_file and parser_result.ip and parser_result.username and parser_result.password:
        # md = connect_aci(parser_result.ip, parser_result.username, parser_result.password)
        md = ''

        for file in [f for f in listdir(getcwd()) if isfile(join(getcwd(), f))]:
            if re.match(parser_result.config_file, file):
                logger1.warning('Opening file {0}'.format(file))

                with open(file, 'r') as fd:
                    apply_config(md, config_sanity_check(config_parser(fd)))

    else:
        logger1.critical('Invalid argument provided')



if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logger1.setLevel(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()