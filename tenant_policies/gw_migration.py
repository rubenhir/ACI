import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.fv
import cobra.model.pol
import cobra.model.vns
import cobra.model.vz
import cobra.model.dhcp
from cobra.internal.codec.xmlcodec import toXMLStr
import requests.packages.urllib3
import csv
import re
import logging
import argparse


def connect_aci(url, username, password):

    logger1.warning('Connecting to APIC with {0} with username {1}'.format(url, username))

    requests.packages.urllib3.disable_warnings()
    ls = cobra.mit.session.LoginSession(url, username, password, secure=False, timeout=60)
    md = cobra.mit.access.MoDirectory(ls)
    md.login()

    return md


def need_to_be_update(md, tenant, bd, unkMcastAct, unkMacUcastAct, arpFlood, unicastRoute, multiDstPktAct):

    result = False

    bd = md.lookupByDn('uni/tn-' + tenant + '/BD-' + bd)

    if bd.unkMcastAct != unkMcastAct:
        result = True
        logger1.warning('\t unkMcastAct doesnt match')
    if bd.unkMacUcastAct != unkMacUcastAct:
        result = True
        logger1.warning('\t unkMacUcastAct doesnt match')
    if bd.unkMacUcastAct != unkMacUcastAct:
        result = True
        logger1.warning('\t unkMacUcastAct doesnt match')
    if bd.arpFlood != arpFlood:
        result = True
        logger1.warning('\t arpFlood doesnt match')
    if bd.unicastRoute != unicastRoute:
        result = True
        logger1.warning('\t unicastRoute doesnt match')
    if bd.multiDstPktAct != multiDstPktAct:
        result = True
        logger1.warning('\t multiDstPktAct doesnt match')

    return result



def update_bd(md, line):

    _tenant = line[0]
    _bd = line[1]
    _subnet = line[2]
    _dhcp_pol = line[3]
    _to_be_migrated = line[4] == 'Y'
    _l3_bd = _to_be_migrated and _subnet != ''

    logger1.warning("Checking BD {0}".format(_bd))

    if _l3_bd:
        _unkMcastAct = 'flood'
        _unkMacUcastAct = 'proxy'
        _arpFlood = 'no'
        _unicastRoute = 'yes'
        _multiDstPktAct = 'bd-flood'
    else:
        _unkMcastAct = 'flood'
        _unkMacUcastAct = 'flood'
        _arpFlood = 'yes'
        _unicastRoute = 'no'
        _multiDstPktAct = 'bd-flood'

    if need_to_be_update(md, _tenant, _bd, _unkMcastAct, _unkMacUcastAct, _arpFlood, _unicastRoute, _multiDstPktAct):
        logger1.warning('\t --> BD needs to be updated')

        fvTenant = md.lookupByDn('uni/tn-' + _tenant)
        fvBD = cobra.model.fv.BD(fvTenant, unkMcastAct=_unkMcastAct, name=_bd, unkMacUcastAct=_unkMacUcastAct, arpFlood=_arpFlood, unicastRoute=_unicastRoute, ownerTag='', multiDstPktAct=_multiDstPktAct)

        if _l3_bd:
            fvSubnet = cobra.model.fv.Subnet(fvBD, ip=_subnet, preferred='no', scope='public', virtual='no')

            if _l3_bd and _dhcp_pol != '':
                dhcpLbl = cobra.model.dhcp.Lbl(fvBD, name=_dhcp_pol, owner='tenant')

        else:
            if md.lookupByClass('fv.Subnet', parentDn= fvBD.dn):
              fvSubnet = cobra.model.fv.Subnet(fvBD, ip=_subnet, status='deleted')

            if md.lookupByClass('dhcp.Lbl', parentDn= fvBD.dn):
               dhcpLbl = cobra.model.dhcp.Lbl(fvBD, name=_dhcp_pol, status='deleted')

        logger1.debug(toXMLStr(fvTenant))
        c = cobra.mit.request.ConfigRequest()
        c.addMo(fvTenant)
        md.commit(c)

    else:
        logger1.warning('\t BD doesnt need to be updated')


def csv_parser(fd, md):

    logger1.warning('Start processing CSV file')

    csv_fd = csv.reader(fd, delimiter=',')
    for line in csv_fd:
        if line[2] == '' or re.match('[0-9]+.[0-9]+.[0-9]+.[0-9]+/[0-9]+', line[2]):
            logger1.debug('Processing line {0}'.format(line))

            update_bd(md, line)

        else:
            logger1.debug('Skipping CSV header')


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-c', action='store', dest='config_file', help='csv config file')
    parser.add_argument('-s', action='store', dest='url', help='APIC URL')
    parser.add_argument('-u', action='store', dest='username', help='Username to login to APIC')
    parser.add_argument('-p', action='store', dest='password', help='Password to login to APIC')

    parser_result = parser.parse_args()

    if parser_result.config_file and parser_result.url and parser_result.username and parser_result.password:

        md = connect_aci(url=parser_result.url, username=parser_result.username, password=parser_result.password)

        with open(parser_result.config_file) as fd:
            csv_parser(fd, md)

    else:
        logger1.critical('Invalid argument provided')


if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.WARNING, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()