import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.fv
import cobra.model.pol
import cobra.model.vns
import cobra.model.vz
from cobra.internal.codec.xmlcodec import toXMLStr
import requests.packages.urllib3
from os import listdir, getcwd
from os.path import isfile, join
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


def create_bd(md, line):

    _tenant = line[0]
    _ap = line[1]
    _cons_contract = line[2]
    _prov_contract = line[3]
    _epg = line[4]
    _bd = line[5]
    _subnet = line[6]
    _vrf = line[7]

    logger1.warning("Crafing request for BD: {0}".format(_bd))

    if _subnet != '':
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


    polUni = cobra.model.pol.Uni('')
    fvTenant = cobra.model.fv.Tenant(polUni, _tenant)
    fvBD = cobra.model.fv.BD(fvTenant, vmac='not-applicable', limitIpLearnToSubnets='no', mcastAllow='no', unkMcastAct=_unkMcastAct, name=_bd, unkMacUcastAct=_unkMacUcastAct, arpFlood=_arpFlood,
                             unicastRoute=_unicastRoute, multiDstPktAct=_multiDstPktAct, type='regular', ipLearning='yes')

    fvRsCtx = cobra.model.fv.RsCtx(fvBD, tnFvCtxName=_vrf)

    if _subnet != '':
        fvSubnet = cobra.model.fv.Subnet(fvBD, name='', descr='', ctrl='', ip=_subnet, preferred='no', scope='public', virtual='no')

    logger1.debug(toXMLStr(fvTenant))

    c = cobra.mit.request.ConfigRequest()
    c.addMo(fvTenant)
    md.commit(c)


def create_epg(md, line ):

    _tenant = line[0]
    _ap = line[1]
    _cons_contract = line[2]
    _prov_contract = line[3]
    _epg = line[4]
    _bd = line[5]
    _subnet = line[6]
    _vrf = line[7]

    logger1.warning("Crafing request for EGP: {0}".format(_epg))

    polUni = cobra.model.pol.Uni('')
    fvTenant = cobra.model.fv.Tenant(polUni, _tenant)
    fvAp = cobra.model.fv.Ap(fvTenant, _ap)

    fvAEPg = cobra.model.fv.AEPg(fvAp, isAttrBasedEPg='no', matchT='AtleastOne', name=_epg, prio='unspecified', pcEnfPref='unenforced')
    fvRsCons = cobra.model.fv.RsCons(fvAEPg, tnVzBrCPName=_cons_contract, prio='unspecified')
    fvRsBd = cobra.model.fv.RsBd(fvAEPg, tnFvBDName=_bd)
    fvRsProv = cobra.model.fv.RsProv(fvAEPg, tnVzBrCPName=_prov_contract, matchT='AtleastOne', prio='unspecified')

    logger1.debug(toXMLStr(fvAp))

    c = cobra.mit.request.ConfigRequest()
    c.addMo(fvAp)
    md.commit(c)


def csv_parser(fd, md):

    logger1.warning('Start processing CSV file')

    csv_fd = csv.reader(fd, delimiter=',')
    for line in csv_fd:
        if line[6] == '' or re.match('[0-9]+.[0-9]+.[0-9]+.[0-9]+/[0-9]+', line[6]):
            logger1.debug('Processing line {0}'.format(line))

            create_bd(md, line)
            create_epg(md, line)

        else:
            logger1.debug('Skipping header line')



def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-c', action='store', dest='config_file', help='csv config file')
    parser.add_argument('-s', action='store', dest='url', help='APIC URL')
    parser.add_argument('-u', action='store', dest='username', help='Username to login to APIC')
    parser.add_argument('-p', action='store', dest='password', help='Password to login to APIC')

    parser_result = parser.parse_args()

    if parser_result.config_file and parser_result.url and parser_result.username and parser_result.password:

        md = connect_aci(url=parser_result.url, username=parser_result.username, password=parser_result.password)

        logger1.warning('Opening file {0}'.format(parser_result.config_file))
        with open(parser_result.config_file) as fd:
            csv_parser(fd, md)

    else:
        logger1.critical('Invalid argument provided')



if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.WARNING, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()