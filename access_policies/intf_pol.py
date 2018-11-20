import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.infra
import cobra.model.lldp
import cobra.model.pol
import cobra.model.lacp
import cobra.model.fabric
import logging
import yaml
import argparse
from cobra.internal.codec.xmlcodec import toXMLStr
import requests.packages.urllib3


def connect_aci(url, username, password):

    logger1.warning('Connecting to APIC with {0} with username {1}'.format(url, username))

    requests.packages.urllib3.disable_warnings()
    ls = cobra.mit.session.LoginSession(url, username, password, secure=False, timeout=60)
    md = cobra.mit.access.MoDirectory(ls)
    md.login()

    return md


def create_policy(md, pol):

    name = pol.keys()[0]
    fct = 'cobra.model.' + pol.values()[0]['type']
    attributes = pol.values()[0]
    attributes.pop('type')

    polUni = cobra.model.pol.Uni('')
    infraInfra = cobra.model.infra.Infra(polUni)
    eval(fct)(infraInfra, name, **attributes)

    logger1.warning('Committing policy {0} of type {1} with properties {2}'.format(name, fct, attributes))
    logger1.debug(toXMLStr(infraInfra))

    logger1.debug(toXMLStr(infraInfra))
    c = cobra.mit.request.ConfigRequest()
    c.addMo(infraInfra)
    md.commit(c)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', action='store', dest='config_file', help='yaml config file')
    parser.add_argument('-c', action='store', dest='url', help='APIC url')
    parser.add_argument('-u', action='store', dest='user', help='APIC User')
    parser.add_argument('-p', action='store', dest='password', help='APIC Password')
    parser_result = parser.parse_args()

    with open(parser_result.config_file, 'r') as yaml_file:
        logger1.debug('Loading configuration')
        config = yaml.load(yaml_file)

    md = connect_aci(parser_result.url, parser_result.user, parser_result.password)

    for pol in config:
        create_policy(md, pol)


if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.WARNING, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()