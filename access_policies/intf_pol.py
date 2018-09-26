import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.infra
import cobra.model.lldp
import cobra.model.pol
import cobra.model.lacp
import logging
import yaml
import argparse
from cobra.internal.codec.xmlcodec import toXMLStr
import requests.packages.urllib3


class Configuration:
    def __init__(self, filename):
        self._config = list()

        with open(filename, 'r') as yaml_file:
            logger1.debug('Loading configuration')
            self._config = yaml.load(yaml_file)
            logger1.debug('Configuration loaded')

    def __iter__(self):
        for pol in self._config:
            yield pol


class AciMo:
    def __init__(self, url, username, password, secure=False, timeout=60):
        self._url = url
        self._username = username
        self._password = password
        self._secure = secure
        self._timeout = timeout

        requests.packages.urllib3.disable_warnings()

        ls = cobra.mit.session.LoginSession(self._url, self._username, self._password, secure=self._secure, timeout=self._timeout)
        self._md = cobra.mit.access.MoDirectory(ls)
        self._md.login()

        self._fct_pt = {
            'lldp' : cobra.model.lldp.IfPol,
            'lacp' : cobra.model.lacp.LagPol
        }


    def apply(self, pol):
        name = pol.keys()[0].split("/")[1]
        type = pol.keys()[0].split("/")[0]
        props = pol.values()[0]

        polUni = cobra.model.pol.Uni('')
        infraInfra = cobra.model.infra.Infra(polUni)
        self._fct_pt[type](infraInfra, name, **props)

        logger1.warning('Comiting policy {0} of type {1} with properties {2}'.format(name, type, props))
        logger1.debug(toXMLStr(infraInfra))

        try:

            new_config = cobra.mit.request.ConfigRequest()
            new_config.addMo(infraInfra)
            self._md.commit(new_config)

        except Exception as e:
            logger1.critical('Error while comiting policy {0}'.format(name))
            logger1.critical(e)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', action='store', dest='config_file', help='yaml config file')
    parser.add_argument('-c', action='store', dest='url', help='APIC url')
    parser.add_argument('-u', action='store', dest='user', help='APIC User')
    parser.add_argument('-p', action='store', dest='password', help='APIC Password')
    parser_result = parser.parse_args()

    apic1 = AciMo(parser_result.url, parser_result.user, parser_result.password)

    policies = Configuration(parser_result.config_file)

    for pol in policies:
        apic1.apply(pol)


if __name__ == '__main__':
    logger1 = logging.getLogger("__main__")
    logging.basicConfig(level=logging.DEBUG, format='=%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()