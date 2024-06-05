import re
import json
from collections import defaultdict
from logging import getLogger
from time import sleep

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException, SupportsException
from octodns.provider.base import BaseProvider
from octodns.record import Record
from octodns.idna import IdnaDict


__version__ = __VERSION__ = '0.0.4'

# Client Exceptions
class BlueCatClientException(ProviderException):
    pass


class BlueCatClientNotFound(BlueCatClientException):
    def __init__(self):
        super().__init__('Not Found')


class BlueCatClientUnauthorized(BlueCatClientException):
    def __init__(self):
        super().__init__('Unauthorized')


# BlueCat Errors
class BlueCatError(ProviderException):
    def __init__(self, data):
        try:
            message = data['errors'][0]['message']
        except (IndexError, KeyError, TypeError):
            message = 'BlueCatError error'
        super().__init__(message)


class BlueCatAuthenticationError(BlueCatError):
    def __init__(self, data):
        BlueCatError.__init__(self, data)


class BlueCatRateLimitError(BlueCatError):
    def __init__(self, data):
        BlueCatError.__init__(self, data)


class BlueCatClient(object):

    TIMEOUT = 15

    def __init__(self, endpnt, uname, pw, confname, viewname):
        self.log = getLogger(f'BlueCatClient[{id}]')
        self.log.debug(f'__init__: id={id}, username={uname}, token=***, password=***')
        sess = Session()
        self._sess = sess
        self.endpoint = endpnt
        self.retry_count=4,
        self.retry_period=250,

        # Generate token
        resp = self._request(
            'GET',
            path='login',
            params={'username': uname, 'password': pw}
        )
        self.log.debug(f'client: __init__: _request: resp: {resp}')
        if 'BAMAuthToken' in resp:
            token = re.findall('BAMAuthToken: (.+) <-', resp)[0]
            sess.headers.update(
                {
                    'Authorization': f'BAMAuthToken: {token}',
                    'Content-Type': 'application/json',
                    'User-Agent': f'octodns/{octodns_version} octodns-bluecat/{__VERSION__}',
                }
            )
            self.log.debug('__init__: token=%s header=%s', token, sess.headers)
        else:
            raise BlueCatError('Could not generate token.')

        # get the BC Configuration and View Ids
        resp = self._request(
            'GET',
            path='getEntityByName',
            params = {
                'parentId': 0,
                'name': confname,
                'type': 'Configuration',
            }
        )
        self.log.debug('__init__: conf_entity: %s', resp)
        conf_id = resp['id']

        resp = self._request(
            'GET',
            path='getEntityByName',
            params = {
                'parentId': conf_id,
                'name': viewname,
                'type': 'View',
            }
        )
        self.log.debug('_init: view_entity: %s', resp)
        view_id = resp['id']
        self.view_id = view_id

    def _request(self, method, path, params=None, data=None, stream=False):
        url = f'https://{self.endpoint}/Services/REST/v1/{path}'
        resp = self._sess.request(
            method, url, params=params, json=data, timeout=self.TIMEOUT, stream=stream
        )
        self.log.debug('_request:  status=%d', resp.status_code)
        if resp.status_code == 400:
            self.log.debug(f'_request:  resp={resp.text}')
            raise BlueCatError(resp.json())
        if resp.status_code == 401:
            raise BlueCatClientUnauthorized()
        if resp.status_code == 403:
            raise BlueCatAuthenticationError(resp.json())
        if resp.status_code == 404:
            raise BlueCatClientNotFound()
        if resp.status_code == 429:
            raise BlueCatAuthenticationError(resp.json())
        resp.raise_for_status()
        if path == 'exportEntities':
            return resp
        elif path == 'getEntities':
            return resp.json()
        elif path == 'delete':
            return
        else:
            return resp.json()

    # a wrapper around request to deal with delays
    def _try_request(self, *args, **kwargs):
        tries = self.retry_count
        while True:  # We'll raise to break after our tries expire
            try:
                return self._request(*args, **kwargs)
            except BlueCatRateLimitError:
                if tries <= 1:
                    raise
                tries -= 1
                self.log.warning(
                    'rate limit encountered, pausing '
                    'for %ds and trying again, %d remaining',
                    self.retry_period,
                    tries,
                )
                sleep(self.retry_period)


    # generates a dictionary of zones which contain one or more RRs as keys and
    # their respective entity ID as values
    # generates a list of zones which contain one or more RRs:

    def domains(self):
        zones = list()
        zone_names = list()
        rr_ents = self._export_entities('GenericRecord,AliasRecord', self.view_id)
        for rr_ent in rr_ents:
            props = rr_ent['properties']
            pid = props['parentId']
            rr_fqdn = props['absoluteName']
            z_name = rr_fqdn[len(rr_ent['name'])+1:]
            if z_name not in zone_names:
                zone_names.append(z_name)
                zones.append({'name': z_name, 'id': pid})
        return zones

    # determines if a zone exists
    def domain(self, zone):
        params = {
            'start': 0,
            'count': 1,
            'containerId': self.view_id,
            'options': f'hint={zone}|overrideType=Zone|accessRight=VIEW',
        }
        self.log.debug(f'domain: _get_zones_by_hint: params={params}')
        return self._request('GET', 'getZonesByHint', params=params)

    def domain_create(self, name):
        self.log.debug(f'domain_create: creating {name}')
        data = {
            'parentId': self.view_id,
            'absoluteName': name, 
            'properties': 'deployable=false|dynamicUpdate=false',
        }
        resp = self._request('POST', 'addZone', data=data)
        zone_id = resp['id']
        return zone_id

    # types =  "HostRecord,AliasRecord,MXRecord,SRVRecord,TXTRecord,HINFORecord,NAPTRRecord,GenericRecord"
    # records = self._export_entities(types, zone_id)
    # 'properties': 'comments=A solo A Resource Record|absoluteName=Q277_test.277.privatelink.ods.opinsights.azure.com|type=A|rdata=10.141.45.196|'
    def records(self, zone_id):
        rrs = []
        if not zone_id:
            return []
        for typ in ["GenericRecord", "HostRecord", "AliasRecord"]:
            ents = self._get_entities(zone_id, typ)
            for ent in ents:
                prop_data = dict()
                prop_str = ent['properties']
                toks = prop_str.split('|')
                for tok in toks:
                    if len(tok):
                        (key, val) = tok.split('=')
                        prop_data[key] = val
                ent['properties'] = prop_data
                rrs.append(ent)
        return rrs

    # data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|linkedRecordName={val}|port={prt}|priority={pri}|weight={wgt}|'
    # data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|order={order}|preference={pref}|service={srv}|regex={regex}|replacement={rep}|flags={flags}|'
    def record_create(self, pid, ent):
        params = {'parentId': pid}
        self.log.debug(f'record_create: zoneID={pid} payload: {ent}')
        self._request('POST', 'addEntity', params=params, data=ent)

    def record_delete(self, ent_id):
        self._try_request('DELETE', 'delete', params={'objectId': ent_id})


    def _export_zone_entities(self):
        zones = self._export_entities('Zone', self.view_id)
        return zones


    #
    # Get all entities and their descendents matching a certain type
    #
    def _export_entities(self, types, startid):
        ents = []
        select = {
            'selector': 'get_entitytree',
            'types': types,
            'startEntityId': startid
        }
        params = {
            'selectCriteria': json.dumps(select),
            'count': 60000
        }
        self.log.debug(f'_export_entities: types={types} params={params}')
        resp = self._request(
            'GET',
            'exportEntities',
            params=params,
            stream=True
        )
        for line in resp.iter_lines():
            if line:
                decoded_line = line.decode('utf-8')
                ents.append(json.loads(decoded_line))
        return ents

    # Format of RRs. from getEntities params = {'parentId': id, type='GenericRecord', start=0, count=100}
    # Generic Records:
    # [ { 'id': 2866216, 'name': 'Q277_test', 'type': 'GenericRecord',
    #     'properties': 'comments=A solo A Resource Record|absoluteName=Q277_test.277.privatelink.ods.opinsights.azure.com|type=A|rdata=10.141.45.196|' }, ]

    def _get_entities(self, pid, typ):
        params = {
            'start': 0,
            'count': 200,
            'parentId': pid,
            'type': typ,
        }
        resp = self._request(
            'GET',
            'getEntities',
            params=params
        )
        return resp


class BlueCatProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'A6',
            'CNAME',
            'MX',
            'NAPTR',
            'SPF',
            'SRV',
            'TXT',
        )
    )
    BC_OBJ_TYPES = set(
        (
            'Entity',
            'Configuration',
            'View',
            'Zone',
            'HostRecord',
            'AliasRecord',
            'MXRecord',
            'TXTRecord',
            'SRVRecord',
            'GenericRecord',
            'HINFORecord',
            'NAPTRRecord',
            'StartOfAuthority',
            'ExternalHostRecord',
        )
    )
    BC_RR_TYPE_MAP = {
        'CNAME': {'obj_type': 'AliasRecord', 'prop_keys': ['linkedRecordName']},
        'MX': {'obj_type': 'MXRecord', 'prop_keys': ['linkedRecordName']},
        'TXT': {'obj_type': 'TXTRecord', 'prop_keys': ['txt']},
        'HINFO': {'obj_type': 'HINFORecord', 'prop_keys': ['cpu','os']},
        'a': {'obj_type': 'HostRecord', 'prop_keys': ['addresses']},
        'A': {'obj_type': 'GenericRecord', 'prop_keys': ['rdata']},
        'AAAA': {'obj_type': 'GenericRecord', 'prop_keys': ['rdata']},
        'PTR': {'obj_type': 'GenericRecord', 'prop_keys': ['rdata']},
        'SPF': {'obj_type': 'GenericRecord', 'prop_keys': ['rdata']},
        'NAPTR': {'obj_type': 'NAPTRRecord', 'prop_keys': ['regexp', 'service', 'preference', 'flags', 'replacement', 'order']},
        'SRV': {'obj_type': 'SRVRecord', 'prop_keys': ['linkedRecordName', 'port', 'weight', 'priority']},
        }

    MIN_TTL = 3600

    def __init__(
        self,
        id,
        endpoint=None,
        username=None,
        password=None,
        confname=None,
        viewname=None,
        retry_count=4,
        retry_period=250,
        *args,
        **kwargs
    ):
        self.log = getLogger(f'BlueCatProvider[{id}]')
        self.log.debug(f'__init__: id={id}, username={username}, token=***, password=***')
        super().__init__(id, *args, **kwargs)
        self._client = BlueCatClient(endpoint, username, password, confname, viewname)

        self._zones = None
        self._zone_records = {}
        self.comment = 'OctoDNS generated'


    def _change_keyer(self, change):
        key = change.__class__.__name__
        order = {'Delete': 0, 'Create': 1, 'Update': 2}
        return order[key]

    # returns to OctoDNS a list of all leaf Zones from a Provider as a dictionary:
    # { 'zone1_fqdn': zone1_id, 'zone2_fqdn': zone2_id }
    # _zones becomes a class operator

    @property
    def zones(self):
        if self._zones is None:
            zones = self._client.domains()
            self._zones = IdnaDict({f'{z["name"]}.': z["id"] for z in zones})
        return self._zones

    """
    All RRs using ExportEntities and a get_entitity tree selector:
    {'name': 'generic', 'id': 2915663, 'type': 'GenericRecord', 
      'properties': {'comments': 'Generic generic record', 'absoluteName': 'generic.123.test', 'rdata': '128.100.102.10', 'type': 'A', 'ttl': 7200, 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'q278_test', 'id': 2915683, 'type': 'GenericRecord',
    'properties': {'comments': 'Aure like record', 'absoluteName': 'q278_test.bozo.test', 'rdata': '10.141.1.2', 'type': 'A', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'ptr', 'id': 2917713, 'type': 'GenericRecord',
    'properties': {'comments': 'Adding a PTR record', 'absoluteName': 'ptr.123.test', 'rdata': '10.141.10.1', 'type': 'PTR', 'ttl': 900, 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'spf', 'id': 2917715, 'type': 'GenericRecord',
    'properties': {'comments': 'SPF record test', 'absoluteName': 'spf.123.test', 'rdata': 'Funky SPF data', 'type': 'SPF', 'ttl': 9999, 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'text', 'id': 2915664, 'type': 'TXTRecord',
    'properties': {'txt': 'Test Text Record', 'comments': 'Generic TXT Record', 'absoluteName': 'text.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'moretext', 'id': 2915665, 'type': 'TXTRecord',
    'properties': {'txt': 'Two Txt Records', 'comments': 'YATR OK', 'absoluteName': 'moretext.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'mx', 'id': 2915667, 'type': 'GenericRecord',
    'properties': {'comments': 'SMTP host', 'absoluteName': 'mx.bozo.test', 'rdata': '128.100.103.17', 'type': 'A', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'mail', 'id': 2915671, 'type': 'MXRecord',
    'properties': {'comments': 'Generic MX record', 'linkedRecordName': 'mx.bozo.test', 'absoluteName': 'mail.bozo.test', 'priority': 10, 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'mx', 'id': 2915672, 'type': 'HINFORecord',
    'properties': {'comments': 'Generic HINFO record', 'os': 'OpenBSD', 'absoluteName': 'mx.bozo.test', 'cpu': 'x86', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'mailer', 'id': 2915674, 'type': 'AliasRecord',
    'properties': {'comments': 'Generic CNAME', 'linkedRecordName': 'mx.bozo.test', 'absoluteName': 'mailer.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'host', 'id': 2915676, 'type': 'HostRecord',
    'properties': {'addresses': '10.10.10.10', 'comments': 'Generic Host record', 'absoluteName': 'host.bozo.test', 'reverseRecord': True, 'addressIds': '2520866', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'toast', 'id': 2915677, 'type': 'AliasRecord',
    'properties': {'comments': 'Generic Host record', 'linkedRecordName': 'host.bozo.test', 'absoluteName': 'toast.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
    {'name': 'naptr', 'id': 2915679, 'type': 'NAPTRRecord',
    'properties': {'regexp': '!^.*$!sip:customer-service@bozo.test!', 'comments': 'Test NAPTR record', 'absoluteName': 'naptr.bozo.test', 'service': 'SIP', 'preference': 10, 'flags': 'S', 'replacement': 'mx.bozo.test', 'parentId': 2915662, 'parentType': 'Zone', 'order': 100}}
    {'name': 'sipper', 'id': 2915682, 'type': 'SRVRecord',
    'properties': {'comments': 'Generic SRV record', 'linkedRecordName': 'host.bozo.test', 'port': 5060, 'absoluteName': 'sipper.bozo.test', 'weight': 20, 'priority': 10, 'parentId': 2915662, 'parentType': 'Zone'}}

    MX Records
    [
    {'id': 2429335, 'name': '', 'type': 'MXRecord'}, 'properties': 'ttl=86400|absoluteName=theta.utoronto.ca|linkedRecordName=alt2.aspmx.l.google.com|priority=5|',
    {'id': 2429340, 'name': '', 'type': 'MXRecord'}, 'properties': 'ttl=86400|absoluteName=lcd.utoronto.ca|linkedRecordName=aspmx3.googlemail.com|priority=10|',
    {'id': 2429341, 'name': '', 'type': 'MXRecord'} 'properties': 'ttl=86400|absoluteName=lcd.utoronto.ca|linkedRecordName=aspmx2.googlemail.com|priority=10|',
    ]
    """

    def _export_entities(self, types, startid):
        ents = []
        select = {
            'selector': 'get_entitytree',
            'types': types,
            'startEntityId': startid
        }
        params = {
            'selectCriteria': json.dumps(select),
            'start': 0,
            'count': 60000
        }
        self.log.debug('_export_entities: types=%s params=%s', types, params)
        resp = self._try_request('GET', 'exportEntities', params=params, stream=True)
        for line in resp.iter_lines():
            if line:
                decoded_line = line.decode('utf-8')
                ents.append(json.loads(decoded_line))
        return ents


    # return the ttl value in a properties dict else the default
    def _ttl_data(self, props):
        if 'ttl' in props:
            return props['ttl']
        else:
            return self.MIN_TTL


    def _data_for_generic(self, _type, records):
        return {
            'ttl': self._ttl_data(records[0]['properties']),
            'type': _type,
            'values': [r['properties']['rdata'] for r in records],
        }

    _data_for_A = _data_for_generic
    _data_for_AAAA = _data_for_generic
    _data_for_A6 = _data_for_generic
    _data_for_SPF = _data_for_generic


    def _data_for_HOST(self, _type, records):
        return {
            'ttl': self._ttl_data(records[0]['properties']),
            'type': 'A',
            'values': [r['properties']['addresses'] for r in records],
        }


    def _data_for_TXT(self, _type, records):
        values = [r['properties']['txt'].replace(';', '\\;') for r in records]
        return {
            'ttl': self._ttl_data(records[0]['properties']),
            'type': _type,
            'values': values
        }


    def _data_for_CNAME(self, _type, records):
        props = records[0]['properties']
        return {
            'ttl': self._ttl_data(props),
            'type': _type,
            'value': f'{props["linkedRecordName"]}.',
        }

    _data_for_Alias = _data_for_CNAME


    def _data_for_HINFO(self, _type, records):
        values = []
        only = records[0]
        for r in records:
            props = r['properties']
            values.append({ 'os': props['os'], 'cpu': props['cpu']})
        return {
            'ttl': self._ttl_data(only['properties']),
            'type': _type,
            'values': values
        }


    def _data_for_MX(self, _type, records):
        values = []
        only = records[0]
        for r in records:
            props = r['properties']
            values.append(
                {
                    'preference': props['priority'],
                    'exchange': f'{props["linkedRecordName"]}.' 
                }
            )
        return {
            'ttl': self._ttl_data(only['properties']),
            'type': _type,
            'values': values
        }


    def _data_for_NAPTR(self, _type, records):
        values = []
        for r in records:
            data = r['properties']
            values.append(
                {
                    'flags': data['flags'],
                    'preference': data['preference'],
                    'regexp': data['regexp'],
                    'replacement': data['replacement'],
                    'service': data['service'],
                    'order': data['order'],
                }
            )
        return {
            'ttl': self._ttl_data(records[0]['properties']),
            'type': _type,
            'values': values,
        }

    """
    Data from BC Export Entities to YAML
    YAML:
    _sip._tcp:
      ttl: 600
      type: SRV
      value:
        port: 5060
        priority: 10
        target: host.123.test.
        weight: 20

    BC Export Entities -> get_entity_tree format: JSON
    {
     'name': 'sipper', 'id': 2915682, 'type': 'SRVRecord',
     'properties': {'comments': 'Generic SRV record', 'linkedRecordName': 'host.bozo.test', 'port': 5060, 'absoluteName': 'sipper.bozo.test', 'weight': 20, 'priority': 10, 'parentId': 2915662, 'parentType': 'Zone'}
    }
    """

    def _data_for_SRV(self, _type, records):
        values = []
        for r in records:
            props = r['properties']
            dd = dict()
            for tag in ['port', 'priority', 'weight']:
                dd[tag] = props[tag]
            dd['target'] = f'{props["linkedRecordName"]}.'
            values.append(dd)
        return {
            'type': _type,
            'ttl': self._ttl_data(records[0]['properties']),
            'values': values,
        }


    # gets the RRs for a ZONE using the ExportEntities API function
    # returns a list of RRs, as BC entities
    # sets _zone_records['zonename']  subclass as the list of BC RRs for a zone

    def zone_records(self, zone):
        self.log.debug(f'zone_records: zone: {zone.name}')
        self.log.debug(f'zone_records: {self._zone_records}')
        if zone.name not in self._zone_records:
            zone_id = self.zones.get(zone.name, False)
            try:
                self._zone_records[zone.name] = self._client.records(zone_id)
            except BlueCatClientNotFound:
                return []
        return self._zone_records[zone.name]


    def _record_for(self, zone, name, _type, records, lenient):
        data_for = getattr(self, f'_data_for_{_type}')
        data = data_for(_type, records)
        record = Record.new(zone, name, data, source=self, lenient=lenient)
        return record

    def list_zones(self):
        return sorted(self.zones.keys())

    # takes the data from BC via the API to prepare it for the (local/yaml) destination
    # calls zone_records to get the RRs on a zone by zone basis
    # values ends up in the YAML Provider

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(f'populate: name={zone.name}, target={target}, lenient={lenient}')

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            self.log.debug(f'populate: record: {record}')
            _type = self._mod_type(record)
            if _type not in self.SUPPORTS:
                self.log.warning(f'populate: skipping unsupported RR type: {_type}')
                continue
            values[record['name']][_type].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
               data_for = getattr(self, f'_data_for_{_type}')
               record = Record.new(
                   zone,
                   name,
                   data_for(_type, records),
                   source=self,
                   lenient=lenient,
               )
               zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        nrecs = len(zone.records) - before
        self.log.info( f'populate: found {nrecs} records, exists={exists}')
        return exists

    # convert from BC RRytpe to regular RRtypes
    def _mod_type(self, rr):
        bc_type = rr['type'][:-6]
        if bc_type == 'Generic':
            rr_type = rr['properties']['type']
        elif bc_type == 'Alias':
            rr_type = 'CNAME'
        elif bc_type == 'Host':
            rr_type = 'APTR'
        else:
            rr_type = bc_type
        return rr_type

    """
     NAPTRRecord addEntity format
         {'id': 2915679, 'name': 'naptr', 'type': 'NAPTRRecord',
         'properties': 'comments=Test NAPTR record|absoluteName=naptr.123.test|order=100|preference=10|service=SIP|regexp=!^.*$!sip:customer-service@bozo.test!|replacement=mx.bozo.test|flags=S|'}

    """
    def _params_for_NAPTR(self, record):
        zone_name = record.zone.name
        fqdn = f'{record.name}.{zone_name}'[:-1]
        for value in record.values:
            props = f'comments={self.comment}|ttl={record.ttl}|absoluteName={fqdn}|order={value.order}|preference={value.preference}|service=value.service|regexp={value.regexp}|replacement={value.replacement}|flags={value.flags}'
            entity = {
                    'name': record.name,
                    'type': f'{record._type}Record',
                    'properties': props
            }
            yield entity

    """
    BC addEntity format
    {'id': 2915674, 'name': 'mailer', 'type': 'AliasRecord', 'properties': 'comments=Generic CNAME|absoluteName=mailer.123.test|linkedRecordName=mx.bozo.test|'}
    """
    def _params_for_CNAME(self, record):
        zone_name = record.zone.name
        fqdn = f'{record.name}.{zone_name}'[:-1]
        props = f'comments={self.comment}|ttl={record.ttl}|absoluteName={fqdn}|linkedRecordName={record.value}|'
        entity = {
                'name': record.name,
                'type': 'AliasRecord',
                'properties': props
        }
        yield entity

    """
    BC addEntity format
    {'id': 2915671, 'name': 'mail', 'type': 'MXRecord', 'properties': 'comments=Generic MX record|absoluteName=mail.123.test|linkedRecordName=mx.bozo.test|priority=10|'}
    """
    def _params_for_MX(self, record):
        zone_name = record.zone.name
        fqdn = f'{record.name}.{zone_name}'[:-1]
        for value in record.values:
            props = f'comments={self.comment}|ttl={record.ttl}|absoluteName={fqdn}|linkedRecordName={value.exchange[:-1]}|priority={value.preference}|'
            entity = {
                'name': record.name,
                'type': f'{record._type}Record',
                'properties': props
            }
            yield entity

    """
    Prepares data to be written into from YAML to BC addEntity Format:
    YAML:
    _sip._tcp:
      ttl: 600
      type: SRV
      value:
        port: 5060
        priority: 10
        target: host.123.test.
        weight: 20
    BC SRVRecord Entity
    {
        'id': 2917727, 'name': '_sip._tcp', 'type': 'SRVRecord',
        'properties': 'comments=Need to reformat|ttl=600|absoluteName=_sip._tcp.123.test|linkedRecordName=host.123.test|port=5060|priority=10|weight=20|'
    }

    """
    def _params_for_SRV(self, record):
        zone_name = record.zone.name
        fqdn = f'{record.name}.{zone_name}'[:-1]
        for value in record.values:
            props = f'comments={self.comment}|ttl={record.ttl}|absoluteName={fqdn}|linkedRecordName={value.target[:-1]}|port={value.port}|priority={value.priority}|weight={value.weight}|'
            entity = {
                    'name': record.name,
                    'type': f'{record._type}Record',
                    'properties': props,
            }
            yield entity

    """
    TXTRecord Entity
    {'id': 2519630, 'name': '', 'type': 'TXTRecord', 'properties': 'comments=Zone Information|ttl=7600|absoluteName=yes.uoft.ca|txt=STOP GO|'}
    """
    def _params_for_TXT(self, record):
        zone_name = record.zone.name
        fqdn = f'{record.name}.{zone_name}'[:-1]
        rr_type = f'{record._type}Record'
        for value in record.values:
            text = value.replace('\\;', ';')
            props = f'comments={self.comment}|ttl={record.ttl}|absoluteName={fqdn}|txt={text}|'
            entity = {
                'name': record.name,
                'type': rr_type,
                'properties': props
            }
            yield entity

    """
    GenericRecord: A record
    {'id': 2915663, 'name': 'generic', 'type': 'GenericRecord', 'properties': 'comments=Generic generic record|ttl=7200|absoluteName=generic.123.test|type=A|rdata=128.100.102.10|'}
    """
    def _params_for_multiple(self, record):
        zone_name = record.zone.name
        fqdn = f'{record.name}.{zone_name}'[:-1]
        for value in record.values:
            props = f'comments={self.comment}|ttl={record.ttl}|absoluteName={fqdn}|type={record._type}|rdata={value}|'
            entity = {
                'name': record.name,
                'type': f'GenericRecord',
                'properties': props
            }
            yield entity

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple



    def _apply_Create(self, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')
        zone_id = self.zones[new.zone.name]
        for params in params_for(new):
            self._client.record_create(zone_id, params)

    def _apply_Delete(self, change):
        existing = change.existing
        name = existing.name
        _type = existing._type
        bc_map = self.BC_RR_TYPE_MAP[_type]
        bc_type = bc_map['obj_type']
        for record in self.zone_records(existing.zone):
            if record['name'] == existing.name and record['type'] == bc_type:
                entid = record['id']
                props = record['properties']
                if 'type' in props and props['type'] == _type:
                    self._client.record_delete(entid)
                else:
                    self._client.record_delete(entid)

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        domain_name = desired.name[:-1]
        try:
            self._client.domain(domain_name)
        except BlueCatClientNotFound:
            self.log.debug(f'_apply: no matching zone, creating one...')
            zid = self._client.domain_create(domain_name)
            self.zones[name] = zone_id
            self._zone_records[name] = {}

        # Force the operation order to be Delete() -> Create() -> Update()
        # This will help avoid problems in updating a CNAME record into an
        # A record and vice-versa
        changes.sort(key=self._change_keyer)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # clear the cache if any
        self._zone_records.pop(desired.name, None)

    def _extra_changes(self, existing, desired, changes):
        extra_changes = []

        existing_records = {r: r for r in existing.records}
        changed_records = {c.record for c in changes}

        for desired_record in desired.records:
            existing_record = existing_records.get(desired_record, None)
            if not existing_record:  # Will be created
                continue
            elif desired_record in changed_records:  # Already being updated
                continue

        return extra_changes
