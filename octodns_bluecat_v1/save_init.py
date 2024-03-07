import re
import json
from collections import defaultdict
from copy import deepcopy
from logging import getLogger
from time import sleep
from urllib.parse import urlsplit

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.idna import IdnaDict
from octodns.provider import ProviderException, SupportsException
from octodns.provider.base import BaseProvider
from octodns.record import Create, Record, Update

__VERSION__ = '0.0.1'

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


_PROXIABLE_RECORD_TYPES = {'A', 'AAAA', 'Alias', 'CNAME'}

class BlueCatProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'A6',
            'APTR'
            'CNAME',
            'MX',
            'NAPTR',
            'SRV',
            'TXT',
        )
    )

    MIN_TTL = 120
    TIMEOUT = 15

    def __init__(
        self,
        id,
        endpoint,
        username=None,
        password=None,
        token=None,
        confname=None,
        viewname=None,
        conf_id=None,
        view_id=None,
        retry_count=4,
        retry_period=300,
        *args,
        **kwargs,
    ):
        self.log = getLogger('BlueCatProvider[{id}]')
        self.log.debug(
            '__init__: id=%s, username=%s, token=***, password=***',
            id,
            username,
        )
        super().__init__(id, *args, **kwargs)

        sess = Session()
        self._sess = sess
        self.endpoint = endpoint
        if username and password:
            # Generate token
            rv = self._request(
                'GET',
                path='login',
                params={'username': username, 'password': password}
            )
            if 'BAMAuthToken' in rv:
                token = re.findall('BAMAuthToken: (.+) <-', rv)[0]
                self.token = token
            else:
                raise BlueCatError('Could not generate token.')
        else:
            self.token = token
        sess.headers.update({'Authorization': f'BAMAuthToken: {token}'})
        sess.headers.update({'Content-Type': 'application/json'})
        sess.headers.update({'User-Agent': f'octodns/{octodns_version} octodns-bluecat/{__VERSION__}'})
        self.log.debug('_init: token=%s header=%s', token, sess.headers)

        # get the BC Configuration and View Ids
        rv = self._request(
                'GET',
                path='getEntityByName',
                params = {'parentId': 0, 'name': confname, 'type': 'Configuration'}
        )
        self.log.debug('_init: conf_entity: %s', rv)
        conf_id = rv['id']
        rv = self._request(
                'GET',
                path='getEntityByName',
                params = {'parentId': conf_id, 'name': viewname, 'type': 'View'}
        )
        self.log.debug('_init: view_entity: %s', rv)
        view_id = rv['id']

        self.conf_id = conf_id
        self.view_id = view_id
        self.retry_count = retry_count
        self.retry_period = retry_period

        self._zones = None
        self._zone_records = {}

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

    def _request(self, method, path, params=None, data=None, stream=False):
        self.log.debug('_request: method=%s, path=%s', method, path)

        url = f'https://{self.endpoint}/Services/REST/v1/{path}'
        resp = self._sess.request(
            method, url, params=params, json=data, timeout=self.TIMEOUT, stream=stream
        )
        self.log.debug('_request:   status=%d', resp.status_code)
        if resp.status_code == 400:
            self.log.debug('_request:   data=%s', data)
            raise BlueCatError(resp.json())
        if resp.status_code == 403:
            raise BlueCatAuthenticationError(resp.json())
        if resp.status_code == 429:
            raise BlueCatAuthenticationError(resp.json())

        resp.raise_for_status()
        if path != 'exportEntities':
            return resp.json()
        else:
            return resp

    def _change_keyer(self, change):
        key = change.__class__.__name__
        order = {'Delete': 0, 'Create': 1, 'Update': 2}
        return order[key]

    @property
    # returns to OctoDNS a list of all Zones from a Provider as a dictionary:
    # { 'zone1_fqdn': zone1_id, 'zone2_fqdn': zone2_id }
    # _zones becomes a class operator
    def zones(self):
        if self._zones is None:
            zones = self._export_leaf_zone_entities()
            # List of zones:
            # [{'id': '', 'name': ''}] -> {'name': 'id'}
            self._zones = IdnaDict(
                {f'{z["properties"]["absoluteName"]}.': z['id'] for z in zones}
            )
        return self._zones

    # does the actual API call to get the Zone or RR entities
    def _export_entities(self, types, startid):
        ents = []
        select = {
                'selector': 'get_entitytree',
                'types': types,
                'startEntityId': startid
        }
        json_select = json.dumps(select)
        params = {
            'selectCriteria': json_select,
            'start': 0,
            'count': 3000
        }
        self.log.debug('_export_entities: types=%s params=%s', types, params)
        resp = self._try_request('GET', 'exportEntities', params=params, stream=True)
        for line in resp.iter_lines():
            if line:
                decoded_line = line.decode('utf-8')
                ents.append(json.loads(decoded_line))
        return ents

    def _export_zone_entities(self):
        zones = self._export_entities('Zone', self.view_id)
        return zones

    def _export_leaf_zone_entities(self):
        ents = []
        zones = self._export_zone_entities()
        for zone in zones:
            if re.match('[0-9][0-9][0-9]', zone['name']):
                ents.append(zone)
        return ents

    def _ttl_data(self, props):
        if 'ttl' in props:
            return props['ttl']
        else:
            return 3600

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
        return {
            'ttl': self._ttl_data(records[0]['properties']),
            'type': _type,
            'values': [r['properties']['txt'].replace(';', '\\;') for r in records],
        }

    def _data_for_CNAME(self, _type, records):
        only = records[0]
        props = only['properties']
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

    def _data_for_SRV(self, _type, records):
        values = []
        for r in records:
            props = r['properties']
            values.append(
                {
                    'priority': props['priority'],
                    'weight': props['weight'],
                    'port': props['port'],
                    'target': f'{props["linkedRecordName"]}.',
                }
            )
        return {
            'type': _type,
            'ttl': self._ttl_data(records[0]['properties']),
            'values': values,
        }

        """
        Format of RRs. from getEntities
        params = {'parentId': id, type='GenericRecord', start=0, count=100}
        Generic Records:
        [
         { 'id': 2866216, 'name': 'Q277_test', 'type': 'GenericRecord',
         'properties': 'comments=A solo A Resource Record|absoluteName=Q277_test.277.privatelink.ods.opinsights.azure.com|type=A|rdata=10.141.45.196|'},
         { 'id': 2866849, 'name': 'n277_test', 'type': 'GenericRecord',
         'properties': 'comments=A solo A Resource Record|absoluteName=n277_test.277.privatelink.ods.opinsights.azure.com|type=A|rdata=10.141.118.199|'}
        ]
        All RRs using ExportEntities
        {'name': 'generic', 'id': 2915663, 'type': 'GenericRecord', 'properties': {'comments': 'Generic generic record', 'absoluteName': 'generic.123.test', 'rdata': '128.100.102.10', 'type': 'A', 'ttl': 7200, 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'q278_test', 'id': 2915683, 'type': 'GenericRecord', 'properties': {'comments': 'Aure like record', 'absoluteName': 'q278_test.bozo.test', 'rdata': '10.141.1.2', 'type': 'A', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'ptr', 'id': 2917713, 'type': 'GenericRecord', 'properties': {'comments': 'Adding a PTR record', 'absoluteName': 'ptr.123.test', 'rdata': '10.141.10.1', 'type': 'PTR', 'ttl': 900, 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'spf', 'id': 2917715, 'type': 'GenericRecord', 'properties': {'comments': 'SPF record test', 'absoluteName': 'spf.123.test', 'rdata': 'Funky SPF data', 'type': 'SPF', 'ttl': 9999, 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'text', 'id': 2915664, 'type': 'TXTRecord', 'properties': {'txt': 'Test Text Record', 'comments': 'Generic TXT Record', 'absoluteName': 'text.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'moretext', 'id': 2915665, 'type': 'TXTRecord', 'properties': {'txt': 'Two Txt Records', 'comments': 'YATR OK', 'absoluteName': 'moretext.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'mx', 'id': 2915667, 'type': 'GenericRecord', 'properties': {'comments': 'SMTP host', 'absoluteName': 'mx.bozo.test', 'rdata': '128.100.103.17', 'type': 'A', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'mail', 'id': 2915671, 'type': 'MXRecord', 'properties': {'comments': 'Generic MX record', 'linkedRecordName': 'mx.bozo.test', 'absoluteName': 'mail.bozo.test', 'priority': 10, 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'mx', 'id': 2915672, 'type': 'HINFORecord', 'properties': {'comments': 'Generic HINFO record', 'os': 'OpenBSD', 'absoluteName': 'mx.bozo.test', 'cpu': 'x86', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'mailer', 'id': 2915674, 'type': 'AliasRecord', 'properties': {'comments': 'Generic CNAME', 'linkedRecordName': 'mx.bozo.test', 'absoluteName': 'mailer.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'host', 'id': 2915676, 'type': 'HostRecord', 'properties': {'addresses': '10.10.10.10', 'comments': 'Generic Host record', 'absoluteName': 'host.bozo.test', 'reverseRecord': True, 'addressIds': '2520866', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'toast', 'id': 2915677, 'type': 'AliasRecord', 'properties': {'comments': 'Generic Host record', 'linkedRecordName': 'host.bozo.test', 'absoluteName': 'toast.bozo.test', 'parentId': 2915662, 'parentType': 'Zone'}}
        {'name': 'naptr', 'id': 2915679, 'type': 'NAPTRRecord', 'properties': {'regexp': '!^.*$!sip:customer-service@bozo.test!', 'comments': 'Test NAPTR record', 'absoluteName': 'naptr.bozo.test', 'service': 'SIP', 'preference': 10, 'flags': 'S', 'replacement': 'mx.bozo.test', 'parentId': 2915662, 'parentType': 'Zone', 'order': 100}}
        {'name': 'sipper', 'id': 2915682, 'type': 'SRVRecord', 'properties': {'comments': 'Generic SRV record', 'linkedRecordName': 'host.bozo.test', 'port': 5060, 'absoluteName': 'sipper.bozo.test', 'weight': 20, 'priority': 10, 'parentId': 2915662, 'parentType': 'Zone'}}
        Format of RRs from CloudFlare:
        --url https://api.cloudflare.com/client/v4/zones/zone_identifier/dns_records
        Response:
        {
          "errors": [],
          "messages": [],
          "result": [
            {
              "content": "198.51.100.4",
              "name": "example.com",
              "proxied": false,
              "type": "A",
              "comment": "Domain verification record",
              "created_on": "2014-01-01T05:20:00.12345Z",
              "id": "023e105f4ecef8ad9ca31a8372d0c353",
              "locked": false,
              "meta": { "auto_added": true, "source": "primary" },
              "modified_on": "2014-01-01T05:20:00.12345Z",
              "proxiable": true,
              "tags": [ "owner:dns-team" ],
              "ttl": 3600,
              "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
              "zone_name": "example.com"
            }
          ],
          "success": true,
          "result_info": { "count": 1, "page": 1, "per_page": 20, "total_count": 2000 }
        }

        """

    # gets the RRs for a ZONE using the ExportEntities API function
    # returns a list of RRs, as BC entities
    # sets _zone_records['zonename']  subclass as the list of BC RRs for a zone
    def zone_records(self, zone):
        self.log.debug(f'zone_records: zone: {zone.name}')
        if zone.name not in self._zone_records:
            zone_id = self.zones.get(zone.name, False)
            if not zone_id:
                return []
        records = []
        types = 'HostRecord,AliasRecord,MXRecord,SRVRecord,TXTRecord,HINFORecord,NAPTRRecord,GenericRecord'
        records = self._export_entities(types, zone_id)
        self.log.debug('zone_records: zone_id:%s, types=%s, records=%s', zone_id, types, records)
        self._zone_records[zone.name] = records
        return records

    def _record_for(self, zone, name, _type, records, lenient):
        data_for = getattr(self, f'_data_for_{_type}')
        data = data_for(_type, records)
        record = Record.new(zone, name, data, source=self, lenient=lenient)
        return record

    def list_zones(self):
        return sorted(self.zones.keys())

    # takes the data from BC via the API to prepare it for the (local/yaml)
    # destination
    # calls zone_records to get the RRs on a zone by zone basis
    # values ends up in the YAML Provider
    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        records = self.zone_records(zone)
        before = len(zone.records)
        exists = False

        if records:
            exists = True
            values = defaultdict(lambda: defaultdict(list))
            for record in records:
                _type = self._mod_type(record)
                if _type not in self.SUPPORTS:
                    continue
                name = record['name']
                values[name][_type].append(record)

            for name, types in values.items():
                for _type, records in types.items():
                    record = self._record_for(zone, name, _type, records, lenient)
                    zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

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

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'rdata': value,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple
    _params_for_SPF = _params_for_multiple

    def _params_for_NAPTR(self, record):
        for value in record.values:
            content = (
                f'{value.order} {value.preference} "{value.flags}" '
                f'"{value.service}" "{value.regexp}" {value.replacement}'
            )
            yield {
                'rdata': content,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_single(self, record):
        yield {
            'rdata': record.value,
            'name': record.name,
            'ttl': record.ttl,
            'type': record._type
        }

    _params_for_CNAME = _params_for_single

    def _params_for_MX(self, record):
        for value in record.values:
            yield {
                'rdata': value.exchange,
                'name': record.name,
                'priority': value.preference,
                'ttl': record.ttl,
                'type': record._type
            }

    def _params_for_SRV(self, record):
        for value in record.values:
            yield {
                'rdata': f'{value.priority} {value.weight} {value.port} {value.target}',
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_TXT(self, record):
        for value in record.values:
            yield {
                'rdata': value.replace('\\;', ';'),
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _contents_for_multiple(self, record):
        for value in record.values:
            yield {'content': value}

    _contents_for_A = _contents_for_multiple
    _contents_for_AAAA = _contents_for_multiple
    _contents_for_SPF = _contents_for_multiple

    def _contents_for_TXT(self, record):
        for value in record.values:
            yield {'content': value.replace('\\;', ';')}

    def _contents_for_CNAME(self, record):
        yield {'content': record.value}

    _contents_for_PTR = _contents_for_CNAME

    def _contents_for_LOC(self, record):
        for value in record.values:
            yield {
                'data': {
                    'lat_degrees': value.lat_degrees,
                    'lat_minutes': value.lat_minutes,
                    'lat_seconds': value.lat_seconds,
                    'lat_direction': value.lat_direction,
                    'long_degrees': value.long_degrees,
                    'long_minutes': value.long_minutes,
                    'long_seconds': value.long_seconds,
                    'long_direction': value.long_direction,
                    'altitude': value.altitude,
                    'size': value.size,
                    'precision_horz': value.precision_horz,
                    'precision_vert': value.precision_vert,
                }
            }

    def _contents_for_MX(self, record):
        for value in record.values:
            yield {'priority': value.preference, 'content': value.exchange}

    def _contents_for_NAPTR(self, record):
        for value in record.values:
            yield {
                'data': {
                    'flags': value.flags,
                    'order': value.order,
                    'preference': value.preference,
                    'regex': value.regexp,
                    'replacement': value.replacement,
                    'service': value.service,
                }
            }

    def _contents_for_SSHFP(self, record):
        for value in record.values:
            yield {
                'data': {
                    'algorithm': value.algorithm,
                    'type': value.fingerprint_type,
                    'fingerprint': value.fingerprint,
                }
            }

    def _contents_for_SRV(self, record):
        try:
            service, proto, subdomain = record.name.split('.', 2)
            # We have a SRV in a sub-zone
        except ValueError:
            # We have a SRV in the zone
            service, proto = record.name.split('.', 1)
            subdomain = None

        name = record.zone.name
        if subdomain:
            name = subdomain

        for value in record.values:
            target = value.target[:-1] if value.target != "." else "."

            yield {
                'data': {
                    'service': service,
                    'proto': proto,
                    'name': name,
                    'priority': value.priority,
                    'weight': value.weight,
                    'port': value.port,
                    'target': target,
                }
            }

    def _contents_for_TLSA(self, record):
        for value in record.values:
            yield {
                'data': {
                    'usage': value.certificate_usage,
                    'selector': value.selector,
                    'matching_type': value.matching_type,
                    'certificate': value.certificate_association_data,
                }
            }

    def _contents_for_URLFWD(self, record):
        name = record.fqdn[:-1]
        for value in record.values:
            yield {
                'targets': [
                    {
                        'target': 'url',
                        'constraint': {
                            'operator': 'matches',
                            'value': name + value.path,
                        },
                    }
                ],
                'actions': [
                    {
                        'id': 'forwarding_url',
                        'value': {
                            'url': value.target,
                            'status_code': value.code,
                        },
                    }
                ],
                'status': 'active',
            }


    def _gen_data(self, record):
        name = record.fqdn[:-1]
        _type = record._type
        ttl = max(self.MIN_TTL, record.ttl)

        contents_for = getattr(self, f'_contents_for_{_type}')
        for content in contents_for(record):
            content.update({'name': name, 'type': _type, 'ttl': ttl})
            yield content

    def _gen_key(self, data):
        # Note that most CF record data has a `content` field the value of
        # which is a unique/hashable string for the record's. It includes all
        # the "value" bits, but not the secondary stuff like TTL's. E.g.  for
        # an A it'll include the value, for a CAA it'll include the flags, tag,
        # and value, ... We'll take advantage of this to try and match up old &
        # new records cleanly. In general when there are multiple records for a
        # name & type each will have a distinct/consistent `content` that can
        # serve as a unique identifier.
        # BUT... there are exceptions. MX, CAA, LOC and SRV don't have a simple
        # content as things are currently implemented so we need to handle
        # those explicitly and create unique/hashable strings for them.
        # AND... for URLFWD/Redirects additional adventures are created.
        _type = data.get('type', 'URLFWD')
        if _type == 'MX':
            priority = data['priority']
            content = data['content']
            return f'{priority} {content}'
        elif _type == 'CAA':
            data = data['data']
            flags = data['flags']
            tag = data['tag']
            value = data['value']
            return f'{flags} {tag} {value}'
        elif _type == 'SRV':
            data = data['data']
            port = data['port']
            priority = data['priority']
            target = data['target']
            weight = data['weight']
            return f'{port} {priority} {target} {weight}'
        elif _type == 'LOC':
            data = data['data']
            lat_degrees = data['lat_degrees']
            lat_minutes = data['lat_minutes']
            lat_seconds = data['lat_seconds']
            lat_direction = data['lat_direction']
            long_degrees = data['long_degrees']
            long_minutes = data['long_minutes']
            long_seconds = data['long_seconds']
            long_direction = data['long_direction']
            altitude = data['altitude']
            size = data['size']
            precision_horz = data['precision_horz']
            precision_vert = data['precision_vert']
            return (
                f'{lat_degrees} {lat_minutes} {lat_seconds} '
                f'{lat_direction} {long_degrees} {long_minutes} '
                f'{long_seconds} {long_direction} {altitude} {size} '
                f'{precision_horz} {precision_vert}'
            )
        elif _type == 'NAPTR':
            data = data['data']
            flags = data['flags']
            order = data['order']
            preference = data['preference']
            regex = data['regex']
            replacement = data['replacement']
            service = data['service']
            return f'{order} {preference} "{flags}" "{service}" "{regex}" {replacement}'
        elif _type == 'SSHFP':
            data = data['data']
            algorithm = data['algorithm']
            fingerprint_type = data['type']
            fingerprint = data['fingerprint']
            return f'{algorithm} {fingerprint_type} {fingerprint}'
        elif _type == 'TLSA':
            data = data['data']
            usage = data['usage']
            selector = data['selector']
            matching_type = data['matching_type']
            certificate = data['certificate']
            return f'{usage} {selector} {matching_type} {certificate}'
        elif _type == 'URLFWD':
            uri = data['targets'][0]['constraint']['value']
            uri = '//' + uri if not uri.startswith('http') else uri
            parsed_uri = urlsplit(uri)
            url = data['actions'][0]['value']['url']
            status_code = data['actions'][0]['value']['status_code']
            return (
                f'{parsed_uri.netloc} {parsed_uri.path} {url} '
                + f'{status_code}'
            )

        return data['content']

    def _apply_Create(self, change):
        data = dict()
        comments = "Generated by OctoDNS"
        new = change.new
        zone_id = self.zones[new.zone.name]
        path = 'addEntity'
        params = {'parentId': zone_id}
        for content in self._gen_data(new):
            fqdn = content['name']
            ttl = content['ttl']
            val = content['content']
            _type = content['type']
            if _type == 'CNAME':
                _type = 'Alias'
            data['name'] = fqdn.split(".")[0]
            data['type'] = f'{_type}Record'
            if _type in ['A', 'PTR', 'SPF']:
                data['type'] = 'GenericRecord'
                data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|type={_type}|rdata={val}|'
            elif _type == 'TXT':
                data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|txt={val}|'
            elif _type == 'Alias':
                data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|linkedRecordName={val}|'
            elif _type == 'MX':
                data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|linkedRecordName={val}|priority={content["priority"]}|'
            elif _type == 'SRV':
                prt = content['port']
                wght = content['weight']
                pri = content['priority']
                data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|linkedRecordName={val}|port={prt}|priority={pri}|weight={wgt}|'
            elif _type == 'NAPTR':
                order = content['order']
                pref = content['preference']
                srv = content['service']
                regex = content['regex']
                rep = content['replacement']
                flags = content['flags']
                data['properties'] = f'comments={comments}|ttl={ttl}|absoluteName={fqdn}|order={order}|preference={pref}|service={srv}|regex={regex}|replacement={rep}|flags={flags}|'
            self._try_request('POST', path, params=params, data=data)

    def _apply_Update(self, change):
        zone = change.new.zone
        zone_id = self.zones[zone.name]
        fqdn = change.new.fqdn[:-1]
        hostname = zone.hostname_from_fqdn(fqdn)
        _type = change.new._type
        if _type == 'CNAME':
            _type = 'Alias'
        if _type in ['A', 'PTR', 'SPF']:
            rr_type = 'GenericRecord'
        else:
            rr_type = f'{_type}Record'
        params = {
            'parentId': zone_id,
            'type': rr_type,
            'start': 0,
            'count': 100
        }
        ents = self._try_request('GET', 'getEntities', params=params)
        existing = {}
        # Find all of the existing CF records for this name & type
        for record in self.zone_records(zone):
            if 'targets' in record:
                uri = record['targets'][0]['constraint']['value']
                uri = '//' + uri if not uri.startswith('http') else uri
                parsed_uri = urlsplit(uri)
                name = zone.hostname_from_fqdn(parsed_uri.netloc)
                path = parsed_uri.path
                # assumption, actions will always contain 1 action
                _values = record['actions'][0]['value']
                _values['path'] = path
                _values['ttl'] = 300
                _values['type'] = 'URLFWD'
                record.update(_values)
            else:
                name = zone.hostname_from_fqdn(record['name'])
            # Use the _record_for so that we include all of standard
            # conversion logic
            r = self._record_for(zone, name, record['type'], [record], True)
            if hostname == r.name and _type == r._type:
                # Round trip the single value through a record to contents
                # flow to get a consistent _gen_data result that matches
                # what went in to new_contents
                data = next(self._gen_data(r))

                # Record the record_id and data for this existing record
                key = self._gen_key(data)
                existing[key] = {'record_id': record['id'], 'data': data}

        # Build up a list of new CF records for this Update
        new = {self._gen_key(d): d for d in self._gen_data(change.new)}

        # OK we now have a picture of the old & new CF records, our next step
        # is to figure out which records need to be deleted
        deletes = {}
        for key, info in existing.items():
            if key not in new:
                deletes[key] = info
        # Now we need to figure out which records will need to be created
        creates = {}
        # And which will be updated
        updates = {}
        for key, data in new.items():
            if key in existing:
                # To update we need to combine the new data and existing's
                # record_id. old_data is just for debugging/logging purposes
                old_info = existing[key]
                updates[key] = {
                    'record_id': old_info['record_id'],
                    'data': data,
                    'old_data': old_info['data'],
                }
            else:
                creates[key] = data

        # To do this as safely as possible we'll add new things first, update
        # existing things, and then remove old things. This should (try) and
        # ensure that we have as many value CF records in their system as
        # possible at any given time. Ideally we'd have a "batch" API that
        # would allow create, delete, and upsert style stuff so operations
        # could be done atomically, but that's not available so we made the
        # best of it...

        # However, there are record types like CNAME that can only have a
        # single value. B/c of that our create and then delete approach isn't
        # actually viable. To address this we'll convert as many creates &
        # deletes as we can to updates. This will have a minor upside of
        # resulting in fewer ops and in the case of things like CNAME where
        # there's a single create and delete result in a single update instead.
        create_keys = sorted(creates.keys())
        delete_keys = sorted(deletes.keys())
        for i in range(0, min(len(create_keys), len(delete_keys))):
            create_key = create_keys[i]
            create_data = creates.pop(create_key)
            delete_info = deletes.pop(delete_keys[i])
            updates[create_key] = {
                'record_id': delete_info['record_id'],
                'data': create_data,
                'old_data': delete_info['data'],
            }

        # The sorts ensure a consistent order of operations, they're not
        # otherwise required, just makes things deterministic

        # Creates
        path = f'zones/{zone_id}/dns_records'
        for _, data in sorted(creates.items()):
            self.log.debug('_apply_Update: creating %s', data)
            self._try_request('POST', path, data=data)

        # Updates
        for _, info in sorted(updates.items()):
            record_id = info['record_id']
            data = info['data']
            old_data = info['old_data']
            path = f'zones/{zone_id}/dns_records/{record_id}'
            self.log.debug(
                '_apply_Update: updating %s, %s -> %s',
                record_id,
                data,
                old_data,
            )
            self._try_request('PUT', path, data=data)

        # Deletes
        for _, info in sorted(deletes.items()):
            record_id = info['record_id']
            old_data = info['data']
            path = f'zones/{zone_id}/dns_records/{record_id}'
            self.log.debug(
                '_apply_Update: removing %s, %s', record_id, old_data
            )
            self._try_request('DELETE', path)

    def _apply_Delete(self, change):
        existing = change.existing
        existing_name = existing.fqdn[:-1]
        existing_type = existing._type
        for record in self.zone_records(existing.zone):
            rtype = record['type'][:-6]
            rec_id = record['id']
            props = record['properities']
            zone_id = props['parentId']
            if rtype == 'Generic':
                rtype = props['type']
            elif rtype == 'Alias':
                rtype = 'CNAME'
            if (
                existing_name == props['absoluteName']
                and existing_type == rtype
            ):
                params = {'objectId': rec_id }
                self._try_request('DELETE', '/delete', params=params)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        name = desired.name
        if name not in self.zones:
            self.log.debug('_apply:   no matching zone, creating')
            data = {
                'parentId': self.view_id,
                'absoluteName': name[:-1], 
                'properties': 'deployable=false',
            }
            resp = self._try_request('POST', 'addZone', data=data)
            zone_id = resp['id']
            self.zones[name] = zone_id
            self._zone_records[name] = {}

        # Force the operation order to be Delete() -> Create() -> Update()
        # This will help avoid problems in updating a CNAME record into an
        # A record and vice-versa
        changes.sort(key=self._change_keyer)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # clear the cache
        self._zone_records.pop(name, None)

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
