"""DNS Authenticator for enum."""
import logging
from typing import Any
from typing import Callable
from typing import cast
from typing import Optional

import requests

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

API_URL = 'https://api.enum.co/enum.api.v1.DnsService'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for enum

    This Authenticator uses the enum API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using enum for DNS).'
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='enum credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the enum API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'enum credentials INI file',
            {
                'api_key': 'API key of an enum service account',
                'project_id': 'ID of the enum project containing the DNS zone',
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_enum_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_enum_client().del_txt_record(domain, validation_name, validation)

    def _get_enum_client(self) -> "_EnumClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _EnumClient(cast(str, self.credentials.conf('api_key')),
                           cast(str, self.credentials.conf('project_id')))


class _EnumClient:
    """
    Encapsulates all communication with the enum API.
    """

    def __init__(self, api_key: str, project_id: str) -> None:
        self.project_id = project_id
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Bearer {api_key}'})

    def add_txt_record(self, domain: str, record_name: str, record_content: str,
                       record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the enum zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the enum API
        """

        zone_id = self._find_zone_id(domain)

        response = self._call('AddRecordSetValue', {
            'zoneId': zone_id,
            'name': record_name.lower(),
            'type': 'TXT',
            'ttl': record_ttl,
            'value': {'content': f'"{record_content}"'},
        })

        if response.status_code != 200:
            raise errors.PluginError(f'Error adding TXT record using the enum API: '
                                     f'{_error_message(response)}')

        logger.debug('Successfully added TXT record %s', record_name)

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        Only the value matching the record's content is removed, so records created concurrently
        (e.g., for a wildcard and its base domain) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the enum zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            zone_id = self._find_zone_id(domain)

            response = self._call('RemoveRecordSetValue', {
                'zoneId': zone_id,
                'name': record_name.lower(),
                'type': 'TXT',
                'content': f'"{record_content}"',
            })
        except errors.PluginError as e:
            logger.warning('Error deleting TXT record using the enum API: %s', e)
            return

        if response.status_code != 200:
            logger.warning('Error deleting TXT record using the enum API: %s',
                           _error_message(response))
            return

        logger.debug('Successfully deleted TXT record %s', record_name)

    def _find_zone_id(self, domain: str) -> str:
        """
        Find the zone_id for a given domain.

        :param str domain: The domain for which to find the zone_id.
        :returns: The zone_id, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no zone_id is found.
        """

        for zone_name_guess in dns_common.base_domain_name_guesses(domain.lower()):
            response = self._call('GetZoneByName', {'name': zone_name_guess})

            if response.status_code == 200:
                zone_id: str = response.json()['zone']['id']
                logger.debug('Found zone_id of %s for %s using name %s',
                             zone_id, domain, zone_name_guess)
                return zone_id

            if response.status_code in (401, 403):
                raise errors.PluginError(f'Error finding zone using the enum API: '
                                         f'{_error_message(response)} '
                                         f'(Did you provide a valid API key and project ID?)')

        raise errors.PluginError(f'Unable to find an enum zone for {domain}.')

    def _call(self, method: str, data: dict[str, Any]) -> requests.Response:
        try:
            return self.session.post(f'{API_URL}/{method}',
                                     json={'projectId': self.project_id, **data},
                                     timeout=30)
        except requests.RequestException as e:
            raise errors.PluginError(f'Error communicating with the enum API: {e}')


def _error_message(response: requests.Response) -> str:
    try:
        return f"{response.json()['message']} ({response.status_code})"
    except (ValueError, KeyError):
        return f'HTTP {response.status_code}'
