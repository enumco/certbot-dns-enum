"""Tests for certbot_dns_enum._internal.dns_enum."""

import sys
import unittest
from unittest import mock

import pytest
import requests

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_KEY = 'an-api-key'
PROJECT_ID = 'proj-01kmyy3t719crcnrrvk1mgyjd0'
ZONE_ID = 'dnszone-01m23faytfe84sxabv306xjee2'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_enum._internal.dns_enum import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"enum_api_key": API_KEY, "enum_project_id": PROJECT_ID}, path)

        self.config = mock.MagicMock(enum_credentials=path,
                                     enum_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "enum")

        self.mock_client = mock.MagicMock()
        # _get_enum_client | pylint: disable=protected-access
        setattr(self.auth, '_get_enum_client', mock.MagicMock(return_value=self.mock_client))

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, 60)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls


def _response(status_code, body):
    response = mock.MagicMock(status_code=status_code)
    if body is None:
        response.json.side_effect = ValueError
    else:
        response.json.return_value = body
    return response


class EnumClientTest(unittest.TestCase):

    record_name = "_acme-challenge." + DOMAIN
    record_content = "bar"
    record_ttl = 60

    def setUp(self):
        from certbot_dns_enum._internal.dns_enum import _EnumClient

        self.client = _EnumClient(API_KEY, PROJECT_ID)

        self.post = mock.MagicMock()
        self.client.session.post = self.post

    def _calls(self):
        return [(call.args[0].rsplit('/', 1)[1], call.kwargs['json']) for call in self.post.call_args_list]

    def test_authorization_header(self):
        assert self.client.session.headers['Authorization'] == 'Bearer ' + API_KEY

    def test_add_txt_record(self):
        self.post.side_effect = [
            _response(200, {'zone': {'id': ZONE_ID}}),
            _response(200, {'recordSet': {}}),
        ]

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        assert self._calls() == [
            ('GetZoneByName', {'projectId': PROJECT_ID, 'name': DOMAIN}),
            ('AddRecordSetValue', {
                'projectId': PROJECT_ID,
                'zoneId': ZONE_ID,
                'name': self.record_name,
                'type': 'TXT',
                'ttl': self.record_ttl,
                'value': {'content': '"bar"'},
            }),
        ]

    def test_add_txt_record_subdomain_zone_guesses(self):
        self.post.side_effect = [
            _response(404, {'code': 'not_found', 'message': 'resource not found'}),
            _response(200, {'zone': {'id': ZONE_ID}}),
            _response(200, {'recordSet': {}}),
        ]

        self.client.add_txt_record('www.' + DOMAIN, self.record_name, self.record_content,
                                   self.record_ttl)

        assert [call[1]['name'] for call in self._calls()[:2]] == ['www.' + DOMAIN, DOMAIN]

    def test_add_txt_record_zone_not_found(self):
        self.post.return_value = _response(404, {'code': 'not_found',
                                                 'message': 'resource not found'})

        with pytest.raises(errors.PluginError):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                       self.record_ttl)

    def test_add_txt_record_unauthenticated(self):
        self.post.return_value = _response(401, {'code': 'unauthenticated',
                                                 'message': 'authentication failed'})

        with pytest.raises(errors.PluginError, match='authentication failed'):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                       self.record_ttl)

        assert self.post.call_count == 1

    def test_add_txt_record_error(self):
        self.post.side_effect = [
            _response(200, {'zone': {'id': ZONE_ID}}),
            _response(400, {'code': 'invalid_argument', 'message': 'invalid record'}),
        ]

        with pytest.raises(errors.PluginError, match='invalid record'):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                       self.record_ttl)

    def test_add_txt_record_connection_error(self):
        self.post.side_effect = requests.ConnectionError('connection refused')

        with pytest.raises(errors.PluginError, match='connection refused'):
            self.client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                       self.record_ttl)

    def test_del_txt_record(self):
        self.post.side_effect = [
            _response(200, {'zone': {'id': ZONE_ID}}),
            _response(200, {}),
        ]

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        assert self._calls() == [
            ('GetZoneByName', {'projectId': PROJECT_ID, 'name': DOMAIN}),
            ('RemoveRecordSetValue', {
                'projectId': PROJECT_ID,
                'zoneId': ZONE_ID,
                'name': self.record_name,
                'type': 'TXT',
                'content': '"bar"',
            }),
        ]

    def test_del_txt_record_zone_not_found(self):
        self.post.return_value = _response(404, {'code': 'not_found',
                                                 'message': 'resource not found'})

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error(self):
        self.post.side_effect = [
            _response(200, {'zone': {'id': ZONE_ID}}),
            _response(500, None),
        ]

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
