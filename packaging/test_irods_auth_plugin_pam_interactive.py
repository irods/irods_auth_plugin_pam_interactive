import copy
import json
import os
import shutil
import tempfile
import time
import unittest

from . import session
from .. import core_file
from .. import lib
from .. import paths
from .. import test
from ..configuration import IrodsConfig
from ..controller import IrodsController


def reload_configuration():
	if IrodsConfig().version_tuple < (4, 90, 0):
		IrodsController().restart()
	else:
		IrodsController().reload_configuration()


@unittest.skipIf(test.settings.USE_SSL, 'TLS is set up in these tests, so just skip if TLS is enabled already.')
@unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, 'TLS configuration cannot be applied to all servers from the tests.')
class test_configurations(unittest.TestCase):
	plugin_name = IrodsConfig().default_rule_engine_plugin

	@staticmethod
	def generate_default_tls_files(tls_directory=None, numbits_for_genrsa=2048):
		tls_directory = tls_directory or os.path.join(IrodsConfig().irods_directory, 'test')

		server_key_path = os.path.join(tls_directory, 'server.key')
		chain_pem_path = os.path.join(tls_directory, 'chain.pem')
		dhparams_pem_path = os.path.join(tls_directory, 'dhparams.pem')

		lib.execute_command(['openssl', 'genrsa', '-out', server_key_path, str(numbits_for_genrsa)])
		lib.execute_command(
			['openssl', 'req', '-batch', '-new', '-x509', '-key', server_key_path, '-out', chain_pem_path, '-days', '365'])
		lib.execute_command(['openssl', 'dhparam', '-2', '-out', dhparams_pem_path, str(numbits_for_genrsa)])

		return (server_key_path, chain_pem_path, dhparams_pem_path)

	@staticmethod
	def make_dict_for_server_config_tls_configuration(server_key_path, chain_pem_path, dhparams_pem_path):
		return {
			"tls_server": {
				"certificate_chain_file": chain_pem_path,
				"certificate_key_file": server_key_path,
				"dh_params_file": dhparams_pem_path
			}
		}

	@staticmethod
	def make_dict_for_tls_client_environment(ca_certificate_path, server_key_path, chain_pem_path, dhparams_pem_path):
		environment_dict = {
			'irods_client_server_negotiation': 'request_server_negotiation',
			'irods_client_server_policy': 'CS_NEG_REQUIRE',
			'irods_ssl_ca_certificate_file': ca_certificate_path,
			'irods_ssl_verify_server': 'none',
		}

		if IrodsConfig().version_tuple < (4, 90, 0):
			environment_dict.update({
				'irods_ssl_certificate_chain_file': chain_pem_path,
				'irods_ssl_certificate_key_file': server_key_path,
				'irods_ssl_dh_params_file': dhparams_pem_path,
			})

		return environment_dict

	@staticmethod
	def get_pep_for_tls(plugin_name):
		import textwrap

		return {
			'irods_rule_engine_plugin-irods_rule_language': textwrap.dedent('''
				acPreConnect(*OUT) {
					*OUT = 'CS_NEG_REQUIRE';
				}
			'''),
			'irods_rule_engine_plugin-python': textwrap.dedent('''
				def acPreConnect(rule_args, callback, rei):
					rule_args[0] = 'CS_NEG_REQUIRE'
			''')
		}[plugin_name]

	@classmethod
	def setUpClass(self):
		self.admin = session.mkuser_and_return_session('rodsadmin', 'otherrods', 'rods', lib.get_hostname())

		cfg = lib.open_and_load_json(
			os.path.join(IrodsConfig().irods_directory, 'test', 'test_framework_configuration.json'))
		self.auth_user = cfg['irods_pam_interactive_name']
		self.auth_pass = cfg['irods_pam_interactive_password']

		try:
			import pwd
			pwd.getpwnam(self.auth_user)

		except KeyError:
			# This is a requirement in order to run these tests and running the tests is required for our test suite, so
			# we always fail here when the prerequisites are not being met on the test-running host.
			raise EnvironmentError(
				'OS user "{}" with password "{}" must exist in order to run these tests.'.format(
				self.auth_user, self.auth_pass))

		self.auth_session = session.mkuser_and_return_session('rodsuser', self.auth_user, self.auth_pass, lib.get_hostname())
		self.other_auth_session = session.make_session_for_existing_user(
			self.auth_user, self.auth_pass, lib.get_hostname(), self.auth_session.zone_name)
		self.service_account_environment_file_path = paths.default_client_environment_path()

		self.server_key_path, self.chain_pem_path, self.dhparams_pem_path = test_configurations.generate_default_tls_files()
		self.authentication_scheme = 'pam_interactive'
		self.configuration_namespace = 'authentication'

		# Make a backup of the server_config and configure TLS.
		self.server_config_backup = tempfile.NamedTemporaryFile(prefix=os.path.basename(paths.server_config_path())).name
		shutil.copyfile(paths.server_config_path(), self.server_config_backup)
		server_config_update = test_configurations.make_dict_for_server_config_tls_configuration(
			self.server_key_path, self.chain_pem_path, self.dhparams_pem_path)
		lib.update_json_file_from_dict(paths.server_config_path(), server_config_update)
		
		# Make a backup of the core.re file and configure it for TLS.
		self.core_re = core_file.CoreFile(self.plugin_name)
		self.core_re_path = os.path.join(paths.core_re_directory(), 'core.re')
		self.core_re_file_backup = tempfile.NamedTemporaryFile(prefix=os.path.basename(self.core_re_path)).name
		shutil.copyfile(self.core_re_path, self.core_re_file_backup)
		self.core_re.add_rule(test_configurations.get_pep_for_tls(self.plugin_name))
		
		reload_configuration()
		
		# Make a backup of the service account client environment and configure all the sessions for TLS.
		self.service_account_environment_file_backup = tempfile.NamedTemporaryFile(
			prefix=os.path.basename(self.service_account_environment_file_path)).name
		shutil.copyfile(self.service_account_environment_file_path, self.service_account_environment_file_backup)
		client_update = test_configurations.make_dict_for_tls_client_environment(
			self.chain_pem_path, self.server_key_path, self.chain_pem_path, self.dhparams_pem_path)
		lib.update_json_file_from_dict(self.service_account_environment_file_path, client_update)
		self.admin.environment_file_contents.update(client_update)
		self.auth_session.environment_file_contents.update(client_update)
		self.other_auth_session.environment_file_contents.update(client_update)

	@classmethod
	def tearDownClass(self):
		self.auth_session.__exit__()
		self.other_auth_session.__exit__()
		self.admin.__exit__()

		# Put all the modified configurations back and reload the server configuration.
		shutil.copyfile(self.service_account_environment_file_backup, self.service_account_environment_file_path)
		shutil.copyfile(self.server_config_backup, paths.server_config_path())
		shutil.copyfile(self.core_re_file_backup, self.core_re_path)
		reload_configuration()

		for filename in [self.chain_pem_path, self.server_key_path, self.dhparams_pem_path]:
			if os.path.exists(filename):
				os.unlink(filename)

		with session.make_session_for_existing_admin() as admin_session:
			admin_session.assert_icommand(['iadmin', 'rmuser', self.auth_session.username])
			admin_session.assert_icommand(['iadmin', 'rmuser', self.admin.username])

	def do_test_invalid_password_time_configurations(self, _option_name):
		# Stash away the original configuration for later...
		original_config = self.admin.assert_icommand(
				['iadmin', 'get_grid_configuration', self.configuration_namespace, _option_name], 'STDOUT')[1].strip()

		auth_session_env_backup = copy.deepcopy(self.auth_session.environment_file_contents)
		try:
			client_update = {'irods_authentication_scheme': self.authentication_scheme}
			self.auth_session.environment_file_contents.update(client_update)

			for option_value in [' ', 'nope', str(-1), str(18446744073709552000), str(-18446744073709552000)]:
				with self.subTest(f'test with value [{option_value}]'):
					self.admin.assert_icommand(
						['iadmin', 'set_grid_configuration', '--', self.configuration_namespace, _option_name, option_value])

					# These invalid configurations will not cause any errors, but default values will be used.
					self.auth_session.assert_icommand(
						['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')
					self.auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

		finally:
			self.auth_session.environment_file_contents = auth_session_env_backup

			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, _option_name, original_config])

			reload_configuration()

	def test_invalid_password_max_time(self):
		self.do_test_invalid_password_time_configurations('password_max_time')

	def test_invalid_password_min_time(self):
		self.do_test_invalid_password_time_configurations('password_min_time')

	def test_password_max_time_less_than_password_min_time_makes_ttl_constraints_unsatisfiable(self):
		min_time_option_name = 'password_min_time'
		max_time_option_name = 'password_max_time'

		# Stash away the original configuration for later...
		original_min_time = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, min_time_option_name], 'STDOUT')[1].strip()

		original_max_time = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, max_time_option_name], 'STDOUT')[1].strip()

		auth_session_env_backup = copy.deepcopy(self.auth_session.environment_file_contents)
		try:
			client_update = {'irods_authentication_scheme': self.authentication_scheme}
			self.auth_session.environment_file_contents.update(client_update)

			# Try a few different values here that are in the range of overall acceptable values:
			#	 - 2 hours allows us to go up OR down by 1 hour (boundary case).
			#	 - 336 hours is 1209600 seconds (or 2 weeks) which is the default maximum allowed TTL value.
			for base_ttl_in_hours in [2, 336]:
				with self.subTest(f'test with TTL of [{base_ttl_in_hours}] hours'):
					base_ttl_in_seconds = base_ttl_in_hours * 3600

					option_value = str(base_ttl_in_seconds + 10)
					self.admin.assert_icommand(
						['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, option_value])

					# Set password_max_time to a value less than the password_min_time.
					option_value = str(base_ttl_in_seconds - 10)
					self.admin.assert_icommand(
						['iadmin', 'set_grid_configuration', self.configuration_namespace, max_time_option_name, option_value])

					# Note: The min/max check does not occur when no TTL parameter is passed. If no TTL is
					# passed, the minimum password lifetime is used for the TTL. Therefore, to test TTL lifetime
					# boundaries, we must pass TTL explicitly for each test.

					# This is lower than the minimum and higher than the maximum. The TTL is invalid.
					self.auth_session.assert_icommand(
						['iinit', '--ttl', str(base_ttl_in_hours)],
						 'STDERR', 'PAM_AUTH_PASSWORD_INVALID_TTL', input=f'{self.auth_session.password}\n')

					# This is lower than the maximum but also lower than the minimum. The TTL is invalid.
					self.auth_session.assert_icommand(
						['iinit', '--ttl', str(base_ttl_in_hours - 1)],
						 'STDERR', 'PAM_AUTH_PASSWORD_INVALID_TTL', input=f'{self.auth_session.password}\n')

					# This is higher than the minimum but also higher than the maximum. The TTL is invalid.
					self.auth_session.assert_icommand(
						['iinit', '--ttl', str(base_ttl_in_hours + 1)],
						 'STDERR', 'PAM_AUTH_PASSWORD_INVALID_TTL', input=f'{self.auth_session.password}\n')

			# Restore grid configuration and try again, with success.
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, max_time_option_name, original_max_time])
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, original_min_time])

			self.auth_session.assert_icommand(
				['iinit', '--ttl', str(1)], 'STDOUT', input=f'{self.auth_session.password}\n')
			self.auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

		finally:
			self.auth_session.environment_file_contents = auth_session_env_backup

			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, max_time_option_name, original_max_time])
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, original_min_time])

			reload_configuration()

	def test_password_expires_appropriately_based_on_grid_configuration_value(self):
		min_time_option_name = 'password_min_time'
		max_time_option_name = 'password_max_time'

		# Stash away the original configuration for later...
		original_min_time = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, min_time_option_name], 'STDOUT')[1].strip()

		original_max_time = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, max_time_option_name], 'STDOUT')[1].strip()

		auth_session_env_backup = copy.deepcopy(self.auth_session.environment_file_contents)
		try:
			client_update = {'irods_authentication_scheme': self.authentication_scheme}
			self.auth_session.environment_file_contents.update(client_update)

			# When no TTL is specified, the default value is the minimum password lifetime as configured in
			# R_GRID_CONFIGURATION. This value should be higher than 3 seconds to ensure steps in the test
			# have enough time to complete.
			ttl = 4
			self.assertGreater(ttl, 3)
			option_value = str(ttl)
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, option_value])

			# Authenticate and run a command...
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

			self.auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

			# Sleep until the password is expired...
			time.sleep(ttl + 1)

			# Password should be expired now...
			self.auth_session.assert_icommand(["ils"], 'STDERR', 'CAT_PASSWORD_EXPIRED: failed to perform request')

			# ...and stays expired.
			# TODO(irods/irods#7344): This should emit a better error message.
			self.auth_session.assert_icommand(["ils"], 'STDERR', 'CAT_INVALID_AUTHENTICATION: failed to perform request')

			# Restore grid configuration and try again, with success.
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, max_time_option_name, original_max_time])
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, original_min_time])

			self.auth_session.assert_icommand(['iinit'], 'STDOUT', input=f'{self.auth_session.password}\n')
			self.auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

		finally:
			self.auth_session.environment_file_contents = auth_session_env_backup

			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, max_time_option_name, original_max_time])
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, original_min_time])

			reload_configuration()

			# Re-authenticate as the session user to make sure things can be cleaned up.
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'iRODS password', input=f'{self.auth_session.password}\n')

	def test_password_extend_lifetime_set_to_true_extends_other_authentications_past_expiration(self):
		min_time_option_name = 'password_min_time'
		extend_lifetime_option_name = 'password_extend_lifetime'

		# Stash away the original configuration for later...
		original_min_time = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, min_time_option_name],
			'STDOUT')[1].strip()

		original_extend_lifetime = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, extend_lifetime_option_name],
			'STDOUT')[1].strip()

		# Set password_extend_lifetime to 1 so that the same randomly generated password is used for all sessions.
		self.admin.assert_icommand(
			['iadmin', 'set_grid_configuration', self.configuration_namespace, extend_lifetime_option_name, '1'])

		# Make a new session of the existing auth_user. The data is "managed" in the session, so the session
		# collection shall be shared with the other session. Re-auth first, just in case.
		self.other_auth_session.assert_icommand(
			['iinit'], 'STDOUT', input=f'{self.auth_session.password}\n')
		self.other_auth_session.assert_icommand(['icd', self.auth_session.session_collection])

		auth_session_env_backup = copy.deepcopy(self.auth_session.environment_file_contents)
		other_auth_session_env_backup = copy.deepcopy(self.other_auth_session.environment_file_contents)
		try:
			client_update = {'irods_authentication_scheme': self.authentication_scheme}
			self.auth_session.environment_file_contents.update(client_update)
			self.other_auth_session.environment_file_contents.update(client_update)

			# Set the minimum time to a very short value so that the password expires in a reasonable amount of
			# time for testing purposes. This value should be higher than 3 seconds to ensure steps in the test
			# have enough time to complete.
			ttl = 4
			self.assertGreater(ttl, 3)
			option_value = str(ttl)
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, option_value])

			# Authenticate with both sessions and run a command...
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')
			self.other_auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

			self.auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)
			self.other_auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

			# Sleep until just before password is expired...
			time.sleep(ttl - 1)

			# Re-authenticate as one of the sessions such that the random password lifetime is extended. This
			# will allow the other session to continue without re-authenticating.
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

			# We want to sleep 1 second past the timeout (ttl + 1) to ensure that the original expiration time
			# has passed. We already slept ttl - 1 seconds, so the remaining time is calculated like this:
			# remaining_sleep_time = total_time_to_sleep - time_already_slept = (ttl + 1) - (ttl - 1) = 2
			time.sleep(2)

			# Run a command as the other session to show that the existing password is still valid.
			self.other_auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

			# The re-authenticated session should also be able to run commands, of course.
			self.auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

			# Sleep again to let the password time out.
			time.sleep(ttl + 1)

			# Password should be expired now...
			self.other_auth_session.assert_icommand(
				["ils"], 'STDERR', 'CAT_PASSWORD_EXPIRED: failed to perform request')
			# The sessions are using the same password, so the second response will be different
			# TODO(irods/irods#7344): This should emit a better error message.
			self.auth_session.assert_icommand(
				["ils"], 'STDERR', 'CAT_INVALID_AUTHENTICATION: failed to perform request')

		finally:
			self.other_auth_session.environment_file_contents = other_auth_session_env_backup
			self.auth_session.environment_file_contents = auth_session_env_backup

			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, extend_lifetime_option_name, original_extend_lifetime])
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, original_min_time])

			reload_configuration()

			# Re-authenticate as the session user to make sure things can be cleaned up.
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'iRODS password', input=f'{self.auth_session.password}\n')
			self.other_auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'iRODS password', input=f'{self.other_auth_session.password}\n')

	def test_password_extend_lifetime_set_to_false_invalidates_other_authentications_on_expiration(self):
		min_time_option_name = 'password_min_time'
		extend_lifetime_option_name = 'password_extend_lifetime'

		# Stash away the original configuration for later...
		original_min_time = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, min_time_option_name],
			'STDOUT')[1].strip()

		original_extend_lifetime = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, extend_lifetime_option_name],
			'STDOUT')[1].strip()

		# Set password_extend_lifetime to 1 so that the same randomly generated password is used for all sessions.
		self.admin.assert_icommand(
			['iadmin', 'set_grid_configuration', self.configuration_namespace, extend_lifetime_option_name, '1'])

		# Make a new session of the existing auth_user. The data is "managed" in the session, so the session
		# collection shall be shared with the other session. Re-auth first, just in case.
		self.other_auth_session.assert_icommand(
			['iinit'], 'STDOUT', input=f'{self.other_auth_session.password}\n')
		self.other_auth_session.assert_icommand(['icd', self.auth_session.session_collection])

		auth_session_env_backup = copy.deepcopy(self.auth_session.environment_file_contents)
		other_auth_session_env_backup = copy.deepcopy(self.other_auth_session.environment_file_contents)
		try:
			client_update = {'irods_authentication_scheme': self.authentication_scheme}
			self.auth_session.environment_file_contents.update(client_update)
			self.other_auth_session.environment_file_contents.update(client_update)

			# Set the minimum time to a very short value so that the password expires in a reasonable amount of
			# time for testing purposes. This value should be higher than 3 seconds to ensure steps in the test
			# have enough time to complete.
			ttl = 4
			self.assertGreater(ttl, 3)
			option_value = str(ttl)
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, option_value])

			# Authenticate with both sessions and run a command...
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')
			self.other_auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'Password:', input=f'{self.other_auth_session.password}\n')

			self.auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)
			self.other_auth_session.assert_icommand(["ils"], 'STDOUT', self.auth_session.session_collection)

			# Disable password_extend_lifetime so that on the next authentication, the expiration time of the
			# existing password will not be extended.
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, extend_lifetime_option_name, '0'])

			# Sleep until just before password is expired...
			seconds_before_password_expires = 2
			sleep_time_before_password_expiration = ttl - seconds_before_password_expires
			time.sleep(sleep_time_before_password_expiration)

			# Re-authenticate as one of the sessions - the random password lifetime will not be extended for
			# either session.
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

			# We want to sleep 1 second past the timeout (ttl + 1) to ensure that the original expiration time
			# has passed. We already slept for some time before the password expired, so the remaining time is
			# calculated like this: remaining_sleep_time = total_time_to_sleep - time_already_slept
			time_past_password_expiration = ttl + 1
			time.sleep(time_past_password_expiration - sleep_time_before_password_expiration)

			# Password should be expired for both sessions despite one having re-authenticated past the
			# expiry time.
			out, err, rc = self.other_auth_session.run_icommand('ils')
			self.assertEqual('', out)
			# TODO(irods/irods#7344): This should always return CAT_PASSWORD_EXPIRED, but sometimes it returns
			# CAT_INVALID_AUTHENTICATION. This should be made more consistent.
			self.assertTrue(
				'CAT_PASSWORD_EXPIRED: failed to perform request' in err or
				'CAT_INVALID_AUTHENTICATION: failed to perform request' in err)
			self.assertNotEqual(0, rc)
			# The sessions are using the same password, so the second response will be different
			# TODO(irods/irods#7344): This should emit a better error message.
			self.auth_session.assert_icommand(
				["ils"], 'STDERR', 'CAT_INVALID_AUTHENTICATION: failed to perform request')

		finally:
			self.other_auth_session.environment_file_contents = other_auth_session_env_backup
			self.auth_session.environment_file_contents = auth_session_env_backup

			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, extend_lifetime_option_name, original_extend_lifetime])
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, min_time_option_name, original_min_time])

			reload_configuration()

			# Re-authenticate as the session user to make sure things can be cleaned up.
			self.auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'iRODS password', input=f'{self.auth_session.password}\n')
			self.other_auth_session.assert_icommand(
				['iinit'], 'STDOUT', 'iRODS password', input=f'{self.other_auth_session.password}\n')

	def test_password_max_time_can_exceed_1209600__issue_3742_5096(self):
		# Note: This does NOT test the TTL as this would require waiting for the password to expire (2 weeks + 1 hour).
		# The test is meant to ensure that a TTL greater than 1209600 is allowed with iinit when it is so configured.

		max_time_option_name = 'password_max_time'

		# Stash away the original configuration for later...
		original_max_time = self.admin.assert_icommand(
			['iadmin', 'get_grid_configuration', self.configuration_namespace, max_time_option_name], 'STDOUT')[1].strip()

		auth_session_env_backup = copy.deepcopy(self.auth_session.environment_file_contents)
		try:
			client_update = {'irods_authentication_scheme': self.authentication_scheme}
			self.auth_session.environment_file_contents.update(client_update)

			# The test value is 2 hours more than the default in order to try a TTL value 1 greater and 1 less
			# than the configured password_max_time while still remaining above 1209600 to show that there is
			# nothing special about that value.
			base_ttl_in_hours = 336 + 2
			base_ttl_in_seconds = base_ttl_in_hours * 3600

			# Set password_max_time to the value for the test.
			option_value = str(base_ttl_in_seconds)
			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, max_time_option_name, option_value])

			# Note: The min/max check does not occur when no TTL parameter is passed. If no TTL is passed, the
			# minimum password lifetime is used for the TTL. Therefore, to test TTL lifetime boundaries, we must
			# pass TTL explicitly for each test.

			# TTL value is higher than the maximum. The TTL is invalid.
			self.auth_session.assert_icommand(
				['iinit', '--ttl', str(base_ttl_in_hours + 1)],
				 'STDERR', 'PAM_AUTH_PASSWORD_INVALID_TTL',
				 input=f'{self.auth_session.password}\n')

			# TTL value is lower than the maximum. The TTL is valid.
			self.auth_session.assert_icommand(
				 ['iinit', '--ttl', str(base_ttl_in_hours - 1)],
				 'STDOUT', 'Password:',
				 input=f'{self.auth_session.password}\n')
 
			# TTL value is equal to the maximum. The TTL is valid.
			self.auth_session.assert_icommand(
				 ['iinit', '--ttl', str(base_ttl_in_hours)],
				 'STDOUT', 'Password:',
				 input=f'{self.auth_session.password}\n')

		finally:
			self.auth_session.environment_file_contents = auth_session_env_backup

			self.admin.assert_icommand(
				['iadmin', 'set_grid_configuration', self.configuration_namespace, max_time_option_name, original_max_time])

			reload_configuration()

	def test_authenticating_with_insecure_mode_in_any_configuration_succeeds_when_tls_is_enabled(self):
		auth_session_env_backup = copy.deepcopy(self.auth_session.environment_file_contents)
		try:
			client_update = {'irods_authentication_scheme': self.authentication_scheme}
			self.auth_session.environment_file_contents.update(client_update)

			server_config_path = paths.server_config_path()
			with lib.file_backed_up(server_config_path):
				# Get the server_config contents so that we can manipulate them.
				with open(server_config_path) as f:
					server_config = json.load(f)

				IrodsController().reload_configuration()

				with self.subTest('insecure_mode = True'):
					# Set the insecure_mode value to true in the server configuration. In this way, we can test
					# the configuration value being true, which would allow non-TLS enabled authentications.
					server_config['plugin_configuration']['authentication']['pam_interactive'] = {
						'insecure_mode': True
					}

					# Write the configuration back out to the file.
					with open(server_config_path, 'w') as f:
						f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

					IrodsController().reload_configuration()

					# Now try to authenticate and observe success because TLS is enabled and it doesn't
					# matter to what value insecure_mode is configured.
					self.auth_session.assert_icommand(
						['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

				with self.subTest('insecure_mode = False'):
					# Set the insecure_mode value to false in the server configuration. In this way, we can test
					# the configuration value being false, which would disallow non-TLS enabled
					# authentications.
					server_config['plugin_configuration']['authentication']['pam_interactive'] = {
						'insecure_mode': False
					}

					# Write the configuration back out to the file.
					with open(server_config_path, 'w') as f:
						f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

					IrodsController().reload_configuration()

					# Now try to authenticate and observe success because TLS is enabled and it doesn't
					# matter to what value insecure_mode is configured.
					self.auth_session.assert_icommand(
						['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

				with self.subTest('insecure_mode is unconfigured'):
					# Delete the insecure_mode configuration if it exists in the server configuration. In this
					# way, we can test the default value used by the plugin for this configuration (which should
					# be false).
					auth_config = server_config['plugin_configuration']['authentication']
					if 'pam_interactive' in auth_config and 'insecure_mode' in auth_config['pam_interactive']:
						del server_config['plugin_configuration']['authentication']['pam_interactive']['insecure_mode']

					# Write the configuration back out to the file.
					with open(server_config_path, 'w') as f:
						f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

					IrodsController().reload_configuration()

					# Now try to authenticate and observe success because TLS is enabled and it doesn't
					# matter whether insecure_mode is configured.
					self.auth_session.assert_icommand(
						['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

		finally:
			self.auth_session.environment_file_contents = auth_session_env_backup

			IrodsController().reload_configuration()


@unittest.skipIf(test.settings.USE_SSL, 'These tests specifically require TLS to be off.')
@unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, 'insecure_mode cannot be configured for all servers from the tests.')
class test_insecure_mode_with_no_tls(unittest.TestCase):
	plugin_name = IrodsConfig().default_rule_engine_plugin

	@classmethod
	def setUpClass(self):
		self.admin = session.mkuser_and_return_session('rodsadmin', 'otherrods', 'rods', lib.get_hostname())

		cfg = lib.open_and_load_json(
			os.path.join(IrodsConfig().irods_directory, 'test', 'test_framework_configuration.json'))
		self.auth_user = cfg['irods_pam_interactive_name']
		self.auth_pass = cfg['irods_pam_interactive_password']

		try:
			import pwd
			pwd.getpwnam(self.auth_user)

		except KeyError:
			# This is a requirement in order to run these tests and running the tests is required for our test suite, so
			# we always fail here when the prerequisites are not being met on the test-running host.
			raise EnvironmentError(
				'OS user "{}" with password "{}" must exist in order to run these tests.'.format(
				self.auth_user, self.auth_pass))

		self.auth_session = session.mkuser_and_return_session('rodsuser', self.auth_user, self.auth_pass, lib.get_hostname())
		self.service_account_environment_file_path = os.path.join(
			os.path.expanduser('~'), '.irods', 'irods_environment.json')

		# Set the authentication scheme for the test session to pam_interactive.
		self.authentication_scheme = 'pam_interactive'
		auth_session_client_environment_contents = self.auth_session.environment_file_contents
		auth_session_client_environment_contents['irods_authentication_scheme'] = self.authentication_scheme
		self.auth_session.environment_file_contents.update(auth_session_client_environment_contents)

	@classmethod
	def tearDownClass(self):
		# Set the authentication scheme for the test session back to native so that we can clean up.
		auth_session_client_environment_contents = self.auth_session.environment_file_contents
		auth_session_client_environment_contents['irods_authentication_scheme'] = 'native'
		self.auth_session.environment_file_contents.update(auth_session_client_environment_contents)

		self.auth_session.__exit__()

		self.admin.assert_icommand(['iadmin', 'rmuser', self.auth_session.username])
		self.admin.__exit__()
		with session.make_session_for_existing_admin() as admin_session:
			admin_session.assert_icommand(['iadmin', 'rmuser', self.admin.username])

	def test_authenticating_with_insecure_mode_unconfigured_fails(self):
		server_config_path = paths.server_config_path()
		with lib.file_backed_up(server_config_path):
			# Get the server_config contents so that we can manipulate them.
			with open(server_config_path) as f:
				server_config = json.load(f)

			# Delete the insecure_mode configuration if it exists in the server configuration. In this way, we can
			# test the default value used by the plugin for this configuration (which should be false).
			auth_config = server_config['plugin_configuration']['authentication']
			if 'pam_interactive' in auth_config and 'insecure_mode' in auth_config['pam_interactive']:
				del server_config['plugin_configuration']['authentication']['pam_interactive']['insecure_mode']

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Now try to authenticate and observe an error because TLS is not enabled and insecure_mode is not
			# enabled.
			self.auth_session.assert_icommand(
				['iinit'], 'STDERR', 'SYS_NOT_ALLOWED', input=f'{self.auth_session.password}\n')

	def test_authenticating_with_insecure_mode_value_of_false_fails(self):
		server_config_path = paths.server_config_path()
		with lib.file_backed_up(server_config_path):
			# Get the server_config contents so that we can manipulate them.
			with open(server_config_path) as f:
				server_config = json.load(f)

			# Set the insecure_mode value to false in the server configuration. In this way, we can test the
			# configuration value being false, which would disallow non-TLS enabled authentications.
			server_config['plugin_configuration']['authentication']['pam_interactive'] = {'insecure_mode': False}

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Now try to authenticate and observe an error because TLS is not enabled and insecure_mode is not
			# enabled.
			self.auth_session.assert_icommand(
				['iinit'], 'STDERR', 'SYS_NOT_ALLOWED', input=f'{self.auth_session.password}\n')

	def test_authenticating_with_insecure_mode_value_of_true_succeeds(self):
		server_config_path = paths.server_config_path()
		with lib.file_backed_up(server_config_path):
			# Get the server_config contents so that we can manipulate them.
			with open(server_config_path) as f:
				server_config = json.load(f)

			# Set the insecure_mode value to true in the server configuration. In this way, we can test the
			# configuration value being true, which would allow non-TLS enabled authentications.
			server_config['plugin_configuration']['authentication']['pam_interactive'] = {'insecure_mode': True}

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Now try to authenticate and observe success because TLS is not enabled, but insecure_mode is enabled.
			self.auth_session.assert_icommand(['iinit'], 'STDOUT', 'Password:', input=f'{self.auth_session.password}\n')

	def test_authenticating_with_insecure_mode_non_boolean_value_fails(self):
		server_config_path = paths.server_config_path()
		with lib.file_backed_up(server_config_path):
			# Get the server_config contents so that we can manipulate them.
			with open(server_config_path) as f:
				server_config = json.load(f)

			# Set the insecure_mode value to some non-boolean value. This will result in an error because the server
			# configuration is malformed.
			server_config['plugin_configuration']['authentication']['pam_interactive'] = {'insecure_mode': 'nope'}

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Now try to authenticate and observe an error because the server is misconfigured.
			self.auth_session.assert_icommand(
				['iinit'], 'STDERR', 'CONFIGURATION_ERROR', input=f'{self.auth_session.password}\n')


@unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, 'insecure_mode cannot be configured for all servers from the tests.')
class test_pam_stack_configuration(unittest.TestCase):
	plugin_name = IrodsConfig().default_rule_engine_plugin

	@classmethod
	def setUpClass(self):
		self.admin = session.mkuser_and_return_session('rodsadmin', 'otherrods', 'rods', lib.get_hostname())

		cfg = lib.open_and_load_json(
			os.path.join(IrodsConfig().irods_directory, 'test', 'test_framework_configuration.json'))
		self.auth_user = cfg['irods_pam_interactive_name']
		self.auth_pass = cfg['irods_pam_interactive_password']

		try:
			import pwd
			pwd.getpwnam(self.auth_user)

		except KeyError:
			# This is a requirement in order to run these tests and running the tests is required for our test suite, so
			# we always fail here when the prerequisites are not being met on the test-running host.
			raise EnvironmentError(
				'OS user "{}" with password "{}" must exist in order to run these tests.'.format(
				self.auth_user, self.auth_pass))

		self.auth_session = session.mkuser_and_return_session('rodsuser', self.auth_user, self.auth_pass, lib.get_hostname())
		self.service_account_environment_file_path = os.path.join(
			os.path.expanduser('~'), '.irods', 'irods_environment.json')

		# Set the authentication scheme for the test session to pam_interactive.
		self.authentication_scheme = 'pam_interactive'
		auth_session_client_environment_contents = self.auth_session.environment_file_contents
		auth_session_client_environment_contents['irods_authentication_scheme'] = self.authentication_scheme
		self.auth_session.environment_file_contents.update(auth_session_client_environment_contents)

	@classmethod
	def tearDownClass(self):
		# Set the authentication scheme for the test session back to native so that we can clean up.
		auth_session_client_environment_contents = self.auth_session.environment_file_contents
		auth_session_client_environment_contents['irods_authentication_scheme'] = 'native'
		self.auth_session.environment_file_contents.update(auth_session_client_environment_contents)

		self.auth_session.__exit__()

		self.admin.assert_icommand(['iadmin', 'rmuser', self.auth_session.username])
		self.admin.__exit__()
		with session.make_session_for_existing_admin() as admin_session:
			admin_session.assert_icommand(['iadmin', 'rmuser', self.admin.username])

	def test_switching_back_and_forth_between_pam_stacks(self):
		server_config_path = paths.server_config_path()
		with lib.file_backed_up(server_config_path):
			# Get the server_config contents so that we can manipulate them.
			with open(server_config_path) as f:
				server_config = json.load(f)

			# Set the insecure_mode value to true in the server configuration for easier testing.
			server_config['plugin_configuration']['authentication']['pam_interactive'] = {'insecure_mode': True}

			# Set the pam_stack_name to always-permit, which will always cause authentication to succeed.
			server_config['plugin_configuration']['authentication']['pam_interactive']['pam_stack_name'] = 'always-permit'

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Try to authenticate and observe success because this stack always allows authentication.
			self.auth_session.assert_icommand(['iinit'], 'STDOUT', ['Connecting as'])

			# Now set the pam_stack_name to always-deny, which will always cause authentication to fail.
			server_config['plugin_configuration']['authentication']['pam_interactive']['pam_stack_name'] = 'always-deny'

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Now try to authenticate and observe failure...
			self.auth_session.assert_icommand(
				["iinit"], 'STDERR', 'CAT_INVALID_AUTHENTICATION: authentication flow completed without success')

			# Set the pam_stack_name back to always-permit...
			server_config['plugin_configuration']['authentication']['pam_interactive']['pam_stack_name'] = 'always-permit'

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Try to authenticate and observe success.
			self.auth_session.assert_icommand(['iinit'], 'STDOUT', ['Connecting as'])

	def test_authenticating_with_pam_stack_name_as_non_string_fails(self):
		server_config_path = paths.server_config_path()
		with lib.file_backed_up(server_config_path):
			# Get the server_config contents so that we can manipulate them.
			with open(server_config_path) as f:
				server_config = json.load(f)

			# Set the insecure_mode value to true in the server configuration for easier testing.
			server_config['plugin_configuration']['authentication']['pam_interactive'] = {'insecure_mode': True}

			# Set the pam_stack_name to some non-string value, which will result in a configuration error.
			server_config['plugin_configuration']['authentication']['pam_interactive']['pam_stack_name'] = False

			# Write the configuration back out to the file.
			with open(server_config_path, 'w') as f:
				f.write(json.dumps(server_config, sort_keys=True, indent=4, separators=(',', ': ')))

			IrodsController().reload_configuration()

			# Now try to authenticate and observe failure because the configuration is malformed.
			self.auth_session.assert_icommand(
				['iinit'], 'STDERR', 'CONFIGURATION_ERROR', input=f'{self.auth_session.password}\n')
