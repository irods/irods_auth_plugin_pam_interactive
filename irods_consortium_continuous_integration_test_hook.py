from __future__ import print_function

import glob
import json
import optparse
import os
import shutil
import textwrap

import irods_python_ci_utilities

def create_pam_stack(name, contents):
	path_to_pam_stack = os.path.join('/etc', 'pam.d', name)
	if os.path.exists(path_to_pam_stack):
		os.rename(path_to_pam_stack, path_to_pam_stack + '.orig')

	with open(path_to_pam_stack, 'w') as f:
		f.write(contents)

def create_pam_stack_for_pam_password_tests():
	pam_stack_contents = textwrap.dedent('''
		auth        required      pam_env.so
		auth        sufficient    pam_unix.so
		auth        requisite     pam_succeed_if.so uid >= 500 quiet
		auth        required      pam_deny.so
	''')
	return create_pam_stack('irods', pam_stack_contents)

def setup_test_pam_stacks():
	create_pam_stack_for_pam_password_tests()

def configure_system_for_pam_password_tests():
	def create_test_user_for_pam_password_tests():
		username = 'pam_user'
		password = 'pam_password!'
		# TODO(#48): Find a different way to derive the "/var/lib/irods" paths.
		path_to_test_config = os.path.join('/var', 'lib', 'irods', 'test', 'test_framework_configuration.json')
		with open(path_to_test_config, 'r') as f:
			test_config = json.load(f)

		test_config['irods_pam_interactive_name'] = username
		test_config['irods_pam_interactive_password'] = password

		with open(path_to_test_config, 'w') as f:
			f.write(json.dumps(test_config, sort_keys=True, indent=4, separators=(',', ': ')))

		os.system(f'useradd {username}')
		os.system(f'echo "{username}:{password}" | chpasswd')

	create_test_user_for_pam_password_tests()

def main():
	parser = optparse.OptionParser()
	parser.add_option('--output_root_directory')
	parser.add_option('--built_packages_root_directory')
	parser.add_option('--test', metavar='dotted name')
	parser.add_option('--skip-setup', action='store_false', dest='do_setup', default=True)
	options, _ = parser.parse_args()

	built_packages_root_directory = options.built_packages_root_directory
	package_suffix = irods_python_ci_utilities.get_package_suffix()
	os_specific_directory = irods_python_ci_utilities.append_os_specific_directory(built_packages_root_directory)

	if options.do_setup:
		configure_system_for_pam_password_tests()
		setup_test_pam_stacks()

		irods_python_ci_utilities.install_os_packages_from_files(
			glob.glob(os.path.join(os_specific_directory,
					  f'irods-auth-plugin-pam-interactive*.{package_suffix}')
			)
		)

	test = options.test or 'test_irods_auth_plugin_pam_interactive'

	try:
		test_output_file = 'log/test_output.log'
		irods_python_ci_utilities.subprocess_get_output(['sudo', 'su', '-', 'irods', '-c',
			f'python3 scripts/run_tests.py --xml_output --run_s {test} 2>&1 | tee {test_output_file}; exit $PIPESTATUS'],
			check_rc=True)
	finally:
		output_root_directory = options.output_root_directory
		if output_root_directory:
			# TODO(#48): Find a different way to derive the "/var/lib/irods" paths.
			irods_python_ci_utilities.gather_files_satisfying_predicate('/var/lib/irods/log', output_root_directory, lambda x: True)
			shutil.copy('/var/lib/irods/log/test_output.log', output_root_directory)

if __name__ == '__main__':
	main()
