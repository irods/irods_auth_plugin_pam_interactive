from __future__ import print_function

import optparse
import os
import shutil
import glob
import irods_python_ci_utilities

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
		# TODO(#42): set up required PAM user and PAM stacks for tests

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
			irods_python_ci_utilities.gather_files_satisfying_predicate('/var/lib/irods/log', output_root_directory, lambda x: True)
			shutil.copy('/var/lib/irods/log/test_output.log', output_root_directory)

if __name__ == '__main__':
	main()
