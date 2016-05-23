#!/usr/bin/env python

import os
import sys
import shutil
import logging
import optparse
import subprocess


def _parse_args():
    parser = optparse.OptionParser(
        description='Continuous integration of '
        'virt-test libvirt test provider.')
    parser.add_option('--list', dest='list', action='store_true',
                      help='List all the test names')
    parser.add_option('--no', dest='no', action='store', default='',
                      help='Exclude specified tests.')
    parser.add_option('--only', dest='only', action='store', default='',
                      help='Run only for specified tests.')
    parser.add_option('--no-check', dest='no_check', action='store_true',
                      help='Disable checking state changes '
                      'after each test.')
    parser.add_option('--no-recover', dest='no_recover',
                      action='store_true',
                      help='Disable recover state changes '
                      'after each test.')
    parser.add_option('--connect-uri', dest='connect_uri', action='store',
                      default='', help='Run tests using specified uri.')
    parser.add_option('--additional-vms', dest='additional_vms', action='store',
                      default='', help='Additional VMs for testing')
    parser.add_option('--smoke', dest='smoke', action='store_true',
                      help='Run one test for each script.')
    parser.add_option('--slice', dest='slice', action='store',
                      default='', help='Specify a URL to slice tests.')
    parser.add_option('--report', dest='report', action='store',
                      default='xunit_result.xml',
                      help='Exclude specified tests.')
    parser.add_option('--text-report', dest='text_report', action='store',
                      default='report.txt',
                      help='Exclude specified tests.')
    parser.add_option('--whitelist', dest='whitelist', action='store',
                      default='', help='Whitelist file contains '
                      'specified test cases to run.')
    parser.add_option('--blacklist', dest='blacklist', action='store',
                      default='', help='Blacklist file contains '
                      'specified test cases to be excluded.')
    parser.add_option('--config', dest='config', action='store',
                      default='', help='Specify a custom Cartesian cfg '
                      'file')
    parser.add_option('--img-url', dest='img_url', action='store',
                      default='', help='Specify a URL to a custom image '
                      'file')
    parser.add_option('--os-variant', dest='os_variant', action='store',
                      default='', help='Specify the --os-variant option '
                      'when doing virt-install.')
    parser.add_option('--password', dest='password', action='store',
                      default='', help='Specify a password for logging '
                      'into guest')
    parser.add_option('--pull-virt-test', dest='pull_virt_test',
                      action='store', default='',
                      help='Merge specified virt-test pull requests. '
                      'Multiple pull requests are separated by ",", '
                      'example: --pull-virt-test 175,183')
    parser.add_option('--virt-test-patch', dest='virt_test_patch',
                      action='store', default='',
                      help='Merge specified virt-test patch files. '
                      'Multiple patch files are separated by ",", '
                      'example: --virt-test-patch patch/path/file.patch0,'
                      'patch/path/file.patch1')
    parser.add_option('--pull-libvirt', dest='pull_libvirt',
                      action='store', default='',
                      help='Merge specified tp-libvirt pull requests. '
                      'Multiple pull requests are separated by ",", '
                      'example: --pull-libvirt 175,183')
    parser.add_option('--libvirt-patch', dest='libvirt_patch',
                      action='store', default='',
                      help='Merge specified tp-libvirt patch files. '
                      'Multiple patch files are separated by ",", '
                      'example: --libvirt-patch patch/path/file.patch0,'
                      'patch/path/file.patch1')
    parser.add_option('--reason-url', dest='reason_url', action='store',
                      default='',
                      help='Specify a URL to a JSON reason file')
    parser.add_option('--with-dependence', dest='with_dependence',
                      action='store_true',
                      help='Merge virt-test pull requests depend on')
    parser.add_option('--no-restore-pull', dest='no_restore_pull',
                      action='store_true', help='This option is deprecated '
                      'and change to --restore-pull, The default will be not '
                      'restore pull.')
    parser.add_option('--restore-pull', dest='restore_pull',
                      action='store_true', help='Restore repo '
                      'to branch master after test.')
    parser.add_option('--only-change', dest='only_change',
                      action='store_true', help='Only test tp-libvirt '
                      'test cases related to changed files.')
    parser.add_option('--fail-diff', dest='fail_diff',
                      action='store_true', help='Report tests who do '
                      'not clean up environment as a failure')
    parser.add_option('--retain-vm', dest='retain_vm',
                      action='store_true', help='Do not reinstall VM '
                      'before tests')
    parser.add_option('--pre-cmd', dest='pre_cmd',
                      action='store', help='Run a command line after '
                      'fetch the source code and before running the test.')
    parser.add_option('--post-cmd', dest='post_cmd',
                      action='store', help='Run a command line after '
                      'running the test')
    parser.add_option('--test-path', dest='test_path', action='store',
                      default='', help='Path for the test directory')
    parser.add_option('--autotest-repo', dest='autotest_repo', action='store',
                      default='https://github.com/libvirt-CI/autotest.git '
                      'master', help='URL and branch for autotest repo')
    parser.add_option('--virt-test-repo', dest='virt_test_repo',
                      action='store',
                      default='https://github.com/wkf31156/virt-test.git '
                      'master', help='URL and branch for virt-test repo')
    parser.add_option('--tp-libvirt-repo', dest='tp_libvirt_repo',
                      action='store',
                      default='https://github.com/wkf31156/tp-libvirt.git '
                      'master', help='URL and branch for tp-libvirt repo')
    parser.add_option('--tp-qemu-repo', dest='tp_qemu_repo', action='store',
                      default='https://github.com/wkf31156/tp-qemu.git master',
                      help='URL and branch for tp-qemu repo')
    parser.add_option('--tp-libvirt-subtest', dest='subtest', action='store',
                      default='libvirt',
                      help='Subtest for tp-libvirt, e.g. libguestfs, libvirt, lvsb and v2v, libvirt is default')
    parser.add_option('--yum-repos', dest='yum_repos', action='store',
                      default='', help='YUM repos setup before test')
    parser.add_option('--install-pkgs', dest='install_pkgs', action='store',
                      default='',
                      help='Packages should be installed before test')
    parser.add_option('--update-all-pkgs', dest='update_all_pkgs', action='store_true',
                      help='Update all packages before test')
    parser.add_option('--timeout', dest='timeout', action='store',
                      default='1200',
                      help='Maximum time to wait for one test entry')
    parser.add_option('--replaces', dest='replaces', action='store',
                      help='Replace patterns in specified files. This option '
                      'is only a placeholder, you should set CI_REPLACES env '
                      'instead.')
    parser.add_option('--main-vm', dest='main_vm', action='store',
                      default='virt-tests-vm1',
                      help="Customized main domain name. Default to 'virt-tests-vm1'")
    parser.add_option('--domxml', dest='domxml', action='store',
                      help='Customized domain XML')
    parser.add_option('--qemu-pkg', dest='qemu_pkg', action='store',
                      default='qemu-rhev',
                      help="Specify with qemu package to be installed. Could "
                      "be one of 'qemu' or 'qemu-rhev'. Default to 'qemu-rhev'")
    args, real_args = parser.parse_args()
    if args.no_restore_pull:
        logging.warning(
            'CI option --no-restore-pull is now deprecated. The default '
            'behavior is not restoring pulls after test now. You can enable '
            'restoration by setting --restore-pull')
    return args


def _retrieve_repos():
    for repo in REPOS:
        repo_env_name = (repo + '_repo').replace('-', '_')
        repo_url, branch = getattr(ARGS, repo_env_name).split()

        logging.info("Retrieving %s from %s" % (repo, repo_url))

        os.system('git clone --quiet %s %s --branch %s' %
                  (repo_url, repo, branch))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)8s|%(message)s')

    REPOS = ['autotest', 'virt-test', 'tp-libvirt', 'tp-qemu']
    ENVS = {}
    for key, value in os.environ.items():
        if key.startswith('CI_'):
            ENVS[key[3:].lower()] = value
    ARGS = _parse_args()
    logging.debug("The current test parameters: \n%s", ARGS)

    for key, value in ENVS.items():
        if value and hasattr(ARGS, key):
            setattr(ARGS, key, value)

    if 'test_path' in ENVS:
        test_path = ENVS['test_path']
    else:
        test_path = os.path.join(os.getcwd(), 'test_dir')
        os.environ['CI_TEST_PATH'] = test_path
        logging.warning("Environment variable CI_TEST_PATH not set. "
                        "Test in %s." % test_path)

    if os.getcwd() == test_path:
        logging.info("--- Testing Phase ---")
        workspace = os.getenv("WORKSPACE")
        if not all([os.path.exists(repo) for repo in REPOS]):
            if not workspace or not all([
                    os.path.exists(os.path.join(workspace, repo))
                    for repo in REPOS]):
                _retrieve_repos()
            else:
                for repo in REPOS:
                    shutil.copytree(os.path.join(workspace, repo), repo)
        if 'test_path' in ENVS:
            # Replace .git of CI with virt-test for applying patch on Jenkins
            os.system('cp -r virt-test/. .')
        else:
            # Leave CI .git for local run
            os.system('cp -r virt-test/* .')
        if not os.path.exists('test-providers.d/downloads/'):
            os.makedirs('test-providers.d/downloads/')
        if not os.path.exists('test-providers.d/downloads/tp-libvirt'):
            os.symlink('../../tp-libvirt',
                       'test-providers.d/downloads/io-github-autotest-libvirt')
        if not os.path.exists('test-providers.d/downloads/tp-qemu'):
            os.symlink('../../tp-qemu',
                       'test-providers.d/downloads/io-github-autotest-qemu')

        from ci import LibvirtCI
        logging.info("Start running libvirt CI in %s" % test_path)
        LibvirtCI(args=ARGS).run()
    else:
        logging.info("--- Loading Phase ---")
        workspace = os.getenv("WORKSPACE")
        if workspace:
            if workspace != os.getcwd():
                logging.warning('WORKSPACE:%s is not current directory:%s',
                                workspace, os.getcwd())
        else:
            os.environ['WORKSPACE'] = os.getcwd()

        if not all([os.path.exists(repo) for repo in REPOS]):
            _retrieve_repos()
        else:
            for repo in REPOS:
                logging.info('Updating repo %s' % repo)
                os.chdir(repo)
                os.system('git pull')
                os.chdir('..')

        if os.path.exists(test_path):
            logging.info("Path %s exists. Cleaning up...", test_path)
            shutil.rmtree(test_path)
        shutil.copytree('.', test_path)
        os.chdir(test_path)
        subprocess.call(sys.argv)
