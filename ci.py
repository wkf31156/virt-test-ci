import os
import re
import sys
import time
import urllib
import urllib2
import json
import fileinput
import traceback
import platform
import ConfigParser

from virttest import data_dir
from virttest import virsh
from virttest import utils_libvirtd
from virttest.staging import service
from autotest.client.shared import error
from autotest.client import utils

from report import Report
from state import States


class LibvirtCI():

    def __init__(self, args):
        self.args = args

    def prepare_pkgs(self):
        def _setup_repos(repo_dict):
            config = ConfigParser.ConfigParser()
            for name, url in repo_dict.items():
                dist_name, dist_version, dist_codename = platform.dist()
                ver_major = None
                if dist_version.count('.') == 0:
                    ver_major = dist_version
                elif dist_version.count('.') >= 1:
                    vers = dist_version.split('.')
                    ver_major = vers[0]

                if name == 'epel':
                    if dist_name == 'redhat':
                        url = ('http://download.fedoraproject.org/pub/'
                               'epel/%s/$basearch' % ver_major)
                else:
                    if url is None:
                        raise AttributeError("Unknown repo name %s, url "
                                             "must be assigned." % name)
                config.add_section(name)
                config.set(name, "name", name)
                config.set(name, "baseurl", url)
                config.set(name, "enabled", 1)
                config.set(name, "gpgcheck", 0)

            path = '/etc/yum.repos.d/virt-test-ci.repo'
            with open(path, 'wb') as repo_file:
                config.write(repo_file)

        def _install_pkgs(pkgs):
            if pkgs:
                if type(pkgs) is list:
                    pkgs = ' '.join(pkgs)

            cmd = 'yum -y install --skip-broken ' + pkgs
            utils.run(cmd)

        def _update_pkgs(pkgs=''):
            if pkgs:
                if type(pkgs) is list:
                    pkgs = ' '.join(pkgs)

            cmd = 'yum -y update --skip-broken ' + pkgs
            utils.run(cmd)


        if self.args.yum_repos:
            repos = ['epel']
            repos += re.split('[ ,]', self.args.yum_repos)
            repo_dict = {}
            for repo_str in repos:
                if '|' in repo_str:
                    repo_name, repo_url = repo_str.split('|')
                else:
                    repo_name = repo_str
                    repo_url = None
                repo_dict[repo_name] = repo_url

            _setup_repos(repo_dict)

        print "Updating all packages"
        _update_pkgs()

        if self.args.install_pkgs:
            pkgs = ['p7zip', 'fakeroot']
            pkgs += re.split('[ ,]', self.args.install_pkgs)
            print "Installing packages %s" % ' '.join(pkgs)
            _install_pkgs(pkgs)


    def prepare_tests(self, whitelist='whitelist.test',
                      blacklist='blacklist.test'):
        """
        Get all tests to be run.

        When a whitelist is given, only tests in whitelist will be run.
        When a blacklist is given, tests in blacklist will be excluded.
        """
        def read_tests_from_file(file_name):
            """
            Read tests from a file
            """
            try:
                tests = []
                with open(file_name) as fp:
                    for line in fp:
                        if not line.strip().startswith('#'):
                            tests.append(line.strip())
                return tests
            except IOError:
                return None

        def get_all_tests():
            """
            Get all libvirt tests.
            """
            if type(self.onlys) == set and not self.onlys:
                return []

            cmd = './run -t libvirt --list-tests'
            if self.args.connect_uri:
                cmd += ' --connect-uri %s' % self.args.connect_uri
            if self.nos:
                cmd += ' --no %s' % ','.join(self.nos)
            if self.onlys:
                cmd += ' --tests %s' % ','.join(self.onlys)
            if self.args.config:
                cmd += ' -c %s' % self.args.config
            res = utils.run(cmd)
            out, err, exitcode = res.stdout, res.stderr, res.exit_status
            tests = []
            class_names = set()
            for line in out.splitlines():
                if line:
                    if line[0].isdigit():
                        test = re.sub(r'^[0-9]+ (.*) \(requires root\)$',
                                      r'\1', line)
                        if self.args.smoke:
                            class_name, _ = self.split_name(test)
                            if class_name in class_names:
                                continue
                            else:
                                class_names.add(class_name)
                        tests.append(test)
            return tests

        def change_to_only(change_list):
            """
            Transform the content of a change file to a only set.
            """
            onlys = set()
            for line in change_list:
                filename = line.strip()
                res = re.match('libvirt/tests/(cfg|src)/(.*).(cfg|py)',
                               filename)
                if res:
                    cfg_path = 'libvirt/tests/cfg/%s.cfg' % res.groups()[1]
                    tp_dir = data_dir.get_test_provider_dir(
                        'io-github-autotest-libvirt')
                    cfg_path = os.path.join(tp_dir, cfg_path)
                    try:
                        with open(cfg_path) as fcfg:
                            only = fcfg.readline().strip()
                            only = only.lstrip('-').rstrip(':').strip()
                            onlys.add(only)
                    except:
                        pass
            return onlys

        self.nos = set(['io-github-autotest-qemu'])
        self.onlys = None

        if self.args.only:
            self.onlys = set(self.args.only.split(','))

        if self.args.slice:
            slices = {}
            slice_opts = self.args.slice.split(',')
            slice_url = slice_opts[0]
            slice_opts = slice_opts[1:]
            config = urllib2.urlopen(slice_url)
            for line in config:
                key, val = line.split()
                slices[key] = val
            for slice_opt in slice_opts:
                if slice_opt in slices:
                    if self.onlys is None:
                        self.onlys = set(slices[slice_opt].split(','))
                    else:
                        self.onlys |= set(slices[slice_opt].split(','))
                elif slice_opt == 'other':
                    for key in slices:
                        self.nos |= set(slices[key].split(','))

        if self.args.no:
            self.nos |= set(self.args.no.split(','))
        if self.args.only_change:
            if self.onlys is not None:
                self.onlys &= change_to_only(self.libvirt_file_changed)
            else:
                self.onlys = change_to_only(self.libvirt_file_changed)

        if self.args.whitelist:
            tests = read_tests_from_file(whitelist)
        else:
            tests = get_all_tests()

        if self.args.blacklist:
            black_tests = read_tests_from_file(blacklist)
            tests = [t for t in tests if t not in black_tests]

        with open('run.test', 'w') as fp:
            for test in tests:
                fp.write(test + '\n')

        if self.args.list:
            for test in tests:
                short_name = test.split('.', 2)[2]
                print short_name
            exit(0)

        self.tests = tests

    def split_name(self, name):
        """
        Try to return the module name of a test.
        """
        if name.startswith('type_specific.io-github-autotest-libvirt'):
            name = name.split('.', 2)[2]

        if name.split('.')[0] in ['virsh']:
            package_name, name = name.split('.', 1)
        else:
            package_name = ""

        names = name.split('.', 1)
        if len(names) == 2:
            name, test_name = names
        else:
            name = names[0]
            test_name = name
        if package_name:
            class_name = '.'.join((package_name, name))
        else:
            class_name = name

        return class_name, test_name

    def bootstrap(self):
        from virttest import bootstrap

        print 'Bootstrapping'
        sys.stdout.flush()

        test_dir = data_dir.get_backend_dir('libvirt')
        default_userspace_paths = ["/usr/bin/qemu-kvm", "/usr/bin/qemu-img"]
        base_dir = data_dir.get_data_dir()
        bootstrap.bootstrap(test_name='libvirt', test_dir=test_dir,
                            base_dir=base_dir,
                            default_userspace_paths=default_userspace_paths,
                            check_modules=[],
                            online_docs_url=None,
                            interactive=False,
                            selinux=True,
                            restore_image=False,
                            verbose=True,
                            update_providers=False,
                            force_update=True)
        os.chdir(data_dir.get_root_dir())

    def replace_pattern_in_file(self, file, search_exp, replace_exp):
        prog = re.compile(search_exp)
        for line in fileinput.input(file, inplace=1):
            match = prog.search(line)
            if match:
                line = prog.sub(replace_exp, line)
            sys.stdout.write(line)

    def prepare_env(self):
        """
        Prepare the environment before all tests.
        """

    def run_test(self, test, restore_image=False):
        """
        Run a specific test.
        """
        img_str = '' if restore_image else 'k'
        down_str = '' if restore_image else '--no-downloads'
        cmd = ('./run -v%st libvirt --keep-image-between-tests %s'
               ' --tests %s' % (img_str, down_str, test))
        if self.args.connect_uri:
            cmd += ' --connect-uri %s' % self.args.connect_uri
        status = 'INVALID'
        try:
            res = utils.run(cmd, timeout=1200, ignore_status=True)
            lines = res.stdout.splitlines()
            for line in lines:
                if line.startswith('(1/1)'):
                    status = line.split()[2]
        except error.CmdError, e:
            res = e.result_obj
            status = 'TIMEOUT'
            res.duration = 1200
        except Exception, e:
            print "Exception when parsing stdout.\n%s" % res
            raise e

        os.chdir(data_dir.get_root_dir())  # Check PWD

        err_msg = []

        print 'Result: %s %.2f s' % (status, res.duration)

        result_line = ''
        for line in res.stderr.splitlines():
            if re.search('(INFO |ERROR)\| (SKIP|ERROR|FAIL|PASS)', line):
                result_line = line
            if 'FAIL' in status or 'ERROR' in status:
                if 'ERROR' in line:
                    err_msg.append('  %s' % line[9:])

        if status == 'INVALID' or status == 'TIMEOUT':
            for line in res.stdout.splitlines():
                err_msg.append(line)
        sys.stdout.flush()
        return status, res, err_msg, result_line

    def prepare_repos(self):
        """
        Prepare repos for the tests.
        """
        def merge_pulls(repo_name, pull_nos):
            branch_name = ','.join(pull_nos)
            cmd = 'git checkout -b %s' % branch_name
            res = utils.run(cmd, ignore_status=True)
            if res.exit_status:
                print res
                raise Exception('Failed to create branch %s' % branch_name)

            for pull_no in pull_nos:
                if pr_open(repo_name, pull_no):
                    patch_url = ('https://github.com/autotest'
                                 '/%s/pull/%s.patch' % (repo_name, pull_no))
                    patch_file = "/tmp/%s.patch" % pull_no
                    with open(patch_file, 'w') as pf:
                        pf.write(urllib2.urlopen(patch_url).read())
                    with open(patch_file, 'r') as pf:
                        if not pf.read().strip():
                            print 'WARING: empty content for PR #%s' % pull_no
                    try:
                        print 'Patching %s PR #%s' % (repo_name, pull_no)
                        cmd = 'git am -3 %s' % patch_file
                        res = utils.run(cmd)
                    except error.CmdError, e:
                        print e
                        raise Exception('Failed applying patch %s.' % pull_no)
                    finally:
                        os.remove(patch_file)
            return branch_name

        def file_changed(repo_name):
            cmd = 'git diff master --name-only'
            res = utils.run(cmd, ignore_status=True)
            if res.exit_status:
                print res
                raise Exception("Failed to get diff info against master")

            return res.stdout.strip().splitlines()

        def search_dep(line):
            pattern1 = r'autotest/virt-test#([0-9]*)'
            pattern2 = (r'https?://github.com/autotest/virt-test/'
                        '(?:pull|issues)/([0-9]*)')
            res = set()
            match = re.findall(pattern1, line)
            res |= set(match)
            match = re.findall(pattern2, line)
            res |= set(match)
            return res

        def pr_open(repo_name, pr_number):
            oauth = ('?client_id=b6578298435c3eaa1e3d&client_secret'
                     '=59a1c828c6002ed4e8a9205486cf3fa86467a609')
            issues_url = ('https://api.github.com/repos/autotest/%s/issues/' %
                          repo_name)
            issue_url = issues_url + pr_number + oauth
            issue_u = urllib2.urlopen(issue_url)
            issue = json.load(issue_u)
            return issue['state'] == 'open'

        def libvirt_pr_dep(pr_numbers):
            oauth = ('?client_id=b6578298435c3eaa1e3d&client_secret'
                     '=59a1c828c6002ed4e8a9205486cf3fa86467a609')
            dep = set()
            for pr_number in pr_numbers:
                # Find PR's first comment for dependencies.
                issues_url = ('https://api.github.com/repos/autotest/'
                              'tp-libvirt/issues/')
                issue_url = issues_url + pr_number + oauth
                issue_u = urllib2.urlopen(issue_url)
                issue = json.load(issue_u)
                for line in issue['body'].splitlines():
                    dep |= search_dep(line)

                # Find PR's other comments for dependencies.
                comments_url = issues_url + '%s/comments' % pr_number + oauth
                comments_u = urllib2.urlopen(comments_url)
                comments = json.load(comments_u)
                for comment in comments:
                    for line in comment['body'].splitlines():
                        dep |= search_dep(line)

            # Remove closed dependences:
            pruned_dep = set()
            for pr_number in dep:
                if pr_open('virt-test', pr_number):
                    pruned_dep.add(pr_number)

            return pruned_dep

        self.virt_branch_name, self.libvirt_branch_name = None, None

        pull_libvirts = set()
        pull_virt_tests = set()

        if self.args.pull_libvirt:
            pull_libvirts = set(self.args.pull_libvirt.split(','))

        if self.args.with_dependence:
            pull_virt_tests = libvirt_pr_dep(pull_libvirts)

        if self.args.pull_virt_test:
            pull_virt_tests |= set(self.args.pull_virt_test.split(','))

        if pull_virt_tests:
            os.chdir(data_dir.get_root_dir())
            self.virt_branch_name = merge_pulls("virt-test", pull_virt_tests)
            if self.args.only_change:
                self.virt_file_changed = file_changed("virt-test")

        if pull_libvirts:
            os.chdir(data_dir.get_test_provider_dir(
                'io-github-autotest-libvirt'))
            self.libvirt_branch_name = merge_pulls("tp-libvirt", pull_libvirts)
            if self.args.only_change:
                self.libvirt_file_changed = file_changed("tp-libvirt")

        os.chdir(data_dir.get_root_dir())

    def restore_repos(self):
        """
        Checkout master branch and remove test branch.
        """
        def restore_repo(branch_name):
            cmd = 'git checkout master'
            res = utils.run(cmd, ignore_status=True)
            if res.exit_status:
                print res
            cmd = 'git branch -D %s' % branch_name
            res = utils.run(cmd, ignore_status=True)
            if res.exit_status:
                print res

        if self.virt_branch_name:
            os.chdir(data_dir.get_root_dir())
            restore_repo(self.virt_branch_name)

        if self.libvirt_branch_name:
            os.chdir(data_dir.get_test_provider_dir(
                'io-github-autotest-libvirt'))
            restore_repo(self.libvirt_branch_name)
        os.chdir(data_dir.get_root_dir())

    def get_reason(self, result_line):
        for name, reason in self.reasons.items():
            if (re.search(reason['case'], result_line) and
                    re.search(reason['result'], result_line)):
                return name

    def prepare_vm(self):
        restore_image = True
        if self.args.img_url:
            print 'Downloading image from %s.' % self.args.img_url
            sys.stdout.flush()
            img_dir = os.path.join(
                os.path.realpath(data_dir.get_data_dir()),
                'images/jeos-19-64.qcow2')
            urllib.urlretrieve(self.args.img_url, img_dir)
            restore_image = False

        if self.args.retain_vm:
            return

        print 'Removing VM\n',  # TODO: use virt-test api remove VM
        sys.stdout.flush()
        if self.args.connect_uri:
            virsh.destroy('virt-tests-vm1',
                          ignore_status=True,
                          uri=self.args.connect_uri)
            virsh.undefine('virt-tests-vm1',
                           '--snapshots-metadata --managed-save',
                           ignore_status=True,
                           uri=self.args.connect_uri)
        else:
            virsh.destroy('virt-tests-vm1', ignore_status=True)
            virsh.undefine('virt-tests-vm1', '--snapshots-metadata',
                           ignore_status=True)
        if self.args.additional_vms:
            for vm in self.args.additional_vms.split(','):
                virsh.destroy(vm, ignore_status=True)
                virsh.undefine(vm, '--snapshots-metadata', ignore_status=True)

        print 'Installing VM',
        sys.stdout.flush()
        if 'lxc' in self.args.connect_uri:
            cmd = ('virt-install --connect=lxc:/// --name virt-tests-vm1 '
                   '--ram 500 --noautoconsole')
            try:
                utils.run(cmd)
            except error.CmdError, e:
                raise Exception('   ERROR: Failed to install guest \n %s' % e)
        else:
            status, res, err_msg, result_line = self.run_test(
                'unattended_install.import.import.default_install.aio_native',
                restore_image=restore_image)
            if 'PASS' not in status:
                raise Exception('   ERROR: Failed to install guest \n %s' %
                                res.stderr)
            virsh.destroy('virt-tests-vm1')
        if self.args.additional_vms:
            for vm in self.args.additional_vms.split(','):
                cmd = 'virt-clone '
                if self.args.connect_uri:
                    cmd += '--connect=%s ' % self.args.connect_uri
                cmd += '--original=virt-tests-vm1 '
                cmd += '--name=%s ' % vm
                cmd += '--auto-clone'
                utils.run(cmd)

    def prepare_cfg(self):
        if self.args.password:
            self.replace_pattern_in_file(
                "shared/cfg/guest-os/Linux.cfg",
                r'password = \S*',
                r'password = %s' % self.args.password)

        if self.args.os_variant:
            self.replace_pattern_in_file(
                "shared/cfg/guest-os/Linux/JeOS/19.x86_64.cfg",
                r'os_variant = \S*',
                r'os_variant = %s' % self.args.os_variant)

        if self.args.additional_vms:
            vms_string = "virt-tests-vm1 " + " ".join(
                self.args.additional_vms.split(','))
            self.replace_pattern_in_file(
                "shared/cfg/base.cfg",
                r'^\s*vms = .*\n',
                r'vms = %s\n' % vms_string)

    def prepare(self):
        self.prepare_pkgs()

        self.prepare_repos()

        if self.args.pre_cmd:
            print 'Running command line "%s" before test.' % self.args.pre_cmd
            res = utils.run(self.args.pre_cmd, ignore_status=True)
            print 'Result:'
            for line in str(res).splitlines():
                print line

        self.bootstrap()

        self.prepare_tests()

        self.report = Report(self.args.fail_diff)
        if not self.tests:
            self.report.update("", "no_test.no_test", "", "", "", "", 0)
            print "No test to run!"
            exit(0)

        utils_libvirtd.Libvirtd().restart()
        service.Factory.create_service("nfs").restart()

        self.prepare_cfg()

        self.reasons = {}
        if self.args.reason_url:
            print 'Downloading reason from %s.' % self.args.reason_url
            sys.stdout.flush()
            reason_u = urllib2.urlopen(self.args.reason_url)
            self.reasons = json.load(reason_u)

        self.prepare_vm()

        self.states = States()
        self.states.backup()

    def run(self):
        """
        Run continuous integrate for virt-test test cases.
        """

        self.prepare()
        try:
            for idx, test in enumerate(self.tests):
                short_name = test.split('.', 2)[2]
                print '%s (%d/%d) %s ' % (time.strftime('%X'), idx + 1,
                                          len(self.tests), short_name),
                sys.stdout.flush()

                status, res, err_msg, result_line = self.run_test(test)

                if not self.args.no_check:
                    diff_msg = self.states.check(
                        recover=(not self.args.no_recover))
                    if diff_msg:
                        diff_msg = ['   DIFF|%s' % l for l in diff_msg]
                        err_msg = diff_msg + err_msg

                if err_msg:
                    for line in err_msg:
                        print line
                sys.stdout.flush()

                reason = self.get_reason(result_line)

                class_name, test_name = self.split_name(test)

                self.report.update(test_name, class_name, status, reason,
                                   res.stderr, err_msg, res.duration)
                self.report.save(self.args.report, self.args.text_report)
            if self.args.post_cmd:
                print ('Running command line "%s" after test.' %
                       self.args.post_cmd)
                res = utils.run(self.args.post_cmd, ignore_status=True)
                print 'Result:'
                for line in str(res).splitlines():
                    print line
        except Exception:
            traceback.print_exc()
        finally:
            if not self.args.no_restore_pull:
                self.restore_repos()
            self.report.save(self.args.report, self.args.text_report)
