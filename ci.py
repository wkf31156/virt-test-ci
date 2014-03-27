#!/usr/bin/env python
import re
import os
import sys
import time
import difflib
import traceback
from virttest import common
from virttest import data_dir
from virttest import virsh
from autotest.client import utils
from autotest.client.tools import JUnit_api as api
from autotest.client.shared import error
from datetime import date


class Report():
    class failureType(api.failureType):
        pass
    class errorType(api.errorType):
        pass
    def __init__(self):
        self.testsuites = api.testsuites()
        self.ts_dict = {}

    def save(self, filename):
        """
        Save current state of report to files.
        """
        for ts_name in self.ts_dict:
            ts = self.ts_dict[ts_name]
            self.testsuites.add_testsuite(ts)
        with open(filename, 'w') as fp:
            self.testsuites.export(fp, 0)


    def update(self, testname, ts_name, result, log, duration):
        """
        Insert a new item into report.
        """

        if not ts_name in self.ts_dict:
            self.ts_dict[ts_name] = api.testsuite(name=ts_name)
            ts = self.ts_dict[ts_name]
            ts.failures = 0
            ts.tests = 0
            ts.errors = 0
        else:
            ts = self.ts_dict[ts_name]

        tc = api.testcaseType()
        tc.name = testname
        tc.time = duration
        if 'FAIL' in result:
            tc.failure = self.failureType(
                    message='Test %s has failed' % testname,
                    type_='Failure',
                    valueOf_="\n<![CDATA[\n%s\n]]>\n" % log)
            ts.failures += 1
        elif 'ERROR' in result:
            tc.error = self.errorType(
                    message='Test %s has failed' % testname,
                    type_='Failure',
                    valueOf_="\n<![CDATA[\n%s\n]]>\n" % log)
            ts.errors += 1
        ts.add_testcase(tc)
        ts.tests += 1
        ts.timestamp = date.isoformat(date.today())


class State():
    perm_key = []
    perm_re = []
    def get_names(self):
        raise NotImplementedError('Function get_names not implemented for %s.'
                                  % self.__class__.__name__)
    def get_info(self, name):
        raise NotImplementedError('Function get_info not implemented for %s.'
                                  % self.__class__.__name__)
    def remove(self):
        raise NotImplementedError('Function remove not implemented for %s.'
                                  % self.__class__.__name__)
    def restore(self, name):
        raise NotImplementedError('Function restore not implemented for %s.'
                                  % self.__class__.__name__)
    def get_state(self):
        names = self.get_names()
        state = {}
        for name in names:
            state[name] = self.get_info(name)
        return state

    def backup(self):
        """
        Backup current state
        """
        self.backup_state = self.get_state()

    def check(self, recover=False):
        """
        Check state changes and recover to specified state.
        Return a result.
        """
        def diff_dict(dict_old, dict_new):
            created = set(dict_new) - set(dict_old)
            deleted = set(dict_old) - set(dict_new)
            shared = set(dict_old) & set(dict_new)
            return created, deleted, shared

        def lines_permitable(diff, permit_re):
            """
            Check whether the diff message is in permitable list of regexs.
            """
            diff_lines = set()
            for line in diff[2:]:
                if re.match(r'^[-+].*', line):
                    diff_lines.add(line)

            for line in diff_lines:
                permit = False
                for r in permit_re:
                    if re.match(r, line):
                        permit = True
                        break
                if not permit:
                    return False
            return True

        self.current_state = self.get_state()
        diff_msg = []
        new_items, del_items, unchanged_items = diff_dict(
                self.backup_state, self.current_state)
        if new_items:
            diff_msg.append('Created %s(s):' % self.name)
            for key in new_items:
                diff_msg.append(key)
                if recover:
                    try:
                        self.remove(self.current_state[key])
                        diff_msg.append('FIXED')
                    except Exception, e:
                        diff_msg.append('Remove is failed:\n %s' % e)

        if del_items:
            diff_msg.append('Deleted %s(s):' % name)
            for key in del_items:
                diff_msg.append(key)
                if recover:
                    try:
                        self.restore(self.current_state[key])
                        diff_msg.append('FIXED')
                    except Exception, e:
                        diff_msg.append('Recover is failed:\n %s' % e)

        for item in unchanged_items:
            cur = self.current_state[item]
            bak = self.backup_state[item]
            item_changed = False
            new_keys, del_keys, unchanged_keys = diff_dict(bak, cur)
            if new_keys:
                diff_msg.append('Created key(s) in %s %s:' % (self.name, item))
                for key in new_keys:
                    diff_msg.append(key)
            if del_keys:
                diff_msg.append('Deleted key(s) in %s %s:' % (self.name, item))
                for key in new_keys:
                    diff_msg.append(key)
            for key in unchanged_keys:
                if type(cur[key]) is str:
                    if key not in self.perm_key and cur[key] != bak[key]:
                        item_changed = True
                        diff_msg.append('%s %s: %s changed: %s -> %s' % (
                                self.name, item, key, bak[key], cur[key]))
                elif type(cur[key]) is list:
                    diff = difflib.unified_diff(
                            bak[key],cur[key], lineterm="")
                    tmp_msg = []
                    for line in diff:
                        tmp_msg.append(line)
                    if tmp_msg and not lines_permitable(tmp_msg, self.perm_re):
                        item_changed = True
                        diff_msg.append('Pool %s: "%s" changed:' % (item, key))
                        diff_msg += tmp_msg
                else:
                    diff_msg.append('Pool %s: %s: Invalid type %s.' % (
                            item, key, type(cur[key])))
            if item_changed and recover:
                try:
                    self.restore(bak)
                    diff_msg.append('FIXED')
                except Exception, e:
                    diff_msg.append('Recover is failed:\n %s' % e)
        return diff_msg


class DomainState(State):
    name = 'domain'
    def get_info(self, name):
        infos = {}
        for line in virsh.dominfo(name).stdout.strip().splitlines():
            key, value = line.split(':', 1)
            infos[key.lower()] = value.strip()
        infos['inactive xml'] = virsh.dumpxml(name, extra='--inactive').stdout.splitlines()
        return infos

    def get_names(self):
        return virsh.dom_list(options='--all --name').stdout.splitlines()


class NetworkState(State):
    name = 'network'
    def get_info(self, name):
        infos = {}
        for line in virsh.net_info(name).stdout.strip().splitlines():
            if line.startswith('Name') or line.startswith('UUID'):
                key, value = line.split()
            else:
                key, value = line.split(':', 1)
            infos[key.lower()] = value.strip()
        infos['inactive xml'] = virsh.net_dumpxml(
                name,'--inactive').stdout.splitlines()
        return infos

    def get_names(self):
        lines = virsh.net_list('--all').stdout.strip().splitlines()[2:]
        return [line.split()[0] for line in lines]


class PoolState(State):
    name = 'pool'
    def get_info(self, name):
        infos = {}
        for line in virsh.pool_info(name).stdout.strip().splitlines():
            key, value = line.split(':', 1)
            infos[key.lower()] = value.strip()
        infos['inactive xml'] = virsh.pool_dumpxml(name, '--inactive').splitlines()
        infos['volumes'] = virsh.vol_list(name).stdout.strip().splitlines()[2:]
        return infos

    def get_names(self):
        lines = virsh.pool_list('--all').stdout.strip().splitlines()[2:]
        return [line.split()[0] for line in lines]


class LibvirtCI():
    def prepare_tests(self, whitelist='whitelist.test', blacklist='blacklist.test'):
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
            res = utils.run('./run -t libvirt --list-tests')
            out, err, exitcode = res.stdout, res.stderr, res.exit_status
            tests = []
            for line in out.splitlines():
                if line:
                    if line[0].isdigit():
                        test = re.sub(r'^[0-9]+ (.*) \(requires root\)$',
                                      r'\1', line)
                        if test.startswith('type_specific'):
                            tests.append(test)
            return tests

        tests = read_tests_from_file(whitelist)
        if not tests:
            tests = get_all_tests()
        black_tests = read_tests_from_file(blacklist)
        if black_tests:
            tests = [t for t in tests if t not in black_tests]
        with open('run.test', 'w') as fp:
            for test in tests:
                fp.write(test + '\n')
        return tests

    def get_module_name(self, name):
        """
        Try to return the module name of a test.
        """
        if name.startswith('type_specific'):
            name = name.split('.', 1)[1]
        if name.startswith('io-github-autotest-libvirt'):
            name = name.split('.', 1)[1]
        if name.startswith('virsh'):
            name = name.split('.', 1)[1]
        return name.split('.', 1)[0]

    def bootstrap(self):
        from virttest import bootstrap

        test_dir = data_dir.get_backend_dir('libvirt')
        default_userspace_paths = ["/usr/bin/qemu-kvm", "/usr/bin/qemu-img"]
        bootstrap.bootstrap(test_name='libvirt', test_dir=test_dir,
                            base_dir=data_dir.get_data_dir(),
                            default_userspace_paths=default_userspace_paths,
                            check_modules=[],
                            online_docs_url=None,
                            interactive=False,
                            download_image=False,
                            selinux=True,
                            restore_image=False,
                            verbose=True,
                            update_providers=False)
        os.chdir(data_dir.get_root_dir())

    def prepare_env(self):
        """
        Prepare the environment before all tests.
        """
        print 'Running bootstrap'
        self.bootstrap()

        print 'Removing VM', # TODO: use virt-test api remove VM
        sys.stdout.flush()
        status, res = self.run_test('remove_guest.without_disk')
        print 'Result: %s %.2f s' % (status, res.duration)
        if not 'PASS' in status:
            virsh.undefine('virt-tests-vm1', '--snapshots-metadata')
            print '   WARNING: Failed to remove guest'

        print 'Installing VM',
        sys.stdout.flush()
        status, res = self.run_test(
                'unattended_install.import.import.default_install.aio_native',
                restore_image=True)
        print 'Result: %s %.2f s' % (status, res.duration)
        if not 'PASS' in status:
            raise Exception('   ERROR: Failed to install guest \n %s' % res.stderr)

    def run_test(self, test, restore_image=False):
        """
        Run a specific test.
        """
        img_str = '' if restore_image else 'k'
        cmd =  './run -v%st libvirt --keep-image-between-tests --tests %s' % (img_str, test)
        test_status = 'INVALID'
        res = utils.run(cmd, timeout=600, ignore_status=True)
        lines = res.stdout.splitlines()
        for line in lines:
            if line.startswith('(1/1)'):
                test_status = line.split()[2]

        return test_status, res

    def run(self):
        """
        Run continuous integrate for virt-test test cases.
        """
        report = Report()
        try:
            states = [DomainState(), NetworkState(), PoolState()]
            for state in states:
                state.backup()

            tests = self.prepare_tests()
            self.prepare_env()
            for idx, test in enumerate(tests):
                short_name = test.split('.', 2)[2]
                print '%s (%d/%d) %s ' % (time.strftime('%X'), idx + 1, len(tests), short_name),
                sys.stdout.flush()

                try:
                    status, res = self.run_test(test)

                    os.chdir(data_dir.get_root_dir())
                    for state in states:
                        state.check(recover=True)

                    print 'Result: %s %.2f s' % (status, res.duration)
                    if 'FAIL' in status or 'ERROR' in status:
                        for line in res.stderr.splitlines():
                            if 'ERROR|' in line:
                                print '  %s' % line[9:]
                    if status == 'INVALID':
                        print res.stdout
                    sys.stdout.flush()
                    module_name = self.get_module_name(test)
                    report.update(test, module_name, status, res.stderr, res.duration)
                except error.CmdError:
                    status = 'TIMEOUT'
                    print 'Result: %s %.2f s' % (status, 600.0)
                    report.update(test, module_name, status, traceback.format_exc(), 600.0)
        except Exception:
            traceback.print_exc()
        finally:
            report.save('libvirt_ci_junit.xml')


if __name__ == '__main__':
    ci = LibvirtCI()
    ci.run()

# vi:set ts=4 sw=4 expandtab:
