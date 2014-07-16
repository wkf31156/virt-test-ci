#!/usr/bin/env python
import re
import os
import sys
import time
import urllib
import urllib2
import json
import shutil
import string
import difflib
import optparse
import tempfile
import fileinput
import traceback
from virttest import common
from virttest import utils_libvirtd, utils_selinux
from virttest import data_dir
from virttest import virsh
from autotest.client import utils
from virttest.utils_misc import mount, umount
from autotest.client.tools import JUnit_api as api
from autotest.client.shared import error
from datetime import date


class Report():

    """
    This is a wrapper of autotest.client.tools.JUnit_api
    """

    class testcaseType(api.testcaseType):

        def __init__(self, classname=None, name=None, time=None, error=None,
                     failure=None, skip=None):
            api.testcaseType.__init__(self, classname, name, time, error,
                                      failure)
            self.skip = skip
            self.system_out = None
            self.system_err = None

        def exportChildren(self, outfile, level, namespace_='',
                           name_='testcaseType', fromsubclass_=False):
            api.testcaseType.exportChildren(
                self, outfile, level, namespace_, name_, fromsubclass_)
            if self.skip is not None:
                self.skip.export(outfile, level, namespace_, name_='skipped')
            if self.system_out is not None:
                outfile.write(
                    '<%ssystem-out><![CDATA[%s]]></%ssystem-out>\n' % (
                        namespace_,
                        self.system_out,
                        namespace_))
            if self.system_err is not None:
                outfile.write(
                    '<%ssystem-err><![CDATA[%s]]></%ssystem-err>\n' % (
                        namespace_,
                        self.system_err,
                        namespace_))

        def hasContent_(self):
            if (
                self.system_out is not None or
                self.system_err is not None or
                self.error is not None or
                self.failure is not None or
                self.skip is not None
            ):
                return True
            else:
                return False

    class failureType(api.failureType):

        def exportAttributes(self, outfile, level, already_processed, namespace_='', name_='failureType'):
            if self.message is not None and 'message' not in already_processed:
                already_processed.append('message')
                outfile.write(' message="%s"' % self.message)
            if self.type_ is not None and 'type_' not in already_processed:
                already_processed.append('type_')
                outfile.write(' type="%s"' % self.type_)

    class errorType(api.errorType):

        def exportAttributes(self, outfile, level, already_processed, namespace_='', name_='errorType'):
            if self.message is not None and 'message' not in already_processed:
                already_processed.append('message')
                outfile.write(' message="%s"' % self.message)
            if self.type_ is not None and 'type_' not in already_processed:
                already_processed.append('type_')
                outfile.write(' type="%s"' % self.type_)

    class skipType(api.failureType):
        pass

    class testsuite(api.testsuite):

        def __init__(self, name=None, skips=None):
            api.testsuite.__init__(self, name=name)
            self.skips = api._cast(int, skips)

        def exportAttributes(
                self, outfile, level, already_processed,
                namespace_='', name_='testsuite'):
            api.testsuite.exportAttributes(self,
                                           outfile, level, already_processed,
                                           namespace_, name_)
            if self.skips is not None and 'skips' not in already_processed:
                already_processed.append('skips')
                outfile.write(' skipped="%s"' %
                              self.gds_format_integer(self.skips,
                                                      input_name='skipped'))

    def __init__(self, fail_diff=False):
        self.ts_dict = {}
        self.fail_diff = fail_diff

    def save(self, filename):
        """
        Save current state of report to files.
        """
        testsuites = api.testsuites()
        for ts_name in self.ts_dict:
            ts = self.ts_dict[ts_name]
            testsuites.add_testsuite(ts)
        with open(filename, 'w') as fp:
            testsuites.export(fp, 0)

    def update(self, testname, ts_name, result, log, error_msg, duration):
        """
        Insert a new item into report.
        """
        def escape_str(inStr):
            """
            Escape a string for HTML use.
            """
            s1 = (isinstance(inStr, basestring) and inStr or
                  '%s' % inStr)
            s1 = s1.replace('&', '&amp;')
            s1 = s1.replace('<', '&lt;')
            s1 = s1.replace('>', '&gt;')
            s1 = s1.replace('"', "&quot;")
            return s1

        if not ts_name in self.ts_dict:
            self.ts_dict[ts_name] = self.testsuite(name=ts_name)
            ts = self.ts_dict[ts_name]
            ts.failures = 0
            ts.skips = 0
            ts.tests = 0
            ts.errors = 0
        else:
            ts = self.ts_dict[ts_name]

        tc = self.testcaseType()
        tc.name = testname
        tc.time = duration

        # Filter non-printable characters in log
        log = ''.join(s for s in unicode(log, errors='ignore')
                      if s in string.printable)
        tc.system_out = log

        error_msg = [escape_str(l) for l in error_msg]

        if 'FAIL' in result:
            error_msg.insert(0, 'Test %s has failed' % testname)
            tc.failure = self.failureType(
                message='&#10;'.join(error_msg),
                type_='Failure')
            ts.failures += 1
        elif 'TIMEOUT' in result:
            error_msg.insert(0, 'Test %s has timed out' % testname)
            tc.failure = self.failureType(
                message='&#10;'.join(error_msg),
                type_='Timeout')
            ts.failures += 1
        elif 'ERROR' in result or 'INVALID' in result:
            error_msg.insert(0, 'Test %s has encountered error' % testname)
            tc.error = self.errorType(
                message='&#10;'.join(error_msg),
                type_='Error')
            ts.errors += 1
        elif 'SKIP' in result:
            error_msg.insert(0, 'Test %s is skipped' % testname)
            tc.skip = self.skipType(
                message='&#10;'.join(error_msg),
                type_='Skip')
            ts.skips += 1
        elif 'DIFF' in result and self.fail_diff:
            error_msg.insert(0, 'Test %s results dirty environment' % testname)
            tc.failure = self.failureType(
                message='&#10;'.join(error_msg),
                type_='DIFF')
            ts.failures += 1
        ts.add_testcase(tc)
        ts.tests += 1
        ts.timestamp = date.isoformat(date.today())


class State():
    permit_keys = []
    permit_re = []

    def get_names(self):
        raise NotImplementedError('Function get_names not implemented for %s.'
                                  % self.__class__.__name__)

    def get_info(self, name):
        raise NotImplementedError('Function get_info not implemented for %s.'
                                  % self.__class__.__name__)

    def remove(self, name):
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
            for item in new_items:
                diff_msg.append(item)
                if recover:
                    try:
                        self.remove(self.current_state[item])
                    except Exception, e:
                        traceback.print_exc()
                        diff_msg.append('Remove is failed:\n %s' % e)

        if del_items:
            diff_msg.append('Deleted %s(s):' % self.name)
            for item in del_items:
                diff_msg.append(item)
                if recover:
                    try:
                        self.restore(self.backup_state[item])
                    except Exception, e:
                        traceback.print_exc()
                        diff_msg.append('Recover is failed:\n %s' % e)

        for item in unchanged_items:
            cur = self.current_state[item]
            bak = self.backup_state[item]
            item_changed = False
            new_keys, del_keys, unchanged_keys = diff_dict(bak, cur)
            if new_keys:
                item_changed = True
                diff_msg.append('Created key(s) in %s %s:' % (self.name, item))
                for key in new_keys:
                    diff_msg.append(key)
            if del_keys:
                item_changed = True
                diff_msg.append('Deleted key(s) in %s %s:' % (self.name, item))
                for key in del_keys:
                    diff_msg.append(key)
            for key in unchanged_keys:
                if type(cur[key]) is str:
                    if key not in self.permit_keys and cur[key] != bak[key]:
                        item_changed = True
                        diff_msg.append('%s %s: %s changed: %s -> %s' % (
                            self.name, item, key, bak[key], cur[key]))
                elif type(cur[key]) is list:
                    diff = difflib.unified_diff(
                        bak[key], cur[key], lineterm="")
                    tmp_msg = []
                    for line in diff:
                        tmp_msg.append(line)
                    if tmp_msg and not lines_permitable(tmp_msg,
                                                        self.permit_re):
                        item_changed = True
                        diff_msg.append('%s %s: "%s" changed:' %
                                        (self.name, item, key))
                        diff_msg += tmp_msg
                else:
                    diff_msg.append('%s %s: %s: Invalid type %s.' % (
                        self.name, item, key, type(cur[key])))
            if item_changed and recover:
                try:
                    self.restore(self.backup_state[item])
                except Exception, e:
                    traceback.print_exc()
                    diff_msg.append('Recover is failed:\n %s' % e)
        return diff_msg


class DomainState(State):
    name = 'domain'
    permit_keys = ['id', 'cpu time', 'security label']

    def remove(self, name):
        dom = name
        if dom['state'] != 'shut off':
            res = virsh.destroy(dom['name'])
            if res.exit_status:
                raise Exception(str(res))
        if dom['persistent'] == 'yes':
            # Make sure the domain is remove anyway
            res = virsh.undefine(
                dom['name'], options='--snapshots-metadata --managed-save')
            if res.exit_status:
                raise Exception(str(res))

    def restore(self, name):
        dom = name
        name = dom['name']
        doms = self.current_state
        if name in doms:
            self.remove(doms[name])

        domfile = tempfile.NamedTemporaryFile(delete=False)
        fname = domfile.name
        domfile.writelines(dom['inactive xml'])
        domfile.close()

        try:
            if dom['persistent'] == 'yes':
                res = virsh.define(fname)
                if res.exit_status:
                    raise Exception(str(res))
                if dom['state'] != 'shut off':
                    res = virsh.start(name)
                    if res.exit_status:
                        raise Exception(str(res))
            else:
                res = virsh.create(fname)
                if res.exit_status:
                    raise Exception(str(res))
        finally:
            os.remove(fname)

        if dom['autostart'] == 'enable':
            res = virsh.autostart(name, '')
            if res.exit_status:
                raise Exception(str(res))

    def get_info(self, name):
        infos = {}
        for line in virsh.dominfo(name).stdout.strip().splitlines():
            key, value = line.split(':', 1)
            infos[key.lower()] = value.strip()
        infos['inactive xml'] = virsh.dumpxml(
            name, extra='--inactive').stdout.splitlines()
        return infos

    def get_names(self):
        return virsh.dom_list(options='--all --name').stdout.splitlines()


class NetworkState(State):
    name = 'network'

    def remove(self, name):
        """
        Remove target network _net_.

        :param net: Target net to be removed.
        """
        net = name
        if net['active'] == 'yes':
            res = virsh.net_destroy(net['name'])
            if res.exit_status:
                raise Exception(str(res))
        if net['persistent'] == 'yes':
            res = virsh.net_undefine(net['name'])
            if res.exit_status:
                raise Exception(str(res))

    def restore(self, name):
        """
        Restore networks from _net_.

        :param net: Target net to be restored.
        :raise CalledProcessError: when restore failed.
        """
        net = name
        name = net['name']
        nets = self.current_state
        if name in nets:
            self.remove(nets[name])

        netfile = tempfile.NamedTemporaryFile(delete=False)
        fname = netfile.name
        netfile.writelines(net['inactive xml'])
        netfile.close()

        try:
            if net['persistent'] == 'yes':
                res = virsh.net_define(fname)
                if res.exit_status:
                    raise Exception(str(res))
                if net['active'] == 'yes':
                    res = virsh.net_start(name)
                    if res.exit_status:
                        res = virsh.net_start(name)
                        if res.exit_status:
                            raise Exception(str(res))
            else:
                res = virsh.net_create(fname)
                if res.exit_status:
                    raise Exception(str(res))
        finally:
            os.remove(fname)

        if net['autostart'] == 'yes':
            res = virsh.net_autostart(name)
            if res.exit_status:
                raise Exception(str(res))

    def get_info(self, name):
        infos = {}
        for line in virsh.net_info(name).stdout.strip().splitlines():
            if line.startswith('Name') or line.startswith('UUID'):
                key, value = line.split()
            else:
                key, value = line.split(':', 1)
            infos[key.lower()] = value.strip()
        infos['inactive xml'] = virsh.net_dumpxml(
            name, '--inactive').stdout.splitlines()
        return infos

    def get_names(self):
        lines = virsh.net_list('--all').stdout.strip().splitlines()[2:]
        return [line.split()[0] for line in lines]


class PoolState(State):
    name = 'pool'
    permit_keys = ['available', 'allocation']
    permit_re = [r'^[-+]\s*\<(capacity|allocation|available).*$']

    def remove(self, name):
        """
        Remove target pool _pool_.

        :param pool: Target pool to be removed.
        """
        pool = name
        if pool['state'] == 'running':
            res = virsh.pool_destroy(pool['name'])
            if not res:
                raise Exception(str(res))
        if pool['persistent'] == 'yes':
            res = virsh.pool_undefine(pool['name'])
            if res.exit_status:
                raise Exception(str(res))

    def restore(self, name):
        pool = name
        name = pool['name']
        pools = self.current_state
        if name in pools:
            self.remove(pools[name])

        pool_file = tempfile.NamedTemporaryFile(delete=False)
        fname = pool_file.name
        pool_file.writelines(pool['inactive xml'])
        pool_file.close()

        try:
            if pool['persistent'] == 'yes':
                res = virsh.pool_define(fname)
                if res.exit_status:
                    raise Exception(str(res))
                if pool['state'] == 'running':
                    res = virsh.pool_start(name)
                    if res.exit_status:
                        raise Exception(str(res))
            else:
                res = virsh.pool_create(fname)
                if res.exit_status:
                    raise Exception(str(res))
        except Exception, e:
            raise e
        finally:
            os.remove(fname)

        if pool['autostart'] == 'yes':
            res = virsh.pool_autostart(name)
            if res.exit_status:
                raise Exception(str(res))

    def get_info(self, name):
        infos = {}
        for line in virsh.pool_info(name).stdout.strip().splitlines():
            key, value = line.split(':', 1)
            infos[key.lower()] = value.strip()
        infos['inactive xml'] = virsh.pool_dumpxml(
            name, '--inactive').splitlines()
        infos['volumes'] = virsh.vol_list(name).stdout.strip().splitlines()[2:]
        return infos

    def get_names(self):
        lines = virsh.pool_list('--all').stdout.strip().splitlines()[2:]
        return [line.split()[0] for line in lines]


class SecretState(State):
    name = 'secret'
    permit_keys = []
    permit_re = []

    def remove(self, name):
        secret = name
        res = virsh.secret_undefine(secret['uuid'])
        if res.exit_status:
            raise Exception(str(res))

    def restore(self, name):
        uuid = name
        cur = self.current_state
        bak = self.backup_state

        if uuid in cur:
            self.remove(name)

        secret_file = tempfile.NamedTemporaryFile(delete=False)
        fname = secret_file.name
        secret_file.writelines(bak[name]['xml'])
        secret_file.close()

        try:
            res = virsh.secret_define(fname)
            if res.exit_status:
                raise Exception(str(res))
        except Exception, e:
            raise e
        finally:
            os.remove(fname)

    def get_info(self, name):
        infos = {}
        infos['uuid'] = name
        infos['xml'] = virsh.secret_dumpxml(name).stdout.splitlines()
        return infos

    def get_names(self):
        lines = virsh.secret_list().stdout.strip().splitlines()[2:]
        return [line.split()[0] for line in lines]


class MountState(State):
    name = 'mount'
    permit_keys = []
    permit_re = []
    info = {}

    def remove(self, name):
        info = name
        # ugly workaround for nfs which unable to umount
        #os.system('systemctl restart nfs')
        if not umount(info['src'], info['mount_point'], info['fstype'],
                      verbose=False):
            raise Exception("Failed to unmount %s" % info['mount_point'])

    def restore(self, name):
        info = name
        if not mount(info['src'], info['mount_point'], info['fstype'],
                     info['options'], verbose=False):
            raise Exception("Failed to mount %s" % info['mount_point'])

    def get_info(self, name):
        return self.info[name]

    def get_names(self):
        """
        Get all mount infomations from /etc/mtab.

        :return: A dict using mount point as keys and 6-element dict as value.
        """
        lines = file('/etc/mtab').read().splitlines()
        names = []
        for line in lines:
            values = line.split()
            if len(values) != 6:
                print 'Warning: Error parsing mountpoint: %s' % line
                continue
            keys = ['src', 'mount_point', 'fstype', 'options', 'dump', 'order']
            mount_entry = dict(zip(keys, values))
            mount_point = mount_entry['mount_point']
            names.append(mount_point)
            self.info[mount_point] = mount_entry
        return names


class ServiceState(State):
    name = 'service'
    libvirtd = utils_libvirtd.Libvirtd()
    permit_keys = []
    permit_re = []

    def remove(self, name):
        raise Exception('It is meaningless to remove service %s' % name)

    def restore(self, name):
        info = name
        if info['name'] == 'libvirtd':
            if info['status'] == 'running':
                if not self.libvirtd.start():
                    raise Exception('Failed to start libvirtd')
            elif info['status'] == 'stopped':
                if not self.libvirtd.stop():
                    raise Exception('Failed to stop libvirtd')
            else:
                raise Exception('Unknown libvirtd status %s' % info['status'])
        elif info['name'] == 'selinux':
            utils_selinux.set_status(info['status'])
        else:
            raise Exception('Unknown service %s' % info['name'])

    def get_info(self, name):
        if name == 'libvirtd':
            if self.libvirtd.is_running():
                status = 'running'
            else:
                status = 'stopped'
        if name == 'selinux':
            status = utils_selinux.get_status()
        return {'name': name, 'status': status}

    def get_names(self):
        return ['libvirtd', 'selinux']


class DirState(State):
    name = 'directory'
    permit_keys = []
    permit_re = []

    def remove(self, name):
        raise Exception('It is not wise to remove a dir %s' % name)

    def restore(self, name):
        dirname = name['dir-name']
        cur = self.current_state[dirname]
        bak = self.backup_state[dirname]
        created_files = set(cur) - set(bak)
        if created_files:
            for fname in created_files:
                fpath = os.path.join(name['dir-name'], fname)
                if os.path.isfile(fpath):
                    os.remove(fpath)
                elif os.path.isdir(fpath):
                    shutil.rmtree(fpath)
        deleted_files = set(bak) - set(cur)
        if deleted_files:
            for fname in deleted_files:
                fpath = os.path.join(name['dir-name'], fname)
                open(fpath, 'a').close()
        # TODO: record file/dir info and recover them separately

    def get_info(self, name):
        infos = {}
        infos['dir-name'] = name
        for f in os.listdir(name):
            infos[f] = f
        return infos

    def get_names(self):
        return ['/tmp',
                data_dir.get_tmp_dir(),
                data_dir.get_root_dir(),
                os.path.join(data_dir.get_root_dir(), 'shared'),
                os.path.join(data_dir.get_data_dir(), 'images'),
                '/var/lib/libvirt/images']


class FileState(State):
    name = 'file'
    permit_keys = []
    permit_re = []

    def remove(self, name):
        raise Exception('It is not wise to remove a system file %s' % name)

    def restore(self, name):
        file_path = name['file-path']
        cur = self.current_state[file_path]
        bak = self.backup_state[file_path]
        if cur['content'] != bak['content']:
            with open(file_path, 'w') as f:
                f.write(bak['content'])

    def get_info(self, name):
        infos = {}
        infos['file-path'] = name
        with open(name) as f:
            infos['content'] = f.read()
        return infos

    def get_names(self):
        return ['/etc/exports',
                '/etc/libvirt/libvirtd.conf',
                '/etc/libvirt/qemu.conf']


class LibvirtCI():

    def parse_args(self):
        parser = optparse.OptionParser(
            description='Continuouse integration of '
            'virt-test libvirt test provider.')
        parser.add_option('--no', dest='no', action='store', default='',
                          help='Exclude specified tests.')
        parser.add_option('--only', dest='only', action='store', default='',
                          help='Run only for specified tests.')
        parser.add_option('--check', dest='check', action='store',
                          default='',
                          help='Check specified changes.')
        parser.add_option('--smoke', dest='smoke', action='store_true',
                          help='Run one test for each script.')
        parser.add_option('--report', dest='report', action='store',
                          default='xunit_result.xml',
                          help='Exclude specified tests.')
        parser.add_option('--white', dest='whitelist', action='store',
                          default='', help='Whitelist file contains '
                          'specified test cases to run.')
        parser.add_option('--black', dest='blacklist', action='store',
                          default='', help='Blacklist file contains '
                          'specified test cases to be excluded.')
        parser.add_option('--img-url', dest='img_url', action='store',
                          default='', help='Specify a URL to a custom image '
                          'file')
        parser.add_option('--password', dest='password', action='store',
                          default='', help='Specify a password for logging '
                          'into guest')
        parser.add_option('--pull-virt-test', dest='virt_test_pull',
                          action='store', default='',
                          help='Merge specified virt-test pull requests')
        parser.add_option('--pull-libvirt', dest='libvirt_pull',
                          action='store', default='',
                          help='Merge specified tp-libvirt pull requests')
        parser.add_option('--with-dependence', dest='with_dependence',
                          action='store_true',
                          help='Merge virt-test pull requests depend on')
        parser.add_option('--no-restore-pull', dest='no_restore_pull',
                          action='store_true', help='Do not restore repo '
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
        self.args, self.real_args = parser.parse_args()

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
            cmd = './run -t libvirt --list-tests'
            if self.nos:
                cmd += ' --no %s' % ','.join(self.nos)
            res = utils.run(cmd)
            out, err, exitcode = res.stdout, res.stderr, res.exit_status
            tests = []
            module_names = set()
            for line in out.splitlines():
                if line:
                    if line[0].isdigit():
                        test = re.sub(r'^[0-9]+ (.*) \(requires root\)$',
                                      r'\1', line)
                        if self.args.smoke:
                            name = self.get_module_name(test)
                            if name in module_names:
                                continue
                            else:
                                module_names.add(name)
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

        if self.onlys is not None:
            filtered_tests = []
            for item in self.onlys:
                filtered_tests += [t for t in tests if item in t]
            tests = filtered_tests

        if self.args.blacklist:
            black_tests = read_tests_from_file(blacklist)
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

        def replace_pattern_in_file(file, search_exp, replace_exp):
            prog = re.compile(search_exp)
            for line in fileinput.input(file, inplace=1):
                match = prog.search(line)
                if match:
                    line = prog.sub(replace_exp, line)
                sys.stdout.write(line)

        print 'Running bootstrap'
        sys.stdout.flush()
        self.bootstrap()
        restore_image = True

        if self.args.img_url:
            def progress_callback(count, block_size, total_size):
                percent = count * block_size * 100 / total_size
                sys.stdout.write("\rDownloaded %2.2f%%" % percent)
                sys.stdout.flush()
            print 'Downloading image from %s.' % self.args.img_url
            img_dir = os.path.join(
                data_dir.get_data_dir(), 'images/jeos-19-64.qcow2'),
            urllib.urlretrieve(self.args.img_url, img_dir[0], progress_callback)
            restore_image = False
            print '\nDownload completed.'

        if self.args.password:
            replace_pattern_in_file(
                "shared/cfg/guest-os/Linux.cfg",
                r'password = \S*',
                r'password = %s' % self.args.password)

        if self.args.retain_vm:
            return

        print 'Removing VM',  # TODO: use virt-test api remove VM
        sys.stdout.flush()
        status, res, err_msg = self.run_test(
            'remove_guest.without_disk', need_check=False)
        if not 'PASS' in status:
            virsh.undefine('virt-tests-vm1', '--snapshots-metadata')
            print '   WARNING: Failed to remove guest'

        print 'Installing VM',
        sys.stdout.flush()
        status, res, err_msg = self.run_test(
            'unattended_install.import.import.default_install.aio_native',
            restore_image=restore_image, need_check=False)
        if not 'PASS' in status:
            raise Exception('   ERROR: Failed to install guest \n %s' %
                            res.stderr)
        virsh.destroy('virt-tests-vm1')

    def run_test(self, test, restore_image=False, need_check=True):
        """
        Run a specific test.
        """
        img_str = '' if restore_image else 'k'
        down_str = '' if restore_image else '--no-downloads'
        cmd = './run -v%st libvirt --keep-image-between-tests %s --tests %s' % (
            img_str, down_str, test)
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

        os.chdir(data_dir.get_root_dir())  # Check PWD

        err_msg = []

        if need_check:
            diff = False
            for state in self.states:
                diffmsg = state.check(recover=True)
                if diffmsg:
                    if not diff:
                        diff = True
                        status += ' DIFF'
                    for line in diffmsg:
                        err_msg.append('   DIFF|%s' % line)

        print 'Result: %s %.2f s' % (status, res.duration)

        if 'FAIL' in status or 'ERROR' in status:
            for line in res.stderr.splitlines():
                if 'ERROR' in line:
                    err_msg.append('  %s' % line[9:])
        if status == 'INVALID' or status == 'TIMEOUT':
            for line in res.stdout.splitlines():
                err_msg.append(line)
        if err_msg:
            for line in err_msg:
                print line
        sys.stdout.flush()
        return status, res, err_msg

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
                patch_url = ('https://github.com/autotest'
                             '/%s/pull/%s.patch' % (repo_name, pull_no))
                patch_file = "/tmp/%s.patch" % pull_no
                urllib.urlretrieve(patch_url, patch_file)
                with open(patch_file, 'r') as pf:
                    if not pf.read().strip():
                        print 'WARING: empty content for PR #%s' % pull_no
                try:
                    print 'Patching %s PR #%s' % (repo_name, pull_no)
                    cmd = 'git am -3 %s' % patch_file
                    res = utils.run(cmd)
                except error.CmdError, e:
                    print e
                    raise Exception('Failed applying patch %s' % pull_no)
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
            pattern2 = (r'https?://github.com/autotest/virt-test/(?:pull|issues)/([0-9]*)')
            res = set()
            match = re.findall(pattern1, line)
            res |= set(match)
            match = re.findall(pattern2, line)
            res |= set(match)
            return res

        def libvirt_pr_dep(pr_numbers):
            oauth = ('?client_id=b6578298435c3eaa1e3d&client_secret'
                     '=59a1c828c6002ed4e8a9205486cf3fa86467a609')
            dep = set()
            for pr_number in pr_numbers:
                # Monitor PR's first comment
                issue_url = 'https://api.github.com/repos/autotest/tp-libvirt/issues/241' % pr_number
                issue_u = urllib2.urlopen(issue_url + oauth)
                issue = json.load(issue_u)
                for line in issue['body'].splitlines():
                    dep |= search_dep(line)

                comments_url = ('https://api.github.com/repos/autotest/tp-libvirt/issues/%s/comments' % pr_number)
                comments_u = urllib2.urlopen(comments_url + oauth)
                comments = json.load(comments_u)
                for comment in comments:
                    for line in comment['body'].splitlines():
                        dep |= search_dep(line)
            return dep

        self.virt_branch_name, self.libvirt_branch_name = None, None

        libvirt_pulls = set()
        virt_test_pulls = set()

        if self.args.libvirt_pull:
            libvirt_pulls = set(self.args.libvirt_pull.split(','))

        if self.args.with_dependence:
            virt_test_pulls = libvirt_pr_dep(libvirt_pulls)

        if self.args.virt_test_pull:
            virt_test_pulls |= self.args.virt_test_pull.split(',')

        if virt_test_pulls:
            os.chdir(data_dir.get_root_dir())
            self.virt_branch_name = merge_pulls("virt-test", virt_test_pulls)
            if self.args.only_change:
                self.virt_file_changed = file_changed("virt-test")

        if libvirt_pulls:
            os.chdir(data_dir.get_test_provider_dir(
                'io-github-autotest-libvirt'))
            self.libvirt_branch_name = merge_pulls("tp-libvirt", libvirt_pulls)
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

    def run(self):
        """
        Run continuous integrate for virt-test test cases.
        """
        self.parse_args()
        report = Report(self.args.fail_diff)
        try:
            self.prepare_repos()
            if self.args.pre_cmd:
                print 'Running command line "%s" before test.' % self.args.pre_cmd
                res = utils.run(self.args.pre_cmd, ignore_status=True)
                print 'Result:'
                for line in str(res).splitlines():
                    print line
            # service must put at first, or the result will be wrong.
            self.states = [ServiceState(), FileState(), DirState(),
                           DomainState(), NetworkState(), PoolState(),
                           SecretState(), MountState()]
            tests = self.prepare_tests()
            self.prepare_env()
            for state in self.states:
                state.backup()

            for idx, test in enumerate(tests):
                short_name = test.split('.', 2)[2]
                print '%s (%d/%d) %s ' % (time.strftime('%X'), idx + 1,
                                          len(tests), short_name),
                sys.stdout.flush()

                status, res, err_msg = self.run_test(test)

                module_name = self.get_module_name(test)
                report.update(test, module_name, status,
                              res.stderr, err_msg, res.duration)
                report.save(self.args.report)
            if self.args.post_cmd:
                print 'Running command line "%s" after test.' % self.args.post_cmd
                res = utils.run(self.args.post_cmd, ignore_status=True)
                print 'Result:'
                for line in str(res).splitlines():
                    print line
        except Exception:
            traceback.print_exc()
        finally:
            if not self.args.no_restore_pull:
                self.restore_repos()
            report.save(self.args.report)


def state_test():
    states = [ServiceState(), FileState(), DirState(), DomainState(),
              NetworkState(), PoolState(), SecretState(), MountState()]
    for state in states:
        state.backup()
    utils.run('echo hello > /etc/exports')
    virsh.start('virt-tests-vm1')
    virsh.net_autostart('default', '--disable')
    virsh.pool_destroy('mount')
    utils.run('rm /var/lib/virt_test/images/hello')
    utils.run('mkdir /var/lib/virt_test/images/hi')
    utils_libvirtd.Libvirtd().stop()
    utils_selinux.set_status('permissive')
    for state in states:
        lines = state.check(recover=True)
        for line in lines:
            print line


if __name__ == '__main__':
#    state_test()
    ci = LibvirtCI()
    ci.run()

# vi:set ts=4 sw=4 expandtab:
