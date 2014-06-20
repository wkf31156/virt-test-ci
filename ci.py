#!/usr/bin/env python
import re
import os
import sys
import time
import uuid
import shutil
import string
import difflib
import argparse
import tempfile
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

    class testcaseType(api.testcaseType):

        def __init__(self, classname=None, name=None, time=None, error=None,
                     failure=None, skip=None):
            api.testcaseType.__init__(self, classname, name, time, error,
                                      failure)
            self.skip = skip

        def exportChildren(self, outfile, level, namespace_='',
                           name_='testcaseType', fromsubclass_=False):
            api.testcaseType.exportChildren(
                self, outfile, level, namespace_, name_, fromsubclass_)
            if self.skip is not None:
                self.skip.export(outfile, level, namespace_, name_='skipped')

        def hasContent_(self):
            if (
                self.error is not None or
                self.failure is not None or
                self.skip is not None
            ):
                return True
            else:
                return False

    class failureType(api.failureType):
        pass

    class errorType(api.errorType):
        pass

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

    def __init__(self):
        self.ts_dict = {}

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

    def update(self, testname, ts_name, result, log, duration):
        """
        Insert a new item into report.
        """

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

        if 'FAIL' in result:
            tc.failure = self.failureType(
                message='Test %s has failed' % testname,
                type_='Failure',
                valueOf_="\n<![CDATA[\n%s\n]]>\n" % log)
            ts.failures += 1
        if 'TIMEOUT' in result:
            tc.failure = self.failureType(
                message='Test %s has timed out' % testname,
                type_='Timeout',
                valueOf_="\n<![CDATA[\n%s\n]]>\n" % log)
            ts.failures += 1
        elif 'ERROR' in result or 'INVALID' in result:
            tc.error = self.errorType(
                message='Test %s has encountered error' % testname,
                type_='Error',
                valueOf_="\n<![CDATA[\n%s\n]]>\n" % log)
            ts.errors += 1
        elif 'SKIP' in result:
            tc.skip = self.skipType(
                message='Test %s has skipped' % testname,
                type_='Skip',
                valueOf_="\n<![CDATA[\n%s\n]]>\n" % log)
            ts.skips += 1
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
        return ['/etc/exports']


class LibvirtCI():

    def parse_args(self):
        parser = argparse.ArgumentParser(
            description='Continuouse integration of '
            'virt-test libvirt test provider.')
        parser.add_argument('--no', dest='no', action='store', default='',
                            help='Exclude specified tests.')
        parser.add_argument('--only', dest='only', action='store', default='',
                            help='Run only for specified tests.')
        parser.add_argument('--check', dest='check', action='store',
                            default='',
                            help='Check specified changes.')
        parser.add_argument('--smoke', dest='smoke', action='store_true',
                            help='Run one test for each script.')
        parser.add_argument('--report', dest='report', action='store',
                            default='xunit_result.xml',
                            help='Exclude specified tests.')
        parser.add_argument('--white', dest='whitelist', action='store',
                            default='', help='Whitelist file contains '
                            'specified test cases to run.')
        parser.add_argument('--black', dest='blacklist', action='store',
                            default='', help='Blacklist file contains '
                            'specified test cases to be excluded.')
        parser.add_argument('--pull-virt-test', dest='virt_test_pull',
                            action='store', default='',
                            help='Merge specified virt-test pull requests')
        parser.add_argument('--pull-libvirt', dest='libvirt_pull',
                            action='store', default='',
                            help='Merge specified tp-libvirt pull requests')
        parser.add_argument('--change', dest='change', action='store',
                            default='', help='A file contains changed files '
                            'in tp-libvirt repo. the file can be get from '
                            '"git diff --name-only > $FILENAME"')
        self.args = parser.parse_args()

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

        def change_to_only(change_file):
            """
            Transform the content of a change file to a only set.
            """
            onlys = set()
            with open(change_file) as fin:
                for line in fin:
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
        if self.args.change:
            if self.onlys is not None:
                self.onlys &= change_to_only(self.args.change)
            else:
                self.onlys = change_to_only(self.args.change)

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
        print 'Running bootstrap'
        self.bootstrap()

        print 'Removing VM',  # TODO: use virt-test api remove VM
        sys.stdout.flush()
        status, res = self.run_test(
            'remove_guest.without_disk', need_check=False)
        if not 'PASS' in status:
            virsh.undefine('virt-tests-vm1', '--snapshots-metadata')
            print '   WARNING: Failed to remove guest'

        print 'Installing VM',
        sys.stdout.flush()
        status, res = self.run_test(
            'unattended_install.import.import.default_install.aio_native',
            restore_image=True, need_check=False)
        if not 'PASS' in status:
            raise Exception('   ERROR: Failed to install guest \n %s' %
                            res.stderr)
        virsh.destroy('virt-tests-vm1')

    def run_test(self, test, restore_image=False, need_check=True):
        """
        Run a specific test.
        """
        img_str = '' if restore_image else 'k'
        cmd = './run -v%st libvirt --keep-image-between-tests --tests %s' % (
            img_str, test)
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

        out = ''

        if need_check:
            diff = False
            for state in self.states:
                diffmsg = state.check(recover=True)
                if diffmsg:
                    if not diff:
                        diff = True
                        status += ' DIFF'
                    for line in diffmsg:
                        out += '   DIFF|%s\n' % line

        print 'Result: %s %.2f s' % (status, res.duration)

        if 'FAIL' in status or 'ERROR' in status:
            for line in res.stderr.splitlines():
                if 'ERROR|' in line:
                    out += '  %s\n' % line[9:]
        if status == 'INVALID' or status == 'TIMEOUT':
            out += res.stdout
        if out:
            print out,
        sys.stdout.flush()
        return status, res

    def prepare_repos(self):
        """
        Prepare repos for the tests.
        """
        def merge_pulls(pull_nos):
            branch_uuid = uuid.uuid4()
            cmd = 'git checkout -b %s' % branch_uuid
            res = utils.run(cmd, ignore_status=True)
            if res.exit_status:
                print res

            for pull_no in pull_nos:
                cmd = 'git pull origin pull/%s/merge' % pull_no
                res = utils.run(cmd, ignore_status=True)
                if res.exit_status:
                    print res
                    print 'Failed when pulling #%s' % pull_no
            return branch_uuid


        self.virt_branch_uuid, self.libvirt_branch_uuid = None, None

        if self.args.virt_test_pull:
            os.chdir(data_dir.get_root_dir())
            self.virt_branch_uuid = merge_pulls(
                    self.args.virt_test_pull.split(','))


        if self.args.libvirt_pull:
            os.chdir(data_dir.get_test_provider_dir(
                'io-github-autotest-libvirt'))
            self.libvirt_branch_uuid = merge_pulls(
                    self.args.libvirt_pull.split(','))

        os.chdir(data_dir.get_root_dir())

    def restore_repos(self):
        """
        Checkout master branch and remove test branch.
        """
        def restore_repo(branch_uuid):
            cmd = 'git checkout master'
            res = utils.run(cmd, ignore_status=True)
            if res.exit_status:
                print res
            cmd = 'git branch -D %s' % branch_uuid
            res = utils.run(cmd, ignore_status=True)
            if res.exit_status:
                print res

        if self.virt_branch_uuid:
            os.chdir(data_dir.get_root_dir())
            restore_repo(self.virt_branch_uuid)

        if self.libvirt_branch_uuid:
            os.chdir(data_dir.get_test_provider_dir(
                'io-github-autotest-libvirt'))
            restore_repo(self.libvirt_branch_uuid)
        os.chdir(data_dir.get_root_dir())

    def run(self):
        """
        Run continuous integrate for virt-test test cases.
        """
        self.parse_args()
        self.prepare_repos()
        report = Report()
        try:
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

                status, res = self.run_test(test)

                module_name = self.get_module_name(test)
                report.update(test, module_name, status,
                              res.stderr, res.duration)
                report.save(self.args.report)
        except Exception:
            traceback.print_exc()
        finally:
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
