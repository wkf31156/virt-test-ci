import re
import os
import logging
import difflib
import tempfile
import traceback
import shutil
from virttest import virsh
from virttest import data_dir
from virttest import utils_selinux
from virttest import utils_libvirtd
from virttest.utils_misc import mount, umount


class States():

    def __init__(self):
        self.states = []
        for name, obj in globals().items():
            if name != "State" and name.endswith("State"):
                # Service mush be put at first, or the result will be wrong.
                if name == "ServiceState":
                    self.states.insert(0, obj())
                else:
                    self.states.append(obj())

    def backup(self):
        for state in self.states:
            state.backup()

    def check(self, recover=True):
        msg = []
        for state in self.states:
            msg += state.check(recover=recover)
        return msg


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
                for key in del_keys:
                    if type(key) is str:
                        if key not in self.permit_keys:
                            item_changed = True
                            diff_msg.append('Deleted key(s) in %s %s:' %
                                            (self.name, item))
                    else:
                        item_changed = True
                        diff_msg.append('Deleted key(s) in %s %s:' %
                                        (self.name, item))
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
            key, value = line.split()
            if key.endswith(':'):
                key = key[:-1]
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
                logging.warning('Error parsing mountpoint: %s', line)
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
    permit_keys = ['aexpect']
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
                    if os.path.ismount(fpath):
                        os.system('umount -l %s' % fpath)
                    else:
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
