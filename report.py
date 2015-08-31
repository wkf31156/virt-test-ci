import re
import string
from autotest.client.tools import JUnit_api as api
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
            if (self.system_out is not None or
                    self.system_err is not None or
                    self.error is not None or
                    self.failure is not None or
                    self.skip is not None):
                return True
            else:
                return False

    class failureType(api.failureType):

        def exportAttributes(self, outfile, level, already_processed,
                             namespace_='', name_='failureType'):
            if self.message is not None and 'message' not in already_processed:
                already_processed.append('message')
                outfile.write(' message="%s"' % self.message)
            if self.type_ is not None and 'type_' not in already_processed:
                already_processed.append('type_')
                outfile.write(' type="%s"' % self.type_)

    class errorType(api.errorType):

        def exportAttributes(self, outfile, level, already_processed,
                             namespace_='', name_='errorType'):
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
        self.result_counter = {}
        self.fail_reason_counter = {}
        self.error_reason_counter = {}
        self.timeout_reason_counter = {}
        self.skip_reason_counter = {}

    def save(self, filename, report_file):
        """
        Save current state of report to files.
        """
        testsuites = api.testsuites()
        for ts_name in self.ts_dict:
            ts = self.ts_dict[ts_name]
            testsuites.add_testsuite(ts)
        with open(filename, 'w') as fp:
            testsuites.export(fp, 0)

        with open(report_file, 'w') as fp:
            for result, cases in self.result_counter.items():
                fp.write("* %3s cases %s\n" % (len(cases), result))
                if result == 'FAIL':
                    for reason, cases in self.fail_reason_counter.items():
                        if reason is None:
                            reason = "unknown reason"
                        fp.write("\t- %3s caused by %s\n" %
                                 (len(cases), reason))
                        for case in cases:
                            fp.write("\t\t%s\n" % case)
                if result == 'ERROR':
                    for reason, cases in self.error_reason_counter.items():
                        if reason is None:
                            reason = "unknown reason"
                        fp.write("\t- %3s caused by %s\n" %
                                 (len(cases), reason))
                        for case in cases:
                            fp.write("\t\t%s\n" % case)
                if result == 'TIMEOUT':
                    for reason, cases in self.timeout_reason_counter.items():
                        if reason is None:
                            reason = "unknown reason"
                        fp.write("\t- %3s caused by %s\n" %
                                 (len(cases), reason))
                        for case in cases:
                            fp.write("\t\t%s\n" % case)
                if result == 'SKIP':
                    for reason, cases in self.skip_reason_counter.items():
                        if reason is None:
                            reason = "unknown reason"
                        fp.write("\t- %3s caused by %s\n" %
                                 (len(cases), reason))
                        for case in cases:
                            fp.write("\t\t%s\n" % case)

    def update(self, testname, ts_name, result, reason, log, error_msg,
               duration):
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

        if ts_name not in self.ts_dict:
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
        if reason:
            tc.name += " " + reason
        tc.time = duration

        if result in self.result_counter:
            self.result_counter[result].append(testname)
        else:
            self.result_counter[result] = [testname]

        if result == 'FAIL':
            if reason in self.fail_reason_counter:
                self.fail_reason_counter[reason].append(testname)
            else:
                self.fail_reason_counter[reason] = [testname]
        elif result == 'ERROR':
            if reason in self.error_reason_counter:
                self.error_reason_counter[reason].append(testname)
            else:
                self.error_reason_counter[reason] = [testname]
        elif result == 'TIMEOUT':
            if reason in self.timeout_reason_counter:
                self.timeout_reason_counter[reason].append(testname)
            else:
                self.timeout_reason_counter[reason] = [testname]
        elif result == 'SKIP':
            if reason in self.skip_reason_counter:
                self.skip_reason_counter[reason].append(testname)
            else:
                self.skip_reason_counter[reason] = [testname]

        # Filter non-printable characters in log
        log = ''.join(s for s in unicode(log, errors='ignore')
                      if s in string.printable)
        tc.system_out = log

        tmp_msg = []

        for line in error_msg:
            # Filter non-printable characters in error message
            line = ''.join(s for s in unicode(line, errors='ignore')
                           if s in string.printable)
            tmp_msg.append(escape_str(line))
        error_msg = tmp_msg

        result_msg = ''
        for line in log:
            res = re.findall(
                r'^[:0-9]+ (ERROR|INFO )\| (FAIL|ERROR|PASS|SKIP|WARN)'
                ' \S+\s+(.*)$',
                line)
            if res:
                result_msg = res[2]
                result_msg = ''.join(
                    s for s in unicode(result_msg, errors='ignore')
                    if s in string.printable)
                if result_msg.startswith('-> '):
                    result_msg = result_msg[3]

        if 'FAIL' in result:
            error_msg.insert(0, 'Test %s has failed' % testname)
            tc.failure = self.failureType(
                message=result_msg,
                type_='Failure')
            ts.failures += 1
        elif 'TIMEOUT' in result:
            error_msg.insert(0, 'Test %s has timed out' % testname)
            tc.failure = self.failureType(
                message=result_msg,
                type_='Timeout')
            ts.failures += 1
        elif 'ERROR' in result or 'INVALID' in result:
            error_msg.insert(0, 'Test %s has encountered error' % testname)
            tc.failure = self.failureType(
                message=result_msg,
                type_='Error')
            ts.errors += 1
        elif 'SKIP' in result:
            error_msg.insert(0, 'Test %s is skipped' % testname)
            tc.skip = self.failureType(
                message=result_msg,
                type_='Skip')
            ts.skips += 1
        elif 'DIFF' in result and self.fail_diff:
            error_msg.insert(0, 'Test %s results dirty environment' % testname)
            tc.failure = self.failureType(
                message=result_msg,
                type_='DIFF')
            ts.failures += 1
        ts.add_testcase(tc)
        ts.tests += 1
        ts.timestamp = date.isoformat(date.today())
