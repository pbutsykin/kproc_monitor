#!/usr/bin/python

import sys, os, tempfile

debug = False
def dlog(msg, prefix = "dlog"):
    if debug:
        print(prefix + ": " + msg)

class KProcFrame:
    kproc_mod_name = "kproc_mon.ko"
    kproc_dir_path = "./../kproc_monitor/"
    kproc_mod_path = kproc_dir_path + kproc_mod_name

    @staticmethod
    def _cmd(cmd_line, user = "", exit = True):
        import subprocess

        dlog(cmd_line, "cmd_debug" if user == "" else ("cmd_debug(%s)" % user))
        if user != "":
            cmd_line = "su %s -c '%s' <<< %s" % (user, cmd_line, user)

        p = subprocess.Popen(cmd_line, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, shell=True)
        output, error = p.communicate()
        if error and exit:
            print("Exit due to command error:\n" + error)
            sys.exit(2)
        return output

    @staticmethod
    def _build(proj_path, user = ""):
        return KProcFrame._cmd("pushd %s; make%s" % (proj_path, "" if user != "" else "; popd"), user)

    def __init__(self, kproc_mod, test_user = "ktest_user"):
        self.passed = 0

        if kproc_mod:
            self._build(self.kproc_dir_path)
            self._cmd("insmod %s" % self.kproc_mod_path)
            self.kproc_mod = kproc_mod

        self.test_user = test_user
        self._cmd("useradd %s" % test_user)
        self._cmd("chpasswd <<< %s:%s"% (test_user, test_user))

        self.tmpdir = tempfile.mkdtemp("-ktest")
        self._cmd("chown %s:%s %s" % (test_user, test_user, self.tmpdir))

        dlog("inited")

    class Unit():
        def __init__(self, base, env):
            self.env = env
            self.base = base
            self.tmp_path = "%s/%s/" % (base.tmpdir, os.path.basename(env.path))

            base._cmd("cp -r %s %s/" % (env.path, base.tmpdir))
            base._cmd("chown -R %s:%s %s/" % (base.test_user, base.test_user, base.tmpdir))

            base._build(self.tmp_path, base.test_user)
            if env.module:
                base._cmd("insmod %s" % (self.tmp_path + env.module))

        def run(self, protection = False):
            for binary in self.env.binaries:
                cmd_line = (self.tmp_path + binary) + ' ' + ' '.join(self.env.args)
                out = self.base._cmd(cmd_line, self.base.test_user, False)
                dlog("'%s'" % out)
                print("%-20s %-14s" % (self.env.name, binary)),
                if self.env.verify(out) ^ protection:
                    self.base.passed += 1
                    print("PASS")
                else:
                    print("FAIL")

        def __del__(self):
            dlog("clean %s" % self.env.name)
            if self.env.module:
                self.base._cmd("rmmod %s" % self.env.module, exit = False)

            self.base._cmd("rm -rf %s" % self.tmp_path, self.base.test_user, exit = False)

    def __del__(self):
        dlog("clean: KProcTest")
        if hasattr(self, "kproc_mod"):
            self._cmd("rmmod %s" % self.kproc_mod_name, exit = False)

        if hasattr(self, "tmpdir"):
            self._cmd("rm -r %s/" % self.tmpdir, self.test_user, exit = False)

        if hasattr(self, "test_user"):
            self._cmd("userdel -r %s" % self.test_user, exit = False)

class TestEnv:
    def __init__(self, name, path, binaries, args = ["<<<", "id"],
                 verify = lambda x: x.startswith("uid=0(root)"), module = False):
        self.name = name
        self.path = os.path.normpath("../" + path)
        self.binaries = binaries if isinstance(binaries, list) else [binaries]
        self.args = args
        self.verify = verify
        self.module = module
        self.num = len(self.binaries)

test_list = [
    TestEnv(name = "Test-Vuln-uid",
            path = "/vuln/",
            binaries = ["vpwn", "vpwn_fork", "vpwn_2fork", "vpwn_dnull"],
            module = "vuln.ko"),

    TestEnv(name = "Test-Vuln-faccess",
            path = "/vuln/",
            binaries = "vpwn_fread",
            verify = lambda x: "success" in x,
            module = "vuln.ko"),

    TestEnv(name = "Test-Vuln-modinit",
            path = "/vuln/",
            binaries = "vpwn_kmod", args = [],
            verify = lambda x: "infected" in KProcFrame._cmd("dmesg|tail -1"),
            module = "vuln.ko"),

    TestEnv(name = "Test-Vuln-umode_exec",
            path = "/vuln/",
            binaries = "vpwn_umod_exec", args = [],
            verify = lambda x: "root" in KProcFrame._cmd(
                "stat -c '%U' /tmp/call_from_kernel && rm -f /tmp/call_from_kernel",
                exit = False),
            module = "vuln.ko"),

    TestEnv(name = "CVE-2014-3153",
            path = "/CVE/CVE-2014-3153",
            binaries = "35370"),

    TestEnv(name = "CVE-2016-5195",
            path = "/CVE/CVE-2016-5195",
            binaries = "cowroot"),
]

def main(argv):
    from optparse import OptionParser
    global debug

    parser = OptionParser(usage="usage: %prog [options]")
    parser.add_option("-k", "--kproc_mod", action="store_true", default = False,
                      help="load kproc-monitor module (need root)")
    parser.add_option("-p", "--protected", action="store_true", default = False,
                      help="protected mode (unprotected by default)")
    parser.add_option("-v", "--verbose", action="store_true", default = False, help="verbose log")

    (opts, args) = parser.parse_args()
    debug = opts.verbose
    if not opts.protected:
        opts.protected = os.path.isdir("/proc/kcs") or opts.kproc_mod

    kframe = KProcFrame(opts.kproc_mod)
    for test in test_list:
        kframe.Unit(kframe, test).run(opts.protected)

    print("\nTests passed %12u/%u" % (kframe.passed, sum([t.num for t in test_list])))

    return 0

if __name__ == "__main__":
    main(sys.argv)
