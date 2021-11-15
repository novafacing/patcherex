#!/usr/bin/env python

import sys
import os
import logging
import traceback
import timeout_decorator
import itertools
import psutil
import multiprocessing
import subprocess
import random
import concurrent.futures
import datetime
import tempfile
import termcolor
import time
import pickle
import platform
from ctypes import cdll

l = logging.getLogger("patcherex.PatchMaster")

try:
    import resource
except ImportError:
    if platform.system() == "Windows":
        l.warning("Skip importing the resource package on Windows.")
    else:
        raise

from .techniques.qemudetection import QemuDetection
from .techniques.shadowstack import ShadowStack
from .techniques.packer import Packer
from .techniques.simplecfi import SimpleCFI
from .techniques.cpuid import CpuId
from .techniques.randomsyscallloop import RandomSyscallLoop
from .techniques.stackretencryption import StackRetEncryption
from .techniques.indirectcfi import IndirectCFI
from .techniques.transmitprotection import TransmitProtection
from .techniques.shiftstack import ShiftStack
from .techniques.nxstack import NxStack
from .techniques.adversarial import Adversarial
from .techniques.backdoor import Backdoor
from .techniques.bitflip import Bitflip
from .techniques.binary_optimization import optimize_it
from .techniques.uninitialized_patcher import UninitializedPatcher
from .techniques.malloc_ext_patcher import MallocExtPatcher
from .techniques.noflagprintf import NoFlagPrintfPatcher
from .techniques.fidgetpatches import fidget_it
from .errors import *
from .backends.detourbackend import DetourBackend
from .backends.reassembler_backend import ReassemblerBackend
from .patches import *
from .networkrules import NetworkRules


class PatchMaster:
    def __init__(self, infile):
        self.infile = infile

    def generate_stackretencryption_binary(self):
        backend = ReassemblerBackend(self.infile)
        patches = []
        patches.extend(StackRetEncryption(self.infile, backend).get_patches())
        backend.apply_patches(patches)
        final_content = backend.get_final_content()
        return (final_content, "")

    def generate_fidget_bitflip_binary(self):
        nr = NetworkRules()
        midfile = self.infile + ".fidget" + str(random.randrange(0, 1000))
        fidget_it(self.infile, midfile)
        backend = DetourBackend(midfile)
        cp = Bitflip(midfile, backend)
        patches1 = cp.get_patches()
        backend.apply_patches(patches1)
        return (backend.get_final_content(), nr.get_bitflip_rule())

    ##################

    def generate_medium_reassembler_optimized_binary(self):
        try:
            intermediate = tempfile.mktemp(prefix="%s_" % os.path.basename(self.infile))
            optimize_it(self.infile, intermediate)

            nr = NetworkRules()
            backend = ReassemblerBackend(intermediate)
            patches = []

            patches.extend(IndirectCFI(intermediate, backend).get_patches())
            patches.extend(TransmitProtection(intermediate, backend).get_patches())
            patches.extend(ShiftStack(intermediate, backend).get_patches())
            patches.extend(Adversarial(intermediate, backend).get_patches())
            patches.extend(Backdoor(intermediate, backend).get_patches())
            # patches.extend(NxStack(intermediate,backend).get_patches())
            patches.extend(MallocExtPatcher(intermediate, backend).get_patches())
            patches.extend(StackRetEncryption(intermediate, backend).get_patches())
            patches.extend(UninitializedPatcher(intermediate, backend).get_patches())
            patches.extend(NoFlagPrintfPatcher(intermediate, backend).get_patches())

            backend.apply_patches(patches)
            final_content = backend.get_final_content()
            res = (final_content, "")
        except PatcherexError as ex:
            traceback.print_exc(ex)
            res = (None, None)

        return res

    def generate_medium_reassembler_binary(self):
        try:
            nr = NetworkRules()
            backend = ReassemblerBackend(self.infile)
            patches = []

            patches.extend(IndirectCFI(self.infile, backend).get_patches())
            patches.extend(TransmitProtection(self.infile, backend).get_patches())
            patches.extend(ShiftStack(self.infile, backend).get_patches())
            patches.extend(Adversarial(self.infile, backend).get_patches())
            patches.extend(Backdoor(self.infile, backend).get_patches())
            # patches.extend(NxStack(self.infile,backend).get_patches())
            patches.extend(MallocExtPatcher(self.infile, backend).get_patches())
            patches.extend(StackRetEncryption(self.infile, backend).get_patches())
            patches.extend(UninitializedPatcher(self.infile, backend).get_patches())
            patches.extend(NoFlagPrintfPatcher(self.infile, backend).get_patches())

            backend.apply_patches(patches)
            final_content = backend.get_final_content()
            res = (final_content, "")
        except PatcherexError as ex:
            traceback.print_exc(ex)
            res = (None, None)
        return res

    def generate_medium_detour_binary(self):
        try:
            nr = NetworkRules()
            backend = DetourBackend(self.infile)
            patches = []

            patches.extend(IndirectCFI(self.infile, backend).get_patches())
            patches.extend(TransmitProtection(self.infile, backend).get_patches())
            patches.extend(ShiftStack(self.infile, backend).get_patches())
            patches.extend(Adversarial(self.infile, backend).get_patches())
            patches.extend(Backdoor(self.infile, backend).get_patches())
            # patches.extend(NxStack(self.infile,backend).get_patches())
            patches.extend(MallocExtPatcher(self.infile, backend).get_patches())
            patches.extend(StackRetEncryption(self.infile, backend).get_patches())
            patches.extend(UninitializedPatcher(self.infile, backend).get_patches())
            patches.extend(NoFlagPrintfPatcher(self.infile, backend).get_patches())

            backend.apply_patches(patches)
            final_content = backend.get_final_content()
            res = (final_content, "")
        except PatcherexError as ex:
            traceback.print_exc(ex)
            res = (None, None)
        return res

    ########################

    def create_one_patch(self, patch_type):
        m = getattr(self, "generate_" + patch_type + "_binary")
        patch, network_rule = m()
        return patch, network_rule


def process_killer():
    cdll["libc.so.6"].prctl(1, 9)


def shellquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def exec_cmd(args, cwd=None, shell=False, debug=False, pkill=True):
    # debug = True
    if debug:
        print("EXECUTING:", repr(args), cwd, shell)
    pipe = subprocess.PIPE
    preexec_fn = None
    if pkill:
        preexec_fn = process_killer
    p = subprocess.Popen(
        args, cwd=cwd, shell=shell, stdout=pipe, stderr=pipe, preexec_fn=process_killer
    )
    std = p.communicate()
    retcode = p.poll()
    res = (std[0], std[1], retcode)
    if debug:
        print("RESULT:", repr(res))
    return res


def worker(inq, outq, filename_with_technique=True, timeout=60 * 3, test_results=True):
    def delete_if_exists(fname):
        try:
            os.unlink(fname)
        except OSError:
            pass

    process_killer()

    while True:
        input_file, technique, output_dir = inq.get()
        if filename_with_technique:
            output_fname = os.path.join(
                output_dir, os.path.basename(input_file) + "_" + technique
            )
        else:
            output_fname = os.path.join(output_dir, os.path.basename(input_file))
        delete_if_exists(output_fname)
        delete_if_exists(output_fname + "_log")
        args = [
            "timeout",
            "-s",
            "9",
            str(timeout),
            os.path.realpath(__file__),
            "single",
            input_file,
            technique,
            output_fname,
        ]
        if test_results:
            args += ["--test"]
        res = exec_cmd(args)
        with open(output_fname + "_log", "w") as fp:
            fp.write("\n" + "=" * 30 + " STDOUT\n")
            fp.write(res[0])
            fp.write("\n" + "=" * 30 + " STDERR\n")
            fp.write(res[1])
            fp.write("\n" + "=" * 30 + " RETCODE: ")
            fp.write(str(res[2]).strip())
            fp.write("\n")
        if res[2] != 0 or not os.path.exists(output_fname):
            outq.put((False, (input_file, technique, output_dir), res))
        else:
            outq.put((True, (input_file, technique, output_dir), res))


def ftodir(f, out):
    dname = os.path.split(os.path.split(f)[-2])[-1]
    res = os.path.join(out, dname)
    # print "-->",out,dname,res
    return res


def ftodir2(f, technique, out):
    sep = os.path.sep
    cb_name, flavour = f.split(sep)[-3:-1]
    res = os.path.join(*[out, flavour, technique, cb_name])
    return res


if __name__ == "__main__":
    if sys.argv[1] == "run":
        logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
        logging.getLogger("patcherex.backend").setLevel("INFO")
        logging.getLogger("patcherex.techniques.NoFlagPrintfPatcher").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.ShiftStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.NxStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

        input_fname = sys.argv[2]
        out = os.path.join(sys.argv[3], os.path.basename(input_fname))
        pm = PatchMaster(input_fname)

        res = pm.run(return_dict=True)
        with open(sys.argv[2]) as fp:
            original_content = fp.read()
        res["original"] = (original_content, "")
        for k, (v, rule) in res.items():
            output_fname = out + "_" + k
            fp = open(output_fname, "wb")
            fp.write(v)
            fp.close()
            os.chmod(output_fname, 0o755)
            with open(output_fname + ".rules", "wb") as rf:
                rf.write(rule)

    elif sys.argv[1] == "single":
        cdll["libc.so.6"].prctl(1, 9)
        mem_limit = 16 * pow(2, 30)
        resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))

        print("=" * 50, "process started at", str(datetime.datetime.now()))
        start_time = time.time()
        print(" ".join(map(shellquote, sys.argv)))

        logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
        logging.getLogger("patcherex.backend").setLevel("INFO")
        logging.getLogger("patcherex.techniques.NoFlagPrintfPatcher").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.ShiftStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.NxStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

        input_fname = sys.argv[2]
        technique = sys.argv[3]
        output_fname = sys.argv[4]
        pm = PatchMaster(input_fname)
        m = getattr(pm, "generate_" + technique + "_binary")

        if "--test" in sys.argv:
            res = m()
        else:
            res = m()

        # handle generate_ methods returning also a network rule
        bitflip = False
        if res[0] is None:
            sys.exit(33)
        if not any([output_fname.endswith("_" + str(i)) for i in range(2, 10)]):
            fp = open(os.path.join(os.path.dirname(output_fname), "ids.rules"), "wb")
            fp.write(res[1])
            fp.close()
        if "bitflip" in res[1]:
            bitflip = True
        patched_bin_content = res[0]

        fp = open(output_fname, "wb")
        fp.write(patched_bin_content)
        fp.close()
        os.chmod(output_fname, 0o755)

        print(
            "=" * 50,
            "process ended at",
            str(datetime.datetime.now()),
            "in",
            str(time.time() - start_time),
        )

    elif (
        sys.argv[1] == "multi"
        or sys.argv[1] == "multi_name"
        or sys.argv[1] == "multi_name2"
    ):
        out = sys.argv[2]
        techniques = sys.argv[3].split(",")
        if sys.argv[7] == "--test":
            test_results = True
        else:
            test_results = False

        files = sys.argv[8:]
        technique_in_filename = True

        if sys.argv[1] == "multi_name":
            tasks = []
            for f in files:
                for t in techniques:
                    outdir = ftodir(f, out)
                    try:
                        os.makedirs(outdir)
                    except OSError:
                        pass
                    tasks.append((f, t, outdir))

        elif sys.argv[1] == "multi_name2":
            tasks = []
            technique_in_filename = False
            for f in files:
                for t in techniques:
                    outdir = ftodir2(f, t, out)
                    try:
                        os.makedirs(outdir)
                    except OSError:
                        pass
                    try:
                        os.mkdir(outdir)
                    except OSError:
                        pass
                    tasks.append((f, t, outdir))

        elif sys.argv[1] == "multi":
            tasks = [(f, t, out) for f, t in list(itertools.product(files, techniques))]

        print(len(tasks))
        res_dict = {}

        inq = multiprocessing.Queue()
        outq = multiprocessing.Queue()
        plist = []
        nprocesses = int(sys.argv[5])
        if nprocesses == 0:
            nprocesses = int(psutil.cpu_count() * 1.0)
        timeout = int(sys.argv[6])
        for i in range(nprocesses):
            p = multiprocessing.Process(
                target=worker,
                args=(inq, outq, technique_in_filename, timeout, test_results),
            )
            p.start()
            plist.append(p)

        ntasks = len(tasks)
        random.shuffle(tasks, lambda: 0.1)
        for t in tasks:
            inq.put(t)
        for i in range(ntasks):
            res = outq.get()
            sep = os.path.sep
            key = (sep.join(res[1][0].split(sep)[-3:]), res[1][1])
            status = res[0]
            value = res[2]
            if status:
                status = termcolor.colored(status, "green")
            else:
                status = termcolor.colored(status, "red")

            print("=" * 20, str(i + 1) + "/" + str(ntasks), key, status)
            # print value
            res_dict[key] = res

        for p in plist:
            p.terminate()

        failed_patches = {k: v for k, v in res_dict.items() if v[0] == False}
        print("FAILED PATCHES", str(len(failed_patches)) + "/" + str(ntasks))
        for k, v in failed_patches:
            print(k, v)

        pickle.dump(res_dict, open(sys.argv[4], "wb"))

        # IPython.embed()
