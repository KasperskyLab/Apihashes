#!/usr/bin/python3
# © 2022 AO Kaspersky Lab. All Rights Reserved.
#
# Installation: copy all the files and directories in the IDA's plugins/ directory

import ida_idaapi, ida_idp, ida_ua, ida_bytes, ida_diskio, zlib, apihashesv2_search

# Hook class
class hk(ida_idp.IDB_Hooks):
    def CheckHash(self, ea, value):
        fname = apihashesv2_search.FindHash(value)
        if fname:
            print(f"[apihashes] {hex(ea)}: Found API hash for {fname}")
            ida_bytes.set_cmt(ea, fname, False)

    # This hook will check the operands of disassembled instructions
    # So, for older IDBs you may need to undefine and disassemble the code
    # again to make the plugin work
    def make_code(self, insn):
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            if op.type == ida_ua.o_imm and op.value != 0:
                self.CheckHash(insn.ea, op.value)

        return None

    # This hook will check the newly created data items (DWORDS, QWORDS)
    # So, for older IDBs you may need to undefine and recreate the data items
    # to force the checks
    def make_data(self, ea, flags, tid, sz):
        if sz == 4:
            opValue = ida_bytes.get_dword(ea)
        elif sz == 8:
            opValue = ida_bytes.get_qword(ea)
        else:
            return None
        self.CheckHash(ea, opValue)
        return None

class apihashes_plugin_t(ida_idaapi.plugin_t):
    flags = 0
    comment = "Resolve API hashes on code/data creation"
    help = "No help"
    wanted_name = "Apihashes"
    wanted_hotkey = ""
    

    def init(self):
        self.hk = hk()
        self.hk.hook()
        # We're looking for the database in the IDA's plugins directory
        res = apihashesv2_search.LoadHashes(ida_diskio.idadir(ida_diskio.PLG_SUBDIR) + "/apihashesv2.bin")
        print(f"[apihashes] v2 plugin loaded, {res} hashes in the database")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return apihashes_plugin_t()
