from struct import *



condition_table_true = ["lt", "gt", "eq"]
condition_table_false = ["ge", "le", "ne"]
trap_condition_table = {
    1: "lgt",
    2: "llt",
    4: "eq",
    5: "lge",
    8: "gt",
    12: "ge",
    16: "lt",
    20: "le",
    31: "u"
}

spr_table = {
    8: "lr",
    9: "ctr"
}

def decodeI(value):
    return (value >> 2) & 0xFFFFFF, (value >> 1) & 1, value & 1

def decodeB(value):
    return (value >> 21) & 0x1F, (value >> 16) & 0x1F, (value >> 2) & 0x3FFF, (value >> 1) & 1, value & 1

def decodeD(value):
    return (value >> 21) & 0x1F, (value >> 16) & 0x1F, value & 0xFFFF

def decodeX(value):
    return (value >> 21) & 0x1F, (value >> 16) & 0x1F, (value >> 11) & 0x1F, (value >> 1) & 0x3FF, value & 1

def extend_sign(value, bits=16):
    if value & 1 << (bits - 1):
        value -= 1 << bits
    return value

def ihex(value):
    return "-" * (value < 0) + "0x" + hex(value).lstrip("-0x").rstrip("L").zfill(1).upper()

def decodeCond(BO, BI):
    #TODO: Better condition code
    if BO == 20: return ""
    if BO & 1: return "?"
    if BI > 2: return "?"
    if BO == 4: return condition_table_false[BI]
    if BO == 12: return condition_table_true[BI]
    return "?"

def loadStore(value, regtype="r"):
    D, A, d = decodeD(value)
    d = extend_sign(d)
    return "%s%i, %s(r%i)" %(regtype, D, ihex(d), A)

def loadStoreX(D, A, B, pad):
    if pad: return "<invalid>"
    return "r%i, %s, r%i" %(D, ("r%i" %A) if A else "0", B)

def add(D, A, B, Rc):
    return "add%s" %("." * Rc), "r%i, r%i, r%i" %(D, A, B)

def addi(value, addr):
    D, A, SIMM = decodeD(value)
    SIMM = extend_sign(SIMM)
    if A == 0:
        return "li", "r%i, %s" %(D, ihex(SIMM))
    return "addi", "r%i, r%i, %s" %(D, A, ihex(SIMM))

def addic(value, addr):
    D, A, SIMM = decodeD(value)
    SIMM = extend_sign(SIMM)
    return "addic", "r%i, r%i, %s" %(D, A, ihex(SIMM))

def addic_(value, addr):
    D, A, SIMM = decodeD(value)
    SIMM = extend_sign(SIMM)
    return "addic.", "r%i, r%i, %s" %(D, A, ihex(SIMM))

def addis(value, addr):
    D, A, SIMM = decodeD(value)
    SIMM = extend_sign(SIMM)
    if A == 0:
        return "lis", "r%i, %s" %(D, ihex(SIMM))
    return "addis", "r%i, r%i, %s" %(D, A, ihex(SIMM))

def and_(S, A, B, Rc):
    return "and%s" % ("." * Rc), "r%i, r%i, r%i" % (A, S, B)

def b(value, addr):
    LI, AA, LK = decodeI(value)
    LI = extend_sign(LI, 24) * 4
    if AA:
        dst = LI
    else:
        dst = addr + LI
    return "b%s%s" %("l" * LK, "a" * AA), ihex(dst)

def bc(value, addr):
    BO, BI, BD, AA, LK = decodeB(value)
    LI = extend_sign(LK, 14) * 4
    instr = "b" + decodeCond(BO, BI)
    if LK: instr += "l"
    if AA:
        instr += "a"
        dst = LI
    else:
        dst = addr + LI
    return instr, ihex(dst)

def bcctr(BO, BI, pad, LK):
    if pad: return "<invalid>"
    instr = "b" + decodeCond(BO, BI) + "ctr"
    if LK:
        instr += "l"
    return instr

def bclr(BO, BI, pad, LK):
    if pad: return "<invalid>"
    instr = "b" + decodeCond(BO, BI) + "lr"
    if LK:
        instr += "l"
    return instr

def cmp(cr, A, B, pad):
    if pad: return "<invalid>"
    if cr & 3:
        return "<invalid>"
    return "cmp", "cr%i, r%i, r%i" %(cr >> 2, A, B)

def cmpi(value, addr):
    cr, A, SIMM = decodeD(value)
    SIMM = extend_sign(SIMM)
    if cr & 3:
        return "<invalid>"
    return "cmpwi", "cr%i, r%i, %s" %(cr >> 2, A, ihex(SIMM))

def cmpl(cr, A, B, pad):
    if pad: return "<invalid>"
    if cr & 3:
        return "<invalid>"
    return "cmplw", "cr%i, r%i, r%i" %(cr >> 2, A, B)

def cmpli(value, addr):
    cr, A, UIMM = decodeD(value)
    if cr & 3:
        return "<invalid>"
    return "cmplwi", "cr%i, r%i, %s" %(cr >> 2, A, ihex(UIMM))

def cntlzw(S, A, pad, Rc):
    if pad: return "<invalid>"
    return "cntlzw%s" %("." * Rc), "r%i, r%i" %(A, S)

def dcbst(pad1, A, B, pad2):
    if pad1 or pad2: return "<invalid>"
    return "dcbst", "r%i, r%i" %(A, B)

def fmr(D, pad, B, Rc):
    if pad: return "<invalid>"
    return "fmr%s" %("." * Rc), "f%i, f%i" %(D, B)

def fneg(D, pad, B, Rc):
    if pad: return "<invalid>"
    return "fneg%s" %("." * Rc), "f%i, f%i" %(D, B)

def mfspr(D, sprLo, sprHi, pad):
    if pad: return "<invalid>"
    sprnum = (sprHi << 5) | sprLo
    if sprnum not in spr_table:
        spr = "?"
    else:
        spr = spr_table[sprnum]
    return "mf%s" %spr, "r%i" %D

def mtspr(S, sprLo, sprHi, pad):
    if pad: return "<invalid>"
    sprnum = (sprHi << 5) | sprLo
    if sprnum not in spr_table:
        spr = ihex(sprnum)
    else:
        spr = spr_table[sprnum]
    return "mt%s" %spr, "r%i" %S

def lbz(value, addr): return "lbz", loadStore(value)
def lfd(value, addr): return "lfd", loadStore(value, "f")
def lfs(value, addr): return "lfs", loadStore(value, "f")
def lmw(value, addr): return "lmw", loadStore(value)
def lwz(value, addr): return "lwz", loadStore(value)
def lwzu(value, addr): return "lwzu", loadStore(value)
def lwarx(D, A, B, pad): return "lwarx", loadStoreX(D, A, B, pad)
def lwzx(D, A, B, pad): return "lwzx", loadStoreX(D, A, B, pad)

def or_(S, A, B, Rc):
    if S == B:
        return "mr%s" %("." * Rc), "r%i, r%i" %(A, S)
    return "or%s" %("." * Rc), "r%i, r%i, r%i" %(A, S, B)

def ori(value, addr):
    S, A, UIMM = decodeD(value)
    if UIMM == 0:
        return "nop"
    return "ori", "r%s, r%s, %s" %(A, S, ihex(UIMM))

def oris(value, addr):
    S, A, UIMM = decodeD(value)
    return "oris", "r%s, r%s, %s" %(A, S, ihex(UIMM))

def rlwinm(value, addr):
    S, A, SH, M, Rc = decodeX(value)
    MB = M >> 5
    ME = M & 0x1F
    dot = "." * Rc
    if SH == 0 and MB == 0 and ME == 31:
        return "nop"
    if MB == 0 and ME == 31 - SH:
        return "slwi%s" %dot, "r%i, r%i, %i" %(A, S, SH)
    if ME == 31 and SH == 32 - MB:
        return "srwi%s" %dot, "r%i, r%i, %i" %(A, S, MB)
    if MB == 0 and ME < 31:
        return "extlwi%s" %dot, "r%i, r%i, %i,%i" %(A, S, ME + 1, SH)
    #extrwi
    if MB == 0 and ME == 31:
        if SH >= 16:
            return "rotlwi%s" %dot, "r%i, r%i, %i" %(A, S, SH)
        return "rotrwi%s" %dot, "r%i, r%i, %i" %(A, S, 32 - SH)
    if SH == 0 and ME == 31:
        return "clrlwi%s" %dot, "r%i, r%i, %i" %(A, S, MB)
    if SH == 0 and MB == 0:
        return "clrrwi%s" %dot, "r%i, r%i, %i" %(A, S, 31 - ME)
    #clrlslwi
    return "rlwinm%s" %dot, "r%i, r%i, %i,%i,%i" %(A, S, SH, MB, ME)

def sc(value, addr):
    if value & 0x3FFFFFF != 2:
        return "<invalid>"
    return "sc"

def stb(value, addr): return "stb", loadStore(value)
def stfd(value, addr): return "stfd", loadStore(value, "f")
def stfs(value, addr): return "stfs", loadStore(value, "f")
def stfsu(value, addr): return "stfsu", loadStore(value, "f")
def stmw(value, addr): return "stmw", loadStore(value)
def stw(value, addr): return "stw", loadStore(value)
def stwu(value, addr): return "stwu", loadStore(value)
def stbx(S, A, B, pad): return "stbx", loadStoreX(S, A, B, pad)
def stwx(S, A, B, pad): return "stwx", loadStoreX(S, A, B, pad)
def stwcx(S, A, B, pad): return "stwcx", loadStoreX(S, A, B, pad ^ 1)

def tw(TO, A, B, pad):
    if pad: return "<invalid>"
    if TO == 31 and A == 0 and B == 0:
        return "trap"

    if TO not in trap_condition_table:
        condition = "?"
    else:
        condition = trap_condition_table[TO]
    return "tw%s" %condition, "r%i, r%i" %(A, B)

opcode_table_ext1 = {
    16: bclr,
    528: bcctr
}

opcode_table_ext2 = {
    0: cmp,
    4: tw,
    20: lwarx,
    23: lwzx,
    26: cntlzw,
    28: and_,
    32: cmpl,
    54: dcbst,
    150: stwcx,
    151: stwx,
    215: stbx,
    266: add,
    339: mfspr,
    444: or_,
    467: mtspr
}

opcode_table_float_ext1 = {
    40: fneg,
    72: fmr
}

def ext1(value, addr):
    DS, A, B, XO, Rc = decodeX(value)
    if not XO in opcode_table_ext1:
        return "ext1 - %s" %bin(XO)
    return opcode_table_ext1[XO](DS, A, B, Rc)

def ext2(value, addr):
    DS, A, B, XO, Rc = decodeX(value)
    if not XO in opcode_table_ext2:
        return "ext2 - %s" %bin(XO)
    return opcode_table_ext2[XO](DS, A, B, Rc)

def float_ext1(value, addr):
    D, A, B, XO, Rc = decodeX(value)
    if not XO in opcode_table_float_ext1:
        return "float_ext1 - %s" %bin(XO)
    return opcode_table_float_ext1[XO](D, A, B, Rc)

opcode_table = {
    10: cmpli,
    11: cmpi,
    12: addic,
    13: addic_,
    14: addi,
    15: addis,
    16: bc,
    17: sc,
    18: b,
    19: ext1,
    21: rlwinm,
    24: ori,
    25: oris,
    31: ext2,
    32: lwz,
    33: lwzu,
    34: lbz,
    36: stw,
    37: stwu,
    38: stb,
    46: lmw,
    47: stmw,
    48: lfs,
    50: lfd,
    52: stfs,
    53: stfsu,
    54: stfd,
    63: float_ext1
}

def disassemble(value, address):
    opcode = value >> 26
    if opcode not in opcode_table:
        return "???"
    instr = opcode_table[opcode](value, address)
    if type(instr) == str:
        return instr
    return instr[0] + " " * (10 - len(instr[0])) + instr[1]
    
def disassembleFile(file):
    f = open(file, "rb")
    add = 0x01000000
    old = ["", "", "","","",""]
    while True:
        opcode = unpack(">I", f.read(4))[0]
        res = disassemble(opcode, add)
        #print "%08x : " % (add),
        #print res
        for i in range(len(old)-1):
            old[i] = old[i+1]
        old[len(old)-1] = res
        if res == "blr":
            print "%08x : " % (add - (len(old)*4)),
            for i in range(len(old)):
                print "%s ; " % (old[i]),
            print ""
        add+=4
    f.close()

disassembleFile("DUMP0E.bin")