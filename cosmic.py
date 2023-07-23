import pymem
import re
import time
import ctypes
import os
import requests
import subprocess
import tkinter as tk

from tkinter import font
from PIL import ImageTk, Image

Injected = False
Root = tk.Tk()

Unattached = ImageTk.PhotoImage(Image.open("images\\Unattached.png"))
Attached = ImageTk.PhotoImage(Image.open("images\\Attached.png"))
Lua = ImageTk.PhotoImage(Image.open("images\\Lua.png"))

Code = tk.Text(Root, height=10, width=57)

Header = tk.Label(Root, text="Cosmic Python", font=font.Font(
    family="Open Sans", size=15, weight="bold"))

DownloadCompiler = True
TaskSchedulerAddress = "Windows10Universal.exe+33A75D4"
TextBoxCharacterLimit = "Windows10Universal.exe+2D93098"
LuaVMLoadFunctionAddress = "Windows10Universal.exe+5687F0"
GetStateFunctionAddress = "Windows10Universal.exe+466C20"
Task_Defer_FunctionAddress = "Windows10Universal.exe+4A5EC0"
Lua_Top = 0x18
Name_Offset = 0x2C
Character_Offset = 0x84
RobloxExtraSpace_Offset = 0x48
Identity_Offset = 0x18
UserId_Offset = 0x118

os.system('cls')

class Exploit:
    def __init__(self, ProgramName=None):
        self.ProgramName = ProgramName
        self.Pymem = pymem.Pymem()
        self.Addresses = {}
        if type(ProgramName) == str:
            self.Pymem = pymem.Pymem(ProgramName)
        elif type(ProgramName) == int:
            self.Pymem.open_process_from_id(ProgramName)

    def h2d(self, hz: str) -> int:
        if type(hz) == int:
            return hz
        return int(hz, 16)

    def d2h(self, dc: int) -> str:
        if type(dc) == str:
            return dc
        if abs(dc) > 4294967295:
            dc = hex(dc & (2**64-1)).replace("0x", "")
        else:
            dc = hex(dc & (2**32-1)).replace("0x", "")
        if len(dc) > 8:
            while len(dc) < 16:
                dc = "0" + dc
        if len(dc) < 8:
            while len(dc) < 8:
                dc = "0" + dc
        return dc

    def PLAT(self, aob: str):
        if type(aob) == bytes:
            return aob
        TrueB = bytearray(b"")
        aob = aob.replace(" ", "")
        PLATlist = []
        for i in range(0, len(aob), 2):
            PLATlist.append(aob[i:i+2])
        for i in PLATlist:
            if "?" in i:
                TrueB.extend(b".")
            if "?" not in i:
                TrueB.extend(re.escape(bytes.fromhex(i)))
        return bytes(TrueB)

    def AOBSCANALL(self, AOB_HexArray, xreturn_multiple=False):
        return pymem.pattern.pattern_scan_all(self.Pymem.process_handle, self.PLAT(AOB_HexArray), return_multiple=xreturn_multiple)

    def gethexc(self, hex: str):
        hex = hex.replace(" ", "")
        hxlist = []
        for i in range(0, len(hex), 2):
            hxlist.append(hex[i:i+2])
        return len(hxlist)

    def hex2le(self, hex: str):
        if type(hex) == int:
            hex = self.d2h(hex)
        lehex = hex.replace(" ", "")
        reniL = 0
        zqSij = ""
        lelist = []
        for i in range(0, len(lehex), 2):
            lelist.append(lehex[i:i+2])
        if len(lelist) != 4:
            reniL = len(lelist) - 4
            zqSij = zqSij + "0"
            for i in range(0, reniL):
                zqSij = zqSij + "00"
        lelist.insert(0, zqSij)
        if len("".join(lelist)) != 8:
            lelist.insert(0, "0")
        lelist.reverse()
        lehex = "".join(lelist)
        return lehex

    def calcjmpop(self, des, cur):
        jmpopc = (self.h2d(des) - self.h2d(cur)) - 5
        jmpopc = hex(jmpopc & (2**32-1)).replace("0x", "")
        if len(jmpopc) % 2 != 0:
            jmpopc = "0" + str(jmpopc)
        return jmpopc

    def DRP(self, Address: int, is64Bit: bool = False) -> int:
        Address = Address
        if type(Address) == str:
            Address = self.h2d(Address)
        if is64Bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        return int.from_bytes(self.Pymem.read_bytes(Address, 4), "little")

    def isValidPointer(self, Address: int, is64Bit: bool = False) -> bool:
        try:
            if type(Address) == str:
                Address = self.h2d(Address)
            self.Pymem.read_bytes(self.DRP(Address, is64Bit), 1)
            return True
        except:
            return False

    def GetModules(self) -> list:
        return list(self.Pymem.list_modules())

    def getAddressFromName(self, Address: str) -> int:
        if type(Address) == int:
            return Address
        AddressBase = 0
        AddressOffset = 0
        for i in self.GetModules():
            if i.name in Address:
                AddressBase = i.lpBaseOfDll
                AddressOffset = self.h2d(Address.replace(i.name + "+", ""))
                AddressNamed = AddressBase + AddressOffset
                return AddressNamed
        return Address

    def getNameFromAddress(self, Address: int) -> str:
        memoryInfo = pymem.memory.virtual_query(
            self.Pymem.process_handle, Address)
        AllocationBase = memoryInfo.AllocationBase
        NameOfDLL = ""
        AddressOffset = 0
        for i in self.GetModules():
            if i.lpBaseOfDll == AllocationBase:
                NameOfDLL = i.name
                AddressOffset = Address - AllocationBase
                break
        if NameOfDLL == "":
            return Address
        NameOfAddress = NameOfDLL + "+" + self.d2h(AddressOffset)
        return NameOfAddress

    def getRawProcesses(self):
        toreturn = []
        for i in pymem.process.list_processes():
            toreturn.append([i.cntThreads, i.cntUsage, i.dwFlags, i.dwSize, i.pcPriClassBase, i.szExeFile,
                            i.th32DefaultHeapID, i.th32ModuleID, i.th32ParentProcessID, i.th32ProcessID])
        return toreturn

    def SimpleGetProcesses(self):
        toreturn = []
        for i in self.getRawProcesses():
            toreturn.append(
                {"Name": i[5].decode(), "Threads": i[0], "ProcessId": i[9]})
        return toreturn

    def YieldForProgram(self, programName, AutoOpen: bool = False, Limit=15):
        Count = 0
        while True:
            if Count > Limit:
                return False
            ProcessesList = self.SimpleGetProcesses()
            for i in ProcessesList:
                if i["Name"] == programName:
                    if AutoOpen:
                        Root.title("Connected to Roblox client.")
                        Root.iconphoto(False, Attached)
                        self.Pymem.open_process_from_id(i["ProcessId"])
                        self.ProgramName = programName
                    return True
            time.sleep(1)
            Count += 1

    def ReadPointer(self, BaseAddress: int, Offsets_L2R: list, is64Bit: bool = False) -> int:
        x = self.DRP(BaseAddress, is64Bit)
        y = Offsets_L2R
        z = x
        count = 0
        for i in y:
            try:
                z = self.DRP(z + i, is64Bit)
                count += 1
            except:
                return z
        return z

    def ChangeProtection(self, Address: int, ProtectionType=0x40, Size: int = 4, OldProtect=ctypes.c_ulong(0)):
        pymem.ressources.kernel32.VirtualProtectEx(
            self.Pymem.process_handle, Address, Size, ProtectionType, ctypes.byref(OldProtect))
        return OldProtect


def xyzStringToHex(text: str, noZeros=False) -> str:
    toreturn = []
    for i in text:
        toreturn.append(Exploit().d2h(ord(i)))
        toreturn.append(" ")
    toreturn = "".join(toreturn)[:-1].upper()
    if noZeros:
        aList = []
        for i in toreturn.split(" "):
            for ii in range(0, len(i)-1):
                if i[ii] != "0":
                    aList.append(i[ii:])
                    break
        toreturn = " ".join(aList).upper()
    return toreturn


def xyzHexToString(hex: str) -> str:
    toreturn = []
    if " " not in hex:
        return chr(Exploit().h2d(hex))
    return "".join(toreturn)


Cosmic = Exploit()
Cosmic.YieldForProgram("Windows10Universal.exe", True)


def ReadRobloxString(ExpectedAddress: int) -> str:
    StringCount = Cosmic.Pymem.read_int(ExpectedAddress + 0x10)
    if StringCount > 15:
        return Cosmic.Pymem.read_string(Cosmic.DRP(ExpectedAddress), StringCount)
    return Cosmic.Pymem.read_string(ExpectedAddress, StringCount)


def GetTaskScheduler() -> int:
    return Cosmic.getAddressFromName(TaskSchedulerAddress)


def isValidTask(TaskInstanceAddress: int) -> bool:
    x = TaskInstanceAddress
    if not Cosmic.isValidPointer(x):
        return False
    y = Cosmic.DRP(x)
    a = y
    b = a + 0x8
    c = a + 0xC
    if Cosmic.DRP(b) == a and Cosmic.isValidPointer(a) and Cosmic.isValidPointer(c):
        return True


def GetTaskName(TaskInstanceAddress: int) -> str:
    x = TaskInstanceAddress
    if not Cosmic.isValidPointer(x):
        return False
    y = Cosmic.DRP(x)
    z = y + 0x10
    return ReadRobloxString(z)


def TaskSchedulerGetJobs() -> list:
    DynamicTaskScheduler = Cosmic.DRP(GetTaskScheduler())
    JobStart = 0x134
    JobEnd = 0x138
    OffsetsPerJob = 8
    CurrentJob = Cosmic.DRP(DynamicTaskScheduler + JobStart)
    JobEndAddress = Cosmic.DRP(DynamicTaskScheduler + JobEnd)
    Jobs = []
    for i in range(0, 1000):
        if CurrentJob == JobEndAddress:
            break
        Jobs.append(CurrentJob)
        CurrentJob += OffsetsPerJob
    return Jobs


def TaskSchedulerFindFirstJob(JobName: str) -> int:
    Jobs = TaskSchedulerGetJobs()
    for i in Jobs:
        if GetTaskName(i) == JobName:
            return i


def GetFPS() -> float:
    return 1/Cosmic.read_double(Cosmic.DRP(GetTaskScheduler())+0x118)


def SetFPS(FPSCount: float):
    Cosmic.write_double(Cosmic.DRP(GetTaskScheduler()) +
                        0x118, 1/float(FPSCount))


def isTaskSchedulerAddress(Address, isDynamic=False):
    CurrentAddress = Address
    if Cosmic.isValidPointer(CurrentAddress) or isDynamic:
        TaskScheduler = CurrentAddress
        DynamicTaskScheduler = None
        if isDynamic:
            DynamicTaskScheduler = TaskScheduler
        else:
            DynamicTaskScheduler = Cosmic.DRP(TaskScheduler)
        JobStart = DynamicTaskScheduler + 0x134
        JobEnd = DynamicTaskScheduler + 0x138
        PointerX = DynamicTaskScheduler + 0x130
        PointerY = DynamicTaskScheduler + 0x13C
        if Cosmic.isValidPointer(JobStart) and Cosmic.isValidPointer(JobEnd) and Cosmic.isValidPointer(PointerX) and Cosmic.isValidPointer(PointerY):
            FirstJob = Cosmic.DRP(JobStart)
            if Cosmic.isValidPointer(FirstJob):
                if Cosmic.DRP(Cosmic.DRP(FirstJob)+8) == Cosmic.DRP(FirstJob):
                    if Cosmic.Pymem.read_double(DynamicTaskScheduler + 0x8) == 0.05:
                        return True


if not isTaskSchedulerAddress(GetTaskScheduler()):
    time.sleep(10)
    exit()


def GetDataModelFromNetPeerSend() -> int:
    NPS = TaskSchedulerFindFirstJob("Net Peer Send")
    if not NPS:
        time.sleep(5)
        return None
    return Cosmic.DRP(Cosmic.DRP(NPS)+0x28)-8


while True:
    if GetDataModelFromNetPeerSend():
        break
    print("Please relaunch Cosmic!")


ClassName_Offset = 0xC


def GetDataModelAddress() -> int:
    DataModel = GetDataModelFromNetPeerSend()
    if DataModel:
        return Cosmic.DRP(DataModel + 0x14)


def GetDataModel() -> int:
    DataModel = GetDataModelFromNetPeerSend()
    if DataModel:
        return Cosmic.DRP(DataModel + 0x14) + 4


def GetDataModelFromRawDataModel(RawDataModel: int) -> int:
    return Cosmic.DRP(RawDataModel + 0x14) + 4


Children_Offset = Name_Offset + 0x4
Parent_Offset = Children_Offset + 0x8


def isPointerToInstance(Instance: int) -> bool:
    if Cosmic.isValidPointer(Instance):
        x = Cosmic.DRP(Instance)
        if Cosmic.isValidPointer(x) and Cosmic.isValidPointer(x + ClassName_Offset) and Cosmic.DRP(x + 4) == x:
            return True


def isInstanceValid(Instance: int) -> bool:
    if not Instance:
        return False
    if Instance == 0:
        return False
    if not Cosmic.isValidPointer(Instance):
        return False
    if Cosmic.DRP(Instance) == 0:
        return False
    if not isPointerToInstance(Instance):
        x = Instance
        if not Cosmic.isValidPointer(x) and not Cosmic.isValidPointer(x + ClassName_Offset) and not Cosmic.DRP(x + 4) == x:
            return False
    return True


def isValidDataModel(Address):
    if isInstanceValid(Address) and GetName(Address) == "Game" and GetClassName(Address) == "DataModel" and GetChildren(Address):
        if len(GetChildren(Address)) > 0:
            return True


def GetInstanceAddress(Instance: int) -> int:
    if not isInstanceValid(Instance):
        return False
    if isPointerToInstance(Instance):
        return Cosmic.DRP(Instance)
    return Instance


def GetName(Instance: int) -> str:
    if not isInstanceValid(Instance):
        return False
    ExpectedAddress = Cosmic.DRP(GetInstanceAddress(Instance) + Name_Offset)
    return ReadRobloxString(ExpectedAddress)


def GetClassDescriptor(Instance: int) -> int:
    if not isInstanceValid(Instance):
        return False
    ClassDescriptor = Cosmic.DRP(
        GetInstanceAddress(Instance) + ClassName_Offset)
    if not Cosmic.isValidPointer(ClassDescriptor):
        return False
    return ClassDescriptor


def GetClassName(Instance: int) -> str:
    ClassDescriptor = GetClassDescriptor(Instance)
    if not ClassDescriptor:
        return False
    ExpectedAddress = Cosmic.DRP(ClassDescriptor + 4)
    return ReadRobloxString(ExpectedAddress)


def GetChildren(Instance: int) -> str:
    ChildrenInstance = []
    if not isInstanceValid(Instance):
        return False
    InstanceAddress = GetInstanceAddress(Instance)
    if not InstanceAddress:
        return False
    ChildrenStart = Cosmic.DRP(InstanceAddress + Children_Offset)
    if ChildrenStart == 0:
        return []
    ChildrenEnd = Cosmic.DRP(ChildrenStart + 4)
    OffsetAddressPerChild = 0x8
    CurrentChildAddress = Cosmic.DRP(ChildrenStart)
    for i in range(0, 9000):
        if CurrentChildAddress == ChildrenEnd:
            break
        if isInstanceValid(CurrentChildAddress):
            ChildrenInstance.append(GetInstanceAddress(CurrentChildAddress))
        CurrentChildAddress += OffsetAddressPerChild
    return ChildrenInstance


def GetDescendants(Instance: int) -> list:
    DescendantChildren = []

    def LoopThroughChildren(InstanceChild):
        ChildrenInstances = GetChildren(InstanceChild)
        if len(ChildrenInstances) > 0:
            for i in ChildrenInstances:
                if isInstanceValid(i):
                    DescendantChildren.append(i)
                    LoopThroughChildren(i)
    LoopThroughChildren(Instance)
    return DescendantChildren


def FindFirstDescendant(Instance: int, Name: str) -> int:
    def LoopThroughChildren(InstanceChild):
        ChildrenInstances = GetChildren(InstanceChild)
        if len(ChildrenInstances) > 0:
            for i in ChildrenInstances:
                if isInstanceValid(i):
                    if GetName(i) == Name:
                        return i
                    else:
                        LoopThroughChildren(i)
    return LoopThroughChildren(Instance)


def FindFirstDescendantOfClass(Instance: int, ClassName: str) -> int:
    def LoopThroughChildren(InstanceChild):
        ChildrenInstances = GetChildren(InstanceChild)
        if len(ChildrenInstances) > 0:
            for i in ChildrenInstances:
                if isInstanceValid(i):
                    if GetClassName(i) == ClassName:
                        return i
                    else:
                        LoopThroughChildren(i)
    return LoopThroughChildren(Instance)


def GetService(ServiceName: str) -> int:
    ChildrenOfDataModel = GetChildren(GetDataModelAddress())
    if not ChildrenOfDataModel:
        return None
    for i in ChildrenOfDataModel:
        if GetClassName(i) == ServiceName:
            return i


def FindFirstChild(Instance: int, ChildName: str, Recursive: bool = False) -> int:
    ChildrenOfInstance = GetChildren(Instance)
    for i in ChildrenOfInstance:
        if GetName(i) == ChildName:
            return i
    if Recursive:
        return FindFirstDescendant(Instance, ChildName)


def FindFirstChildOfClass(Instance: int, ClassName: str, Recursive: bool = False) -> int:
    ChildrenOfInstance = GetChildren(Instance)
    for i in ChildrenOfInstance:
        if GetClassName(i) == ClassName:
            return i
    if Recursive:
        return FindFirstDescendantOfClass(Instance, ClassName)


def GetParent(Instance: int) -> int:
    if not isInstanceValid(Instance):
        return False
    return Cosmic.DRP(GetInstanceAddress(Instance) + Parent_Offset)


def GetFullName(Instance: int):
    if Instance == GetDataModelAddress():
        return GetName(GetDataModelAddress())
    x = GetInstanceAddress(Instance)
    if not x:
        return False
    y = GetParent(Instance)
    z = ""
    ListOfDir = []
    LineName = ""
    currentParent = y
    IsDone = False
    Services = GetChildren(GetDataModelAddress())
    ListOfDir.append(GetName(x))
    for i in range(0, 100):
        for ii in Services:
            if currentParent == GetInstanceAddress(ii):
                ListOfDir.append(GetName(currentParent))
                IsDone = True
                break
        if IsDone:
            break
        ListOfDir.append(GetName(currentParent))
        currentParent = GetParent(currentParent)
    ListOfDir.reverse()
    for i in ListOfDir:
        LineName = LineName + "." + i
    return "game"+LineName


def GetLocalPlayer() -> int:
    return FindFirstChildOfClass(GetService("Players"), "Player")


def GetPlayers() -> list:
    PlayerInstances = []
    PlayersChildren = GetChildren(GetService("Players"))
    for i in PlayersChildren:
        if GetClassName(i) == "Player":
            PlayerInstances.append(i)
    return PlayerInstances


def GetOtherPlayers() -> list:
    Players = GetPlayers()
    Players.pop(0)
    return Players


def GetPlayer(PlayerName: str) -> int:
    for i in GetOtherPlayers():
        if GetName(i).lower() == PlayerName.lower():
            return i


def GetCharacter(Player: int) -> int:
    if not GetClassName(Player) == "Player":
        return None
    return Cosmic.DRP(GetInstanceAddress(Player) + Character_Offset)


def GetUserId(Player: int) -> int:
    if not GetClassName(Player) == "Player":
        return None
    return Cosmic.Pymem.read_ulonglong(GetInstanceAddress(Player) + UserId_Offset)


def IsA(Instance: int, ClassName):
    if GetClassName(Instance) == ClassName:
        return True


def WaitForChild(Instance: int, Child: str, Timeout: int = 1):
    for i in range(Timeout):
        if FindFirstChild(Instance, Child):
            return FindFirstChild(Instance, Child)
        time.sleep(1)


def wait(Seconds):
    time.sleep(Seconds)


def PartCheck(Instance: int) -> bool:
    ClassName = GetClassName(Instance)
    if ClassName == "Part" or ClassName == "BasePart" or ClassName == "MeshPart" or ClassName == "UnionOperation" or ClassName == "Seat":
        return True


Cosmic.Pymem.write_int(Cosmic.getAddressFromName(
    TextBoxCharacterLimit), 999999999)


StoredByteCodes = dict()


def GetStoredByteCode(HexStringByteCode: str) -> int:
    return StoredByteCodes.get(HexStringByteCode)


def MakeByteCodeAddress(HexStringByteCode: str) -> int:
    RawHexString = HexStringByteCode.replace(" ", "")
    ByteCodeAddress = GetStoredByteCode(RawHexString)
    if ByteCodeAddress:
        return ByteCodeAddress
    ByteCodeAddress = Cosmic.Pymem.allocate(50)
    Length = Cosmic.gethexc(RawHexString)
    ByteCodeString = Cosmic.Pymem.allocate(len(RawHexString) + 20)
    Cosmic.Pymem.write_int(ByteCodeAddress, ByteCodeString)
    Cosmic.Pymem.write_int(ByteCodeAddress + 0x10, Length)
    Cosmic.Pymem.write_int(ByteCodeAddress + 0x14, Length + 20)
    Cosmic.Pymem.write_bytes(
        ByteCodeString, bytes.fromhex(RawHexString), Length)
    StoredByteCodes.update({RawHexString: ByteCodeAddress})
    return ByteCodeAddress


def GetByteCodeAddress(Script: int) -> int:
    ClassName = GetClassName(Script)
    if ClassName == "LocalScript":
        return Cosmic.DRP(Script + 0x140) + 0x10
    if ClassName == "ModuleScript":
        return Cosmic.DRP(Script + 0x124) + 0x10


def GetByteCode(ByteCodeAddress: int) -> str:
    Length = Cosmic.Pymem.read_int(ByteCodeAddress + 0x10)
    ByteCode = Cosmic.Pymem.read_bytes(
        Cosmic.DRP(ByteCodeAddress), Length).hex()
    return ByteCode


StoredOScripts = dict()


def GetStoredOScripts(ByteCodeAddress: int) -> int:
    return StoredOScripts.get(ByteCodeAddress)


def OverwriteByteCode(Script: int, ByteCodeAddress: int) -> list:
    x = Script
    y = 0
    ClassName = GetClassName(Script)
    if ClassName == "LocalScript":
        y = x + 0x140
    if ClassName == "ModuleScript":
        y = x + 0x124
    if y == 0:
        return None
    ProtectedStringRegion = Cosmic.DRP(y)
    ProtectedStringRegionData = Cosmic.Pymem.read_bytes(
        ProtectedStringRegion, 20, True)
    ScriptByteCodeAddress = ProtectedStringRegion + 0x10
    LengthA = ScriptByteCodeAddress + 0x10
    LengthB = LengthA + 4
    OriginalByteCode = GetByteCode(ScriptByteCodeAddress)
    NewMemoryRegion = GetStoredOScripts(ProtectedStringRegion)
    if NewMemoryRegion:
        Cosmic.Pymem.write_int(y, NewMemoryRegion)
        return [NewMemoryRegion, ProtectedStringRegion, OriginalByteCode]
    else:
        NewMemoryRegion = Cosmic.Pymem.allocate(64)
        StoredOScripts.update({ByteCodeAddress: NewMemoryRegion})
        Cosmic.Pymem.write_bytes(
            NewMemoryRegion, ProtectedStringRegionData, 20)
        Cosmic.Pymem.write_int(NewMemoryRegion + 0x10,
                               Cosmic.Pymem.read_int(ByteCodeAddress))
        Cosmic.Pymem.write_int(NewMemoryRegion + 0x20,
                               Cosmic.Pymem.read_int(ByteCodeAddress + 0x10))
        Cosmic.Pymem.write_int(NewMemoryRegion + 0x24,
                               Cosmic.Pymem.read_int(ByteCodeAddress + 0x14))
        Cosmic.Pymem.write_int(y, NewMemoryRegion)
    return [NewMemoryRegion, ProtectedStringRegion, OriginalByteCode]


def GetScriptByteCode(Script: int) -> str:
    ClassName = GetClassName(Script)
    if ClassName == "LocalScript":
        return GetByteCode(GetByteCodeAddress(Script))
    if ClassName == "ModuleScript":
        return GetByteCode(GetByteCodeAddress(Script))


def GetIdentity(LuaState: int) -> int:
    SharedMemory = Cosmic.DRP(LuaState + RobloxExtraSpace_Offset)
    Identity = SharedMemory + Identity_Offset
    return Cosmic.Pymem.read_int(Identity)


def SetIdentity(LuaState: int, Level: int):
    SharedMemory = Cosmic.DRP(LuaState + RobloxExtraSpace_Offset)
    Identity = SharedMemory + Identity_Offset
    Cosmic.Pymem.write_int(Identity, Level)


def CompileToRobloxByteCode(RobloxLuaStringSource: str) -> str:
    Source = RobloxLuaStringSource
    CompilerDIR = os.getenv("userprofile")+"\\Desktop\\rbxcompile.exe"
    InputFileDIR = os.getenv("userprofile")+"\\Desktop\\input.luau"
    OutputFileDIR = os.getenv("userprofile")+"\\Desktop\\output.encrbxluauc"
    InputFile = open(InputFileDIR, "w")
    InputFile.write(Source)
    InputFile.close()
    os.system("cd " + os.getenv("userprofile")+"\\Desktop & " + CompilerDIR)
    OutputFile = open(OutputFileDIR, "rb")
    RawCompiledByteCode = OutputFile.read()
    HexCompiledByteCode = RawCompiledByteCode.hex()
    OutputFile.close()
    return HexCompiledByteCode


def GetState() -> int:
    if not GetDataModelFromNetPeerSend():
        return None
    NewMemory = Cosmic.Pymem.allocate(100)
    Argument = NewMemory + 0x40
    Mov_ECX_ScriptContext = "B9" + Cosmic.hex2le(GetService("ScriptContext"))
    Push_Arg1 = "68" + Cosmic.hex2le(Argument)
    Push_Arg2 = "68" + Cosmic.hex2le(Argument)
    Call_GetState_Function = "E8" + Cosmic.hex2le(Cosmic.calcjmpop(
        Cosmic.getAddressFromName(GetStateFunctionAddress), NewMemory + 15))
    Mov_Base_Eax = "A3" + Cosmic.hex2le(NewMemory + 0x30)
    Ret = "C3"
    FullHexString = Mov_ECX_ScriptContext + Push_Arg1 + \
        Push_Arg2 + Call_GetState_Function + Mov_Base_Eax + Ret
    Cosmic.Pymem.write_bytes(NewMemory, bytes.fromhex(
        FullHexString), Cosmic.gethexc(FullHexString))
    Cosmic.Pymem.start_thread(NewMemory)
    ReturnValue = Cosmic.Pymem.read_int(NewMemory + 0x30)
    Cosmic.Pymem.free(NewMemory)
    return ReturnValue


def LuaVMLoad(LuaState: int, ByteCodeAddress: int, ChunkName: str, ENV_Optional="00") -> bool:
    NewMemory = Cosmic.Pymem.allocate(100)
    ChunkNameAddress = Cosmic.Pymem.allocate(len(ChunkName) + 20)
    Cosmic.Pymem.write_string(ChunkNameAddress, ChunkName)
    Mov_ECX_LuaState = "B9" + Cosmic.hex2le(LuaState)
    Mov_EDX_ByteCodeAddress = "BA" + Cosmic.hex2le(ByteCodeAddress)
    Push_ENV_Optional = "6A" + ENV_Optional
    Push_ChunkNameAddress = "68" + Cosmic.hex2le(ChunkNameAddress)
    Call_LuaVMLoad = "E8" + Cosmic.hex2le(Cosmic.calcjmpop(
        Cosmic.getAddressFromName(LuaVMLoadFunctionAddress), NewMemory + 0x11))
    Add_ESP_8 = "83 C4 08"
    Ret = "C3"
    FullHexString = Mov_ECX_LuaState + Mov_EDX_ByteCodeAddress + \
        Push_ENV_Optional + Push_ChunkNameAddress + Call_LuaVMLoad + Add_ESP_8 + Ret
    Cosmic.Pymem.write_bytes(NewMemory, bytes.fromhex(
        FullHexString), Cosmic.gethexc(FullHexString))
    Cosmic.Pymem.start_thread(NewMemory)
    Cosmic.Pymem.free(NewMemory)
    return True

def Task_Defer(LuaState: int) -> bool:
    NewMemory = Cosmic.Pymem.allocate(100)
    Push_LuaState = "68" + Cosmic.hex2le(LuaState)
    Call_Task_Defer = "E8" + Cosmic.hex2le(Cosmic.calcjmpop(
        Cosmic.getAddressFromName(Task_Defer_FunctionAddress), NewMemory + 0x5))
    Add_ESP_4 = "83 C4 04"
    Ret = "C3"
    FullHexString = Push_LuaState + Call_Task_Defer + Add_ESP_4 + Ret
    Cosmic.Pymem.write_bytes(NewMemory, bytes.fromhex(
        FullHexString), Cosmic.gethexc(FullHexString))
    Cosmic.Pymem.start_thread(NewMemory)
    Cosmic.Pymem.free(NewMemory)
    return True

def ByteCodeExecution(ScriptSource: str, Identity: int = 6):
    try:
        if not GetDataModelFromNetPeerSend():
            return None
        LuaState = GetState()
        Original = Cosmic.Pymem.read_int(LuaState + Lua_Top)
        RobloxSourceToExecute = "spawn(function() " + ScriptSource + " end)"
        SetIdentity(LuaState, Identity)
        HexStringDataOfByteCode = CompileToRobloxByteCode(RobloxSourceToExecute)
        ByteCodeAddress = MakeByteCodeAddress(HexStringDataOfByteCode)
        LuaVMLoad(LuaState, ByteCodeAddress, "=bCosmic")
        Task_Defer(LuaState)
        Cosmic.Pymem.write_int(LuaState + Lua_Top, Original)

        # Restore Lua Stack Top
        Cosmic.Pymem.write_int(LuaState + Lua_Top, Original)

    except pymem.exception.MemoryWriteError as e:
        print(f"Memory write error at address {e.address}: {e.error_code}")
    except Exception as e:
        print(f"An error occurred: {e}")

def ByteCodeExecutionRunByteCode(ByteCodeAddress: int, Identity=6):
    LuaState = GetState()
    Original = Cosmic.Pymem.read_int(LuaState + Lua_Top)
    SetIdentity(LuaState, Identity)
    LuaVMLoad(LuaState, ByteCodeAddress, "=bCosmic")
    Task_Defer(LuaState)
    Cosmic.Pymem.write_int(LuaState + Lua_Top, Original)

def CheckSyntax(lua_code):
    try:
        result = subprocess.check_output(['lua', '-e', lua_code], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return e.output.decode()
    return None

def ExtractLoadstring(source: str) -> str:
    pos = source.find('loadstring')
    if pos == -1:
        return None
    start = source.find('(', pos)
    if start == -1:
        return None
    end = start
    count = 0
    while end < len(source):
        if source[end] == '(':
            count += 1
        elif source[end] == ')':
            count -= 1
            if count == 0:
                break
        end += 1
    if count != 0:
        return None
    content = source[start+1:end]
    if content.startswith('"') and content.endswith('"'):
        content = content[1:-1]
    return content

def ExtractHttpGet(source: str) -> str:
    pos = source.find('game:HttpGet')
    if pos == -1:
        return None
    start = source.find('(', pos)
    if start == -1:
        return None
    end = start
    count = 0
    while end < len(source):
        if source[end] == '(':
            count += 1
        elif source[end] == ')':
            count -= 1
            if count == 0:
                break
        end += 1
    if count != 0:
        return None 
    content = source[start+1:end]
    if content.startswith('"') and content.endswith('"'):
        content = content[1:-1]
    return content

def rloadstring(RobloxLuaStringSource: str):
    if "loadstring" in RobloxLuaStringSource:
        ExtractedLoad = ExtractLoadstring(RobloxLuaStringSource)
        if "game:HttpGet" in ExtractedLoad:
            Url = ExtractHttpGet(ExtractedLoad)
            Url = Url.strip("'\"")
            content_from_url = requests.get(Url).text
            # print(content_from_url)
            RobloxLuaStringSource = f'loadstring("{content_from_url}")'
        else:
            RobloxLuaStringSource = ExtractedLoad

    elif "game:HttpGet" in RobloxLuaStringSource:
        Url = ExtractHttpGet(RobloxLuaStringSource)
        Url = Url.strip("'\"")
        rawUrl = requests.get(Url).text
        print(Url)
        print(rawUrl)
        RobloxLuaStringSource = RobloxLuaStringSource.replace(f'game:HttpGet("{Url}")', f'"{rawUrl}"')

    try:
        ByteCodeExecution(RobloxLuaStringSource)
    except Exception as e:
        print(e)
        return

def Interface(SizeX, SizeY):
    Root.title("Not connected to Roblox client.")
    Root.iconphoto(False, Unattached)
    Root.geometry("300x100")
    Root.maxsize(SizeX, SizeY)
    Root.minsize(SizeX, SizeY)


def CodeBox(PadX, PadY):
    Code.insert(tk.END, "")
    Code.pack(padx=PadX, pady=PadY)


def Messages():
    Header.pack(anchor="nw", padx=15, pady=10)


LuaVMEnvironment = False
global Editor

def LuaPopout():
    global LuaVMEnvironment
    global Editor
    if LuaVMEnvironment == False:
        Popout = tk.Toplevel()
        Popout.title("Lua Environment")
        Popout.iconphoto(False, Lua)
        Popout.geometry("500x500")
        Popout.maxsize(750, 500)
        Popout.minsize(450, 250)

        Editor = tk.Text(Popout)
        Editor.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)

        def Close():
            global LuaVMEnvironment
            LuaVMEnvironment = False
            Popout.destroy()

        Popout.protocol("WM_DELETE_WINDOW", Close)
        LuaVMEnvironment = True


TMMode = False
Settings = False


def Buttons():
    def openSettings():
        global Settings
        if Settings == False:
            Info = tk.Toplevel()
            Info.title("Settings")
            Info.iconphoto(False, Attached)
            Info.geometry("300x300")
            Info.maxsize(200, 50)
            Info.minsize(200, 50)

            def TopMost():
                global TMMode
                TMMode = not TMMode
                Root.attributes("-topmost", TMMode)
                Info.attributes("-topmost", TMMode)

            TopMost = tk.Button(Info, text="Top Most", command=TopMost)
            TopMost.pack(anchor="nw", padx=15, pady=15)

            def Close():
                global Settings
                Settings = False
                Info.destroy()

            Info.protocol("WM_DELETE_WINDOW", Close)
            Settings = True

    SettingsButton = tk.Button(Root, text="Settings", command=openSettings)
    SettingsButton.pack(side=tk.LEFT, padx=20, pady=5)

    def Inject():
        global Injected
        if not Injected:
            Exploit().YieldForProgram("Windows10Universal.exe", True)
            Injected = True
        else:
            print("Cosmic is already injected!")

    Inject = tk.Button(Root, text="Attach", command=Inject)
    Inject.pack(side=tk.LEFT, padx=3.5, pady=5)

    def Execute():
        global Injected
        global LuaVMEnvironment
        if Injected:
            if LuaVMEnvironment == True:
                global Editor
                rloadstring(Editor.get(1.0, "end-1c"))
            else:
                rloadstring(Code.get(1.0, "end-1c"))
        else:
            print("Please attach Cosmic!")

    Execute = tk.Button(Root, text="Execute", command=Execute)
    Execute.pack(side=tk.LEFT, padx=3.5, pady=5)

    def Clear():
        Code.delete('1.0', tk.END)
        Code.insert(tk.END, "")

    Clear = tk.Button(Root, text="Clear", command=Clear)
    Clear.pack(side=tk.LEFT, padx=3.5, pady=5)

    def Unfocus():
        Root.focus_set()

    Unfocus = tk.Button(Root, text="Unfocus", command=Unfocus)
    Unfocus.pack(side=tk.LEFT, padx=3.5, pady=5)

    def Environment():
        LuaPopout()

    Environment = tk.Button(Root, text="Lua Env", command=Environment)
    Environment.pack(side=tk.RIGHT, padx=20, pady=5)


Messages()
CodeBox(0, 0)
Interface(500, 275)
Buttons()
Root.mainloop()
