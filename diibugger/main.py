
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import sys, struct, socket, time, os

import disassemble


class Message:
    DSI = 0
    ISI = 1
    Program = 2
    GetStat = 3
    OpenFile = 4
    ReadFile = 5
    CloseFile = 6
    SetPosFile = 7
    GetStatFile = 8

    Continue = 0
    Step = 1
    StepOver = 2

    def __init__(self, type, data, arg):
        self.type = type
        self.data = data
        self.arg = arg


class EventHolder(QObject):
    Exception = pyqtSignal()
    Connected = pyqtSignal()
    Closed = pyqtSignal()
    BreakPointChanged = pyqtSignal()
    Continue = pyqtSignal()
events = EventHolder()


#I don't want to deal with the whole threading trouble to complete big
#file transfers without the UI becoming unresponsive. There probably is
#a better way to code this, but this is what I came up with.
class TaskMgr:
    def __init__(self):
        self.taskQueue = []

    def add(self, task):
        if not self.taskQueue:
            window.mainWidget.statusWidget.disconnectButton.setEnabled(True)
        self.taskQueue.append(task)

    def pop(self, task):
        assert task == self.taskQueue.pop()

        if not self.taskQueue:
            window.mainWidget.tabWidget.setEnabled(True)
            window.mainWidget.statusWidget.cancelButton.setEnabled(True)
            window.mainWidget.statusWidget.disconnectButton.setEnabled(True)
            window.mainWidget.statusWidget.progressBar.setValue(0)
            window.mainWidget.statusWidget.progressInfo.setText("Connected")
        else:
            self.taskQueue[-1].resume()

    def isBlocking(self):
        if not self.taskQueue:
            return False
        return self.taskQueue[-1].blocking

    def cancel(self):
        self.taskQueue[-1].canceled = True
taskMgr = TaskMgr()


class Task:
    def __init__(self, blocking, cancelable):
        taskMgr.add(self)

        self.canceled = False
        self.blocking = blocking
        self.cancelable = cancelable
        window.mainWidget.tabWidget.setEnabled(not blocking)
        window.mainWidget.statusWidget.cancelButton.setEnabled(cancelable)

    def setInfo(self, info, maxValue):
        self.info = info
        self.maxValue = maxValue
        window.mainWidget.statusWidget.progressInfo.setText(info)
        window.mainWidget.statusWidget.progressBar.setRange(0, maxValue)

    def update(self, progress):
        self.progress = progress
        window.mainWidget.statusWidget.progressBar.setValue(progress)
        app.processEvents()

    def resume(self):
        window.mainWidget.tabWidget.setEnabled(not self.blocking)
        window.mainWidget.statusWidget.cancelButton.setEnabled(self.cancelable)
        window.mainWidget.statusWidget.progressInfo.setText(self.info)
        window.mainWidget.statusWidget.progressBar.setRange(0, self.maxValue)
        window.mainWidget.statusWidget.progressBar.setValue(self.progress)

    def end(self):
        taskMgr.pop(self)


class Thread:

    cores = {
        1: "Core 0",
        2: "Core 1",
        4: "Core 2"
    }

    def __init__(self, data, offs=0):
        self.core = self.cores[struct.unpack_from(">I", data, offs)[0]]
        self.priority = struct.unpack_from(">I", data, offs + 4)[0]
        self.stackBase = struct.unpack_from(">I", data, offs + 8)[0]
        self.stackEnd = struct.unpack_from(">I", data, offs + 12)[0]
        self.entryPoint = struct.unpack_from(">I", data, offs + 16)[0]

        namelen = struct.unpack_from(">I", data, offs + 20)[0]
        self.name = data[offs + 24 : offs + 24 + namelen].decode("ascii")


class DirEntry:
    def __init__(self, flags, size, name):
        self.flags = flags
        self.size = size
        self.name = name

    def isDir(self):
        return self.flags & 0x80000000


class PyBugger:
    def __init__(self):
        super().__init__()
        self.connected = False
        self.breakPoints = []

        self.basePath = b""
        self.currentHandle = 0x12345678
        self.files = {}

        self.messageHandlers = {
            Message.DSI: self.handleException,
            Message.ISI: self.handleException,
            Message.Program: self.handleException,
            Message.GetStat: self.handleGetStat,
            Message.OpenFile: self.handleOpenFile,
            Message.ReadFile: self.handleReadFile,
            Message.CloseFile: self.handleCloseFile,
            Message.SetPosFile: self.handleSetPosFile,
            Message.GetStatFile: self.handleGetStatFile
        }

    def handleException(self, msg):
        exceptionState.load(msg.data, msg.type)
        events.Exception.emit()

    def handleGetStat(self, msg):
        gamePath = msg.data.decode("ascii")
        path = os.path.join(self.basePath, gamePath.strip("/vol"))
        print("GetStat: %s" %gamePath)
        self.sendFileMessage(os.path.getsize(path))

    def handleOpenFile(self, msg):
        mode = struct.pack(">I", msg.arg).decode("ascii").strip("\x00") + "b"
        path = msg.data.decode("ascii")
        print("Open: %s" %path)

        f = open(os.path.join(self.basePath, path.strip("/vol")), mode)
        self.files[self.currentHandle] = f
        self.sendFileMessage(self.currentHandle)
        self.currentHandle += 1

    def handleReadFile(self, msg):
        print("Read")
        task = Task(blocking=False, cancelable=False)
        bufferAddr, size, count, handle = struct.unpack(">IIII", msg.data)

        data = self.files[handle].read(size * count)
        task.setInfo("Sending file", len(data))

        bytesSent = 0
        while bytesSent < len(data):
            length = min(len(data) - bytesSent, 0x8000)
            self.sendall(b"\x03")
            self.sendall(struct.pack(">II", bufferAddr, length))
            self.sendall(data[bytesSent : bytesSent + length])
            bufferAddr += length
            bytesSent += length
            task.update(bytesSent)
        self.sendFileMessage(bytesSent // size)
        task.end()

    def handleCloseFile(self, msg):
        print("Close")
        self.files.pop(msg.arg).close()
        self.sendFileMessage()

    def handleSetPosFile(self, msg):
        print("SetPos")
        handle, pos = struct.unpack(">II", msg.data)
        self.files[handle].seek(pos)
        self.sendFileMessage()

    def handleGetStatFile(self, msg):
        print("GetStatFile")
        f = self.files[msg.arg]
        pos = f.tell()
        f.seek(0, 2)
        size = f.tell()
        f.seek(pos)
        self.sendFileMessage(size)

    def connect(self, host):
        self.s = socket.socket()
        self.s.connect((host, 1559))
        self.connected = True
        self.closeRequest = False
        events.Connected.emit()

    def close(self):
        self.sendall(b"\x01")
        self.s.close()
        self.connected = False
        self.breakPoints = []
        events.Closed.emit()

    def updateMessages(self):
        self.sendall(b"\x07")
        count = struct.unpack(">I", self.recvall(4))[0]
        for i in range(count):
            type, ptr, length, arg = struct.unpack(">IIII", self.recvall(16))
            data = None
            if length:
                data = self.recvall(length)
            self.messageHandlers[type](Message(type, data, arg))

    def read(self, addr, num):
        self.sendall(b"\x02")
        self.sendall(struct.pack(">II", addr, num))
        data = self.recvall(num)
        return data

    def write(self, addr, data):
        self.sendall(b"\x03")
        self.sendall(struct.pack(">II", addr, len(data)))
        self.sendall(data)

    def writeCode(self, addr, instr):
        self.sendall(b"\x04")
        self.sendall(struct.pack(">II", addr, instr))

    def getThreadList(self):
        self.sendall(b"\x05")
        length = struct.unpack(">I", self.recvall(4))[0]
        data = self.recvall(length)

        offset = 0
        threads = []
        while offset < length:
            thread = Thread(data, offset)
            threads.append(thread)
            offset += 24 + len(thread.name)
        return threads

    def toggleBreakPoint(self, addr):
        if addr in self.breakPoints: self.breakPoints.remove(addr)
        else:
            if len(self.breakPoints) >= 10:
                return
            self.breakPoints.append(addr)

        self.sendall(b"\x0A")
        self.sendall(struct.pack(">I", addr))
        events.BreakPointChanged.emit()

    def continueBreak(self): self.sendCrashMessage(Message.Continue)
    def stepBreak(self): self.sendCrashMessage(Message.Step)
    def stepOver(self): self.sendCrashMessage(Message.StepOver)

    def sendCrashMessage(self, message):
        self.sendMessage(message)
        events.Continue.emit()

    def sendMessage(self, message, data0=0, data1=0, data2=0):
        self.sendall(b"\x06")
        self.sendall(struct.pack(">IIII", message, data0, data1, data2))

    def sendFileMessage(self, data0=0, data1=0, data2=0):
        self.sendall(b"\x0F")
        self.sendall(struct.pack(">IIII", 0, data0, data1, data2))

    def getStackTrace(self):
        self.sendall(b"\x08")
        count = struct.unpack(">I", self.recvall(4))[0]
        trace = struct.unpack(">%iI" %count, self.recvall(4 * count))
        return trace

    def pokeExceptionRegisters(self):
        self.sendall(b"\x09")
        data = struct.pack(">32I32d", *exceptionState.gpr, *exceptionState.fpr)
        self.sendall(data)

    def readDirectory(self, path):
        self.sendall(b"\x0B")
        self.sendall(struct.pack(">I", len(path)))
        self.sendall(path.encode("ascii"))

        entries = []
        namelen = struct.unpack(">I", self.recvall(4))[0]
        while namelen != 0:
            flags = struct.unpack(">I", self.recvall(4))[0]

            size = -1
            if not flags & 0x80000000:
                size = struct.unpack(">I", self.recvall(4))[0]

            name = self.recvall(namelen).decode("ascii")
            entries.append(DirEntry(flags, size, name))

            namelen = struct.unpack(">I", self.recvall(4))[0]
        return entries

    def dumpFile(self, gamePath, outPath, task):
        if task.canceled:
            return

        self.sendall(b"\x0C")
        self.sendall(struct.pack(">I", len(gamePath)))
        self.sendall(gamePath.encode("ascii"))

        length = struct.unpack(">I", self.recvall(4))[0]
        task.setInfo("Dumping %s" %gamePath, length)

        with open(outPath, "wb") as f:
            bytesDumped = 0
            while bytesDumped < length:
                data = self.s.recv(length - bytesDumped)
                f.write(data)
                bytesDumped += len(data)
                task.update(bytesDumped)

    def getModuleName(self):
        self.sendall(b"\x0D")
        length = struct.unpack(">I", self.recvall(4))[0]
        return self.recvall(length).decode("ascii") + ".rpx"

    def setPatchFiles(self, fileList, basePath):
        self.basePath = basePath
        self.sendall(b"\x0E")

        fileBuffer = struct.pack(">I", len(fileList))
        for path in fileList:
            fileBuffer += struct.pack(">H", len(path))
            fileBuffer += path.encode("ascii")

        self.sendall(struct.pack(">I", len(fileBuffer)))
        self.sendall(fileBuffer)

    def clearPatchFiles(self):
        self.sendall(b"\x10")

    def sendall(self, data):
        try:
            self.s.sendall(data)
        except socket.error:
            self.connected = False
            events.Closed.emit()

    def recvall(self, num):
        try:
            data = b""
            while len(data) < num:
                data += self.s.recv(num - len(data))
        except socket.error:
            self.connected = False
            events.Closed.emit()
            return b"\x00" * num

        return data


class HexSpinBox(QAbstractSpinBox):
    def __init__(self, parent, stepSize = 1):
        super().__init__(parent)
        self._value = 0
        self.stepSize = stepSize

    def validate(self, text, pos):
        if all([char in "0123456789abcdefABCDEF" for char in text]):
            if not text:
                return QValidator.Intermediate, text.upper(), pos

            value = int(text, 16)
            if value <= 0xFFFFFFFF:
                self._value = value
                if value % self.stepSize:
                    self._value -= value % self.stepSize
                    return QValidator.Acceptable, text.upper(), pos
                return QValidator.Acceptable, text.upper(), pos

        return QValidator.Invalid, text.upper(), pos

    def stepBy(self, steps):
        self._value = min(max(self._value + steps * self.stepSize, 0), 0x100000000 - self.stepSize)
        self.lineEdit().setText("%X" %self._value)

    def stepEnabled(self):
        return QAbstractSpinBox.StepUpEnabled | QAbstractSpinBox.StepDownEnabled

    def setValue(self, value):
        self._value = value
        self.lineEdit().setText("%X" %self._value)

    def value(self):
        return self._value


class ExceptionState:

    exceptionNames = ["DSI", "ISI", "Program"]

    def load(self, context, type):
        #Convert tuple to list to make it mutable
        self.gpr = list(struct.unpack_from(">32I", context, 8))
        self.cr, self.lr, self.ctr, self.xer = struct.unpack_from(">4I", context, 0x88)
        self.srr0, self.srr1, self.ex0, self.ex1 = struct.unpack_from(">4I", context, 0x98)
        self.fpr = list(struct.unpack_from(">32d", context, 0xB8))
        self.gqr = list(struct.unpack_from(">8I", context, 0x1BC))
        self.psf = list(struct.unpack_from(">32d", context, 0x1E0))

        self.exceptionName = self.exceptionNames[type]

    def isBreakPoint(self):
        return self.exceptionName == "Program" and self.srr1 & 0x20000


def format_hex(blob, offs):
    return "%02X" %blob[offs]

def format_ascii(blob, offs):
    if 0x30 <= blob[offs] <= 0x39 or 0x41 <= blob[offs] <= 0x5A or 0x61 <= blob[offs] <= 0x7A:
        return chr(blob[offs])
    return "?"

def format_float(blob, offs):
    value = struct.unpack_from(">f", blob, offs)[0]
    if abs(value) >= 1000000 or 0 < abs(value) < 0.000001:
        return "%e" %value
    return ("%.8f" %value).rstrip("0")


class MemoryViewer(QWidget):

    class Format:
        Hex = 0
        Ascii = 1
        Float = 2

    Width = 1, 1, 4
    Funcs = format_hex, format_ascii, format_float

    def __init__(self, parent):
        super().__init__(parent)

        self.layout = QGridLayout()

        for i in range(16):
            self.layout.addWidget(QLabel("%X" %i, self), 0, i + 1)
        self.addrLabels = []
        for i in range(16):
            label = QLabel("%X" %(i * 0x10), self)
            self.layout.addWidget(label, i + 1, 0)
            self.addrLabels.append(label)
        self.dataCells = []

        self.base = 0
        self.format = self.Format.Hex
        self.updateData()

        self.setLayout(self.layout)

        events.Connected.connect(self.connected)

    def connected(self):
        self.setBase(0x10000000)

    def setFormat(self, format):
        self.format = format
        self.updateData()

    def setBase(self, base):
        window.mainWidget.tabWidget.memoryTab.memoryInfo.baseBox.setValue(base)
        self.base = base
        for i in range(16):
            self.addrLabels[i].setText("%X" %(self.base + i * 0x10))
        self.updateData()

    def updateData(self):
        for cell in self.dataCells:
            self.layout.removeWidget(cell)
            cell.setParent(None)

        if bugger.connected:
            blob = bugger.read(self.base, 0x100)
        else:
            blob = b"\x00" * 0x100

        width = self.Width[self.format]
        func = self.Funcs[self.format]
        for i in range(16 // width):
            for j in range(16):
                label = QLabel(func(blob, j * 0x10 + i * width), self)
                self.layout.addWidget(label, j + 1, i * width + 1, 1, width)
                self.dataCells.append(label)


class MemoryInfo(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.dataTypeLabel = QLabel("Data type:")
        self.dataTypeBox = QComboBox(self)
        self.dataTypeBox.addItems(["Hex", "Ascii", "Float"])
        self.dataTypeBox.currentIndexChanged.connect(self.updateDataType)

        self.baseLabel = QLabel("Address:")
        self.baseBox = HexSpinBox(self, 0x10)
        self.baseButton = QPushButton("Update", self)
        self.baseButton.clicked.connect(self.updateMemoryBase)

        self.pokeAddr = HexSpinBox(self, 4)
        self.pokeValue = HexSpinBox(self)
        self.pokeButton = QPushButton("Poke", self)
        self.pokeButton.clicked.connect(self.pokeMemory)

        self.layout = QGridLayout()
        self.layout.addWidget(self.baseLabel, 0, 0)
        self.layout.addWidget(self.baseBox, 0, 1)
        self.layout.addWidget(self.baseButton, 0, 2)
        self.layout.addWidget(self.pokeAddr, 1, 0)
        self.layout.addWidget(self.pokeValue, 1, 1)
        self.layout.addWidget(self.pokeButton, 1, 2)
        self.layout.addWidget(self.dataTypeLabel, 2, 0)
        self.layout.addWidget(self.dataTypeBox, 2, 1, 1, 2)
        self.setLayout(self.layout)

    def updateDataType(self, index):
        window.mainWidget.tabWidget.memoryTab.memoryViewer.setFormat(index)

    def updateMemoryBase(self):
        window.mainWidget.tabWidget.memoryTab.memoryViewer.setBase(self.baseBox.value())

    def pokeMemory(self):
        bugger.write(self.pokeAddr.value(), struct.pack(">I", self.pokeValue.value()))
        window.mainWidget.tabWidget.memoryTab.memoryViewer.updateData()


class MemoryTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.memoryInfo = MemoryInfo(self)
        self.memoryViewer = MemoryViewer(self)
        self.layout = QHBoxLayout()
        self.layout.addWidget(self.memoryInfo)
        self.layout.addWidget(self.memoryViewer)
        self.button = QPushButton("Dump", self)
        self.button.clicked.connect(self.dump)
        self.setLayout(self.layout)

    def dump(self):
        dumpStart = 0x1AB00000
        dumpLength = 0x600000
        dumpFile = "dump.bin"
        with open(dumpFile, 'wb') as f:
            f.write(bugger.read(dumpStart, dumpLength))

class DisassemblyWidget(QTextEdit):
    def __init__(self, parent):
        super().__init__(parent)
        self.setTextInteractionFlags(Qt.NoTextInteraction)

        self.currentInstruction = None
        self.selectedAddress = 0
        self.setBase(0)

        events.BreakPointChanged.connect(self.updateHighlight)
        events.Continue.connect(self.handleContinue)

    def handleContinue(self):
        self.currentInstruction = None
        self.updateHighlight()

    def setCurrentInstruction(self, instr):
        self.currentInstruction = instr
        self.setBase(instr - 0x20)

    def setBase(self, base):
        self.base = base
        self.updateText()
        self.updateHighlight()

    def updateText(self):
        if bugger.connected:
            blob = bugger.read(self.base, 0x60)
        else:
            blob = b"\x00" * 0x60

        text = ""
        for i in range(24):
            address = self.base + i * 4
            value = struct.unpack_from(">I", blob, i * 4)[0]
            instr = disassemble.disassemble(value, address)
            text += "%08X:  %08X  %s\n" %(address, value, instr)
        self.setPlainText(text)

    def updateHighlight(self):
        selections = []
        for i in range(24):
            address = self.base + i * 4

            color = self.getColor(address)
            if color:
                cursor = self.textCursor()
                cursor.movePosition(QTextCursor.Down, n=i)
                cursor.select(QTextCursor.LineUnderCursor)
                format = QTextCharFormat()
                format.setBackground(QBrush(QColor(color)))
                selection = QTextEdit.ExtraSelection()
                selection.cursor = cursor
                selection.format = format
                selections.append(selection)
        self.setExtraSelections(selections)

    def getColor(self, addr):
        colors = []
        if addr in bugger.breakPoints:
            colors.append((255, 0, 0))
        if addr == self.currentInstruction:
            colors.append((0, 255, 0))
        if addr == self.selectedAddress:
            colors.append((0, 0, 255))

        if not colors:
            return None

        color = [sum(l)//len(colors) for l in zip(*colors)]
        return "#%02X%02X%02X" %tuple(color)

    def mousePressEvent(self, e):
        super().mousePressEvent(e)
        line = self.cursorForPosition(e.pos()).blockNumber()
        self.selectedAddress = self.base + line * 4
        if e.button() == Qt.MidButton:
            bugger.toggleBreakPoint(self.selectedAddress)
        self.updateHighlight()


class DisassemblyInfo(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.baseLabel = QLabel("Address:")
        self.baseBox = HexSpinBox(self, 4)
        self.baseButton = QPushButton("Update", self)
        self.baseButton.clicked.connect(self.updateDisassemblyBase)

        self.pokeBox = HexSpinBox(self)
        self.pokeButton = QPushButton("Poke", self)
        self.pokeButton.clicked.connect(self.poke)

        self.layout = QGridLayout()
        self.layout.addWidget(self.baseLabel, 0, 0)
        self.layout.addWidget(self.baseBox, 0, 1)
        self.layout.addWidget(self.baseButton, 0, 2)
        self.layout.addWidget(self.pokeBox, 1, 0)
        self.layout.addWidget(self.pokeButton, 1, 1, 1, 2)
        self.setLayout(self.layout)
        self.setMinimumWidth(300)

    def updateDisassemblyBase(self):
        window.mainWidget.tabWidget.disassemblyTab.disassemblyWidget.setBase(self.baseBox.value())

    def poke(self):
        disassembly = window.mainWidget.tabWidget.disassemblyTab.disassemblyWidget
        if disassembly.selectedAddress:
            bugger.writeCode(disassembly.selectedAddress, self.pokeBox.value())
            disassembly.updateText()


class DisassemblyTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.disassemblyInfo = DisassemblyInfo(self)
        self.disassemblyWidget = DisassemblyWidget(self)
        self.layout = QHBoxLayout()
        self.layout.addWidget(self.disassemblyInfo)
        self.layout.addWidget(self.disassemblyWidget)
        self.setLayout(self.layout)

        events.Connected.connect(self.connected)

    def connected(self):
        self.disassemblyWidget.setBase(0x10000000)


class ThreadList(QTableWidget):
    def __init__(self, parent):
        super().__init__(0, 5, parent)
        self.setHorizontalHeaderLabels(["Name", "Priority", "Core", "Stack", "Entry Point"])
        self.setEditTriggers(self.NoEditTriggers)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        events.Connected.connect(self.updateThreads)

    def updateThreads(self):
        threads = bugger.getThreadList()
        self.setRowCount(len(threads))
        for i in range(len(threads)):
            thread = threads[i]
            self.setItem(i, 0, QTableWidgetItem(thread.name))
            self.setItem(i, 1, QTableWidgetItem(str(thread.priority)))
            self.setItem(i, 2, QTableWidgetItem(thread.core))
            self.setItem(i, 3, QTableWidgetItem("0x%x - 0x%x" %(thread.stackEnd, thread.stackBase)))
            self.setItem(i, 4, QTableWidgetItem(hex(thread.entryPoint)))


class ThreadingTab(QTableWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.threadList = ThreadList(self)
        self.updateButton = QPushButton("Update", self)
        self.updateButton.clicked.connect(self.threadList.updateThreads)
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.threadList)
        self.layout.addWidget(self.updateButton)
        self.setLayout(self.layout)


class BreakPointList(QListWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.itemDoubleClicked.connect(self.goToDisassembly)
        events.BreakPointChanged.connect(self.updateList)

    def updateList(self):
        self.clear()
        for bp in bugger.breakPoints:
            self.addItem("0x%08X" %bp)

    def goToDisassembly(self, item):
        address = bugger.breakPoints[self.row(item)]
        window.mainWidget.tabWidget.disassemblyTab.disassemblyWidget.setBase(address)
        window.mainWidget.tabWidget.setCurrentIndex(1)


class BreakPointTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.list = BreakPointList(self)
        self.button = QPushButton("Remove", self)
        self.button.clicked.connect(self.removeBreakPoint)
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.list)
        self.layout.addWidget(self.button)
        self.setLayout(self.layout)

    def removeBreakPoint(self):
        if self.list.currentRow() != -1:
            bugger.toggleBreakPoint(bugger.breakPoints[self.list.currentRow()])


class RegisterTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.gprLabels = []
        self.gprBoxes = []
        self.fprLabels = []
        self.fprBoxes = []
        for i in range(32):
            self.gprLabels.append(QLabel("r%i" %i, self))
            self.fprLabels.append(QLabel("f%i" % i, self))
            gprBox = HexSpinBox(self)
            fprBox = QDoubleSpinBox(self)
            fprBox.setRange(float("-inf"), float("inf"))
            self.gprBoxes.append(gprBox)
            self.fprBoxes.append(fprBox)

        self.layout = QGridLayout()
        for i in range(32):
            self.layout.addWidget(self.gprLabels[i], i % 16, i // 16 * 2)
            self.layout.addWidget(self.gprBoxes[i], i % 16, i // 16 * 2 + 1)
            self.layout.addWidget(self.fprLabels[i], i % 16, i // 16 * 2 + 4)
            self.layout.addWidget(self.fprBoxes[i], i % 16, i // 16 * 2 + 5)
        self.setLayout(self.layout)

        self.pokeButton = QPushButton("Poke", self)
        self.resetButton = QPushButton("Reset", self)
        self.pokeButton.clicked.connect(self.pokeRegisters)
        self.resetButton.clicked.connect(self.updateRegisters)
        self.layout.addWidget(self.pokeButton, 16, 0, 1, 4)
        self.layout.addWidget(self.resetButton, 16, 4, 1, 4)

        self.setEditEnabled(False)

        events.Exception.connect(self.exceptionOccurred)
        events.Continue.connect(lambda: self.setEditEnabled(False))

    def setEditEnabled(self, enabled):
        for i in range(32):
            self.gprBoxes[i].setEnabled(enabled)
            self.fprBoxes[i].setEnabled(enabled)
        self.pokeButton.setEnabled(enabled)
        self.resetButton.setEnabled(enabled)

    def exceptionOccurred(self):
        self.updateRegisters()
        self.setEditEnabled(exceptionState.isBreakPoint())

    def updateRegisters(self):
        for i in range(32):
            self.gprBoxes[i].setValue(exceptionState.gpr[i])
            self.fprBoxes[i].setValue(exceptionState.fpr[i])

    def pokeRegisters(self):
        for i in range(32):
            exceptionState.gpr[i] = self.gprBoxes[i].value()
            exceptionState.fpr[i] = self.fprBoxes[i].value()
        bugger.pokeExceptionRegisters()


class ExceptionInfo(QGroupBox):
    def __init__(self, parent):
        super().__init__("Info", parent)
        self.typeLabel = QLabel(self)
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.typeLabel)
        self.setLayout(self.layout)

        events.Exception.connect(self.updateInfo)

    def updateInfo(self):
        self.typeLabel.setText("Type: %s" %exceptionState.exceptionName)


class SpecialRegisters(QGroupBox):
    def __init__(self, parent):
        super().__init__("Special registers", parent)
        self.cr = QLabel(self)
        self.lr = QLabel(self)
        self.ctr = QLabel(self)
        self.xer = QLabel(self)
        self.srr0 = QLabel(self)
        self.srr1 = QLabel(self)
        self.ex0 = QLabel(self)
        self.ex1 = QLabel(self)

        self.layout = QHBoxLayout()
        self.userLayout = QFormLayout()
        self.kernelLayout = QFormLayout()

        self.userLayout.addRow("CR:", self.cr)
        self.userLayout.addRow("LR:", self.lr)
        self.userLayout.addRow("CTR:", self.ctr)
        self.userLayout.addRow("XER:", self.xer)

        self.kernelLayout = QFormLayout()
        self.kernelLayout.addRow("SRR0:", self.srr0)
        self.kernelLayout.addRow("SRR1:", self.srr1)
        self.kernelLayout.addRow("EX0:", self.ex0)
        self.kernelLayout.addRow("EX1:", self.ex1)

        self.layout.addLayout(self.userLayout)
        self.layout.addLayout(self.kernelLayout)
        self.setLayout(self.layout)

        events.Exception.connect(self.updateRegisters)

    def updateRegisters(self):
        self.cr.setText("%X" %exceptionState.cr)
        self.lr.setText("%X" %exceptionState.lr)
        self.ctr.setText("%X" %exceptionState.ctr)
        self.xer.setText("%X" %exceptionState.xer)
        self.srr0.setText("%X" %exceptionState.srr0)
        self.srr1.setText("%X" %exceptionState.srr1)
        self.ex0.setText("%X" %exceptionState.ex0)
        self.ex1.setText("%X" %exceptionState.ex1)


class ExceptionInfoTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.exceptionInfo = ExceptionInfo(self)
        self.specialRegisters = SpecialRegisters(self)
        self.layout = QGridLayout()
        self.layout.addWidget(self.exceptionInfo, 0, 0)
        self.layout.addWidget(self.specialRegisters, 0, 1)
        self.setLayout(self.layout)


class StackTrace(QListWidget):
    def __init__(self, parent):
        super().__init__(parent)
        events.Exception.connect(self.updateTrace)

    def updateTrace(self):
        self.clear()
        stackTrace = bugger.getStackTrace()
        for address in (exceptionState.srr0, exceptionState.lr) + stackTrace:
            self.addItem("%X" %address)


class BreakPointActions(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.continueButton = QPushButton("Continue", self)
        self.stepButton = QPushButton("Step", self)
        self.stepOverButton = QPushButton("Step over", self)
        self.continueButton.clicked.connect(bugger.continueBreak)
        self.stepButton.clicked.connect(bugger.stepBreak)
        self.stepOverButton.clicked.connect(bugger.stepOver)

        self.layout = QHBoxLayout()
        self.layout.addWidget(self.continueButton)
        self.layout.addWidget(self.stepButton)
        self.layout.addWidget(self.stepOverButton)
        self.setLayout(self.layout)

        events.Exception.connect(self.updateButtons)
        events.Continue.connect(self.disableButtons)

    def disableButtons(self):
        self.setButtonsEnabled(False)

    def updateButtons(self):
        self.setButtonsEnabled(exceptionState.isBreakPoint())

    def setButtonsEnabled(self, enabled):
        self.continueButton.setEnabled(enabled)
        self.stepButton.setEnabled(enabled)
        self.stepOverButton.setEnabled(enabled)


class StackTraceTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.stackTrace = StackTrace(self)
        self.disassembly = DisassemblyWidget(self)
        self.breakPointActions = BreakPointActions(self)
        self.layout = QVBoxLayout()
        hlayout = QHBoxLayout()
        hlayout.addWidget(self.stackTrace)
        hlayout.addWidget(self.disassembly)
        self.layout.addLayout(hlayout)
        self.layout.addWidget(self.breakPointActions)
        self.setLayout(self.layout)

        self.stackTrace.itemDoubleClicked.connect(self.jumpDisassembly)
        events.Exception.connect(self.exceptionOccurred)

    def exceptionOccurred(self):
        self.disassembly.setCurrentInstruction(exceptionState.srr0)

    def jumpDisassembly(self, item):
        self.disassembly.setBase(int(item.text(), 16) - 0x20)


class ExceptionTab(QTabWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.infoTab = ExceptionInfoTab(self)
        self.registerTab = RegisterTab(self)
        self.stackTab = StackTraceTab(self)
        self.addTab(self.infoTab, "General")
        self.addTab(self.registerTab, "Registers")
        self.addTab(self.stackTab, "Stack trace")

        events.Exception.connect(self.exceptionOccurred)

    def exceptionOccurred(self):
        self.setCurrentIndex(2)  #Stack trace


def formatFileSize(size):
    if size >= 1024 ** 3:
        return "%.1f GiB" %(size / (1024 ** 3))
    if size >= 1024 ** 2:
        return "%.1f MiB" %(size / (1024 ** 2))
    if size >= 1024:
        return "%.1f KiB" %(size / 1024)
    return "%i B" %size

class FileTreeNode(QTreeWidgetItem):
    def __init__(self, parent, name, size, path):
        super().__init__(parent)
        self.name = name
        self.size = size
        self.path = path

        self.setText(0, name)
        if size == -1: #It's a folder
            self.loaded = False
        else: #It's a file
            self.setText(1, formatFileSize(size))
            self.loaded = True

    def loadChildren(self):
        if not self.loaded:
            for i in range(self.childCount()):
                child = self.child(i)
                if not child.loaded:
                    self.child(i).loadContent()
            self.loaded = True

    def loadContent(self):
        entries = bugger.readDirectory(self.path)
        for entry in entries:
            FileTreeNode(self, entry.name, entry.size, self.path + "/" + entry.name)

    def dump(self, outdir, task):
        if task.canceled:
            return

        outpath = os.path.join(outdir, self.name)
        if self.size == -1:
            if os.path.isfile(outpath):
                os.remove(outpath)
            if not os.path.exists(outpath):
                os.mkdir(outpath)

            self.loadChildren()
            for i in range(self.childCount()):
                self.child(i).dump(outpath, task)
        else:
            bugger.dumpFile(self.path, outpath, task)


class FileTreeWidget(QTreeWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setHeaderLabels(["Name", "Size"])
        self.itemExpanded.connect(self.handleItemExpanded)
        events.Connected.connect(self.initFileTree)

    def initFileTree(self):
        self.clear()
        rootItem = FileTreeNode(self, "content", -1, "/vol/content")
        rootItem.loadContent()
        self.resizeColumnToContents(0)

    def handleItemExpanded(self, item):
        item.loadChildren()
        self.resizeColumnToContents(0)


class FileSystemTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.fileTree = FileTreeWidget(self)
        self.dumpButton = QPushButton("Dump", self)
        self.dumpButton.clicked.connect(self.dump)
        self.patchButton = QPushButton("Load patch", self)
        self.patchButton.clicked.connect(self.loadPatch)
        self.clearButton = QPushButton("Clear patch", self)
        self.clearButton.clicked.connect(self.clearPatch)
        self.clearButton.setEnabled(True)

        self.layout = QVBoxLayout()
        hlayout = QHBoxLayout()
        hlayout.addWidget(self.dumpButton)
        hlayout.addWidget(self.patchButton)
        hlayout.addWidget(self.clearButton)
        self.layout.addWidget(self.fileTree)
        self.layout.addLayout(hlayout)
        self.setLayout(self.layout)

    def dump(self):
        item = self.fileTree.currentItem()
        if item:
            outdir = QFileDialog.getExistingDirectory(self, "Dump")
            if outdir:
                task = Task(blocking=True, cancelable=True)
                item.dump(outdir, task)
                task.end()

    def loadPatch(self):
        patchDir = QFileDialog.getExistingDirectory(self, "Load patch")
        if patchDir:
            baseLength = len(patchDir)
            fileList = []
            for dirname, subdirs, files in os.walk(patchDir):
                for filename in files:
                    gamePath = "/vol" + dirname[baseLength:].replace("\\", "/") + "/" + filename
                    fileList.append(gamePath)

            bugger.setPatchFiles(fileList, patchDir)
            self.clearButton.setEnabled(True)

    def clearPatch(self):
        bugger.clearPatchFiles()
        self.clearButton.setEnabled(True)


class DebuggerTabs(QTabWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.memoryTab = MemoryTab(self)
        self.disassemblyTab = DisassemblyTab(self)
        self.threadingTab = ThreadingTab(self)
        self.breakPointTab = BreakPointTab(self)
        self.exceptionTab = ExceptionTab(self)
        self.fileSystemTab = FileSystemTab(self)
        self.addTab(self.memoryTab, "Memory")
        self.addTab(self.disassemblyTab, "Disassembly")
        self.addTab(self.threadingTab, "Threads")
        self.addTab(self.breakPointTab, "Breakpoints")
        self.addTab(self.exceptionTab, "Exceptions")
        self.addTab(self.fileSystemTab, "File System")
        self.setTabEnabled(4, True)

        events.Exception.connect(self.exceptionOccurred)
        events.Connected.connect(self.connected)
        events.Closed.connect(self.disconnected)

    def exceptionOccurred(self):
        self.setTabEnabled(4, True)
        self.setCurrentIndex(4) #Exceptions

    def connected(self):
        self.setEnabled(True)

    def disconnected(self):
        self.setEnabled(True)
        self.setTabEnabled(4, True)


class StatusWidget(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.serverLabel = QLabel("Wii U IP:")
        self.serverBox = QLineEdit(self)
        self.serverBox.returnPressed.connect(self.connect)
        self.connectButton = QPushButton("Connect", self)
        self.connectButton.clicked.connect(self.connect)
        self.disconnectButton = QPushButton("Disconnect", self)
        self.disconnectButton.clicked.connect(bugger.close)
        self.disconnectButton.setEnabled(True)

        self.progressBar = QProgressBar(self)
        self.progressInfo = QLabel("Disconnected", self)
        self.cancelButton = QPushButton("Cancel", self)
        self.cancelButton.clicked.connect(taskMgr.cancel)
        self.cancelButton.setEnabled(True)

        self.layout = QGridLayout()
        self.layout.addWidget(self.serverLabel, 0, 0)
        self.layout.addWidget(self.serverBox, 1, 0)
        self.layout.addWidget(self.connectButton, 0, 1)
        self.layout.addWidget(self.disconnectButton, 1, 1)
        self.layout.addWidget(self.progressBar, 2, 0)
        self.layout.addWidget(self.cancelButton, 2, 1)
        self.layout.addWidget(self.progressInfo, 3, 0, 1, 2)
        self.setLayout(self.layout)

        events.Connected.connect(self.connected)
        events.Closed.connect(self.disconnected)

    def connect(self):
        try: bugger.connect(str(self.serverBox.text()))
        except: pass

    def connected(self):
        self.progressInfo.setText("Connected")
        self.connectButton.setEnabled(True)
        self.serverBox.setEnabled(True)
        self.disconnectButton.setEnabled(True)

    def disconnected(self):
        self.progressInfo.setText("Disconnected")
        self.connectButton.setEnabled(True)
        self.serverBox.setEnabled(True)
        self.disconnectButton.setEnabled(True)


class MainWidget(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.tabWidget = DebuggerTabs(self)
        self.statusWidget = StatusWidget(self)
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.tabWidget)
        self.layout.addWidget(self.statusWidget)
        self.tabWidget.setEnabled(True)
        self.setLayout(self.layout)


class MainWindow(QMainWindow):
    def init(self):
        self.mainWidget = MainWidget(self)
        self.setCentralWidget(self.mainWidget)

        self.setWindowTitle("DiiBugger")
        self.resize(1080, 720)

        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.updateBugger)
        self.timer.start()

        events.Connected.connect(self.updateTitle)
        events.Closed.connect(self.updateTitle)

    def updateTitle(self):
        if bugger.connected:
            name = bugger.getModuleName()
            self.setWindowTitle("DiiBugger - %s" %name)
        else:
            self.setWindowTitle("DiiBugger")

    def updateBugger(self):
        if bugger.connected and not taskMgr.isBlocking():
            bugger.updateMessages()

    def closeEvent(self, e):
        if taskMgr.taskQueue:
            e.ignore()
        else:
            e.accept()


exceptionState = ExceptionState()
bugger = PyBugger()
app = QApplication(sys.argv)
app.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
window = MainWindow()
window.init()
window.show()
app.exec()
if bugger.connected:
    bugger.close()
