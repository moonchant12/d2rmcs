package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	ntdll "github.com/hillu/go-ntdll"
	"golang.org/x/sys/windows"
)

var (
	version string
	info    string
	silent  bool
	verbose bool
	test    bool
	power   bool
)

func init() {
	flag.BoolVar(&silent, "y", false, "Skip prompts")
	flag.BoolVar(&verbose, "v", false, "Verbose")
	flag.BoolVar(&test, "t", false, "Do not close anything")
	flag.BoolVar(&power, "p", false, "Close all Sections, Threads, and BaseNamedObjects Events")
	flag.Parse()
}

func main() {
	var fail bool
	defer func(fail *bool) {
		if r := recover(); r != nil {
			if verbose {
				*fail = true
				log.Println("Unexpected error:", r)
			}
		}
		if *fail {
			log.Println("Process failed.")
		} else {
			log.Println("Successfully finished.")
		}
		if !silent {
			log.Println("Press enter to exit...")
			fmt.Scanln()
		}
		if *fail {
			os.Exit(1)
		}
		os.Exit(0)
	}(&fail)

	if silent {
		log.SetOutput(ioutil.Discard)
	}

	log.Println("d2rmcs", version, info)

	// list processes
	procs, errListProcesses := NewWindowsProcesses()
	if errListProcesses != nil {
		log.Println("Cannot list processes:", errListProcesses)
		fail = true
		return
	}
	if verbose {
		for _, p := range procs {
			log.Printf("[%v] of [%v] \"%v\"\r\n", p.ProcessID, p.ParentProcessID, p.NameExe)
		}
	}

	// detect D2R client
	d2rs := procs.FindProcessesByName("D2R.exe")
	if d2rs == nil || len(d2rs) <= 0 {
		log.Println("Cannot find D2R.exe")
		fail = true
		return
	}

	// iter D2R clients
	for _, d2r := range d2rs {
		log.Printf("Detected client: [%v] of [%v] \"%v\"\r\n", d2r.ProcessID, d2r.ParentProcessID, d2r.NameExe)

		// iter handle infos
		processTarget, errOpenProcess := windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION, false, uint32(d2r.ProcessID))
		if errOpenProcess != nil {
			log.Println(errOpenProcess)
			fail = true
			return
		}
		processCurrent, errGetCurrentProcess := windows.GetCurrentProcess()
		if errGetCurrentProcess != nil {
			log.Println(errGetCurrentProcess)
			fail = true
			return
		}
		handleInfos, errHandleInfos := HandleInfos(uint32(d2r.ProcessID))
		if errHandleInfos != nil {
			log.Println(errHandleInfos)
			fail = true
			return
		}
		for _, handleInfo := range handleInfos {
			if handleName, handleType := handleInfo.ONI.Name.String(), handleInfo.OTI.TypeName.String(); false ||
				strings.Contains(handleName, "windows_shell_global_counters") ||
				strings.Contains(handleName, "DiabloII Check For Other Instances") ||
				(power &&
					((strings.Contains(handleName, "BaseNamedObjects") && handleType == "Event") ||
						handleType == "Section" ||
						handleType == "Thread")) {
				// Necessary: Timer, File, Directory, Key, Event, IoCompletion, ALPC Port, Mutant, Semaphore, TpWorkerFactory, DxgkCompositionObject, DxgkSharedSyncObject
				// Other: WaitCompletionPacket, IRTimer, IoCompletionReserve, Token, Desktop, DxgkSharedResource, WindowStation
				var dupHandle uintptr
				if err := windows.DuplicateHandle(
					processTarget, windows.Handle(handleInfo.SEHTEI.HandleValue),
					processCurrent, (*windows.Handle)(&dupHandle),
					0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
					log.Println(err)
					fail = true
					continue
				}
				if err := windows.CloseHandle(windows.Handle(dupHandle)); err != nil {
					log.Println(err)
					fail = true
					continue
				}
				if test {
					if verbose {
						log.Println("Handle found:", handleInfo)
					}
				} else {
					if err := windows.DuplicateHandle(
						processTarget, windows.Handle(handleInfo.SEHTEI.HandleValue),
						processCurrent, (*windows.Handle)(&dupHandle),
						0, true, windows.DUPLICATE_CLOSE_SOURCE); err != nil {
						log.Println(err)
						fail = true
						return
					}
					if err := windows.CloseHandle(windows.Handle(dupHandle)); err != nil {
						log.Println(err)
						fail = true
						return
					}
					if verbose {
						log.Println("Handle found and closed:", handleInfo)
					}
				}
			}
		}
	}

	// detect Battle.net client
	bnets := procs.FindProcessesByName("Battle.net.exe")
	if bnets == nil || len(bnets) <= 0 {
		log.Println("Cannot find Battle.net.exe")
		return
	}

	// iter Battle.net clients
	for _, bnet := range bnets {
		log.Printf("Detected client: [%v] of [%v] \"%v\"\r\n", bnet.ProcessID, bnet.ParentProcessID, bnet.NameExe)

		if test {
			continue
		}
		if err := exec.Command("taskkill", "/pid", strconv.Itoa(bnet.ProcessID)).Run(); err != nil {
			if verbose {
				log.Printf("Stubborn process: [%v] \"%v\" %v\r\n", bnet.ProcessID, bnet.NameExe, err)
			}
			// fallback: IsProcessCritical() TerminateProcess() of win32api
			hProcess, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(bnet.ProcessID))
			if err != nil {
				if verbose {
					log.Printf("Cannot open process: [%v] \"%v\" %v\r\n", bnet.ProcessID, bnet.NameExe, err)
				}
				fail = true
				continue
			}
			isCritical, err := isProcessCritical(hProcess)
			if err != nil {
				if verbose {
					log.Printf("Cannot determine whether the specified process is critical: [%v] \"%v\" %v\r\n", bnet.ProcessID, bnet.NameExe, err)
				}
				fail = true
				continue
			}
			if isCritical {
				if verbose {
					log.Printf("Skipping critical process: [%v] \"%v\"\r\n", bnet.ProcessID, bnet.NameExe)
				}
				fail = true
				continue
			}
			if err := windows.TerminateProcess(hProcess, uint32(syscall.SIGKILL)); err != nil {
				if verbose {
					log.Printf("Cannot terminate process: [%v] \"%v\" %v\r\n", bnet.ProcessID, bnet.NameExe, err)
				}
				fail = true
				continue
			}
			windows.CloseHandle(hProcess)
			if verbose {
				log.Printf("Forcefully terminated process: [%v] \"%v\"\r\n", bnet.ProcessID, bnet.NameExe)
			}
			continue
		}
		if verbose {
			log.Printf("Gracefully closed task: [%v] \"%v\"\r\n", bnet.ProcessID, bnet.NameExe)
		}
	}

}

type WindowsProcesses []WindowsProcess

// WindowsProcess is a Windows process.
type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	NameExe         string
}

func newWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		NameExe:         syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

// modified a snippet from gopsutil
func PIDs() ([]int32, error) {
	// inspired by https://gist.github.com/henkman/3083408
	// and https://github.com/giampaolo/psutil/blob/1c3a15f637521ba5c0031283da39c733fda53e4c/psutil/arch/windows/process_info.c#L315-L329
	var ret []int32
	var read uint32 = 0
	var psSize uint32 = 1024
	const dwordSize uint32 = 4
	for {
		ps := make([]uint32, psSize)
		if err := windows.EnumProcesses(ps, &read); err != nil {
			return nil, err
		}
		if uint32(len(ps)) == read { // ps buffer was too small to host every results, retry with a bigger one
			psSize += 1024
			continue
		}
		for _, pid := range ps[:read/dwordSize] {
			ret = append(ret, int32(pid))
		}
		return ret, nil
	}
}

func NewWindowsProcesses() (WindowsProcesses, error) {
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(hSnapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = windows.Process32First(hSnapshot, &entry)
	if err != nil {
		return nil, err
	}

	ret := make([]WindowsProcess, 0, 50)
	for {
		ret = append(ret, newWindowsProcess(&entry))
		if err := windows.Process32Next(hSnapshot, &entry); err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if err == syscall.ERROR_NO_MORE_FILES {
				return ret, nil
			}
			return nil, err
		}
	}
}

func (processes WindowsProcesses) FindProcessesByName(name string) WindowsProcesses {
	ret := []WindowsProcess{}
	for _, p := range processes {
		if strings.ToLower(p.NameExe) == strings.ToLower(name) {
			ret = append(ret, p)
		}
	}
	return ret
}

func (processes WindowsProcesses) FindProcessByPID(pid int) *WindowsProcess {
	for _, p := range processes {
		if p.ProcessID == pid {
			return &p
		}
	}
	return nil
}

// win32 def
type SystemExtendedHandleTableEntryInformation struct {
	Object                uintptr
	UniqueProcessId       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// win32 def
type SystemExtendedHandleInformation struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]SystemExtendedHandleTableEntryInformation
}

// custom def
type HandleInfo struct {
	SEHTEI SystemExtendedHandleTableEntryInformation
	OBI    ntdll.ObjectBasicInformationT
	OTI    ntdll.ObjectTypeInformationT
	ONI    ntdll.ObjectNameInformationT
}

func HandleInfos(pid uint32) ([]HandleInfo, error) {
	// SystemExtendedHandleTableEntryInformation
	nSEHI := uint32(1024)
	bufSEHI := make([]byte, nSEHI)
	if st := ntdll.CallWithExpandingBuffer(
		func() ntdll.NtStatus {
			return ntdll.NtQuerySystemInformation(
				windows.SystemExtendedHandleInformation,
				&bufSEHI[0],
				nSEHI,
				&nSEHI,
			)
		},
		&bufSEHI,
		&nSEHI,
	); st.IsError() {
		return nil, st.Error()
	}
	sehi := (*SystemExtendedHandleInformation)(unsafe.Pointer(&bufSEHI[0]))
	sehteis := make([]SystemExtendedHandleTableEntryInformation, int(sehi.NumberOfHandles))
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&sehteis))
	hdr.Data = uintptr(unsafe.Pointer(&sehi.Handles[0]))

	processTarget, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}
	processCurrent, err := windows.GetCurrentProcess()
	if err != nil {
		return nil, err
	}

	retHandleInfos := []HandleInfo{}

	for _, sehtei := range sehteis {
		var dupHandle uintptr
		if uint32(sehtei.UniqueProcessId) != pid {
			continue
		}
		if windows.DuplicateHandle(
			processTarget, windows.Handle(sehtei.HandleValue),
			processCurrent, (*windows.Handle)(&dupHandle),
			0, true, windows.DUPLICATE_SAME_ACCESS) != nil {
			continue
		}

		// ObjectBasicInformation
		nOBI := uint32(reflect.TypeOf(ntdll.ObjectBasicInformationT{}).Size())
		bufOBI := make([]byte, nOBI)
		if st := ntdll.CallWithExpandingBuffer(
			func() ntdll.NtStatus {
				return ntdll.NtQueryObject(
					ntdll.Handle(dupHandle),
					ntdll.ObjectBasicInformation,
					&bufOBI[0],
					uint32(nOBI),
					&nOBI,
				)
			},
			&bufOBI,
			&nOBI,
		); st.IsError() {
			return nil, st.Error()
		}
		obi := *(*ntdll.ObjectBasicInformationT)(unsafe.Pointer(&bufOBI[0]))

		// ObjectTypeInformation
		nOTI := obi.TypeInformationLength + 2
		bufOTI := make([]byte, nOTI)
		if st := ntdll.CallWithExpandingBuffer(
			func() ntdll.NtStatus {
				return ntdll.NtQueryObject(
					ntdll.Handle(dupHandle),
					ntdll.ObjectTypeInformation,
					&bufOTI[0],
					nOTI,
					&nOTI,
				)
			},
			&bufOTI,
			&nOTI,
		); st.IsError() {
			return nil, st.Error()
		}
		oti := *(*ntdll.ObjectTypeInformationT)(unsafe.Pointer(&bufOTI[0]))

		// ObjectNameInformation
		nONI := func() uint32 {
			if obi.NameInformationLength == 0 {
				return windows.MAX_PATH * 2 // *sizeof(WCHAR)
			}
			return obi.NameInformationLength
		}()
		bufONI := make([]byte, nONI)
		if st := ntdll.CallWithExpandingBuffer(
			func() ntdll.NtStatus {
				return ntdll.NtQueryObject(
					ntdll.Handle(dupHandle),
					ntdll.ObjectNameInformation,
					&bufONI[0],
					nONI,
					&nONI,
				)
			},
			&bufONI,
			&nONI,
		); st.IsError() {
			return nil, st.Error()
		}
		oni := *(*ntdll.ObjectNameInformationT)(unsafe.Pointer(&bufONI[0]))

		// Sum
		retHandleInfos = append(retHandleInfos, HandleInfo{SEHTEI: sehtei, OBI: obi, OTI: oti, ONI: oni})

		// Close handle
		if err := windows.CloseHandle(windows.Handle(dupHandle)); err != nil {
			return nil, err
		}
	}

	return retHandleInfos, nil
}

var procIsProcessCritical = syscall.NewLazyDLL("kernel32.dll").NewProc("IsProcessCritical")

func isProcessCritical(hProcess windows.Handle) (ret bool, err error) {
	var holder uintptr
	r1, _, e1 := procIsProcessCritical.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&holder)))
	if r1 == 0 { // r1 is false (func errored)
		return false, e1
	}
	return holder != 0, nil
}
