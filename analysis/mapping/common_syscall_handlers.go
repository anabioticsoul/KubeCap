package mapping

import (
	"go/constant"
	"sort"
	"strings"

	"github.com/awslabs/ar-go-tools/fake/analysis"
	naivereachability "github.com/awslabs/ar-go-tools/fake/reachability"
	"golang.org/x/tools/go/ssa"
)

const F_SETFL = 0x4
const O_NOATIME = 0x40000
const F_SETLEASE = 0x400
const F_RDLCK = 0x00
const F_SETPIPE_SZ = 0x407

// ioctl命令常量定义 - 终端控制
const TCGETS = 0x5401
const TCSETS = 0x5402
const TCSETSW = 0x5403
const TCSETSF = 0x5404

// ioctl命令常量定义 - 文件描述符操作
const FIOCLEX = 0x5451
const FIONCLEX = 0x5452
const FIONBIO = 0x5421
const FIOASYNC = 0x5452

// ioctl命令常量定义 - 网络接口配置
const SIOCGIFFLAGS = 0x8913
const SIOCSIFFLAGS = 0x8914
const SIOCGIFADDR = 0x8915
const SIOCSIFADDR = 0x8916

// ioctl命令常量定义 - 块设备操作
const BLKGETSIZE = 0x1260
const BLKGETSIZE64 = 0x80081272
const BLKROSET = 0x125d
const BLKROGET = 0x125e

const SOCK_RAW = 3
const CLOCK_REALTIME_ALARM = 8
const CLOCK_BOOTTIME_ALARM = 9
const AT_EMPTY_PATH = 0x1000
const TIMER_ABSTIME = 0x01
const IOPL_MAX_LEVEL = 3
const L2CAP_PSM_DYN_START = 0x1001

const CLONE_NEWNS = 0x00020000
const CLONE_NEWUTS = 0x04000000
const CLONE_NEWIPC = 0x08000000
const CLONE_NEWPID = 0x20000000
const CLONE_NEWNET = 0x40000000
const CLONE_NEWCGROUP = 0x02000000

const CLONE_NEW_MASK = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWCGROUP

func callArgsForCallee(callsite ssa.CallInstruction, callee *ssa.Function) ([]ssa.Value, bool) {
	if callsite == nil || callee == nil {
		return nil, false
	}
	common := callsite.Common()
	if common == nil || common.StaticCallee() != callee {
		return nil, false
	}
	return common.Args, true
}

func int64FromConst(c *ssa.Const) (int64, bool) {
	if c == nil || c.Value == nil {
		return 0, false
	}
	if c.Value.Kind() != constant.Int {
		return 0, false
	}
	if v, ok := constant.Int64Val(c.Value); ok {
		return v, true
	}
	if uv, ok := constant.Uint64Val(c.Value); ok && uv <= uint64((1<<63)-1) {
		return int64(uv), true
	}
	return 0, false
}

func isGenericSyscallWrapper(fun *ssa.Function, names ...string) bool {
	if fun == nil {
		return false
	}

	name := strings.ToLower(fun.Name())
	matchedName := false
	for _, candidate := range names {
		if name == strings.ToLower(candidate) {
			matchedName = true
			break
		}
	}
	if !matchedName {
		return false
	}

	if fun.Pkg == nil || fun.Pkg.Pkg == nil {
		return false
	}

	pkgPath := fun.Pkg.Pkg.Path()
	return pkgPath == "runtime" ||
		pkgPath == "syscall" ||
		pkgPath == "unix" ||
		pkgPath == "golang.org/x/sys/unix" ||
		strings.HasPrefix(pkgPath, "golang.org/x/sys/")
}

func Handler_fcntl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "fcntl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok || len(args) < 3 {
							continue
						}
						arg1, ok1 := args[1].(*ssa.Const)
						arg2, ok2 := args[2].(*ssa.Const)
						arg1Val, okArg1 := int64FromConst(arg1)
						arg2Val, okArg2 := int64FromConst(arg2)
						if ok1 && ok2 && okArg1 && okArg2 {
							if arg1Val == F_SETFL && arg2Val&O_NOATIME == O_NOATIME {
								mapping["fcntl"] = append(mapping["fcntl"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "arg[1] == F_SETFL && arg[2] & O_NOATIME == O_NOATIME", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_FOWNER found in function:", caller)
							}
							if arg1Val == F_SETLEASE && arg2Val == F_RDLCK {
								mapping["fcntl"] = append(mapping["fcntl"], analysis.ConditionalCapability{Capability: "CAP_LEASE", ArgCondition: "arg[1] == F_SETLEASE && arg[2] == F_RDLCK", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_LEASE found in function:", caller)
							}
							if arg1Val == F_SETPIPE_SZ {
								mapping["fcntl"] = append(mapping["fcntl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "arg[1] == F_SETPIPE_SZ", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SYS_RESOURCE found in function:", caller)
							}
						} else {
							// TODO: unsound heuristic
							mapping["fcntl"] = append(mapping["fcntl"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})

						}
					}
				}
			}
		}
	}
}

func Handler_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if isGenericSyscallWrapper(fun, "ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok || len(args) < 2 {
							continue
						}
						cmd, okCmd := args[1].(*ssa.Const)
						cmdVal, okCmdVal := int64FromConst(cmd)
						if okCmd && okCmdVal {
							if cmdVal == TCGETS || cmdVal == TCSETS || cmdVal == TCSETSW || cmdVal == TCSETSF {
								mapping["ioctl"] = append(mapping["ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "arg[1] == TCGETS || arg[1] == TCSETS || arg[1] == TCSETSW || arg[1] == TCSETSF", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (terminal control) found in function:", caller)
							}
							if cmdVal == SIOCGIFFLAGS || cmdVal == SIOCSIFFLAGS || cmdVal == SIOCGIFADDR || cmdVal == SIOCSIFADDR {
								mapping["ioctl"] = append(mapping["ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "arg[1] == SIOCGIFFLAGS || arg[1] == SIOCSIFFLAGS || arg[1] == SIOCGIFADDR || arg[1] == SIOCSIFADDR", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (network interface) found in function:", caller)
							}
							if cmdVal == FIOCLEX || cmdVal == FIONCLEX || cmdVal == FIONBIO || cmdVal == FIOASYNC {
								mapping["ioctl"] = append(mapping["ioctl"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "arg[1] == FIOCLEX || arg[1] == FIONCLEX || arg[1] == FIONBIO || arg[1] == FIOASYNC", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_FOWNER (file descriptor) found in function:", caller)
							}
							if cmdVal == BLKGETSIZE || cmdVal == BLKGETSIZE64 || cmdVal == BLKROSET || cmdVal == BLKROGET {
								mapping["ioctl"] = append(mapping["ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "arg[1] == BLKGETSIZE || arg[1] == BLKGETSIZE64 || arg[1] == BLKROSET || arg[1] == BLKROGET", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (block device) found in function:", caller)
							}
						} else {
							mapping["ioctl"] = append(mapping["ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
						}
					}
				}
			}
		}
	}
}

func Handler_write(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "write") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok || len(args) < 3 {
							continue
						}
						fd, okFd := args[0].(*ssa.Const)
						fdVal, okFdVal := int64FromConst(fd)
						if okFd && okFdVal && fdVal == 1 {
							mapping["write"] = append(mapping["write"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "arg[0] == 1", ExtraCondition: "true"})
							logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (write to stdout) found in function:", caller)
						}
					}
				}
			}
		}
	}
}

func Handler_socket(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "socket") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 2 {
							a0, ok0 := args[0].(*ssa.Const)
							a1, ok1 := args[1].(*ssa.Const)
							a0Val, okA0 := int64FromConst(a0)
							a1Val, okA1 := int64FromConst(a1)
							if (ok0 && okA0 && a0Val == SOCK_RAW) || (ok1 && okA1 && a1Val == SOCK_RAW) {
								mapping["socket"] = append(mapping["socket"], analysis.ConditionalCapability{Capability: "CAP_NET_RAW", ArgCondition: "arg[1] == SOCK_RAW", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_NET_RAW found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_timerfd_create(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "timerfd_create") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 1 {
							clockid, okClock := args[0].(*ssa.Const)
							clockVal, okClockVal := int64FromConst(clockid)
							if okClock && okClockVal && (clockVal == CLOCK_REALTIME_ALARM || clockVal == CLOCK_BOOTTIME_ALARM) {
								mapping["timerfd_create"] = append(mapping["timerfd_create"], analysis.ConditionalCapability{Capability: "CAP_WAKE_ALARM", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_WAKE_ALARM found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_linkat(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "linkat") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["linkat"] = append(mapping["linkat"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
			}
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 5 {
							flags, okFlags := args[4].(*ssa.Const)
							flagsVal, okFlagsVal := int64FromConst(flags)
							if okFlags && okFlagsVal && flagsVal&AT_EMPTY_PATH == AT_EMPTY_PATH {
								mapping["linkat"] = append(mapping["linkat"], analysis.ConditionalCapability{Capability: "CAP_DAC_READ_SEARCH", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_DAC_READ_SEARCH found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_setgroups(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setgroups") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 1 {
							gidsetsize, okSize := args[0].(*ssa.Const)
							sizeVal, okSizeVal := int64FromConst(gidsetsize)
							if okSize && okSizeVal && sizeVal > 0 {
								mapping["setgroups"] = append(mapping["setgroups"], analysis.ConditionalCapability{Capability: "CAP_SETGID", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SETGID found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_clone(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if isGenericSyscallWrapper(fun, "clone") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["clone"] = append(mapping["clone"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
			}
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 1 {
							flags, okFlags := args[0].(*ssa.Const)
							flagsVal, okFlagsVal := int64FromConst(flags)
							if okFlags && okFlagsVal && flagsVal&CLONE_NEW_MASK != 0 {
								mapping["clone"] = append(mapping["clone"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (clone namespaces) found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_clock_nanosleep(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "clock_nanosleep") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 2 {
							flags, okFlags := args[1].(*ssa.Const)
							flagsVal, okFlagsVal := int64FromConst(flags)
							if okFlags && okFlagsVal && (flagsVal&^int64(TIMER_ABSTIME)) != 0 {
								mapping["clock_nanosleep"] = append(mapping["clock_nanosleep"], analysis.ConditionalCapability{Capability: "CAP_WAKE_ALARM", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_WAKE_ALARM (clock_nanosleep) found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_iopl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "iopl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 1 {
							level, okLevel := args[0].(*ssa.Const)
							levelVal, okLevelVal := int64FromConst(level)
							if okLevel && okLevelVal && levelVal > IOPL_MAX_LEVEL {
								mapping["iopl"] = append(mapping["iopl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SYS_RAWIO found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_reboot(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "reboot") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["reboot"] = append(mapping["reboot"], analysis.ConditionalCapability{Capability: "CAP_SYS_BOOT", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_BOOT found in function:", caller)
				}
			}
		}
	}
}

func Handler_sethostname(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sethostname") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sethostname"] = append(mapping["sethostname"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (sethostname) found in function:", caller)
				}
			}
		}
	}
}

func Handler_setdomainname(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setdomainname") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["setdomainname"] = append(mapping["setdomainname"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (setdomainname) found in function:", caller)
				}
			}
		}
	}
}

func Handler_kexec_load(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "kexec_load") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["kexec_load"] = append(mapping["kexec_load"], analysis.ConditionalCapability{Capability: "CAP_SYS_BOOT", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_BOOT (kexec_load) found in function:", caller)
				}
			}
		}
	}
}

func Handler_kexec_file_load(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "kexec_file_load") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["kexec_file_load"] = append(mapping["kexec_file_load"], analysis.ConditionalCapability{Capability: "CAP_SYS_BOOT", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_BOOT (kexec_file_load) found in function:", caller)
				}
			}
		}
	}
}

func Handler_delete_module(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "delete_module") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["delete_module"] = append(mapping["delete_module"], analysis.ConditionalCapability{Capability: "CAP_SYS_MODULE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_MODULE found in function:", caller)
				}
			}
		}
	}
}

func Handler_open(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	// Generic open/openat usage does not imply CAP_SYS_ADMIN in Linux.
	// Capability checks depend on the concrete file, filesystem, and follow-up
	// operation, so a name-based handler here is too permissive.
	return
}

func Handler_setgid(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setgid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["setgid"] = append(mapping["setgid"], analysis.ConditionalCapability{Capability: "CAP_SETGID", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SETGID (setgid) found in function:", caller)
				}
			}
		}
	}
}

func Handler_setregid(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setregid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 2 {
							rgid, ok1 := args[0].(*ssa.Const)
							egid, ok2 := args[1].(*ssa.Const)
							rgidVal, okRgid := int64FromConst(rgid)
							egidVal, okEgid := int64FromConst(egid)
							if ok1 && ok2 && okRgid && okEgid && (rgidVal != -1 || egidVal != -1) {
								mapping["setregid"] = append(mapping["setregid"], analysis.ConditionalCapability{Capability: "CAP_SETGID", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SETGID (setregid) found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_setfsgid(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setfsgid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["setfsgid"] = append(mapping["setfsgid"], analysis.ConditionalCapability{Capability: "CAP_SETGID", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SETGID (setfsgid) found in function:", caller)
				}
			}
		}
	}
}

func Handler_prlimit64(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "prlimit64") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 1 {
							pid, okPid := args[0].(*ssa.Const)
							pidVal, okPidVal := int64FromConst(pid)
							if okPid && okPidVal && pidVal != 0 {
								mapping["prlimit64"] = append(mapping["prlimit64"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_SYS_RESOURCE (prlimit64) found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_bind(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "bind") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 2 {
							psm, okPsm := args[1].(*ssa.Const)
							psmVal, okPsmVal := int64FromConst(psm)
							if okPsm && okPsmVal && psmVal < L2CAP_PSM_DYN_START {
								mapping["bind"] = append(mapping["bind"], analysis.ConditionalCapability{Capability: "CAP_NET_BIND_SERVICE", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_NET_BIND_SERVICE (bind privileged port/psm) found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_timerfd_settime(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "timerfd_settime") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["timerfd_settime"] = append(mapping["timerfd_settime"], analysis.ConditionalCapability{Capability: "CAP_WAKE_ALARM", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_WAKE_ALARM (timerfd_settime) found in function:", caller)
				}
			}
		}
	}
}

func Handler_setuid(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setuid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["setuid"] = append(mapping["setuid"], analysis.ConditionalCapability{Capability: "CAP_SETUID", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SETUID (setuid) found in function:", caller)
				}
			}
		}
	}
}

func Handler_setreuid(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setreuid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["setreuid"] = append(mapping["setreuid"], analysis.ConditionalCapability{Capability: "CAP_SETUID", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SETUID (setreuid) found in function:", caller)
				}
			}
		}
	}
}

func Handler_setresuid(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setresuid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["setresuid"] = append(mapping["setresuid"], analysis.ConditionalCapability{Capability: "CAP_SETUID", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SETUID (setresuid) found in function:", caller)
				}
			}
		}
	}
}

func Handler_setfsuid(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "setfsuid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["setfsuid"] = append(mapping["setfsuid"], analysis.ConditionalCapability{Capability: "CAP_SETUID", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SETUID (setfsuid) found in function:", caller)
				}
			}
		}
	}
}

func Handler_caif_create(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "caif_create") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["caif_create"] = append(mapping["caif_create"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				mapping["caif_create"] = append(mapping["caif_create"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN/CAP_SYS_ADMIN (caif_create) found in function:", caller)
				}
			}
		}
	}
}

func Handler_HDIO_DRIVE_CMD(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "hdio_drive_cmd") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["HDIO_DRIVE_CMD"] = append(mapping["HDIO_DRIVE_CMD"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				mapping["HDIO_DRIVE_CMD"] = append(mapping["HDIO_DRIVE_CMD"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN/CAP_SYS_RAWIO (HDIO_DRIVE_CMD) found in function:", caller)
				}
			}
		}
	}
}

func Handler_isst_if_mbox_proc_cmd(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "isst_if_mbox_proc_cmd") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["isst_if_mbox_proc_cmd"] = append(mapping["isst_if_mbox_proc_cmd"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (isst_if_mbox_proc_cmd) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mlx5_ib_devx_create(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "mlx5_ib_devx_create") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			for _, caller := range callers {
				for _, basicBlock := range caller.Blocks {
					for _, instr := range basicBlock.Instrs {
						callsite, ok := instr.(ssa.CallInstruction)
						if !ok {
							continue
						}
						args, ok := callArgsForCallee(callsite, fun)
						if !ok {
							continue
						}
						if len(args) >= 2 {
							if adminFlag, okFlag := args[1].(*ssa.Const); okFlag {
								adminFlagVal, okAdminVal := int64FromConst(adminFlag)
								if !okAdminVal || adminFlagVal == 0 {
									continue
								}
								mapping["mlx5_ib_devx_create"] = append(mapping["mlx5_ib_devx_create"], analysis.ConditionalCapability{Capability: "CAP_NET_RAW", ArgCondition: "true", ExtraCondition: "true"})
								mapping["mlx5_ib_devx_create"] = append(mapping["mlx5_ib_devx_create"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
								mapping["mlx5_ib_devx_create"] = append(mapping["mlx5_ib_devx_create"], analysis.ConditionalCapability{Capability: "CAP_NET_RAW and CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
								logSpecialHandlerMatch("[Info] CAP_NET_RAW/CAP_SYS_RAWIO (mlx5_ib_devx_create) found in function:", caller)
							}
						}
					}
				}
			}
		}
	}
}

func Handler_rtc_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "rtc_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["rtc_ioctl"] = append(mapping["rtc_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_TIME", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_TIME (rtc_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_scsi_ioctl_reset(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "scsi_ioctl_reset") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["scsi_ioctl_reset"] = append(mapping["scsi_ioctl_reset"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				mapping["scsi_ioctl_reset"] = append(mapping["scsi_ioctl_reset"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN/CAP_SYS_RAWIO (scsi_ioctl_reset) found in function:", caller)
				}
			}
		}
	}
}

func Handler_sg_proc_write_dressz(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sg_proc_write_dressz") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sg_proc_write_dressz"] = append(mapping["sg_proc_write_dressz"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				mapping["sg_proc_write_dressz"] = append(mapping["sg_proc_write_dressz"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN/CAP_SYS_RAWIO (sg_proc_write_dressz) found in function:", caller)
				}
			}
		}
	}
}

func Handler_vidioc_s_fbuf(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vidioc_s_fbuf") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vidioc_s_fbuf"] = append(mapping["vidioc_s_fbuf"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				mapping["vidioc_s_fbuf"] = append(mapping["vidioc_s_fbuf"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN/CAP_SYS_RAWIO (vidioc_s_fbuf) found in function:", caller)
				}
			}
		}
	}
}

func Handler___blkdev_reread_part(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "blkdev_reread_part") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["__blkdev_reread_part"] = append(mapping["__blkdev_reread_part"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (__blkdev_reread_part) found in function:", caller)
				}
			}
		}
	}
}

func Handler___rfcomm_create_dev(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "rfcomm_create_dev") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["__rfcomm_create_dev"] = append(mapping["__rfcomm_create_dev"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (__rfcomm_create_dev) found in function:", caller)
				}
			}
		}
	}
}

func Handler___rfcomm_release_dev(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "rfcomm_release_dev") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["__rfcomm_release_dev"] = append(mapping["__rfcomm_release_dev"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (__rfcomm_release_dev) found in function:", caller)
				}
			}
		}
	}
}

func Handler___sock_cmsg_send(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sock_cmsg_send") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["__sock_cmsg_send"] = append(mapping["__sock_cmsg_send"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (__sock_cmsg_send) found in function:", caller)
				}
			}
		}
	}
}

func Handler_acct(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "acct") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["acct"] = append(mapping["acct"], analysis.ConditionalCapability{Capability: "CAP_SYS_PACCT", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_PACCT (acct) found in function:", caller)
				}
			}
		}
	}
}

func Handler_addrconf_add_ifaddr(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "addrconf_add_ifaddr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["addrconf_add_ifaddr"] = append(mapping["addrconf_add_ifaddr"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (addrconf_add_ifaddr) found in function:", caller)
				}
			}
		}
	}
}

func Handler_airo_get_aplist(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "airo_get_aplist") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["airo_get_aplist"] = append(mapping["airo_get_aplist"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (airo_get_aplist) found in function:", caller)
				}
			}
		}
	}
}

func Handler_arcmsr_sysfs_iop_message_write(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "arcmsr_sysfs_iop_message_write") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["arcmsr_sysfs_iop_message_write"] = append(mapping["arcmsr_sysfs_iop_message_write"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (arcmsr_sysfs_iop_message_write) found in function:", caller)
				}
			}
		}
	}
}

func Handler_arp_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "arp_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["arp_ioctl"] = append(mapping["arp_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (arp_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_atm_mpoa_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "atm_mpoa_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["atm_mpoa_ioctl"] = append(mapping["atm_mpoa_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (atm_mpoa_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_audit_bind(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "audit_bind") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["audit_bind"] = append(mapping["audit_bind"], analysis.ConditionalCapability{Capability: "CAP_AUDIT_READ", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_AUDIT_READ (audit_bind) found in function:", caller)
				}
			}
		}
	}
}

func Handler_blkdev_report_zones_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "blkdev_report_zones_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["blkdev_report_zones_ioctl"] = append(mapping["blkdev_report_zones_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (blkdev_report_zones_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_blkdev_reset_zones_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "blkdev_reset_zones_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["blkdev_reset_zones_ioctl"] = append(mapping["blkdev_reset_zones_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (blkdev_reset_zones_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_bpf(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if fun.Name() == "bpf" || strings.Contains(strings.ToLower(fun.Name()), "_bpf") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["bpf"] = append(mapping["bpf"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (bpf) found in function:", caller)
				}
			}
		}
	}
}

func Handler_bpf_map_get_fd_by_id(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "bpf_map_get_fd_by_id") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["bpf_map_get_fd_by_id"] = append(mapping["bpf_map_get_fd_by_id"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (bpf_map_get_fd_by_id) found in function:", caller)
				}
			}
		}
	}
}

func Handler_bpf_prog_get_fd_by_id(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "bpf_prog_get_fd_by_id") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["bpf_prog_get_fd_by_id"] = append(mapping["bpf_prog_get_fd_by_id"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (bpf_prog_get_fd_by_id) found in function:", caller)
				}
			}
		}
	}
}

func Handler_bpf_prog_load(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "bpf_prog_load") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["bpf_prog_load"] = append(mapping["bpf_prog_load"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (bpf_prog_load) found in function:", caller)
				}
			}
		}
	}
}

func Handler_bpf_prog_test_run(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "bpf_prog_test_run") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["bpf_prog_test_run"] = append(mapping["bpf_prog_test_run"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (bpf_prog_test_run) found in function:", caller)
				}
			}
		}
	}
}

func Handler_bpf_task_fd_query(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "bpf_task_fd_query") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["bpf_task_fd_query"] = append(mapping["bpf_task_fd_query"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (bpf_task_fd_query) found in function:", caller)
				}
			}
		}
	}
}

func Handler_br_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "br_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["br_ioctl"] = append(mapping["br_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (br_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_bttv_s_fbuf(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "bttv_s_fbuf") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["bttv_s_fbuf"] = append(mapping["bttv_s_fbuf"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				mapping["bttv_s_fbuf"] = append(mapping["bttv_s_fbuf"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN/CAP_SYS_RAWIO (bttv_s_fbuf) found in function:", caller)
				}
			}
		}
	}
}

func Handler_cachefiles_daemon_open(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "cachefiles_daemon_open") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["cachefiles_daemon_open"] = append(mapping["cachefiles_daemon_open"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (cachefiles_daemon_open) found in function:", caller)
				}
			}
		}
	}
}

func Handler_cacheflush(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "cacheflush") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["cacheflush"] = append(mapping["cacheflush"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (cacheflush) found in function:", caller)
				}
			}
		}
	}
}

func Handler_cdrom_ioctl_reset(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "cdrom_ioctl_reset") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["cdrom_ioctl_reset"] = append(mapping["cdrom_ioctl_reset"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (cdrom_ioctl_reset) found in function:", caller)
				}
			}
		}
	}
}

func Handler_cgroup1_get_tree(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "cgroup1_get_tree") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["cgroup1_get_tree"] = append(mapping["cgroup1_get_tree"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (cgroup1_get_tree) found in function:", caller)
				}
			}
		}
	}
}

func Handler_clip_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "clip_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["clip_ioctl"] = append(mapping["clip_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (clip_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_cobalt_cobaltc(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "cobalt_cobaltc") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["cobalt_cobaltc"] = append(mapping["cobalt_cobaltc"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (cobalt_cobaltc) found in function:", caller)
				}
			}
		}
	}
}

func Handler_comedi_open(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		name := strings.ToLower(fun.Name())
		if strings.Contains(name, "comedi_open") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["comedi_open"] = append(mapping["comedi_open"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (comedi_open) found in function:", caller)
				}
			}
		}
	}
}

func Handler_compat_do_arpt_set_ctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "compat_do_arpt_set_ctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["compat_do_arpt_set_ctl"] = append(mapping["compat_do_arpt_set_ctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (compat_do_arpt_set_ctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_compat_do_ebt_set_ctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "compat_do_ebt_set_ctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["compat_do_ebt_set_ctl"] = append(mapping["compat_do_ebt_set_ctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (compat_do_ebt_set_ctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_compat_do_ipt_get_ctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "compat_do_ipt_get_ctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["compat_do_ipt_get_ctl"] = append(mapping["compat_do_ipt_get_ctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (compat_do_ipt_get_ctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_compat_do_ipt_set_ctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "compat_do_ipt_set_ctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["compat_do_ipt_set_ctl"] = append(mapping["compat_do_ipt_set_ctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (compat_do_ipt_set_ctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ctrl_cdev_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ctrl_cdev_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ctrl_cdev_ioctl"] = append(mapping["ctrl_cdev_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RESOURCE (ctrl_cdev_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_cxgb_extension_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "cxgb_extension_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["cxgb_extension_ioctl"] = append(mapping["cxgb_extension_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (cxgb_extension_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_dasd_ioctl_format(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "dasd_ioctl_format") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["dasd_ioctl_format"] = append(mapping["dasd_ioctl_format"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (dasd_ioctl_format) found in function:", caller)
				}
			}
		}
	}
}

func Handler_dasd_ioctl_set_ro(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "dasd_ioctl_set_ro") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["dasd_ioctl_set_ro"] = append(mapping["dasd_ioctl_set_ro"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (dasd_ioctl_set_ro) found in function:", caller)
				}
			}
		}
	}
}

func Handler_dasd_symm_io(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "dasd_symm_io") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["dasd_symm_io"] = append(mapping["dasd_symm_io"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				mapping["dasd_symm_io"] = append(mapping["dasd_symm_io"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				mapping["dasd_symm_io"] = append(mapping["dasd_symm_io"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN or CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN/CAP_SYS_RAWIO (dasd_symm_io) found in function:", caller)
				}
			}
		}
	}
}

func Handler_do_ipt_set_ctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "do_ipt_set_ctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["do_ipt_set_ctl"] = append(mapping["do_ipt_set_ctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (do_ipt_set_ctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_do_vm86_irq_handling(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "do_vm86_irq_handling") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["do_vm86_irq_handling"] = append(mapping["do_vm86_irq_handling"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (do_vm86_irq_handling) found in function:", caller)
				}
			}
		}
	}
}

func Handler_drm_legacy_addmap_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "drm_legacy_addmap_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["drm_legacy_addmap_ioctl"] = append(mapping["drm_legacy_addmap_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (drm_legacy_addmap_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_eeprom_read(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "eeprom_read") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["eeprom_read"] = append(mapping["eeprom_read"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (eeprom_read) found in function:", caller)
				}
			}
		}
	}
}

func Handler_eni_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "eni_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["eni_ioctl"] = append(mapping["eni_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (eni_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_erofs_getxattr(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "erofs_getxattr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["erofs_getxattr"] = append(mapping["erofs_getxattr"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (erofs_getxattr) found in function:", caller)
				}
			}
		}
	}
}

func Handler_EXT2_IOC_SETVERSION(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ext2") && strings.Contains(strings.ToLower(fun.Name()), "setversion") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["EXT2_IOC_SETVERSION"] = append(mapping["EXT2_IOC_SETVERSION"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (EXT2_IOC_SETVERSION) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ext4_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ext4_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ext4_ioctl"] = append(mapping["ext4_ioctl"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (ext4_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ext4_ioctl_setversion(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ext4_ioctl_setversion") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ext4_ioctl_setversion"] = append(mapping["ext4_ioctl_setversion"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (ext4_ioctl_setversion) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_defragment(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_defragment") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_defragment"] = append(mapping["f2fs_ioc_defragment"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (f2fs_ioc_defragment) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_flush_device(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_flush_device") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_flush_device"] = append(mapping["f2fs_ioc_flush_device"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (f2fs_ioc_flush_device) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_fssetxattr(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_fssetxattr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_fssetxattr"] = append(mapping["f2fs_ioc_fssetxattr"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (f2fs_ioc_fssetxattr) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_gc_range(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_gc_range") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_gc_range"] = append(mapping["f2fs_ioc_gc_range"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (f2fs_ioc_gc_range) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_resize_fs(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_resize_fs") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_resize_fs"] = append(mapping["f2fs_ioc_resize_fs"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (f2fs_ioc_resize_fs) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_setflags(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_setflags") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_setflags"] = append(mapping["f2fs_ioc_setflags"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (f2fs_ioc_setflags) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_shutdown(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_shutdown") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_shutdown"] = append(mapping["f2fs_ioc_shutdown"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (f2fs_ioc_shutdown) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_ioc_start_atomic_write(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_ioc_start_atomic_write") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_ioc_start_atomic_write"] = append(mapping["f2fs_ioc_start_atomic_write"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (f2fs_ioc_start_atomic_write) found in function:", caller)
				}
			}
		}
	}
}

func Handler_f2fs_setattr(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "f2fs_setattr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["f2fs_setattr"] = append(mapping["f2fs_setattr"], analysis.ConditionalCapability{Capability: "CAP_FSETID", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FSETID (f2fs_setattr) found in function:", caller)
				}
			}
		}
	}
}

func Handler_fanotify_init(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "fanotify_init") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["fanotify_init"] = append(mapping["fanotify_init"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (fanotify_init) found in function:", caller)
				}
			}
		}
	}
}

func Handler_FITRIM(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "fitrim") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["FITRIM"] = append(mapping["FITRIM"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (FITRIM) found in function:", caller)
				}
			}
		}
	}
}

func Handler_floppy_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "floppy_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["floppy_ioctl"] = append(mapping["floppy_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (floppy_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_floppy_locked_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "floppy_locked_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["floppy_locked_ioctl"] = append(mapping["floppy_locked_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (floppy_locked_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_fore200e_setloop(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "fore200e_setloop") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["fore200e_setloop"] = append(mapping["fore200e_setloop"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (fore200e_setloop) found in function:", caller)
				}
			}
		}
	}
}

func Handler_fscrypt_ioctl_remove_key_all_users(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "fscrypt_ioctl_remove_key_all_users") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["fscrypt_ioctl_remove_key_all_users"] = append(mapping["fscrypt_ioctl_remove_key_all_users"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (fscrypt_ioctl_remove_key_all_users) found in function:", caller)
				}
			}
		}
	}
}

func Handler_fstrim(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "fstrim") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["fstrim"] = append(mapping["fstrim"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (fstrim) found in function:", caller)
				}
			}
		}
	}
}

func Handler_gelic_net_set_wol(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "gelic_net_set_wol") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["gelic_net_set_wol"] = append(mapping["gelic_net_set_wol"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (gelic_net_set_wol) found in function:", caller)
				}
			}
		}
	}
}

func Handler_gsm_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "gsm_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["gsm_ioctl"] = append(mapping["gsm_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (gsm_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_hci_sock_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "hci_sock_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["hci_sock_ioctl"] = append(mapping["hci_sock_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (hci_sock_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_HDLCDRVCTL_SETMODEMPAR(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "hdlcdrvctl_setmodempar") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["HDLCDRVCTL_SETMODEMPAR"] = append(mapping["HDLCDRVCTL_SETMODEMPAR"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RAWIO (HDLCDRVCTL_SETMODEMPAR) found in function:", caller)
				}
			}
		}
	}
}

func Handler_hpet_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "hpet_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["hpet_ioctl"] = append(mapping["hpet_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RESOURCE (hpet_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_hpfs_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "hpfs_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["hpfs_ioctl"] = append(mapping["hpfs_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (hpfs_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_i915_gem_userptr_init__mmu_notifier(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		name := strings.ToLower(fun.Name())
		if strings.Contains(name, "i915_gem_userptr_init") || strings.Contains(name, "mmu_notifier") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["i915_gem_userptr_init__mmu_notifier"] = append(mapping["i915_gem_userptr_init__mmu_notifier"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (i915_gem_userptr_init__mmu_notifier) found in function:", caller)
				}
			}
		}
	}
}

func Handler_i915_perf_add_config_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "i915_perf_add_config_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["i915_perf_add_config_ioctl"] = append(mapping["i915_perf_add_config_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (i915_perf_add_config_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ioctl_FS_IOC_FSSETXATTR(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "fssetxattr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ioctl(FS_IOC_FSSETXATTR)"] = append(mapping["ioctl(FS_IOC_FSSETXATTR)"], analysis.ConditionalCapability{Capability: "CAP_LINUX_IMMUTABLE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_LINUX_IMMUTABLE (ioctl(FS_IOC_FSSETXATTR)) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ioperm(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ioperm") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ioperm"] = append(mapping["ioperm"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RAWIO (ioperm) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ip_rt_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ip_rt_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ip_rt_ioctl"] = append(mapping["ip_rt_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (ip_rt_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ip6_mroute_setsockopt(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ip6_mroute_setsockopt") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ip6_mroute_setsockopt"] = append(mapping["ip6_mroute_setsockopt"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (ip6_mroute_setsockopt) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ipoib_vlan_add(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ipoib_vlan_add") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ipoib_vlan_add"] = append(mapping["ipoib_vlan_add"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (ipoib_vlan_add) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ipoib_vlan_delete(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ipoib_vlan_delete") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ipoib_vlan_delete"] = append(mapping["ipoib_vlan_delete"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (ipoib_vlan_delete) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ipr_write_dump(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ipr_write_dump") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ipr_write_dump"] = append(mapping["ipr_write_dump"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (ipr_write_dump) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ipv6_flowlabel_opt_get(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ipv6_flowlabel_opt_get") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ipv6_flowlabel_opt_get"] = append(mapping["ipv6_flowlabel_opt_get"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (ipv6_flowlabel_opt_get) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ipv6_sock_ac_join(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ipv6_sock_ac_join") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ipv6_sock_ac_join"] = append(mapping["ipv6_sock_ac_join"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (ipv6_sock_ac_join) found in function:", caller)
				}
			}
		}
	}
}

func Handler_isst_if_mmio_rd_wr(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "isst_if_mmio_rd_wr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["isst_if_mmio_rd_wr"] = append(mapping["isst_if_mmio_rd_wr"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (isst_if_mmio_rd_wr) found in function:", caller)
				}
			}
		}
	}
}

func Handler_isst_if_msr_cmd_req(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "isst_if_msr_cmd_req") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["isst_if_msr_cmd_req"] = append(mapping["isst_if_msr_cmd_req"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (isst_if_msr_cmd_req) found in function:", caller)
				}
			}
		}
	}
}

func Handler_jfs_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "jfs_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["jfs_ioctl"] = append(mapping["jfs_ioctl"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (jfs_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_jfs_listxattr(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "jfs_listxattr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["jfs_listxattr"] = append(mapping["jfs_listxattr"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (jfs_listxattr) found in function:", caller)
				}
			}
		}
	}
}

func Handler_kernel_move_pages(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "kernel_move_pages") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["kernel_move_pages"] = append(mapping["kernel_move_pages"], analysis.ConditionalCapability{Capability: "CAP_SYS_NICE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_NICE (kernel_move_pages) found in function:", caller)
				}
			}
		}
	}
}

func Handler_madvise(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "madvise") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["madvise"] = append(mapping["madvise"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (madvise) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mbind(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "mbind") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["mbind"] = append(mapping["mbind"], analysis.ConditionalCapability{Capability: "CAP_SYS_NICE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_NICE (mbind) found in function:", caller)
				}
			}
		}
	}
}

func Handler_md_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "md_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["md_ioctl"] = append(mapping["md_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (md_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_megadev_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "megadev_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["megadev_ioctl"] = append(mapping["megadev_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (megadev_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_migrate_pages(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "migrate_pages") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["migrate_pages"] = append(mapping["migrate_pages"], analysis.ConditionalCapability{Capability: "CAP_SYS_NICE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_NICE (migrate_pages) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mincore(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "mincore") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["mincore"] = append(mapping["mincore"], analysis.ConditionalCapability{Capability: "CAP_WRITE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_WRITE (mincore) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mkiss_open(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "mkiss_open") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["mkiss_open"] = append(mapping["mkiss_open"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (mkiss_open) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mlock(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "mlock") && !strings.Contains(strings.ToLower(fun.Name()), "mlockall") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["mlock"] = append(mapping["mlock"], analysis.ConditionalCapability{Capability: "CAP_IPC_LOCK", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_IPC_LOCK (mlock) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mlockall(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "mlockall") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["mlockall"] = append(mapping["mlockall"], analysis.ConditionalCapability{Capability: "CAP_IPC_LOCK", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_IPC_LOCK (mlockall) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mmap(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	// Most mmap usage is unprivileged. CAP_SYS_ADMIN only appears in specific
	// device/driver paths, so a generic mmap handler creates systematic false positives.
	return
}

func Handler_moxa_open(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "moxa_open") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["moxa_open"] = append(mapping["moxa_open"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (moxa_open) found in function:", caller)
				}
			}
		}
	}
}

func Handler_mtrr_ioctls(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "mtrr_ioctls") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["mtrr_ioctls"] = append(mapping["mtrr_ioctls"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (mtrr_ioctls) found in function:", caller)
				}
			}
		}
	}
}

func Handler_nice(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "nice") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["nice"] = append(mapping["nice"], analysis.ConditionalCapability{Capability: "CAP_SYS_NICE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_NICE (nice) found in function:", caller)
				}
			}
		}
	}
}

func Handler_OCFS2_IOC_GROUP_EXTEND(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		name := strings.ToLower(fun.Name())
		if strings.Contains(name, "ocfs2") && strings.Contains(name, "group_extend") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["OCFS2_IOC_GROUP_EXTEND"] = append(mapping["OCFS2_IOC_GROUP_EXTEND"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RESOURCE (OCFS2_IOC_GROUP_EXTEND) found in function:", caller)
				}
			}
		}
	}
}

func Handler_open_by_handle(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "open_by_handle") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["open_by_handle"] = append(mapping["open_by_handle"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (open_by_handle) found in function:", caller)
				}
			}
		}
	}
}

func Handler_open_kcore(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "open_kcore") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["open_kcore"] = append(mapping["open_kcore"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RAWIO (open_kcore) found in function:", caller)
				}
			}
		}
	}
}

func Handler_orinoco_ioctl_reset(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "orinoco_ioctl_reset") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["orinoco_ioctl_reset"] = append(mapping["orinoco_ioctl_reset"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (orinoco_ioctl_reset) found in function:", caller)
				}
			}
		}
	}
}

func Handler_pci_read_config(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "pci_read_config") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["pci_read_config"] = append(mapping["pci_read_config"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (pci_read_config) found in function:", caller)
				}
			}
		}
	}
}

func Handler_pciconfig_write(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "pciconfig_write") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["pciconfig_write"] = append(mapping["pciconfig_write"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (pciconfig_write) found in function:", caller)
				}
			}
		}
	}
}

func Handler_perf_event_open(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "perf_event_open") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["perf_event_open"] = append(mapping["perf_event_open"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (perf_event_open) found in function:", caller)
				}
			}
		}
	}
}

func Handler_perf_event_query_prog_array(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "perf_event_query_prog_array") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["perf_event_query_prog_array"] = append(mapping["perf_event_query_prog_array"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (perf_event_query_prog_array) found in function:", caller)
				}
			}
		}
	}
}

func Handler_perf_write(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "perf_write") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["perf_write"] = append(mapping["perf_write"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (perf_write) found in function:", caller)
				}
			}
		}
	}
}

func Handler_pgctrl_write(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "pgctrl_write") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["pgctrl_write"] = append(mapping["pgctrl_write"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (pgctrl_write) found in function:", caller)
				}
			}
		}
	}
}

func Handler_pidns_install(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "pidns_install") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["pidns_install"] = append(mapping["pidns_install"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (pidns_install) found in function:", caller)
				}
			}
		}
	}
}

func Handler_plip_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "plip_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["plip_ioctl"] = append(mapping["plip_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (plip_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_pm_wake_unlock(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "pm_wake_unlock") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["pm_wake_unlock"] = append(mapping["pm_wake_unlock"], analysis.ConditionalCapability{Capability: "CAP_BLOCK_SUSPEND", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_BLOCK_SUSPEND (pm_wake_unlock) found in function:", caller)
				}
			}
		}
	}
}

func Handler_pmu_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "pmu_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["pmu_ioctl"] = append(mapping["pmu_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (pmu_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ppp_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ppp_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ppp_ioctl"] = append(mapping["ppp_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (ppp_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_pppoatm_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "pppoatm_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["pppoatm_ioctl"] = append(mapping["pppoatm_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (pppoatm_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_prctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "prctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["prctl"] = append(mapping["prctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RESOURCE (prctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_proc_bus_pci_mmap(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "proc_bus_pci_mmap") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["proc_bus_pci_mmap"] = append(mapping["proc_bus_pci_mmap"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RAWIO (proc_bus_pci_mmap) found in function:", caller)
				}
			}
		}
	}
}

func Handler_proc_bus_pci_read(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "proc_bus_pci_read") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["proc_bus_pci_read"] = append(mapping["proc_bus_pci_read"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (proc_bus_pci_read) found in function:", caller)
				}
			}
		}
	}
}

func Handler_proc_do_static_key(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "proc_do_static_key") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["proc_do_static_key"] = append(mapping["proc_do_static_key"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (proc_do_static_key) found in function:", caller)
				}
			}
		}
	}
}

func Handler_proc_dointvec_minmax_sysadmin(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "proc_dointvec_minmax_sysadmin") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["proc_dointvec_minmax_sysadmin"] = append(mapping["proc_dointvec_minmax_sysadmin"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (proc_dointvec_minmax_sysadmin) found in function:", caller)
				}
			}
		}
	}
}

func Handler_proc_sched_autogroup_set_nice(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "proc_sched_autogroup_set_nice") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["proc_sched_autogroup_set_nice"] = append(mapping["proc_sched_autogroup_set_nice"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (proc_sched_autogroup_set_nice) found in function:", caller)
				}
			}
		}
	}
}

func Handler_ptrace(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	// Generic ptrace does not imply CAP_SYS_ADMIN. Linux permission checks here
	// are request- and credential-specific, and CAP_SYS_PTRACE is usually the
	// more relevant capability when a privileged path exists.
	return
}

func Handler_qib_get_user_pages(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "qib_get_user_pages") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["qib_get_user_pages"] = append(mapping["qib_get_user_pages"], analysis.ConditionalCapability{Capability: "CAP_IPC_LOCK", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_IPC_LOCK (qib_get_user_pages) found in function:", caller)
				}
			}
		}
	}
}

func Handler_REISERFS_IOC_SETFLAGS(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		name := strings.ToLower(fun.Name())
		if strings.Contains(name, "reiserfs") && strings.Contains(name, "setflags") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["REISERFS_IOC_SETFLAGS"] = append(mapping["REISERFS_IOC_SETFLAGS"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_FOWNER (REISERFS_IOC_SETFLAGS) found in function:", caller)
				}
			}
		}
	}
}

func Handler_reset_rm2(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "reset_rm2") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["reset_rm2"] = append(mapping["reset_rm2"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (reset_rm2) found in function:", caller)
				}
			}
		}
	}
}

func Handler_reuseport_array_alloc(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "reuseport_array_alloc") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["reuseport_array_alloc"] = append(mapping["reuseport_array_alloc"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (reuseport_array_alloc) found in function:", caller)
				}
			}
		}
	}
}

func Handler_rio_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "rio_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["rio_ioctl"] = append(mapping["rio_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (rio_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_rtnetlink_bind(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "rtnetlink_bind") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["rtnetlink_bind"] = append(mapping["rtnetlink_bind"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (rtnetlink_bind) found in function:", caller)
				}
			}
		}
	}
}

func Handler_sbni_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sbni_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sbni_ioctl"] = append(mapping["sbni_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (sbni_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_scc_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "scc_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["scc_ioctl"] = append(mapping["scc_ioctl"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (scc_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_scif_bind(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "scif_bind") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["scif_bind"] = append(mapping["scif_bind"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (scif_bind) found in function:", caller)
				}
			}
		}
	}
}

func Handler_scsi_cmd_blk_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "scsi_cmd_blk_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["scsi_cmd_blk_ioctl"] = append(mapping["scsi_cmd_blk_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_RAWIO (scsi_cmd_blk_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_seccomp_get_filter(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "seccomp_get_filter") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["seccomp_get_filter"] = append(mapping["seccomp_get_filter"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (seccomp_get_filter) found in function:", caller)
				}
			}
		}
	}
}

func Handler_seccomp_get_metadata(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "seccomp_get_metadata") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["seccomp_get_metadata"] = append(mapping["seccomp_get_metadata"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (seccomp_get_metadata) found in function:", caller)
				}
			}
		}
	}
}

func Handler_sed_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sed_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sed_ioctl"] = append(mapping["sed_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (sed_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_set_task_ioprio(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "set_task_ioprio") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["set_task_ioprio"] = append(mapping["set_task_ioprio"], analysis.ConditionalCapability{Capability: "CAP_SYS_NICE", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_NICE (set_task_ioprio) found in function:", caller)
				}
			}
		}
	}
}

func Handler_sg_proc_write_adio(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sg_proc_write_adio") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sg_proc_write_adio"] = append(mapping["sg_proc_write_adio"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (sg_proc_write_adio) found in function:", caller)
				}
			}
		}
	}
}

func Handler_shmctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "shmctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["shmctl"] = append(mapping["shmctl"], analysis.ConditionalCapability{Capability: "CAP_IPC_LOCK", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_IPC_LOCK (shmctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_SIOCAX25ADDUID(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "siocax25adduid") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["SIOCAX25ADDUID"] = append(mapping["SIOCAX25ADDUID"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (SIOCAX25ADDUID) found in function:", caller)
				}
			}
		}
	}
}

func Handler_SIOCDELTUNNEL(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "siocdeltunnel") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["SIOCDELTUNNEL"] = append(mapping["SIOCDELTUNNEL"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (SIOCDELTUNNEL) found in function:", caller)
				}
			}
		}
	}
}

func Handler_SIOCDEVENSLAVE(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "siocdevenslave") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["SIOCDEVENSLAVE"] = append(mapping["SIOCDEVENSLAVE"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_NET_ADMIN (SIOCDEVENSLAVE) found in function:", caller)
				}
			}
		}
	}
}

func Handler_snapshot_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool {
		return funs[i].Pos() < funs[j].Pos()
	})
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "snapshot_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["snapshot_ioctl"] = append(mapping["snapshot_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
				for _, caller := range callers {
					logSpecialHandlerMatch("[Info] CAP_SYS_ADMIN (snapshot_ioctl) found in function:", caller)
				}
			}
		}
	}
}

func Handler_sock_diag_destroy(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sock_diag_destroy") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sock_diag_destroy"] = append(mapping["sock_diag_destroy"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_sock_hash_alloc(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sock_hash_alloc") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sock_hash_alloc"] = append(mapping["sock_hash_alloc"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_sock_setbindtodevice(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sock_setbindtodevice") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sock_setbindtodevice"] = append(mapping["sock_setbindtodevice"], analysis.ConditionalCapability{Capability: "CAP_NET_RAW", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_stack_map_alloc(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "stack_map_alloc") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["stack_map_alloc"] = append(mapping["stack_map_alloc"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_sysctl_numa_balancing(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sysctl_numa_balancing") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sysctl_numa_balancing"] = append(mapping["sysctl_numa_balancing"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_sysctl_schedstats(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "sysctl_schedstats") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["sysctl_schedstats"] = append(mapping["sysctl_schedstats"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_timerslack_ns_write(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "timerslack_ns_write") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["timerslack_ns_write"] = append(mapping["timerslack_ns_write"], analysis.ConditionalCapability{Capability: "CAP_SYS_NICE", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_tioclinux(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "tioclinux") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["tioclinux"] = append(mapping["tioclinux"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_tiocsti(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "tiocsti") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["tiocsti"] = append(mapping["tiocsti"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_tun_set_iff(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "tun_set_iff") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["tun_set_iff"] = append(mapping["tun_set_iff"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_ubi_cdev_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ubi_cdev_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ubi_cdev_ioctl"] = append(mapping["ubi_cdev_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_ubifs_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ubifs_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ubifs_ioctl"] = append(mapping["ubifs_ioctl"], analysis.ConditionalCapability{Capability: "CAP_FOWNER", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_ubifs_listxattr(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "ubifs_listxattr") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["ubifs_listxattr"] = append(mapping["ubifs_listxattr"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_udf_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "udf_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["udf_ioctl"] = append(mapping["udf_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_umount(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "umount") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["umount"] = append(mapping["umount"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_unshare_nsproxy_namespaces(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "unshare_nsproxy_namespaces") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["unshare_nsproxy_namespaces"] = append(mapping["unshare_nsproxy_namespaces"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_user_shm_lock(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "user_shm_lock") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["user_shm_lock"] = append(mapping["user_shm_lock"], analysis.ConditionalCapability{Capability: "CAP_IPC_LOCK", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_userfaultfd(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "userfaultfd") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["userfaultfd"] = append(mapping["userfaultfd"], analysis.ConditionalCapability{Capability: "CAP_SYS_PTRACE", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vfio_group_fops_open(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vfio_group_fops_open") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vfio_group_fops_open"] = append(mapping["vfio_group_fops_open"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vfio_group_get_device_fd(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vfio_group_get_device_fd") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vfio_group_get_device_fd"] = append(mapping["vfio_group_get_device_fd"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vfio_group_set_container(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vfio_group_set_container") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vfio_group_set_container"] = append(mapping["vfio_group_set_container"], analysis.ConditionalCapability{Capability: "CAP_SYS_RAWIO", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_via_dma_init(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "via_dma_init") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["via_dma_init"] = append(mapping["via_dma_init"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vivid_vid_cap_s_fbuf(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vivid_vid_cap_s_fbuf") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vivid_vid_cap_s_fbuf"] = append(mapping["vivid_vid_cap_s_fbuf"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vol_cdev_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vol_cdev_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vol_cdev_ioctl"] = append(mapping["vol_cdev_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_RESOURCE", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vt_compat_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vt_compat_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vt_compat_ioctl"] = append(mapping["vt_compat_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_TTY_CONFIG", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vt_do_kdgkb_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vt_do_kdgkb_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vt_do_kdgkb_ioctl"] = append(mapping["vt_do_kdgkb_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_TTY_CONFIG", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_vt_do_kdsk_ioctl(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "vt_do_kdsk_ioctl") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["vt_do_kdsk_ioctl"] = append(mapping["vt_do_kdsk_ioctl"], analysis.ConditionalCapability{Capability: "CAP_SYS_TTY_CONFIG", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_xfs_ioc_setlabel(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "xfs_ioc_setlabel") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["xfs_ioc_setlabel"] = append(mapping["xfs_ioc_setlabel"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_xfs_readlink_by_handle(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "xfs_readlink_by_handle") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["xfs_readlink_by_handle"] = append(mapping["xfs_readlink_by_handle"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_xfs_set_dmattrs(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "xfs_set_dmattrs") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["xfs_set_dmattrs"] = append(mapping["xfs_set_dmattrs"], analysis.ConditionalCapability{Capability: "CAP_SYS_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}

func Handler_xsk_map_alloc(funs []*ssa.Function, mapping map[string][]analysis.ConditionalCapability) {
	sort.Slice(funs, func(i, j int) bool { return funs[i].Pos() < funs[j].Pos() })
	for index, fun := range funs {
		if strings.Contains(strings.ToLower(fun.Name()), "xsk_map_alloc") {
			logSpecialHandlerFunction(index, fun)
			callers := naivereachability.DirectCallersOf(fun, funs)
			if len(callers) > 0 {
				mapping["xsk_map_alloc"] = append(mapping["xsk_map_alloc"], analysis.ConditionalCapability{Capability: "CAP_NET_ADMIN", ArgCondition: "true", ExtraCondition: "true"})
			}
		}
	}
}
