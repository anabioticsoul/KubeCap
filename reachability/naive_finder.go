package naivereachability

import "golang.org/x/tools/go/ssa"

func DirectCallersOf(target *ssa.Function, all []*ssa.Function) []*ssa.Function {
	var callers []*ssa.Function

	for _, f := range all { // 遍历所有“可达函数”
		if f == nil || len(f.Blocks) == 0 {
			continue
		}
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				call, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				common := call.Common()

				// ① 直接函数调用：foo()
				if common.StaticCallee() == target {
					callers = append(callers, f)
					break // 一个 f 找到一次就够了
				}

				// ② 闭包 / 函数值的情况 common.Value 可能是 *ssa.Function
				if fn, ok := common.Value.(*ssa.Function); ok && fn == target {
					callers = append(callers, f)
					break
				}
			}
		}
	}
	return callers
}
