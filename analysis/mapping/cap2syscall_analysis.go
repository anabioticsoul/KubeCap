package mapping

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/awslabs/ar-go-tools/fake/analysis/deviation"
)

func LoadCapSyscallMaps(path string) (map[string][]string, map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open file error: %w", err)
	}
	defer f.Close()

	// 先用 map[string]map[string]struct{} 做去重
	sysToCapSet := make(map[string]map[string]struct{})
	capToSysSet := make(map[string]map[string]struct{})

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // 跳过空行和注释
		}

		// 先用逗号切分：左边是 cap，右边是 syscall 串
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			// 行格式不符合 "CAP,..."
			continue
		}

		cap := strings.TrimSpace(parts[0])
		sysPart := strings.TrimSpace(parts[1])
		if cap == "" || sysPart == "" {
			continue
		}

		// 剩余部分再用空白切分成多个 syscall 名
		syscalls := strings.Fields(sysPart)

		// 处理 cap -> syscalls
		if _, ok := capToSysSet[cap]; !ok {
			capToSysSet[cap] = make(map[string]struct{})
		}
		for _, s := range syscalls {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			capToSysSet[cap][s] = struct{}{}

			// 处理 syscall -> caps
			if _, ok := sysToCapSet[s]; !ok {
				sysToCapSet[s] = make(map[string]struct{})
			}
			sysToCapSet[s][cap] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan file error: %w", err)
	}

	// 把 set 转成 []string 的 map
	sysToCap := make(map[string][]string)
	for sys, capSet := range sysToCapSet {
		for c := range capSet {
			sysToCap[sys] = append(sysToCap[sys], c)
		}
	}

	capToSys := make(map[string][]string)
	for c, sysSet := range capToSysSet {
		for s := range sysSet {
			capToSys[c] = append(capToSys[c], s)
		}
	}

	return sysToCap, capToSys, nil
}

func LoadMappingFromFile(file string) (map[string][]string, map[string][]string, error) {
	path := file // 换成你的文件路径
	sysToCap, capToSys, err := LoadCapSyscallMaps(path)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, nil, err
	}
	return sysToCap, capToSys, err

	//return sysToCap, capToSys
	//fmt.Println("=== syscall -> capabilities ===")
	//for sys, caps := range sysToCap {
	//	fmt.Printf("%s -> %v\n", sys, caps)
	//}
	//
	//fmt.Println("\n=== capability -> syscalls ===")
	//for cap, syscalls := range capToSys {
	//	fmt.Printf("%s -> %v\n", cap, syscalls)
	//}
}

// LoadDefaultCaps reads default capabilities from file (one capability per line).
func LoadDefaultCaps(path string) (map[string]struct{}, error) {
	return deviation.LoadDefaultCaps(path)
}
