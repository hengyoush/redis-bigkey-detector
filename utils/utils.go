package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GetSocketInfoByPidFd 获取 socket ID
func GetSocketInfoByPidFd(pid int, fd int) (string, error) {
	// 构造文件描述符路径
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)

	// 读取符号链接
	link, err := os.Readlink(fdPath)
	if err != nil {
		return "", fmt.Errorf("failed to read link: %v", err)
	}

	// 判断是否是 socket
	if !strings.HasPrefix(link, "socket:[") {
		return "", fmt.Errorf("fd is not a socket, link: %s", link)
	}

	// 解析 socket:[id] 中的 id
	socketID := strings.TrimPrefix(link, "socket:[")
	socketID = strings.TrimSuffix(socketID, "]")

	return socketID, nil
}

func bytesToIPv4(b []byte) (string, error) {
	if len(b) != 4 {
		return "", fmt.Errorf("invalid IPv4 address length: expected 4 bytes, got %d", len(b))
	}

	// 将每个字节转换为字符串表示
	parts := []string{
		strconv.Itoa(int(b[3])),
		strconv.Itoa(int(b[2])),
		strconv.Itoa(int(b[1])),
		strconv.Itoa(int(b[0])),
	}

	// 拼接为标准 IPv4 格式：X.X.X.X
	return fmt.Sprintf("%s.%s.%s.%s", parts[0], parts[1], parts[2], parts[3]), nil
}

// // ParseIPAndPort 解析十六进制的 IP 和端口号
func ParseIPAndPort(hexIP, hexPort string, ipv6 bool) (string, int, error) {
	// 解析端口
	port, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return "", 0, err
	}

	// 解析 IPv4 或 IPv6 地址
	if ipv6 {
		ipBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			val, err := strconv.ParseUint(hexIP[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0, err
			}
			ipBytes[i] = byte(val)
		}
		return "", int(port), nil
	} else {
		ipBytes := make([]byte, 4)
		for i := 0; i < 4; i++ {
			val, err := strconv.ParseUint(hexIP[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0, err
			}
			ipBytes[i] = byte(val)
		}
		ipStr, _ := bytesToIPv4(ipBytes)
		return ipStr, int(port), nil
	}
}

// // GetConnectionInfo 读取并解析 /proc/net/tcp 文件，匹配 socketID 获取 IP 地址和端口信息
func GetConnectionInfo(socketID string) (string, int, string, int, error) {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", 0, "", 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 跳过第一行标题
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		localAddress := fields[1]
		remoteAddress := fields[2]
		inode := fields[9]

		// 匹配 inode
		if inode == socketID {
			// 解析本地 IP 和端口
			localIP, localPort, err := ParseIPAndPort(localAddress[:8], localAddress[9:], false)
			if err != nil {
				return "", 0, "", 0, err
			}

			// 解析远程 IP 和端口
			remoteIP, remotePort, err := ParseIPAndPort(remoteAddress[:8], remoteAddress[9:], false)
			if err != nil {
				return "", 0, "", 0, err
			}

			return localIP, localPort, remoteIP, remotePort, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", 0, "", 0, err
	}

	return "", 0, "", 0, fmt.Errorf("no connection found for socketID: %s", socketID)
}
func Int8SliceToUint64(arr []uint8) uint64 {
	var result uint64

	// 最多只能处理前 8 个元素
	limit := len(arr)
	if limit > 8 {
		limit = 8
	}

	for i := 0; i < limit; i++ {
		// 将 int8 转换为 uint64，并且按位移位组合成一个 uint64
		result |= uint64(arr[i]&(0xFF)) << (8 * i)
	}

	return result
}
