package main

import (
	"os"
	"redis-bigkey/agent"
	"strconv"
)

func main() {
	pidStr := os.Args[1]
	pid, _ := strconv.Atoi(pidStr)
	agent.AgentOpts.Pid = pid
	agent.SetupAgent()
	// pid := 1690013 // 替换为实际的 PID
	// fd := 12       // 替换为实际的文件描述符

	// // 获取 socket ID
	// socketID, err := getSocketInfoByPidFd(pid, fd)
	// if err != nil {
	// 	fmt.Printf("Error: %v\n", err)
	// 	return
	// }

	// fmt.Printf("Socket ID: %s\n", socketID)

	// // 获取连接信息
	// localIP, localPort, remoteIP, remotePort, err := getConnectionInfo(socketID)
	// if err != nil {
	// 	fmt.Printf("Error: %v\n", err)
	// 	return
	// }

	// fmt.Printf("Local Address: %s:%d\n", localIP, localPort)
	// fmt.Printf("Remote Address: %s:%d\n", remoteIP, remotePort)
}
