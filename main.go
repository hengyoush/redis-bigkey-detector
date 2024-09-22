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
}
