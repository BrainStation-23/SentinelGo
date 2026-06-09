package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/system"
	"sentinelgo/internal/sanitize"
	tasksvc "sentinelgo/internal/service/task"
)

// handleAgentTaskPolling polls for tasks once and stores them locally.
func handleAgentTaskPolling(cfg *config.Config) {
	configDir := system.GetConfigDir()
	if err := os.MkdirAll(configDir, 0750); err != nil {
		log.Fatalf("Error: Failed to create task storage directory %s: %v. Try running with sudo or check permissions.", configDir, err)
	}

	dbPath := filepath.Join(configDir, "tasks.sqlite")
	log.Printf("Polling: Using database path: %s", sanitize.ForLog(dbPath))

	agentTaskPollingService, err := tasksvc.NewTaskPollingService(cfg, dbPath)
	if err != nil {
		log.Fatalf("Failed to create task polling service: %v", err)
	}
	defer func() {
		if err := agentTaskPollingService.Close(); err != nil {
			log.Printf("Error closing agent task polling service: %v", err)
		}
	}()

	ctx := context.Background()
	if err := agentTaskPollingService.PollAndStoreTasks(ctx); err != nil {
		log.Printf("Error polling tasks: %v", err)
	}
}

// handleAgentTaskExecution runs the task execution loop over locally stored tasks.
func handleAgentTaskExecution(cfg *config.Config) {
	configDir := system.GetConfigDir()
	if err := os.MkdirAll(configDir, 0750); err != nil {
		log.Fatalf("Error: Failed to create task storage directory %s: %v. Try running with sudo or check permissions.", configDir, err)
	}

	dbPath := filepath.Join(configDir, "tasks.sqlite")
	log.Printf("Executor: Using database path: %s", sanitize.ForLog(dbPath))

	if _, err := os.Stat(dbPath); err == nil {
		log.Printf("Executor: Database exists, checking content...")
		time.Sleep(100 * time.Millisecond)
	}

	pollingSvc, err := tasksvc.NewTaskPollingService(cfg, dbPath)
	if err != nil {
		log.Fatalf("Failed to create task polling service for execution: %v", err)
	}
	defer func() {
		if err := pollingSvc.Close(); err != nil {
			log.Printf("Error closing polling service: %v", err)
		}
	}()

	agentTaskExecutionService := tasksvc.NewTaskExecutorService(cfg, pollingSvc)

	ctx := context.Background()
	agentTaskExecutionService.RunExecutionLoop(ctx)
}

// handleAgentTaskManager runs the integrated polling + execution task manager
// until an interrupt signal is received.
func handleAgentTaskManager(cfg *config.Config) {
	fmt.Println("Starting integrated task polling and execution service...")

	taskManager, err := tasksvc.NewTaskManager(cfg)
	if err != nil {
		log.Fatalf("Failed to create task manager: %v", err)
	}
	defer func() {
		if err := taskManager.Close(); err != nil {
			log.Printf("Error closing task manager: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	go func() {
		if err := taskManager.Run(ctx); err != nil {
			log.Printf("Task manager error: %v", err)
		}
	}()

	<-sigChan
	fmt.Println("Task manager service stopped")
}
