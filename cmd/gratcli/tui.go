package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cooparo/secure-distributed-chat/internal/ipchandle"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/spf13/cobra"
)

// findGratserver locates the gratserver binary: first next to the current
// executable (e.g. both in bin/), then falls back to PATH lookup.
func findGratserver() (string, error) {
	self, err := os.Executable()
	if err == nil {
		sibling := filepath.Join(filepath.Dir(self), "gratserver")
		if _, err := os.Stat(sibling); err == nil {
			return sibling, nil
		}
	}
	return exec.LookPath("gratserver")
}

// serverAlreadyRunning checks if a gratserver is already listening on the
// Unix socket.
func serverAlreadyRunning() bool {
	sp, err := ipchandle.DefaultSocketPath()
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("unix", sp, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// startServer launches gratserver as a background process and waits for the
// socket to become available. Returns the process so the caller can stop it.
func startServer(keyFile string) (*os.Process, error) {
	bin, err := findGratserver()
	if err != nil {
		return nil, fmt.Errorf("cannot find gratserver: %w", err)
	}

	var outputBuf bytes.Buffer
	cmd := exec.Command(bin, "-k", keyFile, "-a", "::1", "-p", "0")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start gratserver: %w", err)
	}

	// Channel to detect early exit
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
	}()

	// Wait for socket to appear
	sp, err := ipchandle.DefaultSocketPath()
	if err != nil {
		cmd.Process.Kill()
		return nil, err
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			return nil, fmt.Errorf("gratserver exited early (err=%v): %s", err, outputBuf.String())
		default:
		}
		conn, dialErr := net.DialTimeout("unix", sp, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return cmd.Process, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	cmd.Process.Kill()
	return nil, fmt.Errorf("gratserver did not become ready within 5s: %s", outputBuf.String())
}

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Interactive TUI chat interface",
	Run: func(cmd *cobra.Command, args []string) {
		keyFile, err := cmd.Flags().GetString("keyfile")
		if err != nil {
			fmt.Printf("Error reading flags: %s\n", err.Error())
			os.Exit(1)
		}

		privKeyBundle := &identity.PrivateKeyBundle{}
		if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
			fmt.Println("No identity found, generating a new one...")
			privKeyBundle, err = identity.GenerateIdentity()
			if err != nil {
				fmt.Printf("Error generating identity: %s\n", err.Error())
				os.Exit(1)
			}
			if err := privKeyBundle.Save(keyFile); err != nil {
				fmt.Printf("Error saving keyfile: %s\n", err.Error())
				os.Exit(1)
			}
		} else if err := privKeyBundle.Load(keyFile); err != nil {
			fmt.Printf("Error loading keyfile %s: %s\n", keyFile, err.Error())
			os.Exit(1)
		}

		address, err := privKeyBundle.Public().Address()
		if err != nil {
			fmt.Printf("Error calculating address: %s\n", err.Error())
			os.Exit(1)
		}

		// Start gratserver if not already running
		var serverProc *os.Process
		if !serverAlreadyRunning() {
			fmt.Println("Starting gratserver...")
			serverProc, err = startServer(keyFile)
			if err != nil {
				fmt.Printf("Error starting server: %s\n", err.Error())
				os.Exit(1)
			}
			defer func() {
				serverProc.Signal(os.Interrupt)
				// Wait briefly for graceful shutdown, then kill
				time.Sleep(500 * time.Millisecond)
				serverProc.Kill()
			}()
		}

		m := newModel(address)
		p := tea.NewProgram(m, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running TUI: %s\n", err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	tuiCmd.Flags().StringP("keyfile", "k", "./private.key", "Private key file")
}
