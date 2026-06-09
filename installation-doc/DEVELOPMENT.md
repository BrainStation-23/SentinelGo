# Development Guide

## Building for Development

### Prerequisites
- Go 1.22 or higher
- Git

### Build Commands

#### 1. Build the binary
```bash
# Build for current platform
go build -o sentinelgo ./cmd/sentinelgo

# Build with version information
go build -ldflags "-X main.version=v1.0.0" -o sentinelgo ./cmd/sentinelgo

# Build for all platforms
go build -ldflags "-X main.version=v1.0.0" -o sentinelgo ./cmd/sentinelgo
```

#### 2. Manually Run in Development Mode
```bash
# Run in foreground (development mode)
./sentinelgo -run

# Run with custom config

./sentinelgo -run -config .sentinelgo/config.json

# Check status
./sentinelgo -status

# Stop all instances
./sentinelgo -stop
```

#### 3. Setup Agent Registration

Create a config file with your agent credentials:

```json
{
  "agent_uuid": "ca33f7b4-05e4-4af7-89fc-73e55c4a8de7",
  "agent_secret": "Bd025171@1234567",
  "heartbeat_interval": "5m",
  "auto_update": false,
  "github_owner": "habib45",
  "github_repo": "SentinelGo"
}
```

Place the config at:
- Linux/macOS: `~/.sentinelgo/config.json`
- Windows: `%USERPROFILE%\.sentinelgo\config.json`

#### 4. Install as Service

**Linux (systemd):**
```bash
sudo ./sentinelgo -install
```

**macOS (launchd):**
```bash
sudo ./sentinelgo -install
```

**Windows (Service):**
```bash
./sentinelgo -install
```

#### 5. Development Workflow

1. **Make changes to code**
2. **Build and test locally:**
   ```bash
   go build -o sentinelgo ./cmd/sentinelgo
   ./sentinelgo -run
   ```
3. **Check logs for authentication:**
   - Agent registration happens on startup
   - Check for "Agent registration successful" message
4. **Test heartbeat with authentication:**
   - Verify tokens are being used in heartbeat requests
   - Monitor Supabase agents table for updates

#### 6. Testing Authentication Flow

The agent will:
1. Read `agent_uuid` and `agent_secret` from config
2. Call `/functions/v1/agent-login` with credentials
3. Store `refresh_token` in config file
4. Use refresh token for authenticated heartbeat requests
5. Refresh tokens when needed via `/functions/v1/agent-refresh`

#### 7. Debug Tips

- Use `-run` flag for foreground mode to see logs
- Check config file permissions if registration fails
- Verify Supabase endpoint URLs in auth service
- Monitor network requests with tools like `tcpdump` or Wireshark

#### 8. Configuration Options

Key config fields for agent registration:
- `agent_uuid`: Your agent's unique identifier
- `agent_secret`: Your agent's secret key
- `refresh_token`: Automatically populated after successful login

#### 9. Environment Variables

You can override defaults with environment variables:
- `SENTINELGO_CONFIG_PATH`: Custom config file location
- `SENTINELGO_SUPABASE_URL`: Custom Supabase URL (if not hardcoded)

#### 10. Clean Development Environment

```bash
# Stop all running instances
./sentinelgo -stop

# Remove service (if installed)
sudo ./sentinelgo -uninstall

# Clean config
rm -rf ~/.sentinelgo
```

## Architecture Notes

### Clean Architecture Followed
- `cmd/`: Application entrypoints
- `internal/`: Core business logic
  - `auth/`: Authentication service
  - `config/`: Configuration management
  - `heartbeat/`: Heartbeat service
  - `osinfo/`: System information collection
  - `updater/`: Auto-update functionality
  - `lockfile/`: Process locking

### Authentication Flow
1. Agent reads credentials from config
2. Calls Supabase login API
3. Stores refresh token securely
4. Uses token-based auth for heartbeats
5. Implements token refresh mechanism

### Security Best Practices
- No hardcoded secrets in code
- Tokens stored in config file (user-controlled)
- HTTPS-only communication
- Proper timeout and retry logic
- Graceful error handling
