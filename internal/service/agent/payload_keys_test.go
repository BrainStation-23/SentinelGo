package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/localadmin"
	"sentinelgo/internal/osinfo/shared"
)

// inventoryKeys is every top-level key the inventory can carry: the
// contract with agent_enqueue_inventory. Adding or dropping a key means
// changing this list, and checking that the server reads it.
var inventoryKeys = []string{
	"hostname", "computer_name", "cpu_info", "serial_number", "hardware_model",
	"local_users", "battery_condition", "rams", "display", "agent_version",
	"build_flavor", "build_features", "fqdn", "chassis_type", "kernel_version",
	"gpus", "disks", "firmware", "network_adapters", "peripherals",
	"audio_devices", "printers", "os_information", "security_info", "mdm",
	"power_telemetry", "sessions", "capabilities",
	"local_admin_members", "signed_in_users", "last_signed_in_user", "identity_join",
}

// droppedInventoryKeys were sent once and never read by the server (#563):
// status (the server sets online itself), tpm_version (read from
// security_info.hardware_security), admin_grants and yara.
var droppedInventoryKeys = []string{"status", "tpm_version", "admin_grants", "yara"}

// jsonKeys returns the JSON names of t's fields, flattening embedded structs
// as encoding/json does.
func jsonKeys(t reflect.Type) []string {
	var keys []string
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			keys = append(keys, jsonKeys(f.Type)...)
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		keys = append(keys, name)
	}
	return keys
}

func TestInventoryKeys(t *testing.T) {
	got := jsonKeys(reflect.TypeOf(AgentUpdatePayload{}))
	slices.Sort(got)
	want := slices.Clone(inventoryKeys)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("inventory keys = %q\nwant %q", got, want)
	}
	for _, k := range droppedInventoryKeys {
		if slices.Contains(got, k) {
			t.Errorf("inventory still has %q, which the server ignores (#563)", k)
		}
	}
}

// The dropped keys stay out of a real upload, even with a TPM version
// collected and an admin grant stored on the device.
func TestUpdateAgentInfo_OmitsDroppedKeys(t *testing.T) {
	var body map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Payload map[string]json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(b, &req); err != nil {
			t.Errorf("decode: %v", err)
		}
		body = req.Payload
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	dir := t.TempDir()
	grants := `[{"grant_id":"g1","member":"alice","expires_at":"2099-01-01T00:00:00Z","state":"active"}]`
	if err := os.WriteFile(localadmin.StorePath(dir), []byte(grants), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{SupabaseURL: server.URL, AccessToken: "t", DeviceID: "d", Path: filepath.Join(dir, "config.json")}
	si := &shared.SystemInfo{Hostname: "h", TPMVersion: "2.0"}
	if err := NewAgentService().UpdateAgentInfo(context.Background(), cfg, si); err != nil {
		t.Fatal(err)
	}
	if body == nil {
		t.Fatal("no payload sent")
	}
	for _, k := range droppedInventoryKeys {
		if v, ok := body[k]; ok {
			t.Errorf("payload has %q = %s", k, v)
		}
	}
	for k := range body {
		if !slices.Contains(inventoryKeys, k) {
			t.Errorf("payload has undocumented key %q", k)
		}
	}
	for _, k := range []string{"hostname", "build_flavor", "build_features", "capabilities"} {
		if _, ok := body[k]; !ok {
			t.Errorf("payload lacks %q", k)
		}
	}
}
