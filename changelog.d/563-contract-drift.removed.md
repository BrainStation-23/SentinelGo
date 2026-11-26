- The inventory no longer sends `status`, the top-level `tpm_version` (still
  sent in `security_info.hardware_security`), `admin_grants` or the `yara`
  summary, and package uploads no longer send `collected_at`. The server never
  read them. The `X-Device-ID` header is no longer sent on DLP, audit-log and
  MDM calls; the server identifies the device from the agent's token.
- The agent no longer advertises the capabilities `users_inventory_v2`,
  `exposure_scope_v1`, `local_admin_v1`, `windows_mdm_state_v1`,
  `dlp_at_rest_v1` and `apple_mdm_state_v1`, which nothing on the server
  checks. The features themselves are unchanged.
