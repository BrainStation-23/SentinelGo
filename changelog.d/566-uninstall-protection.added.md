- Uninstall protection (Windows): with it switched on in the console, removing
  the agent needs the device's uninstall token. The agent syncs the token's
  hash from the console every 15 minutes (`agent_get_uninstall_protection`;
  it never holds the token). The MSI's uninstall runs the new
  `sentinelgo uninstall-check -token …` and fails without the right token
  (`msiexec /x … UNINSTALL_TOKEN=…`); `sentinelgo -uninstall` takes
  `-uninstall-token -` (read from stdin). Major upgrades never need it, and a
  device that hasn't synced yet lets the uninstall through. A deterrent, not
  tamper protection: an administrator can still remove the service by hand.
  This is the first release with `uninstall-check`; set the backend's
  `UNINSTALL_CHECK_MIN_VERSION` to it (#566).
