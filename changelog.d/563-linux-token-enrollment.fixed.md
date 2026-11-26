- A Linux agent no longer tries first-boot token enrollment, which the server
  doesn't offer for Linux: it logs once that a per-device `config.json` is
  needed. A `400` answer from enrollment is now treated as a rejected token
  instead of being retried.
