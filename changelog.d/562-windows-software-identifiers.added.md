- Windows software inventory now reports each program's uninstall key name
  (`product_code`, the ProductCode GUID for MSI installs), whether Windows hides
  it from Apps & features (`system_component`), its parent key and release type
  for updates and child components, the vendor homepage (`homepage_url`,
  http(s) only), and the package family name of Microsoft Store apps. The
  console uses them to match installed software to winget and Store packages.
