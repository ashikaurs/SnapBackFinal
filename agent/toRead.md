Run the same XML command, but change the destination:
@'
<Sysmon schemaversion="4.91">
<HashAlgorithms>SHA256</HashAlgorithms>
<EventFiltering>
<ProcessCreate onmatch="exclude" />
<ProcessTerminate onmatch="exclude" />
<ImageLoad onmatch="exclude" />
<CreateRemoteThread onmatch="exclude" />
<ProcessAccess onmatch="exclude" />
<FileCreate onmatch="exclude" />
<RegistryEvent onmatch="exclude" />
<FileCreateStreamHash onmatch="exclude" />
<FileDeleteDetected onmatch="exclude" />
</EventFiltering>
</Sysmon>
'@ | Set-Content -Path "C:\SNAP_BACK\config\sysmonconfig.xml" -Encoding UTF8

3. Apply the configuration
   sysmon.exe -c "C:\SNAP_BACK\config\sysmonconfig.xml"

Then verify:
sysmon.exe -c

---

Good. Sysmon is running with our updated configuration.

We now have:

- Process creation and termination monitoring.
- File creation and deletion monitoring.
- Process access and remote-thread monitoring.
- Registry and alternate data stream monitoring.
- SHA256 hashing.
  Important: Ordinary file-content modifications are still handled by ReadDirectoryChangesW. Sysmon Event ID 2 is not enabled here.
  Next: File Inventory
  We'll implement agent/inventory/file_inventory.py.

===================

What this captures:
Event ID Information
1 Process creation
5 Process termination
7 DLL/image loading
8 Remote thread creation
10 Process access
11 File creation
12–14 Registry changes
15 Alternate data stream creation
26 File deletion
