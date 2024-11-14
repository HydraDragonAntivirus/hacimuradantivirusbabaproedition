rule Virus_Autorun_Trojan_GenericKDZ_94942_4 {
   meta:
      description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKDZ.94942_4.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "42856ebb178057d425b0915032faa9243a470593208790861c68cd3115a13240"
   strings:
      $x1 = "UseSystemPowerShell - Execute PowerShell using an external process instead of the built-in PowerShell host. Should only be used " wide
      $x2 = "  install = \"-y -whatif -? --pre --version= --params='' --install-arguments='' --override-arguments --ignore-dependencies --sou" ascii
      $x3 = "  upgrade = \"-y -whatif -? --pre --version='' --except='' --params='' --install-arguments='' --override-arguments --ignore-depe" ascii
      $x4 = "    $wrappedStatements = \"-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat Text -OutputFormat Text -Enco" ascii
      $x5 = "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command \"{0}\"" fullword wide
      $x6 = "$allcommands = \" --debug --verbose --trace --noop --help --accept-license --confirm --limit-output --no-progress --log-file='' " ascii
      $x7 = "  source = \"--name='' --source='' --user='' --password='' --priority= --bypass-proxy --allow-self-service -?\" + $allcommands" fullword ascii
      $x8 = " * ChocolateyResponseTimeout - How long to wait for a download to complete? Set by config `commandExecutionTimeoutSeconds` (CHEC" wide
      $x9 = "# Install-ChocolateyShortcut -shortcutFilePath \"<path>\" -targetPath \"<path>\" [-workDirectory \"C:\\\" -arguments \"C:\\test." wide
      $x10 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><asmv1:assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xml" ascii
      $x11 = "Proxy Password - Explicit proxy password (optional) to be used with username. Requires explicity proxy (`--proxy` or config sett" wide
      $x12 = " * ChocolateyEnvironmentDebug - Was `--debug` passed? If using the built-in PowerShell host, this is always true (but only logs " wide
      $x13 = " * ChocolateyEnvironmentVerbose - Was `--verbose` passed? If using the built-in PowerShell host, this is always true (but only l" wide
      $x14 = "* Get-BinRoot - this is a horribly named function that doesn't do what new folks think it does. It gets you the 'tools' root, wh" wide
      $x15 = "Scripts Check $LastExitCode (external commands) - Leave this off unless you absolutely need it while you fix your package script" wide
      $x16 = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
      $x17 = "                        Environment.ExitCode = CommandExecutor.execute(path_to_exe, arguments, working_directory, is_gui, wait_f" ascii
      $x18 = "                Environment.ExitCode = CommandExecutor.execute(path_to_exe, arguments, working_directory, is_gui, wait_for_exit:" ascii
      $x19 = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
      $x20 = "  Write-Debug \"Error handling check: `'Get-ItemProperty`' fails if a registry key is encoded incorrectly.\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
rule Virus_Autorun_Trojan_GenericKDZ_94942_5 {
   meta:
      description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKDZ.94942_5.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "f424124429184fcce5f03de260e2a123484d1943b89552c527f43cf7d593794c"
   strings:
      $x1 = "UseSystemPowerShell - Execute PowerShell using an external process instead of the built-in PowerShell host. Should only be used " wide
      $x2 = "  install = \"-y -whatif -? --pre --version= --params='' --install-arguments='' --override-arguments --ignore-dependencies --sou" ascii
      $x3 = "  upgrade = \"-y -whatif -? --pre --version='' --except='' --params='' --install-arguments='' --override-arguments --ignore-depe" ascii
      $x4 = "    $wrappedStatements = \"-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat Text -OutputFormat Text -Enco" ascii
      $x5 = "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command \"{0}\"" fullword wide
      $x6 = "$allcommands = \" --debug --verbose --trace --noop --help --accept-license --confirm --limit-output --no-progress --log-file='' " ascii
      $x7 = "  source = \"--name='' --source='' --user='' --password='' --priority= --bypass-proxy --allow-self-service -?\" + $allcommands" fullword ascii
      $x8 = " * ChocolateyResponseTimeout - How long to wait for a download to complete? Set by config `commandExecutionTimeoutSeconds` (CHEC" wide
      $x9 = "# Install-ChocolateyShortcut -shortcutFilePath \"<path>\" -targetPath \"<path>\" [-workDirectory \"C:\\\" -arguments \"C:\\test." wide
      $x10 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><asmv1:assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xml" ascii
      $x11 = "Proxy Password - Explicit proxy password (optional) to be used with username. Requires explicity proxy (`--proxy` or config sett" wide
      $x12 = " * ChocolateyEnvironmentDebug - Was `--debug` passed? If using the built-in PowerShell host, this is always true (but only logs " wide
      $x13 = " * ChocolateyEnvironmentVerbose - Was `--verbose` passed? If using the built-in PowerShell host, this is always true (but only l" wide
      $x14 = "* Get-BinRoot - this is a horribly named function that doesn't do what new folks think it does. It gets you the 'tools' root, wh" wide
      $x15 = "Scripts Check $LastExitCode (external commands) - Leave this off unless you absolutely need it while you fix your package script" wide
      $x16 = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
      $x17 = "                        Environment.ExitCode = CommandExecutor.execute(path_to_exe, arguments, working_directory, is_gui, wait_f" ascii
      $x18 = "                Environment.ExitCode = CommandExecutor.execute(path_to_exe, arguments, working_directory, is_gui, wait_for_exit:" ascii
      $x19 = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
      $x20 = "  Write-Debug \"Error handling check: `'Get-ItemProperty`' fails if a registry key is encoded incorrectly.\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
rule Trojan_Danger_Trojan_GenericKD_72853156_56 {
   meta:
      description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_56.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "f48dc4349b17c5db231be8e38c6e9aa55993614d3ecce977526d872dfe38a50d"
   strings:
      $x1 = "UseSystemPowerShell - Execute PowerShell using an external process instead of the built-in PowerShell host. Should only be used " wide
      $x2 = "  upgrade = \"-y -whatif -? --pre --version='' --except='' --params='' --install-arguments='' --override-arguments --ignore-depe" ascii
      $x3 = "  install = \"-y -whatif -? --pre --version= --params='' --install-arguments='' --override-arguments --ignore-dependencies --sou" ascii
      $x4 = "    $wrappedStatements = \"-NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat Text -OutputFormat Text -Enco" ascii
      $x5 = "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command \"{0}\"" fullword wide
      $x6 = "$allcommands = \" --debug --verbose --trace --noop --help --accept-license --confirm --limit-output --no-progress --log-file='' " ascii
      $x7 = "  source = \"--name='' --source='' --user='' --password='' --priority= --bypass-proxy --allow-self-service -?\" + $allcommands" fullword ascii
      $x8 = " * ChocolateyResponseTimeout - How long to wait for a download to complete? Set by config `commandExecutionTimeoutSeconds` (CHEC" wide
      $x9 = "# Install-ChocolateyShortcut -shortcutFilePath \"<path>\" -targetPath \"<path>\" [-workDirectory \"C:\\\" -arguments \"C:\\test." wide
      $x10 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><asmv1:assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xml" ascii
      $x11 = "  download = \"--internalize --internalize-all-urls --ignore-dependencies --installed-packages --ignore-unfound-packages --resou" ascii
      $x12 = "Proxy Password - Explicit proxy password (optional) to be used with username. Requires explicit proxy (`--proxy` or config setti" wide
      $x13 = "# The command will be elevated to admin privileges." fullword ascii
      $x14 = "* Get-ToolsLocation - used to get you the 'tools' root, which by default is set to 'c:\\tools', not the chocolateyInstall bin fo" wide
      $x15 = " * ChocolateyEnvironmentDebug - Was `--debug` passed? If using the built-in PowerShell host, this is always true (but only logs " wide
      $x16 = " * ChocolateyEnvironmentVerbose - Was `--verbose` passed? If using the built-in PowerShell host, this is always true (but only l" wide
      $x17 = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
      $x18 = "                        Environment.ExitCode = CommandExecutor.execute(path_to_exe, arguments, working_directory, is_gui, wait_f" ascii
      $x19 = "                Environment.ExitCode = CommandExecutor.execute(path_to_exe, arguments, working_directory, is_gui, wait_for_exit:" ascii
      $x20 = "powershell -NoProfile -ExecutionPolicy unrestricted -Command \"\"& `'$psFileFullPath`'  %*\"\"\"| Out-File $packageBatchFileName" ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
rule Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_6_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_6_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "9240fd84d78e86472142e0e8034f985c05493688465eedc746fd3ff7f778ad09"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii
      $x2 = "Usage: %ls [ProcessID [ThreadId [Flags[:MiniDumpFlags] [SqlInfoPtr [DumpDir [ExceptionRecordPtr [ContextPtr [ExtraFile] [Pattern" wide
      $s3 = "yIdentity name=\"setup.exe\" version=\"1.0.0.0\" processorArchitecture=\"x86\" type=\"win32\"></assemblyIdentity><description>Wi" ascii
      $s4 = "Processor Features: %08X - %08X" fullword ascii
      $s5 = "Failed to load ntdll.dll" fullword ascii
      $s6 = "Failed to verify elevation state." fullword ascii
      $s7 = "level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><asmv3:application" ascii
      $s8 = "Read %d bytes from remote process." fullword wide
      $s9 = ".SQL External minidumpe" fullword wide
      $s10 = "mv3:windowsSettings><ws:dpiAware xmlns:ws=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</ws:dpiAware></asmv3:wi" ascii
      $s11 = "<description>Windows Error Reporting</description>" fullword ascii
      $s12 = "Posted message to parent process to signal that the parent process can stop waiting" fullword ascii
      $s13 = "Failed to get the default provider key package id." fullword ascii
      $s14 = "Failed to read exe package execution mode." fullword ascii
      $s15 = "Failed to write exe package execution mode to message buffer." fullword ascii
      $s16 = "Failed to get either ProductCode or UpgradeCode." fullword ascii
      $s17 = "Failed to send completion over the pipe." fullword ascii
      $s18 = "Failed to write message to pipe." fullword ascii
      $s19 = "t Bootstrapper</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Cont" ascii
      $s20 = "GetPathForExtraFiles failed, error: 0x%08X" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and 4 of them
}
rule Trojan_Danger_Trojan_GenericKD_72677122_271_1 {
   meta:
      description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_271_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "75f4e8e349e0790c527833db47183a9262f3ec2d3300eabead1dd855bb35ced4"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x2 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x3 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolchacha20: wrong HChaCha20 key sizecrypto/aes: invalid buffer" ascii
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x5 = "entersyscallexit status gcBitsArenasgcpacertracegetaddrinfowharddecommithost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii
      $x6 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
      $x7 = "http: putIdleConn: keep alives disabledinternal error: exit hook invoked panicinvalid HTTP header value for header %qinvalid ind" ascii
      $x8 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertFindChainInStoreCertOpenSystemStoreWChangeSe" ascii
      $x9 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
      $x10 = "(MISSING)(unknown), newval=, oldval=, size = , tail = -07:00:00244140625: status=AuthorityBassa_VahBhaiksukiClassINETCreateDCWCr" ascii
      $x11 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vunpacking Question.Classupdate d" ascii
      $x12 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii
      $x13 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthlooking for beginning of object key stringmi" ascii
      $x14 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRtlDeleteFunctionTableRtlGetNtVersionNumbersSakhalin Standard " ascii
      $x15 = "AdjustWindowRectAlready ReportedCloseEnhMetaFileConnectNamedPipeContent-EncodingContent-LanguageContent-Length: CopyEnhMetaFileW" ascii
      $x16 = "Temporary RedirectTerminateJobObjectTime.MarshalJSON: Time.MarshalText: UNKNOWN_SETTING_%dVariation_SelectorWriteProcessMemoryad" ascii
      $x17 = "unixpacketunknown pcuser-agentuser32.dllws2_32.dllyt-dlp.exe  of size   (targetpc= , plugin:  ErrCode=%v KiB work,  exp.) for  f" ascii
      $x18 = "os/exec.Command(bad TinySizeClassdecryption failedentersyscallblockexec format errorexec: killing Cmdexec: not startedfractional" ascii
      $x19 = "span set block with unpopped elements found in resettls: received a session ticket with invalid lifetimetls: server selected uns" ascii
      $x20 = "crypto/ecdh: bad X25519 remote ECDH input: low order pointcrypto/ecdh: internal error: converting the wrong key typecrypto/ellip" ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_5_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_5_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "f4f771eec7a852ae96dfccd4796e9930143891c7726fb33b6d1611bf0f9e735e"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "ndency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asI" ascii
      $s3 = "nstall System v3.0a2</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Commo" ascii
      $s4 = "microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
      $s5 = "GAttempt to add quarantined event to quarantine." fullword wide
      $s6 = "Failed to find an open key anywhere in the chain?" fullword wide
      $s7 = "<description>Microsoft Office</description>" fullword ascii
      $s8 = "ker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatib" ascii
      $s9 = "Java(TM) Web Start 10.45.2.18-fcs" fullword wide
      $s10 = "'Get' failed because the Variant is not the correct type." fullword ascii
      $s11 = "SHIP ASSERT FAILED!" fullword wide
      $s12 = "Silhouette" fullword ascii
      $s13 = "lication></compatibility><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schem" ascii
      $s14 = "Sequential Queue" fullword ascii
      $s15 = " is being used after it has been destroyed." fullword ascii
      $s16 = "Rdeque<T> too long" fullword ascii
      $s17 = "GEvent Buffer is full" fullword wide
      $s18 = "G!!UNAVAILABLE!!" fullword wide
      $s19 = "y.v1\"><application><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4" ascii
      $s20 = "@Office" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and 4 of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aeOesjp_6_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aeOesjp_6_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "7460b6921143a152b0975f67e89af586349229d1ff6b1317aff73eb982408f4a"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"setup.exe\" version=\"1.0." ascii
      $s2 = "Plan skipped related bundle: %1!ls!, type: %2!hs!, because it was dependent and the current bundle is being executed as type: %3" ascii
      $s3 = "EBurn Engine Fatal Error: failed to open log file." fullword wide
      $s4 = "Plan skipped related bundle: %1!ls!, type: %2!hs!, because it was dependent and the current bundle is being executed as type: %3" ascii
      $s5 = "Failed to open Application event log" fullword ascii
      $s6 = "Failed to update name and publisher." fullword ascii
      $s7 = "Failed to convert bundle update guid into string." fullword ascii
      $s8 = "Failed to create bundle update guid." fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aiYvnz_5_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_5_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "cb7c8b997f3aaba7302d9824345339e90c34a998bbc20735b17129df3c26ef7b"
   strings:
      $s1 = "<description>NameControl Server - serves to show presence in SP sites</description>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_5_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_5_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "b282111e75a449439772a15d56bcb71ba26e1c730c64d8fbe227ac580794da46"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii
      $s2 = "yIdentity name=\"setup.exe\" version=\"1.0.0.0\" processorArchitecture=\"x86\" type=\"win32\"></assemblyIdentity><description>Wi" ascii
      $s3 = "      <section name=\"serviceHostingEnvironment\" type=\"System.ServiceModel.Configuration.ServiceHostingEnvironmentSection, Sys" ascii
      $s4 = "      <section name=\"comContracts\" type=\"System.ServiceModel.Configuration.ComContractsSection, System.ServiceModel, Version=" ascii
      $s5 = "      <section name=\"dataContractSerializer\" type=\"System.Runtime.Serialization.Configuration.DataContractSerializerSection, " ascii
      $s6 = "      <section name=\"net.tcp\" type=\"System.ServiceModel.Activation.Configuration.NetTcpSection, System.ServiceModel, Version=" ascii
      $s7 = "Failed to load ntdll.dll" fullword ascii
      $s8 = "      <section name=\"diagnostics\" type=\"System.ServiceModel.Activation.Configuration.DiagnosticSection, System.ServiceModel, " ascii
      $s9 = "      <section name=\"bindings\" type=\"System.ServiceModel.Configuration.BindingsSection, System.ServiceModel, Version=3.0.0.0," ascii
      $s10 = "      <section name=\"behaviors\" type=\"System.ServiceModel.Configuration.BehaviorsSection, System.ServiceModel, Version=3.0.0." ascii
      $s11 = "      <section name=\"services\" type=\"System.ServiceModel.Configuration.ServicesSection, System.ServiceModel, Version=3.0.0.0," ascii
      $s12 = "      <section name=\"net.pipe\" type=\"System.ServiceModel.Activation.Configuration.NetPipeSection, System.ServiceModel, Versio" ascii
      $s13 = "      <section name=\"extensions\" type=\"System.ServiceModel.Configuration.ExtensionsSection, System.ServiceModel, Version=3.0." ascii
      $s14 = "      <section name=\"client\" type=\"System.ServiceModel.Configuration.ClientSection, System.ServiceModel, Version=3.0.0.0, Cul" ascii
      $s15 = "      <section name=\"diagnostics\" type=\"System.ServiceModel.Configuration.DiagnosticSection, System.ServiceModel, Version=3.0" ascii
      $s16 = "Failed to verify elevation state." fullword ascii
      $s17 = "ServiceModelReg.exe was unable to register the ServiceModel IIS scriptmaps because another application is locking the IIS metaba" ascii
      $s18 = "level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><asmv3:application" ascii
      $s19 = "mv3:windowsSettings><ws:dpiAware xmlns:ws=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</ws:dpiAware></asmv3:wi" ascii
      $s20 = "Posted message to parent process to signal that the parent process can stop waiting" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and 4 of them
}
rule Virus_Infector_Win32_Nestha_C {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Nestha.C.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "d787818ec51ece351dbfd771829c3815ddaedcb8550c220fb16de9ddf418c146"
   strings:
      $s1 = "Failed to get handle to Win32 OneNote process. Process Id: " fullword wide
      $s2 = "Failed to properly retrieve parent process info" fullword wide
      $s3 = "Error waiting for process handle to terminate, returnCode: " fullword wide
      $s4 = "Failed to terminate process, PID=" fullword wide
      $s5 = "OpenProcess() returned nullptr. Error: " fullword wide
      $s6 = " to the list of known setup active processes" fullword wide
      $s7 = " to the list of unknown setup active processes" fullword wide
      $s8 = "Terminating process " fullword wide
      $s9 = "Found process, PPID=" fullword wide
      $s10 = "Detected parent process name not allowed to log" fullword wide
      $s11 = "Parent Process Name : " fullword wide
      $s12 = " from process list." fullword wide
      $s13 = "Excluding current process ID " fullword wide
      $s14 = "Adding process " fullword wide
      $s15 = "Registry key LastKnownODSInfo was not found, adding all processes as unknown" fullword wide
      $s16 = "CommonUtil::GetResourceStringsForSyncRoot got display name resource:" fullword wide
      $s17 = "Killing Win32 OneNote process with process Id: " fullword wide
      $s18 = "AddFolderToLeftNav failed to get AccountInfo for given instance ID: " fullword wide
      $s19 = "Waiting and shutting down first process. PID=" fullword wide
      $s20 = "CommonUtil::DeleteMatchingKeysUnderSubkey: EnumerateRegistryKeys failed with hr=" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      8 of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_auCCoZb_6_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_6_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "e25748fc0a21f5828cad702244731a582eb13e87950adadf0ac99906d769edb3"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><rg:licenseGroup xmlns:rg=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\"><r:license xmlns:r=\"ur" ascii
      $x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity processorArchitecture=\"x86\" typ" ascii
      $s3 = "rosoft.com/xrml/lwc14n\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference><Transforms><Tra" ascii
      $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity processorArchitecture=\"x86\" typ" ascii
      $s5 = "cription><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" pro" ascii
      $s6 = "orm Algorithm=\"urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform\"/><Transform Algorithm=\"http://www.microsoft.com/xrml/lwc14n" ascii
      $s7 = "om/DRM/XrML2/SL/v2\" xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"><r:title>Office 16 UL phone License (Private)</r:titl" ascii
      $s8 = "2003:01-REL-R-NS:licenseTransform\"/><Transform Algorithm=\"http://www.microsoft.com/xrml/lwc14n\"/></Transforms><DigestMethod A" ascii
      $s9 = "Tables xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"><tm:infoList tag=\"#global\"><tm:infoStr name=\"licenseType\">msft:" ascii
      $s10 = "r:grant><r:forAll varName=\"anyRight\"></r:forAll><r:forAll varName=\"anyAppId\"></r:forAll><r:keyHolder licensePartId=\"account" ascii
      $s11 = "0*** Software Failure: %s ***" fullword ascii
      $s12 = "<Package Id=\"OneNoteMUI.it-it\" Type=\"MSI\" Path=\"OneNoteMUI.MSI\" Version=\"1.0\" ProductCode=\"{90120000-00A1-0410-0000-000" ascii
      $s13 = "<Package Id=\"OneNoteMUI.it-it\" Type=\"MSI\" Path=\"OneNoteMUI.MSI\" Version=\"1.0\" ProductCode=\"{90120000-00A1-0410-0000-000" ascii
      $s14 = "/Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></r:info></r:keyHolder><tm:decryptContent/><tm:symmetricKey><tm:AESKe" ascii
      $s15 = "icensePartIdRef=\"accountKey\"/><r:right varRef=\"anyRight\"/><sl:appId varRef=\"anyAppId\"/><r:trustedRootIssuers><r:keyHolder>" ascii
      $s16 = "<r:info><KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru16t2VcbVg92rhNO1ng3kIn/AY/" ascii
      $s17 = "o><KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><RSAKeyValue><Modulus>lAi6wXhcWOjn1rN1aIy6z4YBcYlkdrxP9EEw7iiD0tg6i0aVO" ascii
      $s18 = "></r:forAll><r:keyHolder><r:info><KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><RSAKeyValue><Modulus>ptV5l33YkYwdOV/Ru1" ascii
      $s19 = "32\" name=\"Microsoft.Windows.ErrorReporter\" version=\"12.0.4518.1014\"></assemblyIdentity><description>Windows Error Reporting" ascii
      $s20 = "tedRootIssuers></r:prerequisiteRight><r:allConditions></r:allConditions></r:allConditions></r:grant><r:issuer><Signature xmlns=" ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and 4 of them
}
rule Virus_Infector_Win32_Neshta_A {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Neshta.A.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "d17027039d1db86b6a61156685426359e5a0b2ef24165d8b5c57d5ce4bf50769"
   strings:
      $s1 = "Shell (Isolated) - ENU" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_109_1 {
   meta:
      description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_109_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "b551d289abe40f80f561705b3668d42f98f50f6a6ba1b38577f01f7ba3350a3b"
   strings:
      $s1 = "Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_253_1 {
   meta:
      description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_253_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "5eccd29cd2f6bc6e15d4d204b5ff7180ac7ae8ebcd2938c7b1c5c80135055729"
   strings:
      $s1 = "Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_34_1 {
   meta:
      description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_34_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "57c186dabcda2d49f379aa85c27b83ea5d0bc69ccbc78da87a4762c7e87474e0"
   strings:
      $s1 = "Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_570_1 {
   meta:
      description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_570_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "5639629b94a89798aada7a36c42200e52dccb6bf450ed13c9f6ab97dff14ec12"
   strings:
      $s1 = "Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_10 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_10.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "8ffa85f273bfcae54f0015220b4165f4035b6df391db2c8ff8bb89fcf6ca9cc8"
   strings:
      $s1 = "Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_5 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_5.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "7946fcb7ab8ef188dc4e509f9c4f4433514f168e901b15cf468014df655fdd0d"
   strings:
      $s1 = "Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_7 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_7.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "0a86eb357d3302da75a0f645e3e5b787b13a669b1ba6f47191ed0bbbdc37c4ce"
   strings:
      $s1 = "Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_10_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_10_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "7457fb2599134d7076532de2efca7214161eb37689f9636eb31a616902300e2d"
   strings:
      $s1 = "<description>Microsoft Office</description>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_6_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_6_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "de9e708276fbc97aa681c900684f7b4ff17ceb977a8a7b36638e17e8cf355cab"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_364_1 {
   meta:
      description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_364_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "3db78838d40b38b14ebd9d90f67c0d18f8ab46606f405b8b6005ec13b769ae6e"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
rule Trojan_Homepage__Trojan_GenericKD_63563925 {
   meta:
      description = "datamaliciousorder - file Trojan.Homepage _Trojan.GenericKD.63563925.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "8b4611cc77680eec12104fb7a4ada4c1de2f7526f09283f4c6fbf90959c4dadf"
   strings:
      $s1 = "cannot be run in DOS mode." fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_6 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_6.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "36329142833efa47e44ad6493d3b65c5d0360680a3e0ff520d2c86142862fa76"
   strings:
      $s1 = "&Workshop" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_22_2 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_22_2.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "77311b5befa85ee0afc85e7fbe13b7eda88dbcf6f8ec68c4a9a1686a753c5cda"
   strings:
      $s1 = "Database Compare" fullword wide
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Infector_Win32_Backdoor_Agent_A_18 {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Backdoor.Agent.A_18.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "49e3df484261b8348dbbd0ba4c90f172da67c838c0b959eda922be346934f9cf"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*)
}
rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_au4JtZd_6_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_6_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "606adb77757326264f522f52f2289b58ac12832eb9875543c29e9ad75ce844ce"
   strings:
      $s1 = "; name" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_3_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_3_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "8208c636b3a17a37e80849cb1931543a259e7e18e50667fa89855ee853eec067"
   strings:
      $s1 = "lns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0" ascii
      $s2 = "c9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:R" ascii
      $s3 = "c9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:R" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_TBZ_aCEmdoo_1_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.TBZ@aCEmdoo_1_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "e24ffc6abf9a4b76f741e62c5df8bad63c53db6c0544e6a4ff22daaa7aeca077"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aOYcrUm_5_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aOYcrUm_5_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "52ea0ea4a1a112a06dc302a01101492230c9f7b82457d55c256e5b4fd936c351"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_zyZ_aCEmdoo_1_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.zyZ@aCEmdoo_1_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "77a816d60db4a50c3f15111c5d4bbd116c55f53f83cabcb993807fe84b69fba0"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Variant_Packy_4_1_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Packy.4_1_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "78f7f526bed2737d302d75390bacc29e65ea7eacf89f5ce767d566ce28d56969"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_GenPack_Backdoor_Hangup_B_135_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_135_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "e3d2249ebb53739e1604b8a4c4871d03ab3066a27d21d70438fea4fcf8edf9c9"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Trojan_ShellObject_xyZ_aSgChKg_3_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aSgChKg_3_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "3f03e58cb29d9f6db6e584d142843e1f81515e45d53d3b6361957bd4674a9c33"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Gen_Variant_TDss_69_1_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.TDss.69_1_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "4d8ed3c8f56e0933b5828bccedc83d1cf8ed7aafa81ddb3fd3e32b937a05c9eb"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_GenPack_Backdoor_Hangup_B_315_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_315_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "36dceb3fd380211838bce3bf5c73f442910759995d3d2135b83c787a59552edd"
   strings:
      $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_GenPack_Backdoor_Hangup_B_431_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_431_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "287fddb223dbfce4be3c0db2760bc07a4c16400f9e03816bb99fcac9da803f34"
   strings:
      $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_Agent_DQQO_53_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_53_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "6379fe9cdb770360ce8f2ba051ba209ebae5154cfecae09ea2ea71e825bcfdc7"
   strings:
      $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_237_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_237_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "1749f59239e11f55d44eec8b11f8d854ca81590a905252727d77b53aca39f369"
   strings:
      $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_398_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_398_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "a698f733aab05066e023983b3140f8ae27dff74cbeed5d198518bfe27a653b3d"
   strings:
      $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_GenPack_Backdoor_Hangup_B_72_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_72_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "9cb20039a979b6eabf19e8757299de8fc3ca25c3baa20c7d9aba8668755440eb"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_GenPack_Trojan_GenericKDZ_103285_14_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_GenPack.Trojan.GenericKDZ.103285_14_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "e10c23c0a265f962e23b8e234532f04ecf143318b3ca849d7dd442a03856f722"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_329_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_329_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "c3c5451dbd96760b63cf9454e4ef30e660a8f1caa5361e78b0e54372d31ac240"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_34_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_34_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "a86baa02228b9381cacb8cfa72069faeda208c47aade4be0ca85c66436b05c72"
   strings:
      $s1 = "url.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_655_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_655_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "53b3e3104ecf86b725095a2721c82364a0ebfe7ca830614b17250bb2f5a33a3e"
   strings:
      $s1 = "url.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_633_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_633_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "554a67afb6b5d2e145d698231e4166e92164eed0fe049cc40504bba5ba1b4006"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_86_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_86_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "f7df8cc868719237e6a10183e66c3fb0ced11ef2ac8a77e696286390b04f5c8a"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule Virus_Hijack_Trojan_GenericKDZ_103285_870_1 {
   meta:
      description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_870_1.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "d7c6f1ce0ca401e8a9558e19eb928f2f8291dca30cf74ac5a9f225c158c5ffa6"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
   condition:
      uint16(0) == 0x5a4d and
      all of them
}
rule _Virus_Autorun_Win32_Worm_Viking_NDL_Virus_Infector_Win32_Nestha_C_161 {
   meta:
      description = "datamaliciousorder - from files Virus.Autorun_Win32.Worm.Viking.NDL.vir, Virus.Infector_Win32.Nestha.C.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "9cdc59aee6fee87fe93d8986f3cc5ca8e89ec48c1d89ae8aa3ea9f16a9b3ae07"
      hash2 = "d787818ec51ece351dbfd771829c3815ddaedcb8550c220fb16de9ddf418c146"
   strings:
      $s1 = "Failed to get handle to Win32 OneNote process. Process Id: " fullword wide
      $s2 = "Failed to properly retrieve parent process info" fullword wide
      $s3 = "Error waiting for process handle to terminate, returnCode: " fullword wide
      $s4 = "Failed to terminate process, PID=" fullword wide
      $s5 = "OpenProcess() returned nullptr. Error: " fullword wide
      $s6 = " to the list of known setup active processes" fullword wide
      $s7 = " to the list of unknown setup active processes" fullword wide
      $s8 = "Found process, PPID=" fullword wide
      $s9 = "Detected parent process name not allowed to log" fullword wide
      $s10 = "Parent Process Name : " fullword wide
      $s11 = " from process list." fullword wide
      $s12 = "Excluding current process ID " fullword wide
      $s13 = "Adding process " fullword wide
      $s14 = "Registry key LastKnownODSInfo was not found, adding all processes as unknown" fullword wide
      $s15 = "CommonUtil::GetResourceStringsForSyncRoot got display name resource:" fullword wide
      $s16 = "Killing Win32 OneNote process with process Id: " fullword wide
      $s17 = "AddFolderToLeftNav failed to get AccountInfo for given instance ID: " fullword wide
      $s18 = "Waiting and shutting down first process. PID=" fullword wide
      $s19 = "CommonUtil::DeleteMatchingKeysUnderSubkey: EnumerateRegistryKeys failed with hr=" fullword wide
      $s20 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?1??GetDeviceManagementState@CommonUtil@@SA?AV?$variant@W4DeviceManagementState@CommonUtil" ascii
   condition:
      ( uint16(0) == 0x5a4d and ( 8 of them )
      ) or ( all of them )
}
rule _Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_25_1_Virus_Hijack_Gen_Trojan_ShellObject_EuZ_aiy413e_10_2_Virus_Hi_677 {
   meta:
      description = "datamaliciousorder - from files Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_25_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aeOesjp_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_15_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aOGzovi_6.vir"
      author = "Emirhan Ucan & Hacimurad"
      reference = "VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, VirusTotal"
      date = "2024-11-12"
      hash1 = "4794864a8729d154f6c0edfa9e41fcf02e064033d2321bf1ceaa98ec09fc64dd"
      hash2 = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
      hash3 = "cf617c50ba14391b1d4304d2d89eae47be73b674a501f2f2651cd50e46e58325"
      hash4 = "7460b6921143a152b0975f67e89af586349229d1ff6b1317aff73eb982408f4a"
      hash5 = "940de455f281b3225827ecddd883f1b43ba1368dbd7f57716d0a339045f24379"
      hash6 = "c840acb87ccf2b90613e0d7eadf815329bac4527d35bafc52e77e29023f2f89d"
   strings:
      $s1 = "Plan skipped related bundle: %1!ls!, type: %2!hs!, because it was dependent and the current bundle is being executed as type: %3" ascii
      $s2 = "EBurn Engine Fatal Error: failed to open log file." fullword wide
      $s3 = "Plan skipped related bundle: %1!ls!, type: %2!hs!, because it was dependent and the current bundle is being executed as type: %3" ascii
      $s4 = "Failed to open Application event log" fullword ascii
      $s5 = "Failed to update name and publisher." fullword ascii
      $s6 = "Failed to convert bundle update guid into string." fullword ascii
      $s7 = "Failed to create bundle update guid." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and ( all of them )
      ) or ( all of them )
}
