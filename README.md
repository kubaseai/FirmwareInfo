# FirmwareInfo
UEFI/BIOS firmware info for Windows.

Example report:
```
Machine uniquely identified as {f1b6c2ce-406f-00bb-1344-007b5f6e6968}
SMBIOS size=464, SHA-256=ebd474f1a499b17787f9c50fd3c138ccdafe6323b8f4edd22873a045d073309f
-> Extracted BIOS info: vendor=innotek GmbH, version=VirtualBox, date=12/01/2006
Enumeration of ACPI tables. If some entry is duplicated Win32 API only allows to get 1st one.
-> ACPI MCFG 1 of 1: size=60, SHA-256=5f800e06cc94e06916d049c746b5fbde08912470259599ece8110e6660a82883
-> ACPI FACP 1 of 1: size=244, SHA-256=1619303277b6ea499b2223ae3ed41fd5391f97755fea355a8004c3e73c198ad1
-> ACPI APIC 1 of 1: size=92, SHA-256=7687c30e42aed8dbeca1736aeaa8195580b219bca1c44f9d9e1673e5347d6ee7
-> ACPI HPET 1 of 1: size=56, SHA-256=1ff0b4a1c352ec88146f2110ecbef601039cafc68386f4fecf4958e4d3ab445e
-> ACPI TPM2 1 of 1: size=52, SHA-256=ce9e51927f885c4f0e267fecc599ddc35109102227b250144b075f9fe9149fcc
-> ACPI SSDT 1 of 2: size=292, SHA-256=3e4f73a2e1b9fc23746c86a5434e74feb4c52877f1e82072d98545030f2e4d13
-> ACPI BGRT 1 of 1: size=56, SHA-256=4b5f28ad54de8b83654e8f6dee31a2d861923e37ef23b6fdd468fcac38fc307d

BootOrder entry Boot0004
-> name: Windows Boot Manager
-> EFI_DEVICE_PATH_PROTOCOL: type=0x04 Media Device Path, subtype=1, len=42
-> EFI file: \EFI\Microsoft\Boot\bootmgfw.efi

BootOrder entry Boot0000
-> name: UiApp
-> EFI_DEVICE_PATH_PROTOCOL: type=0x04 Media Device Path, subtype=7, len=20

BootOrder entry Boot0001
-> name: UEFI VBOX CD-ROM VB1-1a2b3c4d 
-> EFI_DEVICE_PATH_PROTOCOL: type=0x02 ACPI Device Path, subtype=1, len=12

BootOrder entry Boot0002
-> name: UEFI VBOX HARDDISK VBea158be0-f2dfdb36 
-> EFI_DEVICE_PATH_PROTOCOL: type=0x02 ACPI Device Path, subtype=1, len=12

BootOrder entry Boot0003
-> name: EFI Internal Shell
-> EFI_DEVICE_PATH_PROTOCOL: type=0x04 Media Device Path, subtype=7, len=20

List of UEFI vars
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::SetupMode
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::SignatureSupport
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::SecureBoot
UEFI VAR d9bee56e-75dc-49d9-b4d7-b534210f637a::certdbv
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::VendorKeys
UEFI VAR 4d1ede05-38c7-4a6a-9cc6-4bcca8b38c14::BackgroundClear
UEFI VAR 7c436110-ab2a-4bbb-a880-fe41995c9f82::boot-args
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::OsIndicationsSupported
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::BootOptionSupport
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::LangCodes
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::PlatformLangCodes
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::PlatformRecovery0000
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::ConOutDev
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::ConInDev
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::BootCurrent
UEFI VAR 4d1ede05-38c7-4a6a-9cc6-4bcca8b38c14::FirmwareFeatures
UEFI VAR 4d1ede05-38c7-4a6a-9cc6-4bcca8b38c14::FirmwareFeaturesMask
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Boot0000
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::PlatformLang
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Lang
UEFI VAR 04b37fe8-f6ae-480b-bdd5-37d98c5e89aa::VarErrorFlag
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Key0000
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Key0001
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Boot0001
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Boot0002
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Boot0003
UEFI VAR d9bee56e-75dc-49d9-b4d7-b534210f637a::certdb
UEFI VAR 77fa9abd-0359-4d32-bd60-28f4e78f784b::CurrentPolicy
UEFI VAR eaec226f-c9a3-477a-a826-ddc716cdc0e3::UnlockIDCopy
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Boot0004
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::BootOrder
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::Timeout
UEFI VAR eaec226f-c9a3-477a-a826-ddc716cdc0e3::OfflineUniqueIDEKPub
UEFI VAR eaec226f-c9a3-477a-a826-ddc716cdc0e3::OfflineUniqueIDEKPubCRC
UEFI VAR a9b5f8d2-cb6d-42c2-bc01-b5ffaae4335e::PBRDevicePath
UEFI VAR d719b2cb-3d3a-4596-a3bc-dad00e67656f::dbx
UEFI VAR 616e2ea6-af89-7eb3-f2ef-4e47368a657b::AUTOPILOT_MARKER
UEFI VAR eb704011-1402-11d3-8e77-00a0c969723b::MTC
UEFI VAR 8be4df61-93ca-11d2-aa0d-00e098032b8c::ConOut
GetFirmwareEnvironmentVariable errorCode=203 for KEK

Couldn't get (((KEK))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for KEKDefault

Couldn't get (((KEKDefault))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for PK

Couldn't get (((PK))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for PKDefault

Couldn't get (((PKDefault))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for db

Couldn't get (((db))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for dbx

Couldn't get (((dbx))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for dbDefault

Couldn't get (((dbDefault))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for dbxDefault

Couldn't get (((dbxDefault))) in namespace {8be4df61-93ca-11d2-aa0d-00e098032b8c}
GetFirmwareEnvironmentVariable errorCode=203 for KEK

Couldn't get (((KEK))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
GetFirmwareEnvironmentVariable errorCode=203 for KEKDefault

Couldn't get (((KEKDefault))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
GetFirmwareEnvironmentVariable errorCode=203 for PK

Couldn't get (((PK))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
GetFirmwareEnvironmentVariable errorCode=203 for PKDefault

Couldn't get (((PKDefault))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
GetFirmwareEnvironmentVariable errorCode=203 for db

Couldn't get (((db))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
GetFirmwareEnvironmentVariable errorCode=203 for dbx

Processing (((dbx))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
Known GUID in ESL: c1c41626-504c-4092-aca9-41f936934328, size=10588, sha-256=f00a0880db7b33b082b3fe5757092c5862fce62741e70ac4422f946babeebed5, number of entries=220
-> Entry #0 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 80b4d96931bf0d02fd91a61e19d14f1da452e66db2408ca8604d411f92659f0a
-> Entry #1 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f52f83a3fa9cfbd6920f722824dbe4034534d25b8507246b3b957dac6e1bce7a
-> Entry #2 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c5d9d8a186e2c82d09afaa2a6f7f2e73870d3e64f72c4e08ef67796a840f0fbd
-> Entry #3 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1aec84b84b6c65a51220a9be7181965230210d62d6d33c48999c6b295a2b0a06
-> Entry #4 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c3a99a460da464a057c3586d83cef5f4ae08b7103979ed8932742df0ed530c66
-> Entry #5 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 58fb941aef95a25943b3fb5f2510a0df3fe44c58c95e0ab80487297568ab9771
-> Entry #6 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 5391c3a2fb112102a6aa1edc25ae77e19f5d6f09cd09eeb2509922bfcd5992ea
-> Entry #7 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d626157e1d6a718bc124ab8da27cbb65072ca03a7b6b257dbdcbbd60f65ef3d1
-> Entry #8 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d063ec28f67eba53f1642dbf7dff33c6a32add869f6013fe162e2c32f1cbe56d
-> Entry #9 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 29c6eb52b43c3aa18b2cd8ed6ea8607cef3cfae1bafe1165755cf2e614844a44
-> Entry #10 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 90fbe70e69d633408d3e170c6832dbb2d209e0272527dfb63d49d29572a6f44c
-> Entry #11 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 106faceacfecfd4e303b74f480a08098e2d0802b936f8ec774ce21f31686689c
-> Entry #12 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 174e3a0b5b43c6a607bbd3404f05341e3dcf396267ce94f8b50e2e23a9da920c
-> Entry #13 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 2b99cf26422e92fe365fbf4bc30d27086c9ee14b7a6fff44fb2f6b9001699939
-> Entry #14 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 2e70916786a6f773511fa7181fab0f1d70b557c6322ea923b2a8d3b92b51af7d
-> Entry #15 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3fce9b9fdf3ef09d5452b0f95ee481c2b7f06d743a737971558e70136ace3e73
-> Entry #16 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 47cc086127e2069a86e03a6bef2cd410f8c55a6d6bdb362168c31b2ce32a5adf
-> Entry #17 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 71f2906fd222497e54a34662ab2497fcc81020770ff51368e9e3d9bfcbfd6375
-> Entry #18 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 82db3bceb4f60843ce9d97c3d187cd9b5941cd3de8100e586f2bda5637575f67
-> Entry #19 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 8ad64859f195b5f58dafaa940b6a6167acd67a886e8f469364177221c55945b9
-> Entry #20 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 8d8ea289cfe70a1c07ab7365cb28ee51edd33cf2506de888fbadd60ebf80481c
-> Entry #21 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is aeebae3151271273ed95aa2e671139ed31a98567303a332298f83709a9d55aa1
-> Entry #22 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c409bdac4775add8db92aa22b5b718fb8c94a1462c1fe9a416b95d8a3388c2fc
-> Entry #23 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c617c1a8b1ee2a811c28b5a81b4c83d7c98b5b0c27281d610207ebe692c2967f
-> Entry #24 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c90f336617b8e7f983975413c997f10b73eb267fd8a10cb9e3bdbfc667abdb8b
-> Entry #25 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 64575bd912789a2e14ad56f6341f52af6bf80cf94400785975e9f04e2d64d745
-> Entry #26 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 45c7c8ae750acfbb48fc37527d6412dd644daed8913ccd8a24c94d856967df8e
-> Entry #27 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 81d8fb4c9e2e7a8225656b4b8273b7cba4b03ef2e9eb20e0a0291624eca1ba86
-> Entry #28 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is b92af298dc08049b78c77492d6551b710cd72aada3d77be54609e43278ef6e4d
-> Entry #29 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e19dae83c02e6f281358d4ebd11d7723b4f5ea0e357907d5443decc5f93c1e9d
-> Entry #30 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 39dbc2288ef44b5f95332cb777e31103e840dba680634aa806f5c9b100061802
-> Entry #31 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 32f5940ca29dd812a2c145e6fc89646628ffcc7c7a42cae512337d8d29c40bbd
-> Entry #32 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 10d45fcba396aef3153ee8f6ecae58afe8476a280a2026fc71f6217dcf49ba2f
-> Entry #33 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 4b8668a5d465bcdd9000aa8dfcff42044fcbd0aece32fc7011a83e9160e89f09
-> Entry #34 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 89f3d1f6e485c334cd059d0995e3cdfdc00571b1849854847a44dc5548e2dcfb
-> Entry #35 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c9ec350406f26e559affb4030de2ebde5435054c35a998605b8fcf04972d8d55
-> Entry #36 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is b3e506340fbf6b5786973393079f24b66ba46507e35e911db0362a2acde97049
-> Entry #37 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9f1863ed5717c394b42ef10a6607b144a65ba11fb6579df94b8eb2f0c4cd60c1
-> Entry #38 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is dd59af56084406e38c63fbe0850f30a0cd1277462a2192590fb05bc259e61273
-> Entry #39 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is dbaf9e056d3d5b38b68553304abc88827ebc00f80cb9c7e197cdbc5822cd316c
-> Entry #40 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 65f3c0a01b8402d362b9722e98f75e5e991e6c186e934f7b2b2e6be6dec800ec
-> Entry #41 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 5b248e913d71853d3da5aedd8d9a4bc57a917126573817fb5fcb2d86a2f1c886
-> Entry #42 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 2679650fe341f2cf1ea883460b3556aaaf77a70d6b8dc484c9301d1b746cf7b5
-> Entry #43 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is bb1dd16d530008636f232303a7a86f3dff969f848815c0574b12c2d787fec93f
-> Entry #44 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 0ce02100f67c7ef85f4eed368f02bf7092380a3c23ca91fd7f19430d94b00c19
-> Entry #45 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 95049f0e4137c790b0d2767195e56f73807d123adcf8f6e7bf2d4d991d305f89
-> Entry #46 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 02e6216acaef6401401fa555ecbed940b1a5f2569aed92956137ae58482ef1b7
-> Entry #47 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 6efefe0b5b01478b7b944c10d3a8aca2cca4208888e2059f8a06cb5824d7bab0
-> Entry #48 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9d00ae4cd47a41c783dc48f342c076c2c16f3413f4d2df50d181ca3bb5ad859d
-> Entry #49 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d8d4e6ddf6e42d74a6a536ea62fd1217e4290b145c9e5c3695a31b42efb5f5a4
-> Entry #50 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f277af4f9bdc918ae89fa35cc1b34e34984c04ae9765322c3cb049574d36509c
-> Entry #51 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 0dc24c75eb1aef56b9f13ab9de60e2eca1c4510034e290bbb36cf60a549b234c
-> Entry #52 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 835881f2a5572d7059b5c8635018552892e945626f115fc9ca07acf7bde857a4
-> Entry #53 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is badff5e4f0fea711701ca8fb22e4c43821e31e210cf52d1d4f74dd50f1d039bc
-> Entry #54 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c452ab846073df5ace25cca64d6b7a09d906308a1a65eb5240e3c4ebcaa9cc0c
-> Entry #55 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f1863ec8b7f43f94ad14fb0b8b4a69497a8c65ecbc2a55e0bb420e772b8cdc91
-> Entry #56 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 7bc9cb5463ce0f011fb5085eb8ba77d1acd283c43f4a57603cc113f22cebc579
-> Entry #57 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e800395dbe0e045781e8005178b4baf5a257f06e159121a67c595f6ae22506fd
-> Entry #58 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1cb4dccaf2c812cfa7b4938e1371fe2b96910fe407216fd95428672d6c7e7316
-> Entry #59 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3ece27cbb3ec4438cce523b927c4f05fdc5c593a3766db984c5e437a3ff6a16b
-> Entry #60 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 68ee4632c7be1c66c83e89dd93eaee1294159abf45b4c2c72d7dc7499aa2a043
-> Entry #61 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e24b315a551671483d8b9073b32de11b4de1eb2eab211afd2d9c319ff55e08d0
-> Entry #62 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e7c20b3ab481ec885501eca5293781d84b5a1ac24f88266b5270e7ecb4aa2538
-> Entry #63 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is dccc3ce1c00ee4b0b10487d372a0fa47f5c26f57a359be7b27801e144eacbac4
-> Entry #64 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 0257ff710f2a16e489b37493c07604a7cda96129d8a8fd68d2b6af633904315d
-> Entry #65 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3a91f0f9e5287fa2994c7d930b2c1a5ee14ce8e1c8304ae495adc58cc4453c0c
-> Entry #66 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 495300790e6c9bf2510daba59db3d57e9d2b85d7d7640434ec75baa3851c74e5
-> Entry #67 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 81a8b2c9751aeb1faba7dbde5ee9691dc0eaee2a31c38b1491a8146756a6b770
-> Entry #68 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 8e53efdc15f852cee5a6e92931bc42e6163cd30ff649cca7e87252c3a459960b
-> Entry #69 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 992d359aa7a5f789d268b94c11b9485a6b1ce64362b0edb4441ccc187c39647b
-> Entry #70 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9fa4d5023fd43ecaff4200ba7e8d4353259d2b7e5e72b5096eff8027d66d1043
-> Entry #71 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d372c0d0f4fdc9f52e9e1f23fc56ee72414a17f350d0cea6c26a35a6c3217a13
-> Entry #72 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 5c5805196a85e93789457017d4f9eb6828b97c41cb9ba6d3dc1fcc115f527a55
-> Entry #73 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 03f64a29948a88beffdb035e0b09a7370ccf0cd9ce6bcf8e640c2107318fab87
-> Entry #74 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 05d87e15713454616f5b0ed7849ab5c1712ab84f02349478ec2a38f970c01489
-> Entry #75 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 06eb5badd26e4fae65f9a42358deef7c18e52cc05fbb7fc76776e69d1b982a14
-> Entry #76 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 08bb2289e9e91b4d20ff3f1562516ab07e979b2c6cefe2ab70c6dfc1199f8da5
-> Entry #77 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 0928f0408bf725e61d67d87138a8eebc52962d2847f16e3587163b160e41b6ad
-> Entry #78 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 09f98aa90f85198c0d73f89ba77e87ec6f596c491350fb8f8bba80a62fbb914b
-> Entry #79 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 0a75ea0b1d70eaa4d3f374246db54fc7b43e7f596a353309b9c36b4fd975725e
-> Entry #80 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 0c51d7906fc4931149765da88682426b2cfe9e6aa4f27253eab400111432e3a7
-> Entry #81 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 0fa3a29ad05130d7fe5bf4d2596563cded1d874096aacc181069932a2e49519a
-> Entry #82 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 147730b42f11fe493fe902b6251e97cd2b6f34d36af59330f11d02a42f940d07
-> Entry #83 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 148fe18f715a9fcfe1a444ce0fff7f85869eb422330dc04b314c0f295d6da79e
-> Entry #84 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1b909115a8d473e51328a87823bd621ce655dfae54fa2bfa72fdc0298611d6b8
-> Entry #85 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1d8b58c1fdb8da8b33ccee1e5f973af734d90ef317e33f5db1573c2ba088a80c
-> Entry #86 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1f179186efdf5ef2de018245ba0eae8134868601ba0d35ff3d9865c1537ced93
-> Entry #87 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 270c84b29d86f16312b06aaae4ebb8dff8de7d080d825b8839ff1766274eff47
-> Entry #88 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 29cca4544ea330d61591c784695c149c6b040022ac7b5b89cbd72800d10840ea
-> Entry #89 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 2b2298eaa26b9dc4a4558ae92e7bb0e4f85cf34bf848fdf636c0c11fbec49897
-> Entry #90 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 2dcf8e8d817023d1e8e1451a3d68d6ec30d9bed94cbcb87f19ddc1cc0116ac1a
-> Entry #91 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 311a2ac55b50c09b30b3cc93b994a119153eeeac54ef892fc447bbbd96101aa1
-> Entry #92 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 32ad3296829bc46dcfac5eddcb9dbf2c1eed5c11f83b2210cf9c6e60c798d4a7
-> Entry #93 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 340da32b58331c8e2b561baf300ca9dfd6b91cd2270ee0e2a34958b1c6259e85
-> Entry #94 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 362ed31d20b1e00392281231a96f0a0acfde02618953e695c9ef2eb0bac37550
-> Entry #95 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 367a31e5838831ad2c074647886a6cdff217e6b1ba910bff85dc7a87ae9b5e98
-> Entry #96 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3765d769c05bf98b427b3511903b2137e8a49b6f859d0af159ed6a86786aa634
-> Entry #97 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 386d695cdf2d4576e01bcaccf5e49e78da51af9955c0b8fa7606373b007994b3
-> Entry #98 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3a4f74beafae2b9383ad8215d233a6cf3d057fb3c7e213e897beef4255faee9d
-> Entry #99 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3ae76c45ca70e9180c1559981f42622dd251bca1fbe6b901c52ec11673b03514
-> Entry #100 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3be8e7eb348d35c1928f19c769846788991641d1f6cf09514ca10269934f7359
-> Entry #101 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 3e3926f0b8a15ad5a14167bb647a843c3d4321e35dbc44dce8c837417f2d28b0
-> Entry #102 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 400ac66d59b7b094a9e30b01a6bd013aff1d30570f83e7592f421dbe5ff4ba8f
-> Entry #103 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 4185821f6dab5ba8347b78a22b5f9a0a7570ca5c93a74d478a793d83bac49805
-> Entry #104 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 41d1eeb177c0324e17dd6557f384e532de0cf51a019a446b01efb351bc259d77
-> Entry #105 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 45876b4dd861d45b3a94800774027a5db45a48b2a729410908b6412f8a87e95d
-> Entry #106 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 4667bf250cd7c1a06b8474c613cdb1df648a7f58736fbf57d05d6f755dab67f4
-> Entry #107 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 47ff1b63b140b6fc04ed79131331e651da5b2e2f170f5daef4153dc2fbc532b1
-> Entry #108 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 57e6913afacc5222bd76cdaf31f8ed88895464255374ef097a82d7f59ad39596
-> Entry #109 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 5890fa227121c76d90ed9e63c87e3a6533eea0f6f0a1a23f1fc445139bc6bcdf
-> Entry #110 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 5d1e9acbbb4a7d024b6852df025970e2ced66ff622ee019cd0ed7fd841ccad02
-> Entry #111 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 61cec4a377bf5902c0feaee37034bf97d5bc6e0615e23a1cdfbae6e3f5fb3cfd
-> Entry #112 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 631f0857b41845362c90c6980b4b10c4b628e23dbe24b6e96c128ae3dcb0d5ac
-> Entry #113 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 65b2e7cc18d903c331df1152df73ca0dc932d29f17997481c56f3087b2dd3147
-> Entry #114 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 66aa13a0edc219384d9c425d3927e6ed4a5d1940c5e7cd4dac88f5770103f2f1
-> Entry #115 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 6873d2f61c29bd52e954eeff5977aa8367439997811a62ff212c948133c68d97
-> Entry #116 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 6dbbead23e8c860cf8b47f74fbfca5204de3e28b881313bb1d1eccdc4747934e
-> Entry #117 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 6dead13257dfc3ccc6a4b37016ba91755fe9e0ec1f415030942e5abc47f07c88
-> Entry #118 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 70a1450af2ad395569ad0afeb1d9c125324ee90aec39c258880134d4892d51ab
-> Entry #119 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 72c26f827ceb92989798961bc6ae748d141e05d3ebcfb65d9041b266c920be82
-> Entry #120 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 781764102188a8b4b173d4a8f5ec94d828647156097f99357a581e624b377509
-> Entry #121 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 788383a4c733bb87d2bf51673dc73e92df15ab7d51dc715627ae77686d8d23bc
-> Entry #122 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 78b4edcaabc8d9093e20e217802caeb4f09e23a3394c4acc6e87e8f35395310f
-> Entry #123 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 7f49ccb309323b1c7ab11c93c955b8c744f0a2b75c311f495e18906070500027
-> Entry #124 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 82acba48d5236ccff7659afc14594dee902bd6082ef1a30a0b9b508628cf34f4
-> Entry #125 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 894d7839368f3298cc915ae8742ef330d7a26699f459478cf22c2b6bb2850166
-> Entry #126 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 8c0349d708571ae5aa21c11363482332073297d868f29058916529efc520ef70
-> Entry #127 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 8d93d60c691959651476e5dc464be12a85fa5280b6f524d4a1c3fcc9d048cfad
-> Entry #128 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9063f5fbc5e57ab6de6c9488146020e172b176d5ab57d4c89f0f600e17fe2de2
-> Entry #129 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 91656aa4ef493b3824a0b7263248e4e2d657a5c8488d880cb65b01730932fb53
-> Entry #130 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 91971c1497bf8e5bc68439acc48d63ebb8faabfd764dcbe82f3ba977cac8cf6a
-> Entry #131 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 947078f97c6196968c3ae99c9a5d58667e86882cf6c8c9d58967a496bb7af43c
-> Entry #132 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 96e4509450d380dac362ff8e295589128a1f1ce55885d20d89c27ba2a9d00909
-> Entry #133 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9783b5ee4492e9e891c655f1f48035959dad453c0e623af0fe7bf2c0a57885e3
-> Entry #134 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 97a51a094444620df38cd8c6512cac909a75fd437ae1e4d22929807661238127
-> Entry #135 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 97a8c5ba11d61fefbb5d6a05da4e15ba472dc4c6cd4972fc1a035de321342fe4
-> Entry #136 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 992820e6ec8c41daae4bd8ab48f58268e943a670d35ca5e2bdcd3e7c4c94a072
-> Entry #137 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9954a1a99d55e8b189ab1bca414b91f6a017191f6c40a86b6f3ef368dd860031
-> Entry #138 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9baf4f76d76bf5d6a897bfbd5f429ba14d04e08b48c3ee8d76930a828fff3891
-> Entry #139 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9c259fcb301d5fc7397ed5759963e0ef6b36e42057fd73046e6bd08b149f751c
-> Entry #140 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9dd2dcb72f5e741627f2e9e03ab18503a3403cf6a904a479a4db05d97e2250a9
-> Entry #141 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9ed33f0fbc180bc032f8909ca2c4ab3418edc33a45a50d2521a3b5876aa3ea2c
-> Entry #142 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is a4d978b7c4bda15435d508f8b9592ec2a5adfb12ea7bad146a35ecb53094642f
-> Entry #143 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is a924d3cad6da42b7399b96a095a06f18f6b1aba5b873b0d5f3a0ee2173b48b6c
-> Entry #144 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is ad3be589c0474e97de5bb2bf33534948b76bb80376dfdc58b1fed767b5a15bfc
-> Entry #145 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is b8d6b5e7857b45830e017c7be3d856adeb97c7290eb0665a3d473a4beb51dcf3
-> Entry #146 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is b93f0699598f8b20fa0dacc12cfcfc1f2568793f6e779e04795e6d7c22530f75
-> Entry #147 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is bb01da0333bb639c7e1c806db0561dc98a5316f22fef1090fb8d0be46dae499a
-> Entry #148 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is bc75f910ff320f5cb5999e66bbd4034f4ae537a42fdfef35161c5348e366e216
-> Entry #149 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is bdd01126e9d85710d3fe75af1cc1702a29f081b4f6fdf6a2b2135c0297a9cec5
-> Entry #150 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is be435df7cd28aa2a7c8db4fc8173475b77e5abf392f76b7c76fa3f698cb71a9a
-> Entry #151 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is bef7663be5ea4dbfd8686e24701e036f4c03fb7fcd67a6c566ed94ce09c44470
-> Entry #152 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c2469759c1947e14f4b65f72a9f5b3af8b6f6e727b68bb0d91385cbf42176a8a
-> Entry #153 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c3505bf3ec10a51dace417c76b8bd10939a065d1f34e75b8a3065ee31cc69b96
-> Entry #154 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c42d11c70ccf5e8cf3fb91fdf21d884021ad836ca68adf2cbb7995c10bf588d4
-> Entry #155 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c69d64a5b839e41ba16742527e17056a18ce3c276fd26e34901a1bc7d0e32219
-> Entry #156 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is cb340011afeb0d74c4a588b36ebaa441961608e8d2fa80dca8c13872c850796b
-> Entry #157 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is cc8eec6eb9212cbf897a5ace7e8abeece1079f1a6def0a789591cb1547f1f084
-> Entry #158 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is cf13a243c1cd2e3c8ceb7e70100387cecbfb830525bbf9d0b70c79adf3e84128
-> Entry #159 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d89a11d16c488dd4fbbc541d4b07faf8670d660994488fe54b1fbff2704e4288
-> Entry #160 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d9668ab52785086786c134b5e4bddbf72452813b6973229ab92aa1a54d201bf5
-> Entry #161 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is da3560fd0c32b54c83d4f2ff869003d2089369acf2c89608f8afa7436bfa4655
-> Entry #162 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is df02aab48387a9e1d4c65228089cb6abe196c8f4b396c7e4bbc395de136977f6
-> Entry #163 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is df91ac85a94fcd0cfb8155bd7cbefaac14b8c5ee7397fe2cc85984459e2ea14e
-> Entry #164 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e051b788ecbaeda53046c70e6af6058f95222c046157b8c4c1b9c2cfc65f46e5
-> Entry #165 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e36dfc719d2114c2e39aea88849e2845ab326f6f7fe74e0e539b7e54d81f3631
-> Entry #166 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e39891f48bbcc593b8ed86ce82ce666fc1145b9fcbfd2b07bad0a89bf4c7bfbf
-> Entry #167 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e6856f137f79992dc94fa2f43297ec32d2d9a76f7be66114c6a13efc3bcdf5c8
-> Entry #168 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is eaff8c85c208ba4d5b6b8046f5d6081747d779bada7768e649d047ff9b1f660c
-> Entry #169 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is ee83a566496109a74f6ac6e410df00bb29a290e0021516ae3b8a23288e7e2e72
-> Entry #170 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is eed7e0eff2ed559e2a79ee361f9962af3b1e999131e30bb7fd07546fae0a7267
-> Entry #171 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f1b4f6513b0d544a688d13adc291efa8c59f420ca5dcb23e0b5a06fa7e0d083d
-> Entry #172 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f2a16d35b554694187a70d40ca682959f4f35c2ce0eab8fd64f7ac2ab9f5c24a
-> Entry #173 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f31fd461c5e99510403fc97c1da2d8a9cbe270597d32badf8fd66b77495f8d94
-> Entry #174 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f48e6dd8718e953b60a24f2cbea60a9521deae67db25425b7d3ace3c517dd9b7
-> Entry #175 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c805603c4fa038776e42f263c604b49d96840322e1922d5606a9b0bbb5bffe6f
-> Entry #176 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1f16078cce009df62edb9e7170e66caae670bce71b8f92d38280c56aa372031d
-> Entry #177 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 37a480374daf6202ce790c318a2bb8aa3797311261160a8e30558b7dea78c7a6
-> Entry #178 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 408b8b3df5abb043521a493525023175ab1261b1de21064d6bf247ce142153b9
-> Entry #179 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 540801dd345dc1c33ef431b35bf4c0e68bd319b577b9abe1a9cff1cbc39f548f
-> Entry #180 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 040b3bc339e9b6f9acd828b88f3482a5c3f64e67e5a714ba1da8a70453b34af6
-> Entry #181 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1142a0cc7c9004dff64c5948484d6a7ec3514e176f5ca6bdeed7a093940b93cc
-> Entry #182 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 288878f12e8b9c6ccbf601c73d5f4e985cac0ff3fcb0c24e4414912b3eb91f15
-> Entry #183 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 2ea4cb6a1f1eb1d3dce82d54fde26ded243ba3e18de7c6d211902a594fe56788
-> Entry #184 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 40d6cae02973789080cf4c3a9ad11b5a0a4d8bba4438ab96e276cc784454dee7
-> Entry #185 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 4f0214fce4fa8897d0c80a46d6dab4124726d136fc2492efd01bfedfa3887a9c
-> Entry #186 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 5c2afe34bd8a7aebbb439c251dfb6a424f00e535ac4df61ec19745b6f10e893a
-> Entry #187 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 99d7ada0d67e5233108dbd76702f4b168087cfc4ec65494d6ca8aba858febada
-> Entry #188 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is a608a87f51bdf7532b4b80fa95eadfdf1bf8b0cbb58a7d3939c9f11c12e71c85
-> Entry #189 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is bdd4086c019f5d388453c6d93475d39a576572baff75612c321b46a35a5329b1
-> Entry #190 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is cb994b400590b66cbf55fc663555caf0d4f1ce267464d0452c2361e05ee1cd50
-> Entry #191 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d6ee8db782e36caffb4d9f8207900487de930aabcc1d196fa455fbfd6f37273d
-> Entry #192 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is dda0121dcf167db1e2622d10f454701837ac6af304a03ec06b3027904988c56b
-> Entry #193 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e42572afac720f5d4a1c7aaaf802f094daceb682f4e92783b2bb3fa00862af7f
-> Entry #194 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e6236dc1ee074c077c7a1c9b3965947430847be125f7aeb71d91a128133aea7f
-> Entry #195 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is ef87be89a413657de8721498552cf9e0f3c1f71bc62dfa63b9f25bbc66e86494
-> Entry #196 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is f5e892dd6ec4c2defa4a495c09219b621379b64da3d1b2e34adf4b5f1102bd39
-> Entry #197 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is d4241190cd5a369d8c344c660e24f3027fb8e7064fab33770e93fa765ffb152e
-> Entry #198 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 23142e14424fb3ff4efc75d00b63867727841aba5005149070ee2417df8ab799
-> Entry #199 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 91721aa76266b5bb2f8009f1188510a36e54afd56e967387ea7d0b114d782089
-> Entry #200 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is dc8aff7faa9d1a00a3e32eefbf899b3059cbb313a48b82fa9c8d931fd58fb69d
-> Entry #201 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 9959ed4e05e548b59f219308a45563ea85bb224c1ad96dec0e96c0e71ffccd81
-> Entry #202 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 47b31a1c7867644b2ee8093b2d5fbe21e21f77c1617a2c08812f57ace0850e9f
-> Entry #203 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is fabc379df395e6f52472b44fa5082f9f0e0da480f05198c66814b7055b03f446
-> Entry #204 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e37ff3fc0eff20bfc1c060a4bf56885e1efd55a8e9ce3c5f4869444cacffad0b
-> Entry #205 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 4cdae3920a512c9c052a8b4aba9096969b0a0197b614031e4c64a5d898cb09b9
-> Entry #206 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 5b89f1aa2435a03d18d9b203d17fb4fba4f8f5076cf1f9b8d6d9b826222235c1
-> Entry #207 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 007f4c95125713b112093e21663e2d23e3c1ae9ce4b5de0d58a297332336a2d8
-> Entry #208 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e060da09561ae00dcfb1769d6e8e846868a1e99a54b14aa5d0689f2840cec6df
-> Entry #209 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 48f4584de1c5ec650c25e6c623635ce101bd82617fc400d4150f0aee2355b4ca
-> Entry #210 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is af79b14064601bc0987d4747af1e914a228c05d622ceda03b7a4f67014fee767
-> Entry #211 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is c55be4a2a6ac574a9d46f1e1c54cac29d29dcd7b9040389e7157bb32c4591c4c
-> Entry #212 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is e9d873cbcede3634e0a4b3644b51e1c8a0a048272992c738513ebc96cd3e3360
-> Entry #213 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 66d0803e2550d9e790829ae1b5f81547cc9bfbe69b51817068ecb5dabb7a89fc
-> Entry #214 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 284153e7d04a9f187e5c3dbfe17b2672ad2fbdd119f27bec789417b7919853ec
-> Entry #215 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is edd2cb55726e10abedec9de8ca5ded289ad793ab3b6919d163c875fec1209cd5
-> Entry #216 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 90aec5c4995674a849c1d1384463f3b02b5aa625a5c320fc4fe7d9bb58a62398
-> Entry #217 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is ca65a9b2915d9a055a407bc0698936349a04e3db691e178419fba701aad8de55
-> Entry #218 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 1788d84aa61ede6f2e96cfc900ad1cab1c5be86537f27212e8c291d6ade3b1e9
-> Entry #219 for 77fa9abd-0359-4d32-bd60-28f4e78f784b is not X509 (Cannot find the requested object.
). As Hash(32) it is 6a0e824654b7479152058cf738a378e629483874b6dbd67e0d8c3327b2fcac64
GetFirmwareEnvironmentVariable errorCode=203 for dbDefault

Couldn't get (((dbDefault))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
GetFirmwareEnvironmentVariable errorCode=203 for dbxDefault

Couldn't get (((dbxDefault))) in namespace {d719b2cb-3d3a-4596-a3bc-dad00e67656f}

Analyzing UEFI volumes
-> \\?\Volume{4ec461e8-31ef-47a0-8dd2-481b59df3b01}\
Is EFI file \EFI\Microsoft\Boot\bootmgfw.efi trusted? True
Signature: state=SignedAndTrusted, details=
--------
[Subject]
  CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

[Issuer]
  CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

[Serial Number]
  330000041331BC198807A90774000000000413

[Not Before]
  2/3/2023 1:05:41 AM

[Not After]
  2/1/2024 1:05:41 AM

[Thumbprint]
  58FD671E2D4D200CE92D6E799EC70DF96E6D2664

--------
File \EFI\Microsoft\Boot\bootmgfw.efi: size=2577376, created=10/21/2023 7:00:57 PM, modified=9/13/2023 12:22:32 PM, sha256=e3b1cc1841c5b09b824115858d3d7fdee04aea2362347ae5b1d5c148e8713b36

Getting drivers info
Driver=ntoskrnl.exe, File C:\Windows\system32\ntoskrnl.exe: size=12105200, created=9/13/2023 9:22:24 PM, modified=9/13/2023 9:22:24 PM, sha256=d67c38552062a51eef56013bae30eedd2bae1c357067efb50be18a300860dce4, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=hal.dll, File C:\Windows\system32\hal.dll: size=30032, created=9/13/2023 9:22:24 PM, modified=9/13/2023 9:22:24 PM, sha256=b2253e6045909ca13a4d7d1e193134b3a24bbbc58331f986eb5064135f73053f, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=kd.dll, File C:\Windows\system32\kd.dll: size=54632, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=2a86d618ca5df223a90ea511962990e40d69804f8929443eed33bb7950a5509f, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=mcupdate_GenuineIntel.dll, File C:\Windows\system32\mcupdate_GenuineIntel.dll: size=3650896, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=989df5352659effb42fb8382fc2d27196482f0d7e3ee414b6de79bd6cd4e7a75, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=CLFS.SYS, File C:\Windows\System32\drivers\CLFS.SYS: size=456064, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=f9f878ea08806c3e04cbd02ecc305a8600c7792a25e0dfc614e88de33251bce9, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=tm.sys, File C:\Windows\System32\drivers\tm.sys: size=177536, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=5056e83f90e70493063ba558c436044a02e60dec0ee1998c56868c93bc71ce66, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=PSHED.dll, File C:\Windows\system32\PSHED.dll: size=116064, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=e820b379d198a7f120b7452b99c1263204f6c1847b9c7811bc686980a50c9ff8, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=BOOTVID.dll, File C:\Windows\system32\BOOTVID.dll: size=62816, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=9ef0231bdf93ba27e5039bd66b13dbe7a83471257e10cac5f5160cc3f7c0217f, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=FLTMGR.SYS, File C:\Windows\System32\drivers\FLTMGR.SYS: size=488800, created=9/13/2023 9:22:24 PM, modified=9/13/2023 9:22:24 PM, sha256=4bc91eb4fcb02409147bfb6bedc8950ed6d9613e489e7f2045b15fae56fb9c75, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=msrpc.sys, File C:\Windows\System32\drivers\msrpc.sys: size=415056, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=59db33b1c5479b34c1f376492e325175c0840ca5004411e4442ce28352ce2833, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=ksecdd.sys, File C:\Windows\System32\drivers\ksecdd.sys: size=189808, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=8fcf60acfbdbd48a08efd1366383d1b227de2b113747c84defd2a7715064efa5, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=clipsp.sys, File C:\Windows\System32\drivers\clipsp.sys: size=1140080, created=9/13/2023 9:21:59 PM, modified=9/13/2023 9:21:59 PM, sha256=a224fcf724bc943f297504d44d6e76be115a3649d68132e33c374a55db2a6214, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=cmimcext.sys, File C:\Windows\System32\drivers\cmimcext.sys: size=71040, created=9/13/2023 9:21:45 PM, modified=9/13/2023 9:21:45 PM, sha256=07d62936e5cfe0b5cea231208bb03a7bf6463a3c6a147cdfdd2d2ad52c954915, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=werkernel.sys, File C:\Windows\System32\drivers\werkernel.sys: size=99672, created=9/13/2023 9:22:28 PM, modified=9/13/2023 9:22:28 PM, sha256=1ed8355977d5eb898e85e5bc9d77d48f791eb5afafe07e43363ceb9a09b179b9, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=ntosext.sys, File C:\Windows\System32\drivers\ntosext.sys: size=58704, created=5/7/2022 7:19:39 AM, modified=5/7/2022 7:19:39 AM, sha256=c3e3e69d11437c1bb707a0a7587151c31bd716d56dda2210d71c2e8a00267476, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=CI.dll, File C:\Windows\system32\CI.dll: size=1018000, created=9/13/2023 9:22:23 PM, modified=9/13/2023 9:22:23 PM, sha256=239a5a5311b92937dff3d553b5a8735285cdea6db97f2b15ef8bde81ccca3a57, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=cng.sys, File C:\Windows\System32\drivers\cng.sys: size=782368, created=9/13/2023 9:22:23 PM, modified=9/13/2023 9:22:23 PM, sha256=cd57a26ab08ae876039a8202fd12ae0988929f1ff500e1adda7865220e0c84e8, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=Wdf01000.sys, File C:\Windows\system32\drivers\Wdf01000.sys: size=820592, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=bebc0f29060612d108bfbbfdb3d2bdebfe5375037a55708f5e299127062fc5ee, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=WppRecorder.sys, File C:\Windows\system32\drivers\WppRecorder.sys: size=87384, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=137fd5b71867ef325595ddd55f03e62ace7799096562b873e1989baade20d6cf, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=WDFLDR.SYS, File C:\Windows\system32\drivers\WDFLDR.SYS: size=103808, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=a41afd6482c0db63f35a24acfcaf1e92dd6be3721c1f0c2bfa84a3a44b5d2051, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=PRM.sys, File C:\Windows\System32\DriverStore\FileRepository\prm.inf_amd64_de435dc5c75d64a5\PRM.sys: size=66896, created=5/7/2022 7:19:03 AM, modified=5/7/2022 7:19:03 AM, sha256=5b2d3ade64509d8c81f3c06fab38d05a87216fa53112805dd743ab1172741c86, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=acpiex.sys, File C:\Windows\System32\Drivers\acpiex.sys: size=169440, created=9/13/2023 9:21:45 PM, modified=9/13/2023 9:21:45 PM, sha256=1b3a057c590b974695ec5a3b40d106f0c762a806cd059469f6835ebde9bc8a05, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=msseccore.sys, File C:\Windows\system32\drivers\msseccore.sys: size=71024, created=9/13/2023 9:21:16 PM, modified=9/13/2023 9:21:16 PM, sha256=56ef534b48a167fe744fcb52744e047b5849c75c2eacfeae26c7d6b3179630b4, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=ACPI.sys, File C:\Windows\System32\drivers\ACPI.sys: size=755176, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=25016f544046f1550c2f91b97e8a9c62ba90de45efbe624bbcf8c51c5e367db1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=WMILIB.SYS, File C:\Windows\System32\drivers\WMILIB.SYS: size=58704, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=2662b054b7cb8d77337a31e27b7391f26156deb89a65b33c94cd013c227c5b2a, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=msisadrv.sys, File C:\Windows\System32\drivers\msisadrv.sys: size=54608, created=5/7/2022 7:19:04 AM, modified=5/7/2022 7:19:04 AM, sha256=bf5dec606c0244019b3c3e75b739739eabfdce562da91e7891a27eb675ad4083, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=pci.sys, File C:\Windows\System32\drivers\pci.sys: size=574936, created=9/13/2023 9:21:45 PM, modified=9/13/2023 9:21:45 PM, sha256=92d7fc0986907ee18007a3044b86fdc4e3e75062031ceaeda36d3145e1470857, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=tpm.sys, File C:\Windows\System32\drivers\tpm.sys: size=365920, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=dfefb2a9125d327669fb1b1634104e4b45999ea00086565e8ffa59e938286e2e, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=intelpep.sys, File C:\Windows\System32\drivers\intelpep.sys: size=517616, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=da03c6345f8ffe0b546436ed9546737829a4917b9564cfcadeb56c55c0d0cc79, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=WindowsTrustedRT.sys, File C:\Windows\system32\drivers\WindowsTrustedRT.sys: size=108032, created=9/13/2023 9:22:11 PM, modified=9/13/2023 9:22:11 PM, sha256=d71e84d3f24fbb03f9f7bccbdb01b8a8535e936ec39c4f1abd6dfe4d76b28dc2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=IntelPMT.sys, File C:\Windows\System32\drivers\IntelPMT.sys: size=91688, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=8432c337c71fa764b943d28aacf5dcf45e9bc8a54db405d958a70f80bf671a50, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=WindowsTrustedRTProxy.sys, File C:\Windows\System32\drivers\WindowsTrustedRTProxy.sys: size=54784, created=5/7/2022 7:19:25 AM, modified=5/7/2022 7:19:25 AM, sha256=c5ffcb47c5465f7fa347888f5cffad7094e1352d8ecd4f5b5da7e92afda9ecdb, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=pcw.sys, File C:\Windows\System32\drivers\pcw.sys: size=99672, created=9/13/2023 9:22:23 PM, modified=9/13/2023 9:22:23 PM, sha256=8e85b2e7c403705435577fcc755315752a100a9559b18e54d78b48a1730e54b1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=vdrvroot.sys, File C:\Windows\System32\drivers\vdrvroot.sys: size=124248, created=5/7/2022 7:19:05 AM, modified=5/7/2022 7:19:05 AM, sha256=a192e183a320ca453b6fde55f1790f74025747a21fced1c21dfb731ed188ba68, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=pdc.sys, File C:\Windows\system32\drivers\pdc.sys: size=202080, created=9/13/2023 9:21:45 PM, modified=9/13/2023 9:21:45 PM, sha256=0877497d2a02c0143bbb9402df30d8ceddd75034ddf2d32836d290aa7680896d, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=CEA.sys, File C:\Windows\system32\drivers\CEA.sys: size=107880, created=5/7/2022 7:19:20 AM, modified=5/7/2022 7:19:20 AM, sha256=1ec240781b3fad486f912fcec74b3508c61a12d503acbcfc0c8400546edc52b2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=partmgr.sys, File C:\Windows\System32\drivers\partmgr.sys: size=218448, created=9/13/2023 9:22:24 PM, modified=9/13/2023 9:22:24 PM, sha256=e7a1599c4bd6d0a6e3b1771475b1a1b8f6bc57c236c6700c72e76695b9738822, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=spaceport.sys, File C:\Windows\System32\drivers\spaceport.sys: size=931152, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=c74992570e4107da61457671a17acedd7b1825daf32e24155b210cf06fac4808, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=volmgr.sys, File C:\Windows\System32\drivers\volmgr.sys: size=124256, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=d132e4ba00cd28aa4a3a4d5865c3f2eb6929a3fc42f0487d0a8a4141782c430c, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=volmgrx.sys, File C:\Windows\System32\drivers\volmgrx.sys: size=419168, created=5/7/2022 7:20:03 AM, modified=5/7/2022 7:20:03 AM, sha256=01bba9a399e5be36523d12b6bc176b4118dd104b2ad9ae940964b942bfe2d464, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=mountmgr.sys, File C:\Windows\System32\drivers\mountmgr.sys: size=136544, created=9/13/2023 9:22:24 PM, modified=9/13/2023 9:22:24 PM, sha256=43e3549dbefa009a0713b77c45a3c09dc990c29e1bd8bd832c0fd83d3804acac, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=storahci.sys, File C:\Windows\System32\drivers\storahci.sys: size=214352, created=9/13/2023 9:21:45 PM, modified=9/13/2023 9:21:45 PM, sha256=01cafd8077617acb133e6e76ce654129269f0575a6f7b8c7756b07f661bd4a8b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=storport.sys, File C:\Windows\System32\drivers\storport.sys: size=1164624, created=9/13/2023 9:21:45 PM, modified=9/13/2023 9:21:45 PM, sha256=0464dcdd989c23eb65bb58a52647be20d10701273639e66b25f74716aa269bd2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=EhStorClass.sys, File C:\Windows\System32\drivers\EhStorClass.sys: size=152944, created=5/7/2022 7:20:05 AM, modified=5/7/2022 7:20:05 AM, sha256=6b457f08185d3c3d7c2b65e91912d0b0cf07f6b6b7230bea201f3e80b6380313, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=fileinfo.sys, File C:\Windows\System32\drivers\fileinfo.sys: size=124240, created=5/7/2022 7:19:33 AM, modified=5/7/2022 7:19:33 AM, sha256=6f4f77f614904e4c2526bc45782648afa7ce63e37fa877bed2f6e80e488ca0b5, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=Wof.sys, File C:\Windows\System32\Drivers\Wof.sys: size=283984, created=9/13/2023 9:22:32 PM, modified=9/13/2023 9:22:32 PM, sha256=98e1bda0110944a6c950499e9647f160e7c843d5f7e8a9ad3cd4339e6216c2a1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=WdFilter.sys, File C:\Windows\system32\drivers\WdFilter.sys: size=438544, created=5/7/2022 7:19:08 AM, modified=5/7/2022 7:19:08 AM, sha256=293a7ae935f941bdacd2407833c35589108b5fd58fdcc4b0ebdbb40704f77431, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=Ntfs.sys, File C:\Windows\System32\Drivers\Ntfs.sys: size=3343848, created=9/13/2023 9:22:24 PM, modified=9/13/2023 9:22:24 PM, sha256=06966d1cb7406e6901f11ce3b389aa78e7bef95ee5345813b42b0b9b20b67a31, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=VBoxGuest.sys, File C:\Windows\system32\DRIVERS\VBoxGuest.sys: size=280648, created=10/12/2023 10:29:28 AM, modified=10/12/2023 10:29:28 AM, sha256=1a6fd5ec9e4bf40296867c0e3bfb09e5843fe541bc2b9c27d5afbcf4ec683761, sigCertSubject=(CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=3300000062F45CF99E58A96A89000000000062, sigCertThumbprint=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuer=(CN=Microsoft Windows Third Party Component CA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuedAt=4/6/2023 9:16:30 PM
Driver=Fs_Rec.sys, File C:\Windows\System32\Drivers\Fs_Rec.sys: size=71008, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=b5ffab1d3415e370d9cab7b63edb15ae3d4431cb0e2ede3453c66b814dd4a867, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=ndis.sys, File C:\Windows\system32\drivers\ndis.sys: size=1635712, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=8af6f4e394e125e4dc6bbbed32f7ae1180def453ccaf91b87d9405772b3c8517, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=NETIO.SYS, File C:\Windows\system32\drivers\NETIO.SYS: size=669160, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=788a4daa5c4d3d7bedeab8e4ec35a4da9641d16aaaad9c495dd98ae99bca76b4, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=ksecpkg.sys, File C:\Windows\System32\Drivers\ksecpkg.sys: size=218480, created=9/13/2023 9:22:27 PM, modified=9/13/2023 9:22:28 PM, sha256=c27f9482a25a40a3c55b5babd99cba47d18100a0c16892c228490d8520c147cd, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=tcpip.sys, File C:\Windows\System32\drivers\tcpip.sys: size=3306992, created=9/13/2023 9:22:28 PM, modified=9/13/2023 9:22:29 PM, sha256=22dc7d0301a9a04e0356d8013326acf9f89fba5898c1f9c3d788eea635c017ef, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=fwpkclnt.sys, File C:\Windows\System32\drivers\fwpkclnt.sys: size=546280, created=9/13/2023 9:22:29 PM, modified=9/13/2023 9:22:29 PM, sha256=27205600e370ce5a2410e38d7a71d4d8060d7530349f7174821e75849461941d, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=wfplwfs.sys, File C:\Windows\System32\drivers\wfplwfs.sys: size=210304, created=9/13/2023 9:22:06 PM, modified=9/13/2023 9:22:06 PM, sha256=c9ac9e6ad12ca1b6c2f5e1a4f475a7bcf65c2f57315ab4cc3dd05ec4e449b755, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=fvevol.sys, File C:\Windows\System32\DRIVERS\fvevol.sys: size=882048, created=9/13/2023 9:23:55 PM, modified=9/13/2023 9:23:55 PM, sha256=d0a4a7c42c55061003b1f0b8ec80708fb933adabdb84748bd66a846864aa6a5d, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=volume.sys, File C:\Windows\System32\drivers\volume.sys: size=54640, created=5/7/2022 7:19:03 AM, modified=5/7/2022 7:19:03 AM, sha256=b9b26d40a62517dd4a09eefb39ac7cd90389e56cf9261fefd3e7e2216b1916fa, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=volsnap.sys, File C:\Windows\System32\drivers\volsnap.sys: size=468352, created=9/13/2023 9:21:54 PM, modified=9/13/2023 9:21:54 PM, sha256=415230c6a751dd72602bd32854d8ff923f8b9d5f32a9765a2eafaab254ac689e, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=rdyboost.sys, File C:\Windows\System32\drivers\rdyboost.sys: size=329056, created=9/13/2023 9:23:39 PM, modified=9/13/2023 9:23:39 PM, sha256=c89046bdc70b5b5d691e2cdab55a0ff69e77ca30b3aa75cadabd77bafae32750, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=mup.sys, File C:\Windows\System32\Drivers\mup.sys: size=169288, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=2cd03e0a772521cd39837461b136cddb7c168c35e7f9c624409ddfc9d7fbc0b4, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=iorate.sys, File C:\Windows\system32\drivers\iorate.sys: size=87392, created=5/7/2022 7:18:58 AM, modified=5/7/2022 7:18:58 AM, sha256=f3091674a0f057ae7afc0cc4d0664f419db61e4a65435cda1ce6865f102532b3, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000033C89C66A7B45BB1FBD00000000033C, sigCertThumbprint=FE51E838A087BB561BBB2DD9BA20143384A03B3F, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FE51E838A087BB561BBB2DD9BA20143384A03B3F, sigCertIssuedAt=9/2/2021 8:23:41 PM
Driver=disk.sys, File C:\Windows\System32\drivers\disk.sys: size=140624, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=a9faf3cfbd4bbafc8de425db2de7bb037b70463ad3d2324567a52a720fadc130, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=CLASSPNP.SYS, File C:\Windows\System32\drivers\CLASSPNP.SYS: size=491568, created=9/13/2023 9:22:24 PM, modified=9/13/2023 9:22:24 PM, sha256=c9269e91434982e5e6f4cb90b73b17908140d1c63d5fad4d3996d51e4c4a74ac, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=crashdmp.sys, File C:\Windows\System32\Drivers\crashdmp.sys: size=157056, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=559ec963bfbee756c3c7c8e55b55790ca0ebf22d822a0aeeed96160454b619b7, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=cdrom.sys, File C:\Windows\System32\drivers\cdrom.sys: size=204800, created=5/7/2022 7:19:03 AM, modified=5/7/2022 7:19:03 AM, sha256=3912fc710549cb54813faac81f9dcfff0f1783cb03500965c888f47123a8a10e, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=filecrypt.sys, File C:\Windows\system32\drivers\filecrypt.sys: size=90112, created=5/7/2022 7:19:02 AM, modified=5/7/2022 7:19:02 AM, sha256=5af6b10eb044dcc6205170dabf0258f0672965a341d38fbeb7ec58d1ec04fc21, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=tbs.sys, File C:\Windows\system32\drivers\tbs.sys: size=75112, created=9/13/2023 9:21:49 PM, modified=9/13/2023 9:21:49 PM, sha256=2e0c95c2dadaf00ac6555dbb59c8a5cfbc740a6a9345164baa62a4ad433635b3, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=Null.SYS, File C:\Windows\System32\Drivers\Null.SYS: size=45056, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=da130960c7d47577c8272cbc34b7d725014f9fc6c7ab031d1e3a6f090b901f0c, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=Beep.SYS, File C:\Windows\System32\Drivers\Beep.SYS: size=40960, created=5/7/2022 7:19:45 AM, modified=5/7/2022 7:19:45 AM, sha256=e53f33dba66eeb01ea796831d357a198e659481f4f5e401775f4de5bf49a7a9e, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=dxgkrnl.sys, File C:\Windows\System32\drivers\dxgkrnl.sys: size=4691416, created=9/13/2023 9:21:59 PM, modified=9/13/2023 9:21:59 PM, sha256=2548ae148985304fbd85339acfa9d3a4a25b80dfa1da5c97c69cbe6b595669aa, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=watchdog.sys, File C:\Windows\System32\drivers\watchdog.sys: size=139264, created=9/13/2023 9:21:59 PM, modified=9/13/2023 9:21:59 PM, sha256=a72bc8bf290f445af307f051c1c082e8fbe42e0e7f3f7545bc4808c09cdece06, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=BasicDisplay.sys, File C:\Windows\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_02da009b3d736cc1\BasicDisplay.sys: size=94208, created=5/7/2022 7:19:05 AM, modified=5/7/2022 7:19:05 AM, sha256=abde6ac28248ec1d853f0549bf79c03184fbcd247e6e5c63e6ee1496af90f5a7, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=BasicRender.sys, File C:\Windows\System32\DriverStore\FileRepository\basicrender.inf_amd64_f7df692e0f5ee07f\BasicRender.sys: size=73728, created=9/13/2023 9:21:45 PM, modified=9/13/2023 9:21:45 PM, sha256=8b37e69c444862f9a6fc275153e7aeea4b1dc160af2773bc6b6deca8df949071, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=Npfs.SYS, File C:\Windows\System32\Drivers\Npfs.SYS: size=120176, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=1f9915d050152370df43d8149f75a1806baab391e66cb104aa13798781403623, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=Msfs.SYS, File C:\Windows\System32\Drivers\Msfs.SYS: size=79192, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=732112734328fc4b3e3ddc31156ecefc04cf1bfd2da26afdeec76e396953d009, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=CimFS.SYS, File C:\Windows\System32\Drivers\CimFS.SYS: size=173424, created=5/7/2022 7:19:23 AM, modified=5/7/2022 7:19:23 AM, sha256=7cedd33e00e0f8e42ac8f2d27f0e8a58e3aad79f5aa9d531f1a6404230d385f6, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=tdx.sys, File C:\Windows\system32\DRIVERS\tdx.sys: size=157000, created=9/13/2023 9:23:18 PM, modified=9/13/2023 9:23:18 PM, sha256=2b1ec8a2be37fe0306d2d94267d381feb9f90c001c8bb782ceebcd117fb421ab, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=TDI.SYS, File C:\Windows\system32\DRIVERS\TDI.SYS: size=79184, created=5/7/2022 7:19:31 AM, modified=5/7/2022 7:19:31 AM, sha256=5d0c97f8024b7ad6fb4b8f4dbc52152dad37b4776adea7994cbab700ea8f8ffe, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=netbt.sys, File C:\Windows\System32\DRIVERS\netbt.sys: size=327680, created=9/13/2023 9:22:44 PM, modified=9/13/2023 9:22:44 PM, sha256=e21eee1d954ae96be259dc7a2ba2f711b9104da7868f5da68f34f4a794b4f55a, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=afunix.sys, File C:\Windows\system32\drivers\afunix.sys: size=81920, created=5/7/2022 7:19:42 AM, modified=5/7/2022 7:19:42 AM, sha256=585afce129073707685a7b4741e32db01762bb99e0b0399666ac7b3f404f96ad, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=afd.sys, File C:\Windows\system32\drivers\afd.sys: size=697824, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=c90347f2bb0a42612d6d107f49127dc9739f0e5730e6e53211679a3257684e79, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=vwififlt.sys, File C:\Windows\System32\drivers\vwififlt.sys: size=110592, created=5/7/2022 7:19:11 AM, modified=5/7/2022 7:19:11 AM, sha256=83c9571949d7b9449df12fa11e880e7cf95bbb71c48dc03df7e88dac8269ecb1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=pacer.sys, File C:\Windows\System32\drivers\pacer.sys: size=185680, created=9/13/2023 9:22:06 PM, modified=9/13/2023 9:22:06 PM, sha256=cd31094708b9fb911adc120303d1cce948066b0079a26be56a65611beefc47f8, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=ndiscap.sys, File C:\Windows\System32\drivers\ndiscap.sys: size=86016, created=5/7/2022 7:20:14 AM, modified=5/7/2022 7:20:14 AM, sha256=ffc0dd4a6e9a1621f1c53694179ea3f629add2aad4638ec63c06d8db09f32d31, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=netbios.sys, File C:\Windows\system32\drivers\netbios.sys: size=95584, created=9/13/2023 9:22:44 PM, modified=9/13/2023 9:22:44 PM, sha256=e5e732f58c42d73272d66ad0fd9344a1af0e95ce66ec7b5e166b7d9f8396eb29, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=VBoxSF.sys, File C:\Windows\System32\drivers\VBoxSF.sys: size=406416, created=10/12/2023 10:29:34 AM, modified=10/12/2023 10:29:34 AM, sha256=c337f9acd1844b9929929810c890bdc7eaacb8c6d659ec51c1e588299b6ce7ad, sigCertSubject=(CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=3300000062F45CF99E58A96A89000000000062, sigCertThumbprint=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuer=(CN=Microsoft Windows Third Party Component CA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuedAt=4/6/2023 9:16:30 PM
Driver=Vid.sys, File C:\Windows\System32\drivers\Vid.sys: size=828744, created=9/13/2023 9:23:18 PM, modified=9/13/2023 9:23:18 PM, sha256=9427f5d4150380c2a09c83ff62ad2850effc822f2256bf7195ec5421a8dc9602, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000038C385D5C2E7483CCFB00000000038C, sigCertThumbprint=745A64E580C00EE694639E92FC9C8AC1BEAC5E5D, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=745A64E580C00EE694639E92FC9C8AC1BEAC5E5D, sigCertIssuedAt=5/5/2022 9:23:14 PM
Driver=winhvr.sys, File C:\Windows\System32\drivers\winhvr.sys: size=144768, created=9/13/2023 9:23:19 PM, modified=9/13/2023 9:23:19 PM, sha256=f3cfbe9ec5d8e974cbd94549e29f6a544a349108d770f9915b03a4f6454b6a13, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=rdbss.sys, File C:\Windows\system32\DRIVERS\rdbss.sys: size=496992, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=93d6d0016ef8789b286c2cc9aac2f35781ba88c585945cdbb39d67f6f1521493, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=csc.sys, File C:\Windows\system32\drivers\csc.sys: size=602112, created=5/7/2022 7:20:48 AM, modified=5/7/2022 9:39:26 AM, sha256=828c54cfecb2a08863319544ac716aee3898dfe78a87d7757a0e92f1b1f1daf1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000033C89C66A7B45BB1FBD00000000033C, sigCertThumbprint=FE51E838A087BB561BBB2DD9BA20143384A03B3F, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FE51E838A087BB561BBB2DD9BA20143384A03B3F, sigCertIssuedAt=9/2/2021 8:23:41 PM
Driver=nsiproxy.sys, File C:\Windows\system32\drivers\nsiproxy.sys: size=77824, created=5/7/2022 7:19:31 AM, modified=5/7/2022 7:19:31 AM, sha256=2ae09607054429194b8eb45dd88b6288115b189db903b781a546d13ab4da565e, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=npsvctrig.sys, File C:\Windows\System32\drivers\npsvctrig.sys: size=65536, created=5/7/2022 7:19:32 AM, modified=5/7/2022 7:19:32 AM, sha256=5d69278de135483fbdcd7eaa99ff58d30666922276a94b92a4c39ea479155f43, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=mssmbios.sys, File C:\Windows\System32\drivers\mssmbios.sys: size=79216, created=5/7/2022 7:19:04 AM, modified=5/7/2022 7:19:04 AM, sha256=76e79d2b988691474b2289a3b961188e8f52cb6a4667a4e7b762c00c2fa57d1b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=dfsc.sys, File C:\Windows\System32\Drivers\dfsc.sys: size=184320, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=3112011c3038116cf80156b2aecafa9274604bfeddefdc64cf2a305da29a1714, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=fastfat.SYS, File C:\Windows\System32\Drivers\fastfat.SYS: size=456048, created=9/13/2023 9:21:39 PM, modified=9/13/2023 9:21:39 PM, sha256=28664eea36643621c2cf138b9cc5070cb1840dae51c2d010a1f8b86d78fc6f21, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=bam.sys, File C:\Windows\system32\drivers\bam.sys: size=116056, created=5/7/2022 7:19:29 AM, modified=5/7/2022 7:19:29 AM, sha256=4d8a19f6f7da5f6b6fca5783487fb9bf6d8dc9e62f45a2d8356c9a185157baf8, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=ahcache.sys, File C:\Windows\system32\DRIVERS\ahcache.sys: size=376832, created=9/13/2023 9:22:39 PM, modified=9/13/2023 9:22:39 PM, sha256=3d0d004eb077b024291b5b08f31462172c3127fa0fec27c246dc9a82eac9bead, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=CompositeBus.sys, File C:\Windows\System32\DriverStore\FileRepository\compositebus.inf_amd64_2e50c98177d80a40\CompositeBus.sys: size=81920, created=5/7/2022 7:19:01 AM, modified=5/7/2022 7:19:01 AM, sha256=76937703bc26582f5e485eaba436bbc62d89e014e7e79cd49cd2f41680efd6eb, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=kdnic.sys, File C:\Windows\System32\drivers\kdnic.sys: size=70992, created=5/7/2022 7:19:31 AM, modified=5/7/2022 7:19:31 AM, sha256=fe65d837ef4fe4bedb2f9208eddc7138e3e05d4ca670d89542f376a8c9cba8b0, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=umbus.sys, File C:\Windows\System32\DriverStore\FileRepository\umbus.inf_amd64_8ee833e5ca48d1de\umbus.sys: size=94208, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=f73b2bf1d3c38531b4de55ca4589974d8f9de4e8729f7c1f5ddc12f6c87bb5f1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=VBoxWddm.sys, File C:\Windows\System32\drivers\VBoxWddm.sys: size=411144, created=10/12/2023 10:29:42 AM, modified=10/12/2023 10:29:42 AM, sha256=f04fe7c6136511876b9181eff9ecff2386089b60bd7c911e8642505efda83918, sigCertSubject=(CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=3300000062F45CF99E58A96A89000000000062, sigCertThumbprint=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuer=(CN=Microsoft Windows Third Party Component CA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuedAt=4/6/2023 9:16:30 PM
Driver=E1G6032E.sys, File C:\Windows\System32\drivers\E1G6032E.sys: size=147584, created=5/7/2022 7:19:03 AM, modified=5/7/2022 7:19:03 AM, sha256=3b0a51e1fc4d5bd3e7ec182799ad712aeeaf1dcd761d7e98bec8a0a67f7334af, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=i8042prt.sys, File C:\Windows\System32\drivers\i8042prt.sys: size=159744, created=5/7/2022 7:19:25 AM, modified=5/7/2022 7:19:25 AM, sha256=1614a4557f28191469ebd63faf1dd61274981f978e474211befff0866e4c61b6, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=kbdclass.sys, File C:\Windows\System32\drivers\kbdclass.sys: size=95576, created=5/7/2022 7:19:25 AM, modified=5/7/2022 7:19:25 AM, sha256=d69fa21c855ac31ebfb78d52047479d578cd1ee757cae9f383437abcf9387405, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=VBoxMouse.sys, File C:\Windows\system32\DRIVERS\VBoxMouse.sys: size=214160, created=10/21/2023 6:39:53 PM, modified=10/12/2023 10:29:30 AM, sha256=56744551c56637c3c6d57e5a8eed5c43823c9466d514719359cd2808c64d5969, sigCertSubject=(CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=3300000062F45CF99E58A96A89000000000062, sigCertThumbprint=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuer=(CN=Microsoft Windows Third Party Component CA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuedAt=4/6/2023 9:16:30 PM
Driver=mouclass.sys, File C:\Windows\System32\drivers\mouclass.sys: size=95592, created=5/7/2022 7:19:25 AM, modified=5/7/2022 7:19:25 AM, sha256=48c6c7f501bb951c3884720365e1cff4d472d7e97141663f678ea2c9c17f5505, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=usbohci.sys, File C:\Windows\System32\drivers\usbohci.sys: size=65536, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=f4cb3ea4d22d00031ff6b92a5595d12ef6b6f595ed5e08be897f4571ee49bf7f, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=USBPORT.SYS, File C:\Windows\System32\drivers\USBPORT.SYS: size=505216, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=88bc75a556dc85bce13963d2b27cefc1884755eb2ea9abe63db9ae1d4dd3be3b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=usbehci.sys, File C:\Windows\System32\drivers\usbehci.sys: size=120192, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=3e34d662b7c8301515019b7edded948c114297e95abb43d14059355a9d2e84fc, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=CmBatt.sys, File C:\Windows\System32\drivers\CmBatt.sys: size=73728, created=5/7/2022 7:19:04 AM, modified=5/7/2022 7:19:04 AM, sha256=e2142d8866432241258b9f73d16a208939b6d9b762aaaf60b89e037ba3b59558, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=BATTC.SYS, File C:\Windows\System32\drivers\BATTC.SYS: size=107880, created=5/7/2022 7:19:04 AM, modified=5/7/2022 7:19:04 AM, sha256=0291eaf64abd2a47b58da941e27e5259bcd327d65944859090b114dad5a17385, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=intelppm.sys, File C:\Windows\System32\drivers\intelppm.sys: size=296320, created=9/13/2023 9:21:44 PM, modified=9/13/2023 9:21:44 PM, sha256=0b9eeaaf55a55f08304b1e60e0661f360d0a4216a1d999bd8d528905cd9aadb2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=NdisVirtualBus.sys, File C:\Windows\System32\drivers\NdisVirtualBus.sys: size=57344, created=5/7/2022 7:19:42 AM, modified=5/7/2022 7:19:42 AM, sha256=b38271f729175c4c401832d47e5185e580e7009eee5c053c92ee0985ee60a06d, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=swenum.sys, File C:\Windows\System32\DriverStore\FileRepository\swenum.inf_amd64_d84a235075a8ff73\swenum.sys: size=58728, created=5/7/2022 7:19:02 AM, modified=5/7/2022 7:19:02 AM, sha256=40c9a3a401c47833e83610077f1aedc1af6bf665b47dbfce2ee7bdda5858fce9, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=ks.sys, File C:\Windows\System32\drivers\ks.sys: size=544768, created=9/13/2023 9:22:38 PM, modified=9/13/2023 9:22:38 PM, sha256=002c9acd1692c3567947fe7cac7502c57e083343e25382db9e3ad9114f8837e3, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=rdpbus.sys, File C:\Windows\System32\drivers\rdpbus.sys: size=65536, created=9/13/2023 9:23:35 PM, modified=9/13/2023 9:23:35 PM, sha256=f4e2720f4f8c5b58b023de032589842f467b2e8c08a5d91ceba0ec7ac8da9760, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=usbhub.sys, File C:\Windows\System32\drivers\usbhub.sys: size=558464, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=44619c04a7420f1ef6d77519360e91f9af03ea812c0c7b2683c36f6dc22bd309, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=USBD.SYS, File C:\Windows\System32\drivers\USBD.SYS: size=71040, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=cbcaa261469bb57c70ba484aefe79502ca4ad14846721eed56217643d4470bc8, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=hidusb.sys, File C:\Windows\System32\drivers\hidusb.sys: size=77824, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=ea9d9aeb38c740dd9bc1c7be20c6585aab45d1c83fe8f2bb9ac9433d543688f2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=HIDCLASS.SYS, File C:\Windows\System32\drivers\HIDCLASS.SYS: size=278528, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=05b52ebc50786c87e20d0bb4e4914089f47485be79634cd50a50501b9f83ffd4, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=HIDPARSE.SYS, File C:\Windows\System32\drivers\HIDPARSE.SYS: size=90112, created=9/13/2023 9:22:13 PM, modified=9/13/2023 9:22:13 PM, sha256=3dc59ca96d3276fe6c6653c37419a8d79f31a979d1294427cc2c76f1d152c6f4, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=mouhid.sys, File C:\Windows\System32\drivers\mouhid.sys: size=69632, created=5/7/2022 7:19:25 AM, modified=5/7/2022 7:19:25 AM, sha256=0bea5d62acaf74c74dcab6f88d1d240120f67dc6aec56e55691bf57b241010c9, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=cdfs.sys, File C:\Windows\system32\DRIVERS\cdfs.sys: size=131072, created=9/13/2023 9:23:23 PM, modified=9/13/2023 9:23:23 PM, sha256=19709ad52bc7bda9b4af313a40781be45adaa8ed86a813189334d911673b29ba, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=win32k.sys, File C:\Windows\System32\win32k.sys: size=692224, created=9/13/2023 9:22:10 PM, modified=9/13/2023 9:22:10 PM, sha256=e2aebc5159f3f9de61ebcb23c1eeba0680f50c016ebf9b1e3917d11d067ca81c, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=WIN32KSGD.SYS, File C:\Windows\System32\WIN32KSGD.SYS: size=49152, created=9/13/2023 9:22:10 PM, modified=9/13/2023 9:22:10 PM, sha256=eefe228fd8d46815188495f56b2181736e1cd1949090256821541934c013767e, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=win32kbase.sys, File C:\Windows\System32\win32kbase.sys: size=3211264, created=9/13/2023 9:22:08 PM, modified=9/13/2023 9:22:08 PM, sha256=f41c316b198ffa8866022c28575a05326b65ea7971486f7b174bb0e811f09fde, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=dump_diskdump.sys, Error: File missing on path 'C:\Windows\System32\Drivers\dump_diskdump.sys'
Driver=dump_storahci.sys, Error: File missing on path 'C:\Windows\System32\drivers\dump_storahci.sys'
Driver=dump_dumpfve.sys, Error: File missing on path 'C:\Windows\System32\Drivers\dump_dumpfve.sys'
Driver=win32kfull.sys, File C:\Windows\System32\win32kfull.sys: size=3833856, created=9/13/2023 9:22:10 PM, modified=9/13/2023 9:22:10 PM, sha256=74a0bab7a874a26ec85c2e75118d63596e339cfb9db2a7aadeb3ef534793c89d, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=monitor.sys, File C:\Windows\System32\drivers\monitor.sys: size=122880, created=9/13/2023 9:21:43 PM, modified=9/13/2023 9:21:43 PM, sha256=c8c16c7c1c3a2ce2a8620a4330d4dc79b89d30ce4b335b28e5f55c4463a54519, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=dxgmms2.sys, File C:\Windows\System32\drivers\dxgmms2.sys: size=1152384, created=9/13/2023 9:21:59 PM, modified=9/13/2023 9:21:59 PM, sha256=cde4b4946e9a4f99d0f22fe00ced74b1eb800047790a5ad38a6d649e41827d3d, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=cdd.dll, File C:\Windows\System32\cdd.dll: size=290816, created=9/13/2023 9:21:59 PM, modified=9/13/2023 9:21:59 PM, sha256=57a6842b637262c679bfd59efa05d04b14ca84a6d5a4d02f36ea775e37299e75, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=bfs.sys, File C:\Windows\system32\drivers\bfs.sys: size=91504, created=9/13/2023 9:22:12 PM, modified=9/13/2023 9:22:12 PM, sha256=33c337a0f6bc7eba03139e5b138023b72fc1b167b03e76bcbabad3421c5e5b17, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=luafv.sys, File C:\Windows\system32\drivers\luafv.sys: size=167936, created=9/13/2023 9:22:39 PM, modified=9/13/2023 9:22:39 PM, sha256=dba3c4dd3aa9610fad002a4af97879c358ef2710ea41d3c85ce592b96544df10, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=wcifs.sys, File C:\Windows\system32\drivers\wcifs.sys: size=251224, created=9/13/2023 9:22:10 PM, modified=9/13/2023 9:22:10 PM, sha256=792072c68dfa03f7791f9fb503f199e6799a79604c18a01d42c33a5ba2cd3663, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=cldflt.sys, File C:\Windows\system32\drivers\cldflt.sys: size=569344, created=9/13/2023 9:22:32 PM, modified=9/13/2023 9:22:32 PM, sha256=62ac1977d221c9fceef242ab03e27386a0ab65ea14002b8134baf3991397c679, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=storqosflt.sys, File C:\Windows\system32\drivers\storqosflt.sys: size=120192, created=9/13/2023 9:22:11 PM, modified=9/13/2023 9:22:11 PM, sha256=82c9128eed13b1585e72c20f4c7a44b98fc24e7425d4671da6b24ddd3dfa81b6, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=bindflt.sys, File C:\Windows\system32\drivers\bindflt.sys: size=173424, created=9/13/2023 9:22:10 PM, modified=9/13/2023 9:22:10 PM, sha256=d4d35ba162bda3996275d8a477302cfdfe3433be2a4926005e8561e583f56b81, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=mslldp.sys, File C:\Windows\system32\drivers\mslldp.sys: size=102400, created=9/13/2023 9:22:44 PM, modified=9/13/2023 9:22:44 PM, sha256=2ab373b35084a9279b19dce833dc4642a9302a389f1119046acaeaeac9232a44, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000038C385D5C2E7483CCFB00000000038C, sigCertThumbprint=745A64E580C00EE694639E92FC9C8AC1BEAC5E5D, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=745A64E580C00EE694639E92FC9C8AC1BEAC5E5D, sigCertIssuedAt=5/5/2022 9:23:14 PM
Driver=lltdio.sys, File C:\Windows\system32\drivers\lltdio.sys: size=102400, created=9/13/2023 9:22:37 PM, modified=9/13/2023 9:22:37 PM, sha256=7220127f7f8b0d31c9244f6491b587a4341bb56f09b54454fc8c6dd9de49b677, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=rspndr.sys, File C:\Windows\system32\drivers\rspndr.sys: size=118784, created=9/13/2023 9:22:37 PM, modified=9/13/2023 9:22:37 PM, sha256=850a863de19a678afba348d0e5052eb01f7917135b856dbce0934ed33b7618f9, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=wanarp.sys, File C:\Windows\System32\DRIVERS\wanarp.sys: size=126976, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=0fe7e3e59c1b18554021756afa228fe4097e7f28fa66dd0ceb7c71a5d8ae232b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=msquic.sys, File C:\Windows\system32\drivers\msquic.sys: size=419152, created=9/13/2023 9:22:26 PM, modified=9/13/2023 9:22:26 PM, sha256=e567474495204a51a4d2e140427e7e2e0fe1f1a54607b94518e601353d9d8a8b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=HTTP.sys, File C:\Windows\system32\drivers\HTTP.sys: size=1721680, created=9/13/2023 9:22:23 PM, modified=9/13/2023 9:22:23 PM, sha256=2456f0cd4d42a94bd263ea9b611d17beb03a4b9f2b21e16b7cb3cd64e5e1c53c, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=bowser.sys, File C:\Windows\system32\DRIVERS\bowser.sys: size=155648, created=5/7/2022 7:19:10 AM, modified=5/7/2022 7:19:10 AM, sha256=e3dab4c29a71cbc3167d946c015fda7bf0f0a791bec6d7d69c98ecb0ba807071, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=mrxsmb.sys, File C:\Windows\system32\DRIVERS\mrxsmb.sys: size=660864, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=e6da690831eea207e9066f48c610297698ceca0823a612f096938e54c3f9a395, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=mpsdrv.sys, File C:\Windows\System32\drivers\mpsdrv.sys: size=110592, created=9/13/2023 9:21:57 PM, modified=9/13/2023 9:21:57 PM, sha256=4c9c11e5ca07faf2759425882ee3b148f4ca6a034d034675957a675c113872db, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=mrxsmb20.sys, File C:\Windows\system32\DRIVERS\mrxsmb20.sys: size=329216, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=e944769f4bcd081cc851ae6127a92b2d380d735529404ba691f81dbb2663afec, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=srvnet.sys, File C:\Windows\System32\DRIVERS\srvnet.sys: size=368640, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=3d630a248eb803650e5317c400cb0670dbd05fea2fb08493fcafad274b8b3ca3, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=mmcss.sys, File C:\Windows\system32\drivers\mmcss.sys: size=90112, created=9/13/2023 9:21:40 PM, modified=9/13/2023 9:21:40 PM, sha256=0838f001fb4dfde8b76df670994ec3ae33b83f9a5608733f27b9823d07f3f2d3, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=srv2.sys, File C:\Windows\System32\DRIVERS\srv2.sys: size=864256, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=367f1f5d1da3f0e5d095c8ca58b701d62ad86f2dc2b1cb993f0219f625d93a85, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=Ndu.sys, File C:\Windows\system32\drivers\Ndu.sys: size=188416, created=9/13/2023 9:23:18 PM, modified=9/13/2023 9:23:18 PM, sha256=ba556e9f9e0363bee7d93270419a8a6a1a4d1d5a7f0f2cd2d14728d285ad06c1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=peauth.sys, File C:\Windows\system32\drivers\peauth.sys: size=856064, created=9/13/2023 9:21:47 PM, modified=9/13/2023 9:21:47 PM, sha256=189c49360580e07bb067d43af6ad940c30f10ad7b514a7e77ff702e356bd0ddf, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=tcpipreg.sys, File C:\Windows\System32\drivers\tcpipreg.sys: size=81920, created=9/13/2023 9:22:29 PM, modified=9/13/2023 9:22:29 PM, sha256=a8cd32772ca5ef002d97d0e8a7109a8146551440a93691938a90019d5ff71958, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=wtd.sys, File C:\Windows\System32\drivers\wtd.sys: size=128384, created=9/13/2023 9:23:20 PM, modified=9/13/2023 9:23:20 PM, sha256=06b5b116f64963091a20528e6a4517163e45a603c9e5a0f9599ab73f39eb9e27, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=condrv.sys, File C:\Windows\System32\drivers\condrv.sys: size=87376, created=5/7/2022 7:19:23 AM, modified=5/7/2022 7:19:23 AM, sha256=c492918e772afa75d6183b2c3ed03d16b15d4d2da6a75d99fcf27e05f3efab55, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=WdNisDrv.sys, File C:\Windows\system32\Drivers\WdNisDrv.sys: size=90384, created=5/7/2022 7:19:08 AM, modified=5/7/2022 7:19:08 AM, sha256=733372859dcb13dd2116297f379dc0a0e8096ad57833d6bc18be760684329072, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Driver=rassstp.sys, File C:\Windows\System32\drivers\rassstp.sys: size=122880, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=8146c3576e3bc7b44ad1e837336b7554aa86b7acbe9524c36dcc957e5256db69, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=NDProxy.sys, File C:\Windows\System32\DRIVERS\NDProxy.sys: size=122880, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=9e13b92d89cf3ce04a034005746cfda172fb15aec8d425623ab065573f853650, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=AgileVpn.sys, File C:\Windows\System32\drivers\AgileVpn.sys: size=147456, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=4fd8a684f44ed37c0b6af6ccd90e7e1af1a74f2410f2f994c00087b88da30257, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=rasl2tp.sys, File C:\Windows\System32\drivers\rasl2tp.sys: size=139264, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=ea6d9c8784b8bd9df3f7d3dbed1a0f543718c71322568fdb1494017745d14dc1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=raspptp.sys, File C:\Windows\System32\drivers\raspptp.sys: size=139264, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=a14e417716836359813bbf53305b46570d67dde54508c20b4039d96a918e4926, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=raspppoe.sys, File C:\Windows\System32\DRIVERS\raspppoe.sys: size=122880, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=cb6dbee80db238d32f26e3ad86ab046a64fad6476dbbd6bec5ac7a305ad017f2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=ndistapi.sys, File C:\Windows\System32\DRIVERS\ndistapi.sys: size=65536, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=f9b3f8d906b52cad543b5ef039bb3c94ae2b39784a9237bc58e377ee4a1028a9, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Driver=ndiswan.sys, File C:\Windows\System32\drivers\ndiswan.sys: size=237568, created=9/13/2023 9:22:47 PM, modified=9/13/2023 9:22:47 PM, sha256=8681d826585c6bc50ab84972e3ec985e2fe510cfd15abacb57e62ccb4bf97814, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM

Getting info about processes
Proces 3016=svchost, File C:\Windows\System32\svchost.exe: size=79920, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 2152=svchost, already seen
Proces 856=fontdrvhost, File C:\Windows\System32\fontdrvhost.exe: size=856712, created=9/13/2023 9:22:34 PM, modified=9/13/2023 9:22:34 PM, sha256=040d7040528fa7b2c191ddedb959e70b321a3c38cce118d4064be230997c4e50, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 3004=svchost, already seen
Proces 848=ApplicationFrameHost, File C:\Windows\System32\ApplicationFrameHost.exe: size=96424, created=9/13/2023 9:22:18 PM, modified=9/13/2023 9:22:18 PM, sha256=8234f2a3d3e49a6dd60c27d83796b606b2041a6be2299ada092533492f58af38, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 3864=svchost, already seen
Proces 6880=Code, File C:\Users\User\AppData\Local\Programs\Microsoft VS Code\Code.exe: size=154697648, created=12/25/2023 11:10:56 PM, modified=12/13/2023 10:18:56 AM, sha256=a632fa9d1a2b6e1bfec57f8d9732a12fb5903f5119870fa1b03618b05095be43, sigCertSubject=(CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000003AF30400E4CA34D05410000000003AF, sigCertThumbprint=C2048FB509F1C37A8C3E9EC6648118458AA01780, sigCertIssuer=(CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=C2048FB509F1C37A8C3E9EC6648118458AA01780, sigCertIssuedAt=11/16/2023 8:09:00 PM
Handle error for MsMpEng and file MsMpEng.exe: 5
FileName error for MsMpEng and file MsMpEng.exe: 5
Proces 2996=MsMpEng, File=MsMpEng.exe, Path unknown so assuming %windr%
Proces 2996=MsMpEng, Error: File missing on path 'C:\Windows\System32\MsMpEng.exe'
Proces 840=dwm, File C:\Windows\System32\dwm.exe: size=118784, created=9/13/2023 9:22:33 PM, modified=9/13/2023 9:22:33 PM, sha256=76073e284a29c9c20fc11f96199be4e214fe5ce90454f17e098ae183bb2f9495, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Proces 1268=svchost, already seen
Proces 1692=svchost, already seen
Handle error for smss and file smss.exe: 5
FileName error for smss and file smss.exe: 5
Proces 396=smss, File=smss.exe, Path unknown so assuming %windr%
Proces 396=smss, File C:\Windows\System32\smss.exe: size=183232, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=b6800c2ca4bfec26c8b8553beee774f4ebab741b1a48adcccce79f07062977be, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 5136=RuntimeBroker, File C:\Windows\System32\RuntimeBroker.exe: size=133616, created=9/13/2023 9:21:58 PM, modified=9/13/2023 9:21:58 PM, sha256=3074fa572ca1a3ab76f0135a9b56a92b13e973380bf4a63bb920fa797c7d76a8, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 8152=Code, already seen
Proces 2976=svchost, already seen
Proces 2544=svchost, already seen
Proces 7708=Code, already seen
Proces 10872=dotnet, File C:\Program Files\dotnet\dotnet.exe: size=185520, created=10/20/2023 2:44:54 AM, modified=10/20/2023 2:44:54 AM, sha256=c39151964cae8f06c2d268d685704566fdb6e07be3ce94fa32563272a6c8776a, sigCertSubject=(CN=.NET, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000037BA10A3ECB66E901C000000000037B, sigCertThumbprint=4C7642E107BA2BECEEF6A20FCD00A3CD897B1459, sigCertIssuer=(CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=4C7642E107BA2BECEEF6A20FCD00A3CD897B1459, sigCertIssuedAt=5/11/2023 9:03:30 PM
Proces 1672=svchost, already seen
Proces 2964=svchost, already seen
Proces 2096=svchost, already seen
Proces 1660=svchost, already seen
Proces 1228=svchost, already seen
Proces 4240=svchost, already seen
Proces 8844=svchost, already seen
Proces 5960=WmiPrvSE, File C:\Windows\System32\wbem\WmiPrvSE.exe: size=516096, created=5/7/2022 7:19:27 AM, modified=5/7/2022 7:19:27 AM, sha256=196cabed59111b6c4bbf78c84a56846d96cbbc4f06935a4fd4e6432ef0ae4083, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 3804=svchost, already seen
Proces 5092=RuntimeBroker, already seen
Proces 6384=SystemSettingsBroker, File C:\Windows\System32\SystemSettingsBroker.exe: size=220416, created=9/13/2023 9:21:49 PM, modified=9/13/2023 9:21:49 PM, sha256=b8c72044231801f90ab0cde90c54695db7a5ca7b1590222a80e59b7d3f52d9c7, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Handle error for MpCopyAccelerator and file MpCopyAccelerator.exe: 5
FileName error for MpCopyAccelerator and file MpCopyAccelerator.exe: 5
Proces 11116=MpCopyAccelerator, File=MpCopyAccelerator.exe, Path unknown so assuming %windr%
Proces 11116=MpCopyAccelerator, Error: File missing on path 'C:\Windows\System32\MpCopyAccelerator.exe'
Proces 3788=dasHost, File C:\Windows\System32\dasHost.exe: size=151552, created=9/13/2023 9:22:11 PM, modified=9/13/2023 9:22:11 PM, sha256=0d60336de6816cd6164a2f312afcca1bfa2ecd8b62ccfe046f84bcbba9d5aea2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Proces 1632=svchost, already seen
Proces 4648=RuntimeBroker, already seen
Proces 5940=svchost, already seen
Proces 7520=Code, already seen
Proces 5936=svchost, already seen
Proces 6796=msedgewebview2, File C:\Program Files (x86)\Microsoft\EdgeWebView\Application\120.0.2210.91\msedgewebview2.exe: size=3393472, created=12/25/2023 11:19:35 PM, modified=12/21/2023 5:07:44 AM, sha256=6a4e8a5761c51840ce988c9241b514028a5e45fdb386b072db0447e3961e3a06, sigCertSubject=(CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000003A54111E8F07FBE0B750000000003A5, sigCertThumbprint=05A822642CF64464460CB4684FF11C7F476873CA, sigCertIssuer=(CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=05A822642CF64464460CB4684FF11C7F476873CA, sigCertIssuedAt=10/19/2023 9:51:56 PM
Proces 8088=svchost, already seen
Proces 6036=svchost, already seen
Proces 6896=msedge, File C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe: size=3854280, created=4/11/2022 8:47:49 PM, modified=12/21/2023 5:07:44 AM, sha256=628792b5b5a4d71b8d66b1a1c6b775b84e3a5e64c0c05b8d7138164fbad5c21a, sigCertSubject=(CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000003A4CBE356B8CB7FE4270000000003A4, sigCertThumbprint=FBFF636EBB3DE3A9FD6A55111F00B16D2FDFCF3D, sigCertIssuer=(CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FBFF636EBB3DE3A9FD6A55111F00B16D2FDFCF3D, sigCertIssuedAt=10/19/2023 9:51:55 PM
Proces 1616=svchost, already seen
Proces 2908=svchost, already seen
Proces 5924=Code, already seen
Proces 880=svchost, already seen
Proces 2900=svchost, already seen
Proces 2036=svchost, already seen
Handle error for services and file services.exe: 5
FileName error for services and file services.exe: 5
Proces 740=services, File=services.exe, Path unknown so assuming %windr%
Proces 740=services, File C:\Windows\System32\services.exe: size=757576, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=4a12143226b7090d6e9bb8d040618a2c7a9ef5282f7cc10fa374adc9ab19cbeb, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 2888=svchost, already seen
Proces 3744=svchost, already seen
Proces 8912=SystemSettings, File C:\Windows\ImmersiveControlPanel\SystemSettings.exe: size=117128, created=9/13/2023 9:22:20 PM, modified=9/13/2023 9:22:20 PM, sha256=57e030dce7cb168904ba506c1467b1347bb279c9ab8ffaa057d4fb97e8f02771, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 8480=ctfmon, File C:\Windows\System32\ctfmon.exe: size=28672, created=5/7/2022 7:19:12 AM, modified=5/7/2022 7:19:12 AM, sha256=7e067b7da5da60458b5f7d5a99bc7c7c1f41999cd2559985f09267b1ec2e56ec, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 7176=SecurityHealthSystray, File C:\Windows\System32\SecurityHealthSystray.exe: size=266240, created=9/13/2023 9:22:18 PM, modified=9/13/2023 9:22:18 PM, sha256=a244ef58012a251c5fcb12b18cf5f18e3c281fe873f0f2b17aa9ad19e5663bb1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 3296=svchost, already seen
Proces 1140=svchost, already seen
Proces 704=winlogon, File C:\Windows\System32\winlogon.exe: size=909312, created=9/13/2023 9:22:23 PM, modified=9/13/2023 9:22:23 PM, sha256=caba1d86db544b52a4bfddbe33dc40f24b463e4c7e62abe61b13eecc5caaf413, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 6736=WidgetService, File C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_423.23500.0.0_x64__cw5n1h2txyewy\Dashboard\WidgetService.exe: size=193424, created=10/22/2023 11:41:48 AM, modified=10/22/2023 11:42:34 AM, sha256=d0da4c384aa8f30615c7533d8c1fb6f7331ec51e4382de8ffb25b7776b31d72b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041F1CA0357F3F17771800000000041F, sigCertThumbprint=44E6EF23CE18D8EF2B75E4381E7EFC27C67C7EB6, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=44E6EF23CE18D8EF2B75E4381E7EFC27C67C7EB6, sigCertIssuedAt=4/6/2023 8:43:51 PM
Proces 1132=svchost, already seen
Proces 4148=svchost, already seen
Proces 5008=SearchHost, File C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe: size=9728, created=9/13/2023 9:21:33 PM, modified=9/13/2023 9:21:33 PM, sha256=2551d1b7b0f97a08a27295ba2358acf17ad6a38aacb4ba4a5c54c47b14e020c1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 6300=svchost, already seen
Proces 5436=dllhost, File C:\Windows\System32\dllhost.exe: size=46416, created=5/7/2022 7:19:31 AM, modified=5/7/2022 7:19:31 AM, sha256=fdfad08eadd54a431e431febe60e87b574ce90e5502ed0be2f026a1828120fc6, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 4136=explorer, File C:\Windows\explorer.exe: size=5199488, created=9/13/2023 9:21:50 PM, modified=9/13/2023 9:21:50 PM, sha256=1510d045acbb5991bddfc93ad83eb34eae623e907746549e58e6455325164b1d, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Proces 6288=svchost, already seen
Proces 9304=msedge, already seen
Proces 1976=svchost, already seen
Handle error for svchost and file svchost.exe: 5
FileName error for svchost and file svchost.exe: 5
Proces 6716=svchost, File=svchost.exe, Path unknown so assuming %windr%
Proces 6716=svchost, File C:\Windows\System32\svchost.exe: size=79920, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 6832=SearchProtocolHost, File C:\Windows\System32\SearchProtocolHost.exe: size=462848, created=9/13/2023 9:22:08 PM, modified=9/13/2023 9:22:08 PM, sha256=c21828068b220a2be1a663151a768bcd53ba7a7b9f75922e0456e0493222e729, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 3692=sihost, File C:\Windows\System32\sihost.exe: size=147456, created=5/7/2022 7:19:20 AM, modified=5/7/2022 7:19:20 AM, sha256=51eb6455bdca85d3102a00b1ce89969016efc3ed8b08b24a2aa10e03ba1e2b13, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Proces 8428=msedgewebview2, already seen
Proces 2392=svchost, already seen
Proces 5408=svchost, already seen
Proces 2816=svchost, already seen
Proces 4536=conhost, File C:\Windows\System32\conhost.exe: size=1040384, created=9/13/2023 9:22:23 PM, modified=9/13/2023 9:22:23 PM, sha256=c59205c19edc4b83db79df597b94e36f11b8c2820625041889be0445a52c7ba7, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 2380=svchost, already seen
Proces 1948=svchost, already seen
Proces 1084=svchost, already seen
Proces 3668=ShellExperienceHost, File C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe: size=2174320, created=9/13/2023 9:24:07 PM, modified=9/13/2023 9:24:07 PM, sha256=ec8bbc16bfd725b6c18b863ecccbad88f79aff324a8a4e28590012fd3eb6f0ec, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 4960=StartMenuExperienceHost, File C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe: size=1020800, created=9/13/2023 9:22:16 PM, modified=9/13/2023 9:22:16 PM, sha256=a40d65506f093e1427c24d39444efdcb10fc1cef51ca112779346cc67e34eea1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Handle error for svchost and file svchost.exe: 5
FileName error for svchost and file svchost.exe: 5
Proces 1080=svchost, File=svchost.exe, Path unknown so assuming %windr%
Proces 1080=svchost, File C:\Windows\System32\svchost.exe: size=79920, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 1072=svchost, already seen
Proces 3656=svchost, already seen
Proces 1500=svchost, already seen
Proces 7100=SearchIndexer, File C:\Windows\System32\SearchIndexer.exe: size=966656, created=9/13/2023 9:22:08 PM, modified=9/13/2023 9:22:08 PM, sha256=4428f22c62e1ff602626e1295ed0369a6aea517a6232980a40df29c3315a9b14, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 1060=svchost, already seen
Handle error for csrss and file csrss.exe: 5
FileName error for csrss and file csrss.exe: 5
Proces 624=csrss, File=csrss.exe, Path unknown so assuming %windr%
Proces 624=csrss, File C:\Windows\System32\csrss.exe: size=38616, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=eac814cee400a078e2d549ba6e3d7bd09d1bc9805a1c6c9ec0610a0e558472a1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 3636=cmd, File C:\Windows\System32\cmd.exe: size=323584, created=9/13/2023 9:22:11 PM, modified=9/13/2023 9:22:11 PM, sha256=423e0e810a69aaceba0e5670e58aff898cf0ebffab99ccb46ebb3464c3d2facb, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Proces 4496=svchost, already seen
Proces 10960=msedgewebview2, already seen
Proces 7080=dllhost, already seen
Proces 4492=VBoxTray, File C:\Windows\System32\VBoxTray.exe: size=921232, created=10/12/2023 10:29:40 AM, modified=10/12/2023 10:29:40 AM, sha256=23397d279c959054cf79bd16ebcd3ebd87d3c2473de9dede0c289ed332a64707, sigCertSubject=(CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=3300000062F45CF99E58A96A89000000000062, sigCertThumbprint=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuer=(CN=Microsoft Windows Third Party Component CA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=FAC666005546D6BE881A31C1267717879401A950, sigCertIssuedAt=4/6/2023 9:16:30 PM
Proces 1904=svchost, already seen
Proces 7936=svchost, already seen
Handle error for wininit and file wininit.exe: 5
FileName error for wininit and file wininit.exe: 5
Proces 608=wininit, File=wininit.exe, Path unknown so assuming %windr%
Proces 608=wininit, File C:\Windows\System32\wininit.exe: size=579944, created=9/13/2023 9:22:27 PM, modified=9/13/2023 9:22:27 PM, sha256=c68ac230566c1e7e775bea31a232d0912542c8506391e691795bece67504aa03, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 6208=svchost, already seen
Proces 4480=svchost, already seen
Proces 416=SearchFilterHost, File C:\Windows\System32\SearchFilterHost.exe: size=286720, created=9/13/2023 9:22:08 PM, modified=9/13/2023 9:22:08 PM, sha256=27ced08b0dcd94b46857d2dea62c5bd8f5ae3e924aaa549a1b526b470cc190f2, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Handle error for NisSrv and file NisSrv.exe: 5
FileName error for NisSrv and file NisSrv.exe: 5
Proces 6632=NisSrv, File=NisSrv.exe, Path unknown so assuming %windr%
Proces 6632=NisSrv, Error: File missing on path 'C:\Windows\System32\NisSrv.exe'
Proces 4044=taskhostw, File C:\Windows\System32\taskhostw.exe: size=113000, created=9/13/2023 9:21:53 PM, modified=9/13/2023 9:21:53 PM, sha256=82472a84bcbb4009add338200f8e853fe4c5eafe2e2c3a2d711b85bf29b72d54, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 10052=svchost, already seen
Proces 7488=svchost, already seen
Proces 1884=svchost, already seen
Proces 2004=msedgewebview2, already seen
Proces 4032=msedge, already seen
Proces 10924=svchost, already seen
Proces 2732=svchost, already seen
Proces 2300=svchost, already seen
Proces 8760=svchost, already seen
Proces 4880=Code, already seen
Proces 3492=conhost, already seen
Proces 3152=svchost, already seen
Proces 996=svchost, already seen
Proces 7888=svchost, already seen
Proces 5732=svchost, already seen
Proces 1420=VBoxService, File C:\Windows\System32\VBoxService.exe: size=971560, created=10/12/2023 6:58:28 PM, modified=10/12/2023 6:58:28 PM, sha256=e1520a22ae1203a0ab8083fe2ecf42ba8a327eea469ccc0e09ccf066d5c47615, sigCertSubject=(CN=Oracle Corporation, OU=VirtualBox, O=Oracle Corporation, L=Redwood City, S=California, C=US), sigCertSerialNumber=0F526506CC8288117DA6BED3A5ABEC20, sigCertThumbprint=30656FCA8C48B1D98623A94B40A6BC98BD87BFAD, sigCertIssuer=(CN=DigiCert SHA2 Assured ID Code Signing CA, OU=www.digicert.com, O=DigiCert Inc, C=US), sigCertHash=30656FCA8C48B1D98623A94B40A6BC98BD87BFAD, sigCertIssuedAt=2/23/2021 1:00:00 AM
Proces 5728=msedgewebview2, already seen
Proces 9604=MoNotificationUx, File C:\Windows\UUS\Packages\Preview\amd64\MoNotificationUx.exe: size=533472, created=9/13/2023 9:22:14 PM, modified=9/13/2023 9:22:14 PM, sha256=adea84d1623afbe8fa11619573ac9c2363238138c2b3b0c000f2ebb5cbccd6c0, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 7448=MicrosoftEdgeUpdate, File C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe: size=215992, created=4/11/2022 8:47:49 PM, modified=4/11/2022 8:47:00 PM, sha256=54545f352215a9c0f370a01980aadcd5749a93589931662d89a974d7bd60f476, sigCertSubject=(CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=3300000254CA2BF3CB9DDAA675000000000254, sigCertThumbprint=EDFF0D6EA868D5A5A1A7367AEF3528F7A5512842, sigCertIssuer=(CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=EDFF0D6EA868D5A5A1A7367AEF3528F7A5512842, sigCertIssuedAt=9/2/2021 8:33:01 PM
Proces 2268=svchost, already seen
Handle error for csrss and file csrss.exe: 5
FileName error for csrss and file csrss.exe: 5
Proces 540=csrss, File=csrss.exe, Path unknown so assuming %windr%
Proces 540=csrss, File C:\Windows\System32\csrss.exe: size=38616, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=eac814cee400a078e2d549ba6e3d7bd09d1bc9805a1c6c9ec0610a0e558472a1, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Handle error for Memory Compression and file Memory Compression.exe: 5
FileName error for Memory Compression and file Memory Compression.exe: 5
Proces 1832=Memory Compression, File=Memory Compression.exe, Path unknown so assuming %windr%
Proces 1832=Memory Compression, Error: File missing on path 'C:\Windows\System32\Memory Compression.exe'
Proces 9152=msedge, already seen
Proces 764=lsass, File C:\Windows\System32\lsass.exe: size=84096, created=9/13/2023 9:22:25 PM, modified=9/13/2023 9:22:25 PM, sha256=7cb8f22828a71c63c9fcf39ef12385a1d13a2aab495e2921f6a0b3a4feab7a77, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 4836=UserOOBEBroker, File C:\Windows\System32\oobe\UserOOBEBroker.exe: size=98304, created=9/13/2023 9:22:45 PM, modified=9/13/2023 9:22:45 PM, sha256=057f103d6cbb936ba16f25ff75b9a0bee55bd095bbacd5cec912e9fc7771ec34, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 4404=MoUsoCoreWorker, File C:\Windows\UUS\Packages\Preview\amd64\MoUsoCoreWorker.exe: size=3428208, created=9/13/2023 9:22:15 PM, modified=9/13/2023 9:22:15 PM, sha256=fb98f1c124103d73726722bdaf2d47d0fa9b188084c1ed418e5eb2f80a3e9f31, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Handle error for Registry and file Registry.exe: 5
FileName error for Registry and file Registry.exe: 5
Proces 84=Registry, File=Registry.exe, Path unknown so assuming %windr%
Proces 84=Registry, Error: File missing on path 'C:\Windows\System32\Registry.exe'
Proces 5248=dllhost, already seen
Proces 7388=msedge, already seen
Proces 6524=svchost, already seen
Proces 1780=Widgets, File C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_423.23500.0.0_x64__cw5n1h2txyewy\Dashboard\Widgets.exe: size=2210600, created=10/22/2023 11:41:48 AM, modified=10/22/2023 11:42:34 AM, sha256=04f93c2c22f05115913caa85ee8e15aeb2ed4711522ae288fb41e20c3573bdae, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041F1CA0357F3F17771800000000041F, sigCertThumbprint=44E6EF23CE18D8EF2B75E4381E7EFC27C67C7EB6, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=44E6EF23CE18D8EF2B75E4381E7EFC27C67C7EB6, sigCertIssuedAt=4/6/2023 8:43:51 PM
Handle error for SecurityHealthService and file SecurityHealthService.exe: 5
FileName error for SecurityHealthService and file SecurityHealthService.exe: 5
Proces 484=SecurityHealthService, File=SecurityHealthService.exe, Path unknown so assuming %windr%
Proces 484=SecurityHealthService, File C:\Windows\System32\SecurityHealthService.exe: size=146056, created=9/13/2023 9:22:23 PM, modified=9/13/2023 9:22:23 PM, sha256=97b10920c960eda7336d2a0b2dd6d0ff6ea83e3484dedb1156e6efd96b6a1927, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 9964=FirmwareInfo, File C:\Users\User\Desktop\FirmwareInfo\bin\Debug\net4.8\win-x64\FirmwareInfo.exe: size=28672, created=12/23/2023 11:23:40 PM, modified=12/25/2023 11:42:59 PM, sha256=2c807e31c203764fc57d0c5efb3a7a35c6453deeab0d6b7636750e1ede9a4cac, no signature cert, state=Unsigned
Proces 2492=spoolsv, File C:\Windows\System32\spoolsv.exe: size=929792, created=9/13/2023 9:21:48 PM, modified=9/13/2023 9:21:48 PM, sha256=3668c100fe2c0232ce49f50f7b934e19041387211ab18935daaada83b4eb80bb, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=330000041331BC198807A90774000000000413, sigCertThumbprint=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=58FD671E2D4D200CE92D6E799EC70DF96E6D2664, sigCertIssuedAt=2/3/2023 1:05:41 AM
Proces 3496=svchost, already seen
Proces 2632=VSSVC, File C:\Windows\System32\VSSVC.exe: size=1449984, created=5/7/2022 7:19:26 AM, modified=5/7/2022 7:19:26 AM, sha256=321120de419b488b6eb0d9f32e733756fe9e97689fc0fe7fd2c9bf50afb1bcc4, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 5216=svchost, already seen
Proces 2628=svchost, already seen
Proces 5212=ctfmon, already seen
Proces 11244=Code, already seen
Proces 7360=Code, already seen
Proces 2180=svchost, already seen
Proces 5196=msedgewebview2, already seen
Proces 1316=svchost, already seen
Proces 8640=msedge, already seen
Proces 6484=svchost, already seen
Proces 2604=svchost, already seen
Handle error for svchost and file svchost.exe: 5
FileName error for svchost and file svchost.exe: 5
Proces 8828=svchost, File=svchost.exe, Path unknown so assuming %windr%
Proces 8828=svchost, File C:\Windows\System32\svchost.exe: size=79920, created=5/7/2022 7:19:30 AM, modified=5/7/2022 7:19:30 AM, sha256=949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b, sigCertSubject=(CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertSerialNumber=33000004158295A1A3D82E2857000000000415, sigCertThumbprint=8870483E0E833965A53F422494F1614F79286851, sigCertIssuer=(CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US), sigCertHash=8870483E0E833965A53F422494F1614F79286851, sigCertIssuedAt=2/3/2023 1:05:42 AM
Proces 876=svchost, already seen
Proces 9492=msedge, already seen
Proces 3888=svchost, already seen
Proces 436=svchost, already seen
Handle error for System and file System.exe: 5
FileName error for System and file System.exe: 5
Proces 4=System, File=System.exe, Path unknown so assuming %windr%
Proces 4=System, Error: File missing on path 'C:\Windows\System32\System.exe'
Proces 864=fontdrvhost, already seen
Proces 3880=svchost, already seen
Handle error for Idle and file Idle.exe: 87
FileName error for Idle and file Idle.exe: 87
Proces 0=Idle, File=Idle.exe, Path unknown so assuming %windr%
Proces 0=Idle, Error: File missing on path 'C:\Windows\System32\Idle.exe'
```
