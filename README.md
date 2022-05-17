# windows CET
windows CET is a protect mechanism to avoid ROP exploit skill.
For example:
test.asm
```asm
.code

rop proc
mov [rsp], rcx
ret
rop endp

end
```
main.c
```c
void rop(void*);
void test2(void) {
	printf("hello2\n");
}
void test(void) {
	printf("hello1\n");
	rop(test2);
}

void test3(void){
  test();
}

int main(void) {
	printf("%p\n", test2);
	test3();
	getch();
	return 0;
}
```

We will get an exception error if it enabled [/CETCOMPAT](https://docs.microsoft.com/en-us/cpp/build/reference/cetcompat?view=msvc-170)
```
$ test.exe
00007FF7E4E83AFE
hello1
```
if Host doesn't support CET:
```
$ test.exe
00007FF7E4E83AFE
hello1
hello2
```
> CET is supported starting from Intel 11th CPU.

We can enable it in VS2019 by:
`Configuration Properties` > `Linker` > `Additional Options`, select `CET shadow stack compatible`

# Check if enabled CET
We can use `C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.28.29333\bin\Hostx64\x64\dumpbin.exe` to check if a program enabled CET:
```bash
$ .\dumpbin.exe  /headers "C:\Windows\System32\conhost.exe"|findstr CET
                   CET compatible
$
```


# Weakness
1. it doesn't check if we return from `test` to `main` at position after called `test3`. This means CET won't check return stack out-of-order.
2. if exe doesn't enable CETCOMPAT, though it loads dll enabled CET, running process don't have CET whether `ret` in program or dll. This is different from ASLR or DEP.
3. For VMware Workstation, it doesn't support CET in VM.

# Enabled CET list in windows:
Windows 21H2
```
C:\windows\System32\conhost.exe
C:\windows\System32\csrss.exe
C:\windows\System32\fontdrvhost.exe
C:\windows\System32\lsass.exe
C:\windows\System32\MpSigStub.exe
C:\windows\System32\MRT.exe
C:\windows\System32\sc.exe
C:\windows\System32\services.exe
C:\windows\System32\smss.exe
C:\windows\System32\wininit.exe
C:\windows\System32\winlogon.exe
C:\windows\System32\DriverStore\FileRepository\iclsclient.inf_amd64_76523213b78d9046\lib\IntelPTTEKRecertification.exe
C:\windows\System32\DriverStore\FileRepository\iclsclient.inf_amd64_76523213b78d9046\lib\SocketHeciServer.exe
C:\windows\System32\DriverStore\FileRepository\iclsclient.inf_amd64_76523213b78d9046\lib\TPMProvisioningService.exe
C:\windows\SysWOW64\fontdrvhost.exe
C:\windows\SysWOW64\sc.exe
C:\windows\WinSxS\amd64_hyperv-compute-host-service_31bf3856ad364e35_10.0.19041.1645_none_6c4115cc61067274\vmcompute.exe
C:\windows\WinSxS\amd64_hyperv-compute-host-service_31bf3856ad364e35_10.0.19041.1682_none_6c455b4c61028aed\vmcompute.exe
C:\windows\WinSxS\amd64_hyperv-compute-host-service_31bf3856ad364e35_10.0.19041.1706_none_6c322df0611242aa\vmcompute.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmms_31bf3856ad364e35_10.0.19041.1645_none_ab2eb1aa14402f5a\vmms.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmms_31bf3856ad364e35_10.0.19041.1682_none_ab32f72a143c47d3\vmms.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmms_31bf3856ad364e35_10.0.19041.1706_none_ab1fc9ce144bff90\vmms.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmwp_31bf3856ad364e35_10.0.19041.1566_none_a9e5f2081512526d\vmwp.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmwp_31bf3856ad364e35_10.0.19041.1682_none_a9dd7dd015183a88\vmwp.exe
C:\windows\WinSxS\amd64_microsoft-onecore-console-host-core_31bf3856ad364e35_10.0.19041.1566_none_e23ba731d97ebb90\conhost.exe
C:\windows\WinSxS\amd64_microsoft-windows-csrss_31bf3856ad364e35_10.0.19041.546_none_36dd2ad842e4f8c3\csrss.exe
C:\windows\WinSxS\amd64_microsoft-windows-gdi_31bf3856ad364e35_10.0.19041.1620_none_1e6a33d60fdb2417\fontdrvhost.exe
C:\windows\WinSxS\amd64_microsoft-windows-lsa-minwin_31bf3856ad364e35_10.0.19041.1586_none_b21305f3479643c9\lsass.exe
C:\windows\WinSxS\amd64_microsoft-windows-s..cecontroller-minwin_31bf3856ad364e35_10.0.19041.928_none_1d29b4735b607954\services.exe
C:\windows\WinSxS\amd64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.19041.1_none_2a5f489c740a390b\sc.exe
C:\windows\WinSxS\amd64_microsoft-windows-smss-minwin_31bf3856ad364e35_10.0.19041.964_none_5c42846f47acb1a6\smss.exe
C:\windows\WinSxS\amd64_microsoft-windows-wininit_31bf3856ad364e35_10.0.19041.1620_none_a589d42cb9a56d6d\wininit.exe
C:\windows\WinSxS\amd64_microsoft-windows-winlogon_31bf3856ad364e35_10.0.19041.1620_none_e45a1c748a4642c0\winlogon.exe
C:\windows\WinSxS\wow64_microsoft-windows-gdi_31bf3856ad364e35_10.0.19041.1620_none_28bede28443be612\fontdrvhost.exe
C:\windows\WinSxS\wow64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.19041.1_none_34b3f2eea86afb06\sc.exe
```

Windows server 2022 enabled hyper-v
```
C:\windows\System32\conhost.exe
C:\windows\System32\csrss.exe
C:\windows\System32\dpnsvr.exe
C:\windows\System32\fontdrvhost.exe
C:\windows\System32\lsass.exe
C:\windows\System32\MpSigStub.exe
C:\windows\System32\ntkrla57.exe
C:\windows\System32\ntoskrnl.exe
C:\windows\System32\sc.exe
C:\windows\System32\services.exe
C:\windows\System32\smss.exe
C:\windows\System32\vmcompute.exe
C:\windows\System32\vmms.exe
C:\windows\System32\vmwp.exe
C:\windows\System32\wininit.exe
C:\windows\System32\winlogon.exe
C:\windows\SysWOW64\fontdrvhost.exe
C:\windows\SysWOW64\sc.exe
C:\windows\WinSxS\amd64_hyperv-compute-host-service_31bf3856ad364e35_10.0.20344.1_none_8113681e74bd29f3\vmcompute.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmms_31bf3856ad364e35_10.0.20344.1_none_c00103fc27f6e6d9\vmms.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmwp_31bf3856ad364e35_10.0.20344.1_none_beab8aa228d2d98e\vmwp.exe
C:\windows\WinSxS\amd64_microsoft-onecore-console-host-core_31bf3856ad364e35_10.0.20344.1_none_f7013fcbed3f42b1\conhost.exe
C:\windows\WinSxS\amd64_microsoft-windows-csrss_31bf3856ad364e35_10.0.20344.1_none_e24ee033ad1fdf69\csrss.exe
C:\windows\WinSxS\amd64_microsoft-windows-d..directplay8-payload_31bf3856ad364e35_1.0.20344.1_none_3cca8619e478de59\dpnsvr.exe
C:\windows\WinSxS\amd64_microsoft-windows-gdi_31bf3856ad364e35_10.0.20344.1_none_333e14d423908e69\fontdrvhost.exe
C:\windows\WinSxS\amd64_microsoft-windows-lsa-minwin_31bf3856ad364e35_10.0.20344.1_none_c6d69df95b58983c\lsass.exe
C:\windows\WinSxS\amd64_microsoft-windows-os-kernel-la57_31bf3856ad364e35_10.0.20344.1_none_d5e1df603cdf2bbf\ntkrla57.exe
C:\windows\WinSxS\amd64_microsoft-windows-os-kernel_31bf3856ad364e35_10.0.20344.1_none_f59b5dfc7d2d4385\ntoskrnl.exe
C:\windows\WinSxS\amd64_microsoft-windows-s..cecontroller-minwin_31bf3856ad364e35_10.0.20344.1_none_c883c1cac5ad7092\services.exe
C:\windows\WinSxS\amd64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.20344.1_none_fdd937749db6e3ad\sc.exe
C:\windows\WinSxS\amd64_microsoft-windows-smss-minwin_31bf3856ad364e35_10.0.20344.1_none_07cbd29eb1d59e7c\smss.exe
C:\windows\WinSxS\amd64_microsoft-windows-wininit_31bf3856ad364e35_10.0.20344.1_none_ba5db52acd5ad7bf\wininit.exe
C:\windows\WinSxS\amd64_microsoft-windows-winlogon_31bf3856ad364e35_10.0.20344.1_none_f92dfd729dfbad12\winlogon.exe
C:\windows\WinSxS\amd64_windows-defender-nis-service_31bf3856ad364e35_10.0.20344.1_none_a75d9c5cdbf9a8a0\NisSrv.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.20344.1_none_4f111f2a1fd6c50f\MpCmdRun.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.20344.1_none_4f111f2a1fd6c50f\MpCopyAccelerator.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.20344.1_none_4f111f2a1fd6c50f\MpDlpCmd.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.20344.1_none_4f111f2a1fd6c50f\MsMpEng.exe
C:\windows\WinSxS\wow64_microsoft-windows-gdi_31bf3856ad364e35_10.0.20344.1_none_3d92bf2657f15064\fontdrvhost.exe
C:\windows\WinSxS\wow64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.20344.1_none_082de1c6d217a5a8\sc.exe
```

Windows 11
```
C:\windows\System32\conhost.exe
C:\windows\System32\csrss.exe
C:\windows\System32\dpnsvr.exe
C:\windows\System32\fontdrvhost.exe
C:\windows\System32\lsass.exe
C:\windows\System32\ntkrla57.exe
C:\windows\System32\ntoskrnl.exe
C:\windows\System32\sc.exe
C:\windows\System32\services.exe
C:\windows\System32\smss.exe
C:\windows\System32\wininit.exe
C:\windows\System32\winlogon.exe
C:\windows\SysWOW64\sc.exe
C:\windows\WinSxS\amd64_hyperv-compute-host-service_31bf3856ad364e35_10.0.22000.41_none_d9e7edc8c7849596\vmcompute.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmms_31bf3856ad364e35_10.0.22000.41_none_18d589a67abe527c\vmms.exe
C:\windows\WinSxS\amd64_microsoft-hyper-v-vstack-vmwp_31bf3856ad364e35_10.0.22000.41_none_1780104c7b9a4531\vmwp.exe
C:\windows\WinSxS\amd64_microsoft-onecore-console-host-core_31bf3856ad364e35_10.0.22000.1_none_c3d9e11628fe2504\conhost.exe
C:\windows\WinSxS\amd64_microsoft-windows-csrss_31bf3856ad364e35_10.0.22000.1_none_af27817de8dec1bc\csrss.exe
C:\windows\WinSxS\amd64_microsoft-windows-d..directplay8-payload_31bf3856ad364e35_1.0.22000.1_none_8270b443c99f06ee\dpnsvr.exe
C:\windows\WinSxS\amd64_microsoft-windows-gdi_31bf3856ad364e35_10.0.22000.1_none_0016b61e5f4f70bc\fontdrvhost.exe
C:\windows\WinSxS\amd64_microsoft-windows-lsa-minwin_31bf3856ad364e35_10.0.22000.1_none_93af3f4397177a8f\lsass.exe
C:\windows\WinSxS\amd64_microsoft-windows-os-kernel-la57_31bf3856ad364e35_10.0.22000.51_none_2eb666f08fa69489\ntkrla57.exe
C:\windows\WinSxS\amd64_microsoft-windows-os-kernel_31bf3856ad364e35_10.0.22000.51_none_4e6fe58ccff4ac4f\ntoskrnl.exe
C:\windows\WinSxS\amd64_microsoft-windows-s..cecontroller-minwin_31bf3856ad364e35_10.0.22000.51_none_2158495b1874d95c\services.exe
C:\windows\WinSxS\amd64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.22000.1_none_cab1d8bed975c600\sc.exe
C:\windows\WinSxS\amd64_microsoft-windows-smss-minwin_31bf3856ad364e35_10.0.22000.1_none_d4a473e8ed9480cf\smss.exe
C:\windows\WinSxS\amd64_microsoft-windows-wininit_31bf3856ad364e35_10.0.22000.1_none_873656750919ba12\wininit.exe
C:\windows\WinSxS\amd64_microsoft-windows-winlogon_31bf3856ad364e35_10.0.22000.37_none_51c1a1aef0f3c334\winlogon.exe
C:\windows\WinSxS\amd64_windows-defender-nis-service_31bf3856ad364e35_10.0.22000.1_none_74363da717b88af3\NisSrv.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.22000.1_none_1be9c0745b95a762\MpCmdRun.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.22000.1_none_1be9c0745b95a762\MpCopyAccelerator.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.22000.1_none_1be9c0745b95a762\MpDlpCmd.exe
C:\windows\WinSxS\amd64_windows-defender-service_31bf3856ad364e35_10.0.22000.1_none_1be9c0745b95a762\MsMpEng.exe
C:\windows\WinSxS\wow64_microsoft-windows-s..llercommandlinetool_31bf3856ad364e35_10.0.22000.1_none_d50683110dd687fb\sc.exe
```

Other program
```
C:\Program Files\Google\Chrome\Application\chrome.exe
C:\Program Files\Google\Chrome\Application\new_chrome.exe
C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
C:\Program Files (x86)\Microsoft\Edge\Application\pwahelper.exe
C:\Program Files (x86)\Microsoft\Edge\Application\101.0.1210.47\cookie_exporter.exe
C:\Program Files (x86)\Microsoft\Edge\Application\101.0.1210.47\identity_helper.exe
C:\Program Files (x86)\Microsoft\Edge\Application\101.0.1210.47\msedge.exe
C:\Program Files (x86)\Microsoft\Edge\Application\101.0.1210.47\msedgewebview2.exe
C:\Program Files (x86)\Microsoft\Edge\Application\101.0.1210.47\pwahelper.exe
C:\Program Files (x86)\Microsoft\Edge\Application\101.0.1210.47\BHO\ie_to_edge_stub.exe
C:\Program Files (x86)\Microsoft\EdgeCore\101.0.1210.47\cookie_exporter.exe
C:\Program Files (x86)\Microsoft\EdgeCore\101.0.1210.47\identity_helper.exe
C:\Program Files (x86)\Microsoft\EdgeCore\101.0.1210.47\msedge.exe
C:\Program Files (x86)\Microsoft\EdgeCore\101.0.1210.47\msedgewebview2.exe
C:\Program Files (x86)\Microsoft\EdgeCore\101.0.1210.47\pwahelper.exe
C:\Program Files (x86)\Microsoft\EdgeCore\101.0.1210.47\BHO\ie_to_edge_stub.exe
C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.161.35\MicrosoftEdgeUpdate.exe
C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.161.35\MicrosoftEdgeUpdateBroker.exe
C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.161.35\MicrosoftEdgeUpdateComRegisterShell64.exe
C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.161.35\MicrosoftEdgeUpdateCore.exe
C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.161.35\MicrosoftEdgeUpdateOnDemand.exe
C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.161.35\MicrosoftEdgeUpdateSetup.exe
C:\Program Files (x86)\Microsoft\EdgeUpdate\Download\{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}\1.3.161.35\MicrosoftEdgeUpdateSetup_X86_1.3.161.35.exe
C:\Program Files (x86)\Microsoft Office\root\VFS\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\ai.exe
C:\Program Files (x86)\Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\OFFICE16\ai.exe
```
