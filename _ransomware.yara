rule detect_ransomware_test35
{
	strings:
		$ransom0 = "PhysicalDrive" ascii wide
		$ransom1 = "attrib" ascii wide
		$ransom2 = "runas" ascii wide
		$ransom3 = "net" ascii wide
		$ransom4 = "stop" ascii wide
		$ransom5 = "sc" ascii wide
		$ransom6 = "config" ascii wide
		$ransom7 = "wevtutil" ascii wide
		$ransom8 = "taskkill" ascii wide
		$ransom9 = "vssadmin" ascii wide
		$ransom10 = "quiet" ascii wide
		$ransom11 = "diskshadow" ascii wide
		$ransom12 = "shadows" ascii wide
		$ransom13 = "all" ascii wide
		$ransom14 = "schtasks" ascii wide
		$ransom15 = "create" ascii wide
		$ransom16 = "system" ascii wide
		$ransom17 = "wmic" ascii wide
		$ransom18 = "powershell" ascii wide
		$ransom19 = "cmd" ascii wide
		$ransom20 = "bcdedit" ascii wide
		$ransom21 = "set" ascii wide
		$ransom22 = "fsutil" ascii wide
		$ransom23 = "deletejournal" ascii wide
		$ransom24 = "usn" ascii wide
		$ransom25 = "recoveryenabled" ascii wide
		$ransom26 = "bootstatuspolicy" ascii wide
		$ransom27 = "ignoreallfailures" ascii wide
		$ransom28 = "wmic" ascii wide
		$ransom29 = "shadowcopy" ascii wide
		$ransom30 = "delete" ascii wide
		$ransom31 = "powershell" ascii wide
		$ransom32 = "win32_shadowcopy" ascii wide
		$ransom33 = "vssadmin" ascii wide
		$ransom34 = "resize" ascii wide
		$ransom35 = "shadowstorage" ascii wide
		$ransom36 = "process" ascii wide
		$ransom37 = "call" ascii wide
		$ransom38 = "create" ascii wide
		$ransom39 = "wbadmin" ascii wide
		$ransom40 = "catalog" ascii wide
		$ransom41 = "quiet" ascii wide
		$ransom42 = "systemstatebackup" ascii wide
		$ransom43 = "backup" ascii wide
		$ransom44 = "ransom" ascii wide
		$ransom45 = "files" ascii wide
		$ransom46 = "encrypt" ascii wide
		$ransom47 = "RSA" ascii wide
		$ransom48 = "AES" ascii wide
		$ransom49 = "key" ascii wide
		$ransom50 = "wallet" ascii wide
		$ransom51 = "decrypt" ascii wide
		$ransom52 = "recover" ascii wide
		$ransom53 = "payment" ascii wide
		
	condition:
		uint16(0) == 0x5a4d and filesize < 1MB and 35 of them
}