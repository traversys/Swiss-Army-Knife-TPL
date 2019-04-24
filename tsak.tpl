// (C) 2019 Traversys Limited
// Licensed under GPL-3.0-or-later

tpl 1.15 module TSAK;

metadata
    __name:='Traversys Swiss Army Knife (TSAK)';
    description:='Lots of additional discovery';
    tree_path:='Traversys', 'Extensions', 'TSAK';
end metadata;

from TSAKLicense import gpl_license 1.0;

pattern TSAK_Host 1.1
  """
  Author: Wes Moskal-Fitzpatrick

  The Swiss Army Knife of additional discovery.

  Change History:
  2019-04-23 1.0 WMF : Created.
  2019-04-24 1.1 WMF : Fixed ECA error caused by reg query failure with last_online.
                       Fixed dn.result > dn.value.
                       Updated Last Online to get registry key list.
                       Fixed anaconda file parse.
                       Added alternative commands for Linux DNS and Host uptime.
                       Added License File.
  
  """

  overview
     tags traversys, tsak;
  end overview;

  triggers
    on h:= Host created, confirmed;
    
  end triggers;
  
  body
  
    if gpl_license.accept_gpl = false then
        stop;
    end if;

    if h.os_type = "Windows" then
    
        // Get Device LDAP Details
        dn                              := discovery.registryKey(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Distinguished-Name");
        if dn and dn.value then
            h.tsak_distinguished_name   := dn.value;
        end if;
        
        // Get Installation, Last Boot
        boot                            := discovery.wmiQuery(h, 'SELECT InstallDate, LastBootUpTime FROM Win32_OperatingSystem', 'root\CIMV2');
        if boot then
            h.tsak_install_date         := boot[0].InstallDate;
            h.tsak_last_boot            := boot[0].LastBootUpTime;
        end if;
        
        // Get Build Date
        build                           := discovery.runCommand(h, 'systeminfo | find /i "date"');
        if build and build.result then
            h.tsak_build_date           := build.result;
        end if;
        
        // Get DNS Servers
        dns                             := discovery.wmiQuery(h, 'SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=1', 'root\CIMV2');
        if dns then
            h.tsak_dns_servers          := dns[0].DNSServerSearchOrder;
        end if;
        
        // Get BIOS Version
        bios                            := discovery.wmiQuery(h, 'SELECT SMBIOSBIOSVersion FROM Win32_BIOS', 'root\CIMV2');
        if bios then
            h.tsak_bios_version         := bios[0].SMBIOSBIOSVersion;
        end if;
        
        // Windows System Info
        sysinfo                         := discovery.runCommand(h, 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"OS Manufacturer"');
        if sysinfo and sysinfo.result then
            h.tsak_sysinfo              := sysinfo.result;
        end if;
        
        // Alternative OS Lookup
        productName                     := discovery.registryKey(h, raw "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName");
        releaseId                       := discovery.registryKey(h, raw "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ReleaseId");
        if productName and productName.value then
            h.tsak_os                   := productName.value;
        end if;
        if releaseId and releaseId.value then
            h.tsak_os_release           := releaseId.value;
        end if;
        
        // Last Patch Info
        lastPatchPs                     := discovery.runCommand(h,
                                        "powershell \"Get-HotFix | sort InstalledOn -Descending | select HotFixID, @{Name='Installed'; Expression={'{0:dd MMMM yyyy}' -f [datetime]$_.InstalledOn.Tostring()}} -First 1\""
                                        );
        lastPatchReg                    := discovery.registryKey(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install\LastSuccessTime");
        lastOnlineList                  := discovery.listRegistry(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\LastOnlineScanTimeForAppCategory");
        if lastPatchPs and lastPatchPs.result then
            h.tsak_last_patch           := lastPatchPs.result;
        elif lastPatchReg and lastPatchReg.value then
            h.tsak_last_patch           := lastPatchReg.value;
        elif lastOnlineList then
            for key in lastOnlineList do
                lastOnline              := discovery.registryKey(h, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\LastOnlineScanTimeForAppCategory\\%key%");
                if lastOnline and lastOnline[0].value then
                    h.tsak_last_online  := lastOnline[0].value;
                end if;
            end for;
        end if;
        
        // Logged Users
        users                           := discovery.wmiQuery(h, 'select LastLogon, Name, UserType from Win32_NetworkLoginProfile', 'root\CIMV2');
        loggedUsers                     := [];
        for row in users do
            user                        := "%row.Name%, %row.LastLogon%";
            list.append(loggedUsers, user);
        end for;
        h.tsak_logged_users             := loggedUsers;
        
        // Registered Owner
        regOwner                       := discovery.registryKey(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner");
        if regOwner and regOwner.value then
            h.tsak_registered_owner     := regOwner.value;
        end if;
    
    else // Non-Windows
    
        // Get DNS Servers
        dns                             := discovery.runCommand(h, "nmcli dev show | grep DNS");
        if dns and dns.result then
            if dns.result matches "Error:" then
                dns                     := discovery.runCommand(h, "cat /etc/resolv.conf | grep 'nameserver'");
            end if;
            h.tsak_dns_servers          := dns.result;
        end if;
        
        // Get Host Uptime
        up                              := discovery.runCommand(h, "uptime -p");
        if up and up.result matches "usage:" then
            if up.result matches "usage:" then
                up                      := discovery.runCommand(h, "uptime");
            end if;
            h.tsak_uptime               := up.result;
        end if;
        
        // Last Reboot
        lastBoot                        := discovery.runCommand(h, "who -b");
        if lastBoot and lastBoot.result then
            h.tsak_last_boot            := lastBoot.result;
        end if;
        
        // Get Build Date
        anacondaFile                    := discovery.runCommand(h, 'ls -ld --time-style=long-iso /var/log/anaconda 2> /dev/null || ls -ld --time-style=long-iso /var/log/installer 2> /dev/null');
        if anacondaFile and anacondaFile.result then
            buildDate:= regex.extract(anacondaFile.result, regex "(\d{4}-\d+-\d+\s\d+:\d+)", raw "\1", no_match:= anacondaFile.result);
            h.tsak_build_date           := buildDate;
        end if;
        if h.os_type matches "AIX" then
            build                       := discovery.runCommand(h, 'lslpp -h | grep -p bos.rte');
        elif h.os_type matches "Solaris" then
            build                       := discovery.runCommand(h, 'pkg info kernel');
        elif h.os_type matches "HP-UX" then
            build                       := discovery.runCommand(h, '/opt/ignite/bin/print_manifest | more');
        end if;
        if build and build.result then
            h.tsak_build_date           := build.result;
        end if;
        
    end if;
    
  end body;
    
end pattern;

pattern TSAK_UID 1.1
  """
  Author: Wes Moskal-Fitzpatrick

  Pattern for correcting usernames is set to UID.

  Change History:
  2019-04-23 1.0 WMF : Created.
  2019-04-24 1.0 WMF : Fixed ECA error for UID.
  
  """

  overview
     tags traversys, tsak;
  end overview;

  triggers
    on p:= DiscoveredProcess where username = none or username matches regex "^\d+$";
    
  end triggers;
  
  body
  
    if gpl_license.accept_gpl = false then
        stop;
    end if;
    
    if text.toNumber(p.username) = p.uid then
        da                      := discovery.access(p);
        if da.device_summary has subword "Windows" then
            // Skip
            stop;
        else
            pwd                 := discovery.fileGet(da, "/etc/passwd");
            if pwd and pwd.content then
                rx              := raw "(\w+):x:" + p.username + ":";
                uid             := regex.extract(pwd.content, rx, raw "\1", no_match:= p.username);
                p.tsak_username := uid;
            end if;
        end if;
    end if;
    
  end body;
    
end pattern;