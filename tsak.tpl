// (C) 2019 GPL-3.0-or-later, Traversys Limited
// Traversys Swiss Army Knife (TSAK)

tpl 1.15 module TSAK;

metadata
    __name:='Traversys Swiss Army Knife (TSAK)';
    description:='Lots of additional discovery';
    tree_path:='Traversys', 'Extensions', 'TSAK';
end metadata;

pattern TSAK_Host 1.0
  """
  Author: Wes Moskal-Fitzpatrick

  The Swiss Army Knife of additional discovery.

  Change History:
  2019-04-23 1.0 WMF : Created.
  
  """

  overview
     tags traversys, tsak;
  end overview;

  triggers
    on h:= Host created, confirmed;
    
  end triggers;
  
  body

    if h.os_type = "Windows" then
    
        // Get Device LDAP Details
        dn                          := discovery.registryKey(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Distinguished-Name");
        h.tsak_distinguished_name   := dn.result;
        
        // Get Installation, Last Boot
        boot                        := discovery.wmiQuery(h, 'SELECT InstallDate, LastBootUpTime FROM Win32_OperatingSystem', 'root\CIMV2');
        h.tsak_install_date         := boot[0].InstallDate;
        h.tsak_last_boot            := boot[0].LastBootUpTime;
        
        // Get Build Date
        build                       := discovery.runCommand(h, 'systeminfo | find /i "date"');
        h.tsak_build_date           := build.result;
        
        // Get DNS Servers
        dns                         := discovery.wmiQuery(h, 'SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=1', 'root\CIMV2');
        h.tsak_dns_servers          := dns[0].DNSServerSearchOrder;
        
        // Get BIOS Version
        bios                        := discovery.wmiQuery(h, 'SELECT SMBIOSBIOSVersion FROM Win32_BIOS', 'root\CIMV2');
        h.tsak_bios_version         := bios[0].SMBIOSBIOSVersion;
        
        // Windows System Info
        sysinfo                     := discovery.runCommand(h, 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"OS Manufacturer"');
        h.tsak_sysinfo              := sysinfo.result;
        
        // Alternative OS Lookup
        product_name                := discovery.registryKey(h, raw "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName");
        release_id                  := discovery.registryKey(h, raw "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ReleaseId");
        h.tsak_os                   := product_name.value;
        h.tsak_os_release           := release_id.value;
        
        // Last Patch Info
        last_patch_ps               := discovery.runCommand(h,
                                        "powershell \"Get-HotFix | sort InstalledOn -Descending | select HotFixID, @{Name='Installed'; Expression={'{0:dd MMMM yyyy}' -f [datetime]$_.InstalledOn.Tostring()}} -First 1\""
                                        );
        last_patch_reg              := discovery.registryKey(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install\LastSuccessTime");
        last_online                 := discovery.registryKey(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\LastOnlineScanTimeForAppCategory");
        if last_patch_ps and last_patch_ps.result then
            h.tsak_last_patch       := last_patch_ps.result;
        elif last_patch_reg and last_patch_reg.value then
            h.tsak_last_patch       := last_patch_reg.value;
        end if;
        h.tsak_last_online          := last_online.value;
        
        // Logged Users
        users                       := discovery.wmiQuery(h, 'select LastLogon, Name, UserType from Win32_NetworkLoginProfile', 'root\CIMV2');
        logged_users                := [];
        for row in users do
            user                    := "%row.Name%, %row.LastLogon%";
            list.append(logged_users, user);
        end for;
        h.tsak_logged_users         := logged_users;
        
        // Registered Owner
        reg_owner                   := discovery.registryKey(h, raw "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner");
        h.tsak_registered_owner     := reg_owner.value;
    
    else // Non-Windows
    
        // Get DNS Servers
        dns                         := discovery.runCommand(h, "nmcli dev show | grep DNS");
        h.tsak_dns_servers          := dns.result;
        
        // Get Host Uptime
        up                          := discovery.runCommand(h, "uptime -p");
        h.tsak_uptime               := up.result;
        
        // Last Reboot
        last_boot                   := discovery.runCommand(h, "who -b");
        h.tsak_last_boot            := last_boot.result;
        
        // Get Build Date
        if h.os_type matches "AIX" then
            build                   := discovery.runCommand(h, 'lslpp -h | grep -p bos.rte');
        elif h.os_type matches "Solaris" then
            build                   := discovery.runCommand(h, 'pkg info kernel');
        elif h.os_type matches "HP-UX" then
            build                   := discovery.runCommand(h, '/opt/ignite/bin/print_manifest | more');
        else
            build                   := discovery.runCommand(h, 'ls -ld --time-style=long-iso /var/log/anaconda 2> /dev/null || ls -ld --time-style=long-iso /var/log/installer 2> /dev/null');
        end if;
        h.tsak_build_date           := build.result;
        
    end if;
    
  end body;
    
end pattern;

pattern TSAK_UID 1.0
  """
  Author: Wes Moskal-Fitzpatrick

  Pattern for correcting usernames is set to UID.

  Change History:
  2019-04-23 1.0 WMF : Created.
  
  """

  overview
     tags traversys, tsak;
  end overview;

  triggers
    on p:= DiscoveredProcess where username = none or username matches regex "^\d+$";
    
  end triggers;
  
  body
    
    if text.toNumber(p.username) = p.uid then
        da                      := discovery.access(p);
        if da.device_summary has subword "Windows" then
            // Skip
            stop;
        else
            pwd                 := discovery.fileGet(da, "/etc/passwd");
            if pwd and pwd.content then
                rx              := raw "(\w+):x:" + p.uid + ":";
                uid             := regex.extract(pwd.content, rx, raw "\1", no_match:= p.username);
                p.tsak_username := uid;
            end if;
        end if;
    end if;
    
  end body;
    
end pattern;
