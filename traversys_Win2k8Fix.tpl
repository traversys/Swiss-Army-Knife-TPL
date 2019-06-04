// (C) 2019 Traversys Limited
// Licensed under GPL-3.0-or-later

tpl 1.15 module Win7_2008Fix;

metadata
    __name     :='Windows 7/2008 R2 Fix';
    origin     :='Traversys';
    description:='Fixes the problem where Win 7 Desktop identifies as Win 2008 R2 on WMI failure (RemQuery)';
    tree_path  :='Traversys', 'Extensions', 'Windows 7/2008 R2 Fix';
end metadata;

from TSAKLicense import gpl_license 1.0;

pattern Win7_2008Fix 1.0
    """
        This pattern fixes Windows Version 6.1.7601 which stands for both Windows 7 and Windows 2008 R2.
        If WMI and RemQuery fails - then the OS name string is not returned.

        Change History:
        2018-05-01 1.0 WMF : Created.

        Validation Query:
        search Host where os = 'Microsoft Windows [Version 6.1.7601]'
        show name, type, os_version, os, age_count, #:::DiscoveryAccess.#:::DeviceInfo.os

    """

    overview
        tags Windows, Traversys;
    end overview;

    triggers
        on h:= Host created, confirmed where os = "Microsoft Windows [Version 6.1.7601]";
    end triggers;

    body

        if gpl_license.accept_gpl = false then
            stop;
        end if;

        sysInfo         := discovery.runCommand(h, 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"OS Manufacturer"');
        regProductName  := discovery.registryKey(h, raw "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName");

        reqList         := discovery.listRegistry(h, raw "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        regReleaseId    := discovery.registryKey(h, raw "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ReleaseId");

        hOS:= h.os;

        if sysInfo and sysInfo.result then
            hOS:= regex.extract(sysInfo.result, regex "OS Name:\s+(.*)", raw "\1");
            h.os_version:= regex.extract(hOS, regex "Microsoft Windows (.*) (Enterprise|Standard)", raw "\1", no_match:= hOS);
            h.os_edition:= regex.extract(hOS, regex "Microsoft Windows (.*) (Enterprise|Standard)", raw "\2", no_match:= hOS);
        elif regProductName and regProductName.value then
            hOS:= regProductName.value;
            h.os:= hOS;
            h.os_version:= regex.extract(hOS, regex "Windows (.*) (Enterprise|Standard)", raw "\1", no_match:= hOS);
            h.os_edition:= regex.extract(hOS, regex "Windows (.*) (Enterprise|Standard)", raw "\2", no_match:= hOS);
        end if;

        if hOS matches "Windows 7" then
            h.host_type:= "Windows Desktop";
            h.type:= "Windows Desktop";
            h._os_modified:= true;
        end if;

    end body;

end pattern;
