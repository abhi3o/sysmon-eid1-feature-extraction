from scipy import stats

exp0 = ["appinstaller.exe", "aspnet_compiler.exe", "atbroker.exe", "at.exe", "bash.exe", "bitsadmin.exe", "certoc.exe", "certreq.exe", "certutil.exe", "cmdkey.exe", "cmdl32.exe", "cmd.exe", "cmstp.exe", "configsecuritypolicy.exe", "conhost.exe", "control.exe", "cscript.exe", "csc.exe", "customshellhost.exe", "datasvcutil.exe", "desktopimgdownldr.exe", "devicecredentialdeployment.exe", "dfsvc.exe", "diantz.exe", "diskshadow.exe", "dnscmd.exe", "esentutl.exe", "eventvwr.exe", "expand.exe", "explorer.exe", "extexport.exe", "extrac32.exe", "findstr.exe", "finger.exe", "fltmc.exe", "forfiles.exe", "fsutil.exe", "ftp.exe", "gpscript.exe", "hh.exe", "ie4uinit.exe", "ieexec.exe", "ilasm.exe", "imewdbld.exe", "infdefaultinstall.exe", "installutil.exe", "jsc.exe", "ldifde.exe", "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe", "mmc.exe", "mpcmdrun.exe", "msbuild.exe", "msconfig.exe", "msdt.exe", "msedgewebview2.exe", "msedge.exe", "mshta.exe", "msiexec.exe", "netsh.exe", "odbcconf.exe", "offlinescannershell.exe", "onedrivestandaloneupdater.exe", "pcalua.exe", "pcwrun.exe", "pktmon.exe", "pnputil.exe", "presentationhost.exe", "printbrm.exe", "print.exe", "psr.exe", "rasautou.exe", "rdrleakdiag.exe", "regasm.exe", "regedit.exe", "regini.exe", "register-cimprovider.exe", "regsvcs.exe", "regsvr32.exe", "reg.exe", "replace.exe", "rpcping.exe", "rundll32.exe", "runexehelper.exe", "runonce.exe", "runscripthelper.exe", "schtasks.exe", "scriptrunner.exe", "sc.exe", "setres.exe", "settingsynchost.exe", "ssh.exe", "stordiag.exe", "syncappvpublishingserver.exe", "tar.exe", "teams.exe", "ttdinject.exe", "tttracer.exe", "unregmp2.exe", "vbc.exe", "verclsid.exe", "wab.exe", "winget.exe", "wlrmdr.exe", "wmic.exe", "workfolders.exe", "wscript.exe", "wsreset.exe", "wt.exe", "wuauclt.exe", "xwizard.exe"]
exp1 = "(?:programfiles|winsysdir|windir)"
exp2 = "(?:temp|downloads|public|drive|userprofile)"
exp3 = r"NT\s+AUTHORITY\\SYSTEM"
exp4 = r"\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"
exp5 = "(?:\.ps1|\.vbs|\.bat|\.dll)"
exp6 = "(?:https?:\/\/|ftp:\/\/)"
exp7 = r"\\\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"
exp8 = r"\s+(\\)(\\[\w\.\-_]+){2,}"
exp9 = r'\w:\\Program Files \(x86\)'
exp10 = r'\w:\\Program Files'
exp11 = r'\w:\\Windows\\System32'
exp12 = r'\w:\\Windows\\SysWOW64'
exp13 = 'SystemRoot\\System32'
exp14 = 'SystemRoot\\SysWOW64'
exp15 = r'\w:\\Windows\\Temp'
exp16 = r'\w:\\ProgramData'
exp17 = r'\w:\\Users\\[\w\-. ]+\\AppData\\Local\\Temp'
exp18 = r'\w:\\Windows\\'
exp19 = r'\w:\\Users\\[\w\-. ]+'
exp20 = r'\w:\\'
exp21 = r'\w:\\Users\\Public'
exp22 = r'\w:\\Users\\[\w\-. ]+\\Downloads'
exp23 = r'([^\\]+$)'

# A function to score an event as unfamiliar, and thus, anomalous if the parent-child pair has not been seen often in the dataset
def unfamiliarityscore(df, uniqueParents):
    counts = dict()
    
    for parent in uniqueParents:
        a = df.loc[df['Parent'] == parent, 'Child'].value_counts().to_dict()
        av = list(a.values())
    
        ap = dict()
        for key, value in a.items():
            ap[key] = round(stats.percentileofscore(av, value, kind='rank') / 100.00, 2)
        counts[parent] = ap
    
    pairCounts = dict()
    for key, value in counts.items():
        for k, v in value.items():
            pairCounts[tuple((key, k))] = v
    return pairCounts
