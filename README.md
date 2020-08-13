# Shamoon
Shamoon's payload simulation

************
This script can run with a windows machine that has a Python 2 version installed.
************
# This script contains most of the payload for the Shamoon malware

To run it: 
  open a new cmd and cd to the shamoon folder (>>cd C:\Users\....\Shamoon\shamoon)
  in the cmd windows type: python shamoon.py -i

In order to run the cleanup (deletion of all the files and process shamoon created):
  open a new cmd and cd to the shamoon folder (>>cd C:\Users\....\Shamoon\shamoon)
	in the cmd windows type: python shamoon.py -d


# Please make sure there is live internet connection.

# Couple of remarks:


1. The log file of for the run is stored in C:\ under the name logs.txt
   The log file of the delete operation is stored in C:\ under the name Sh_cleanuplogs.txt.
   In order to see the cleanup logs the cleanup opeartion need to be initialize first.


2. DUI170.dll is created on C:\Windows\Temp

3. The system information gathered from the msinfo32 command is located in a log file on ->
    C:\Users\shamoon\msinfo_log.txt

4. For test purpose The user have to give the Ip address and class he want to scan.
   
 
5. Because I didn't know which file the originial malware copied from the ADMIN$ I decided
   to copy a random file from ADMIN$ called winhelp.exe to %windir%\System32


6. The sciprt sometimes creates unnecessary files: 'TrkSrv.sat' and 'dist directory', in the 
   shamoon folder. You can igonore them and delete if they show up.

7. for some reason the pip and the Psexec not work sometimes because their PATH is deleted.
   if that is the case please add the path to the psexec.exe (i.e C:\Users\emulator_testing\Desktop\Shamoon\shamoon)
   to the %PATH% variable and the pip (usually installed in python\Scripts) to the PATH as well.

8. Task 7 - Start workstation service and 
    Task 12 - ping -n 30 127.0.0.1 >nul && sc config TrkSvr binpath= system32\trksrv.exe
    Sometimes causes the cmd to crash on windwos 7. I didn't find a solution for it.
    If that happens try running it again.

9. All the files (batch files and exes) need to be in the same folder as the python shamoon.py script.

1011. In the start of the run you will see Errno 13 - Permission denied for pywin32. You can igonore it
