name: Wacatac.exe
description: Watacat - behavioural detection
event:
  RegSetValue:
    value_name: Windows Live Messenger
    key_name: \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    data: C:\WINDOWS\system32\evil.exe