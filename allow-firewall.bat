@echo off
REM Opens TCP port 8081 so other computers on the network can reach the dashboard.
REM Run as administrator on the machine where the monitor runs.
net session >nul 2>&1
if %errorlevel% neq 0 ( echo Run as administrator. & pause & exit /b 1 )
netsh advfirewall firewall add rule name="Server Signal Desk" dir=in action=allow protocol=TCP localport=8081
REM Passive ear (v0.24): SSDP/mDNS announcements arrive as inbound UDP multicast.
REM Without these rules the listener binds fine but hears silence.
netsh advfirewall firewall add rule name="Server Signal Desk SSDP" dir=in action=allow protocol=UDP localport=1900
netsh advfirewall firewall add rule name="Server Signal Desk mDNS" dir=in action=allow protocol=UDP localport=5353
echo.
echo Ports opened: TCP 8081 (dashboard), UDP 1900+5353 (passive ear). Other PCs can now reach http://THIS-PC-IP:8081
echo Find this PC's IP with:  ipconfig   (look for IPv4 Address)
pause
