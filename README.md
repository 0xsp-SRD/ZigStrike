# ZigStrike

<img src="https://github.com/0xsp-SRD/0xsp.com/blob/main/images/3e209efa-4228-4119-b9dc-590a0aa183cb.jpeg" width=50% height=50% align="center">

ZigStrike is a robust shellcode loader developed in Zig, offering a variety of injection techniques and anti-sandbox features. It leverages compile-time capabilities for efficient shellcode allocation, demonstrating proven success in [bypassing advanced security solutions](https://kpmg.com/nl/en/home/insights/2024/12/zig-strike-the-ultimate-toolkit-for-payload-creation-and-evasion.html). ZigStrike includes a custom payload builder, allowing users to easily select and construct payloads via a web application built with Python.


### Features ( release 2.0 )

- **Multiple Injection Techniques**:
  - Local Thread 
  - Local Mapping
  - Remote Mapping
  - Remote Thread hijacking
  - EarlyCascade injection 

- **Anti-Sandbox Protection**:
  - TPM Presence Check.
  - Domain Join Check.
  - Run-Time protection.

- **Output Formats**:
  - XLL (Excel Add-in)
  - DLL
  - CPL

- **Advanced Features**:
  - Shellcode advanced allocation. 
  - Payload Runtime protection; preventing emulation and sandbox dynamic anaylsis.  
  - Bypass common detection rules.
* **Front-end enhancement**:
  - Added new page to view generated payloads. 
  - Detailed information for each created payload. 
  - Fix flask issue to support uploading large shellcode. 

## Prerequisites

- Zig 0.14.0
- Ubuntu / Debian 
- Python 3.x (for the web interface)
- Flask

## Article 

The following article is released for ZigStrike highlighting the features and showcase the capabilities to bypass advanced security solutions. 

https://kpmg.com/nl/en/home/insights/2024/12/zig-strike-the-ultimate-toolkit-for-payload-creation-and-evasion.html


## Installation 

```
git clone https://github.com/0xsp-SRD/ZigStrike/
cd ZigStrike/App/ 
python3 App.py 
```

## Docker 
you have problem running it? you can run it via docker. 

```
git clone https://github.com/0xsp-SRD/ZigStrike/
cd ZigStrike/

# Build the image
docker build -t zigstrike .

# Run the container
docker run -p 5002:5002 zigstrike

```
## Pending feature 
* [ 🔺 ] Direct Syscalls. 

## Reporting Bugs or Issues

If you encounter any bugs or issues while using ZigStrike, please report them by opening an issue in the [Issues](https://github.com/0xsp-SRD/ZigStrike/issues) section of this repository. When reporting, please include detailed information about the problem, steps to reproduce it, and any relevant logs or screenshots. This will help us address the issue more efficiently.


## Support and Donations
If you find ZigStrike useful and would like to support its development, consider buying me a coffee! Your support is greatly appreciated and helps maintain and improve the project. You can make a donation through Buy Me a Coffee.https://buymeacoffee.com/zux0x3a
