param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$Icon,
    [Parameter(Mandatory=$true)][string]$Shortcut
)
$ErrorActionPreference = 'Stop'
# Preserve all other PE resources, including the application's manifest.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class ElementsIcon {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr BeginUpdateResource(string file, bool deleteExisting);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UpdateResource(IntPtr handle, IntPtr type, IntPtr name,
        ushort language, byte[] data, uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool EndUpdateResource(IntPtr handle, bool discard);
    public static void Apply(string executable, string icon) {
        byte[] bytes=File.ReadAllBytes(icon);
        using(var input=new BinaryReader(new MemoryStream(bytes))) {
            if(input.ReadUInt16()!=0 || input.ReadUInt16()!=1)
                throw new InvalidDataException("Expected an ICO file");
            ushort count=input.ReadUInt16();
            if(count==0)throw new InvalidDataException("Empty ICO file");
            var handle=BeginUpdateResource(executable,false);
            if(handle==IntPtr.Zero)throw new Win32Exception();
            bool finished=false;
            try {
                using(var group=new MemoryStream())
                using(var writer=new BinaryWriter(group)) {
                    writer.Write((ushort)0);writer.Write((ushort)1);writer.Write(count);
                    for(ushort i=0;i<count;i++) {
                        input.BaseStream.Position=6+16*i;
                        byte[] entry=input.ReadBytes(12);
                        uint size=BitConverter.ToUInt32(entry,8), offset=input.ReadUInt32();
                        if(offset>bytes.Length || size>bytes.Length-offset)
                            throw new InvalidDataException("Invalid ICO image bounds");
                        byte[] image=new byte[size];Array.Copy(bytes,offset,image,0,size);
                        ushort id=(ushort)(600+i);
                        if(!UpdateResource(handle,(IntPtr)3,(IntPtr)id,0,image,size))
                            throw new Win32Exception();
                        writer.Write(entry);writer.Write(id);
                    }
                    byte[] directory=group.ToArray();
                    if(!UpdateResource(handle,(IntPtr)14,(IntPtr)1,0,directory,(uint)directory.Length))
                        throw new Win32Exception();
                }
                if(!EndUpdateResource(handle,false))throw new Win32Exception();
                finished=true;
            } finally {if(!finished)EndUpdateResource(handle,true);}
        }
    }
}
'@
[ElementsIcon]::Apply($Executable,$Icon)
$shell=New-Object -ComObject WScript.Shell
$link=$shell.CreateShortcut($Shortcut)
$link.TargetPath=$Executable
$link.WorkingDirectory=Split-Path -Parent $Executable
$link.IconLocation="$Icon,0"
$link.Description='Elements wallet'
$link.Save()
