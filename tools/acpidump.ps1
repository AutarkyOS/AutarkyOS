# Dump this machine's ACPI tables, so the kernel's AML interpreter can be run
# against real firmware without rebooting into it.
#
# **One table is not a machine.** The GF63 has a DSDT and fourteen SSDTs, and
# the DSDT is the one that does *not* hold the discrete GPU's power control --
# `Opt2Tabl` does. A session spent reading only the DSDT concluded the firmware
# had no `_ON` method for the GPU, which was true of that table and false of
# the machine.
#
# `GetSystemFirmwareTable` cannot enumerate tables that share a signature, and
# fourteen of these are all `SSDT`. The registry can: Windows publishes every
# table it parsed under HKLM\HARDWARE\ACPI, one subtree per table, with the raw
# bytes in a value named 00000000.
#
#     .\tools\acpidump.ps1                 # -> out\acpi\*.aml
#     .\tools\acpidump.ps1 -Out D:\somewhere
#
# The dumps are this laptop's firmware and belong to its vendor, so `out\` is
# where they go and they are not committed -- the same rule that keeps a WAD
# and a model checkpoint out of this repository.
#
# To use one, put it on the NVMe test image and load it in the shell. `+` adds
# a table to the namespace already standing, which is how the whole set is
# assembled:
#
#     .\tools\venv\Scripts\python.exe tools\mkfat.py .qemu\nvme.img `
#         out\acpi\DSDT.aml out\acpi\SSD4.aml out\acpi\SSD6.aml out\acpi\SSDD.aml
#     fat get /DSDT.AML /tmp/d   &&  acpi load /tmp/d
#     fat get /SSDD.AML /tmp/sd  &&  acpi load /tmp/sd +

param([string]$Out = "out\acpi")

$root = "HKLM:\HARDWARE\ACPI"
if (-not (Test-Path $root)) {
    Write-Error "no $root -- this needs Windows, which is where the firmware was parsed"
    exit 1
}

New-Item -ItemType Directory -Force $Out | Out-Null
$wrote = 0

foreach ($k in Get-ChildItem $root) {
    $name = $k.PSChildName
    # FACS, FADT and RSDT are not AML and there is nothing here to walk.
    if ($name -notmatch '^(DSDT|SSD)') { continue }

    $leaf = Get-ChildItem $k.PSPath -Recurse |
        Where-Object { $_.Property -contains "00000000" } |
        Select-Object -First 1
    if ($null -eq $leaf) {
        Write-Output ("{0,-6} no table data under it" -f $name)
        continue
    }

    $bytes = (Get-ItemProperty -Path $leaf.PSPath -Name "00000000")."00000000"
    if ($bytes.Length -lt 36) {
        Write-Output ("{0,-6} {1} bytes, too short to be a table" -f $name, $bytes.Length)
        continue
    }

    $sig = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
    # The OEM table id is what tells fourteen SSDTs apart, and it is the only
    # thing that does: `Opt2Tabl` against `CpuSsdt` against `SocGpe`.
    $tid = [System.Text.Encoding]::ASCII.GetString($bytes, 16, 8).Trim()
    $declared = [BitConverter]::ToUInt32($bytes, 4)
    $path = Join-Path $Out "$name.aml"
    [System.IO.File]::WriteAllBytes($path, $bytes)
    $wrote++

    # The length field disagreeing with the file is how a truncated dump looks,
    # and a truncated table walks perfectly until it stops mid-term.
    $note = if ($declared -ne $bytes.Length) { "  LENGTH FIELD SAYS $declared" } else { "" }
    Write-Output ("{0,-6} {1}  {2,-10} {3,8} bytes{4}" -f $name, $sig, $tid, $bytes.Length, $note)
}

Write-Output ""
Write-Output "$wrote table(s) -> $Out"
