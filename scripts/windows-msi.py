"""Write the WiX manifest for the staged Hydrat Windows x64 bundle."""

from pathlib import Path
import re
import sys
from uuid import UUID, uuid5
from xml.etree import ElementTree as xml

UPGRADE_CODE = UUID("593adb21-a956-4853-bb1b-4928c5d190ca")
NS = "http://schemas.microsoft.com/wix/2006/wi"


def guid(key):
    return str(uuid5(UPGRADE_CODE, key)).upper()


def add(parent, tag, **attrs):
    return xml.SubElement(parent, f"{{{NS}}}{tag}", attrs)


def component_id(path):
    return "cmp_" + guid(f"x64/{path.as_posix().lower()}").replace("-", "")


def add_payload(directory, feature, source):
    for entry in sorted(source.iterdir()):
        if entry.is_dir():
            child_dir = add(directory, "Directory",
                            Id="dir_" + guid(entry.as_posix().lower()).replace("-", ""), Name=entry.name)
            add_payload(child_dir, feature, entry)
        elif entry.is_file():
            key = component_id(entry)
            component = add(directory, "Component", Id=key, Guid=guid(key), Win64="yes")
            executable = entry == Path("Hydrat/Hydrat.exe")
            file = add(component, "File", Id="HydratExecutable" if executable else "file_" + key[4:],
                       Name=entry.name, Source=entry.as_posix(), KeyPath="yes")
            if executable:
                add(file, "Shortcut", Id="StartMenuHydrat", Directory="ProgramMenuFolder",
                    Name="Hydrat", Advertise="yes", WorkingDirectory="INSTALLFOLDER")
            add(feature, "ComponentRef", Id=key)


def main(version):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise SystemExit("MSI version must have three numeric parts")
    if any(value > limit for value, limit in zip(map(int, version.split(".")), (255, 255, 65535))):
        raise SystemExit("MSI version is outside the Windows Installer range")
    for name in ("Hydrat.exe", "wintun.dll", "tor/tor.exe",
                 "tor/pluggable_transports/lyrebird.exe", "geo/geoip.dat", "geo/geosite.dat", "icon.png"):
        if not (Path("Hydrat") / name).is_file():
            raise SystemExit(f"Missing bundle file {name}")

    xml.register_namespace("", NS)
    wix = xml.Element(f"{{{NS}}}Wix")
    product = add(wix, "Product", Id=guid("product/x64/" + version), Name="Hydrat",
                  Language="1033", Version=version, Manufacturer="Hydrat",
                  UpgradeCode=str(UPGRADE_CODE).upper())
    add(product, "Package", InstallerVersion="500", Compressed="yes", InstallScope="perMachine")
    add(product, "MediaTemplate", EmbedCab="yes")
    add(product, "MajorUpgrade", DowngradeErrorMessage="A newer version of Hydrat is already installed.")
    add(product, "Property", Id="ARPNOMODIFY", Value="1")
    add(product, "Property", Id="ARPCONTACT", Value="https://github.com/only-hydrat/hydrat")
    if Path("Hydrat/hydrat.ico").is_file():
        add(product, "Icon", Id="Hydrat.ico", SourceFile="Hydrat/hydrat.ico")
        add(product, "Property", Id="ARPPRODUCTICON", Value="Hydrat.ico")

    root = add(product, "Directory", Id="TARGETDIR", Name="SourceDir")
    program_files = add(root, "Directory", Id="ProgramFiles64Folder")
    install_dir = add(program_files, "Directory", Id="INSTALLFOLDER", Name="Hydrat")
    add(root, "Directory", Id="ProgramMenuFolder")
    feature = add(product, "Feature", Id="Hydrat", Title="Hydrat", Level="1")
    add_payload(install_dir, feature, Path("Hydrat"))
    xml.ElementTree(wix).write("Hydrat.wxs", encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    main(sys.argv[1])
