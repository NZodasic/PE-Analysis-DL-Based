import os
import pefile
import hashlib
import json
import csv
from collections import defaultdict


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_pe_features(pe_path: str):
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        print(f"[!] Failed to parse {pe_path}: {e}")
        return None, None

    # Unique file id
    file_hash = sha256_file(pe_path)

    # Tabular features
    features = {
        "file": os.path.basename(pe_path),
        "sha256": file_hash,
    }

    # --- Header features ---
    oh = pe.OPTIONAL_HEADER
    features.update({
        "Machine": pe.FILE_HEADER.Machine,
        "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
        "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
        "Characteristics": pe.FILE_HEADER.Characteristics,
        "AddressOfEntryPoint": oh.AddressOfEntryPoint,
        "ImageBase": oh.ImageBase,
        "SectionAlignment": oh.SectionAlignment,
        "SizeOfImage": oh.SizeOfImage,
        "Subsystem": oh.Subsystem,
    })

    # --- Section features ---
    section_names = []
    section_entropies = []
    section_sizes = []
    for s in pe.sections:
        name = s.Name.decode(errors="ignore").rstrip("\x00")
        section_names.append(name)
        section_entropies.append(s.get_entropy())
        section_sizes.append(s.SizeOfRawData)

    for name in section_names:
        features[f"Section_{name}"] = 1
    features["SectionCount"] = len(section_names)
    features["SectionMeanEntropy"] = sum(section_entropies) / len(section_entropies) if section_entropies else 0
    features["SectionTotalSize"] = sum(section_sizes)

    # --- Imports ---
    dlls, apis = set(), set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            dlls.add(dll_name)
            for imp in entry.imports:
                if imp.name:
                    apis.add(imp.name.decode(errors="ignore"))

    for dll in dlls:
        features[f"DLL_{dll}"] = 1
    for api in list(apis)[:100]:  # limit top 100 apis per file to keep CSV manageable
        features[f"API_{api}"] = 1

    # --- Exports ---
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        features["ExportCount"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    else:
        features["ExportCount"] = 0

    # --- Resources ---
    features["HasResources"] = int(hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"))

    # --- Certificate ---
    dir_security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    features["HasCertificate"] = int(dir_security.VirtualAddress != 0)

    # --- Overlay size ---
    overlay_offset = pe.get_overlay_data_start_offset()
    features["OverlaySize"] = os.path.getsize(pe_path) - overlay_offset if overlay_offset else 0

    # Metadata (for reversibility)
    metadata = {
        "file": os.path.basename(pe_path),
        "sha256": file_hash,
        "headers": {
            "FILE_HEADER": pe.FILE_HEADER.dump_dict(),
            "OPTIONAL_HEADER": pe.OPTIONAL_HEADER.dump_dict(),
        },
        "sections": [s.dump_dict() for s in pe.sections],
        "imports": {dll: [imp.name.decode(errors="ignore") if imp.name else None
                           for imp in entry.imports]
                    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
                    for dll in [entry.dll.decode(errors="ignore")]},
        "exports": [sym.name.decode(errors="ignore") if sym.name else None
                     for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])],
        "resources": hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"),
        "certificate_present": features["HasCertificate"],
        "overlay_size": features["OverlaySize"],
    }

    return features, metadata


def process_directory(input_dir: str, output_csv: str, metadata_dir: str):
    os.makedirs(metadata_dir, exist_ok=True)

    all_features = []
    for root, _, files in os.walk(input_dir):
        for f in files:
            if not f.lower().endswith((".exe", ".dll")):
                continue
            path = os.path.join(root, f)
            features, metadata = extract_pe_features(path)
            if features is None:
                continue
            all_features.append(features)
            with open(os.path.join(metadata_dir, f"{features['sha256']}.json"), "w") as jf:
                json.dump(metadata, jf, indent=2)

    # Write CSV
    if all_features:
        fieldnames = sorted({k for feat in all_features for k in feat.keys()})
        with open(output_csv, "w", newline="") as cf:
            writer = csv.DictWriter(cf, fieldnames=fieldnames)
            writer.writeheader()
            for feat in all_features:
                writer.writerow(feat)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract reversible PE features into CSV + metadata JSON")
    parser.add_argument("input_dir", help="Directory containing PE files")
    parser.add_argument("--out_csv", default="features.csv", help="Output CSV file")
    parser.add_argument("--meta_dir", default="metadata", help="Directory to save metadata JSON")
    args = parser.parse_args()

    process_directory(args.input_dir, args.out_csv, args.meta_dir)
