"""
oui_lookup.py - MAC Address Vendor Lookup
Matches MAC prefixes to device manufacturers.
"""

# Common OUI Prefixes
VENDORS = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
    "00:16:CB": "Apple", "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple", "00:1C:B3": "Apple",
    "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:24:36": "Apple", "00:25:00": "Apple",
    "00:25:4B": "Apple", "00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple", "00:26:B0": "Apple",
    "10:40:F3": "Apple", "14:10:9F": "Apple", "14:99:E2": "Apple", "18:AF:61": "Apple", "18:F1:D8": "Apple",
    "3C:07:54": "Apple", "3C:D0:F8": "Apple", "40:30:04": "Apple", "44:4C:0C": "Apple", "48:43:7C": "Apple",
    "48:D7:05": "Apple", "58:55:CA": "Apple", "5C:96:9D": "Apple", "60:F8:1D": "Apple", "64:20:0C": "Apple",
    "00:00:F0": "Samsung", "00:07:AB": "Samsung", "00:0D:E6": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung",
    "00:15:B9": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung", "00:16:DB": "Samsung", "00:17:C9": "Samsung",
    "00:17:D5": "Samsung", "00:18:AF": "Samsung", "00:1A:11": "Samsung", "00:1B:98": "Samsung", "00:1C:43": "Samsung",
    "14:F4:2A": "Samsung", "1C:5A:3E": "Samsung", "24:4B:03": "Samsung", "24:F5:AA": "Samsung", "28:98:7B": "Samsung",
    "30:07:4D": "Samsung", "38:AA:3C": "Samsung", "40:0E:85": "Samsung", "44:4E:1A": "Samsung", "48:44:F7": "Samsung",
    "50:85:69": "Samsung", "5C:A3:9D": "Samsung", "60:6B:BD": "Samsung", "64:77:91": "Samsung", "70:05:14": "Samsung",
    "00:15:5D": "Microsoft", "00:50:F2": "Microsoft", "00:1D:D8": "Microsoft", "00:12:5A": "Microsoft",
    "00:04:F2": "Polycom", "00:04:13": "Cisco", "00:05:9A": "Cisco", "00:06:28": "Cisco", "00:06:53": "Cisco",
    "00:0C:30": "Cisco", "00:0D:BD": "Cisco", "00:0E:D7": "Cisco", "00:11:21": "Cisco", "00:12:01": "Cisco",
    "00:12:44": "Cisco", "00:12:7F": "Cisco", "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "00:1C:14": "VMware", "08:00:27": "VirtualBox", "00:16:3E": "Xen", "00:21:28": "Intel", "00:1E:65": "Intel",
    "D8:3B:BF": "Xiaomi", "00:9E:C8": "Xiaomi", "28:6C:07": "Xiaomi", "34:80:B3": "Xiaomi", "50:64:2B": "Xiaomi",
    "64:09:80": "Xiaomi", "8C:BE:BE": "Xiaomi", "94:87:E0": "Xiaomi", "AC:F7:F3": "Xiaomi", "F4:8A:5A": "Xiaomi",
    "00:0E:8E": "TP-Link", "00:14:78": "TP-Link", "00:1D:0F": "TP-Link", "00:23:69": "TP-Link", "14:CC:20": "TP-Link",
    "30:B5:C2": "TP-Link", "40:A5:EF": "TP-Link", "50:C7:BF": "TP-Link", "60:E3:27": "TP-Link", "BC:46:99": "TP-Link",
    "00:0C:E7": "Huawei", "00:0E:7B": "Huawei", "00:18:82": "Huawei", "00:1E:10": "Huawei", "08:19:A6": "Huawei",
    "28:31:66": "Huawei", "28:5F:DB": "Huawei", "30:87:30": "Huawei", "40:4D:8E": "Huawei", "54:89:98": "Huawei"
}

def get_vendor(mac):
    """Returns the manufacturer name for a given MAC address."""
    if not mac or ":" not in mac:
        return "Unknown"
    
    prefix = mac.upper()[:8]
    return VENDORS.get(prefix, "Generic/Other")
