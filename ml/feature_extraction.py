import re
import ipaddress
from urllib.parse import urlparse

def hostname_length(url):
    """Extract hostname length from URL"""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return len(hostname)

def url_length(url):
    """Extract total URL length"""
    return len(url)

def fd_length(url):
    """Extract the length of the first directory in the path"""
    parsed = urlparse(url)
    path = parsed.path or "/"
    # Remove leading slash and get first directory
    path = path.lstrip("/")
    if "/" in path:
        return len(path.split("/")[0])
    return len(path)

def get_counts(url):
    """Extract count-based features"""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    
    # Count of dots in hostname (subdomains)
    dot_count = hostname.count(".")
    
    # Count of hyphens in hostname
    hyphen_count = hostname.count("-")
    
    # Count of underscores in URL
    underscore_count = url.count("_")
    
    # Count of percent signs (URL encoded characters)
    percent_count = url.count("%")
    
    # Count of query parameters
    query_count = len(parsed.query.split("&")) if parsed.query else 0
    
    # Count of slashes in path
    slash_count = path.count("/")
    
    return [dot_count, hyphen_count, underscore_count, percent_count, query_count, slash_count]

def digit_count(url):
    """Count digits in URL"""
    return sum(c.isdigit() for c in url)

def letter_count(url):
    """Count letters in URL"""
    return sum(c.isalpha() for c in url)

def no_of_dir(url):
    """Count number of directories in the URL path"""
    parsed = urlparse(url)
    path = parsed.path or ""
    # Remove leading and trailing slashes, then count
    path = path.strip("/")
    return len(path.split("/")) if path else 0

def having_ip_address(url):
    """Check if the URL contains an IP address"""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname)
        return 1
    except:
        return 0

def extract_features(url):
    """
    Extract all features from a URL.
    Returns a list of numerical features.
    """
    url_features = []
    
    # 1. hostname length
    url_features.append(hostname_length(url))
    
    # 2. url length (total)
    url_features.append(url_length(url))
    
    # 3. first directory length
    url_features.append(fd_length(url))
    
    # 4. counts: [dot_count, hyphen_count, underscore_count, percent_count, query_count, slash_count]
    counts = get_counts(url)
    url_features.extend(counts)
    
    # 5. digit count
    url_features.append(digit_count(url))
    
    # 6. letter count
    url_features.append(letter_count(url))
    
    # 7. number of directories
    url_features.append(no_of_dir(url))
    
    # 8. has IP address (1 or 0)
    url_features.append(having_ip_address(url))
    
    return url_features


# === Utility function to process CSV lines from dataset ===
def parse_dataset_row(row):
    """Parse a dataset row that has comma-separated features + label.
    Format: url_len,host_len,fd_len,dot_count,hyphen_count,underscore_count,
            percent_count,query_count,slash_count,digit_count,letter_count,
            dir_count,has_ip,label
    """
    values = row.strip().split(",")
    features = [float(v) for v in values[:-1]]
    label = int(values[-1])
    return features, label