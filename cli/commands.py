import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Web Security Testing Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Crawling depth")
    parser.add_argument("-o", "--output", default="report.pdf", help="Output report path")
    return parser.parse_args()