import csv
import random
import os
from urllib.parse import urlparse

# --- Feature Extraction Functions (same as feature_extraction.py) ---

def hostname_length(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return len(hostname)

def url_length(url):
    return len(url)

def fd_length(url):
    parsed = urlparse(url)
    path = parsed.path or "/"
    path = path.lstrip("/")
    if "/" in path:
        return len(path.split("/")[0])
    return len(path)

def get_counts(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    dot_count = hostname.count(".")
    hyphen_count = hostname.count("-")
    underscore_count = url.count("_")
    percent_count = url.count("%")
    query_count = len(parsed.query.split("&")) if parsed.query else 0
    slash_count = path.count("/")
    return [dot_count, hyphen_count, underscore_count, percent_count, query_count, slash_count]

def digit_count(url):
    return sum(c.isdigit() for c in url)

def letter_count(url):
    return sum(c.isalpha() for c in url)

def no_of_dir(url):
    parsed = urlparse(url)
    path = parsed.path or ""
    path = path.strip("/")
    return len(path.split("/")) if path else 0

def having_ip_address(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        return 1
    except:
        return 0

def extract_features(url):
    url_features = []
    url_features.append(hostname_length(url))
    url_features.append(url_length(url))
    url_features.append(fd_length(url))
    counts = get_counts(url)
    url_features.extend(counts)
    url_features.append(digit_count(url))
    url_features.append(letter_count(url))
    url_features.append(no_of_dir(url))
    url_features.append(having_ip_address(url))
    return url_features

# --- Generate URLs ---

# Benign (legitimate) URL patterns
benign_urls = [
    # Major websites
    "https://www.google.com/search?q=python",
    "https://www.facebook.com/profile?id=12345",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.wikipedia.org/wiki/Python_(programming_language)",
    "https://www.github.com/username/repository",
    "https://stackoverflow.com/questions/12345/python-list",
    "https://www.linkedin.com/in/username",
    "https://twitter.com/username/status/123456789",
    "https://www.instagram.com/p/ABC123/",
    "https://www.reddit.com/r/python/comments/12345/",
    "https://mail.google.com/mail/u/0/",
    "https://drive.google.com/file/d/ABC123/view",
    "https://docs.google.com/document/d/XYZ456/edit",
    "https://www.microsoft.com/en-us/software-download",
    "https://support.apple.com/en-us/HT201222",
    "https://www.adobe.com/products/photoshop.html",
    "https://www.oracle.com/java/technologies/",
    "https://www.ibm.com/products/db2",
    "https://www.cisco.com/c/en/us/products/",
    "https://www.dell.com/en-us/shop",
    "https://www.hp.com/us-en/printers.html",
    "https://www.samsung.com/us/televisions/",
    "https://www.netflix.com/browse",
    "https://www.spotify.com/us/premium/",
    "https://www.udemy.com/course/python-bootcamp/",
    "https://www.coursera.org/learn/python",
    "https://www.w3schools.com/python/default.asp",
    "https://www.tutorialspoint.com/python/index.htm",
    "https://realpython.com/python-tutorials/",
    "https://pypi.org/project/requests/",
    "https://flask.palletsprojects.com/en/2.3.x/",
    "https://docs.djangoproject.com/en/4.2/",
    "https://www.postgresql.org/docs/current/",
    "https://dev.mysql.com/doc/refman/8.0/en/",
    "https://www.mongodb.com/docs/manual/",
    "https://nodejs.org/en/docs/",
    "https://react.dev/learn",
    "https://angular.io/docs",
    "https://vuejs.org/guide/introduction.html",
    "https://www.docker.com/products/docker-desktop/",
    "https://kubernetes.io/docs/home/",
    "https://aws.amazon.com/documentation/",
    "https://cloud.google.com/docs",
    "https://azure.microsoft.com/en-us/documentation/",
    "https://www.office.com/login",
    "https://outlook.live.com/mail/0/",
    "https://onedrive.live.com/",
    "https://teams.microsoft.com/v2/",
    "https://slack.com/signin",
    "https://zoom.us/meeting",
    "https://discord.com/channels/123456/789012",
    "https://www.whatsapp.com/download",
    "https://telegram.org/dl/desktop",
    "https://signal.org/download/",
    "https://www.vscode.dev/",
    "https://code.visualstudio.com/download",
    "https://www.jetbrains.com/pycharm/download/",
    "https://atom.io/",
    "https://www.sublimetext.com/3",
    "https://notepad-plus-plus.org/downloads/",
    "https://www.7-zip.org/download.html",
    "https://www.vmware.com/products/workstation-pro.html",
    "https://www.virtualbox.org/wiki/Downloads",
    "https://www.ubuntu.com/download/desktop",
    "https://www.kali.org/get-kali/",
    "https://www.centos.org/download/",
    "https://getfedora.org/",
    "https://www.debian.org/distrib/",
    "https://archlinux.org/download/",
    "https://www.npmjs.com/package/express",
    "https://getbootstrap.com/docs/5.3/getting-started/introduction/",
    "https://jquery.com/download/",
    "https://fontawesome.com/icons",
    "https://cdnjs.com/libraries",
    "https://news.ycombinator.com/",
    "https://medium.com/tag/python",
    "https://dev.to/",
    "https://www.freecodecamp.org/news/",
    "https://www.codecademy.com/learn/learn-python-3",
    "https://www.khanacademy.org/computing/computer-programming",
    "https://www.udacity.com/course/intro-to-machine-learning--ud120",
    "https://www.edx.org/course/introduction-to-computer-science",
    "https://www.pluralsight.com/courses/python-fundamentals",
    "https://www.datacamp.com/courses/intro-to-python-for-data-science",
    "https://www.kaggle.com/learn/python",
    "https://leetcode.com/problemset/all/",
    "https://www.hackerrank.com/domains/python",
    "https://www.codechef.com/problems/school",
    "https://www.topcoder.com/challenges",
    "https://atcoder.jp/contests",
    "https://codeforces.com/problemset",
    "https://www.spoj.com/problems/classical/",
    "https://projecteuler.net/archives",
    "https://exercism.org/tracks/python",
    "https://www.codewars.com/dashboard",
    "https://www.hackerearth.com/practice/",
    "https://www.geeksforgeeks.org/python-programming-language/",
    "https://www.programiz.com/python-programming",
    "https://www.javatpoint.com/python-tutorial",
    "https://www.guru99.com/python-tutorials.html",
    "https://www.learnpython.org/",
    "https://pythonbasics.org/",
    "https://automatetheboringstuff.com/",
    "https://inventwithpython.com/",
    "https://www.python.org/downloads/",
    "https://docs.python.org/3/",
    "https://peps.python.org/pep-0008/",
    "https://pandas.pydata.org/docs/",
    "https://numpy.org/doc/stable/",
    "https://matplotlib.org/stable/tutorials/index.html",
    "https://scikit-learn.org/stable/user_guide.html",
    "https://www.tensorflow.org/tutorials",
    "https://pytorch.org/tutorials/",
    "https://keras.io/guides/",
    "https://seaborn.pydata.org/tutorial.html",
    "https://plotly.com/python/",
    "https://www.streamlit.io/gallery",
    "https://gradio.app/demos/",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://www.django-rest-framework.org/",
    "https://www.fullstackpython.com/",
    "https://awesome-python.com/",
    "https://github.com/vinta/awesome-python",
    "https://github.com/jakevdp/PythonDataScienceHandbook",
    "https://github.com/ageron/handson-ml2",
    "https://github.com/rasbt/python-machine-learning-book-3rd-edition",
    "https://github.com/joelgrus/data-science-from-scratch",
    "https://github.com/jupyter/jupyter",
    "https://github.com/ipython/ipython",
    "https://github.com/numpy/numpy",
    "https://github.com/pandas-dev/pandas",
    "https://github.com/scikit-learn/scikit-learn",
    "https://github.com/pallets/flask",
    "https://github.com/django/django",
    "https://github.com/psf/requests",
    "https://github.com/matplotlib/matplotlib",
    "https://github.com/encode/httpx",
    "https://github.com/tiangolo/fastapi",
    "https://github.com/Textualize/rich",
    "https://github.com/pytest-dev/pytest",
    "https://github.com/python/cpython",
    "https://github.com/microsoft/vscode",
    "https://github.com/atom/atom",
    "https://www.bbc.com/news/technology",
    "https://www.cnn.com/world",
    "https://www.nytimes.com/international/",
    "https://www.theguardian.com/international",
    "https://www.reuters.com/world/",
    "https://www.aljazeera.com/",
    "https://www.economist.com/",
    "https://www.wsj.com/",
    "https://www.bloomberg.com/",
    "https://www.forbes.com/",
    "https://www.techcrunch.com/",
    "https://www.wired.com/",
    "https://www.theverge.com/",
    "https://arstechnica.com/",
    "https://www.zdnet.com/",
    "https://www.cnet.com/",
    "https://www.engadget.com/",
    "https://www.pcmag.com/",
    "https://www.tomshardware.com/",
    "https://www.anandtech.com/",
    "https://www.howtogeek.com/",
    "https://lifehacker.com/",
    "https://www.makeuseof.com/",
    "https://www.techradar.com/",
    "https://www.digitaltrends.com/",
    "https://www.gartner.com/en",
    "https://www.gartner.com/en/documents",
    "https://www.idc.com/",
    "https://www.statista.com/statistics/",
    "https://www.grandviewresearch.com/industry",
    "https://www.marketsandmarkets.com/",
]

# Phishing URL patterns
phishing_urls = [
    "http://192.168.1.100/login",
    "http://secure-bank-login.xyz/verify",
    "http://paypal-account-recovery.com/login",
    "http://free-iphone-winner.click/claim",
    "http://netflix-update.info/verify",
    "http://amazon-discount.buzz/redeem",
    "http://facebook-security-alert.work",
    "http://apple-id-verify.tk/account",
    "http://google-drive-share.xyz/file",
    "http://instagram-followers.top/free",
    "http://microsoft-support-alert.com/help",
    "http://whatsapp-verify.info/login",
    "http://linkedin-connection.work/profile",
    "http://twitter-verification.click/confirm",
    "http://steam-community-gift.com/claim",
    "http://bit.ly/3fG7k2L",
    "http://tinyurl.com/yzx123",
    "http://bit.ly/2Mn9xR",
    "http://rebrand.ly/abc123",
    "http://ow.ly/XYZ123",
    "http://is.gd/abc123",
    "http://buff.ly/3aBcDe",
    "http://tiny.cc/xyz123",
    "http://shorturl.at/abcDE",
    "http://free-vpn-download.top/install",
    "http://covid19-relief-fund.click/donate",
    "http://lottery-winner-2024.xyz/claim",
    "http://bank-of-america-secure.com/login",
    "http://chase-bank-alert.work/verify",
    "http://wells-fargo-update.info/account",
    "http://citibank-security.com/confirm",
    "http://hsbc-account-verify.top/login",
    "http://barclays-secure.click/verify",
    "http://fedex-delivery-update.xyz/track",
    "http://dhl-package-alert.com/shipping",
    "http://usps-delivery.info/confirm",
    "http://ups-package-tracking.work/update",
    "http://amazon-order-confirm.info/receipt",
    "http://ebay-auction-winner.click/claim",
    "http://aliexpress-order.top/refund",
    "http://walmart-gift-card.xyz/redeem",
    "http://target-promotion.click/coupon",
    "http://best-buy-reward.com/points",
    "http://costco-member-update.info/account",
    "http://irs-tax-refund.click/file",
    "http://tax-refund-2024.work/deposit",
    "http://social-security-benefits.top/update",
    "http://medicare-card-renew.info/confirm",
    "http://unemployment-benefits.click/claim",
    "http://student-loan-forgiveness.work/apply",
    "http://paypal-payment-confirm.com/receipt",
    "http://stripe-billing-update.info/card",
    "http://square-payment-alert.work/verify",
    "http://venmo-deposit-confirm.click/claim",
    "http://cashapp-account-verify.top/login",
    "http://google-account-recovery.xyz/password",
    "http://icloud-storage-upgrade.info/billing",
    "http://dropbox-storage-alert.com/upgrade",
    "http://onedrive-account-verify.work/login",
    "http://adobe-license-expiry.click/renew",
    "http://spotify-premium-offer.top/claim",
    "http://netflix-account-suspended.xyz/reactivate",
    "http://hulu-billing-update.info/payment",
    "http://disney-plus-offer.click/free",
    "http://twitch-prime-loot.work/claim",
    "http://roblox-free-robux.com/redeem",
    "http://minecraft-free-account.xyz/claim",
    "http://fortnite-v-bucks.top/free",
    "http://pubg-uc-gift.click/redeem",
    "http://free-gift-cards-generator.work/claim",
    "http://www.paypal.com@evil.com/login",
    "http://www.facebook.com@malicious.net",
    "http://www.google.com@phish-site.xyz",
    "http://www.amazon.com@scam-page.top",
    "http://192.168.0.50/admin",
    "http://10.0.0.1/router-config",
    "http://172.16.0.100/panel",
    "http://192.168.1.1/cgi-bin/login",
    "http://203.0.113.50/wp-admin",
    "http://198.51.100.25/administrator",
    "http://register-your-free-iphone-now.click/claim",
    "http://urgent-security-alert-your-account-has-been-compromised.work",
    "http://win-free-bitcoin-cryptocurrency-giveaway.top/claim",
    "http://verify-your-identity-to-unlock-account-now.info/login",
    "http://click-here-to-claim-your-free-500-dollars.xyz/reward",
    "http://update-payment-method-to-prevent-service-interruption.com/billing",
    "http://confirm-your-email-address-to-keep-receiving-updates.work/verify",
    "http://reset-your-password-immediately-unauthorized-access-detected.info/reset",
    "http://download-free-antivirus-protection-now.click/install",
    "http://activate-windows-10-pro-free-license-key.top/activate",
    "http://watch-netflix-for-free-lifetime-access.xyz/signup",
    "http://get-free-spotify-premium-account-generator.com/claim",
    "http://claim-your-free-amazon-gift-card-500-dollars.work/redeem",
    "http://your-package-is-on-hold-please-confirm-delivery.info/tracking",
    "http://court-notice-appearance-required-failure-to-appear.click/case",
    "http://unusual-login-attempt-detected-from-your-account.work/verify",
    "http://your-computer-has-been-infected-with-virus-call-now.top/support",
    "http://congratulations-you-have-been-selected-as-our-winner.xyz/claim",
    "http://job-offer-from-top-company-sign-up-today.click/apply",
    "http://free-cruise-vacation-for-two-claim-now.work/booking",
    "http://www.paypal-secure-center.com",
    "http://www.facebook-login-helper.com",
    "http://www.google-account-verify.info",
    "http://www.amazon-order-support.xyz",
    "http://www.netflix-billing-help.com",
    "http://www.instagram-verify-account.work",
    "http://www.linkedin-connection-request.top",
    "http://www.twitter-account-security.com",
    "http://www.microsoft-license-activation.info",
    "http://www.adobe-subscription-renewal.click",
    "http://www.dropbox-account-upgrade.work",
    "http://www.icloud-storage-alert.com",
    "http://www.spotify-premium-free.xyz",
    "http://www.whatsapp-web-verify.info",
    "http://www.telegram-channel-verify.com",
    "http://login.update-paypal-account.com",
    "http://secure.verify-facebook-identity.com",
    "http://account.apple-id-recovery.com",
    "http://billing.amazon-order-confirm.com",
    "http://support.microsoft-security-alert.com",
    "http://help.netflix-account-recovery.com",
    "http://verify.google-workspace-account.com",
    "http://secure.bank-login-authentication.com",
    "http://update.credit-card-verification.com",
    "http://reset.email-password-confirmation.com",
    "http://confirm.shipping-address-verification.com",
    "http://claim.prize-money-winner-notification.com",
    "http://track.package-delivery-confirmation.com",
    "http://view.invoice-payment-receipt.com",
    "http://download.file-sharing-access.com",
    "http://activate.subscription-service-renewal.com",
    "http://secure-login.bank-of-america.com@evil.com",
    "http://www.google.com.evil-phishing-site.xyz",
    "http://login.facebook.com.secure-login.info",
    "http://www.amazon.com.account-verify.work",
    "http://paypal.com@malicious-redirect.top",
    "http://instagram.com.login-verify.click",
    "http://twitter.com@account-security.xyz",
    "http://linkedin.com.connection-request.work",
    "http://github.com.login-verify.info",
    "http://reddit.com.security-alert.top",
    "http://stackoverflow.com.account-verify.click",
    "http://192.168.0.1/manager/html",
    "http://10.10.10.1/phpMyAdmin",
    "http://172.16.0.1/phpmyadmin",
    "http://192.168.1.254/cgi-bin/status",
    "http://203.0.113.100/shell",
    "http://198.51.100.50/backdoor",
    "http://demo.hackthebox.com",
    "http://test.pentesterlab.com",
    "http://vulnerable.web.app/login",
    "http://challenge.ctf.com/flag",
]

# Generate more URLs with variations
more_benign = []
for i in range(1, 800):
    template = random.choice([
        f"https://www.example{i}.com/page{i}/article",
        f"https://blog.domain{i}.org/post/{i}",
        f"https://sub{i}.website{i}.net/docs/{i}",
        f"https://docs{i}.service{i}.io/api/v{i}/endpoint",
        f"https://help{i}.platform{i}.com/article/{i}/details",
        f"https://www.random{i}.org/items/{i}",
        f"https://portal{i}.app{i}.com/dashboard",
        f"https://files{i}.storage{i}.cloud/file/{i}",
        f"https://profile{i}.social{i}.net/user/{i}",
        f"https://status{i}.monitor{i}.io/health",
        f"https://static{i}.cdn{i}.net/assets/{i}/style.css",
        f"https://api{i}.service{i}.com/v2/{i}/data",
        f"https://admin{i}.system{i}.io/config/{i}",
        f"https://logs{i}.monitor{i}.com/events/{i}",
        f"https://cache{i}.proxy{i}.net/content/{i}",
    ])
    more_benign.append(template)

more_phishing = []
for i in range(1, 900):
    template = random.choice([
        f"http://login-secure{i}.xyz/verify",
        f"http://account-alert{i}.click/confirm",
        f"http://free-gift{i}.top/claim",
        f"http://update-billing{i}.work/payment",
        f"http://security-verify{i}.info/login",
        f"http://urgent-alert{i}.buzz/reset",
        f"http://confirm-identity{i}.loan/verify",
        f"http://reward-claim{i}.win/redeem",
        f"http://package-delivery{i}.zip/track",
        f"http://account-recovery{i}.site/restore",
        f"http://promo{i}.xyz/discount{i}",
        f"http://verify{i}.click/secure{i}",
        f"http://secure{i}.top/login{i}",
        f"http://update{i}.work/payment{i}",
        f"http://claim{i}.info/reward{i}",
        f"http://alert{i}.buzz/account{i}",
        f"http://reset{i}.loan/password{i}",
        f"http://track{i}.win/delivery{i}",
        f"http://free{i}.site/gift{i}",
        f"http://support{i}.zip/help{i}",
        f"http://192.168.{i%255}.{i%254}/admin",
        f"http://10.{i%255}.{i%255}.{i%254}/login",
        f"http://172.{(i%32)+16}.{i%255}.{i%254}/panel",
        f"http://203.0.113.{i%254}/shell",
        f"http://198.51.100.{i%254}/backdoor",
    ])
    more_phishing.append(template)

# Combine all URLs
all_benign = benign_urls + more_benign
all_phishing = phishing_urls + more_phishing

# Shuffle both lists
random.shuffle(all_benign)
random.shuffle(all_phishing)

# Target: 1000 benign + 1000 phishing = 2000 rows
benign_selected = all_benign[:1000]
phishing_selected = all_phishing[:1000]

# --- Generate CSV ---
header = [
    "url_len", "host_len", "fd_len", "dot_count", "hyphen_count",
    "underscore_count", "percent_count", "query_count", "slash_count",
    "digit_count", "letter_count", "dir_count", "has_ip", "label"
]

# Create dataset directory
dataset_dir = os.path.join(os.path.dirname(__file__), "dataset")
os.makedirs(dataset_dir, exist_ok=True)

csv_path = os.path.join(dataset_dir, "phishing_dataset.csv")

with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    
    # Write benign URLs (label = 0)
    for url in benign_selected:
        features = extract_features(url)
        row = features + [0]  # 0 = benign
        writer.writerow(row)
    
    # Write phishing URLs (label = 1)
    for url in phishing_selected:
        features = extract_features(url)
        row = features + [1]  # 1 = phishing
        writer.writerow(row)

print(f"✅ Dataset generated successfully!")
print(f"📁 Location: {csv_path}")
print(f"📊 Total rows: {len(benign_selected) + len(phishing_selected)} ({len(benign_selected)} benign + {len(phishing_selected)} phishing)")
print(f"🔢 Features: {len(header)} columns")