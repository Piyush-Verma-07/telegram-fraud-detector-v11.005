# ----------------------------
# DATASET CREATION SCRIPT
# ----------------------------

import pandas as pd

# This will store all URLs with labels
dataset = []

print("Dataset script started...")




# ----------------------------
# LOAD OPENPHISH DATA (PHISHING)
# ----------------------------

import os

# Get correct path of project folder
base_dir = os.path.dirname(os.path.abspath(__file__))

# Build path to openphish file
openphish_path = os.path.join(base_dir, "data", "openphish.txt")

try:
    with open(openphish_path, "r") as file:
        for line in file:
            url = line.strip()

            if url:
                dataset.append((url, 1))  # phishing label

    print("OpenPhish data loaded:", len(dataset))

except Exception as e:
    print("Error loading OpenPhish:", e)





# ----------------------------
# LOAD URLHAUS DATA (FILTERED CLEAN)
# ----------------------------

import re  # import at top level (safe)

urlhaus_path = os.path.join(base_dir, "data", "urlhaus.csv")

try:
    count_before = len(dataset)

    with open(urlhaus_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:

            # Skip comment lines
            if line.startswith("#"):
                continue

            parts = line.split(",")

            if len(parts) > 2:
                url = parts[2].strip().strip('"')

                # Process only valid URLs
                if url.startswith("http"):

                    # Skip IP-based URLs
                    ip_pattern = r'^http[s]?://\d+\.\d+\.\d+\.\d+'
                    if re.match(ip_pattern, url):
                        continue

                    dataset.append((url, 1))

    count_after = len(dataset)

    print("URLHaus data loaded:", count_after - count_before)

except Exception as e:
    print("Error loading URLHaus:", e)





# ----------------------------
# LOAD TRANCO DATA (SAFE URLs)
# ----------------------------

# Update filename if needed (VERY IMPORTANT)
tranco_path = os.path.join(base_dir, "data", "tranco_9W772.csv")

try:
    tranco_df = pd.read_csv(
        tranco_path,
        header=None,
        names=["rank", "domain"]
    )

    count_before = len(dataset)

    # Take top 3000 safe domains (you can increase later)
    for domain in tranco_df["domain"].head(3000):

        if isinstance(domain, str) and domain.strip():
            url = "https://" + domain.strip()
            dataset.append((url, 0))  # label 0 = safe

    count_after = len(dataset)

    print("Tranco safe data loaded:", count_after - count_before)

except Exception as e:
    print("Error loading Tranco:", e)





# ----------------------------
# ADD REALISTIC SAFE URLs (IMPORTANT)
# ----------------------------

realistic_safe = [
    "https://amazon.com/login/help",
    "https://google.com/account/security",
    "https://facebook.com/settings/security",
    "https://github.com/login",
    "https://microsoft.com/en-us/security/update",
    "https://linkedin.com/in/user-profile",
    "https://stackoverflow.com/questions/12345",
    "https://paypal.com/us/home",
    "https://bankofamerica.com/login",
    "https://support.apple.com/account"
    "https://music.youtube.com/watch?v=J0rEeO3HFv8&list=RDCLAK5uy_lFuh0seSkGQjEEqrmTk7hs2OCMvx86nSo",
    "https://www.youtube.com/feed/history",
    "https://en.wikipedia.org/wiki/Uttar_Pradesh",
    "https://pay.google.com/intl/en_us/about/",
    "https://www.iplt20.com/matches/fixtures",
    "https://aws.amazon.com/contact-us/?nc2=h_ut_cu",
    "https://signin.aws.amazon.com/signup?request_type=register",
    "https://www.amazon.in/dp/B0FN7RN9TH?_encoding=UTF8&ref_=cct_cg_Budget_3a1"
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html",
    "https://support.google.com/accounts/answer/185833",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
    "https://stripe.com/docs/payments",
    "https://dashboard.stripe.com/login",
    "https://accounts.google.com/o/oauth2/auth",
    "https://myaccount.google.com/privacy",
]

count_before = len(dataset)

for url in realistic_safe:
    dataset.append((url, 0))  # safe

count_after = len(dataset)

print("Realistic safe URLs added:", count_after - count_before)





# ----------------------------
# ADD NEAR-PHISHING SAFE URLs (IMPORTANT)
# ----------------------------

advanced_safe = [
    "https://accounts.google.com/ServiceLogin",
    "https://secure.paytm.com/login",
    "https://signin.amazon.in/ap/signin",
    "https://login.microsoftonline.com/",
    "https://paypal.com/signin",
    "https://netbanking.hdfcbank.com/netbanking/"
]

count_before = len(dataset)

for url in advanced_safe:
    dataset.append((url, 0))  # label 0 = safe

count_after = len(dataset)

print("Advanced safe URLs added:", count_after - count_before)




# ----------------------------
# FINAL DATASET CREATION
# ----------------------------

try:
    print("Total URLs before cleaning:", len(dataset))

    # Convert to DataFrame
    df = pd.DataFrame(dataset, columns=["url", "label"])

    # Remove duplicate URLs
    df = df.drop_duplicates(subset="url")

    print("Total URLs after removing duplicates:", len(df))

    # Shuffle dataset (VERY IMPORTANT for ML)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Save final dataset
    output_path = os.path.join(base_dir, "data", "url_dataset.csv")
    df.to_csv(output_path, index=False)

    print("Final dataset saved at:", output_path)

except Exception as e:
    print("Error creating final dataset:", e)