import re
import requests
import tldextract
import os
import joblib
import dns.resolver
from datetime import datetime
import math
from urllib.parse import unquote
from collections import Counter

# ----------------------------
# Load trained ML phishing model
# ----------------------------

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_path = os.path.join(base_dir, "phishing_model.pkl")
model = None

# ----------------------------
# Suspicious domain words
# ----------------------------

suspicious_domain_words = [
    "login","verify","secure","bonus","reward",
    "gift","bank","wallet","upi","pay"
]

# ----------------------------
# Target brands
# ----------------------------

target_brands = [
    "google","gmail","youtube","googlepay","gpay",
    "amazon","flipkart","myntra","ajio",
    "paypal","paytm","phonepe","bharatpe","mobikwik","bhim",
    "apple","icloud","appleid","meesho",
    "microsoft","outlook","office365","azure",
    "facebook","instagram","whatsapp",
    "linkedin","twitter",
    "netflix","primevideo","hotstar","spotify",
    "hdfc","icici","axis","kotak","pnb",
    "yono","onlinesbi","unionbank",
    "irctc","uidai","aadhaar","incometax",
    "uber","zomato","swiggy",
    "telegram","snapchat","discord",
    "dropbox","googledrive","onedrive",
    "github","gitlab",
    "byjus","unacademy",
    "airtel"
]




# ----------------------------
# TRUST / PHISHING KEYWORDS
# ----------------------------

trust_keywords = [
    "bank", "secure", "login", "verify",
    "update", "payment", "wallet",
    "account", "signin", "auth",
    "support", "service"
]



# ----------------------------
# SCAM CATEGORY DETECTION
# ----------------------------

# Banking / KYC scams
banking_scam_words = [
    "bank", "kyc", "account", "verify",
    "otp", "suspended", "blocked",
    "update", "payment", "upi"
]

# Delivery / parcel scams
delivery_scam_words = [
    "parcel", "delivery", "shipment",
    "tracking", "courier", "dispatch",
    "colis", "relay"
]

# Login / credential phishing
credential_scam_words = [
    "login", "signin", "password",
    "auth", "secure", "verify",
    "office365"
]

# Reward / lottery scams
reward_scam_words = [
    "reward", "prize", "winner",
    "lottery", "claim", "bonus",
    "gift"
]







# # ----------------------------
# # PHISHING INTENT DETECTION
# # ----------------------------

# # Login / credential theft intent
# credential_intent_words = [
#     "login", "signin", "password",
#     "verify", "authentication",
#     "secure", "account"
# ]

# # Payment / billing intent
# payment_intent_words = [
#     "payment", "billing", "invoice",
#     "refund", "transaction", "upi",
#     "card"
# ]

# # Support / helpdesk impersonation
# support_intent_words = [
#     "support", "helpdesk", "customer care",
#     "service", "assistance", "help"
# ]







# # ----------------------------
# # SOCIAL ENGINEERING DETECTION
# # ----------------------------

# # Urgency / pressure tactics
# urgency_words = [
#     "urgent", "immediately", "now",
#     "today", "expire", "suspended",
#     "blocked", "warning", "limited time"
# ]

# # Fear-based manipulation
# fear_words = [
#     "suspended", "blocked", "unauthorized",
#     "security alert", "compromised",
#     "locked", "fraud detected"
# ]

# # Reward / temptation manipulation
# reward_words = [
#     "winner", "bonus", "reward",
#     "claim", "gift", "prize",
#     "free"
# ]






# ----------------------------
# SHORT BRANDS (STRICT MATCH ONLY)
# ----------------------------

short_brands = ["x", "vi", "bob","sbi","ola","jio"]




# ----------------------------
# Popular trusted domains
# ----------------------------

popular_domains = [
    "google.com","youtube.com","facebook.com","instagram.com","whatsapp.com",
    "twitter.com","x.com","linkedin.com","reddit.com","pinterest.com",
    "chatgpt.com","bing.com","yahoo.com","duckduckgo.com","gmail.com",
    "outlook.com","office.com","microsoft.com","apple.com","icloud.com",

    "amazon.in","amazon.com","flipkart.com","myntra.com","ajio.com",
    "meesho.com","snapdeal.com","tatacliq.com","nykaa.com","jiomart.com",

    "netflix.com","primevideo.com","hotstar.com","sonyliv.com","zee5.com",
    "spotify.com","gaana.com","jiosaavn.com","wynk.in","voot.com",

    "wikipedia.org","quora.com","medium.com","stackoverflow.com","github.com",
    "gitlab.com","coursera.org","udemy.com","byjus.com","unacademy.com",

    "paytm.com","phonepe.com","gpay.com","razorpay.com","bharatpe.com",
    "freecharge.in","mobikwik.com","airtel.in","jio.com","vi.in",

    "irctc.co.in","uidai.gov.in","incometax.gov.in","india.gov.in","epfindia.gov.in",
    "onlinesbi.sbi","hdfcbank.com","icicibank.com","axisbank.com","kotak.com",

    "cricbuzz.com","espncricinfo.com","indiatimes.com","ndtv.com","aajtak.in",
    "hindustantimes.com","thehindu.com","timesofindia.com","indianexpress.com","news18.com",

    "ola.com","uber.com","rapido.bike","zomato.com","swiggy.com",
    "makemytrip.com","goibibo.com","yatra.com","booking.com","airbnb.com",

    "dropbox.com","drive.google.com","mega.nz","weebly.com","wordpress.com",
    "shopify.com","canva.com","figma.com","notion.so","trello.com",

    "bharatbillpay.com", "npci.org.in"


]


# ----------------------------
# Short URL services
# ----------------------------

short_url_services = [
    "bit.ly","tinyurl.com","t.co","goo.gl","cutt.ly","is.gd"
]

# ----------------------------
# Suspicious keywords
# ----------------------------

suspicious_keywords = [
    "lottery","reward","claim","urgent","verify","otp","win","claim","blocked",
    "Suspended"
]




# ----------------------------
# KEYWORD CLASSIFICATION (NEW)
# ----------------------------

# High-risk keywords (strong scam indicators)
high_risk_keywords = [
    "lottery", "winner", "prize", "reward", "claim","Urgently","Final Notice",
    "urgent", "otp", "bank", "blocked", "suspended","Immediatly"
]

# Normal suspicious keywords (common but less risky)
normal_keywords = [
    "verify", "login", "update", "secure", "account"
]





# ----------------------------
# Suspicious TLDs
# ----------------------------

suspicious_tlds = [
    "xyz","top","click","site","live","gq","cf","ml"
]

# ----------------------------
# Load scam patterns
# ----------------------------

def load_scam_patterns():

    patterns = []
    file_path = os.path.join(base_dir,"data","scam_patterns.txt")

    try:
        with open(file_path,"r") as file:
            for line in file:
                patterns.append(line.strip().lower())
    except:
        print("Scam pattern dataset not found")

    return patterns

scam_patterns = load_scam_patterns()










# ----------------------------
# Load URLhaus database
# ----------------------------

def load_urlhaus():

    urlhaus_set = set()

    file_path = os.path.join(base_dir, "data", "urlhaus.csv")

    try:
        with open(file_path, "r", encoding="utf-8") as f:

            for line in f:

                # Skip comments
                if line.startswith("#"):
                    continue

                parts = line.split(",")

                # URL is 3rd column (index 2)
                if len(parts) > 2:
                    url = parts[2].strip().strip('"')
                    urlhaus_set.add(url)

    except:
        print("URLhaus dataset not found")

    return urlhaus_set


# Load once
urlhaus_db = load_urlhaus()









# ----------------------------
# Jaccard similarity
# ----------------------------

def jaccard_similarity(text1,text2):

    text1 = re.sub(r'[^\w\s]','',text1)
    text2 = re.sub(r'[^\w\s]','',text2)

    words1=set(text1.split())
    words2=set(text2.split())

    intersection=words1.intersection(words2)
    union=words1.union(words2)

    if len(union)==0:
        return 0

    return len(intersection)/len(union)

# ----------------------------
# Domain age using APILayer
# ----------------------------

def get_domain_age(domain):

    API_KEY = "nOmMJNL00UiCQgHbPVn698GXNVce7otZ"

    url = "https://api.apilayer.com/whois/query"

    headers = {
        "apikey": API_KEY
    }

    params = {
        "domain": domain
    }

    try:

        response = requests.get(url, headers=headers, params=params, timeout=5)

        data = response.json()

        result = data.get("result")

        if not result:
            return None

        creation_date = result.get("creation_date")

        if not creation_date:
            return None

        creation_date = datetime.strptime(creation_date[:10], "%Y-%m-%d")

        today = datetime.now()

        age_days = (today - creation_date).days

        return age_days

    except:
        return None

# ----------------------------
# Domain entropy
# ----------------------------

def calculate_entropy(text):

    counter=Counter(text)
    length=len(text)

    entropy=0

    for count in counter.values():
        probability=count/length
        entropy-=probability*math.log2(probability)

    return entropy

# ----------------------------
# Levenshtein distance
# ----------------------------

def levenshtein_distance(a,b):

    if len(a)<len(b):
        return levenshtein_distance(b,a)

    if len(b)==0:
        return len(a)

    previous_row=range(len(b)+1)

    for i,c1 in enumerate(a):

        current_row=[i+1]

        for j,c2 in enumerate(b):

            insertions=previous_row[j+1]+1
            deletions=current_row[j]+1
            substitutions=previous_row[j]+(c1!=c2)

            current_row.append(min(insertions,deletions,substitutions))

        previous_row=current_row

    return previous_row[-1]






# ----------------------------
# Homograph Attack Detection (ASCII-based)
# ----------------------------
def detect_homograph_attack(domain):
    """
    Detects if domain contains non-ASCII characters.
    Phishing domains often use Unicode characters that look like normal letters.
    
    Example:
    google.com  -> normal (ASCII)
    gооgle.com  -> contains Cyrillic 'о' (non-ASCII)
    """

    for char in domain:
        # ord(char) gives ASCII/Unicode value
        # ASCII characters range: 0–127
        if ord(char) > 127:
            return True  # Non-ASCII detected → suspicious

    return False  # Safe ASCII domain





# ----------------------------
# URL PATH ATTACK DETECTION
# ----------------------------
def detect_path_attack(url):
    """
    Detects phishing intent based on multiple suspicious
    keywords in the URL path.
    """

    suspicious_words = [
        "login", "verify", "secure", "account",
        "update", "bank", "payment", "auth", "signin"
    ]

    try:
        parts = url.split("/", 3)

        # No path present
        if len(parts) < 4:
            return False

        path = parts[3].lower()

        count = 0

        for word in suspicious_words:
            if word in path:
                count += 1

        # Trigger only if multiple keywords
        return count >= 2

    except:
        return False
    






# ----------------------------
# Subdomain Brand Trap Detection
# ----------------------------
def detect_subdomain_brand_trap(url, brands):
    """
    Detects if a trusted brand name is used in subdomain
    instead of actual domain.

    Example:
    amazon.login.xyz  -> suspicious
    amazon.com        -> safe
    """

    extracted = tldextract.extract(url)

    subdomain = extracted.subdomain.lower()
    main_domain = extracted.domain.lower()

    # Check each brand
    for brand in brands:

        # If brand appears in subdomain BUT not actual domain
        if brand in subdomain and brand != main_domain:
            return True

    return False





# ----------------------------
# Character Ratio Analysis
# ----------------------------
def digit_ratio(domain):
    """
    Calculates ratio of digits in domain.
    Helps detect short randomized phishing domains.
    """

    total = len(domain)

    if total == 0:
        return 0

    digits = sum(c.isdigit() for c in domain)

    return digits / total







# ----------------------------
# Resolve redirect URL
# ----------------------------

def resolve_final_url(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)

        final_url = response.url

        # Count redirects
        redirect_count = len(response.history)

        return final_url, redirect_count

    except:
        return url, 0

# ----------------------------
# PhishTank API check
# ----------------------------

def check_phishtank(url):

    api_url = "https://checkurl.phishtank.com/checkurl/"

    payload = {
        "url": url,
        "format": "json"
    }

    headers = {
        "User-Agent": "fraud-detector"
    }

    try:

        response = requests.post(api_url, data=payload, headers=headers, timeout=5)
        data = response.json()

        if "results" in data:

            result = data["results"]

            if result.get("in_database") and result.get("verified"):
                return True

    except:
        pass

    return False

# ----------------------------
# ML phishing detection
# ----------------------------

def ml_detect(url):

    # features = [
    #     len(url),
    #     url.count("-"),
    #     url.count("."),
    #     int("https" in url),
    #     int(re.search(r'\d+\.\d+\.\d+\.\d+', url) is not None)
    # ]

    # prediction = model.predict([features])

    # return prediction[0]
    return 0






# ----------------------------
# Load OpenPhish Feed
# ----------------------------

def load_openphish():
    
    openphish_set = set()
    
    file_path = os.path.join(base_dir, "data", "openphish.txt")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip().lower()
                # Normalize URL (same as detection)
                url = url.replace("https://", "").replace("http://", "")
                url = url.rstrip("/")

                if url:
                    openphish_set.add(url)
    
    except:
        print("OpenPhish dataset not found")

    return openphish_set


# Load once
openphish_db = load_openphish()

print("Total OpenPhish entries:", len(openphish_db))




def check_google_safe_browsing(url):

    API_KEY = "AIzaSyDkldRwcVa83tl5PJu-qqIOADeTSUhV4jk"

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "fraud-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:

        response = requests.post(endpoint, json=payload, timeout=5)

        data = response.json()

        print("Safe Browsing API Response:", data)  # DEBUG

        if "matches" in data:
            return True

    except Exception as e:
        print("Safe Browsing error:", e)

    return False






def check_urlhaus(url):

    api_url = "https://urlhaus-api.abuse.ch/v1/url/"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    }

    payload = {
        "url": url
    }

    try:
        response = requests.post(api_url, headers=headers, data=payload, timeout=5)

        result = response.json()

        print("URLhaus response:", result)  # DEBUG

        if result.get("query_status") == "ok":
            return True

    except Exception as e:
        print("URLhaus error:", e)

    return False










def check_abuseipdb(ip):

    API_KEY = "9e9c72067b88af9d60f3618d3a1d02a4866be923ad5e8a640b70a3739c7f901eeb050d08e425303c"

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        data = response.json()

        abuse_score = data["data"]["abuseConfidenceScore"]

        if abuse_score > 50:
            return True, abuse_score

    except:
        pass

    return False, 0








def load_threatfox():

    threatfox_set = set()

    file_path = os.path.join(base_dir, "data", "threatfox.json")

    try:
        import json

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

            # Loop through dictionary values
            for key in data:
                entries = data[key]

                for item in entries:
                    ioc = item.get("ioc_value")

                    if ioc:
                        threatfox_set.add(ioc.strip())

        print("Total ThreatFox entries:", len(threatfox_set))

    except Exception as e:
        print("ThreatFox dataset error:", e)

    return threatfox_set
threatfox_db = load_threatfox()







# ----------------------------
# SMART BRAND MATCHING (NEW)
# ----------------------------
def is_brand_match(domain, brand):
    """
    Smart brand matching to avoid false positives like 'x' in 'xyz'
    """

    domain = domain.lower()
    brand = brand.lower()

    # Split domain into tokens
    parts = re.split(r'[-.]', domain)

    # Rule 1: Short brands (<=3 chars) → exact match only
    if len(brand) <= 3:
        return brand in parts

    # Rule 2: Normal brands → allow substring OR typo
    for part in parts:
        if brand in part:
            return True

        # Typosquatting check
        if 0 < levenshtein_distance(part, brand) <= 2:
            return True

    return False







# ----------------------------
# GENERIC TOKENS TO IGNORE
# ----------------------------

generic_tokens = {
    "login", "secure", "verify", "update", "account",
    "check", "bank", "service", "support", "help",
    "auth", "user", "portal", "payment", "online",
    "signin", "confirm", "access", "system"
}



# ----------------------------
# MAIN DETECTION FUNCTION
# ----------------------------

def analyze_message(message):

    score = 0
    weak_score = 0
    # LIMIT TOTAL STRUCTURAL IMPACT
    structure_score = 0
    #Brand Score 
    brand_score = 0
    reasons = []


    # ----------------------------
# HELPER FUNCTION TO AVOID DUPLICATES
# ----------------------------
    def add_reason(reason):
        if reason not in reasons:
            reasons.append(reason)

    decoded_message = unquote(message)
    text = decoded_message.lower()







    # ----------------------------
# KEYWORD COUNTING (NEW)
# ----------------------------

    high_keyword_count = 0
    normal_keyword_count = 0

# Count high-risk keywords
    for word in high_risk_keywords:
        if word.lower() in text:
            high_keyword_count += 1

# Count normal keywords
    for word in normal_keywords:
        if word.lower() in text:
            normal_keyword_count += 1

# Flag
    keyword_flag = (high_keyword_count + normal_keyword_count) > 0





    # ----------------------------
# SCAM CATEGORY ANALYSIS
# ----------------------------

    detected_scam_categories = []

# Banking scam detection
    if sum(word in text for word in banking_scam_words) >= 2:
        detected_scam_categories.append("banking")

# Delivery scam detection
    if sum(word in text for word in delivery_scam_words) >= 2:
        detected_scam_categories.append("delivery")

# Credential phishing detection
    if sum(word in text for word in credential_scam_words) >= 2:
        detected_scam_categories.append("credential")

# Reward scam detection
    if sum(word in text for word in reward_scam_words) >= 2:
        detected_scam_categories.append("reward")







    # ----------------------------
# SEMANTIC SCAM CONTEXT
# ----------------------------

    for category in detected_scam_categories:

        if category == "banking":
            score += 8
            add_reason(
                "The message resembles a banking or account verification scam"
            )

        elif category == "delivery":
            score += 8
            add_reason(
                "The message resembles a parcel or delivery phishing scam"
            )

        elif category == "credential":
            score += 10
            add_reason(
                "The message appears designed to steal account login credentials"
            )

        elif category == "reward":
            score += 8
            add_reason(
                "The message resembles a prize, reward, or lottery scam"
            )



    



#     # ----------------------------
# # BRAND + INTENT RELATIONSHIP ANALYSIS
# # ----------------------------

#     brand_intent_detected = False

#     for brand in target_brands:

#         if brand in text:

#         # Credential phishing
#             if sum(word in text for word in credential_intent_words) >= 2:

#                 score += 12

#                 add_reason(
#                     f"The message appears to imitate {brand} account services to steal login credentials"
#                 )

#                 brand_intent_detected = True

#         # Payment phishing
#             elif sum(word in text for word in payment_intent_words) >= 2:

#                 score += 10

#                 add_reason(
#                     f"The message appears to impersonate {brand} payment or billing services"
#                 )

#                 brand_intent_detected = True

#         # Support impersonation
#             elif sum(word in text for word in support_intent_words) >= 2:

#                 score += 10

#                 add_reason(
#                     f"The message appears to imitate {brand} customer support services"
#                 )

#                 brand_intent_detected = True

#             break





    # ----------------------------
# MESSAGE INTENT CONTROL (FIXED)
# ----------------------------

    keyword_flag = False
    pattern_flag = False

# Keyword detection
    # for word in suspicious_keywords:
    #     if word in text:
    #         keyword_flag = True
    #         detected_word = word
    #         break

# Pattern detection
    for pattern in scam_patterns:
        if pattern in text:
            pattern_flag = True
            score += 18
            add_reason("Matched known scam pattern: " + pattern)
            break

# Similarity detection (only if no direct pattern)
    similarity_flag = False   # ADD THIS BEFORE LOOP

    if not pattern_flag:
        for pattern in scam_patterns:
            similarity = jaccard_similarity(text, pattern)
            if similarity > 0.5:
                similarity_flag = True   # ADD THIS
                
                score += 12
                add_reason("Message similar to scam pattern: " + pattern)
                break
    






    




# Final message scoring (ONLY if no pattern found)
    # if keyword_flag and not pattern_flag:
    #     weak_score += 8
    #     add_reason("Suspicious keyword detected: " + detected_word)



    

    # URL Encoding Detection
    if re.search(r'%[0-9a-fA-F]{2}', message):
        score += 15
        add_reason("URL encoding detected (possible obfuscation)")




    
    print("\n[DEBUG] Processing message:", message)
    print("[DEBUG] Decoded message:", decoded_message)





    # ----------------------------
# CONTEXT-AWARE DETECTION (NEW)
# ----------------------------

# Detect phrases commonly used in phishing messages
#     scam_context_phrases = [
#         "send money", "click link", "verify now",
#         "account blocked", "urgent action",
#         "limited time", "claim now", "act now"
#     ]

#     for phrase in scam_context_phrases:
#         if phrase in text:
#             score += 15
#             add_reason(f"Suspicious message context detected: '{phrase}'")




    # URL extraction
    # Unicode-aware URL extraction
    urls = re.findall(
        r'(https?://[^\s]+|(?:[\w\-]+\.)+[\w\-]{2,})',
        text,
        re.UNICODE
    )
    # to remove duplicate
    urls = list(set(urls))    




    # ----------------------------
# FILTER INVALID DOMAINS (FIX)
# ----------------------------

    valid_urls = []

    for u in urls:
    # Only keep URLs with real domain-like structure
        if "." in u and not u.endswith((".py", ".txt", ".exe", ".jpg", ".png")):
            valid_urls.append(u)

    urls = valid_urls
    print("[DEBUG] Extracted URLs:", urls)


    # ----------------------------
# CHECK IF URL EXISTS
# ----------------------------
    has_url = len(urls) > 0


    



    
    # ----------------------------
# Hidden URL Detection
# ----------------------------

# Extract visible domains from text
    visible_domains = re.findall(
        r'(?:[\w\-]+\.)+[\w\-]{2,}',
        text,
        re.UNICODE
    )
    print("[DEBUG] Visible domains:", visible_domains)






    # ----------------------------
# Hidden URL Detection (FIXED FINAL)
# ----------------------------

    unique_domains = set(visible_domains)

    if len(unique_domains) >= 2:
        score += 18
        add_reason("The visible link text does not match the actual destination")





    if urls:
        score += 10
        add_reason("Message contains URL or domain")


    # URL analysis
    for url in urls:
        ip = None


        decoded_url = unquote(url)
        # if url redirected
        final_url, redirect_count = resolve_final_url(decoded_url)








        # ----------------------------
# SUBDOMAIN BRAND TRAP CHECK (NEW)
# ----------------------------

        if detect_subdomain_brand_trap(final_url, target_brands):

    # Add to brand_score (important: not main score)
            

            add_reason("Brand name used in subdomain (possible phishing trap)")
        





        # ----------------------------
# QUERY PARAMETER DETECTION (NEW)
# ----------------------------

        if "?" in final_url:
            query_part = final_url.split("?")[1]

    # Long query string
            if len(query_part) > 30:
                score += 10
                add_reason("Long query parameters detected")

    # Too many parameters
            param_count = query_part.count("=")
            if param_count >= 3:
                score += 10
                add_reason(f"Too many URL parameters ({param_count})")

    # Suspicious parameter keywords
            suspicious_params = ["token", "session", "auth", "key", "login", "verify"]

            for param in suspicious_params:
                if param in query_part:
                    score += 10
                    add_reason(f"Suspicious parameter detected: {param}")
                    break



        # ----------------------------
# HTTP vs HTTPS Detection (NEW)
# ----------------------------

        if final_url.startswith("http://"):
            weak_score += 12
            add_reason("Uses HTTP instead of HTTPS (less secure)")






        # ----------------------------
# Digit Ratio Detection
# ----------------------------

        # digits = sum(c.isdigit() for c in final_url)
        # if digits > 3:
        #     structure_score += 15
        #     add_reason(f"Too many numbers in URL ({digits})")




        

        # Domain extraction
        domain_info = tldextract.extract(final_url)
        domain = domain_info.domain
        suffix = domain_info.suffix





        # Full hostname for phishing analysis
        hostname = domain_info.fqdn.lower()

# Remove www prefix
        hostname = hostname.replace("www.", "")
        print("[DEBUG] Hostname:", hostname)





        


        # ----------------------------
# DOMAIN STRUCTURE ENGINE (FIXED)
# ----------------------------

        digit_count = sum(c.isdigit() for c in hostname)
        hyphen_count = hostname.count("-")
        dot_count = final_url.count(".")

        length = len(hostname)

# Avoid division error
        digit_ratio = digit_count / length if length > 0 else 0

        signals = 0

# ---- Individual checks ----

        if digit_count >= 4:
            signals += 1

        if hyphen_count >= 2:
            signals += 1

        if dot_count >= 3:
            signals += 1

        if digit_ratio > 0.3:
            signals += 1


# ---- Final scoring ----

        if signals >= 3:
            structure_score += 30
            add_reason("Highly suspicious domain structure commonly used in phishing URLs (multiple indicators)")

        elif signals == 2:
            structure_score += 20
            add_reason("Suspicious domain structure commonly used in phishing URLs")

        elif signals == 1:
            structure_score += 10
            add_reason("Domain contains unusual structure commonly used in phishing URLs")





        # ----------------------------
# LONG URL DETECTION (FIXED - EARLY)
# ----------------------------

        url_length = len(final_url)
        print("[DEBUG] URL Length:", url_length)

        if url_length > 60:
            structure_score += 15
            add_reason(f"Very long URLs are commonly used to hide phishing intent ({url_length} characters)")





        # ----------------------------
# DOT COUNT DETECTION (NEW)
# ----------------------------
#         dot_count = final_url.count(".")

# # If too many dots → phishing pattern
#         if dot_count >= 4:
#             structure_score += 15
#             add_reason(f"Too many dots in URL ({dot_count})")





        



        domain_name = domain + "." + suffix





        





        # ----------------------------
# Skip trusted domains (CLEAN OUTPUT)
# ----------------------------

        # TRUSTED DOMAIN CHECK
        if domain_name in popular_domains:
            score -= 25
            add_reason("The domain matches a widely recognized and commonly trusted service")
            continue   # skip further risky checks





        # ----------------------------
# DOMAIN POPULARITY (IMPROVED)
# ----------------------------

        if domain_name not in popular_domains:

    # Only add weak signal if structure is not already strong
            if structure_score < 20:
                weak_score += 5
                add_reason("This domain is not commonly recognized or widely used")




        # ----------------------------
# SAFE DOMAIN KEYWORD CHECK (RULE 4)
# ----------------------------

        # safe_keywords = ["github", "google", "youtube", "amazon", "microsoft"]

        # if any(safe in domain_name for safe in safe_keywords):
        #     score -= 5
        #     add_reason("Known safe service keyword detected")


        


        # ----------------------------
# BRAND + STRUCTURE PATTERN (ADVANCED)
# ----------------------------

        if any(brand in domain_name for brand in target_brands):

    # hyphen-based pattern (very common phishing)
            if "-" in domain_name:
                structure_score += 10
                add_reason("Brand combined with hyphen pattern detected")

    # multiple words pattern
            if len(domain_name.split("-")) >= 3:
                structure_score += 10
                add_reason("Complex brand-based domain structure detected")






        
        # ----------------------------
# SUSPICIOUS TLD DETECTION (FIXED)
# ----------------------------

        tld = suffix.lower()

        if any(tld.endswith(bad) for bad in suspicious_tlds):
            structure_score += 15   # moved to structure layer
            add_reason(f"This domain extension is commonly used in phishing attack domain (.{tld})")



        brand_signals = 0

        entropy_detected = False





        # Detect whether domain already contains brand-related patterns
        brand_context_detected = any(
            brand in domain_name for brand in target_brands
        )




        # ----------------------------
# ENTROPY DETECTION (FIXED)
# ----------------------------

# Ignore very small domains
        if len(domain) > 5:
            entropy = calculate_entropy(domain)

            if entropy > 3.0:
        # Reduce impact if TLD already suspicious
                if any(tld.endswith(bad) for bad in suspicious_tlds):
                    structure_score += 8
                else:
                    structure_score += 20

                # Show entropy explanation only if stronger brand attacks are absent
                entropy_detected = True




        
        # ----------------------------
# Improved Hyphen Detection (STRONG)
# ----------------------------

# Count hyphens only in domain
        # if domain.count("-") > 2:
        #     score += 20
        #     add_reason("Too many hyphens in domain")




        # ----------------------------
# Improved Subdomain Detection (STRONG)
# ----------------------------

        subdomain = domain_info.subdomain

        if subdomain:
            levels = subdomain.split(".")

            if len(levels) >= 3:
                score += 15
                add_reason("Too many subdomains (phishing pattern)")


        

        # ----------------------------
# PATH INTELLIGENCE ENGINE (FIXED)
# ----------------------------
        # Calculate path depth
        path_depth = final_url.count("/")
        # Detect keyword attack
        is_path_attack = detect_path_attack(final_url)

# Case 1: Strong phishing pattern
        if path_depth > 4 and is_path_attack:
            structure_score += 20
            add_reason("Deep path with multiple suspicious keywords")

# Case 2: Only keyword-based attack
        elif is_path_attack:
            structure_score += 15
            add_reason("Suspicious keywords in URL path")

# Case 3: Only deep structure
        elif path_depth > 4:
            structure_score += 10
            add_reason("Unusually deep URL path")

        





#         # ----------------------------
# # DEEP PATH STRUCTURE DETECTION (NEW)
# # ----------------------------

# # Count number of slashes in URL path
#         # ----------------------------
# # COMBINED PATH ANALYSIS (SMART)
# # ----------------------------

# # Calculate path depth
#         path_depth = final_url.count("/")

# # Detect keyword attack
#         is_path_attack = detect_path_attack(final_url)

# # Case 1: Deep + suspicious keywords (HIGH RISK)
#         if path_depth > 4 and is_path_attack:
#             structure_score += 20
#             add_reason("Deep path with suspicious keywords")

# # Case 2: Only deep path
#         elif path_depth > 4:
#             structure_score += 10
#             add_reason("Unusually deep URL path")

# # Case 3: Only keyword attack
#         elif is_path_attack:
#             structure_score += 15
#             add_reason("Multiple suspicious keywords in URL path")






        

        # ----------------------------
# COMBINATION SIGNAL BOOST (RULE 3)
# ----------------------------

# If both suspicious path AND suspicious TLD → strong phishing pattern
        # if path_hits > 0 and suffix in suspicious_tlds:
        #     score += 10
        #     add_reason("Combination: Suspicious path + suspicious TLD")



        # ----------------------------
# REDIRECT ANALYSIS (FIXED)
# ----------------------------

        print("[DEBUG] Redirect count:", redirect_count)

        if redirect_count >= 3:
            score += 25
            add_reason(f"The link redirects through multiple destinations, which is commonly used to hide malicious websites ({redirect_count})")

        elif redirect_count == 2:
            score += 15
            add_reason("Double redirect detected")

        elif redirect_count == 1:
            score += 10
            add_reason("Single redirect detected")





# Domain change detection
        original_domain = tldextract.extract(decoded_url).registered_domain
        final_domain = tldextract.extract(final_url).registered_domain

        if original_domain != final_domain:
            score += 15
            add_reason("Redirect leads to different domain")



        
        # ----------------------------
# SHORT URL DETECTION (FINAL)
# ----------------------------

        if domain_name in short_url_services:
            score += 15
            add_reason("Shortened URL detected")







       
        


        # ----------------------------
# BRAND DETECTION (CLEAN)
# ----------------------------

        full_url = final_url.lower()

        for brand in target_brands:

    # Detect brand in URL but NOT actual domain
            if is_brand_match(full_url, brand) and not is_brand_match(domain, brand):
                
                # add_reason(f"Brand impersonation detected: {brand}")
                break




        # Store strongest detected impersonated brand
        detected_brand = None

        
# ----------------------------
# TYPOSQUATTING DETECTION (CLEAN)
# ----------------------------

        parts = re.split(r'[-.]', hostname)

        for part in parts:

    # Ignore very short tokens
            if len(part) < 4:
                continue

    # Ignore generic phishing words
            if part in generic_tokens:
                continue

            for brand in target_brands:

                distance = levenshtein_distance(part, brand)

                # Stronger typosquatting validation
                similarity_ratio = 1 - (distance / max(len(part), len(brand)))

                if (
                    0 < distance <= 2
                        and abs(len(part) - len(brand)) <= 1
                        and similarity_ratio >= 0.7
                ):
                    if detected_brand is None:
                        detected_brand = brand
                    add_reason(f"The website name is intentionally misspelled to resemble a trusted brand: {brand}")
                    break
        



        # ----------------------------
# VISUAL SIMILARITY DETECTION (NEW)
# ----------------------------

# Common character replacements used in phishing
        char_map = {
            '0': 'o',
            '1': 'l',
            '3': 'e',
            '@': 'a',
            '$': 's'
        }

# Normalize domain
        normalized_domain = hostname
        for fake, real in char_map.items():
            normalized_domain = normalized_domain.replace(fake, real)

# Check if it mimics a brand visually
        for brand in target_brands:
            if brand in normalized_domain and not is_brand_match(domain_name, brand):
                if detected_brand is None:
                    detected_brand = brand
                add_reason(f"The domain is designed to visually resemble a trusted brand (looks like {brand})")
                break







        # ----------------------------
# HOMOGRAPH ATTACK CHECK (NEW)
# ----------------------------

# Check if domain contains Unicode characters
        if detect_homograph_attack(hostname):

    # Add to brand_score (not main score → avoid duplication)
              

    # Reason for detection
            add_reason("The website name uses confusing letters to look like a trusted site")




        

        # ----------------------------
# BRAND INTELLIGENCE ENGINE (FINAL)
# ----------------------------

        
        brand_types = []

# --- Subdomain trap ---
        if detect_subdomain_brand_trap(final_url, target_brands):
            brand_signals += 1
            brand_types.append("subdomain")

# --- Typosquatting ---
        parts = re.split(r'[-.]', hostname)
        for part in parts:

    # Ignore very short tokens
            if len(part) < 4:
                continue

    # Ignore generic phishing words
            if part in generic_tokens:
                continue

            for brand in target_brands:
                distance = levenshtein_distance(part, brand)
                similarity_ratio = 1 - (distance / max(len(part), len(brand)))

                if (
                        0 < distance <= 2
                        and abs(len(part) - len(brand)) <= 1
                        and similarity_ratio >= 0.7
                ):
                    brand_signals += 1
                    brand_types.append("typosquatting")
                    break

# --- Visual similarity ---
        char_map = {'0':'o','1':'l','3':'e','@':'a','$':'s'}
        normalized = hostname
        for f, r in char_map.items():
            normalized = normalized.replace(f, r)

        for brand in target_brands:
            if brand in normalized and brand not in domain:
                brand_signals += 1
                brand_types.append("visual")
                break

# --- Homograph ---
        if detect_homograph_attack(hostname):
            brand_signals += 1
            brand_types.append("homograph")






        # ----------------------------
# FINAL BRAND MESSAGE (CLEAN)
# ----------------------------

        

# Try to find which brand matched
        for brand in target_brands:
            if is_brand_match(hostname, brand):
                if detected_brand is None:
                    detected_brand = brand
                break

        if brand_signals >= 3:
            brand_score += 45
            if detected_brand is None:
                detected_brand = brand
            add_reason(f"The domain references a trusted brand in a potentially misleading way ({detected_brand})")

        elif brand_signals == 2:
            brand_score += 30
            if detected_brand is None:
                detected_brand = brand
            add_reason(f"The domain references a trusted brand in a potentially misleading way ({detected_brand})")

        elif brand_signals == 1:
            brand_score += 20
            if detected_brand is None:
                detected_brand = brand
            add_reason(f"This domain appears designed to impersonate the trusted brand ({detected_brand})")





        

        # Show entropy reason only if stronger phishing indicators are absent
        if entropy_detected and brand_signals == 0:
            add_reason("The domain uses an unusually complex structure often associated with phishing websites")
            






        # ----------------------------
# IP ADDRESS DETECTION (IMPROVED)
# ----------------------------

        ip_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}\b'

        match = re.search(ip_pattern, final_url)

        if match:
            ip = match.group()

    # Check for private IP ranges
            if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
                weak_score += 12
                add_reason(f"Private IP used in URL ({ip})")
            else:
                score += 25
                add_reason(f"The link uses a raw IP address instead of a normal domain name, which is common in phishing attacks({ip})")
        



        # Normalize URL
        clean_url = final_url.lower()

# Remove protocol
        clean_url = clean_url.replace("https://", "").replace("http://", "")

# Remove trailing slash
        clean_url = clean_url.rstrip("/")







        # DATABASE CHECKS (STRONG) DB 

        # PhishTank
        if check_phishtank(final_url):
            score += 100
            add_reason("URL found in PhishTank phishing database")

        # URLhaus (CSV ONLY)
        if clean_url.rstrip("/") in urlhaus_db:
            score += 100
            add_reason("URL found in URLhaus malware database")


        # ----------------------------
# ----------------------------
# OpenPhish Check (FIXED)
# ----------------------------



# Extract only domain
        domain_only = clean_url.split("/")[0]

# Check multiple formats
        if (clean_url in openphish_db or domain_only in openphish_db):
            score += 100
            add_reason("URL found in OpenPhish phishing database")



        if score >= 100:
            score = 100
            break 





        # ----------------------------
# NOW DO API CALLS (ONLY FOR SUSPICIOUS)
# ----------------------------

        if score >= 30:
            if check_google_safe_browsing(final_url):
                score += 100
                add_reason("Google Safe Browsing flagged this URL as dangerous")
                score = 100
                break






        # ThreatFox API (only if not found in DB)
        if score >= 30:
            if domain_name in threatfox_db or final_url in threatfox_db:
                score += 100
                add_reason("Found in ThreatFox database")
                score = 100
                break



        
        




        # Get IP from domain DNS CHECK
            if score >= 30:
                try:
                    ip = dns.resolver.resolve(domain_name, "A")[0].to_text()
                except:
                    ip = None

    # Only flag if domain looks real
            if "." in domain_name:
                score += 10
                add_reason("The domain could not be verified or reached through normal internet lookup")
        

        is_bad = False
        score_ip = 0
        if ip is not None:
            is_bad, score_ip = check_abuseipdb(ip)
            if is_bad:
                score += 25
                add_reason(f"IP reported malicious (AbuseIPDB score: {score_ip})")


    

        

        # ----------------------------
# DOMAIN AGE DETECTION (SMART)
# ----------------------------
        if score >= 30:
            age = get_domain_age(domain_name)

            if age is not None:

                if age < 7:
                    score += 18
                    add_reason("Domain extremely new (<7 days)")

                elif age < 30:
                    score += 15
                    add_reason("Domain recently registered (<30 days)")

                elif age < 90:
                    weak_score += 12
                    add_reason("Domain relatively new (<90 days)")




                
        
        # ----------------------------
# MULTI-SIGNAL INTELLIGENCE BOOST (NEW)
# ----------------------------

# Count strong phishing signals
        strong_signal_count = 0

        strong_keywords = [
            "domain extension",
            "misspelled",
            "visually resemble",
            "impersonate",
            "homograph",
            "deep path",
            "redirects",
            "raw IP address",
            "subdomain"
        ]

# Check how many strong signals already triggered
        for reason in reasons:
            for keyword in strong_keywords:
                if keyword in reason:
                    strong_signal_count += 1
                    break

# If multiple strong signals → boost score
        if strong_signal_count >= 3 and score < 65:
            score += 10
            add_reason("Multiple strong phishing indicators detected")





        # ML detection
        if ml_detect(final_url) == 1:
            score += 15
            add_reason("ML model suggests phishing")





        



    


        print("[DEBUG] URL detected:", final_url)
        print("[DEBUG] Domain:", domain_name)

    # ----------------------------
# CONFIDENCE ADJUSTMENT (NEW)
# ----------------------------

    # Count important signals
     
    important_signals = 0

    for reason in reasons:
        if any(key in reason for key in ["Suspicious top-level domain",
            "Deep path",
            "Brand impersonation",
            "High entropy",
            "Shortened URL"
        ]):
            important_signals += 1

# If only 1 strong signal → reduce impact
    if important_signals == 1 and score > 50:
        score -= 10

# If multiple strong signals → boost confidence
    elif important_signals >= 3:
        score += 10






    






    # ----------------------------
# CONTEXT-AWARE BOOST (LIGHT)
# ----------------------------

    message_flag = False
    url_flag = False

# Message suspicious?
    for reason in reasons:
        if "Suspicious keyword" in reason or "scam pattern" in reason:
            message_flag = True
            break

# URL suspicious?
    if structure_score >= 10:
        url_flag = True

# Combine both
    if message_flag and url_flag:
        score += 15
        add_reason("Message + URL combination indicates phishing intent")





        # Limit weak signals impact
    if weak_score > 40:
        weak_score = 40

    score += weak_score

        #Limit Structure Score
    if structure_score > 40:
        structure_score = 40

    score += structure_score

           # Brand Similarity score
    if brand_score > 50:
        brand_score = 50

    score += brand_score

    # ----------------------------
# TEXT-ONLY SCORING BOOST (NEW)
# ----------------------------

    if not has_url:

        # add_reason("⚠️ Only message analyzed — no URL provided. Risk may increase if a link is included.")

        text_score = 0

    # High-risk keywords
        if high_keyword_count > 0:
            text_score += 30
            add_reason(f"{high_keyword_count} high-risk keyword(s) detected")

        # Extra keywords boost
            if high_keyword_count > 1:
                text_score += min((high_keyword_count - 1) * 10, 20)

    # Normal keywords
        if normal_keyword_count > 0:
            text_score += 10
            add_reason(f"{normal_keyword_count} normal keyword(s) detected")

    # Scam pattern match
        if pattern_flag:
            text_score += 35
            add_reason("The message contains phrases frequently associated with scams or phishing attempts")

    # Similarity detection
# Only add small reinforcement if exact pattern was NOT already detected
        if similarity_flag and not pattern_flag:
            text_score += 12
            add_reason("The message closely resembles wording commonly used in scam or phishing messages")

    # Combine logic
        signal_count = 0
        if high_keyword_count > 0 or normal_keyword_count > 0:
            signal_count += 1
        if pattern_flag:
            signal_count += 1
        if similarity_flag:
            signal_count += 1

    # Boost for multiple signals
        if signal_count >= 2:
            text_score += 15
            add_reason("Several independent warning signs were detected in the message")


        # Show warning only if suspicious signals exist
        if high_keyword_count > 0 or normal_keyword_count > 0 or pattern_flag or similarity_flag:
            add_reason("⚠️ Only message analyzed — no URL provided. Risk may increase if a link is included.")

    # Cap text score
        if text_score > 85:
            text_score = 85

    # Override score if text-only is stronger
        if text_score > score:
            score = text_score





    # ----------------------------
# SMART ML INTEGRATION (FINAL)
# ----------------------------

    # try:
    # # Use ML ONLY for borderline cases
    #     if 40 <= score <= 65:

    #         ml_result = ml_detect(final_url)

    #         if ml_result == 1:
    #             score += 12
    #             add_reason("ML detected phishing pattern (borderline case)")

    #         else:
    #             score -= 5  # slight confidence boost for safe
    #             add_reason("ML suggests URL is likely safe")

    # except Exception as e:
    #     print("ML error:", e)





        # # DNS check
        # try:
        #     dns.resolver.resolve(domain_name, "A")
        # except:
        #     score += 25
        #     add_reason("DNS lookup failed")

    if score > 100:
        score = 100

    
    # ----------------------------
# FINAL NORMALIZATION
# ----------------------------

# Soft cap (gradual control)
    if score > 90:
        score = 90 + (score - 90) * 0.3




    # ----------------------------
# FINAL RISK CLASSIFICATION (CONTEXT-AWARE)
# ----------------------------

# Decide mode
    mode = "url_present" if has_url else "text_only"

# Text-only → stricter (keywords dominate)
    if mode == "text_only":
        if score >= 50:
            verdict = "HIGH RISK"
        elif score >= 20:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

# URL present → balanced (URL dominates)
    else:
        if score >= 60:
            verdict = "HIGH RISK"
        elif score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

# Add one clean final message
    add_reason(f"FINAL VERDICT: {verdict}")

    return score, reasons, verdict


print("Total URLhaus entries:", len(urlhaus_db))

# print(get_domain_age("google.com"))