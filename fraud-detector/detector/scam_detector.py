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
model = joblib.load(model_path)

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
    "paypal","paytm","phonepe","upi","bharatpe","mobikwik","bhim",
    "apple","icloud","appleid","meesho",
    "microsoft","outlook","office365","azure",
    "facebook","instagram","whatsapp","messenger",
    "linkedin","twitter","x",
    "netflix","primevideo","hotstar","spotify",
    "sbi","hdfc","icici","axis","kotak","pnb","bob",
    "yono","onlinesbi","unionbank",
    "irctc","uidai","aadhaar","incometax",
    "ola","uber","zomato","swiggy",
    "telegram","snapchat","discord",
    "dropbox","drive","googledrive","onedrive",
    "github","gitlab",
    "byjus","unacademy",
    "airtel","jio","vi"
]




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
    "lottery","reward","claim","urgent","verify","otp","win"
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

    features = [
        len(url),
        url.count("-"),
        url.count("."),
        int("https" in url),
        int(re.search(r'\d+\.\d+\.\d+\.\d+', url) is not None)
    ]

    prediction = model.predict([features])

    return prediction[0]






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
# MESSAGE INTENT CONTROL (FIXED)
# ----------------------------

    keyword_flag = False
    pattern_flag = False

# Keyword detection
    for word in suspicious_keywords:
        if word in text:
            keyword_flag = True
            detected_word = word
            break

# Pattern detection
    for pattern in scam_patterns:
        if pattern in text:
            pattern_flag = True
            score += 18
            add_reason("Matched known scam pattern: " + pattern)
            break

# Similarity detection (only if no direct pattern)
    if not pattern_flag:
        for pattern in scam_patterns:
            similarity = jaccard_similarity(text, pattern)
            if similarity > 0.3:
                pattern_flag = True
                score += 15
                add_reason("Message similar to scam pattern: " + pattern)
                break

# Final message scoring (ONLY if no pattern found)
    if keyword_flag and not pattern_flag:
        weak_score += 8
        add_reason("Suspicious keyword detected: " + detected_word)



    

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
    urls = re.findall(r'(https?://\S+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})', text)
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
# Hidden URL Detection
# ----------------------------

# Extract visible domains from text
    visible_domains = re.findall(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', text)
    print("[DEBUG] Visible domains:", visible_domains)






    # ----------------------------
# Hidden URL Detection (FIXED FINAL)
# ----------------------------

    unique_domains = set(visible_domains)

    if len(unique_domains) >= 2:
        score += 18
        add_reason("Hidden URL mismatch detected")





    if urls:
        score += 15
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





        


        # ----------------------------
# DOMAIN STRUCTURE ENGINE (FIXED)
# ----------------------------

        digit_count = sum(c.isdigit() for c in domain)
        hyphen_count = domain.count("-")
        dot_count = final_url.count(".")

        length = len(domain)

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
            add_reason("Highly suspicious domain structure (multiple indicators)")

        elif signals == 2:
            structure_score += 20
            add_reason("Suspicious domain structure")

        elif signals == 1:
            structure_score += 10
            add_reason("Minor domain irregularity")





        # ----------------------------
# LONG URL DETECTION (FIXED - EARLY)
# ----------------------------

        url_length = len(final_url)
        print("[DEBUG] URL Length:", url_length)

        if url_length > 60:
            structure_score += 15
            add_reason(f"Long URL detected ({url_length} characters)")





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
            add_reason("Trusted domain detected")
            continue   # skip further risky checks





        # ----------------------------
# DOMAIN POPULARITY (IMPROVED)
# ----------------------------

        if domain_name not in popular_domains:

    # Only add weak signal if structure is not already strong
            if structure_score < 20:
                weak_score += 5
                add_reason("Domain not in popular domain list")




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
            add_reason(f"Suspicious top-level domain (.{tld})")




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

                add_reason(f"High entropy domain detected ({round(entropy,2)})")




        
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
            score += 18
            add_reason(f"Multiple redirects detected ({redirect_count})")

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
# BRAND MISUSE DETECTION (IMPROVED)
# ----------------------------

        for brand in target_brands:
            if brand in domain_name:

        # Exact match → skip
                if domain_name == brand + ".com":
                    continue

        # Subdomain trick (paypal.com.fake.xyz)
                if domain_name.endswith("." + brand + ".com"):
                    continue

        # Otherwise suspicious
                structure_score += 30
                add_reason(f"Brand misuse detected: {brand}")

        


        # ----------------------------
# BRAND DETECTION (CLEAN)
# ----------------------------

        full_url = final_url.lower()

        for brand in target_brands:

    # Detect brand in URL but NOT actual domain
            if brand in full_url and brand not in domain.lower():
                
                add_reason(f"Brand impersonation detected: {brand}")
                break


# ----------------------------
# TYPOSQUATTING DETECTION (CLEAN)
# ----------------------------

        parts = re.split(r'[-.]', domain)

        for part in parts:

            if len(part) < 4:
                continue

            for brand in target_brands:

                distance = levenshtein_distance(part, brand)

                if 0 < distance <= 2 and abs(len(part) - len(brand)) <= 1:
                    
                    add_reason(f"Possible typosquatting of brand: {brand}")
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
        normalized_domain = domain
        for fake, real in char_map.items():
            normalized_domain = normalized_domain.replace(fake, real)

# Check if it mimics a brand visually
        for brand in target_brands:
            if brand in normalized_domain and brand not in domain:
                
                add_reason(f"Visual similarity attack detected (looks like {brand})")
                break







        # ----------------------------
# HOMOGRAPH ATTACK CHECK (NEW)
# ----------------------------

# Check if domain contains Unicode characters
        if detect_homograph_attack(domain):

    # Add to brand_score (not main score → avoid duplication)
              

    # Reason for detection
            add_reason("Possible homograph attack (non-ASCII domain characters)")




        

        # ----------------------------
# BRAND INTELLIGENCE ENGINE (FINAL)
# ----------------------------

        brand_signals = 0
        brand_types = []

# --- Subdomain trap ---
        if detect_subdomain_brand_trap(final_url, target_brands):
            brand_signals += 1
            brand_types.append("subdomain")

# --- Typosquatting ---
        parts = re.split(r'[-.]', domain)
        for part in parts:
            if len(part) < 4:
                continue

            for brand in target_brands:
                distance = levenshtein_distance(part, brand)
                if 0 < distance <= 2:
                    brand_signals += 1
                    brand_types.append("typosquatting")
                    break

# --- Visual similarity ---
        char_map = {'0':'o','1':'l','3':'e','@':'a','$':'s'}
        normalized = domain
        for f, r in char_map.items():
            normalized = normalized.replace(f, r)

        for brand in target_brands:
            if brand in normalized and brand not in domain:
                brand_signals += 1
                brand_types.append("visual")
                break

# --- Homograph ---
        if detect_homograph_attack(domain):
            brand_signals += 1
            brand_types.append("homograph")






        # ---- Final decision ----

        if brand_signals >= 3:
            brand_score += 45
            add_reason("Strong brand impersonation attack")
            

        elif brand_signals == 2:
            brand_score += 30
            add_reason("Likely brand impersonation")
            

        elif brand_signals == 1:
            brand_score += 20
            add_reason("Possible brand-related risk")
            






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
                add_reason(f"Public IP address used in URL ({ip})")
        



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
                add_reason("Domain failed DNS resolution")
        

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
            "Suspicious top-level domain",
            "High entropy",
            "Brand impersonation",
            "Possible typosquatting",
            "Public IP address",
            "Shortened URL"
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
# SMART ML INTEGRATION (FINAL)
# ----------------------------

    try:
    # Use ML ONLY for borderline cases
        if 40 <= score <= 65:

            ml_result = ml_detect(final_url)

            if ml_result == 1:
                score += 12
                add_reason("ML detected phishing pattern (borderline case)")

            else:
                score -= 5  # slight confidence boost for safe
                add_reason("ML suggests URL is likely safe")

    except Exception as e:
        print("ML error:", e)





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
# FINAL RISK CLASSIFICATION
# ----------------------------
    if score >= 80:
        add_reason("FINAL VERDICT: HIGH RISK (Likely Phishing)")

    elif score >= 50:
        add_reason("FINAL VERDICT: MEDIUM RISK (Suspicious)")

    else:
        add_reason("FINAL VERDICT: LOW RISK (Likely Safe)")

    return score, reasons


print("Total URLhaus entries:", len(urlhaus_db))

# print(get_domain_age("google.com"))