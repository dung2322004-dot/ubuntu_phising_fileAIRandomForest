import pandas as pd

from url_features import *

print("Loading dataset...")

df = pd.read_csv(
    "final_dataset.csv",
    usecols=["url", "label"]
)

phishing = df[
    df["label"] == 1
].sample(
    n=100,
    random_state=42
)

safe = df[
    df["label"] == 0
].sample(
    n=100,
    random_state=42
)

df = pd.concat(
    [phishing, safe]
).reset_index(drop=True)

print("\nLabel distribution:")
print(df["label"].value_counts())

rows = []

total = len(df)

for index, row in df.iterrows():

    if index % 100 == 0:
        print(f"Processing {index}/{total}")

    url = str(row["url"])
    label = int(row["label"])

    structure = url_structure(url)

    rows.append({

        "domain_reputation": 
        	domain_reputation(url),
        "domain_age":  
        	get_domain_age(url),
        "ssl": 
        	has_ssl(url),
        "url_length":
            	structure["url_length"],
        "typo":
            	typo_score(url),
        "redirect": 	
        	redirect_count(url),
        "blacklist":
            	blacklist_score(url),
        "content":
    		content_score(url),
	"headers":
    		security_headers(url),
        "label": label
    })

out = pd.DataFrame(rows)

out.to_csv(
    "dataset_9criteria.csv",
    index=False
)

print("\nOutput shape:")
print(out.shape)

print("\nSaved -> dataset_9criteria.csv")
