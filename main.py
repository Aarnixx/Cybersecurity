import pandas as pd
import requests
from requests.structures import CaseInsensitiveDict

API_KEY = "a67e8979758f4feea51637156bbdaf25"
DEBUG = True
csv_path = r"C:\Users\aarni.annanolli\Python\KyberturvallisuusTilastot\LocationIntelligenceCybersecurity2025.csv"

location = pd.read_csv(csv_path, usecols=[1, 2])
location_info = pd.read_csv(csv_path, usecols=[3, 4, 5, 6, 7, 8]) 
breach_info = pd.read_csv(csv_path, usecols=[13, 14, 15])

def place_name(lat: float, lon: float) -> str:
    url = (f"https://api.geoapify.com/v1/geocode/reverse?lat={lat}&lon={lon}&type=city&lang=en&limit=1&format=json&apiKey={API_KEY}")
    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        if data.get("results"):
            city = data["results"][0].get("city")
            return city if city else "unknown"
        else:
            return "unknown"
    else:
        return "unknown"

def main():
    if DEBUG:
        random_row = location.sample(n=1).iloc[0]
        lat = random_row['Latitude']
        lon = random_row['Longitude']
        city = place_name(lat, lon)
        print(f"Latitude: {lat}, Longitude: {lon} -> City: {city}")
    

if __name__ == "__main__":
    main()
