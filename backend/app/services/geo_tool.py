import requests

def get_geo_info(ip_or_domain: str):
    """
    Fetches physical location data for a target.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_or_domain}")
        data = response.json()
        
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
        return {"error": "Could not locate target"}
    except Exception as e:
        return {"error": str(e)}