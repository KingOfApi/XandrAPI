import streamlit as st
import requests
import pprint  # For debugging, can be removed from final UI output
from tenacity import retry, stop_after_attempt, wait_exponential  # Added for retry mechanism
import logging
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

if st.__version__ < "1.0.0":
    st.error("Please upgrade Streamlit to version 1.0.0 or higher.")

# --- Xandr API Configuration ---
XANDR_BASE_URL = "https://api.appnexus.com"

# --- Helper Functions (Refactored from your script) ---

def get_cities_for_country(token: str, country_name: str, city_name: str = None) -> list[dict] | None:
    """Fetches city IDs for a given country and optionally filters by city name."""
    url = f"{XANDR_BASE_URL}/city"
    params = {'name': country_name}
    headers = {"Authorization": token}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        json_response = response.json()

        if 'response' not in json_response or 'cities' not in json_response['response']:
            st.error(f"Unexpected API response structure when fetching cities for {country_name}.")
            st.json(json_response)  # Show the problematic response
            return None

        if not isinstance(json_response.get('response', {}).get('cities', []), list):
            st.error("Unexpected API response structure.")
            return None

        cities_data = json_response['response']['cities']
        filtered_data = []
        for city in cities_data:
            # Filter by country name
            if city.get('country_name', '').lower() == country_name.lower():
                # Optionally filter by city name
                if city_name and city.get('name', '').lower() != city_name.lower():
                    continue
                filtered_data.append({"id": city['id']})

        if not filtered_data:
            st.warning(f"No cities found for country: {country_name} and city: {city_name}.")
            return None
        return filtered_data
    except requests.exceptions.RequestException as e:
        st.error(f"API Error fetching cities: {e}")
        logging.error(f"API Error fetching cities: {e}")
        if hasattr(e, 'response') and e.response is not None:
            st.json(e.response.json())
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred while fetching cities: {e}")
        return None

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def update_line_item_profile_geo(token, profile_id, city_targets):
    """Updates the geo targeting for a given profile ID."""
    url = f"{XANDR_BASE_URL}/profile?id={profile_id}"  # ID in query param for PUT on profile
    headers = {"Authorization": token}
    data = {
        "profile": {
            "id": profile_id,
            "city_targets": city_targets,
            "city_action": "include"  # This will replace existing city targets
        }
    }
    try:
        response = requests.put(url, headers=headers, json=data)
        response.raise_for_status()
        json_response = response.json()

        # Check if the response contains the expected keys
        if 'response' not in json_response or 'status' not in json_response['response']:
            st.error(f"Unexpected API response structure while updating profile ID {profile_id}.")
            st.json(json_response)  # Show the problematic response
            return None

        return json_response
    except requests.exceptions.RequestException as e:
        st.error(f"API Error updating profile ID {profile_id}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            st.json(e.response.json())
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred while updating profile: {e}")
        return None

def get_line_item_ids_from_io(token: str, insertion_order_id: int) -> list[int] | None:
    """Fetches line item IDs for a given insertion order ID."""
    url = f"{XANDR_BASE_URL}/line-items?insertion_order_id={insertion_order_id}"
    headers = {"Authorization": token}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()
        return [item['id'] for item in json_response.get('response', {}).get('line_items', [])]
    except Exception as e:
        logging.error(f"Error fetching line item IDs: {e}")
        return None

def get_profile_id_for_line_item(token: str, line_item_id: int) -> int | None:
    """Fetches the profile ID for a given line item ID."""
    # Placeholder implementation
    return 54321  # Replace with actual API call logic

def authenticate(username: str, password: str) -> str | None:
    """Authenticates the user and retrieves the API token."""
    credentials = f'{{"auth": {{"username": "{username}", "password": "{password}"}}}}'
    try:
        # Send the credentials as raw data in the `data` parameter
        response = requests.post(f"{XANDR_BASE_URL}/auth", data=credentials)
        response.raise_for_status()
        json_response = response.json()

        if 'response' in json_response and 'token' in json_response['response']:
            return json_response['response']['token']
        else:
            st.error("Authentication failed. Please check your credentials.")
            st.json(json_response)  # Show the problematic response for debugging
            return None
    except requests.exceptions.RequestException as e:
        st.error(f"Error during authentication: {e}")
        logging.error("Error during authentication: Redacted sensitive data.")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred during authentication: {e}")
        logging.error(f"Unexpected error during authentication: {e}")
        return None

# --- Streamlit UI ---
st.set_page_config(layout="wide")
st.title("Xandr Tools: Geo Targeting, Conversion Pixels & Reporting")

# --- Login Section ---
st.sidebar.header("Login")
username = st.sidebar.text_input("Username", placeholder="Enter your username")
password = st.sidebar.text_input("Password", placeholder="Enter your password", type="password")
login_button = st.sidebar.button("Log In")

# Store the token in session state
if "api_token" not in st.session_state:
    st.session_state["api_token"] = None

if login_button:
    if username and password:
        # Authenticate and retrieve the token
        token = authenticate(username, password)
        if token:
            st.session_state["api_token"] = token
            st.sidebar.success("Logged in successfully!")
        else:
            st.sidebar.error("Login failed. Please check your credentials.")
    else:
        st.sidebar.error("Please enter both username and password.")

# Tabs for different tools
tab1, tab2, tab3 = st.tabs(["Geo Targeting Updater", "Conversion Pixel Updater", "Reporting"])

# --- Tab 1: Geo Targeting Updater ---
with tab1:
    st.header("Geo Targeting Updater")
    if st.session_state["api_token"] is None:
        st.error("Please log in to use this tool.")
    else:
        country_name_input = st.text_input("Country Name", placeholder="e.g., Sweden, Germany, United States")
        city_name_input = st.text_input("City Name (Optional)", placeholder="e.g., Stockholm")
        insertion_order_id_input = st.text_input(
            "Insertion Order ID (Optional)", 
            placeholder="Enter a valid Insertion Order ID",
            help="Provide the Insertion Order ID to update all line items within it."
        )
        line_item_ids_input = st.text_area(
            "Line Item IDs (Optional)", 
            placeholder="Enter line item IDs separated by commas (e.g., 12345, 67890, 11223)",
            help="Provide the line item IDs you want to update. Leave blank to skip line item updates."
        )
        if st.button("Update Geo Targeting"):
            st.write("Processing Geo Targeting...")  # Placeholder for logic

# --- Tab 2: Conversion Pixel Updater ---
with tab2:
    st.header("Conversion Pixel Updater")
    insertion_order_id_input = st.text_input(
        "Insertion Order ID (Optional)", 
        placeholder="Enter a valid Insertion Order ID",
        help="Provide the Insertion Order ID to update all line items with the new conversion pixel."
    )
    line_item_ids_input = st.text_area(
        "Line Item IDs (Optional)", 
        placeholder="Enter line item IDs separated by commas (e.g., 12345, 67890, 11223)",
        help="Provide the line item IDs you want to update. Leave blank to update all line items in the insertion order."
    )
    new_pixel_id_input = st.text_input(
        "New Conversion Pixel ID", 
        placeholder="Enter the new conversion pixel ID",
        help="Provide the ID of the new conversion pixel to apply."
    )
    if st.button("Update Conversion Pixels"):
        st.write("Processing Conversion Pixel Updates...")  # Placeholder for logic

# --- Tab 3: Reporting ---
with tab3:
    st.header("Reporting: Site Domain Performance")
    if st.session_state["api_token"] is None:
        st.error("Please log in to use this tool.")
    else:
        report_type = st.selectbox(
            "Select Report Type",
            ["Network Site Domain Performance", "Insertion Order Site Domain Performance"]
        )
        insertion_order_id_input = st.text_input(
            "Insertion Order ID (Required for Insertion Order Report)",
            placeholder="Enter Insertion Order ID"
        )
        report_interval = st.selectbox(
            "Select Report Interval",
            ["today", "yesterday", "last_7_days", "last_48_hours"]
        )
        columns = st.multiselect(
            "Select Columns",
            [
                "site_domain", "mobile_application_name", "insertion_order_id", "insertion_order_name",
                "line_item_id", "line_item_name", "geo_country_name", "imps", "clicks", "ctr",
                "total_convs", "convs_rate", "booked_revenue", "cpm", "view_rate"
            ],
            default=["site_domain", "imps", "clicks", "ctr", "booked_revenue"]
        )
        if st.button("Generate Report"):
            if report_type == "Insertion Order Site Domain Performance" and not insertion_order_id_input.strip():
                st.error("Insertion Order ID is required for Insertion Order Site Domain Performance reports.")
            else:
                # Construct the report payload
                report_payload = {
                    "report": {
                        "report_type": "network_site_domain_performance" if report_type == "Network Site Domain Performance" else "site_domain_performance",
                        "report_interval": report_interval,
                        "columns": columns,
                        "format": "csv"
                    }
                }

                # Add insertion_order_id to the endpoint if required
                endpoint = f"{XANDR_BASE_URL}/report"
                if report_type == "Insertion Order Site Domain Performance":
                    endpoint += f"?insertion_order_id={insertion_order_id_input.strip()}"

                # Make the API request to generate the report
                try:
                    response = requests.post(endpoint, headers={"Authorization": st.session_state["api_token"]}, json=report_payload)
                    response.raise_for_status()
                    report_id = response.json().get("report_id")
                    
                    download_url = f"{XANDR_BASE_URL}/report-download?id={report_id}"
                    report_data = requests.get(download_url, headers={"Authorization": st.session_state["api_token"]})
                    with open("report.csv", "wb") as file:
                        file.write(report_data.content)
                    st.success("Report downloaded successfully!")
                except Exception as e:
                    st.error(f"An error occurred: {e}")