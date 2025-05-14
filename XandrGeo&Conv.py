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
    headers = {"Authorization": token}

    try:
        response = requests.get(url, headers=headers, params={"name": city_name or ""})
        response.raise_for_status()
        json_response = response.json()

        if 'response' not in json_response or 'cities' not in json_response['response']:
            st.error(f"Unexpected API response structure when fetching cities for {country_name}.")
            st.json(json_response)  # Debugging
            return None

        cities_data = json_response['response']['cities']
        filtered_data = [
            {"id": city['id']}
            for city in cities_data
            if city['country_name'].strip().lower() == country_name.strip().lower()
        ]

        if not filtered_data:
            st.warning(f"No cities found for country: {country_name} and city: {city_name}.")
            return None

        return filtered_data
    except Exception as e:
        st.error(f"Error fetching cities: {e}")
        return None

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def update_line_item_profile_geo(token: str, profile_id: int, city_targets: list[dict]) -> bool:
    """Updates the geo targeting for a given profile ID."""
    url = f"{XANDR_BASE_URL}/profile?id={profile_id}"
    headers = {"Authorization": token}
    data = {
        "profile": {
            "id": profile_id,
            "city_targets": city_targets,
            "city_action": "include"
        }
    }

    try:
        response = requests.put(url, headers=headers, json=data)
        response.raise_for_status()
        return True
    except Exception as e:
        st.error(f"Error updating geo targeting for profile ID {profile_id}: {e}")
        return False

def get_line_item_ids_from_io(token: str, insertion_order_id: int) -> list[int] | None:
    """Fetches line item IDs for a given insertion order ID."""
    url = f"{XANDR_BASE_URL}/insertion-order?id={insertion_order_id}"
    headers = {"Authorization": token}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()

        if 'response' not in json_response or 'insertion-order' not in json_response['response']:
            st.error(f"Unexpected API response structure for insertion order ID: {insertion_order_id}.")
            st.json(json_response)  # Debugging
            return None

        line_items = json_response['response']['insertion-order']['line_items']
        return [item['id'] for item in line_items]
    except Exception as e:
        st.error(f"Error fetching line item IDs: {e}")
        return None

def get_profile_id_for_line_item(token: str, line_item_id: int) -> int | None:
    """Fetches the profile ID for a given line item ID."""
    url = f"{XANDR_BASE_URL}/line-item?id={line_item_id}"
    headers = {"Authorization": token}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()

        if 'response' not in json_response or 'line-item' not in json_response['response']:
            st.error(f"Unexpected API response structure for line item ID: {line_item_id}.")
            st.json(json_response)  # Debugging
            return None

        return json_response['response']['line-item']['profile_id']
    except Exception as e:
        st.error(f"Error fetching profile ID for line item ID {line_item_id}: {e}")
        return None

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

# Initialize session state variables
if "api_token" not in st.session_state:
    st.session_state["api_token"] = None
if "username" not in st.session_state:
    st.session_state["username"] = None

# --- Login Section ---
st.sidebar.header("Login")

# Check if the user is already logged in
if st.session_state["api_token"]:
    st.sidebar.success(f"Logged in as {st.session_state['username']}")
    logout_button = st.sidebar.button("Log Out")
    if logout_button:
        st.session_state["api_token"] = None
        st.session_state["username"] = None
        st.sidebar.info("You have been logged out.")
else:
    # Show the login form if the user is not logged in
    username = st.sidebar.text_input("Username", placeholder="Enter your username")
    password = st.sidebar.text_input("Password", placeholder="Enter your password", type="password")
    login_button = st.sidebar.button("Log In")

    if login_button:
        if username and password:
            # Authenticate and retrieve the token
            token = authenticate(username, password)
            if token:
                st.session_state["api_token"] = token
                st.session_state["username"] = username
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
            if not country_name_input.strip():
                st.error("Country Name is required.")
                st.stop()

            # Fetch city targets
            city_targets = get_cities_for_country(st.session_state["api_token"], country_name_input, city_name_input)
            if not city_targets:
                st.error("No valid city targets found. Please check your inputs.")
                st.stop()

            # Fetch line item IDs
            if insertion_order_id_input.strip():
                line_item_ids = get_line_item_ids_from_io(st.session_state["api_token"], int(insertion_order_id_input.strip()))
                if not line_item_ids:
                    st.error("No line items found for the provided Insertion Order ID.")
                    st.stop()
            else:
                st.error("Insertion Order ID is required.")
                st.stop()

            # Update geo targeting for each line item
            for line_item_id in line_item_ids:
                profile_id = get_profile_id_for_line_item(st.session_state["api_token"], line_item_id)
                if not profile_id:
                    st.error(f"Profile ID not found for Line Item ID: {line_item_id}")
                    continue

                success = update_line_item_profile_geo(st.session_state["api_token"], profile_id, city_targets)
                if success:
                    st.success(f"Geo targeting updated for Line Item ID: {line_item_id}")
                else:
                    st.error(f"Failed to update geo targeting for Line Item ID: {line_item_id}")

# --- Tab 2: Conversion Pixel Updater ---
with tab2:
    st.header("Conversion Pixel Updater")
    if st.session_state["api_token"] is None:
        st.error("Please log in to use this tool.")
    else:
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
        # Report Type Selection
        report_type = st.selectbox(
            "Select Report Type",
            ["Site Domain Performance"]
        )

        # Date Range Selection
        use_custom_dates = st.checkbox("Use Custom Date Range")
        if use_custom_dates:
            start_date = st.date_input("Start Date")
            end_date = st.date_input("End Date")
        else:
            report_interval = st.selectbox(
                "Select Report Interval",
                ["yesterday", "last_7_days", "month_to_yesterday", "month_to_date"]
            )

        # Columns Selection
        columns = st.multiselect(
            "Select Columns",
            [
                "day", "site_domain", "imps", "clicks", "total_convs", "ctr",
                "convs_rate", "booked_revenue", "cpm"
            ],
            default=["day", "site_domain", "imps", "clicks", "ctr", "booked_revenue"]
        )

        # Advertiser ID Input (if required)
        advertiser_id_input = st.text_input(
            "Advertiser ID (Required for Network Users)",
            placeholder="Enter Advertiser ID"
        )

        # Generate Report Button
        if st.button("Generate Report"):
            # Validate Inputs
            if use_custom_dates:
                if not start_date or not end_date:
                    st.error("Both Start Date and End Date are required for custom date ranges.")
                    st.stop()
                if start_date >= end_date:
                    st.error("Start Date must be earlier than End Date.")
                    st.stop()
            elif not report_interval:
                st.error("Please select a report interval.")
                st.stop()

            if not advertiser_id_input.strip():
                st.error("Advertiser ID is required for network users.")
                st.stop()

            # Construct the Report Payload
            report_payload = {
                "report": {
                    "report_type": "site_domain_performance",
                    "columns": columns,
                    "format": "xlsx"  # Change format to XLSX
                }
            }

            # Add Date Range or Interval
            if use_custom_dates:
                report_payload["report"]["start_date"] = start_date.strftime("%Y-%m-%d")
                report_payload["report"]["end_date"] = end_date.strftime("%Y-%m-%d")
            else:
                report_payload["report"]["report_interval"] = report_interval

            # API Endpoint
            endpoint = f"{XANDR_BASE_URL}/report?advertiser_id={advertiser_id_input.strip()}"

            # Make the API Request to Generate the Report
            try:
                response = requests.post(endpoint, headers={"Authorization": st.session_state["api_token"]}, json=report_payload)
                response.raise_for_status()
                json_response = response.json()
                st.json(json_response)  # Debugging: Display the API response
                report_id = json_response.get("report_id")
                if not report_id:
                    st.error("Failed to retrieve report ID. Please check the API response.")
                    return
            except Exception as e:
                st.error(f"An error occurred while generating the report: {e}")
                return

            # Poll for Report Status
            status_url = f"{XANDR_BASE_URL}/report?id={report_id}"
            while True:
                try:
                    status_response = requests.get(status_url, headers={"Authorization": st.session_state["api_token"]})
                    status_response.raise_for_status()
                    status_data = status_response.json()
                    st.json(status_data)  # Debugging: Display the status response
                    if status_data.get("execution_status") == "ready":
                        break
                    elif status_data.get("execution_status") == "error":
                        st.error("An error occurred while generating the report.")
                        st.json(status_data)  # Debugging: Display the error details
                        return
                    st.info("Report is being generated... Please wait.")
                    time.sleep(5)  # Wait before polling again
                except Exception as e:
                    st.error(f"An error occurred while checking report status: {e}")
                    return

            # Download the Report
            try:
                download_url = f"{XANDR_BASE_URL}/report-download?id={report_id}"
                report_data = requests.get(download_url, headers={"Authorization": st.session_state["api_token"]})
                report_data.raise_for_status()
                with open("site_domain_performance.xlsx", "wb") as file:
                    file.write(report_data.content)
                st.success("Report downloaded successfully!")
                st.download_button(
                    label="Download Report",
                    data=report_data.content,
                    file_name="site_domain_performance.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
            except Exception as e:
                st.error(f"An error occurred while downloading the report: {e}")
                return